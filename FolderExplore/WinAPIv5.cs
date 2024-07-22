using Microsoft.Win32.SafeHandles;
using System.Collections;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace FastFileV5
{
    [Serializable]
    public class WinAPIv5
    {
        public long Length { get; }
        public string Name { get; }
        public string AlternateName { get; }
        public string FullName { get; }
        public FileAttributes Attributes { get; }
        public string? DirectoryName => Path.GetDirectoryName(FullName);
        public bool Exists => File.Exists(FullName);
        public override string ToString() => FullName;

        public WinAPIv5(string filename) : this(new FileInfo(filename)) { }

        public WinAPIv5(FileInfo file)
        {
            Name = file.Name;
            FullName = file.FullName;
            if (file.Exists)
            {
                Length = file.Length;
                Attributes = file.Attributes;
            }
        }

        internal WinAPIv5(string dir, WIN32_FIND_DATA findData)
        {
            Attributes = findData.dwFileAttributes;
            Length = CombineHighLowInts(findData.nFileSizeHigh, findData.nFileSizeLow);
            Name = findData.cFileName;
            AlternateName = findData.cAlternateFileName;
            FullName = Path.Combine(dir, findData.cFileName);
        }

        public static long CombineHighLowInts(uint high, uint low) => (((long)high) << 32) | low;

        public static IEnumerable<WinAPIv5> EnumerateFileSystem(
            string path,
            string searchPattern = "*",
            SearchOption searchOption = SearchOption.TopDirectoryOnly,
            SearchFor searchFor = SearchFor.Files,
            int deepnessLevel = -1,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(path);
            ArgumentNullException.ThrowIfNull(searchPattern);

            return new FileEnumerable(Path.GetFullPath(path), searchPattern, searchOption, searchFor, deepnessLevel, cancellationToken);
        }

        private class FileEnumerable : IEnumerable<WinAPIv5>
        {
            private readonly string _path;
            private readonly string _filter;
            private readonly SearchOption _searchOption;
            private readonly SearchFor _searchFor;
            private readonly int _maxDegreeOfParallelism;
            private readonly int _deepnessLevel;
            private readonly CancellationToken _cancellationToken;

            public FileEnumerable(string path, string filter, SearchOption searchOption, SearchFor searchFor, int deepnessLevel, CancellationToken cancellationToken)
            {
                _path = path;
                _filter = filter;
                _searchOption = searchOption;
                _searchFor = searchFor;
                _maxDegreeOfParallelism = (int)(Environment.ProcessorCount * 1.5);
                _deepnessLevel = deepnessLevel <= 0 ? -1 : deepnessLevel;
                _cancellationToken = cancellationToken;
            }

            public IEnumerator<WinAPIv5> GetEnumerator()
            {
                return new ParallelFileEnumerator(_path, _filter, _searchOption, _searchFor, _maxDegreeOfParallelism, _deepnessLevel, _cancellationToken);
            }

            IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        }

        private sealed class SafeFindHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            [DllImport("kernel32.dll")]
            private static extern bool FindClose(IntPtr handle);

            internal SafeFindHandle() : base(true) { }

            protected override bool ReleaseHandle()
            {
                return FindClose(handle);
            }
        }

        private class ParallelFileEnumerator : IEnumerator<WinAPIv5>
        {
            private readonly string _initialPath;
            private readonly string _searchPattern;
            private readonly SearchOption _searchOption;
            private readonly SearchFor _searchFor;
            private readonly int _maxDegreeOfParallelism;
            private readonly CancellationToken _cancellationToken;
            private readonly ConcurrentStack<(string path, int depth)> _directoryStack;
            private readonly BlockingCollection<WinAPIv5> _resultQueue;
            private readonly ConcurrentDictionary<string, byte> _processedDirectories = new();
            private readonly ObjectPool<WIN32_FIND_DATA> _findDataPool;
            private Task[] _producerTasks;
            private bool _isCompleted;
            private int _activeProducers;
            private int _deepnessLevel;

            public ParallelFileEnumerator(string path, string searchPattern, SearchOption searchOption, SearchFor searchFor, int maxDegreeOfParallelism, int deepnessLevel, CancellationToken cancellationToken)
            {
                _initialPath = path;
                _searchPattern = searchPattern;
                _searchOption = searchOption;
                _searchFor = searchFor;
                _maxDegreeOfParallelism = maxDegreeOfParallelism;
                _deepnessLevel = deepnessLevel;
                _cancellationToken = cancellationToken;
                _directoryStack = new ConcurrentStack<(string path, int depth)>();
                _resultQueue = new BlockingCollection<WinAPIv5>(new ConcurrentQueue<WinAPIv5>());
                _findDataPool = new ObjectPool<WIN32_FIND_DATA>(() => new WIN32_FIND_DATA(), maxSize: _maxDegreeOfParallelism * 2);

                _directoryStack.Push((_initialPath, 0));
                StartProducerTasks();
            }

            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern SafeFindHandle FindFirstFile(string fileName, [In, Out] WIN32_FIND_DATA data);

            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool FindNextFile(SafeFindHandle hndFindFile, [In, Out, MarshalAs(UnmanagedType.LPStruct)] WIN32_FIND_DATA lpFindFileData);

            private void StartProducerTasks()
            {
                _producerTasks = new Task[_maxDegreeOfParallelism];
                _activeProducers = _maxDegreeOfParallelism;
                for (int i = 0; i < _maxDegreeOfParallelism; i++)
                {
                    _producerTasks[i] = Task.Run(ProducerWork, _cancellationToken);
                }

                Task.Run(async () =>
                {
                    try
                    {
                        await Task.WhenAll(_producerTasks);
                        _resultQueue.CompleteAdding();
                    }
                    catch (OperationCanceledException)
                    {
                        // Expected when cancellation is requested
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"Error in producer tasks: {ex}");
                    }
                    finally
                    {
                        _isCompleted = true;
                    }
                });
            }

            private void ProducerWork()
            {
                try
                {
                    while (_directoryStack.TryPop(out var dirInfo))
                    {
                        ProcessDirectory(dirInfo.path, dirInfo.depth);
                        if (_directoryStack.IsEmpty && _activeProducers == 1) break;
                        if (_cancellationToken.IsCancellationRequested) break;
                    }
                }
                catch (OperationCanceledException)
                {
                    // Expected when cancellation is requested
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error in producer work: {ex}");
                }
                finally
                {
                    if (Interlocked.Decrement(ref _activeProducers) == 0)
                    {
                        _resultQueue.CompleteAdding();
                    }
                }
            }



            private void ProcessDirectory(string path, int depth)
            {
                if (!_processedDirectories.TryAdd(path, 1)) return;
                if (_deepnessLevel != -1 && depth >= _deepnessLevel) return;
                var findData = _findDataPool.Rent();
                try
                {
                    using var hFind = FindFirstFile(Path.Combine(path, _searchPattern), findData);

                    if (hFind.IsInvalid)
                    {
                        Debug.WriteLine($"Failed to access directory: {path}");
                        return;
                    }

                    do
                    {
                        _cancellationToken.ThrowIfCancellationRequested();

                        if (findData.cFileName is "." or ".." or "Thumbs.db") continue;

                        var fullPath = Path.Combine(path, findData.cFileName);

                        if (findData.dwFileAttributes.HasFlag(FileAttributes.Directory))
                        {
                            if (_searchOption == SearchOption.AllDirectories)
                            {
                                _directoryStack.Push((fullPath, depth + 1));
                            }

                            if (_searchFor is SearchFor.Directories or SearchFor.FilesAndDirectories)
                                _resultQueue.Add(new WinAPIv5(path, findData));
                        }
                        else if (_searchFor is SearchFor.Files or SearchFor.FilesAndDirectories)
                        {
                            _resultQueue.Add(new WinAPIv5(path, findData));
                        }
                    }
                    while (FindNextFile(hFind, findData));
                }
                catch (OperationCanceledException)
                {
                    // Expected when cancellation is requested
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error processing directory {path}: {ex.Message}");
                }
                finally
                {
                    _findDataPool.Return(findData);
                }
            }

            public bool MoveNext()
            {
                if (_isCompleted) return false;

                try
                {
                    if (_resultQueue.TryTake(out var item, Timeout.Infinite, _cancellationToken))
                    {
                        Current = item;
                        return true;
                    }
                }
                catch (OperationCanceledException)
                {
                    // Expected when cancellation is requested
                }
                catch (InvalidOperationException)
                {
                    // Queue is completed
                }

                _isCompleted = true;
                return false;
            }

            public void Dispose()
            {
                _resultQueue.CompleteAdding();
                Task.WaitAll(_producerTasks, TimeSpan.FromSeconds(30));
                _resultQueue.Dispose();
                _directoryStack.Clear();
            }


            public WinAPIv5 Current { get; private set; }

            object IEnumerator.Current => Current;

            public void Reset() => throw new NotSupportedException();
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    internal class WIN32_FIND_DATA
    {
        public FileAttributes dwFileAttributes;
        public uint ftCreationTime_dwLowDateTime;
        public uint ftCreationTime_dwHighDateTime;
        public uint ftLastAccessTime_dwLowDateTime;
        public uint ftLastAccessTime_dwHighDateTime;
        public uint ftLastWriteTime_dwLowDateTime;
        public uint ftLastWriteTime_dwHighDateTime;
        public uint nFileSizeHigh;
        public uint nFileSizeLow;
        public int dwReserved0;
        public int dwReserved1;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string cFileName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)]
        public string cAlternateFileName;

        public override string ToString() => "FileName = " + cFileName;
    }

    public enum SearchFor
    {
        Files = 0,
        Directories = 1,
        FilesAndDirectories = 2,
    }
    public class ObjectPool<T> where T : class
    {
        private readonly Func<T> _objectGenerator;
        private readonly ConcurrentBag<T> _objects;
        private readonly int _maxSize;

        public ObjectPool(Func<T> objectGenerator, int maxSize = int.MaxValue)
        {
            _objectGenerator = objectGenerator ?? throw new ArgumentNullException(nameof(objectGenerator));
            _objects = new ConcurrentBag<T>();
            _maxSize = maxSize;
        }

        public T Rent()
        {
            if (_objects.TryTake(out T item))
                return item;

            return _objectGenerator();
        }

        public void Return(T item)
        {
            if (_objects.Count < _maxSize)
                _objects.Add(item);
        }
    }
}
