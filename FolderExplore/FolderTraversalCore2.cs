using System.Collections;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace FolderExplore
{
    public class FolderTraversalCore2
    {
        /// <summary>
        /// Enumerates the filesystem entries.
        /// </summary>
        /// <param name="path"></param>
        /// <param name="searchPattern"></param>
        /// <param name="searchFor"></param>
        /// <param name="deepnessLevel"></param>
        /// <param name="cancellationToken"></param>
        /// <returns> An enumerable of <see cref="FileSystemEntry"/> objects. </returns>
        public static IEnumerable<FileSystemEntry> EnumerateFileSystem(string path,
                                                                string searchPattern = "*",
                                                                SearchFor searchFor = SearchFor.Files,
                                                                int deepnessLevel = -1,
                                                                bool isOwner = false,
                                                                bool isInherited = false,
                                                                CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(path);
            ArgumentNullException.ThrowIfNull(searchPattern);

            return new FileEnumerable(Path.GetFullPath(path), searchPattern, searchFor, deepnessLevel, isOwner, isInherited, cancellationToken);
        }

        private class FileEnumerable(string path, string filter, SearchFor searchFor, int deepnessLevel, bool isOwner, bool isInherited, CancellationToken cancellationToken) : IEnumerable<FileSystemEntry>
        {
            private readonly int _deepnessLevel = deepnessLevel <= 0 ? -1 : deepnessLevel;
            private readonly int _maxDegreeOfParallelism = (int)(Environment.ProcessorCount * 1.5);
            public IEnumerator<FileSystemEntry> GetEnumerator() => new ParallelFileEnumerator(path, filter, searchFor, _maxDegreeOfParallelism, _deepnessLevel, isOwner, isInherited, cancellationToken);

            IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        }

        /// <summary>
        /// The main parallel enumerator, which is used to enumerate files and folders.
        /// </summary>
        [SuppressUnmanagedCodeSecurity]
        public class ParallelFileEnumerator : IEnumerator<FileSystemEntry>
        {
            private readonly ManualResetEventSlim _completionEvent = new(false);
            private readonly AutoResetEvent _workAvailable = new(false);
            private readonly CancellationToken _cToken;

            private readonly BlockingCollection<FileSystemEntry> _resultQueue;
            private readonly ConcurrentQueue<(string path, int depth)> _directoryQueue;

            private readonly SearchFor _searchFor;
            private readonly string _initialPath;
            private readonly string _searchPattern;
            private readonly int _deepnessLevel;
            private readonly int _maxDegreeOfParallelism;
            private readonly bool _isOwner;
            private readonly bool _isInherited;

            private int _activeProducers;
            private bool _enumerateRunning = true;

            /// <summary>
            /// Initializes a new instance of the <see cref="ParallelFileEnumerator"/> class.
            /// </summary>
            /// <param name="path"> The main folder to start enumerating. </param>
            /// <param name="searchPattern"> Given filter for search </param>
            /// <param name="searchFor"> Search for files or folders or both </param>
            /// <param name="maxDegreeOfParallelism"> The maximum degree of parallelism, which is the maximum number of tasks that can be active at the same time. </param>
            /// <param name="deepnessLevel"> The deepness level of the search </param>
            /// <param name="cancellationToken"></param>
            public ParallelFileEnumerator(string path, string searchPattern, SearchFor searchFor, int maxDegreeOfParallelism, int deepnessLevel, bool isOwner, bool isInherited, CancellationToken cancellationToken)
            {
                _cToken = cancellationToken;
                _maxDegreeOfParallelism = maxDegreeOfParallelism > 0 ? maxDegreeOfParallelism : Environment.ProcessorCount;
                _activeProducers = _maxDegreeOfParallelism;

                _initialPath = path;
                _searchPattern = searchPattern;
                _searchFor = searchFor;

                _deepnessLevel = deepnessLevel;
                _isOwner = isOwner;
                _isInherited = isInherited;

                _directoryQueue = new ConcurrentQueue<(string path, int depth)>([(_initialPath, 0)]);
                _resultQueue = [];
                StartProducerTasks();
            }
            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            private static extern SafeFindHandle FindFirstFile(StringBuilder fileName, out WIN32_FIND_DATA data);

            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            private static extern bool FindNextFile(SafeFindHandle hndFindFile, out WIN32_FIND_DATA lpFindFileData);

            public void Reset() => throw new NotSupportedException();
            public FileSystemEntry Current { get; private set; }
            object IEnumerator.Current => Current;

            public void Dispose()
            {
                _enumerateRunning = false;
                _workAvailable.Set(); // Wake up any waiting threads
                _completionEvent.Wait(TimeSpan.FromSeconds(30)); // Wait for all producers to complete
                _resultQueue.Dispose();
                _completionEvent.Dispose();
                _workAvailable.Dispose();
            }

            /// <summary>
            /// Moves the enumerator to the next element from the <see cref="BlockingCollection{T}"/>.
            /// </summary>
            /// <returns>Enumerated <see cref="FileSystemEntry"/> items</returns>
            public bool MoveNext()
            {
                while (_enumerateRunning || _resultQueue.Count > 0)
                {
                    if (_resultQueue.TryTake(out var item, 1000, _cToken))
                    {
                        Current = item;
                        return true;
                    }

                    if (_directoryQueue.IsEmpty) _enumerateRunning = false;

                }
                return false;
            }

            /// <summary>
            /// Checks if the <paramref name="fileName"/> is <c>reparse point</c> or <c>Thumbs.db</c>
            /// </summary>
            /// <param name="fileName"></param>
            /// <returns></returns>
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static bool IsToLeftOut(string fileName) => fileName switch
            {
                "." or ".." or "Thumbs.db" => true,
                _ => false
            };

            /// <summary>
            /// Processes the <see cref="ConcurrentStack{T}"/>
            /// Main thread, which gets the full <paramref name="path"/> and <paramref name="depth"/>
            /// </summary>
            /// <param name="path"></param>
            /// <param name="depth"></param>
            private void ProcessDirectory(string path, int depth)
            {
                if (_deepnessLevel != -1 && depth >= _deepnessLevel) return;
                try
                {
                    var findData = new WIN32_FIND_DATA();
                    var stringBuilderPath = new StringBuilder(260).Append(path).Append(Path.DirectorySeparatorChar).Append(_searchPattern);
                    using var hFind = FindFirstFile(stringBuilderPath, out findData);

                    if (hFind.IsInvalid) return;

                    do
                    {
                        if (_cToken.IsCancellationRequested) return;
                        if (IsToLeftOut(findData.cFileName)) continue;

                        stringBuilderPath.Clear().Append(path).Append(Path.DirectorySeparatorChar).Append(findData.cFileName);
                        var fullPath = stringBuilderPath.ToString();
                        if (findData.dwFileAttributes.HasFlag(FileAttributes.Directory))
                        {

                            _directoryQueue.Enqueue((fullPath, depth + 1));
                            _workAvailable.Set(); // Signal that work is available

                            if (_searchFor != SearchFor.Files) _resultQueue.Add(SecurityCheck.CreateFileSystemEntry(new DirectoryInfo(fullPath), true, findData.dwFileAttributes, _isOwner, _isInherited));
                        }
                        else if (_searchFor != SearchFor.Directories)
                        {
                            //long fileSize = ((long)findData.nFileSizeHigh << 32) | findData.nFileSizeLow;
                            _resultQueue.Add(SecurityCheck.CreateFileSystemEntry(new FileInfo(fullPath), true, findData.dwFileAttributes, _isOwner, _isInherited));
                        }
                    }
                    while (FindNextFile(hFind, out findData));
                }
                catch (Exception ex)
                {
                    //Debug.WriteLine($"Error processing directory {path}: {ex.Message}");
                }
            }

            /// <summary>
            /// Thread that consumes the <see cref="BlockingCollection{T}"/>.
            /// Each folder is processed by <see cref="ProcessDirectory(StringBuilder, int)"/>
            /// </summary>
            private void ProducerWork()
            {
                try
                {
                    while (!_cToken.IsCancellationRequested && _enumerateRunning)
                    {
                        if (_directoryQueue.TryDequeue(out (string path, int depth) current)) ProcessDirectory(current.path, current.depth);
                        else _workAvailable.WaitOne(100); // Wait for work or timeout
                    }
                }
                finally
                {
                    if (Interlocked.Decrement(ref _activeProducers) == 0)
                    {
                        _resultQueue.CompleteAdding();
                        _completionEvent.Set();
                    }
                }
            }

            /// <summary>
            /// Creates <see cref="Task"/> for each <see cref="ProducerWork()"/>
            /// </summary>
            private void StartProducerTasks()
            {
                for (int i = 0; i < _maxDegreeOfParallelism; i++)
                {
                    Task.Factory.StartNew(ProducerWork, _cToken, TaskCreationOptions.LongRunning, TaskScheduler.Default);
                }
            }
        }
    }
}
