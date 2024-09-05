using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;

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
                                                                CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(path);
            ArgumentNullException.ThrowIfNull(searchPattern);

            return new FileEnumerable(Path.GetFullPath(path), searchPattern, searchFor, deepnessLevel, cancellationToken);
        }

        private class FileEnumerable(string path, string filter, SearchFor searchFor, int deepnessLevel, CancellationToken cancellationToken) : IEnumerable<FileSystemEntry>
        {
            private readonly int _deepnessLevel = deepnessLevel <= 0 ? -1 : deepnessLevel;
            private readonly int _maxDegreeOfParallelism = (int)(Environment.ProcessorCount * 1.5);
            public IEnumerator<FileSystemEntry> GetEnumerator() => new ParallelFileEnumerator(path, filter, searchFor, _maxDegreeOfParallelism, _deepnessLevel, cancellationToken);

            IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        }

        /// <summary>
        /// The main parallel enumerator, which is used to enumerate files and folders.
        /// </summary>
        [System.Security.SuppressUnmanagedCodeSecurity]
        public class ParallelFileEnumerator : IEnumerator<FileSystemEntry>
        {
            private readonly ManualResetEventSlim _completionEvent = new(false);
            private readonly CancellationToken _cToken;
            private readonly ConcurrentQueue<(string path, int depth)> _directoryQueue;
            private readonly string _initialPath;
            private readonly int _maxDegreeOfParallelism;
            private readonly BlockingCollection<FileSystemEntry> _resultQueue;
            private readonly SearchFor _searchFor;
            private readonly string _searchPattern;
            private readonly AutoResetEvent _workAvailable = new(false);
            private int _activeProducers;
            private readonly int _deepnessLevel;
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
            public ParallelFileEnumerator(string path, string searchPattern, SearchFor searchFor, int maxDegreeOfParallelism, int deepnessLevel, CancellationToken cancellationToken)
            {
                _initialPath = path;
                _searchPattern = searchPattern;
                _searchFor = searchFor;
                _maxDegreeOfParallelism = maxDegreeOfParallelism > 0 ? maxDegreeOfParallelism : Environment.ProcessorCount;
                _directoryQueue = new ConcurrentQueue<(string path, int depth)>([(_initialPath, 0)]);
                _deepnessLevel = deepnessLevel;
                _resultQueue = [];
                _cToken = cancellationToken;
                _activeProducers = _maxDegreeOfParallelism;

                StartProducerTasks();
            }
            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            private static extern SafeFindHandle FindFirstFile(string fileName, [In, Out] WIN32_FIND_DATA data);

            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            private static extern bool FindNextFile(SafeFindHandle hndFindFile, [In, Out, MarshalAs(UnmanagedType.LPStruct)] WIN32_FIND_DATA lpFindFileData);

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
                    using var hFind = FindFirstFile(Path.Combine(path, _searchPattern), findData);

                    if (hFind.IsInvalid) return;

                    do
                    {
                        if (_cToken.IsCancellationRequested) return;
                        if (IsToLeftOut(findData.cFileName)) continue;

                        var fullPath = Path.Combine(path, findData.cFileName);

                        if (findData.dwFileAttributes.HasFlag(FileAttributes.Directory))
                        {

                            _directoryQueue.Enqueue((fullPath, depth + 1));
                            _workAvailable.Set(); // Signal that work is available

                            if (_searchFor != SearchFor.Files) _resultQueue.Add(SecurityCheck.CreateFileSystemEntry(new DirectoryInfo(fullPath), findData.dwFileAttributes, true, true));
                        }
                        else if (_searchFor != SearchFor.Directories)
                        {
                            long fileSize = ((long)findData.nFileSizeHigh << 32) | findData.nFileSizeLow;
                            _resultQueue.Add(SecurityCheck.CreateFileSystemEntry(new FileInfo(fullPath), findData.dwFileAttributes, true, true));
                        }
                    }
                    while (FindNextFile(hFind, findData));
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error processing directory {path}: {ex.Message}");
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
                        if (_directoryQueue.TryDequeue(out var current)) ProcessDirectory(current.path, current.depth);
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

        private static class SecurityCheck
        {
            public static FileSystemEntry CreateFileSystemEntry(FileSystemInfo fsi, FileAttributes fileAttributes, bool isOwner, bool isInherited)
            {
                try
                {
                    var currentAccountType = typeof(NTAccount);
                    var accessRules = GetAccessRules(fsi, currentAccountType, isInherited);
                    var owner = isOwner ? GetOwner(fsi, currentAccountType) : string.Empty;

                    return FileSystemEntry.Create(
                        fsi.FullName,
                        owner,
                        fileAttributes,
                        accessRules,
                        true,
                        string.Empty
                    );
                }
                catch (Exception ex)
                {
                    return FileSystemEntry.Create(
                        fsi.FullName,
                        string.Empty,
                        FileAttributes.None,
                        ImmutableDictionary<string, FileSystemRights>.Empty,
                        false,
                        GetErrorType(ex)
                    );
                }
            }
            public static ImmutableDictionary<string, FileSystemRights> GetAccessRules(FileSystemInfo fsi, Type currentAccountType, bool isInherited)
            {
                var accessRules = fsi switch
                {
                    DirectoryInfo di => di.GetAccessControl().GetAccessRules(true, isInherited, currentAccountType),
                    FileInfo fi => fi.GetAccessControl().GetAccessRules(true, isInherited, currentAccountType),
                    _ => null
                };

                return accessRules == null
                    ? ImmutableDictionary<string, FileSystemRights>.Empty
                    : accessRules.Cast<FileSystemAccessRule>()
                        .ToImmutableDictionary(x => x.IdentityReference.Value, x => x.FileSystemRights);
            }
            public static string GetOwner(FileSystemInfo fsi, Type currentAccountType)
            {
                try
                {
                    IdentityReference? owner = GetOwnerSwitch(fsi, currentAccountType);
                    return owner == null ? "Missing Owner" : owner.ToString();
                }
                catch (IdentityNotMappedException)
                {
                    return "Owner Sid unrecognized";
                }
            }
            private static IdentityReference? GetOwnerSwitch(FileSystemInfo fsi, Type currentAccountType) => fsi switch
            {
                DirectoryInfo di => di.GetAccessControl().GetOwner(currentAccountType),
                FileInfo fi => fi.GetAccessControl().GetOwner(currentAccountType),
                _ => null
            };
            private static string GetErrorType(Exception ex) => ex switch
            {
                UnauthorizedAccessException _ => "Authority level too low to check ACLs",
                PathTooLongException _ => "Path too long",
                DirectoryNotFoundException _ or FileNotFoundException _ => "Path not found",
                IOException _ => "IO Error happened",
                SecurityException _ => "Security error occurred",
                _ => "Unknown Error"
            };
        }
    }
}
