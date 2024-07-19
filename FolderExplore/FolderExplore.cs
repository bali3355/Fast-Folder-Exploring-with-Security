using Microsoft.Win32.SafeHandles;
using System.Collections;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace FolderExploring
{
    public class FileEntry
    {
        public FileEntry(string path)
        {
            FullName = path;
        }

        public FileEntry() { }
        public string FullName { get; set; }
        public FileAttributes Attributes { get; set; }
        public string Owner { get; set; }
        public List<AclEntry> ACL { get; set; } = [];
        public string Error { get; set; }

        public bool Exists => File.Exists(FullName);
        public override string ToString() => FullName;
    }

    public class AclEntry
    {
        public string Identity { get; set; }
        public string AccessType { get; set; }
    }

    public static class FolderExplore
    {
        public static IEnumerable<FileEntry> EnumerateFileSystem(
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

        private class FileEnumerable : IEnumerable<FileEntry>
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

            public IEnumerator<FileEntry> GetEnumerator()
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

        private class ParallelFileEnumerator : IEnumerator<FileEntry>
        {
            private readonly string _initialPath;
            private readonly string _searchPattern;
            private readonly SearchOption _searchOption;
            private readonly SearchFor _searchFor;
            private readonly int _maxDegreeOfParallelism;
            private readonly CancellationToken _cancellationToken;
            private readonly ConcurrentStack<(string path, int depth)> _directoryStack;
            private readonly BlockingCollection<FileEntry> _resultQueue;
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
                _resultQueue = new BlockingCollection<FileEntry>(new ConcurrentQueue<FileEntry>());
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
                        var fileEntry = new FileEntry(fullPath)
                        {
                            Attributes = findData.dwFileAttributes,
                        };

                        try
                        {
                            SecurityInfoRetriever.GetSecurityInfo(fileEntry);
                        }
                        catch (Exception ex)
                        {
                            fileEntry.Error = $"Failed to retrieve security info: {ex.Message}";
                        }

                        if (fileEntry.Attributes.HasFlag(FileAttributes.Directory))
                        {
                            if (_searchOption == SearchOption.AllDirectories)
                            {
                                _directoryStack.Push((fullPath, depth + 1));
                            }

                            if (_searchFor is SearchFor.Directories or SearchFor.FilesAndDirectories)
                                _resultQueue.Add(fileEntry);
                        }
                        else if (_searchFor is SearchFor.Files or SearchFor.FilesAndDirectories)
                        {
                            _resultQueue.Add(fileEntry);
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


            public FileEntry Current { get; private set; }

            object IEnumerator.Current => Current;

            public void Reset() => throw new NotSupportedException();
        }
    }

    public static class SecurityInfoRetriever
    {
        #region Structures

        [StructLayout(LayoutKind.Sequential)]
        private struct ACE_HEADER
        {
            public byte AceType;
            public byte AceFlags;
            public ushort AceSize;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ACL_SIZE_INFORMATION
        {
            public uint AceCount;
            public uint AclBytesInUse;
            public uint AclBytesFree;
        }

        [Flags]
        private enum SecurityInformation : uint
        {
            Owner = 0x00000001,
            Group = 0x00000002,
            Dacl = 0x00000004,
            Sacl = 0x00000008
        }

        private enum SE_OBJECT_TYPE
        {
            SE_FILE_OBJECT = 1
        }
        #endregion

        #region WinAPI Imports
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint GetNamedSecurityInfo(
            string pObjectName,
            SE_OBJECT_TYPE ObjectType,
            SecurityInformation SecurityInfo,
            out IntPtr pSidOwner,
            out IntPtr pSidGroup,
            out IntPtr pDacl,
            out IntPtr pSacl,
            out IntPtr pSecurityDescriptor);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetAclInformation(
            IntPtr pAcl,
            out ACL_SIZE_INFORMATION pAclInformation,
            uint nAclInformationLength,
            uint dwAclInformationClass);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetAce(IntPtr pAcl, uint dwAceIndex, out IntPtr pAce);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool LookupAccountSid(
            string lpSystemName,
            IntPtr Sid,
            StringBuilder lpName,
            ref uint cchName,
            StringBuilder lpReferencedDomainName,
            ref uint cchReferencedDomainName,
            out int peUse);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr hMem);

        #endregion

        private static readonly ConcurrentDictionary<string, string> _ownerCache = [];
        private static readonly ConcurrentDictionary<IntPtr, string> _sidCache = [];
        private static readonly ObjectPool<StringBuilder> _stringBuilderPool = new(() => new StringBuilder(256), Environment.ProcessorCount * 2);
        private static readonly ObjectPool<List<AclEntry>> _aclListPool = new(() => [], Environment.ProcessorCount * 2);

        public static FileEntry GetFileInfo(string path)
        {
            var fileEntry = new FileEntry { FullName = path };

            IntPtr pSecurityDescriptor = IntPtr.Zero;
            var aclList = _aclListPool.Rent();

            try
            {
                fileEntry.Attributes = File.GetAttributes(path);

                uint result = GetNamedSecurityInfo(path, SE_OBJECT_TYPE.SE_FILE_OBJECT,
                    SecurityInformation.Owner | SecurityInformation.Dacl,
                    out IntPtr pSidOwner, out _, out IntPtr pDacl, out _, out pSecurityDescriptor);

                if (result != 0) throw new Exception($"GetNamedSecurityInfo failed with error code: {result}");

                fileEntry.Owner = GetSidString(pSidOwner);
                ProcessAcl(pDacl, aclList);

                fileEntry.ACL = aclList;
            }
            catch (Exception ex)
            {
                // Handle or log the exception as needed
                fileEntry.Owner = "";
                fileEntry.ACL = [];
                fileEntry.Error = ex.Message;
            }
            finally
            {
                if (pSecurityDescriptor != IntPtr.Zero) LocalFree(pSecurityDescriptor);
            }

            return fileEntry;
        }

        private static void ProcessAcl(IntPtr pDacl, List<AclEntry> aclList)
        {
            if (pDacl == IntPtr.Zero) return;
            if (!GetAclInformation(pDacl, out ACL_SIZE_INFORMATION aclInfo, (uint)Marshal.SizeOf(typeof(ACL_SIZE_INFORMATION)), 2)) return;

            for (uint i = 0; i < aclInfo.AceCount; i++)
            {
                if (!GetAce(pDacl, i, out IntPtr pAce)) continue;
                ProcessAce(pAce, aclList);
            }
        }

        private static void ProcessAce(IntPtr pAce, List<AclEntry> aclList)
        {
            int mask = Marshal.ReadInt32(pAce, 4);
            IntPtr pSid = new IntPtr(pAce.ToInt64() + 8);
            string sidString = GetSidString(pSid);
            string accessType = GetAccessType((uint)mask);

            aclList.Add(new AclEntry
            {
                Identity = sidString,
                AccessType = accessType
            });
        }

        private static string GetSidString(IntPtr pSid)
        {
            return _sidCache.GetOrAdd(pSid, sid =>
            {
                var name = _stringBuilderPool.Rent();
                var domain = _stringBuilderPool.Rent();
                try
                {
                    uint nameLen = 256, domainLen = 256;

                    return LookupAccountSid(null, sid, name, ref nameLen, domain, ref domainLen, out int sidUse) ? $"{domain}\\{name}" : "-";
                }
                finally
                {
                    _stringBuilderPool.Return(name);
                    _stringBuilderPool.Return(domain);
                }
            });
        }

        private static string GetAccessType(uint mask)
        {
            if ((mask & 0x1F01FF) == 0x1F01FF) return "Full Control";
            if ((mask & 0x1301BF) == 0x1301BF) return "Modify";
            if ((mask & 0x1201BF) == 0x1201BF) return "Write";
            if ((mask & 0x1200A9) == 0x1200A9) return "Read";
            return "Special";
        }

        public static void GetSecurityInfo(FileEntry fileEntry)
        {
            IntPtr pSecurityDescriptor = IntPtr.Zero;

            try
            {
                uint result = GetNamedSecurityInfo(fileEntry.FullName, SE_OBJECT_TYPE.SE_FILE_OBJECT,
                    SecurityInformation.Owner | SecurityInformation.Dacl,
                    out IntPtr pSidOwner, out _, out IntPtr pDacl, out _, out pSecurityDescriptor);

                if (result != 0) throw new Exception($"GetNamedSecurityInfo failed with error code: {result}");

                fileEntry.Owner = GetSidString(pSidOwner);
                ProcessAcl(pDacl, fileEntry.ACL);
            }
            finally
            {
                if (pSecurityDescriptor != IntPtr.Zero) LocalFree(pSecurityDescriptor);
            }
        }

        // ... (Keep other methods of SecurityInfoRetriever)
    }


    public enum SearchFor
    {
        Files = 0,
        Directories = 1,
        FilesAndDirectories = 2,
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
    // ... (Keep the ObjectPool class implementation)
}
