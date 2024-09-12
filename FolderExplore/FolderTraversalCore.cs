using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace FolderExplore
{
    public static class FolderTraversalCore
    {
        private static ConcurrentQueue<FileSystemEntry> ConcurrentResults = [];
        private static ConcurrentQueue<string> ConcurrentResultsString = [];
        private static SearchFor? _SearchFor = SearchFor.Files;
        private static bool IsInherited;
        private static bool IsOwner;

        #region Methods for reading files and directories from WinAPI32

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern SafeFindHandle FindFirstFileW(string lpFileName, out WIN32_FIND_DATA lpFindFileData);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool FindNextFileW(SafeFindHandle hFindFile, out WIN32_FIND_DATA lpFindFileData);

        private static IEnumerable<(string path, WIN32_FIND_DATA findData)> CallEnumerateFile(string path, string searchPattern)
        {
            using var safeFindHandle = FindFirstFileW(Path.Combine(path, searchPattern), out WIN32_FIND_DATA _findData);
            if (safeFindHandle.IsInvalid) yield break;
            do
            {
                if ((_findData.dwFileAttributes & FileAttributes.Directory) != 0 || IsToLeftOut(_findData.cFileName)) continue;
                yield return (Path.Combine(path, _findData.cFileName), _findData);
            } while (FindNextFileW(safeFindHandle, out _findData));
        }
        private static IEnumerable<(string path, WIN32_FIND_DATA findData)> CallEnumerateDirectory(string path, string searchPattern)
        {
            using var safeFindHandle = FindFirstFileW(Path.Combine(path, searchPattern), out WIN32_FIND_DATA _findData);
            if (safeFindHandle.IsInvalid) yield break;
            do
            {
                if ((_findData.dwFileAttributes & FileAttributes.Directory) == 0 || IsToLeftOut(_findData.cFileName)) continue;
                yield return (Path.Combine(path, _findData.cFileName), _findData);
            } while (FindNextFileW(safeFindHandle, out _findData));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsToLeftOut(string fileName) => fileName switch
        {
            "." or ".." or "Thumbs.db" => true,
            _ => false
        };

        #endregion

        #region Folder Traversing Methods

        /// <summary>
        /// Searches for files and subdirectories in a specified path. Leave out thumb.db and stop when all files have been found.
        /// </summary>
        /// <param name="path"></param>
        /// <param name="searchPattern"></param>
        /// <returns></returns>
        public static IEnumerable<(string path, WIN32_FIND_DATA findData)> EnumerateFiles(string path, string searchPattern) => CallEnumerateFile(path, searchPattern);
        /// <summary>
        /// Searches for subdirectories in a specified path. Leave out reparse points and stop when all files have been found.
        /// </summary>
        /// <param name="path"></param>
        /// <param name="searchPattern"></param>
        /// <returns></returns>
        public static IEnumerable<(string path, WIN32_FIND_DATA findData)> EnumerateDirectory(string path, string searchPattern) => CallEnumerateDirectory(path, searchPattern);

        #endregion


        public static IEnumerable<FileSystemEntry> Start(string path, SearchFor searchFor = SearchFor.Files, bool isInherited = true, bool isOwner = true)
        {
            IsInherited = isInherited;
            IsOwner = isOwner;
            _SearchFor = searchFor;
            return GetFileSystemEntries(path);
        }
        public static IEnumerable<string> GetFiles(string path, SearchFor searchFor = SearchFor.Files)
        {
            _SearchFor = _SearchFor ?? searchFor;
            try
            {
                var folderQueue = new ConcurrentQueue<string>([path]);
                while (!folderQueue.IsEmpty) folderQueue = InternalGetFiles(folderQueue);
                return ConcurrentResultsString;
            }
            finally
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();
            }
        }

        private static ConcurrentQueue<string> InternalGetFiles(ConcurrentQueue<string> folderQueue)
        {
            var tmpQueue = folderQueue;
            folderQueue = [];
            Parallel.ForEach(tmpQueue, (currentPath) =>
            {
                foreach (var subDir in EnumerateDirectory(currentPath, "*"))
                {
                    if (_SearchFor != SearchFor.Files) ConcurrentResultsString.Enqueue(subDir.path);
                    folderQueue.Enqueue(subDir.path);
                }
                if (_SearchFor != SearchFor.Directories) foreach (var subFile in EnumerateFiles(currentPath, "*")) ConcurrentResultsString.Enqueue(subFile.path);
            });
            return folderQueue;
        }
        public static IEnumerable<FileSystemEntry> GetFileSystemEntries(string path, SearchFor? searchFor = SearchFor.Files)
        {
            _SearchFor = searchFor ?? SearchFor.Files;
            try
            {
                var folderQueue = new ConcurrentQueue<string>([path]);
                while (!folderQueue.IsEmpty) folderQueue = TraverseFileSystem(folderQueue);
                return ConcurrentResults;
            }
            finally
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();
            }
        }

        private static ConcurrentQueue<string> TraverseFileSystem(ConcurrentQueue<string> folderQueue)
        {
            var tmpQueue = folderQueue;
            folderQueue = [];
            Parallel.ForEach(tmpQueue, (currentDirectory) =>
                {

                    foreach (var (dirPath, dirFindData) in EnumerateDirectory(currentDirectory, "*"))
                    {
                        folderQueue.Enqueue(dirPath);
                        if (_SearchFor != SearchFor.Files) ConcurrentResults.Enqueue(SecurityCheck.CreateFileSystemEntry(new DirectoryInfo(dirPath), false, dirFindData.dwFileAttributes, IsOwner, IsInherited));
                    }
                    if (_SearchFor != SearchFor.Directories)
                    {
                        foreach (var (filePath, fileFindData) in EnumerateFiles(currentDirectory, "*"))
                        {
                            ConcurrentResults.Enqueue(SecurityCheck.CreateFileSystemEntry(new FileInfo(filePath), false, fileFindData.dwFileAttributes, IsOwner, IsInherited));
                        }
                    }
                });
            return folderQueue;
        }
    }
}
