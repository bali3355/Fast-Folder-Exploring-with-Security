using Microsoft.Win32.SafeHandles;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace FolderExplore
{
    public static class FolderExplore2
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="FileSystemFile"/> class with the specified parameters.
        /// </summary>
        /// <param name="path">The path of the file.</param>
        /// <param name="account">The account associated with the file.</param>
        /// <param name="accessType">The access type of the file.</param>
        /// <param name="owner">The owner of the file.</param>
        /// <param name="accessTypeDescription">The description of the access type.</param>
        /// <param name="error">The error message related to the file.</param>
        public class FileSystemFile(string path, string account, string accessType, string owner, string accessTypeDescription, string error, string modified = null)
        {
            public string Path { get; set; } = path;
            public string Account { get; set; } = account;
            public string AccessType { get; set; } = accessType;
            public string Owner { get; set; } = owner;
            public string Error { get; set; } = error;

            public override string ToString() => $"{Path} - {Account} - {AccessType} - {Owner} - {Error}";
            public FileSystemFile(string path, string account, string accessType, string owner) : this(path, account, accessType, owner, string.Empty) { }
            public FileSystemFile(string path, string account, string accessType, string owner, string error) : this(path, account, accessType, owner, error, string.Empty) { }
        }

        public static ConcurrentBag<FileSystemFile> Start(string path, bool isIncludeDirectories = true, bool isInherited = true, bool isOwner = true)
        {
            IsIncludeDirectories = isIncludeDirectories;
            IsInherited = isInherited;
            IsOwner = isOwner;
            _ = GetFiles(path);
            return ResultsConBag;
        }

        private static Task GetFiles(string path)
        {
            //var maxParallelism = new ParallelOptions { MaxDegreeOfParallelism = Convert.ToInt32(Math.Ceiling(Environment.ProcessorCount * 1.5)) };
            var subFiles = EnumerateFiles(path, "*");
            _ = Parallel.ForEach(subFiles,/* maxParallelism,*/ async (subFile) =>
            {
                var relativePathFiles = Path.Combine(path, subFile);
                await FillListOfResults(new FileInfo(relativePathFiles));
            });

            IEnumerable<string> subDirs = EnumerateDirectories(path, "*");
            _ = Parallel.ForEach(subDirs, /*maxParallelism,*/ async (subDir) =>
            {
                var relativePath = Path.Combine(path, subDir);
                if (IsIncludeDirectories) await FillListOfResults(new FileInfo(relativePath));
                await GetFiles(relativePath);
            });
            return Task.CompletedTask;
        }

        public static ConcurrentBag<FileSystemFile> ResultsConBag = [];
        private static bool IsIncludeDirectories;
        private static bool IsInherited;
        private static bool IsOwner;


        /// <summary>
        /// Fills <seealso cref="ResultsConBag"/>
        /// </summary>
        /// <param name="fileSystemInfo">Starting point with <seealso cref="mainfolder"/></param>
        private static Task FillListOfResults(FileSystemInfo fileSystemInfo)
        {
            try
            {
                Type currentAccountType = typeof(NTAccount);
                var accessRules = AccessRules(fileSystemInfo, IsInherited, currentAccountType);
                if (accessRules == null || accessRules.Count <= 0) return Task.CompletedTask;

                var owner = GetOwner(fileSystemInfo, IsOwner, currentAccountType);
                var rules = accessRules.Cast<FileSystemAccessRule>().Distinct();
                Parallel.ForEach(rules, acl =>
                {

                    ResultsConBag.Add(new FileSystemFile(fileSystemInfo.FullName, acl.IdentityReference.Value ,acl.FileSystemRights.ToString(), owner));
                });
            }
            catch (Exception ex)
            {
                var errorMessage = ex switch
                {
                    UnauthorizedAccessException _ => "Authority level too low to check ACLs",
                    PathTooLongException _ => "Path too long",
                    DirectoryNotFoundException _ or FileNotFoundException _ => "Path not found",
                    IOException _ => "IO Error happened",
                    _ => "Unknown Error"
                };
                ResultsConBag.Add(new FileSystemFile(fileSystemInfo.FullName, string.Empty, string.Empty, string.Empty, errorMessage));
            }
            return Task.CompletedTask;
        }

        private sealed class SafeFindHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            public SafeFindHandle() : base(true) { }
            protected override bool ReleaseHandle() => FindClose(handle);
        }

        #region Import from kernel32

        [Serializable, StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto), BestFitMapping(false)]
        internal struct WIN32_FIND_DATA
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
        }
        #endregion Import from kernel32

        private static string MakePath(string path, string searchPattern)
        {
            if (!path.EndsWith('\\')) path += "\\";
            return Path.Combine(path, searchPattern);
        }

        public static IEnumerable<string> EnumerateFiles(string path, string searchPattern)
        {
            return FileSearch(path, searchPattern);
        }

        public static IEnumerable<string> EnumerateDirectories(string path, string searchPattern)
        {
            return DirSearch(path, searchPattern);
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool FindClose(IntPtr hFindFile);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern SafeFindHandle FindFirstFileW(string lpFileName,
                                                   out WIN32_FIND_DATA lpFindFileData);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool FindNextFileW(SafeFindHandle hFindFile,
                                                out WIN32_FIND_DATA lpFindFileData);


        /// <summary>
        /// Searches for files and subdirectories in a specified path.
        /// </summary>
        /// <param name="path"></param>
        /// <param name="searchPattern"></param>
        /// <returns></returns>
        private static IEnumerable<string> FileSearch(string path, string searchPattern)
        {
            using var safeFindHandle = FindFirstFileW(Path.Combine(path, searchPattern), out WIN32_FIND_DATA findData);
            if (safeFindHandle.IsInvalid) yield break;
            do
            {
                if ((findData.dwFileAttributes & FileAttributes.Directory) != 0 || findData.cFileName == "thumbs.db") continue;
                yield return Path.Combine(path, findData.cFileName);
            } while (FindNextFileW(safeFindHandle, out findData));
        }

        /// <summary>
        /// Searches for subdirectories in a specified path.
        /// </summary>
        /// <param name="path"></param>
        /// <param name="searchPattern"></param>
        /// <returns></returns>
        private static IEnumerable<string> DirSearch(string path, string searchPattern)
        {
            using var safeFindHandle = FindFirstFileW(Path.Combine(path, searchPattern), out WIN32_FIND_DATA findData);
            if (safeFindHandle.IsInvalid) yield break;
            do
            {
                if ((findData.dwFileAttributes & FileAttributes.Directory) == 0 || findData.cFileName is "." or "..") continue;
                yield return Path.Combine(path, findData.cFileName);
            } while (FindNextFileW(safeFindHandle, out findData));
        }

        /// <summary>
        /// Returns the owner of a given <seealso cref="DirectoryInfo"/>
        /// </summary>
        /// <returns>The owner in string format.</returns>
        public static string GetOwner(DirectoryInfo di, Type currentAccountType)
        {
            try
            {
                var owner = di.GetAccessControl().GetOwner(currentAccountType);
                return owner == null ? "Missing Owner" : owner.ToString();
            }
            catch (IdentityNotMappedException)
            {
                return "Owner ID unrecognised";
            }
        }

        /// <summary>
        /// Returns the owner of a given <seealso cref="FileInfo"/>
        /// </summary>
        /// <returns></returns>
        public static string GetOwner(FileInfo fi, Type currentAccountType)
        {
            try
            {
                var owner = fi.GetAccessControl().GetOwner(currentAccountType);
                return owner == null ? "Missing Owner" : owner.ToString();
            }
            catch (IdentityNotMappedException)
            {
                return "Owner ID unrecognised";
            }
        }

        /// <summary>
        /// Returns the access rules of a given <seealso cref="FileSystemInfo"/>
        /// </summary>
        /// <param name="fileSystemInfo"></param>
        /// <param name="inherited"></param>
        /// <param name="currentAccountType"></param>
        /// <returns></returns>
        public static AuthorizationRuleCollection? AccessRules(FileSystemInfo fileSystemInfo, bool inherited, Type currentAccountType)
        {
            if (fileSystemInfo is DirectoryInfo directoryInfo) return directoryInfo.GetAccessControl().GetAccessRules(true, inherited, currentAccountType);
            else if (fileSystemInfo is FileInfo fileInfo) return fileInfo.GetAccessControl().GetAccessRules(true, inherited, currentAccountType);
            return null;
        }

        /// <summary>
        /// Returns the owner of a given <seealso cref="FileSystemInfo"/>
        /// </summary>
        /// <param name="fileSystemInfo"></param>
        /// <param name="isNeedOwner"></param>
        /// <param name="currentAccountType"></param>
        /// <returns></returns>
        public static string GetOwner(FileSystemInfo fileSystemInfo, bool isNeedOwner, Type currentAccountType)
        {
            if (!isNeedOwner) return string.Empty;
            if (fileSystemInfo is DirectoryInfo directoryInfo) return GetOwner(directoryInfo, currentAccountType);
            else if (fileSystemInfo is FileInfo fileInfo) GetOwner(fileInfo, currentAccountType);
            return string.Empty;
        }
    }


}
