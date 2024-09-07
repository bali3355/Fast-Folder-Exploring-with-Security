using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace FolderExplore
{

    internal class FolderExplore
    {
        public static ConcurrentQueue<(string FullPath, string Identity, string Owner, string Rights, string ErrorMessage)> Results { get; set; } = [];
        private static bool _isInherited;
        private static bool _isOwner;

        /// <summary>
        /// Handle the file search
        /// </summary>
        #region Import from kernel32

        /// <summary>
        /// You can find more information on <seealso href="https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstfilew"/>
        /// </summary>
        /// <param name="lpFileName"></param>
        /// <param name="lpFindFileData"></param>
        /// <returns></returns>
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern SafeFindHandle FindFirstFileW(string lpFileName, out WIN32_FIND_DATA lpFindFileData);

        /// <summary>
        /// You can find more information on <seealso href="https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findnextfilew"/>
        /// </summary>
        /// <param name="hFindFile"></param>
        /// <param name="lpFindFileData"></param>
        /// <returns></returns>
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool FindNextFileW(SafeFindHandle hFindFile, out WIN32_FIND_DATA lpFindFileData);

        #endregion Import from kernel32

        /// <summary>
        /// Main Search Function for retrieve access list for files
        /// </summary>
        /// <param name="path"></param>
        /// <param name="isInherited"></param>
        /// <param name="isOwner"></param>
        /// <returns></returns>
        public static IEnumerable<(string FullPath, string Identity, string Owner, string Rights, string ErrorMessage)> Explore(string path, bool isInherited, bool isOwner)
        {
            _isInherited = isInherited;
            _isOwner = isOwner;
            GetFilesQueueParallel(path);
            return Results;
        }

        /// <summary>
        /// Searches for files in a given directory
        /// </summary>
        /// <param name="path"></param>
        public static void GetFilesQueueParallel(string path)
        {
            var folderQueue = new ConcurrentQueue<string>([path]);
            while (!folderQueue.IsEmpty)
            {
                var tmpQueue = folderQueue;
                folderQueue = [];
                _ = Parallel.ForEach(tmpQueue, (currentPath) =>
                {
                    foreach (var subDir in DirectorySearch(currentPath, "*")) folderQueue.Enqueue(subDir);
                    foreach (var subFile in FileSearch(currentPath, "*"))
                    {
                        foreach (var acl in SecurityFileInfo.GetInfo(new FileInfo(subFile), _isInherited, _isOwner)) 
                            Results.Enqueue(acl);
                    }
                });
            }
        }
          #region Search Types
        /// <summary>
        /// Searches for files in a given directory
        /// </summary>
        /// <param name="path"></param>
        /// <param name="searchPattern"></param>
        /// <returns></returns>
        private static IEnumerable<string> FileSearch(string path, string searchPattern)
        {
            using var findHandle = FindFirstFileW(Path.Combine(path, searchPattern), out WIN32_FIND_DATA findData);
            if (findHandle.IsInvalid) yield break;
            do
            {
                if ((findData.dwFileAttributes & FileAttributes.Directory) != 0 || findData.cFileName == "thumbs.db") continue;
                yield return Path.Combine(path, findData.cFileName);
            } while (FindNextFileW(findHandle, out findData));
        }

        /// <summary>
        /// Searches for folders in a given directory
        /// </summary>
        /// <param name="path"></param>
        /// <param name="searchPattern"></param>
        /// <returns></returns>
        private static IEnumerable<string> DirectorySearch(string path, string searchPattern)
        {
            using var findHandle = FindFirstFileW(Path.Combine(path, searchPattern), out WIN32_FIND_DATA findData);
            if (findHandle.IsInvalid) yield break;
            do
            {
                if ((findData.dwFileAttributes & FileAttributes.Directory) == 0 || findData.cFileName is "." or "..") continue;
                yield return Path.Combine(path, findData.cFileName);
            } while (FindNextFileW(findHandle, out findData));
        }
        #endregion Search Types
    }

    public static class SecurityFileInfo
    {

        private static bool _isInherited;
        private static bool _isOwner;
        private static Type _currentAccountType = typeof(NTAccount);

        /// <summary>
        /// Returns the access rules of a given <seealso cref="FileSystemInfo"/>
        /// </summary>
        /// <param name="path"></param>
        /// <param name="inherited"></param>
        /// <param name="owner"></param>
        /// <returns> <seealso cref="ConcurrentBag{T}"/></returns>
        public static ConcurrentQueue<(string FullName, string Identity, string Owner, string Rights, string ErrorMessage)> GetInfo(FileSystemInfo path, bool inherited, bool owner)
        {
            _isInherited = inherited;
            _isOwner = owner;
            _currentAccountType = typeof(NTAccount);
            return GetInfo(path);
        }

        /// <summary>
        /// Gets a path and returns a concurrent stack of ACL entries.
        /// </summary>
        /// <param name="path">Starting point with <seealso cref="fileSystemInfo"/></param>
        /// <returns>Concurrent Stack of ACL entries</returns>
        public static ConcurrentQueue<(string FullName, string Identity, string Owner, string Rights, string ErrorMessage)> GetInfo(FileSystemInfo path)
        {
            var securityResult = new ConcurrentQueue<(string FullName, string Identity, string Owner, string Rights, string ErrorMessage)>();
            AuthorizationRuleCollection? accessRules = null;

            try
            {
                accessRules = AccessRules(path, _currentAccountType);
                if (accessRules == null) return [];
                var owner = GetOwner(path, _currentAccountType);

                if (accessRules.Count > 0)
                {

#pragma warning disable CA1416 // This call site is reachable on all platforms. 'FileSystemAccessRule' is only supported on: 'windows'.

                    var rules = accessRules.Cast<FileSystemAccessRule>();
                    Parallel.ForEach(rules.Distinct(), acl =>
                                {
                                    securityResult.Enqueue((path.FullName, acl.IdentityReference.Value, owner, acl.FileSystemRights.ToString(), string.Empty));
                                });

#pragma warning restore CA1416 // This call site is reachable on all platforms. 'FileSystemAccessRule' is only supported on: 'windows'.

                }
            }
            catch (Exception ex)
            {
                securityResult.Enqueue(ErrorHandler.HandleException(ex, path.FullName));
            }
            return securityResult;
        }
        public static string GetOwner(FileSystemInfo fsi, Type currentAccountType)
        {
            if (!_isOwner) return string.Empty;
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
        public static AuthorizationRuleCollection? AccessRules(FileSystemInfo fileSystemInfo, Type currentAccountType) => fileSystemInfo switch
        {
            DirectoryInfo di => di.GetAccessControl().GetAccessRules(true, _isInherited, currentAccountType),
            FileInfo fi => fi.GetAccessControl().GetAccessRules(true, _isInherited, currentAccountType),
            _ => null
        };
    }

    public static class ErrorHandler
    {
        public static (string FullName, string Identity, string Owner, string Rights, string ErrorMessage) HandleException(Exception ex, string fullName)
        {
            string errorMessage = ex switch
            {
                UnauthorizedAccessException _ => "Authority level too low to check ACLs",
                PathTooLongException _ => "Path too long",
                DirectoryNotFoundException _ or FileNotFoundException _ => "Path not found",
                IOException _ => "IO Error happened",
                _ => "Unknown Error"
            };
            return (fullName, string.Empty, string.Empty, string.Empty, errorMessage);
        }
    }
}