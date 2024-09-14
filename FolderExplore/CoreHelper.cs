using Microsoft.Win32.SafeHandles;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace FolderExplore
{
    public enum SearchFor
    {
        Files,
        Directories,
        FilesAndDirectories
    }
    sealed class SafeFindHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeFindHandle() : base(true) { }
        protected override bool ReleaseHandle() => FindClose(handle);

        //https://stackoverflow.com/questions/17918266/winapi-getlasterror-vs-marshal-getlastwin32error#17918729
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool FindClose(IntPtr hFindFile);
    }

    [Serializable, StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto), BestFitMapping(false)]
    public struct WIN32_FIND_DATA
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

    /// <summary>
    /// Contains a class for return file information from FindFirstFile or FindNextFile
    /// </summary>
    [StructLayout(LayoutKind.Auto)]
    public readonly struct FileSystemEntry
    {
        public string Path { get; }
        public string Owner { get; }
        public FileAttributes FileEntryAttributes { get; }
        public ImmutableDictionary<string, FileSystemRights> AccessControlList { get; }
        public bool IsModified { get; }
        public string Error { get; }

        private FileSystemEntry(string path, string owner, FileAttributes fileEntryAttributes, ImmutableDictionary<string, FileSystemRights> acl, bool isModified, string error)
        {
            Path = path;
            FileEntryAttributes = fileEntryAttributes;
            Owner = owner;
            AccessControlList = acl ?? ImmutableDictionary<string, FileSystemRights>.Empty;
            IsModified = isModified;
            Error = error;
        }

        public static FileSystemEntry Create(string path, string owner = null, FileAttributes fileEntryAttributes = FileAttributes.None, ImmutableDictionary<string, FileSystemRights> acl = null, bool isModified = false, string error = null)
        {
            if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("Path cannot be null or whitespace.", nameof(path));

            return new FileSystemEntry(path, owner, fileEntryAttributes, acl, isModified, error);
        }

        public override string ToString()
        {
            return $"Path: {Path}, Owner: {Owner ?? "-"}, ACL Count: {AccessControlList.Count}, Modified: {IsModified}, Error: {Error ?? "-"}";
        }

        public bool HasError => !string.IsNullOrWhiteSpace(Error);
    }

    [Serializable]
    public static class NativeWinAPI
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public int Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool GetFileSecurity(
            string lpFileName,
            uint RequestedInformation,
            IntPtr pSecurityDescriptor,
            uint nLength,
            out uint lpnLengthNeeded);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool GetSecurityDescriptorOwner(
            IntPtr pSecurityDescriptor,
            out IntPtr pOwner,
            out bool lpbOwnerDefaulted);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool LookupAccountSid(
            string lpSystemName,
            IntPtr Sid,
            StringBuilder lpName,
            ref uint cchName,
            StringBuilder ReferencedDomainName,
            ref uint cchReferencedDomainName,
            out int peUse);
    }

    public static class SecurityCheck
    {
        private static ConcurrentDictionary<string, string> SidOwnerCache { get; set; } = [];
        public static void CacheClear() => SidOwnerCache.Clear();
        public static FileSystemEntry CreateFileSystemEntry(FileSystemInfo fsi, bool isNative, FileAttributes fileAttributes, bool isOwner, bool isInherited)
        {
            try
            {
                var currentAccountType = typeof(NTAccount);
                var accessRules = GetAccessRules(fsi, currentAccountType, isInherited);
                var owner = isOwner ? isNative ? NativeGetOwner(fsi, currentAccountType) : GetOwner(fsi, currentAccountType) : string.Empty;
                var error = string.Empty;
                if (owner.StartsWith("Unknown Owner"))
                {
                    error = owner;
                    owner = string.Empty;
                }
                return FileSystemEntry.Create(
                    fsi.FullName,
                    owner,
                    fileAttributes,
                    accessRules,
                    true,
                    error
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

        private static T HandleFileSystemInfo<T>(FileSystemInfo fsi, Func<DirectoryInfo, T> dirHandler, Func<FileInfo, T> fileHandler) => fsi switch
        {
            DirectoryInfo di => dirHandler(di),
            FileInfo fi => fileHandler(fi),
            _ => default
        };
        public static ImmutableDictionary<string, FileSystemRights> GetAccessRules(FileSystemInfo fsi, Type currentAccountType, bool isInherited)
        {
            var accessRules = HandleFileSystemInfo(fsi,
                di => di.GetAccessControl().GetAccessRules(true, isInherited, currentAccountType),
                fi => fi.GetAccessControl().GetAccessRules(true, isInherited, currentAccountType));

            return accessRules == null
                ? ImmutableDictionary<string, FileSystemRights>.Empty
                : accessRules.Cast<FileSystemAccessRule>()
                    .ToImmutableDictionary(static x => x.IdentityReference.Value, static x => x.FileSystemRights);
        }
        public static string GetOwner(FileSystemInfo fsi, Type currentAccountType)
        {
            try
            {
                var owner = HandleFileSystemInfo(fsi,
                    di => di.GetAccessControl().GetOwner(currentAccountType),
                    fi => fi.GetAccessControl().GetOwner(currentAccountType));
                return owner == null ? "Owner Missing" : owner.Value;
            }
            catch (IdentityNotMappedException ex)
            {
                return $"Unknown Owner, unable to get current Owner SID: {ex.Message}";
            }
        }
        private static string GetErrorType(Exception ex) => ex switch
        {
            UnauthorizedAccessException => "Authority level too low to check ACLs",
            PathTooLongException => "Path too long",
            DirectoryNotFoundException or FileNotFoundException => "Path not found",
            IOException => $"IO Error occured: {ex.Message}",
            SecurityException => $"Security error occurred: {ex.Message}",
            _ => $"Unknown Error: {ex.GetType().Name} - {ex.Message}"
        };

        public static string NativeGetOwner(FileSystemInfo path, Type currentAccountType)
        {
            //It's set to 0x00000001, which corresponds to OWNER_SECURITY_INFORMATION.
            NativeWinAPI.GetFileSecurity(path.FullName, 0x00000001, IntPtr.Zero, 0, out uint length);

            IntPtr securityDescriptor = Marshal.AllocHGlobal((int)length);
            try
            {
                if (!NativeWinAPI.GetFileSecurity(path.FullName, 0x00000001, securityDescriptor, length, out _))
                    throw new SecurityException($"Unknown Owner, no access (Error Code: {Marshal.GetLastWin32Error()}) to path: {path.FullName}");

                if (!NativeWinAPI.GetSecurityDescriptorOwner(securityDescriptor, out IntPtr ownerSid, out _))
                    throw new SecurityException($"Unknown Owner (Error code: {Marshal.GetLastWin32Error()}), unable to get Owner SID: {path.FullName}");

                return TranslateSidToAccountName(ownerSid);
            }
            catch (SecurityException SEx)
            {
                Debug.WriteLine("Trying GetAccessControl.GetOwner");
                var fallbackGetOwner = GetOwner(path, currentAccountType);
                if (!string.IsNullOrEmpty(fallbackGetOwner) || !fallbackGetOwner.StartsWith("Owner") || !fallbackGetOwner.StartsWith("Unknown")) return fallbackGetOwner;
                else return SEx.Message;
            }
            catch (Exception ex)
            {
                Debug.WriteLine(path.FullName + " : " + ex.Message);
                return "Unknown Owner, unable to get Owner SID";
            }
            finally
            {
                Marshal.FreeHGlobal(securityDescriptor);
            }
        }

        private static string TranslateSidToAccountName(IntPtr ownerSid) => GetSidToAccountName(ownerSid);

        private static string GetSidToAccountName(nint ownerSid)
        {
            var AccountToStringSID = ConvertToAccount(ownerSid);
            try
            {
                if (SidOwnerCache.TryGetValue(AccountToStringSID, out string Account)) return Account;

                uint nameLength = 0;
                uint domainLength = 0;
                // First call to get required buffer sizes
                NativeWinAPI.LookupAccountSid(null, ownerSid, null, ref nameLength, null, ref domainLength, out int sidUse);

                if (nameLength == 0 && domainLength == 0)
                {
                    SidOwnerCache.TryAdd(AccountToStringSID, AccountToStringSID);
                    return AccountToStringSID;
                }


                StringBuilder name = new((int)nameLength);
                StringBuilder domain = new((int)domainLength);

                //Load the account into buffered pointers
                if (NativeWinAPI.LookupAccountSid(null, ownerSid, name, ref nameLength, domain, ref domainLength, out sidUse))
                {
                    var resultAccount = domain.Length > 0 ? $"{domain}\\{name}" : name.ToString();
                    SidOwnerCache.TryAdd(AccountToStringSID, resultAccount);
                    return resultAccount;
                }
                else
                {
                    SidOwnerCache.TryAdd(AccountToStringSID, AccountToStringSID);
                    return AccountToStringSID;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
                return AccountToStringSID;
            }
        }

        private static string ConvertToAccount(IntPtr ownerSid) => NativeWinAPI.ConvertSidToStringSid(ownerSid, out string accountSid)
                ? accountSid
                : "Unknown Owner, unable to convert owner SID to string";
    }
}
