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
            return $"Path: {Path}, Owner: {Owner ?? "N/A"}, ACL Count: {AccessControlList.Count}, Modified: {IsModified}, Error: {Error ?? "None"}";
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

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr LocalFree(IntPtr hMem);
    }

    public static class SecurityCheck
    {
        private static readonly ConcurrentDictionary<IntPtr, string> _sidOwnerCache = [];
        public static FileSystemEntry CreateFileSystemEntry(FileSystemInfo fsi, bool isNative, FileAttributes fileAttributes, bool isOwner, bool isInherited)
        {
            try
            {
                var currentAccountType = typeof(NTAccount);
                var accessRules = GetAccessRules(fsi, currentAccountType, isInherited);
                var owner = isOwner ? isNative ? NativeGetOwner(fsi,currentAccountType) : GetOwner(fsi, currentAccountType) : string.Empty;
                //if (owner.Contains("SZOLG")) Console.WriteLine(fsi.FullName + " | " + owner);
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
                return owner == null ? "Missing Owner" : owner.ToString();
            }
            catch (IdentityNotMappedException)
            {
                return "Owner Sid unrecognized";
            }
        }
        private static string GetErrorType(Exception ex) => ex switch
        {
            UnauthorizedAccessException _ => "Authority level too low to check ACLs",
            PathTooLongException _ => "Path too long",
            DirectoryNotFoundException _ or FileNotFoundException _ => "Path not found",
            IOException _ => $"IO Error occured: {ex.Message}",
            SecurityException _ => $"Security error occurred: {ex.Message}",
            _ => $"Unknown Error: {ex.GetType().Name} - {ex.Message}"
        };

        public static string NativeGetOwner(FileSystemInfo path, Type currentAccountType)
        {
            NativeWinAPI.GetFileSecurity(path.FullName, 0x00000001, IntPtr.Zero, 0, out uint length);

            IntPtr securityDescriptor = Marshal.AllocHGlobal((int)length);
            try
            {
                if (!NativeWinAPI.GetFileSecurity(path.FullName, 0x00000001, securityDescriptor, length, out _))
                    return GetOwner(path, currentAccountType);
                if (!NativeWinAPI.GetSecurityDescriptorOwner(securityDescriptor, out IntPtr ownerSid, out _)) 
                    return "Unknown Owner, unable to get Owner SID";
                return TranslateSidToAccountName(ownerSid);
            }
            catch
            {
                return "Unknown Owner, unable to get Owner SID";
            }
            finally
            {
                Marshal.FreeHGlobal(securityDescriptor);
            }
        }

        private static string TranslateSidToAccountName(IntPtr ownerSid)
        {
            if (_sidOwnerCache.TryGetValue(ownerSid, out string accountName)) return accountName;
            else
            {
                accountName = GetSidToAccountName(ownerSid);
                _sidOwnerCache.TryAdd(ownerSid, accountName);
                return accountName;
            }
        }

        private static string GetSidToAccountName(nint ownerSid)
        {
            try
            {
                uint nameLength = 0;
                uint domainLength = 0;
                // First call to get required buffer sizes
                NativeWinAPI.LookupAccountSid(null, ownerSid, null, ref nameLength, null, ref domainLength, out int sidUse);

                if (nameLength == 0 && domainLength == 0) return ConvertToAccount(ownerSid);


                StringBuilder name = new((int)nameLength);
                StringBuilder domain = new((int)domainLength);

                if (NativeWinAPI.LookupAccountSid(null, ownerSid, name, ref nameLength, domain, ref domainLength, out sidUse))
                {
                    if (domain.Length > 0) return $"{domain}\\{name}";
                    else return name.ToString();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
            }
            return ConvertToAccount(ownerSid);
        }

        private static string ConvertToAccount(IntPtr ownerSid)
        {
            if (NativeWinAPI.ConvertSidToStringSid(ownerSid, out string accountSid)) return accountSid;
            return "Unknown Owner, unable to convert owner SID to string";
        }
    }
}
