using Microsoft.Win32.SafeHandles;
using System.Collections.Immutable;
using System.Runtime.InteropServices;
using System.Security.AccessControl;

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
}
