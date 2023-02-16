using System;
using System.Runtime.InteropServices;

namespace ThreadlessInject;

public static class Win32
{
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObj);

    [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    public static extern IntPtr GetProcAddress(
        IntPtr hModule,
        string procName);

    [Flags]
    public enum ProcessAccess : uint
    {
        None = 0,
        Terminate = 0x0001,
        CreateThread = 0x0002,
        SetSessionId = 0x0004,
        VmOperation = 0x0008,
        VmRead = 0x0010,
        VmWrite = 0x0020,
        DupHandle = 0x0040,
        CreateProcess = 0x0080,
        SetQuota = 0x0100,
        SetInformation = 0x0200,
        QueryInformation = 0x0400,
        SuspendResume = 0x0800,
        QueryLimitedInformation = 0x1000,
        SetLimitedInformation = 0x2000,
        AllAccess = 0x1FFFFF
    }
    
    [Flags]
    public enum MemoryAllocation : uint
    {
        Commit = 0x1000,
        Reserve = 0x2000,
        Reset = 0x80000,
        ResetUndo = 0x1000000,
        LargePages = 0x20000000,
        Physical = 0x400000,
        TopDown = 0x100000,
        WriteWatch = 0x200000,
        CoalescePlaceholders = 0x1,
        PreservePlaceholder = 0x2,
        Decommit = 0x4000,
        Release = 0x8000
    }
        
    [Flags]
    public enum MemoryProtection : uint
    {
        PageNoAccess = 0x01,
        Readonly = 0x02,
        ReadWrite = 0x04,
        WriteCopy = 0x08,
        Execute = 0x10,
        ExecuteRead = 0x20,
        ExecuteReadWrite = 0x40,
        ExecuteWriteCopy = 0x80,
        Guard = 0x100,
        NoCache = 0x200,
        WriteCombine = 0x400,
        TargetsInvalid = 0x40000000,
        TargetsNoUpdate = 0x40000000
    }
}