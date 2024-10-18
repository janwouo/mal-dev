#include <windows.h>
#include <stdio.h>
#include "../utils/utility.h"


int main(int argc, char const *argv[])
{
    HANDLE                 processHandle        = NULL; 
    HANDLE                 threadHandle         = NULL;
    HMODULE                moduleHandle         = NULL;
    LPTHREAD_START_ROUTINE funcAddr             = NULL;
    LPVOID                 paramAddr            = NULL;
    LPCSTR                 dllPath              = argv[2]; 
    DWORD                  TID                  = 0;
    DWORD                  dllPathSize;
    DWORD                  pid;

    if (argc < 3) {
		MESSAGE(FAIL, "Usage: %s <PID> <DLL-FULL-PATH>\n", argv[0]);
		return EXIT_FAILURE;
	}
    pid = atoi(argv[1]);
    dllPathSize = strlen(dllPath);

    MESSAGE(INFO, "DLL injector pid[%ld]\n", GetCurrentProcessId());
    MESSAGE(INFO, "Trying to open a process[%ld] and load '%s' in its address space\n", pid, dllPath);
    MESSAGE(OKAY, "Press <enter> to continue...\n");
    getchar();
    
    // Open handle to the process
    processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    if (processHandle == NULL){
        MESSAGE(FAIL, "Impossible to get handle of the process[%ld]\n", pid);
        PRINT_ERROR("OpenProcess");
        return EXIT_FAILURE;
    }
    MESSAGE(OKAY, "Process[%ld] opened: Handle got[0x%p]\n", pid, processHandle);

    // LPVOID VirtualAllocEx(
    //   [in]           HANDLE processHandle,
    //   [in, optional] LPVOID lpAddress,
    //   [in]           SIZE_T dwSize,
    //   [in]           DWORD  flAllocationType,
    //   [in]           DWORD  flProtect
    // );

    // Allocate bytes to process memory
    allocateAndCopyRemote(processHandle, &paramAddr, (LPCVOID)dllPath, dllPathSize);
    // paramAddr = VirtualAllocEx(processHandle, NULL, dllPathSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
    // if (paramAddr == NULL){
    //     MESSAGE(FAIL, "Impossible to allocate memory in process[%ld]\n", pid);
    //     PRINT_ERROR("VirtualAllocEx");
    //     return EXIT_FAILURE;
    // }
    // MESSAGE(OKAY, "%ld bytes of memory successfully allocated in process[%ld]\n", dllPathSize, pid);

    // // BOOL WriteProcessMemory(
    // //   [in]  HANDLE  processHandle,
    // //   [in]  LPVOID  lpBaseAddress,
    // //   [in]  LPCVOID lpBuffer,
    // //   [in]  SIZE_T  nSize,
    // //   [out] SIZE_T  *lpNumberOfBytesWritten
    // // );

    // // Write bytes(dll path) to process allocated memory
    // if (WriteProcessMemory(processHandle, paramAddr, dllPath, dllPathSize, NULL) == 0){
    //     MESSAGE(FAIL, "Impossible to write dll path to process[%ld]\n", pid);
    //     PRINT_ERROR("WriteProcessMemory");
    //     return EXIT_FAILURE;
    // }
    // MESSAGE(OKAY, "DLL path \"%s\" successfully wrote in memory of process[%ld]\n", dllPath, pid);

    // HMODULE GetModuleHandle(
    //   [in, optional] LPCWSTR lpModuleName
    // );

    // Get handle of kernl32 module
    moduleHandle = GetModuleHandle("kernel32");
    if (moduleHandle == NULL){
        MESSAGE(FAIL, "Impossible to get handle of 'kernel32' module\n");
        PRINT_ERROR(GetModuleHandle);
        return EXIT_FAILURE;
    }
    MESSAGE(OKAY,"Successfully got handle of 'kernel32' module\n");

    //Retrieves the address of ''LoadLibrary' or variable from kernel32
    MESSAGE(INFO, "Trying to get address of 'LoadLibraryA' from 'kernel32'\n");
    funcAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(moduleHandle, "LoadLibraryA");
    if (funcAddr == NULL){
        MESSAGE(FAIL, "Impossible to get addres of 'LoadLibraryA'\n");
        PRINT_ERROR(GetProcAddress);
		return EXIT_FAILURE;
    }
    MESSAGE(OKAY, "Address of 'LoadLibraryA' succesfully got[0x%p]\n", funcAddr);

    MESSAGE(INFO, "Trying to create and inject thread that will run our dll in process[%ld]\n", pid);
    MESSAGE(INFO, "Press <enter> to continue...\n");
    getchar();
    threadHandle = CreateRemoteThread(processHandle, NULL, 0, funcAddr, paramAddr, 0, &TID);
    if (threadHandle == NULL){
        MESSAGE(FAIL, "Impossible to create thread\n");
        PRINT_ERROR("CreateRemoteThread");
		return EXIT_FAILURE;
    }
    MESSAGE(OKAY, "Thread[%ld] created and dll entry point executed successfully\n", TID);
    MESSAGE(INFO, "waiting for thread to finish\n");
    WaitForSingleObject(threadHandle, INFINITE);
	MESSAGE(OKAY, "thread execution finished\n");
    MESSAGE(INFO, "Press <enter> to continue and clean all the handles...\n");
    getchar();

    // Clean Up
    if (threadHandle) CloseHandle(threadHandle);
    if (processHandle) CloseHandle(processHandle);
    MESSAGE(OKAY, "Bye!\n");

    return EXIT_SUCCESS;
}
