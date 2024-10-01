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