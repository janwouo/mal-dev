#include <windows.h>
#include <stdio.h>
#include "../utils/utility.h"
#include "../utils/messageBoxDLL.h"

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved )  // reserved
{
    // Perform actions based on the reason for calling.
    // g++ -shared -D MESSAGEBOX_DLL -o messageBoxDLL.dll messageBoxDLL.cpp
    switch( fdwReason ) 
    { 
        case DLL_PROCESS_ATTACH:
         // Initialize once for each new process.
         // Return FALSE to fail DLL load.
            char msg[100];
            sprintf(msg, "Hello World: DLL Loaded in process %ld", GetCurrentProcessId());
            MessageBox(NULL, msg, "DLL INJECTION", MB_OKCANCEL);
            break;

        case DLL_THREAD_ATTACH:
         // Do thread-specific initialization.
            break;

        case DLL_THREAD_DETACH:
         // Do thread-specific cleanup.
            break;

        case DLL_PROCESS_DETACH:
         // Perform any necessary cleanup.
            break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}


extern "C" {

    export void __stdcall helloDLL(){
        MessageBox(NULL, "Hello World: DLL function executed", "DLL INJECTION", MB_OKCANCEL);
    }

}