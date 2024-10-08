#include <Windows.h>
#include <stdio.h>
#include "../utils/utility.h"


int main(int argc, char const *argv[])
{

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    char msg[100];

     if (argc < 2){
        MESSAGE(INFO, "Usage %s <path to exe>\n", argv[0]);
        return EXIT_SUCCESS;
    }

    si.cb = sizeof(si);
    ZeroMemory(&si, sizeof(si));
    
    // BOOL CreateProcessA(
    //   [in, optional]      LPCSTR                lpApplicationName,
    //   [in, out, optional] LPSTR                 lpCommandLine,
    //   [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
    //   [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
    //   [in]                BOOL                  bInheritHandles,
    //   [in]                DWORD                 dwCreationFlags,
    //   [in, optional]      LPVOID                lpEnvironment,
    //   [in, optional]      LPCSTR                lpCurrentDirectory,
    //   [in]                LPSTARTUPINFOA        lpStartupInfo,
    //   [out]               LPPROCESS_INFORMATION lpProcessInformation
    // );
    if( CreateProcess(
        (LPCSTR)argv[1],
        NULL,
        NULL,
        NULL,
        FALSE,
        NORMAL_PRIORITY_CLASS,
        NULL,
        NULL,
        &si,
        &pi
    )){
        MESSAGE(OKAY, "Process creation: Done!\n");
        MESSAGE(OKAY, "Process PID: %d\n", pi.dwProcessId);
        MESSAGE(OKAY, "Process TID: %d\n", pi.dwThreadId); 
        MESSAGE(OKAY, "Process Handle: 0x%p\n", pi.processHandle); 
        MESSAGE(OKAY, "Thread Handle: 0x%p\n", pi.threadHandle); 

        // DWORD WaitForSingleObject(
        //   [in] HANDLE hHandle,
        //   [in] DWORD  dwMilliseconds
        // );
        DWORD hP = WaitForSingleObject(pi.processHandle, INFINITE);
        DWORD hT = WaitForSingleObject(pi.threadHandle, INFINITE);

        if ( hT == WAIT_OBJECT_0 ) {
            MESSAGE(OKAY, "Signal received by Process\n");
            if ( !TerminateProcess(pi.processHandle, EXIT_SUCCESS) ){ 
                MESSAGE(FAIL, "TerminateProcess failed (%d).\n", GetLastError() );
            } 
            MESSAGE(OKAY, "Close processHandle: %d\n", CloseHandle(pi.processHandle));
            MESSAGE(OKAY, "Close threadHandle: %d\n", CloseHandle(pi.threadHandle)); 
        }else if ( hP == WAIT_TIMEOUT ){
            MESSAGE(OKAY, "Time out on processHandle\n");
            if ( !TerminateProcess(pi.processHandle, EXIT_SUCCESS) ){ 
                MESSAGE(FAIL, "TerminateProcess failed (%d).\n", GetLastError()); 
            }
            else {
                MESSAGE(OKAY, "Terminate process: Done!\n");
            }
            MESSAGE(OKAY, "Close processHandle: %d\n", CloseHandle(pi.processHandle));
            MESSAGE(OKAY, "Close threadHandle: %d\n", CloseHandle(pi.threadHandle));
        }
    }
    else { MESSAGE(FAIL, "CreateProcess failed (%d).\n", GetLastError() ); }
    
    Sleep(2000);

    return EXIT_SUCCESS;
}
