#include <Windows.h>
#include <stdio.h>

void okay(char *msg) { printf("[+] %s", msg); }
void info(char *msg) { printf("[*] %s", msg); }
void error(char *msg) { printf("[-] %s", msg); }


int main(int argc, char const *argv[])
{

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    char msg[100];

     if (argc < 2){
        sprintf(msg, "Usage %s <path to exe>\n", argv[0]);
        info(msg);
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
        okay((char*)"Process creation: Done!\n");
        sprintf(msg, "Process PID: %d\n", pi.dwProcessId); okay(msg);
        sprintf(msg, "Process TID: %d\n", pi.dwThreadId); okay(msg);
        sprintf(msg, "Process Handle: 0x%p\n", pi.hProcess); okay(msg);
        sprintf(msg, "Thread Handle: 0x%p\n", pi.hThread); okay(msg);

        // DWORD WaitForSingleObject(
        //   [in] HANDLE hHandle,
        //   [in] DWORD  dwMilliseconds
        // );
        DWORD hP = WaitForSingleObject(pi.hProcess, INFINITE);
        //DWORD hT = WaitForSingleObject(pi.hThread, INFINITE);

        if ( hT == WAIT_OBJECT_0 ) {
            okay((char*)"Signal received by Process\n");
            if ( !TerminateProcess(pi.hProcess, EXIT_SUCCESS) ){ sprintf(msg, "TerminateProcess failed (%d).\n", GetLastError() ); error(msg); } 
            sprintf(msg, "Close hProcess: %d\n", CloseHandle(pi.hProcess)); okay(msg);
            sprintf(msg, "Close hThread: %d\n", CloseHandle(pi.hThread)); okay(msg);
        }else if ( hP == WAIT_TIMEOUT ){
            okay((char*)"Time out on hProcess\n");
            if ( !TerminateProcess(pi.hProcess, EXIT_SUCCESS) ){ sprintf(msg, "TerminateProcess failed (%d).\n", GetLastError()); error(msg); }
            else okay((char*)"Terminate process: Done!\n");
            sprintf(msg, "Close hProcess: %d\n", CloseHandle(pi.hProcess)); okay(msg);
            sprintf(msg, "Close hThread: %d\n", CloseHandle(pi.hThread)); okay(msg);
        }
    }
    else { sprintf(msg, "CreateProcess failed (%d).\n", GetLastError() ); error(msg); }
    
    Sleep(2000);

    return EXIT_SUCCESS;
}
