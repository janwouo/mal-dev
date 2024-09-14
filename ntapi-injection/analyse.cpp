#include <windows.h>
#include <stdio.h>
#include "../utils/utility.h"


int main(int argc, char const *argv[])
{
    DWORD PID;
    HANDLE processHandle;

    PID = atoi(argv[1]);
    MESSAGE(INFO, "Open process with pid: %ld\n", PID);
    MESSAGE(INFO, "Press <enter> to continue...\n");
    getchar();
    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (processHandle == NULL){
        MESSAGE(FAIL, "Impossible to get handle of the process(0x%p)\n", PID);
        PRINT_ERROR(OpenProcess);
        return EXIT_FAILURE;
    }
    MESSAGE(OKAY, "Handle got for process(0x%p)\n", processHandle);

    MESSAGE(INFO, "Press <enter> to exit...\n");
    getchar();
    CloseHandle(processHandle);
    
    return EXIT_SUCCESS;
}
