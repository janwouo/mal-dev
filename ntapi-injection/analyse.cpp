#include <windows.h>
#include <stdio.h>
#include "../utils/utility.h"


int main(int argc, char const *argv[])
{
    DWORD PID;
    HANDLE hProcess;

    PID = atoi(argv[1]);
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (hProcess == NULL){
        MESSAGE(FAIL, "Impossible to get handle of the process(0x%p)\n", PID);
        PRINT_ERROR(OpenProcess);
        return EXIT_FAILURE;
    }
    MESSAGE(OKAY, "Handle got for process(0x%p)\n", hProcess);

    puts("Press <enter> to exit...");
    getchar();
    CloseHandle(hProcess);
    
    return EXIT_SUCCESS;
}
