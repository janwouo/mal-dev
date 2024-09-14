#include <stdio.h>
#include "../utils/ntapi.h"
#include "../utils/utility.h"

int main(int argc, char const *argv[])
{
    HANDLE          processHandle;
    HMODULE         ntdllHandle;
    PNTOPENPROCESS  ntOpenProcessAddr;
    NTSTATUS        status;
    DWORD           PID;
    CHAR            processExecutablePath[MAX_STRING];
    DWORD           pathSize = MAX_STRING;

    PID = atoi(argv[1]);
    MESSAGE(INFO, "Using 'NtOpenProcess' to open process with pid: %ld\n", PID);
    MESSAGE(INFO, "Press <enter> to continue...\n");
    getchar();

    ntdllHandle = GetModuleHandle("ntdll");
    if (ntdllHandle == NULL){
        MESSAGE(FAIL, "Impossible to get handle of 'ntdll' module\n");
        PRINT_ERROR(GetModuleHandle);
        return EXIT_FAILURE;
    }
    MESSAGE(OKAY,"Successfully got handle of 'ntdll' module\n");

    ntOpenProcessAddr = (PNTOPENPROCESS)GetProcAddress(ntdllHandle, "NtOpenProcess");
    if (ntOpenProcessAddr == NULL){
        MESSAGE(FAIL, "Impossible to get address of 'ntOpenProecss' ntdll\n");
        PRINT_ERROR(GetProcAddress);
        return EXIT_FAILURE;
    }
    MESSAGE(OKAY,"Successfully got address of 'NtOpenProcess'\n");

    PUNICODE_STRING objectName = NULL;

    size_t objAttrSize = sizeof(OBJECT_ATTRIBUTES);
    POBJECT_ATTRIBUTES objAttributes = (POBJECT_ATTRIBUTES)malloc(objAttrSize);
    objAttributes->length = objAttrSize;
    objAttributes->attributes = 0;
    objAttributes->objName = objectName;
    objAttributes->rootDirectory = NULL;
    objAttributes->securityDescriptor = NULL;
    objAttributes->seecurityQualityOfService = NULL;

 
    PCLIENT_ID clientId = (PCLIENT_ID)malloc(sizeof(CLIENT_ID));
    clientId->uniqueProcess = (HANDLE)PID;
    clientId->uniqueThread = NULL;

    MESSAGE(INFO, "Press <enter> to to continue...\n");
    getchar();
    status = ntOpenProcessAddr(&processHandle, PROCESS_ALL_ACCESS, objAttributes, clientId);
    if (status != 0){
        MESSAGE(FAIL, "Error when running 'NtOpenProecss': status 0x%x\n", status);
        return EXIT_FAILURE;
    }
    MESSAGE(OKAY,"Successfully executed 'NtOpenProcess'\n");
    QueryFullProcessImageName(processHandle, PROCESS_NAME_NATIVE, processExecutablePath, &pathSize);
    MESSAGE(INFO, "Process id: %ld\n", GetProcessId(processHandle));
    MESSAGE(INFO, "Process file: %s, %ld bytes\n", &processExecutablePath, pathSize);

    MESSAGE(INFO, "Press <enter> to exit...\n");
    getchar();
    free(clientId);
    free(objAttributes);
    CloseHandle(processHandle);
    
    return EXIT_SUCCESS;
}
