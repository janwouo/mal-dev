#if !defined(__UTILITY_H__)
#define __UTILITY_H__

    #define MAX_STRING 100

    #define OKAY "[+]"
    #define INFO "[*]"
    #define FAIL "[!]"

    #define MESSAGE(X, ...) printf(X " " __VA_ARGS__)
    #define PRINT_ERROR(X) fprintf(stderr, FAIL " " X " failed, error %ld : %s[line %d]", GetLastError(), __FILE__, __LINE__)

#endif // __UTILITY_H__