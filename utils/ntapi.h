#include <windows.h>

#if !defined(__NTAPI_H__)
#define __NTAPI_H__

typedef struct {
    USHORT  length;
    USHORT  maximumLength;
    PWSTR   buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;

typedef struct {
    USHORT          length;
    HANDLE          rootDirectory;
    PUNICODE_STRING objName;
    UINT            attributes;
    LPVOID          securityDescriptor;
    LPVOID          seecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;

typedef struct {
    HANDLE  uniqueProcess;
    HANDLE  uniqueThread;
}  CLIENT_ID;
typedef CLIENT_ID *PCLIENT_ID;

typedef NTSTATUS (*PNTOPENPROCESS)(
    PHANDLE             processHandle,
    ACCESS_MASK         desiredAccess,
    POBJECT_ATTRIBUTES  objAttributes,
    PCLIENT_ID          clientId

);

// __declspec(dllimport) NTSATUS NtOpenProcess(
//     PHANDLE             processHandle;
//     ACCESS_MASK         desiredAccess;
//     POBJECT_ATTRIBUTES  objAttributes;
//     PCLIENT_ID          clientId;
// )

#endif // __NTAPI_H__
