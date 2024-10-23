#ifndef __MESSAGEBOXDLL_H__

    #define __MESSAGEBOXDLL_H__

    #ifdef MESSAGEBOX_DLL
        #define export __declspec(dllexport)
    #else
        #define export __declspec(dllimport)
    #endif

#endif // __MESSAGEBOXDLL_H__

extern "C" { 
    
    export void helloDLL();
    
}