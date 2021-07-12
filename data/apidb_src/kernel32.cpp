//@formatter:off
// cl.exe -nologo -Gm- -GR- -EHa- -Oi kernel32.cpp -link /dll /out:kernel32.dll
// -nodefaultlib /entry:DllMain
//@formatter:on

#include <windows.h>

#ifdef __cplusplus  // If used by C++ code,
extern "C" {        // we need to export the C interface
#endif
}
HANDLE handle_array[1000] = {};
unsigned long index = 0;


LPCSTR saved_lpFileName;
DWORD saved_dwDesiredAccess;
DWORD saved_dwShareMode;
LPSECURITY_ATTRIBUTES saved_lpSecurityAttributes;
DWORD saved_dwCreationDisposition;
DWORD saved_dwFlagsAndAttributes;
HANDLE saved_hTemplateFile;

__declspec(dllexport) HANDLE
    __stdcall CreateFile(LPCSTR lpFileName, DWORD dwDesiredAccess,
                         DWORD dwShareMode,
                         LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                         DWORD dwCreationDisposition,
                         DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    handle_array[index] = (HANDLE)index;

    // More or less to make sure the arguments survive decompilation
    saved_lpFileName = lpFileName;
    saved_dwDesiredAccess = dwDesiredAccess;
    saved_dwShareMode = dwShareMode;
    saved_lpSecurityAttributes = lpSecurityAttributes;
    saved_dwCreationDisposition = dwCreationDisposition;
    saved_dwFlagsAndAttributes = dwFlagsAndAttributes;
    saved_hTemplateFile = hTemplateFile;

    HANDLE x = (HANDLE)index;

    index++;
    return x;
}

__declspec(dllexport) BOOL __stdcall CloseHandle(HANDLE hObject) {
    unsigned long i = (unsigned long)hObject;
    handle_array[i] = INVALID_HANDLE_VALUE;

    return true;
}

BOOL __stdcall DllMain(HINSTANCE hinstDLL,  // handle to DLL module
                       DWORD fdwReason,     // reason for calling function
                       LPVOID lpReserved)   // reserved
{
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}