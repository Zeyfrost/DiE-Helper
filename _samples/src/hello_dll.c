#include <windows.h>

__declspec(dllexport) int __cdecl hello_add(int a, int b)
{
    return a + b;
}

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
    (void)hInstance;
    (void)dwReason;
    (void)lpReserved;
    return TRUE;
}
