/* Test sample for the DiE Helper (never executed): typical cheap obfuscation / anti-analysis traits.
   - anti-debug imports (IsDebuggerPresent, CheckRemoteDebuggerPresent, OutputDebugStringA)
   - API names XOR-encoded and resolved at runtime with GetProcAddress
   - a TLS callback (code that runs before the entry point) */
#include <windows.h>

#pragma comment(linker, "/INCLUDE:_tls_used")

static void NTAPI tls_callback(PVOID hModule, DWORD dwReason, PVOID pReserved)
{
    (void)hModule;
    (void)pReserved;
    if (dwReason == DLL_PROCESS_ATTACH && IsDebuggerPresent()) {
        ExitProcess(1);
    }
}

#pragma const_seg(".CRT$XLB")
const PIMAGE_TLS_CALLBACK p_tls_callback = tls_callback;
#pragma const_seg()

static void xor_decode(char *s, unsigned char k)
{
    for (; *s; s++) *s ^= k;
}

typedef BOOL(WINAPI *PFN_BEEP)(DWORD, DWORD);

int main(void)
{
    BOOL bRemote = FALSE;
    /* "kernel32.dll" and "Beep" XOR 0x5A */
    char szLib[] = {0x31, 0x3f, 0x28, 0x34, 0x3f, 0x36, 0x69, 0x68, 0x74, 0x3e, 0x36, 0x36, 0};
    char szFunc[] = {0x18, 0x3f, 0x3f, 0x2a, 0};
    HMODULE hLib;
    PFN_BEEP pBeep;

    CheckRemoteDebuggerPresent(GetCurrentProcess(), &bRemote);
    if (bRemote) {
        OutputDebugStringA("x");
        return 1;
    }

    xor_decode(szLib, 0x5A);
    xor_decode(szFunc, 0x5A);
    hLib = LoadLibraryA(szLib);
    pBeep = hLib ? (PFN_BEEP)GetProcAddress(hLib, szFunc) : NULL;
    if (pBeep) pBeep(440, 10);
    return 0;
}
