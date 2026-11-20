/* Test sample for the DiE Helper (never executed): hidden strings and API hashing, for HelperStrings / HelperApiHash.
   - stack strings "kernel32.dll" and "http://example.invalid/x" built byte by byte in volatile char arrays
     (volatile + /O1 keeps one "mov byte ptr [rsp+X], imm8" per character)
   - "SOFTWARE\Microsoft\Windows\CurrentVersion\Run" XOR 0x37 encoded in .data
   - ror13 API hashes (h = ror(h, 13) + c, no terminator), verified with Python:
       LoadLibraryA 0xEC0E4E8E, VirtualAlloc 0x91AFCA54
   - GetProcAddress(h, "Sleep") with a plain string argument */
#include <windows.h>

/* XOR 0x37 of "SOFTWARE\Microsoft\Windows\CurrentVersion\Run", plain NUL terminator */
static unsigned char g_szEncoded[] = {0x64, 0x78, 0x71, 0x63, 0x60, 0x76, 0x65, 0x72, 0x6b, 0x7a, 0x5e, 0x54, 0x45, 0x58, 0x44, 0x58,
                                      0x51, 0x43, 0x6b, 0x60, 0x5e, 0x59, 0x53, 0x58, 0x40, 0x44, 0x6b, 0x74, 0x42, 0x45, 0x45, 0x52,
                                      0x59, 0x43, 0x61, 0x52, 0x45, 0x44, 0x5e, 0x58, 0x59, 0x6b, 0x65, 0x42, 0x59, 0x00};

#define HASH_LOADLIBRARYA 0xEC0E4E8E
#define HASH_VIRTUALALLOC 0x91AFCA54

typedef HMODULE(WINAPI *PFN_LOADLIBRARYA)(LPCSTR);
typedef LPVOID(WINAPI *PFN_VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef VOID(WINAPI *PFN_SLEEP)(DWORD);

static DWORD ror13_hash(const char *s)
{
    DWORD h = 0;

    while (*s) {
        h = (h >> 13) | (h << 19);
        h += (unsigned char)*s++;
    }

    return h;
}

static FARPROC find_export_by_hash(HMODULE hModule, DWORD dwHash)
{
    BYTE *pBase = (BYTE *)hModule;
    IMAGE_NT_HEADERS *pNt = (IMAGE_NT_HEADERS *)(pBase + ((IMAGE_DOS_HEADER *)pBase)->e_lfanew);
    IMAGE_DATA_DIRECTORY *pDir = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY *pExport = (IMAGE_EXPORT_DIRECTORY *)(pBase + pDir->VirtualAddress);
    DWORD *pNames = (DWORD *)(pBase + pExport->AddressOfNames);
    WORD *pOrdinals = (WORD *)(pBase + pExport->AddressOfNameOrdinals);
    DWORD *pFunctions = (DWORD *)(pBase + pExport->AddressOfFunctions);
    DWORD i;

    for (i = 0; i < pExport->NumberOfNames; i++) {
        if (ror13_hash((const char *)(pBase + pNames[i])) == dwHash) {
            return (FARPROC)(pBase + pFunctions[pOrdinals[i]]);
        }
    }

    return NULL;
}

int main(void)
{
    volatile char szLib[13];
    volatile char szUrl[25];
    HMODULE hKernel;
    PFN_LOADLIBRARYA pLoadLibraryA;
    PFN_VIRTUALALLOC pVirtualAlloc;
    PFN_SLEEP pSleep;
    int i;
    int nResult = 0;

    szLib[0] = 'k';
    szLib[1] = 'e';
    szLib[2] = 'r';
    szLib[3] = 'n';
    szLib[4] = 'e';
    szLib[5] = 'l';
    szLib[6] = '3';
    szLib[7] = '2';
    szLib[8] = '.';
    szLib[9] = 'd';
    szLib[10] = 'l';
    szLib[11] = 'l';
    szLib[12] = 0;

    szUrl[0] = 'h';
    szUrl[1] = 't';
    szUrl[2] = 't';
    szUrl[3] = 'p';
    szUrl[4] = ':';
    szUrl[5] = '/';
    szUrl[6] = '/';
    szUrl[7] = 'e';
    szUrl[8] = 'x';
    szUrl[9] = 'a';
    szUrl[10] = 'm';
    szUrl[11] = 'p';
    szUrl[12] = 'l';
    szUrl[13] = 'e';
    szUrl[14] = '.';
    szUrl[15] = 'i';
    szUrl[16] = 'n';
    szUrl[17] = 'v';
    szUrl[18] = 'a';
    szUrl[19] = 'l';
    szUrl[20] = 'i';
    szUrl[21] = 'd';
    szUrl[22] = '/';
    szUrl[23] = 'x';
    szUrl[24] = 0;

    hKernel = LoadLibraryA((LPCSTR)szLib);

    if (!hKernel) {
        return 1;
    }

    pLoadLibraryA = (PFN_LOADLIBRARYA)find_export_by_hash(hKernel, HASH_LOADLIBRARYA);
    pVirtualAlloc = (PFN_VIRTUALALLOC)find_export_by_hash(hKernel, HASH_VIRTUALALLOC);
    pSleep = (PFN_SLEEP)GetProcAddress(hKernel, "Sleep");

    for (i = 0; g_szEncoded[i]; i++) {
        g_szEncoded[i] ^= 0x37;
    }

    nResult += lstrlenA((LPCSTR)g_szEncoded);
    nResult += lstrlenA((LPCSTR)szUrl);

    if (pLoadLibraryA && pVirtualAlloc && pSleep) {
        pSleep(1);
        nResult += (pVirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE) != NULL);
    }

    return nResult;
}
