// DiE Helper (fork addition): finds API-hashing constants (ror13, Metasploit block_api ror13+module, crc32, djb2, fnv1a32, sdbm) and dynamic API resolution call sites.
// STATUS: done (written, not compiled yet)
// Static only: code is disassembled (never executed or emulated); the API-name database is built once from the export tables of
// System32 DLLs, which are read as data files, never loaded. No GUI code; safe on a worker thread.
#ifndef HELPERAPIHASH_H
#define HELPERAPIHASH_H

#include <QList>
#include <QString>

#include "xbinary.h"

class HelperApiHash {
public:
    struct HIT {
        qint64 nOffset;        // file offset of the instruction (code immediate) or of the dword (data table)
        XADDR nAddress;        // virtual address of the same place, (XADDR)-1 if not mapped
        quint32 nHash;
        QString sAlgorithm;    // "ror13", "ror13+module", "crc32", "djb2", "fnv1a32", "sdbm"
        QString sLibrary;      // "kernel32.dll" (for the module-independent algorithms: the first listed DLL that exports the name)
        QString sFunction;     // "LoadLibraryA"
    };

    struct CALLSITE {
        XADDR nAddress;        // address of the call instruction
        QString sCallee;       // "KERNEL32.dll!GetProcAddress"
        QString sArgument;     // "\"Sleep\"", "\"kernel32.dll\" (stack)", "ordinal 5", "? (computed)", ...
    };

    struct RESULT {
        bool bIsValid;         // false: not a PE or could not be read (see sError)
        QString sError;        // also set (with bIsValid true) when the API-name database could not be built
        QList<HIT> listHits;   // sorted by offset
        QList<CALLSITE> listCallSites;  // calls of GetProcAddress / LoadLibrary* / GetModuleHandle* / Ldr* with their name argument
        qint32 nKnownApis;     // distinct export names in the database
    };

    static RESULT scan(const QString &sFileName, XBinary::PDSTRUCT *pPdStruct = nullptr);
};

#endif  // HELPERAPIHASH_H
