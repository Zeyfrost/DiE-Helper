// DiE Helper (fork addition): static recovery of hidden strings (stack strings, single-byte XOR/ADD/ROL and rolling-XOR encoded strings, .NET #US).
// Reads the file as data only: the code is disassembled, never executed or emulated. No GUI code; safe on a worker thread.
#ifndef HELPERSTRINGS_H
#define HELPERSTRINGS_H

#include <QList>
#include <QString>

#include "xbinary.h"

class HelperStrings {
public:
    struct RECORD {
        QString sMethod;  // "stack string", "stack string, xor 0x5A", "xor 0x5A", "xor rolling 0x10", "add 0x13", "rol 3", ".NET #US"
        qint64 nOffset;   // file offset of the encoded bytes (data) or of the first store instruction (stack strings)
        XADDR nAddress;   // virtual address of the same place, (XADDR)-1 if not mapped
        QString sString;  // recovered (decoded) text
        qint32 nScore;    // 0..100, how much the text looks like a real string
    };

    struct RESULT {
        bool bIsValid;  // false: not a PE or could not be read (see sError)
        QString sError;
        QList<RECORD> listRecords;  // sorted by score (descending), deduplicated by text, capped at ~2000
    };

    // "add K" means plaintext = (byte + K) & 0xFF, "rol N" means plaintext = rol8(byte, N),
    // "xor rolling K" means plaintext[i] = byte[i] ^ ((K + i) & 0xFF) from the start of the string.
    static RESULT recover(const QString &sFileName, XBinary::PDSTRUCT *pPdStruct = nullptr);
};

#endif  // HELPERSTRINGS_H
