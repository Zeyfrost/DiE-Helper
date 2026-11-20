// DiE Helper (fork addition): static OEP finder - walks the unpacking stub from the entry point (disassembly only,
// nothing is executed or emulated) and ranks the tail transfers that leave the stub as original-entry-point candidates.
// No GUI code here; it runs on a worker thread.
#ifndef HELPEROEPFINDER_H
#define HELPEROEPFINDER_H

#include <QList>
#include <QString>
#include <QStringList>

#include "xbinary.h"

class HelperOepFinder {
public:
    struct CANDIDATE {
        XADDR nAddress;
        qint64 nRVA;
        qint64 nOffset;  // -1 if not file-backed
        QString sSection;
        QString sRule;  // "popad; jmp far", "push imm; ret", "mov reg,imm; jmp reg", "jmp [mem]", "UPX tail", "ASPack push/ret slot", "NsPack popad/popfd/jmp",
                        // "PECompact jmp eax", "jump into virtual-only section", "entry point is already the OEP", ...
        QString sDetails;  // facts with addresses
        XADDR nJumpSiteAddress;
        qint32 nConfidence;  // 0..100
    };

    struct RESULT {
        bool bIsValid;
        QString sError;
        QList<CANDIDATE> listCandidates;  // sorted desc, dedup by nAddress
        QStringList listTrace;            // <= 200 lines
    };

    static RESULT find(const QString &sFileName, XBinary::PDSTRUCT *pPdStruct = nullptr);
};

#endif  // HELPEROEPFINDER_H
