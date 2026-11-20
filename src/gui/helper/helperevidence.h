// DiE Helper (fork addition): collects concrete evidence of packing/obfuscation from a PE file
// (sections, entropy, entry point, imports, TLS, overlay) and ranks it into indicators.
// No GUI code here; it runs on a worker thread.
#ifndef HELPEREVIDENCE_H
#define HELPEREVIDENCE_H

#include <QList>
#include <QMetaType>
#include <QString>
#include <QStringList>

#include "xbinary.h"

class HelperEvidence {
public:
    enum SEVERITY {
        SEVERITY_INFO = 0,  // context, not suspicious by itself
        SEVERITY_LOW,
        SEVERITY_MEDIUM,
        SEVERITY_HIGH
    };

    enum CATEGORY {
        CATEGORY_PACKING = 0,   // compression / encryption of the image, unpacking stub
        CATEGORY_OBFUSCATION,   // code/metadata/string obfuscation, dynamic API resolution
        CATEGORY_ANTIANALYSIS,  // anti-debug / anti-VM / anti-dump hints
        CATEGORY_INFO           // neutral facts (overlay present, is a DLL, ...)
    };

    enum LOCATION {
        LOCATION_NONE = 0,
        LOCATION_HEX,     // open the hex view at nOffset (file offset), nSize bytes
        LOCATION_DISASM   // open the disassembler at nAddress (virtual address)
    };

    struct SECTION {
        qint32 nIndex;          // -1 for the pseudo-sections "Headers" and "Overlay"
        QString sName;          // as in the header ("UPX0", ".text"), "Headers", "Overlay"
        qint64 nRawOffset;      // PointerToRawData
        qint64 nRawSize;        // SizeOfRawData (clamped to the file size)
        qint64 nRVA;            // VirtualAddress (-1 for pseudo-sections)
        qint64 nVirtualSize;    // Misc.VirtualSize (-1 for pseudo-sections)
        quint32 nCharacteristics;
        bool bRead;
        bool bWrite;
        bool bExecute;
        bool bContainsEntryPoint;
        bool bIsUnusualName;    // not a standard compiler section name
        double dEntropy;        // 0..8 over the raw data; -1 if no raw data
    };

    struct INDICATOR {
        QString sId;            // stable id, e.g. "ep_last_section", "rwx_section"
        CATEGORY category;
        SEVERITY severity;
        qint32 nWeight;         // ranking weight (higher = stronger evidence of packing)
        QString sTitle;         // short chip text: "EP in last section"
        QString sDetails;       // one line with the facts: "EP RVA 0x1A2F0 in UPX1 (#1 of 2)"
        LOCATION location;
        qint64 nOffset;         // file offset for LOCATION_HEX (and for display)
        qint64 nSize;
        XADDR nAddress;         // virtual address for LOCATION_DISASM
    };

    struct RESULT {
        bool bIsValid;          // false: not a PE or could not be read (see sError)
        QString sError;
        QString sFileName;
        qint64 nFileSize;
        bool bIs64;
        bool bIsDll;
        bool bIsNET;
        XADDR nImageBase;
        qint64 nHeadersSize;    // SizeOfHeaders
        // entry point
        qint64 nEntryPointRVA;
        XADDR nEntryPointAddress;
        qint64 nEntryPointOffset;  // -1 if the EP is not backed by file data
        qint32 nEntryPointSection; // index into the real sections, -1 if none
        QByteArray baEntryPointBytes;  // first 32 bytes at the EP (empty if not in file)
        // layout (in file order: Headers, sections..., Overlay if present)
        QList<SECTION> listSections;
        double dFileEntropy;
        // imports
        qint32 nImportLibraries;
        qint32 nImportFunctions;
        QStringList listNotableImports;  // LoadLibrary*, GetProcAddress, VirtualAlloc*, VirtualProtect*, ...
        // TLS / overlay
        QList<XADDR> listTLSCallbacks;
        qint64 nOverlayOffset;  // -1 if none
        qint64 nOverlaySize;
        // strings (printable ASCII runs >= 5 chars over the whole file)
        qint32 nStringCount;
        double dStringDensity;  // strings per KiB of raw section data
        // .NET (only when bIsNET)
        qint32 nNetTypes;              // TypeDef rows (or names seen), 0 if unknown
        qint32 nNetObfuscatedNames;    // type/method names that are non-printable, very short random, or invisible-unicode
        QStringList listNetSampleNames;// a few examples of the suspicious names (escaped)
        // ranked indicators (sorted by nWeight, descending) and the derived scores (0..100 each)
        QList<INDICATOR> listIndicators;
        qint32 nPackingScore;      // sum of weights of PACKING indicators, capped at 100
        qint32 nObfuscationScore;  // sum of weights of OBFUSCATION + ANTIANALYSIS indicators, capped at 100
    };

    // Reads and analyses the file. Safe to call from a worker thread. Never executes anything.
    static RESULT analyze(const QString &sFileName);

    static QString severityToString(SEVERITY severity);
    static QString categoryToString(CATEGORY category);
};

Q_DECLARE_METATYPE(HelperEvidence::INDICATOR)  // row locations stored in QTreeWidgetItem data

#endif  // HELPEREVIDENCE_H
