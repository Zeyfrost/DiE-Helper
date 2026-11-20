// DiE Helper (fork addition): static PE rebuild from a decompressed blob and import reconstruction from
// leftover loader data. Works on bytes only (never executes or maps the sample); the result is a NEW file.
//
// rebuildWithBlob: the target section (default: first section without raw data, else the first section)
//   becomes file-backed and receives the blob at its start (or at nTargetRVA inside it); the other
//   sections' raw data is re-laid out after the headers in section order (FileAlignment), the overlay is
//   appended unchanged, SizeOfImage is recomputed, the entry point is set, debug-directory file offsets
//   and an overlay certificate offset follow their data, and the checksum is recomputed.
//   Limitations: the blob must fit in front of the next section's RVA (only the last section can grow);
//   relocations, TLS, resources and the packer's own import table are NOT touched; a certificate table
//   outside the overlay is dropped (the signature is invalid after any rebuild anyway); COFF symbols
//   outside the overlay are dropped; low-alignment images (SectionAlignment < 0x1000) need raw == RVA,
//   which is kept, but sections must then be in ascending RVA order.
//
// reconstructImports (first method that finds something wins):
//   1. a complete IMAGE_IMPORT_DESCRIPTOR array (zero-terminated, DLL names and thunks valid) that is not
//      the active one: the import directory is simply pointed at it (original IAT addresses kept).
//   2. IAT-shaped tables (pointer-sized RVAs to hint/name entries, groups separated by one zero slot) with
//      a DLL name string near the names: rebuilt with XPE::setImports into a new section, then each
//      descriptor's FirstThunk is pointed back at the original table so the code's IAT calls still match.
//   3. name lists: "xxx.dll\0" followed by NUL-terminated function names (optionally with UPX-style
//      0x01 / 0xFF+ordinal prefixes): rebuilt with XPE::setImports; the IAT location is unknown, so the
//      new IAT lives in the new section and the code's calls do NOT go through it (the file shows the
//      right imports to static tools but will not run).
//   Not handled: imports resolved by hash or by GetProcAddress at runtime, encrypted name lists,
//   UPX's packed import list inside its compressed stream (decompress first), forwarded/bound imports.
#ifndef HELPERREBUILD_H
#define HELPERREBUILD_H

#include <QByteArray>
#include <QStringList>

#include "xbinary.h"

class HelperRebuild {
public:
    struct OPTIONS {
        XADDR nOEP;          // 0 = keep; a VA (ImageBase + RVA) or an RVA
        qint64 nTargetRVA;   // -1 = auto: first raw-less section, else the first section
        bool bRebuildImports;
        bool bFixChecksum;
        bool bRestoreCharacteristics;
    };

    struct RESULT {
        bool bSuccess;
        QString sError;
        QStringList listLog;
        qint32 nImportsRecovered;
    };

    static RESULT rebuildWithBlob(const QString &sInput, const QString &sOutput, const QByteArray &baDecompressed, const OPTIONS &options,
                                  XBinary::PDSTRUCT *pPdStruct = nullptr);
    static RESULT reconstructImports(const QString &sInput, const QString &sOutput, XBinary::PDSTRUCT *pPdStruct = nullptr);

private:
    static bool _reconstructImportsInPlace(const QString &sFileName, RESULT *pResult, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // HELPERREBUILD_H
