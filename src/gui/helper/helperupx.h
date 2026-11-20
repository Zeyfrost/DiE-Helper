// DiE Helper (fork addition): UPX-specific finishing for "Decompress -> Rebuild": reads the UPX pack header,
// undoes UPX's call/jump filter and relocation encoding in the decompressed stream, then on the rebuilt copy
// rebuilds the import table, restores the original section names and clears the leftover UPX header block.
// Everything comes from data UPX itself stores in its stream ("extra info": original headers, packed
// imports, packed relocations); nothing is executed.
#ifndef HELPERUPX_H
#define HELPERUPX_H

#include <QByteArray>
#include <QList>
#include <QStringList>

class HelperUpx {
public:
    struct PACKINFO {
        bool bIsValid;
        quint8 nVersion;
        quint8 nFormat;
        quint8 nMethod;
        quint8 nFilter;     // 0x26 (x86 E8/E9 + cto), 0x49 / 0x46 (E8/E9/Jcc + cto, --brute), ...
        quint8 nFilterCto;
        quint32 nUncompressedSize;  // u_len: size of the decompressed stream
    };

    struct ORIGINAL_SECTION {
        QString sName;
        quint32 nVirtualAddress;
        quint32 nVirtualSize;
    };

    static PACKINFO readPackHeader(const QString &sFileName);

    // pbaStream: the decompressed UPX stream starting at nStreamRVA (the empty "UPX0" section).
    // Undoes the call/jump filter on the original code and the relocation encoding (32 and 64 bit),
    // and returns the original section table. Returns false if the stream does not look like UPX's.
    static bool unfilter(QByteArray *pbaStream, qint64 nStreamRVA, const PACKINFO &packInfo, QList<ORIGINAL_SECTION> *pListOriginalSections, QStringList *pListLog);

    // On the Helper's rebuilt copy (modified in place): rebuild imports from UPX's packed import list,
    // restore section names, clear the "UPX!" header block, fix the checksum.
    static bool finishRebuiltFile(const QString &sRebuiltFile, const QString &sPackedFile, const QByteArray &baStream, qint64 nStreamRVA,
                                  const QList<ORIGINAL_SECTION> &listOriginalSections, QStringList *pListLog);

private:
    struct HEADERS {
        bool bIsValid;
        qint64 nNT;            // offset of "PE\0\0" in the stream
        bool bIs64;
        quint16 nSections;
        qint64 nSectionTable;
        qint64 nWords;         // first byte after the section table (UPX's offsets follow)
        qint64 nExtra;         // extra info offset (last dword of the stream); equals nNT
        qint64 nDataDirectory; // offset of the data directories
        quint64 nImageBase;
        quint32 nBaseOfCode;
        quint32 nSizeOfCode;
    };

    static HEADERS _getHeaders(const QByteArray &baStream);
    static bool _applyFilter(unsigned char *pData, qint64 nDataSize, quint8 nFilter, quint8 nFilterCto, quint32 nAddValue);
    static qint64 _findRelocList(const QByteArray &baStream, const HEADERS &headers);
    static bool _rebuildImports(const QString &sRebuiltFile, const QString &sPackedFile, const QByteArray &baStream, qint64 nStreamRVA, const HEADERS &headers,
                                QStringList *pListLog);
};

#endif  // HELPERUPX_H
