// DiE Helper (fork addition): static PE rebuild from a decompressed blob and import reconstruction.
#include "helperrebuild.h"

#include <QBuffer>
#include <QFile>
#include <QFileInfo>
#include <QMap>
#include <QSet>
#include <QtEndian>
#include <algorithm>
#include <cstring>

#include "xpe.h"

namespace {

const qint64 N_HELPER_REBUILD_MAX_FILE = 512ll << 20;
const qint32 N_HELPER_MAX_THUNKS = 4096;
const qint32 N_HELPER_MAX_DESCRIPTORS = 512;

qint64 _alignUp(qint64 nValue, qint64 nAlignment)
{
    if (nAlignment <= 1) {
        return nValue;
    }

    return ((nValue + nAlignment - 1) / nAlignment) * nAlignment;
}

QString _sectionName(const XPE_DEF::IMAGE_SECTION_HEADER &header)
{
    return QString::fromLatin1((const char *)header.Name, (int)strnlen((const char *)header.Name, 8));
}

bool _isPowerOfTwo(quint32 nValue)
{
    return nValue && !(nValue & (nValue - 1));
}

// old file range -> new file offset (raw data that was moved)
struct MOVE {
    qint64 nOldOffset;
    qint64 nSize;
    qint64 nNewOffset;
};

bool _remap(const QList<MOVE> &listMoves, qint64 nOldOffset, qint64 *pnNewOffset)
{
    for (const MOVE &move : listMoves) {
        if ((nOldOffset >= move.nOldOffset) && (nOldOffset < move.nOldOffset + move.nSize)) {
            *pnNewOffset = move.nNewOffset + (nOldOffset - move.nOldOffset);
            return true;
        }
    }

    return false;
}

// ---------------------------------------------------------------------------------------------
// import reconstruction helpers (all reads bounds-checked against the file buffer)
// ---------------------------------------------------------------------------------------------
bool _readCString(const QByteArray &baData, qint64 nOffset, qint32 nMaxLength, QString *psString)
{
    if ((nOffset < 0) || (nOffset >= baData.size())) {
        return false;
    }

    const quint8 *pData = (const quint8 *)baData.constData();
    qint64 nEnd = qMin<qint64>(baData.size(), nOffset + nMaxLength + 1);

    for (qint64 i = nOffset; i < nEnd; i++) {
        if (pData[i] == 0) {
            if (i == nOffset) {
                return false;
            }

            *psString = QString::fromLatin1((const char *)pData + nOffset, (int)(i - nOffset));
            return true;
        }

        if ((pData[i] < 0x20) || (pData[i] > 0x7E)) {
            return false;
        }
    }

    return false;
}

bool _isDllNameChar(quint8 nChar)
{
    return ((nChar >= 'a') && (nChar <= 'z')) || ((nChar >= 'A') && (nChar <= 'Z')) || ((nChar >= '0') && (nChar <= '9')) || (nChar == '_') || (nChar == '-') ||
           (nChar == '.') || (nChar == '~') || (nChar == '$') || (nChar == ' ');
}

bool _isDllName(const QString &sName)
{
    if ((sName.length() < 5) || (sName.length() > 64)) {
        return false;
    }

    for (QChar c : sName) {
        if ((c.unicode() > 0x7F) || !_isDllNameChar((quint8)c.unicode())) {
            return false;
        }
    }

    QString sLower = sName.toLower();

    if (!(sLower.endsWith(".dll") || sLower.endsWith(".drv") || sLower.endsWith(".sys") || sLower.endsWith(".exe") || sLower.endsWith(".ocx") ||
          sLower.endsWith(".cpl"))) {
        return false;
    }

    // the base name needs a letter
    for (qint32 i = 0; i < sName.length() - 4; i++) {
        if (sName.at(i).isLetter()) {
            return true;
        }
    }

    return false;
}

// C identifiers and MSVC-mangled C++ names
bool _isApiName(const QString &sName)
{
    if ((sName.length() < 2) || (sName.length() > 256)) {
        return false;
    }

    for (qint32 i = 0; i < sName.length(); i++) {
        ushort c = sName.at(i).unicode();
        bool bLetter = ((c >= 'a') && (c <= 'z')) || ((c >= 'A') && (c <= 'Z')) || (c == '_') || (c == '?') || (c == '@');

        if (i == 0) {
            if (!bLetter) {
                return false;
            }
        } else if (!(bLetter || ((c >= '0') && (c <= '9')) || (c == '$') || (c == '.'))) {
            return false;
        }
    }

    return true;
}

struct FILE_REGION {
    qint64 nOffset;
    qint64 nSize;
    qint64 nRVA;
};

struct GROUP {
    QString sLibrary;
    qint64 nTableRVA;  // original thunk table (method 2), -1 if unknown
    QList<XPE::IMPORT_POSITION> listPositions;
};

}  // namespace

HelperRebuild::RESULT HelperRebuild::rebuildWithBlob(const QString &sInput, const QString &sOutput, const QByteArray &baDecompressed, const OPTIONS &options,
                                                     XBinary::PDSTRUCT *pPdStruct)
{
    RESULT result = {};

    if (baDecompressed.isEmpty()) {
        result.sError = QString("The decompressed data is empty");
        return result;
    }

    QFile fileIn(sInput);

    if (!fileIn.open(QIODevice::ReadOnly)) {
        result.sError = QString("Cannot open %1").arg(sInput);
        return result;
    }

    if (fileIn.size() > N_HELPER_REBUILD_MAX_FILE) {
        result.sError = QString("The input is larger than %1 MiB").arg(N_HELPER_REBUILD_MAX_FILE >> 20);
        return result;
    }

    QByteArray baIn = fileIn.readAll();
    fileIn.close();

    QBuffer bufferIn(&baIn);
    bufferIn.open(QIODevice::ReadOnly);
    XPE pe(&bufferIn);

    if (!pe.isValid()) {
        result.sError = QString("Not a valid PE file");
        return result;
    }

    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders(pPdStruct);

    if (listSections.isEmpty()) {
        result.sError = QString("The file has no sections");
        return result;
    }

    quint32 nFileAlignment = pe.getOptionalHeader_FileAlignment();
    quint32 nSectionAlignment = pe.getOptionalHeader_SectionAlignment();

    if (!_isPowerOfTwo(nFileAlignment)) {
        result.listLog.append(QString("FileAlignment 0x%1 is not a power of two; using 0x200").arg(nFileAlignment, 0, 16));
        nFileAlignment = 0x200;
    }

    if (!_isPowerOfTwo(nSectionAlignment)) {
        result.listLog.append(QString("SectionAlignment 0x%1 is not a power of two; using 0x1000").arg(nSectionAlignment, 0, 16));
        nSectionAlignment = 0x1000;
    }

    bool bLowAlignment = (nSectionAlignment < 0x1000);
    qint64 nSizeOfHeaders = pe.getOptionalHeader_SizeOfHeaders();
    XADDR nImageBase = pe.getOptionalHeader_ImageBase();
    quint32 nOldSizeOfImage = pe.getOptionalHeader_SizeOfImage();
    bool bOverlay = pe.isOverlayPresent(pPdStruct);
    qint64 nOverlayOffset = bOverlay ? pe.getOverlayOffset(pPdStruct) : -1;
    qint64 nOverlaySize = bOverlay ? pe.getOverlaySize(pPdStruct) : 0;

    if ((nSizeOfHeaders <= 0) || (nSizeOfHeaders > baIn.size())) {
        result.sError = QString("Invalid SizeOfHeaders 0x%1").arg(nSizeOfHeaders, 0, 16);
        return result;
    }

    // --- target section
    qint32 nTarget = -1;
    qint64 nTargetDelta = 0;

    if (options.nTargetRVA < 0) {
        for (qint32 i = 0; i < listSections.count(); i++) {
            if (listSections.at(i).SizeOfRawData == 0) {
                nTarget = i;
                break;
            }
        }

        if (nTarget == -1) {
            nTarget = 0;
            result.listLog.append(QString("No section without raw data; using the first section"));
        }
    } else {
        for (qint32 i = 0; i < listSections.count(); i++) {
            qint64 nVA = listSections.at(i).VirtualAddress;
            qint64 nSize = qMax<qint64>(listSections.at(i).Misc.VirtualSize, listSections.at(i).SizeOfRawData);

            if ((options.nTargetRVA >= nVA) && (options.nTargetRVA < nVA + nSize)) {
                nTarget = i;
                nTargetDelta = options.nTargetRVA - nVA;
                break;
            }
        }

        if (nTarget == -1) {
            result.sError = QString("RVA 0x%1 is not inside any section").arg(options.nTargetRVA, 0, 16);
            return result;
        }
    }

    XPE_DEF::IMAGE_SECTION_HEADER headerTarget = listSections.at(nTarget);
    QString sTargetName = _sectionName(headerTarget);
    qint64 nTargetVSize = headerTarget.Misc.VirtualSize ? headerTarget.Misc.VirtualSize : headerTarget.SizeOfRawData;
    qint64 nNeeded = nTargetDelta + baDecompressed.size();

    // room in memory before the next section
    qint64 nNextVA = -1;

    for (qint32 i = 0; i < listSections.count(); i++) {
        qint64 nVA = listSections.at(i).VirtualAddress;

        if ((nVA > headerTarget.VirtualAddress) && ((nNextVA == -1) || (nVA < nNextVA))) {
            nNextVA = nVA;
        }
    }

    // The unpacked image often spans more than the empty section: UPX unpacks over UPX0 *and* the start of UPX1
    // (whose packed data is no longer needed once unpacked). Lay the stream over the following sections by RVA;
    // only what lies beyond the last section (packer loader tables) goes to a side file.
    QByteArray baBlob = baDecompressed;  // part placed into the target section
    QMap<qint32, QByteArray> mapSpill;   // following sections whose raw data is replaced by the rest of the stream

    if (nNeeded > nTargetVSize) {
        if ((nNextVA != -1) && (headerTarget.VirtualAddress + nNeeded > nNextVA)) {
            qint64 nFit = (nNextVA - headerTarget.VirtualAddress) - nTargetDelta;

            if (nFit <= 0) {
                result.sError = QString("No room for the data in section %1").arg(sTargetName);
                return result;
            }

            baBlob = baDecompressed.left(nFit);
            nNeeded = nTargetDelta + baBlob.size();

            qint64 nStreamRVA = headerTarget.VirtualAddress + nTargetDelta;
            qint64 nStreamEnd = nStreamRVA + baDecompressed.size();
            qint64 nCoveredEnd = nStreamRVA + nFit;
            qint64 nSectionAlignment = qMax<qint64>(pe.getOptionalHeader_SectionAlignment(), 1);

            QList<qint32> listOrder;

            for (qint32 i = 0; i < listSections.count(); i++) {
                if ((i != nTarget) && (listSections.at(i).VirtualAddress >= (quint32)nNextVA)) {
                    listOrder.append(i);
                }
            }

            std::sort(listOrder.begin(), listOrder.end(), [&](qint32 a, qint32 b) { return listSections.at(a).VirtualAddress < listSections.at(b).VirtualAddress; });

            for (qint32 nIndex : listOrder) {
                const XPE_DEF::IMAGE_SECTION_HEADER &header = listSections.at(nIndex);
                qint64 nSecRVA = header.VirtualAddress;

                if ((nSecRVA >= nStreamEnd) || (nSecRVA > nCoveredEnd)) {
                    break;  // stream ended, or a gap that the stream does not cover contiguously
                }

                qint64 nSecSpan = _alignUp(qMax<qint64>(header.Misc.VirtualSize, header.SizeOfRawData), nSectionAlignment);
                qint64 nLen = qMin(nStreamEnd, nSecRVA + nSecSpan) - nSecRVA;

                mapSpill.insert(nIndex, baDecompressed.mid(nSecRVA - nStreamRVA, nLen));
                nCoveredEnd = nSecRVA + nLen;
                result.listLog.append(QString("%1 (#%2): overwritten with 0x%3 bytes of the stream (RVA 0x%4..0x%5)")
                                          .arg(_sectionName(header))
                                          .arg(nIndex)
                                          .arg(nLen, 0, 16)
                                          .arg(nSecRVA, 0, 16)
                                          .arg(nSecRVA + nLen, 0, 16));
            }

            if (nCoveredEnd < nStreamEnd) {
                QByteArray baTail = baDecompressed.mid(nCoveredEnd - nStreamRVA);
                QString sTailFile = sOutput + QString(".tail.bin");
                QFile fileTail(sTailFile);

                if (fileTail.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                    fileTail.write(baTail);
                    fileTail.close();
                }

                result.listLog.append(QString("0x%1 bytes beyond the last section (usually the packer's own loader tables) saved to %2")
                                          .arg(baTail.size(), 0, 16)
                                          .arg(QFileInfo(sTailFile).fileName()));
            }
        } else {
            result.listLog.append(QString("%1: VirtualSize 0x%2 -> 0x%3 (blob is larger)").arg(sTargetName).arg(nTargetVSize, 0, 16).arg(nNeeded, 0, 16));
            nTargetVSize = nNeeded;
        }
    }

    if ((baDecompressed.size() >= 2) && (baDecompressed.at(0) == 'M') && (baDecompressed.at(1) == 'Z')) {
        result.listLog.append(QString("Note: the blob starts with MZ - it may be a complete file; saving it directly may be the better choice"));
    }

    // new raw content of the target: existing raw bytes (if any) with the blob written over them
    QByteArray baTargetRaw;

    if ((headerTarget.SizeOfRawData > 0) && (headerTarget.PointerToRawData < (quint32)baIn.size())) {
        baTargetRaw = baIn.mid(headerTarget.PointerToRawData, qMin<qint64>(headerTarget.SizeOfRawData, baIn.size() - headerTarget.PointerToRawData));
    }

    if (baTargetRaw.size() < nNeeded) {
        baTargetRaw.append(QByteArray((qsizetype)(nNeeded - baTargetRaw.size()), 0));
    }

    memcpy(baTargetRaw.data() + nTargetDelta, baBlob.constData(), (size_t)baBlob.size());

    // --- entry point
    quint32 nOldEntryPoint = pe.getOptionalHeader_AddressOfEntryPoint();
    quint32 nEntryPoint = nOldEntryPoint;

    if (options.nOEP) {
        quint64 nSizeOfImageGuess = qMax<qint64>(nOldSizeOfImage, headerTarget.VirtualAddress + nTargetVSize);

        if ((options.nOEP >= nImageBase) && (options.nOEP - nImageBase < nSizeOfImageGuess)) {
            nEntryPoint = (quint32)(options.nOEP - nImageBase);
        } else if (options.nOEP < nSizeOfImageGuess) {
            nEntryPoint = (quint32)options.nOEP;
        } else {
            result.sError = QString("OEP 0x%1 is neither a VA nor an RVA inside the image").arg(options.nOEP, 0, 16);
            return result;
        }
    }

    // --- new layout: headers, then every section with raw data in section order, then the overlay
    QByteArray baOut = baIn.left((qsizetype)nSizeOfHeaders);
    baOut.append(QByteArray((qsizetype)(_alignUp(nSizeOfHeaders, nFileAlignment) - nSizeOfHeaders), 0));

    QList<MOVE> listMoves;
    QList<XPE_DEF::IMAGE_SECTION_HEADER> listNewSections = listSections;

    for (qint32 i = 0; i < listSections.count(); i++) {
        XPE_DEF::IMAGE_SECTION_HEADER header = listSections.at(i);
        QByteArray baRaw;
        bool bMoved = false;

        if (i == nTarget) {
            baRaw = baTargetRaw;
        } else if (mapSpill.contains(i)) {
            baRaw = mapSpill.value(i);
            header.Misc.VirtualSize = qMax<quint32>(header.Misc.VirtualSize, (quint32)baRaw.size());

            if (options.bRestoreCharacteristics) {
                bool bHasEntry = (nEntryPoint >= header.VirtualAddress) && (nEntryPoint < header.VirtualAddress + header.Misc.VirtualSize);
                header.Characteristics = bHasEntry ? 0x60000020 : 0xC0000040;
            }
        } else if ((header.SizeOfRawData > 0) && (header.PointerToRawData < (quint32)baIn.size())) {
            baRaw = baIn.mid(header.PointerToRawData, qMin<qint64>(header.SizeOfRawData, baIn.size() - header.PointerToRawData));
            bMoved = true;
        }

        if (baRaw.isEmpty()) {
            header.PointerToRawData = 0;
            header.SizeOfRawData = 0;
        } else {
            qint64 nNewOffset = baOut.size();

            if (bLowAlignment) {
                // low-alignment images are mapped 1:1, raw offset must equal the RVA
                if (nNewOffset > header.VirtualAddress) {
                    result.sError = QString("Low-alignment image with sections out of RVA order; not supported");
                    return result;
                }

                nNewOffset = header.VirtualAddress;
            }

            if (nNewOffset > baOut.size()) {
                baOut.append(QByteArray((qsizetype)(nNewOffset - baOut.size()), 0));
            }

            qint64 nRawSize = _alignUp(baRaw.size(), nFileAlignment);
            header.PointerToRawData = (quint32)nNewOffset;
            header.SizeOfRawData = (quint32)nRawSize;
            baOut.append(baRaw);
            baOut.append(QByteArray((qsizetype)(nRawSize - baRaw.size()), 0));

            if (bMoved) {
                MOVE move = {listSections.at(i).PointerToRawData, baRaw.size(), nNewOffset};
                listMoves.append(move);
            }
        }

        if (i == nTarget) {
            header.Misc.VirtualSize = (quint32)nTargetVSize;
            quint32 nOld = header.Characteristics;
            bool bHasEntry = (nEntryPoint >= header.VirtualAddress) && (nEntryPoint < header.VirtualAddress + nTargetVSize);

            header.Characteristics &= ~0x00000080u;  // no longer uninitialized data

            if (options.bRestoreCharacteristics) {
                if (bHasEntry) {
                    header.Characteristics = 0x60000020;  // code, R-X
                } else {
                    header.Characteristics = 0xC0000040;  // initialized data, RW-
                }
            } else {
                header.Characteristics |= XPE_DEF::S_IMAGE_SCN_MEM_READ;

                if (!(header.Characteristics & 0x00000020)) {
                    header.Characteristics |= 0x00000040;
                }
            }

            result.listLog.append(QString("%1 (#%2): blob 0x%3 bytes at RVA 0x%4, raw 0x%5 at file offset 0x%6, characteristics 0x%7 -> 0x%8")
                                      .arg(sTargetName)
                                      .arg(i)
                                      .arg(baDecompressed.size(), 0, 16)
                                      .arg(header.VirtualAddress + nTargetDelta, 0, 16)
                                      .arg(header.SizeOfRawData, 0, 16)
                                      .arg(header.PointerToRawData, 0, 16)
                                      .arg(nOld, 8, 16, QChar('0'))
                                      .arg(header.Characteristics, 8, 16, QChar('0')));
        }

        listNewSections[i] = header;
    }

    qint64 nNewOverlayOffset = -1;

    if (bOverlay && (nOverlayOffset > 0) && (nOverlaySize > 0)) {
        nNewOverlayOffset = baOut.size();
        baOut.append(baIn.mid(nOverlayOffset, nOverlaySize));
        result.listLog.append(QString("Overlay 0x%1 bytes kept (0x%2 -> 0x%3)").arg(nOverlaySize, 0, 16).arg(nOverlayOffset, 0, 16).arg(nNewOverlayOffset, 0, 16));
    }

    // --- patch the headers of the new image
    QBuffer bufferOut(&baOut);
    bufferOut.open(QIODevice::ReadWrite);
    XPE peOut(&bufferOut);

    if (!peOut.isValid()) {
        result.sError = QString("Internal error: the rebuilt headers are not valid");
        return result;
    }

    qint64 nSizeOfImage = 0;

    for (qint32 i = 0; i < listNewSections.count(); i++) {
        peOut.setSectionHeader(i, &listNewSections[i]);
        qint64 nEnd = (qint64)listNewSections.at(i).VirtualAddress + qMax<qint64>(listNewSections.at(i).Misc.VirtualSize, listNewSections.at(i).SizeOfRawData);
        nSizeOfImage = qMax<qint64>(nSizeOfImage, nEnd);
    }

    nSizeOfImage = _alignUp(nSizeOfImage, nSectionAlignment);
    peOut.setOptionalHeader_SizeOfImage((quint32)nSizeOfImage);

    if (nSizeOfImage != nOldSizeOfImage) {
        result.listLog.append(QString("SizeOfImage 0x%1 -> 0x%2").arg(nOldSizeOfImage, 0, 16).arg(nSizeOfImage, 0, 16));
    }

    if (nEntryPoint >= nSizeOfImage) {
        result.sError = QString("Entry point RVA 0x%1 is outside the image").arg(nEntryPoint, 0, 16);
        return result;
    }

    peOut.setOptionalHeader_AddressOfEntryPoint(nEntryPoint);

    if (nEntryPoint != nOldEntryPoint) {
        result.listLog.append(QString("AddressOfEntryPoint 0x%1 -> 0x%2 (VA 0x%3)").arg(nOldEntryPoint, 0, 16).arg(nEntryPoint, 0, 16).arg(nImageBase + nEntryPoint, 0, 16));
    }

    // certificate table: its "VirtualAddress" is a file offset
    XPE_DEF::IMAGE_DATA_DIRECTORY ddSecurity = peOut.getOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_SECURITY);

    if (ddSecurity.VirtualAddress || ddSecurity.Size) {
        if ((nNewOverlayOffset >= 0) && (ddSecurity.VirtualAddress >= nOverlayOffset) && (ddSecurity.VirtualAddress < nOverlayOffset + nOverlaySize)) {
            ddSecurity.VirtualAddress = (quint32)(nNewOverlayOffset + (ddSecurity.VirtualAddress - nOverlayOffset));
            result.listLog.append(QString("Certificate table moved with the overlay (the signature is no longer valid)"));
        } else {
            ddSecurity.VirtualAddress = 0;
            ddSecurity.Size = 0;
            result.listLog.append(QString("Certificate table dropped (not in the overlay)"));
        }

        peOut.setOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_SECURITY, &ddSecurity);
    }

    // COFF symbol table pointer (file offset)
    quint32 nSymbols = peOut.getFileHeader_PointerToSymbolTable();

    if (nSymbols) {
        qint64 nNew = -1;

        if ((nNewOverlayOffset >= 0) && (nSymbols >= nOverlayOffset) && (nSymbols < nOverlayOffset + nOverlaySize)) {
            nNew = nNewOverlayOffset + (nSymbols - nOverlayOffset);
        } else if (!_remap(listMoves, nSymbols, &nNew)) {
            nNew = -1;
        }

        if (nNew >= 0) {
            peOut.setFileHeader_PointerToSymbolTable((quint32)nNew);
        } else {
            peOut.setFileHeader_PointerToSymbolTable(0);
            peOut.setFileHeader_NumberOfSymbols(0);
            result.listLog.append(QString("COFF symbol table pointer cleared"));
        }
    }

    // debug directory entries: PointerToRawData is a file offset
    XPE_DEF::IMAGE_DATA_DIRECTORY ddDebug = peOut.getOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_DEBUG);

    if (ddDebug.VirtualAddress && ddDebug.Size) {
        XBinary::_MEMORY_MAP memoryMapOut = peOut.getMemoryMap(XBinary::MAPMODE_UNKNOWN, pPdStruct);
        qint64 nDebugOffset = XBinary::relAddressToOffset(&memoryMapOut, ddDebug.VirtualAddress);
        qint32 nFixed = 0;

        if (nDebugOffset > 0) {
            qint32 nEntries = qMin<qint32>(ddDebug.Size / 28, 64);

            for (qint32 i = 0; i < nEntries; i++) {
                qint64 nField = nDebugOffset + i * 28 + 24;

                if (nField + 4 > baOut.size()) {
                    break;
                }

                quint32 nOld = qFromLittleEndian<quint32>(baOut.constData() + nField);
                qint64 nNew = -1;

                if (nOld && _remap(listMoves, nOld, &nNew)) {
                    qToLittleEndian<quint32>((quint32)nNew, baOut.data() + nField);
                    nFixed++;
                }
            }
        }

        if (nFixed) {
            result.listLog.append(QString("Debug directory: %1 file offset(s) updated").arg(nFixed));
        }
    }

    bufferOut.close();

    // --- write
    if (QFile::exists(sOutput) && !QFile::remove(sOutput)) {
        result.sError = QString("Cannot overwrite %1").arg(sOutput);
        return result;
    }

    {
        QFile fileOut(sOutput);

        if (!fileOut.open(QIODevice::WriteOnly | QIODevice::Truncate) || (fileOut.write(baOut) != baOut.size())) {
            result.sError = QString("Cannot write %1").arg(sOutput);
            return result;
        }
    }

    result.listLog.append(QString("Wrote %1 (0x%2 bytes)").arg(sOutput).arg(baOut.size(), 0, 16));

    if (options.bRebuildImports) {
        RESULT resultImports = {};

        if (_reconstructImportsInPlace(sOutput, &resultImports, pPdStruct)) {
            result.nImportsRecovered = resultImports.nImportsRecovered;
        } else {
            resultImports.listLog.append(QString("Imports not rebuilt: %1").arg(resultImports.sError));
        }

        result.listLog.append(resultImports.listLog);
    }

    if (options.bFixChecksum) {
        QFile file(sOutput);

        if (file.open(QIODevice::ReadWrite)) {
            XPE peFile(&file);

            if (peFile.isValid()) {
                peFile.fixCheckSum();
                result.listLog.append(QString("CheckSum 0x%1").arg(peFile.getOptionalHeader_CheckSum(), 8, 16, QChar('0')));
            }

            file.close();
        }
    }

    result.bSuccess = true;

    return result;
}

HelperRebuild::RESULT HelperRebuild::reconstructImports(const QString &sInput, const QString &sOutput, XBinary::PDSTRUCT *pPdStruct)
{
    RESULT result = {};

    if (QFile::exists(sOutput) && !QFile::remove(sOutput)) {
        result.sError = QString("Cannot overwrite %1").arg(sOutput);
        return result;
    }

    if (!XBinary::copyFile(sInput, sOutput)) {
        result.sError = QString("Cannot copy %1 to %2").arg(sInput, sOutput);
        return result;
    }

    result.listLog.append(QString("Copy: %1").arg(sOutput));
    result.bSuccess = _reconstructImportsInPlace(sOutput, &result, pPdStruct);

    if (!result.bSuccess) {
        QFile::remove(sOutput);
    }

    return result;
}

bool HelperRebuild::_reconstructImportsInPlace(const QString &sFileName, RESULT *pResult, XBinary::PDSTRUCT *pPdStruct)
{
    QFile file(sFileName);

    if (!file.open(QIODevice::ReadWrite)) {
        pResult->sError = QString("Cannot open %1 for writing").arg(sFileName);
        return false;
    }

    if (file.size() > N_HELPER_REBUILD_MAX_FILE) {
        pResult->sError = QString("The file is larger than %1 MiB").arg(N_HELPER_REBUILD_MAX_FILE >> 20);
        return false;
    }

    const QByteArray baFile = file.readAll();
    const quint8 *pFile = (const quint8 *)baFile.constData();
    const qint64 nFileSize = baFile.size();

    XPE pe(&file);

    if (!pe.isValid()) {
        pResult->sError = QString("Not a valid PE file");
        return false;
    }

    XBinary::_MEMORY_MAP memoryMap = pe.getMemoryMap(XBinary::MAPMODE_UNKNOWN, pPdStruct);
    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders(pPdStruct);
    const bool bIs64 = pe.is64();
    const qint32 nPtr = bIs64 ? 8 : 4;
    const quint64 nOrdinalFlag = bIs64 ? 0x8000000000000000ULL : 0x80000000ULL;
    const qint64 nSizeOfImage = pe.getOptionalHeader_SizeOfImage();
    XPE_DEF::IMAGE_DATA_DIRECTORY ddImport = pe.getOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_IMPORT);

    QList<FILE_REGION> listRegions;

    for (const XPE_DEF::IMAGE_SECTION_HEADER &header : listSections) {
        if ((header.SizeOfRawData == 0) || (header.PointerToRawData == 0) || (header.PointerToRawData >= nFileSize)) {
            continue;
        }

        FILE_REGION region = {};
        region.nOffset = header.PointerToRawData;
        region.nSize = qMin<qint64>(qMin<qint64>(header.SizeOfRawData, nFileSize - header.PointerToRawData),
                                    header.Misc.VirtualSize ? (qint64)header.Misc.VirtualSize : (qint64)header.SizeOfRawData);
        region.nRVA = header.VirtualAddress;
        listRegions.append(region);
    }

    auto rvaToOffset = [&](quint64 nRVA) -> qint64 {
        if ((nRVA == 0) || (nRVA >= (quint64)nSizeOfImage)) {
            return -1;
        }

        qint64 nOffset = XBinary::relAddressToOffset(&memoryMap, (qint64)nRVA);

        if ((nOffset < 0) || (nOffset >= nFileSize)) {
            return -1;
        }

        return nOffset;
    };

    auto readThunk = [&](qint64 nOffset) -> quint64 {
        return bIs64 ? qFromLittleEndian<quint64>(pFile + nOffset) : (quint64)qFromLittleEndian<quint32>(pFile + nOffset);
    };

    // a thunk value -> import position (named via hint/name entry, or ordinal); false if it is not one
    auto thunkToPosition = [&](quint64 nValue, XPE::IMPORT_POSITION *pPosition) -> bool {
        *pPosition = XPE::IMPORT_POSITION();

        if (nValue & nOrdinalFlag) {
            if ((nValue & ~nOrdinalFlag) > 0xFFFF) {
                return false;
            }

            pPosition->nOrdinal = (qint64)(nValue & 0xFFFF);
            pPosition->sFunction = QString("#%1").arg(pPosition->nOrdinal);

            return pPosition->nOrdinal != 0;
        }

        qint64 nHintOffset = rvaToOffset(nValue);
        QString sName;

        if ((nHintOffset < 0) || (nHintOffset + 2 >= nFileSize) || !_readCString(baFile, nHintOffset + 2, 256, &sName) || !_isApiName(sName)) {
            return false;
        }

        pPosition->nHint = qFromLittleEndian<quint16>(pFile + nHintOffset);
        pPosition->sName = sName;
        pPosition->sFunction = sName;

        return true;
    };

    // zero-terminated thunk table at an RVA
    auto parseThunkTable = [&](quint64 nTableRVA, QList<XPE::IMPORT_POSITION> *pList) -> bool {
        qint64 nOffset = rvaToOffset(nTableRVA);

        if (nOffset < 0) {
            return false;
        }

        for (qint32 j = 0; j < N_HELPER_MAX_THUNKS; j++) {
            qint64 nSlot = nOffset + (qint64)j * nPtr;

            if (nSlot + nPtr > nFileSize) {
                return false;
            }

            quint64 nValue = readThunk(nSlot);

            if (nValue == 0) {
                return true;
            }

            XPE::IMPORT_POSITION position;

            if (!thunkToPosition(nValue, &position)) {
                return false;
            }

            pList->append(position);
        }

        return false;
    };

    // ranges of the active import tables (excluded from the search)
    QList<QPair<qint64, qint64>> listActive;  // RVA, size

    {
        QList<XPE_DEF::IMAGE_IMPORT_DESCRIPTOR> listDescriptors = pe.getImportDescriptors(&memoryMap);

        for (const XPE_DEF::IMAGE_IMPORT_DESCRIPTOR &iid : listDescriptors) {
            const quint32 nTables[2] = {iid.OriginalFirstThunk, iid.FirstThunk};

            for (quint32 nTable : nTables) {
                qint64 nOffset = rvaToOffset(nTable);

                if (nOffset < 0) {
                    continue;
                }

                qint64 nCount = 0;

                while ((nOffset + (nCount + 1) * nPtr <= nFileSize) && (nCount < N_HELPER_MAX_THUNKS) && readThunk(nOffset + nCount * nPtr)) {
                    nCount++;
                }

                listActive.append(qMakePair((qint64)nTable, (nCount + 1) * nPtr));
            }
        }

        if (ddImport.VirtualAddress) {
            listActive.append(qMakePair((qint64)ddImport.VirtualAddress, (qint64)qMax<quint32>(ddImport.Size, 20)));
        }

        // delay-load name/address tables look exactly like IATs: keep them out of method 2
        XPE_DEF::IMAGE_DATA_DIRECTORY ddDelay = pe.getOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
        qint64 nDelayOffset = rvaToOffset(ddDelay.VirtualAddress);
        quint64 nImageBase = pe.getOptionalHeader_ImageBase();

        if (nDelayOffset >= 0) {
            listActive.append(qMakePair((qint64)ddDelay.VirtualAddress, (qint64)qMax<quint32>(ddDelay.Size, 32)));

            for (qint32 i = 0; (i < N_HELPER_MAX_DESCRIPTORS) && (nDelayOffset + (i + 1) * 32 <= nFileSize); i++) {
                const quint8 *pEntry = pFile + nDelayOffset + i * 32;
                quint32 nAttributes = qFromLittleEndian<quint32>(pEntry + 0);
                quint64 nIAT = qFromLittleEndian<quint32>(pEntry + 12);
                quint64 nINT = qFromLittleEndian<quint32>(pEntry + 16);

                if ((qFromLittleEndian<quint32>(pEntry + 4) == 0) && (nIAT == 0) && (nINT == 0)) {
                    break;
                }

                if (!(nAttributes & 1)) {
                    // VC6-style delay descriptor: VAs (32-bit images only)
                    nIAT = (nIAT >= nImageBase) ? (nIAT - nImageBase) : 0;
                    nINT = (nINT >= nImageBase) ? (nINT - nImageBase) : 0;
                }

                const quint64 nDelayTables[2] = {nIAT, nINT};

                for (quint64 nTable : nDelayTables) {
                    qint64 nOffset = rvaToOffset(nTable);

                    if (nOffset < 0) {
                        continue;
                    }

                    qint64 nCount = 0;

                    while ((nOffset + (nCount + 1) * nPtr <= nFileSize) && (nCount < N_HELPER_MAX_THUNKS) && readThunk(nOffset + nCount * nPtr)) {
                        nCount++;
                    }

                    listActive.append(qMakePair((qint64)nTable, (nCount + 1) * nPtr));
                }
            }
        }

        pResult->listLog.append(QString("Active import directory: %1 DLL(s)").arg(listDescriptors.count()));
    }

    auto isActive = [&](qint64 nRVA) -> bool {
        for (const QPair<qint64, qint64> &range : listActive) {
            if ((nRVA >= range.first) && (nRVA < range.first + range.second)) {
                return true;
            }
        }

        return false;
    };

    // ---------------------------------------------------------------- method 1: descriptor arrays
    qint64 nBestArrayRVA = -1;
    qint32 nBestArrayCount = 0;
    qint32 nBestArrayFunctions = 0;
    qint64 nBestIatStart = -1;
    qint64 nBestIatEnd = -1;

    for (const FILE_REGION &region : listRegions) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) {
            break;
        }

        for (qint64 nOffset = _alignUp(region.nOffset, 4); nOffset + 20 <= region.nOffset + region.nSize; nOffset += 4) {
            const quint8 *pIID = pFile + nOffset;
            quint32 nName = qFromLittleEndian<quint32>(pIID + 12);
            quint32 nFirstThunk = qFromLittleEndian<quint32>(pIID + 16);
            quint32 nOFT = qFromLittleEndian<quint32>(pIID + 0);

            if ((nName == 0) || (nName >= nSizeOfImage) || (nFirstThunk == 0) || (nFirstThunk >= nSizeOfImage) || (nOFT >= nSizeOfImage)) {
                continue;
            }

            qint64 nArrayRVA = region.nRVA + (nOffset - region.nOffset);

            if (isActive(nArrayRVA)) {
                continue;
            }

            QString sDll;

            if (!_readCString(baFile, rvaToOffset(nName), 64, &sDll) || !_isDllName(sDll)) {
                continue;
            }

            // parse the whole array
            qint32 nCount = 0;
            qint32 nFunctions = 0;
            bool bTerminated = false;
            bool bValid = true;
            qint64 nIatStart = -1;
            qint64 nIatEnd = -1;

            for (qint32 k = 0; k < N_HELPER_MAX_DESCRIPTORS; k++) {
                qint64 nEntry = nOffset + (qint64)k * 20;

                if (nEntry + 20 > region.nOffset + region.nSize) {
                    break;
                }

                const quint8 *pEntry = pFile + nEntry;
                quint32 nEntryOFT = qFromLittleEndian<quint32>(pEntry + 0);
                quint32 nEntryName = qFromLittleEndian<quint32>(pEntry + 12);
                quint32 nEntryFirstThunk = qFromLittleEndian<quint32>(pEntry + 16);

                if ((nEntryOFT == 0) && (nEntryName == 0) && (nEntryFirstThunk == 0)) {
                    bTerminated = true;
                    break;
                }

                QString sEntryDll;

                if (!_readCString(baFile, rvaToOffset(nEntryName), 64, &sEntryDll) || !_isDllName(sEntryDll) || (nEntryFirstThunk == 0) ||
                    (nEntryFirstThunk >= nSizeOfImage)) {
                    bValid = false;
                    break;
                }

                QList<XPE::IMPORT_POSITION> listPositions;
                bool bTable = (nEntryOFT != 0) && parseThunkTable(nEntryOFT, &listPositions);

                if (!bTable) {
                    listPositions.clear();
                    bTable = parseThunkTable(nEntryFirstThunk, &listPositions);
                }

                if (!bTable) {
                    bValid = false;  // neither table readable: the loader could not use it either
                    break;
                }

                nFunctions += listPositions.count();
                nCount++;

                qint64 nTableEnd = (qint64)nEntryFirstThunk + (listPositions.count() + 1) * nPtr;
                nIatStart = (nIatStart == -1) ? nEntryFirstThunk : qMin<qint64>(nIatStart, nEntryFirstThunk);
                nIatEnd = qMax<qint64>(nIatEnd, nTableEnd);
            }

            if (bValid && bTerminated && (nCount > 0) && (nFunctions > 0)) {
                if (nFunctions > nBestArrayFunctions) {
                    nBestArrayRVA = nArrayRVA;
                    nBestArrayCount = nCount;
                    nBestArrayFunctions = nFunctions;
                    nBestIatStart = nIatStart;
                    nBestIatEnd = nIatEnd;
                }

                nOffset += (qint64)nCount * 20;  // past the terminator (loop adds 4)
            }
        }
    }

    if (nBestArrayRVA != -1) {
        XPE_DEF::IMAGE_DATA_DIRECTORY ddNewImport = {};
        ddNewImport.VirtualAddress = (quint32)nBestArrayRVA;
        ddNewImport.Size = (quint32)((nBestArrayCount + 1) * 20);
        pe.setOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_IMPORT, &ddNewImport);

        XPE_DEF::IMAGE_DATA_DIRECTORY ddIAT = {};
        ddIAT.VirtualAddress = (quint32)nBestIatStart;
        ddIAT.Size = (quint32)(nBestIatEnd - nBestIatStart);
        pe.setOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_IAT, &ddIAT);
        pe.fixCheckSum();

        pResult->nImportsRecovered = nBestArrayFunctions;
        pResult->listLog.append(QString("Imports: found a complete import descriptor array at RVA 0x%1 (%2 DLL(s), %3 function(s)); import directory "
                                        "0x%4/0x%5 -> 0x%6/0x%7, IAT directory 0x%8/0x%9")
                                    .arg(nBestArrayRVA, 0, 16)
                                    .arg(nBestArrayCount)
                                    .arg(nBestArrayFunctions)
                                    .arg(ddImport.VirtualAddress, 0, 16)
                                    .arg(ddImport.Size, 0, 16)
                                    .arg(ddNewImport.VirtualAddress, 0, 16)
                                    .arg(ddNewImport.Size, 0, 16)
                                    .arg(ddIAT.VirtualAddress, 0, 16)
                                    .arg(ddIAT.Size, 0, 16));

        return true;
    }

    // ---------------------------------------------------------------- method 2: IAT-shaped tables
    QList<GROUP> listGroups;

    auto findDllNameNear = [&](qint64 nNamesStart, qint64 nNamesEnd, QString *psDll) -> bool {
        // forward: linkers put the DLL name right after its hint/name entries
        for (qint64 p = nNamesEnd; (p < nNamesEnd + 0x200) && (p < nFileSize); p++) {
            if ((p == nNamesEnd) || (pFile[p - 1] == 0)) {
                QString sString;

                if (_readCString(baFile, p, 64, &sString) && _isDllName(sString)) {
                    *psDll = sString;
                    return true;
                }
            }
        }

        for (qint64 p = qMax<qint64>(0, nNamesStart - 0x200); p < nNamesStart; p++) {
            if ((p == 0) || (pFile[p - 1] == 0)) {
                QString sString;

                if (_readCString(baFile, p, 64, &sString) && _isDllName(sString)) {
                    *psDll = sString;  // keep the closest one before the names
                }
            }
        }

        return !psDll->isEmpty();
    };

    for (const FILE_REGION &region : listRegions) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) {
            break;
        }

        qint64 nRegionEnd = region.nOffset + region.nSize;
        qint64 nOffset = region.nOffset + (_alignUp(region.nRVA, nPtr) - region.nRVA);

        while (nOffset + nPtr <= nRegionEnd) {
            qint64 nSlotRVA = region.nRVA + (nOffset - region.nOffset);
            XPE::IMPORT_POSITION first;

            if (isActive(nSlotRVA) || !thunkToPosition(readThunk(nOffset), &first) || first.sName.isEmpty()) {
                nOffset += nPtr;
                continue;
            }

            // parse groups separated by a single zero slot
            QList<GROUP> listIat;
            qint64 nPos = nOffset;
            qint32 nNamed = 0;

            while (nPos + nPtr <= nRegionEnd) {
                GROUP group;
                group.nTableRVA = region.nRVA + (nPos - region.nOffset);
                qint64 nNamesStart = -1;
                qint64 nNamesEnd = -1;

                while ((nPos + nPtr <= nRegionEnd) && (group.listPositions.count() < N_HELPER_MAX_THUNKS)) {
                    quint64 nValue = readThunk(nPos);

                    if (nValue == 0) {
                        break;
                    }

                    XPE::IMPORT_POSITION position;

                    if (isActive(region.nRVA + (nPos - region.nOffset)) || !thunkToPosition(nValue, &position)) {
                        break;
                    }

                    if (!position.sName.isEmpty()) {
                        qint64 nHintOffset = rvaToOffset(nValue);
                        nNamesStart = (nNamesStart == -1) ? nHintOffset : qMin<qint64>(nNamesStart, nHintOffset);
                        nNamesEnd = qMax<qint64>(nNamesEnd, nHintOffset + 2 + position.sName.length() + 1);
                        nNamed++;
                    }

                    group.listPositions.append(position);
                    nPos += nPtr;
                }

                bool bTerminated = (nPos + nPtr <= nRegionEnd) && (readThunk(nPos) == 0);

                if (group.listPositions.isEmpty() || !bTerminated || (nNamesStart == -1)) {
                    break;
                }

                if (!findDllNameNear(nNamesStart, nNamesEnd, &group.sLibrary)) {
                    pResult->listLog.append(QString("Imports: thunk table at RVA 0x%1 (%2 entries) has no DLL name nearby; skipped")
                                                .arg(group.nTableRVA, 0, 16)
                                                .arg(group.listPositions.count()));
                } else {
                    listIat.append(group);
                }

                nPos += nPtr;  // the zero slot

                // next group follows directly?
                XPE::IMPORT_POSITION next;

                if ((nPos + nPtr > nRegionEnd) || !thunkToPosition(readThunk(nPos), &next)) {
                    break;
                }
            }

            if (nNamed >= 2) {
                listGroups.append(listIat);
                nOffset = qMax<qint64>(nPos, nOffset + nPtr);
            } else {
                nOffset += nPtr;
            }
        }
    }

    bool bKnownIat = !listGroups.isEmpty();

    // ---------------------------------------------------------------- method 3: name lists
    if (listGroups.isEmpty()) {
        QMap<QString, qint32> mapLibraryIndex;  // lower-case name -> index in listGroups

        for (const FILE_REGION &region : listRegions) {
            if (!XBinary::isPdStructNotCanceled(pPdStruct)) {
                break;
            }

            qint64 nRegionEnd = region.nOffset + region.nSize;

            for (qint64 nOffset = region.nOffset; nOffset + 5 <= nRegionEnd; nOffset++) {
                if ((pFile[nOffset] != '.') || (pFile[nOffset + 4] != 0) || (qstrnicmp((const char *)pFile + nOffset, ".dll", 4) != 0)) {
                    continue;
                }

                qint64 nStart = nOffset;

                while ((nStart > region.nOffset) && (nOffset - nStart < 60) && _isDllNameChar(pFile[nStart - 1])) {
                    nStart--;
                }

                QString sDll = QString::fromLatin1((const char *)pFile + nStart, (int)(nOffset + 4 - nStart));

                if (!_isDllName(sDll)) {
                    continue;
                }

                QList<XPE::IMPORT_POSITION> listPositions;
                qint32 nNamed = 0;
                qint64 nPos = nOffset + 5;

                while ((nPos < nRegionEnd) && (listPositions.count() < N_HELPER_MAX_THUNKS)) {
                    quint8 nByte = pFile[nPos];

                    if (nByte == 0) {
                        break;
                    }

                    if (nByte == 0xFF) {
                        // UPX-style: 0xFF + 16-bit ordinal
                        if (nPos + 3 > nRegionEnd) {
                            break;
                        }

                        XPE::IMPORT_POSITION position = {};
                        position.nOrdinal = qFromLittleEndian<quint16>(pFile + nPos + 1);

                        if (position.nOrdinal == 0) {
                            break;
                        }

                        position.sFunction = QString("#%1").arg(position.nOrdinal);
                        listPositions.append(position);
                        nPos += 3;
                        continue;
                    }

                    if (nByte == 0x01) {
                        nPos++;  // UPX-style name prefix
                    }

                    QString sName;

                    if (!_readCString(baFile, nPos, 256, &sName) || !_isApiName(sName)) {
                        break;
                    }

                    XPE::IMPORT_POSITION position = {};
                    position.sName = sName;
                    position.sFunction = sName;
                    listPositions.append(position);
                    nNamed++;
                    nPos += sName.length() + 1;
                }

                if (nNamed >= 2) {
                    QString sKey = sDll.toLower();

                    if (!mapLibraryIndex.contains(sKey)) {
                        GROUP group;
                        group.sLibrary = sDll;
                        group.nTableRVA = -1;
                        mapLibraryIndex.insert(sKey, listGroups.count());
                        listGroups.append(group);
                    }

                    GROUP &group = listGroups[mapLibraryIndex.value(sKey)];
                    QSet<QString> stKnown;

                    for (const XPE::IMPORT_POSITION &position : group.listPositions) {
                        stKnown.insert(position.sFunction);
                    }

                    for (const XPE::IMPORT_POSITION &position : listPositions) {
                        if (!stKnown.contains(position.sFunction)) {
                            group.listPositions.append(position);
                            stKnown.insert(position.sFunction);
                        }
                    }

                    nOffset = nPos;
                }
            }
        }
    }

    if (listGroups.isEmpty()) {
        pResult->sError = QString("No leftover import data found besides the active import directory");
        return false;
    }

    // ---------------------------------------------------------------- rebuild through XPE::setImports
    QList<XPE::IMPORT_HEADER> listHeaders;
    qint32 nFunctions = 0;

    for (const GROUP &group : listGroups) {
        XPE::IMPORT_HEADER header = {};
        header.sName = group.sLibrary;
        header.nFirstThunk = 0;  // patched below (XPE::setImports copies only 32-bit values for it)
        header.listPositions = group.listPositions;
        listHeaders.append(header);
        nFunctions += group.listPositions.count();

        QStringList listNames;

        for (qint32 i = 0; (i < group.listPositions.count()) && (i < 6); i++) {
            listNames.append(group.listPositions.at(i).sFunction);
        }

        pResult->listLog.append(QString("Imports: %1 - %2 function(s)%3: %4%5")
                                    .arg(group.sLibrary)
                                    .arg(group.listPositions.count())
                                    .arg((group.nTableRVA >= 0) ? QString(" (IAT at RVA 0x%1)").arg(group.nTableRVA, 0, 16) : QString())
                                    .arg(listNames.join(", "))
                                    .arg((group.listPositions.count() > 6) ? QString(", ...") : QString()));
    }

    if (!pe.setImports(&listHeaders, pPdStruct)) {
        pResult->sError = QString("XPE::setImports failed (no room for a new section header?)");
        return false;
    }

    XPE peNew(&file);

    if (!peNew.isValid()) {
        pResult->sError = QString("The file is not valid after adding the import section");
        return false;
    }

    quint32 nNumberOfSections = peNew.getFileHeader_NumberOfSections();

    if (nNumberOfSections) {
        peNew.setSection_NameAsString(nNumberOfSections - 1, ".hidata");
    }

    if (bKnownIat) {
        // point every descriptor back at the original thunk table, so the code's IAT slots get resolved
        qint64 nIatStart = -1;
        qint64 nIatEnd = -1;

        for (qint32 i = 0; i < listGroups.count(); i++) {
            XPE_DEF::IMAGE_IMPORT_DESCRIPTOR iid = peNew.getImportDescriptor(i);
            iid.FirstThunk = (quint32)listGroups.at(i).nTableRVA;
            peNew.setImportDescriptor(i, &iid);

            qint64 nEnd = listGroups.at(i).nTableRVA + (listGroups.at(i).listPositions.count() + 1) * nPtr;
            nIatStart = (nIatStart == -1) ? listGroups.at(i).nTableRVA : qMin<qint64>(nIatStart, listGroups.at(i).nTableRVA);
            nIatEnd = qMax<qint64>(nIatEnd, nEnd);
        }

        XPE_DEF::IMAGE_DATA_DIRECTORY ddIAT = {};
        ddIAT.VirtualAddress = (quint32)nIatStart;
        ddIAT.Size = (quint32)(nIatEnd - nIatStart);
        peNew.setOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_IAT, &ddIAT);
        pResult->listLog.append(QString("Imports: FirstThunk of each descriptor points at the original table; IAT directory 0x%1/0x%2")
                                    .arg(ddIAT.VirtualAddress, 0, 16)
                                    .arg(ddIAT.Size, 0, 16));
    } else {
        pResult->listLog.append(QString("Imports: rebuilt from name lists; the IAT location is unknown, so the new IAT is in .hidata and the code does "
                                        "not call through it (static view only, the file will not run)"));
    }

    peNew.fixCheckSum();

    pResult->nImportsRecovered = nFunctions;
    pResult->listLog.append(QString("Imports: %1 DLL(s), %2 function(s) written to a new section .hidata").arg(listGroups.count()).arg(nFunctions));

    return true;
}
