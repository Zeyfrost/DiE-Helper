// DiE Helper (fork addition): UPX-specific finishing for "Decompress -> Rebuild": reads the UPX pack header,
// undoes UPX's call/jump filter and relocation encoding in the decompressed stream, then on the rebuilt copy
// rebuilds the import table, restores the original section names and clears the leftover UPX header block.
// Everything comes from data UPX itself stores in its stream ("extra info": original headers, packed
// imports, packed relocations); nothing is executed.
//
// Stream layout (as UPX's own PE unpacker reads it; verified on MSVC x86/x64 EXE and x86 DLL, UPX 5.30):
//   [image from RVAmin] ... [packed imports] ... [packed relocations, 0-terminated][extra info][dword: offset of extra info]
//   extra info = original IMAGE_NT_HEADERS + section table, then dwords: imports offset, ?, relocations offset, ...
#include "helperupx.h"

#include <QFile>
#include <cstring>

#include "xpe.h"

static quint32 _readLE32(const unsigned char *p)
{
    return (quint32)p[0] | ((quint32)p[1] << 8) | ((quint32)p[2] << 16) | ((quint32)p[3] << 24);
}

static quint64 _readLE64(const unsigned char *p)
{
    return (quint64)_readLE32(p) | ((quint64)_readLE32(p + 4) << 32);
}

static quint32 _readBE32(const unsigned char *p)
{
    return ((quint32)p[0] << 24) | ((quint32)p[1] << 16) | ((quint32)p[2] << 8) | (quint32)p[3];
}

static quint64 _readBE64(const unsigned char *p)
{
    return ((quint64)_readBE32(p) << 32) | (quint64)_readBE32(p + 4);
}

static void _writeLE32(unsigned char *p, quint32 nValue)
{
    p[0] = (unsigned char)(nValue);
    p[1] = (unsigned char)(nValue >> 8);
    p[2] = (unsigned char)(nValue >> 16);
    p[3] = (unsigned char)(nValue >> 24);
}

static void _writeLE64(unsigned char *p, quint64 nValue)
{
    _writeLE32(p, (quint32)nValue);
    _writeLE32(p + 4, (quint32)(nValue >> 32));
}

static QString _sectionName(const XPE_DEF::IMAGE_SECTION_HEADER &header)
{
    return QString::fromLatin1((const char *)header.Name, (int)strnlen((const char *)header.Name, 8));
}

HelperUpx::PACKINFO HelperUpx::readPackHeader(const QString &sFileName)
{
    PACKINFO result = {};

    QFile file(sFileName);

    if (!file.open(QIODevice::ReadOnly)) {
        return result;
    }

    // pack header: "UPX!" version format method level u_adler c_adler u_len c_len u_file_size filter filter_cto n_mru checksum
    QByteArray baHead = file.read(0x1000);
    qint32 nOffset = baHead.indexOf("UPX!");

    if ((nOffset >= 0) && (nOffset + 30 <= baHead.size())) {
        const unsigned char *p = (const unsigned char *)baHead.constData() + nOffset;
        result.nVersion = p[4];
        result.nFormat = p[5];
        result.nMethod = p[6];
        result.nUncompressedSize = _readLE32(p + 16);
        result.nFilter = p[28];
        result.nFilterCto = p[29];
        result.bIsValid = (result.nVersion >= 10) && (result.nUncompressedSize > 0);
    }

    return result;
}

HelperUpx::HEADERS HelperUpx::_getHeaders(const QByteArray &baStream)
{
    HEADERS result = {};
    const unsigned char *pData = (const unsigned char *)baStream.constData();
    qint64 nSize = baStream.size();

    if (nSize < 0x200) {
        return result;
    }

    qint64 nNT = _readLE32(pData + nSize - 4);

    if ((nNT <= 0) || (nNT + 0x100 > nSize) || (memcmp(pData + nNT, "PE\0\0", 4) != 0)) {
        return result;
    }

    quint16 nMachine = (quint16)(pData[nNT + 4] | (pData[nNT + 5] << 8));
    quint16 nMagic = (quint16)(pData[nNT + 24] | (pData[nNT + 25] << 8));

    if (!(((nMachine == 0x14c) && (nMagic == 0x10b)) || ((nMachine == 0x8664) && (nMagic == 0x20b)))) {
        return result;
    }

    result.nNT = nNT;
    result.nExtra = nNT;
    result.bIs64 = (nMagic == 0x20b);
    result.nSections = (quint16)(pData[nNT + 6] | (pData[nNT + 7] << 8));
    quint16 nOptionalSize = (quint16)(pData[nNT + 20] | (pData[nNT + 21] << 8));
    result.nSectionTable = nNT + 24 + nOptionalSize;
    result.nWords = result.nSectionTable + (qint64)result.nSections * 40;
    result.nDataDirectory = nNT + 24 + (result.bIs64 ? 112 : 96);
    result.nImageBase = result.bIs64 ? _readLE64(pData + nNT + 24 + 24) : _readLE32(pData + nNT + 24 + 28);
    result.nSizeOfCode = _readLE32(pData + nNT + 24 + 4);
    result.nBaseOfCode = _readLE32(pData + nNT + 24 + 20);
    result.bIsValid = (result.nSections >= 1) && (result.nSections <= 96) && (result.nWords + 4 <= nSize);

    return result;
}

// Ported from DIE-engine dep/XStaticUnpacker/xupx.cpp applyPEFilter() (MIT, hors), the 32-bit PE filters only.
// They follow UPX's filter/ct.h (call-trick) and filter/ctok.h (call-trick with a CTO byte, optional Jcc).
bool HelperUpx::_applyFilter(unsigned char *pData, qint64 nDataSize, quint8 nFilter, quint8 nFilterCto, quint32 nAddValue)
{
    if (nFilter == 0) {
        return true;
    }

    if ((nFilter == 0x14) || (nFilter == 0x16)) {
        for (qint64 i = 0; i < (nDataSize - 5); i++) {
            if ((pData[i] == 0xe8) || ((nFilter == 0x16) && (pData[i] == 0xe9))) {
                _writeLE32(pData + i + 1, _readBE32(pData + i + 1) - (quint32)i - 1 - nAddValue);
                i += 4;
            }
        }
    } else if ((nFilter == 0x24) || (nFilter == 0x26)) {
        quint32 nCto = ((quint32)nFilterCto) << 24;

        for (qint64 i = 0; i < (nDataSize - 5); i++) {
            if (((pData[i] == 0xe8) || ((nFilter == 0x26) && (pData[i] == 0xe9))) && (pData[i + 1] == nFilterCto)) {
                _writeLE32(pData + i + 1, _readBE32(pData + i + 1) - (quint32)i - 1 - nAddValue - nCto);
                i += 4;
            }
        }
    } else if ((nFilter == 0x49) || (nFilter == 0x46) || (nFilter == 0x36)) {
        // 0x49 also handles Jcc (0F 8x); 0x36/0x46 are the same loop without it (UPX's own condition)
        quint32 nCto = ((quint32)nFilterCto) << 24;
        quint32 nLastCall = 0;

        for (qint64 i = 0; i < (nDataSize - 5); i++) {
            bool bMatch = (pData[i] == 0xe8) || (pData[i] == 0xe9);

            if ((!bMatch) && (i > 0) && (9 <= (0x0f & nFilter)) && (nLastCall != (quint32)i) && (pData[i - 1] == 0x0f) && (pData[i] >= 0x80) && (pData[i] <= 0x8f)) {
                bMatch = true;
            }

            if (bMatch && (pData[i + 1] == nFilterCto)) {
                _writeLE32(pData + i + 1, _readBE32(pData + i + 1) - (quint32)i - 1 - nAddValue - nCto);
                i += 4;
                nLastCall = (quint32)i + 1;
            }
        }
    } else {
        return false;  // filter not ported: leave the stream as is
    }

    return true;
}

// UPX's packed relocation list: bytes < 0xF0 are position deltas; 0xFn + le16 is a larger delta (n * 0x10000 + le16),
// with a following le32 if that is 0. The list ends with 0 right before the extra info. Its offset is one of the
// dwords after the section table: take the one whose list ends exactly there.
qint64 HelperUpx::_findRelocList(const QByteArray &baStream, const HEADERS &headers)
{
    const unsigned char *pStream = (const unsigned char *)baStream.constData();
    qint64 nSize = baStream.size();

    for (qint64 w = headers.nWords; (w + 4) <= (nSize - 4); w++) {
        qint64 nCandidate = _readLE32(pStream + w);

        if ((nCandidate <= 0) || (nCandidate >= headers.nExtra)) {
            continue;
        }

        qint64 q = nCandidate;

        while ((q < headers.nExtra) && (pStream[q] != 0)) {
            if (pStream[q] >= 0xf0) {
                if (q + 3 > headers.nExtra) {
                    break;
                }

                bool bLong = ((pStream[q] & 0x0f) * 0x10000 + (pStream[q + 1] | (pStream[q + 2] << 8))) == 0;
                q += bLong ? 7 : 3;
            } else {
                q++;
            }
        }

        if (q == headers.nExtra - 1) {
            return nCandidate;
        }
    }

    return -1;
}

bool HelperUpx::unfilter(QByteArray *pbaStream, qint64 nStreamRVA, const PACKINFO &packInfo, QList<ORIGINAL_SECTION> *pListOriginalSections, QStringList *pListLog)
{
    HEADERS headers = _getHeaders(*pbaStream);

    if (!headers.bIsValid) {
        pListLog->append(QString("UPX: the stream has no UPX extra info (original headers); left as is"));
        return false;
    }

    unsigned char *pStream = (unsigned char *)pbaStream->data();
    qint64 nSize = pbaStream->size();

    if (pListOriginalSections) {
        for (qint32 i = 0; i < headers.nSections; i++) {
            const unsigned char *pSection = pStream + headers.nSectionTable + i * 40;
            ORIGINAL_SECTION section = {};
            section.sName = QString::fromLatin1((const char *)pSection, (int)strnlen((const char *)pSection, 8));
            section.nVirtualSize = _readLE32(pSection + 8);
            section.nVirtualAddress = _readLE32(pSection + 12);
            pListOriginalSections->append(section);
        }
    }

    // 1) call/jump filter over the original code range
    qint64 nCodeOffset = (qint64)headers.nBaseOfCode - nStreamRVA;

    if ((packInfo.nFilter == 0) || (headers.nSizeOfCode == 0) || (nCodeOffset < 0) || (nCodeOffset + headers.nSizeOfCode > nSize)) {
        pListLog->append(QString("UPX: no call/jump filter to undo (filter 0x%1)").arg(packInfo.nFilter, 0, 16));
    } else if (!_applyFilter(pStream + nCodeOffset, headers.nSizeOfCode, packInfo.nFilter, packInfo.nFilterCto, (quint32)nCodeOffset)) {
        pListLog->append(QString("UPX: filter 0x%1 is not supported; call/jump targets in the code stay transformed").arg(packInfo.nFilter, 0, 16));
    } else {
        pListLog->append(QString("UPX: undid call/jump filter 0x%1 (cto 0x%2) over the original code RVA 0x%3..0x%4")
                             .arg(packInfo.nFilter, 0, 16)
                             .arg(packInfo.nFilterCto, 0, 16)
                             .arg(headers.nBaseOfCode, 0, 16)
                             .arg(headers.nBaseOfCode + headers.nSizeOfCode, 0, 16));
    }

    // 2) relocations: UPX stores each relocated address big-endian, relative to ImageBase + RVAmin
    //    (dword for PE32, qword for PE32+). Verified byte-exact on x86 and x64 MSVC builds.
    quint32 nRelocDirRVA = _readLE32(pStream + headers.nDataDirectory + 5 * 8);

    if (nRelocDirRVA) {
        qint64 nRelocStart = _findRelocList(*pbaStream, headers);

        if (nRelocStart > 0) {
            qint64 q = nRelocStart;
            qint64 nPos = -4;
            qint32 nCount = 0;
            qint32 nWidth = headers.bIs64 ? 8 : 4;
            quint64 nAdd = headers.nImageBase + (quint64)nStreamRVA;

            while ((q < headers.nExtra) && (pStream[q] != 0)) {
                quint8 b = pStream[q];

                if (b < 0xf0) {
                    nPos += b;
                } else {
                    qint64 nDelta = (b & 0x0f) * 0x10000 + (pStream[q + 1] | (pStream[q + 2] << 8));
                    q += 2;

                    if (nDelta == 0) {
                        nDelta = _readLE32(pStream + q + 1);
                        q += 4;
                    }

                    nPos += nDelta;
                }

                q++;

                if ((nPos >= 0) && (nPos + nWidth <= nRelocStart)) {
                    if (headers.bIs64) {
                        _writeLE64(pStream + nPos, _readBE64(pStream + nPos) + nAdd);
                    } else {
                        _writeLE32(pStream + nPos, _readBE32(pStream + nPos) + (quint32)nAdd);
                    }

                    nCount++;
                }
            }

            pListLog->append(QString("UPX: restored %1 relocated %2-bit address(es)").arg(nCount).arg(nWidth * 8));
        } else {
            pListLog->append(QString("UPX: relocation list not found; absolute addresses stay in UPX's encoded form"));
        }
    }

    return true;
}

// UPX's packed import list (offset = first dword after the section table), per DLL:
//   le32 DLL name offset (into the PACKED file's own import section), le32 IAT RVA (relative to RVAmin),
//   entries: 0x01 name\0 | 0xFF le16 ordinal, ..., 0x00 ; the list ends with a 0 name offset.
// Rebuilt as a new ".idata" section whose descriptors keep the ORIGINAL IAT addresses (FirstThunk), so code
// that calls through the IAT still points at the right slots; the IAT slots get the import-by-name thunks.
bool HelperUpx::_rebuildImports(const QString &sRebuiltFile, const QString &sPackedFile, const QByteArray &baStream, qint64 nStreamRVA, const HEADERS &headers,
                                QStringList *pListLog)
{
    struct ENTRY {
        bool bOrdinal;
        quint16 nOrdinal;
        QByteArray baName;
    };

    struct DLL {
        QByteArray baName;
        quint32 nIAT;
        QList<ENTRY> listEntries;
    };

    const unsigned char *pStream = (const unsigned char *)baStream.constData();
    qint64 nImports = _readLE32(pStream + headers.nWords);

    if ((nImports <= 0) || (nImports >= headers.nExtra)) {
        pListLog->append(QString("UPX: no packed import list"));
        return false;
    }

    // DLL names live in the packed file's import section
    QByteArray baPackedImports;
    {
        QFile filePacked(sPackedFile);

        if (!filePacked.open(QIODevice::ReadOnly)) {
            return false;
        }

        XPE pePacked(&filePacked);
        XBinary::_MEMORY_MAP memoryMap = pePacked.getMemoryMap();
        XPE_DEF::IMAGE_DATA_DIRECTORY directory = pePacked.getOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_IMPORT);
        qint64 nOffset = XBinary::relAddressToOffset(&memoryMap, directory.VirtualAddress);

        if (nOffset < 0) {
            return false;
        }

        baPackedImports = pePacked.read_array(nOffset, 0x10000);
    }

    QList<DLL> listDlls;
    qint64 q = nImports;

    while ((q + 8 <= headers.nExtra) && (_readLE32(pStream + q) != 0)) {
        DLL dll = {};
        quint32 nNameOffset = _readLE32(pStream + q);
        dll.nIAT = _readLE32(pStream + q + 4) + (quint32)nStreamRVA;
        q += 8;

        if (nNameOffset < (quint32)baPackedImports.size()) {
            dll.baName = QByteArray(baPackedImports.constData() + nNameOffset);
        }

        while ((q < headers.nExtra) && (pStream[q] != 0)) {
            ENTRY entry = {};

            if (pStream[q] == 0x01) {
                entry.baName = QByteArray((const char *)pStream + q + 1);
                q += 1 + entry.baName.size() + 1;
            } else if (pStream[q] == 0xff) {
                entry.bOrdinal = true;
                entry.nOrdinal = (quint16)(pStream[q + 1] | (pStream[q + 2] << 8));
                q += 3;
            } else {
                pListLog->append(QString("UPX: unknown import entry type 0x%1; imports not rebuilt").arg(pStream[q], 0, 16));
                return false;
            }

            dll.listEntries.append(entry);
        }

        q++;  // entries terminator

        if (dll.baName.isEmpty() || dll.listEntries.isEmpty()) {
            pListLog->append(QString("UPX: malformed import list; imports not rebuilt"));
            return false;
        }

        listDlls.append(dll);
    }

    if (listDlls.isEmpty()) {
        return false;
    }

    QFile file(sRebuiltFile);

    if (!file.open(QIODevice::ReadWrite)) {
        return false;
    }

    XPE pe(&file);
    qint32 nPtr = headers.bIs64 ? 8 : 4;
    quint32 nSectionAlignment = qMax<quint32>(pe.getOptionalHeader_SectionAlignment(), 1);
    quint32 nNewRVA = ((pe.getOptionalHeader_SizeOfImage() + nSectionAlignment - 1) / nSectionAlignment) * nSectionAlignment;

    // layout of the new section: descriptors | OFT arrays | hint/name entries | DLL names
    qint32 nDescriptors = (listDlls.count() + 1) * 20;
    qint32 nThunks = 0;

    for (const DLL &dll : listDlls) {
        nThunks += (dll.listEntries.count() + 1) * nPtr;
    }

    QByteArray baSection(nDescriptors + nThunks, 0);
    QList<QList<quint64>> listThunkValues;
    qint32 nThunkOffset = nDescriptors;

    for (qint32 i = 0; i < listDlls.count(); i++) {
        const DLL &dll = listDlls.at(i);
        QList<quint64> listValues;

        for (const ENTRY &entry : dll.listEntries) {
            quint64 nValue = 0;

            if (entry.bOrdinal) {
                nValue = (headers.bIs64 ? 0x8000000000000000ULL : 0x80000000ULL) | entry.nOrdinal;
            } else {
                if (baSection.size() % 2) {
                    baSection.append('\0');
                }

                nValue = nNewRVA + baSection.size();
                baSection.append(QByteArray(2, '\0'));  // hint 0
                baSection.append(entry.baName);
                baSection.append('\0');
            }

            listValues.append(nValue);
        }

        unsigned char *pDescriptor = (unsigned char *)baSection.data() + i * 20;
        _writeLE32(pDescriptor + 0, nNewRVA + nThunkOffset);  // OriginalFirstThunk
        _writeLE32(pDescriptor + 16, dll.nIAT);               // FirstThunk: the ORIGINAL IAT slot

        for (qint32 j = 0; j < listValues.count(); j++) {
            if (headers.bIs64) {
                _writeLE64((unsigned char *)baSection.data() + nThunkOffset + j * nPtr, listValues.at(j));
            } else {
                _writeLE32((unsigned char *)baSection.data() + nThunkOffset + j * nPtr, (quint32)listValues.at(j));
            }
        }

        nThunkOffset += (listValues.count() + 1) * nPtr;
        listThunkValues.append(listValues);
    }

    for (qint32 i = 0; i < listDlls.count(); i++) {
        _writeLE32((unsigned char *)baSection.data() + i * 20 + 12, nNewRVA + baSection.size());  // Name
        baSection.append(listDlls.at(i).baName);
        baSection.append('\0');
    }

    // add the section by hand (append raw data + one more section header in the free header space):
    // the rebuilt copy has no overlay, so this is a plain append
    {
        quint32 nFileAlignment = qMax<quint32>(pe.getOptionalHeader_FileAlignment(), 1);
        quint16 nNumberOfSections = pe.getFileHeader_NumberOfSections();
        qint64 nHeaderOffset = pe.getSectionsTableOffset() + (qint64)nNumberOfSections * 40;
        QList<XPE_DEF::IMAGE_SECTION_HEADER> listCurrent = pe.getSectionHeaders();
        qint64 nFirstRaw = pe.getOptionalHeader_SizeOfHeaders();

        for (const XPE_DEF::IMAGE_SECTION_HEADER &current : listCurrent) {
            if (current.PointerToRawData && (current.PointerToRawData < nFirstRaw)) {
                nFirstRaw = current.PointerToRawData;
            }
        }

        if (nHeaderOffset + 40 > nFirstRaw) {
            pListLog->append(QString("UPX: no room for another section header; imports not rebuilt"));
            return false;
        }

        qint64 nRawOffset = ((file.size() + nFileAlignment - 1) / nFileAlignment) * nFileAlignment;
        qint64 nRawSize = ((baSection.size() + nFileAlignment - 1) / nFileAlignment) * nFileAlignment;
        QByteArray baRaw = baSection;
        baRaw.append(QByteArray(nRawSize - baSection.size(), '\0'));

        file.resize(nRawOffset);
        file.seek(nRawOffset);
        file.write(baRaw);

        XPE_DEF::IMAGE_SECTION_HEADER header = {};
        memcpy(header.Name, ".idata", 6);
        header.Misc.VirtualSize = baSection.size();
        header.VirtualAddress = nNewRVA;
        header.SizeOfRawData = (quint32)nRawSize;
        header.PointerToRawData = (quint32)nRawOffset;
        header.Characteristics = 0xC0000040;  // initialized data, RW

        file.seek(nHeaderOffset);
        file.write((const char *)&header, sizeof(header));

        XPE peHeaders(&file);
        peHeaders.setFileHeader_NumberOfSections(nNumberOfSections + 1);
        peHeaders.setOptionalHeader_SizeOfImage(((nNewRVA + baSection.size() + nSectionAlignment - 1) / nSectionAlignment) * nSectionAlignment);
    }

    // point the directories at the new table and fill the original IAT slots
    XPE peNew(&file);
    XPE_DEF::IMAGE_DATA_DIRECTORY directoryImport = {};
    directoryImport.VirtualAddress = nNewRVA;
    directoryImport.Size = nDescriptors;
    peNew.setOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_IMPORT, &directoryImport);

    XPE_DEF::IMAGE_DATA_DIRECTORY directoryIAT = {};
    directoryIAT.VirtualAddress = _readLE32(pStream + headers.nDataDirectory + 12 * 8);
    directoryIAT.Size = _readLE32(pStream + headers.nDataDirectory + 12 * 8 + 4);
    peNew.setOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_IAT, &directoryIAT);

    XBinary::_MEMORY_MAP memoryMap = peNew.getMemoryMap();
    qint32 nFunctions = 0;

    for (qint32 i = 0; i < listDlls.count(); i++) {
        qint64 nOffset = XBinary::relAddressToOffset(&memoryMap, listDlls.at(i).nIAT);

        if (nOffset < 0) {
            continue;
        }

        QByteArray baIAT((listThunkValues.at(i).count() + 1) * nPtr, 0);

        for (qint32 j = 0; j < listThunkValues.at(i).count(); j++) {
            if (headers.bIs64) {
                _writeLE64((unsigned char *)baIAT.data() + j * nPtr, listThunkValues.at(i).at(j));
            } else {
                _writeLE32((unsigned char *)baIAT.data() + j * nPtr, (quint32)listThunkValues.at(i).at(j));
            }
        }

        peNew.write_array(nOffset, baIAT);
        nFunctions += listThunkValues.at(i).count();
    }

    QStringList listNames;

    for (const DLL &dll : listDlls) {
        listNames.append(QString("%1 (%2)").arg(QString::fromLatin1(dll.baName)).arg(dll.listEntries.count()));
    }

    pListLog->append(QString("UPX: rebuilt imports: %1 function(s) from %2 DLL(s) [%3]; IAT at the original addresses")
                         .arg(nFunctions)
                         .arg(listDlls.count())
                         .arg(listNames.join(", ")));

    file.close();

    return true;
}

bool HelperUpx::finishRebuiltFile(const QString &sRebuiltFile, const QString &sPackedFile, const QByteArray &baStream, qint64 nStreamRVA,
                                  const QList<ORIGINAL_SECTION> &listOriginalSections, QStringList *pListLog)
{
    HEADERS headers = _getHeaders(baStream);

    if (!headers.bIsValid) {
        return false;
    }

    _rebuildImports(sRebuiltFile, sPackedFile, baStream, nStreamRVA, headers, pListLog);

    QFile file(sRebuiltFile);

    if (!file.open(QIODevice::ReadWrite)) {
        return false;
    }

    XPE pe(&file);

    if (!pe.isValid()) {
        return false;
    }

    // section names: exact VA match first; leftover "UPXn" sections take the name of the original section that
    // starts inside them (they now hold the tail of the image), so no UPX names remain
    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders();
    QStringList listRenamed;

    for (qint32 i = 0; i < listSections.count(); i++) {
        QString sOld = _sectionName(listSections.at(i));
        QString sNew;
        quint32 nVA = listSections.at(i).VirtualAddress;
        quint32 nEnd = nVA + qMax<quint32>(listSections.at(i).Misc.VirtualSize, listSections.at(i).SizeOfRawData);

        for (const ORIGINAL_SECTION &original : listOriginalSections) {
            if (original.nVirtualAddress == nVA) {
                sNew = original.sName;
                break;
            }
        }

        if (sNew.isEmpty() && sOld.startsWith("UPX")) {
            for (const ORIGINAL_SECTION &original : listOriginalSections) {
                if ((original.nVirtualAddress > nVA) && (original.nVirtualAddress < nEnd)) {
                    sNew = original.sName;
                    break;
                }
            }

            if (sNew.isEmpty()) {
                sNew = QString(".udata");  // nothing original inside: the packer's own loader data
            }
        }

        if (!sNew.isEmpty() && (sNew != sOld)) {
            pe.setSection_NameAsString(i, sNew.left(8));
            listRenamed.append(QString("%1 -> %2").arg(sOld, sNew.left(8)));
        }
    }

    if (!listRenamed.isEmpty()) {
        pListLog->append(QString("Restored section names: %1").arg(listRenamed.join(", ")));
    }

    // the "UPX!" pack header (with the version string before it) is meaningless in an unpacked copy and makes
    // scanners keep reporting UPX: clear it
    QByteArray baHead = pe.read_array(0, qMin<qint64>(0x1000, pe.getSize()));
    qint32 nMagic = baHead.indexOf("UPX!");

    if (nMagic >= 0) {
        // version string "x.xx\0" + 32-byte pack header, but never past the end of the headers (the block usually
        // ends exactly where the first section's raw data starts)
        qint64 nFirstRaw = pe.getOptionalHeader_SizeOfHeaders();

        for (const XPE_DEF::IMAGE_SECTION_HEADER &section : listSections) {
            if (section.PointerToRawData && (section.PointerToRawData < nFirstRaw)) {
                nFirstRaw = section.PointerToRawData;
            }
        }

        qint64 nStart = qMax(0, nMagic - 5);
        qint64 nEnd = qMin<qint64>(nMagic + 32, nFirstRaw);

        if (nEnd > nStart) {
            pe.write_array(nStart, QByteArray((qsizetype)(nEnd - nStart), '\0'));
            pListLog->append(QString("Cleared the leftover UPX pack header at offset 0x%1..0x%2").arg(nStart, 0, 16).arg(nEnd, 0, 16));
        }
    }

    pe.fixCheckSum();
    file.close();

    return true;
}
