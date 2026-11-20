// DiE Helper (fork addition): collects concrete evidence of packing/obfuscation from a PE file and ranks it into indicators.
#include "helperevidence.h"

#include <QFile>
#include <QSet>

#include <algorithm>

#include "xcliassembly.h"
#include "xpe.h"

// Same value as XBinary::D_ENTROPY_THRESHOLD (private there)
static const double D_ENTROPY_MEDIUM = 6.5;
static const double D_ENTROPY_HIGH = 7.0;
static const double D_ENTROPY_RESOURCES = 7.5;
static const qint64 N_ENTROPY_SAMPLE_MAX = 32 * 1024 * 1024;  // per section / overlay
static const qint64 N_STRINGS_SCAN_MAX = 64 * 1024 * 1024;    // over all raw section data
static const qint64 N_READ_CHUNK = 1024 * 1024;
static const qint64 N_ENTROPY_MIN_SIZE = 0x400;  // entropy of tiny blocks is meaningless
static const qint32 N_EP_BYTES = 32;
static const qint32 N_NET_SAMPLE_NAMES = 5;
static const quint32 N_NET_MAX_TYPES = 0x10000;
static const quint32 N_NET_MAX_METHODS = 0x40000;
static const quint32 N_SCN_CNT_CODE = 0x00000020;  // IMAGE_SCN_CNT_CODE

static QString _hex(quint64 nValue)
{
    return QString("0x%1").arg(QString::number(nValue, 16).toUpper());
}

static QString _entropyToString(double dEntropy)
{
    return QString::number(dEntropy, 'f', 2);
}

static QString _flagsToString(bool bRead, bool bWrite, bool bExecute)
{
    QString sResult;

    sResult.append(bRead ? QChar('R') : QChar('-'));
    sResult.append(bWrite ? QChar('W') : QChar('-'));
    sResult.append(bExecute ? QChar('X') : QChar('-'));

    return sResult;
}

static QString _getSectionName(const XPE_DEF::IMAGE_SECTION_HEADER &header)
{
    qint32 nLength = 0;

    while ((nLength < XPE_DEF::S_IMAGE_SIZEOF_SHORT_NAME) && (header.Name[nLength] != 0)) {
        nLength++;
    }

    return QString::fromLatin1((const char *)header.Name, nLength);
}

static QString _sectionLabel(const HelperEvidence::SECTION &section)
{
    QString sResult = section.sName;

    if (sResult.isEmpty()) {
        sResult = QString("#%1").arg(section.nIndex);
    }

    return sResult;
}

static QString _rawRangeToString(const HelperEvidence::SECTION &section)
{
    return QString("raw %1..%2").arg(_hex(section.nRawOffset), _hex(section.nRawOffset + section.nRawSize));
}

static bool _isUnusualSectionName(const QString &sName)
{
    // Names emitted by the usual compilers/linkers (MSVC, Delphi, MinGW, Go, LLVM). Case-sensitive on purpose.
    static const QSet<QString> setStandard = {".text",   ".data",   ".rdata",  ".bss",    ".idata",   ".edata",  ".pdata",  ".rsrc",   ".reloc",
                                              ".tls",    ".CRT",    ".didat",  ".gfids",  ".00cfg",   ".xdata",  ".textbss", ".sdata",  "CODE",
                                              "DATA",    "BSS",     ".itext",  ".orpc",   "_RDATA",   ".retplne", ".voltbl", ".didata", ".fptable",
                                              ".gehcont", ".eh_fram", ".buildid", ".symtab", ".rodata"};

    bool bResult = true;

    if (setStandard.contains(sName) || sName.startsWith(".debug") || sName.startsWith("/")) {
        bResult = false;
    }

    return bResult;
}

static bool _isBssLikeName(const QString &sName)
{
    return (sName == ".bss") || (sName == "BSS") || (sName == ".textbss") || (sName == ".data") || (sName == "DATA") || (sName == ".tls") || (sName == ".CRT");
}

static QString _escapeName(const QString &sName)
{
    QString sResult;
    qint32 nLength = sName.length();

    for (qint32 i = 0; (i < nLength) && (sResult.length() < 48); i++) {
        ushort nChar = sName.at(i).unicode();

        if ((nChar >= 0x20) && (nChar <= 0x7E)) {
            sResult.append(sName.at(i));
        } else {
            sResult.append(QString("\\u") + QString("%1").arg((uint)nChar, 4, 16, QChar('0')).toUpper());
        }
    }

    if (sResult.isEmpty()) {
        sResult = "\"\"";
    }

    return sResult;
}

static QString _readNetString(const QByteArray &baStrings, quint32 nIndex)
{
    QString sResult;
    qint64 nSize = baStrings.size();

    if ((nIndex > 0) && ((qint64)nIndex < nSize)) {
        const char *pData = baStrings.constData() + nIndex;
        qint64 nMax = qMin<qint64>(nSize - nIndex, 1024);
        qint64 nLength = 0;

        while ((nLength < nMax) && (pData[nLength] != 0)) {
            nLength++;
        }

        sResult = QString::fromUtf8(pData, (qint32)nLength);
    }

    return sResult;
}

// 0 - ignore (empty/compiler generated), 1 - looks normal, 2 - looks obfuscated
static qint32 _classifyNetName(const QString &sName)
{
    if (sName.isEmpty()) {
        return 0;
    }

    qint32 nLength = sName.length();

    // Non-printable / invisible / non-ASCII characters (ConfuserEx, .NET Reactor, Babel, ...)
    for (qint32 i = 0; i < nLength; i++) {
        ushort nChar = sName.at(i).unicode();

        if ((nChar < 0x20) || (nChar > 0x7E)) {
            return 2;
        }
    }

    // Compiler generated
    if (sName.startsWith(QChar('<')) || (sName == ".ctor") || (sName == ".cctor") || sName.startsWith("__StaticArrayInitTypeSize") || sName.startsWith("$")) {
        return 0;
    }

    QString sBase = sName;

    qint32 nTick = sBase.lastIndexOf(QChar('`'));  // generic arity: List`1

    if (nTick > 0) {
        sBase.truncate(nTick);
    }

    if (sBase.startsWith("get_") || sBase.startsWith("set_") || sBase.startsWith("add_")) {
        sBase = sBase.mid(4);
    } else if (sBase.startsWith("remove_")) {
        sBase = sBase.mid(7);
    }

    qint32 nBaseLength = sBase.length();

    if (nBaseLength == 0) {
        return 0;
    }

    // Very short names: a, b, aa, Ab, ...
    if (nBaseLength <= 2) {
        static const QSet<QString> setShort = {"X",  "Y",  "Z",  "W",  "H",  "R",  "G",  "B",  "A",  "Id", "ID", "IO", "UI",
                                               "Ok", "OK", "Is", "To", "Do", "On", "Go", "Up", "Of", "Or", "At", "By", "In"};

        return setShort.contains(sBase) ? 1 : 2;
    }

    qint32 nLetters = 0;
    qint32 nVowels = 0;
    qint32 nUpper = 0;
    qint32 nDigits = 0;
    qint32 nHex = 0;
    qint32 nConfusable = 0;

    static const QString sVowels = "aeiouyAEIOUY";

    for (qint32 i = 0; i < nBaseLength; i++) {
        QChar cChar = sBase.at(i);
        char cLatin = cChar.toLatin1();

        if (cChar.isLetter()) {
            nLetters++;

            if (cChar.isUpper()) {
                nUpper++;
            }

            if (sVowels.contains(cChar)) {
                nVowels++;
            }
        } else if (cChar.isDigit()) {
            nDigits++;
        }

        if (((cLatin >= '0') && (cLatin <= '9')) || ((cLatin >= 'a') && (cLatin <= 'f')) || ((cLatin >= 'A') && (cLatin <= 'F'))) {
            nHex++;
        }

        if ((cLatin == 'I') || (cLatin == 'l') || (cLatin == '1') || (cLatin == '|') || (cLatin == 'O') || (cLatin == '0')) {
            nConfusable++;
        }
    }

    // lIlIIlIl / O0O0OO0
    if ((nBaseLength >= 4) && (nConfusable == nBaseLength)) {
        return 2;
    }

    // Hash-like names: 3f9a0c1e7b2d4a6f
    if ((nBaseLength >= 16) && (nHex == nBaseLength) && (nDigits >= 4) && (nLetters >= 4)) {
        return 2;
    }

    // Random gibberish: long, almost no vowels, not an all-caps acronym
    if ((nLetters >= 8) && (nUpper < nLetters) && ((nVowels * 100) < (nLetters * 12))) {
        return 2;
    }

    return 1;
}

static void _addIndicator(HelperEvidence::RESULT *pResult, const QString &sId, HelperEvidence::CATEGORY category, HelperEvidence::SEVERITY severity, qint32 nWeight,
                          const QString &sTitle, const QString &sDetails, HelperEvidence::LOCATION location = HelperEvidence::LOCATION_NONE, qint64 nOffset = -1,
                          qint64 nSize = 0, XADDR nAddress = (XADDR)-1)
{
    HelperEvidence::INDICATOR indicator = {};

    indicator.sId = sId;
    indicator.category = category;
    indicator.severity = severity;
    indicator.nWeight = nWeight;
    indicator.sTitle = sTitle;
    indicator.sDetails = sDetails;
    indicator.location = location;
    indicator.nOffset = nOffset;
    indicator.nSize = nSize;
    indicator.nAddress = nAddress;

    pResult->listIndicators.append(indicator);
}

static double _getEntropy(XPE *pPE, qint64 nOffset, qint64 nSize)
{
    double dResult = -1;

    if ((nOffset >= 0) && (nSize > 0)) {
        dResult = pPE->getBinaryStatus(XBinary::BSTATUS_ENTROPY, nOffset, qMin<qint64>(nSize, N_ENTROPY_SAMPLE_MAX), nullptr);
    }

    return dResult;
}

static QStringList _presentFunctions(const QSet<QString> &setFunctions, const QStringList &listNames)
{
    QStringList listResult;

    for (qint32 i = 0; i < listNames.count(); i++) {
        if (setFunctions.contains(listNames.at(i))) {
            listResult.append(listNames.at(i));
        }
    }

    return listResult;
}

HelperEvidence::RESULT HelperEvidence::analyze(const QString &sFileName)
{
    RESULT result = {};

    result.bIsValid = false;
    result.sFileName = sFileName;
    result.nImageBase = 0;
    result.nEntryPointRVA = -1;
    result.nEntryPointAddress = (XADDR)-1;
    result.nEntryPointOffset = -1;
    result.nEntryPointSection = -1;
    result.dFileEntropy = 0;
    result.nOverlayOffset = -1;
    result.nOverlaySize = 0;

    QFile file(sFileName);

    if (!file.open(QIODevice::ReadOnly)) {
        result.sError = QString("Cannot open file: %1").arg(file.errorString());
        return result;
    }

    XPE pe(&file);

    if (!pe.isValid()) {
        result.sError = "Not a valid PE file";
        file.close();
        return result;
    }

    result.bIsValid = true;
    result.nFileSize = pe.getSize();
    result.bIs64 = pe.is64();
    result.bIsDll = pe.isDll();
    result.bIsNET = pe.isNETPresent();
    result.nImageBase = pe.getOptionalHeader_ImageBase();

    const qint64 nFileSize = result.nFileSize;

    XBinary::_MEMORY_MAP memoryMap = pe.getMemoryMap();

    // ---- headers
    qint64 nHeadersSize = pe.getOptionalHeader_SizeOfHeaders();

    if ((nHeadersSize <= 0) || (nHeadersSize > nFileSize)) {
        nHeadersSize = nFileSize;
    }

    result.nHeadersSize = nHeadersSize;

    // ---- real sections (header order)
    QList<XPE_DEF::IMAGE_SECTION_HEADER> listHeaders = pe.getSectionHeaders(nullptr);
    qint32 nNumberOfSections = listHeaders.count();
    QList<SECTION> listReal;

    for (qint32 i = 0; i < nNumberOfSections; i++) {
        const XPE_DEF::IMAGE_SECTION_HEADER &header = listHeaders.at(i);

        SECTION section = {};
        section.nIndex = i;
        section.sName = _getSectionName(header);
        section.nRawOffset = header.PointerToRawData;
        section.nRawSize = header.SizeOfRawData;

        if (section.nRawOffset >= nFileSize) {
            section.nRawSize = 0;
        } else if (section.nRawOffset + section.nRawSize > nFileSize) {
            section.nRawSize = nFileSize - section.nRawOffset;
        }

        section.nRVA = header.VirtualAddress;
        section.nVirtualSize = header.Misc.VirtualSize;
        section.nCharacteristics = header.Characteristics;
        section.bRead = (header.Characteristics & XPE_DEF::S_IMAGE_SCN_MEM_READ) != 0;
        section.bWrite = (header.Characteristics & XPE_DEF::S_IMAGE_SCN_MEM_WRITE) != 0;
        section.bExecute = (header.Characteristics & XPE_DEF::S_IMAGE_SCN_MEM_EXECUTE) != 0;
        section.bContainsEntryPoint = false;
        section.bIsUnusualName = _isUnusualSectionName(section.sName);
        section.dEntropy = _getEntropy(&pe, section.nRawOffset, section.nRawSize);

        listReal.append(section);
    }

    // ---- entry point
    quint32 nEntryPointRVA = pe.getOptionalHeader_AddressOfEntryPoint();
    bool bHasEntryPoint = (nEntryPointRVA != 0);  // 0: IL-only .NET image or resource-only DLL

    result.nEntryPointRVA = nEntryPointRVA;

    if (bHasEntryPoint) {
        result.nEntryPointAddress = result.nImageBase + nEntryPointRVA;

        for (qint32 i = 0; i < nNumberOfSections; i++) {
            const XPE_DEF::IMAGE_SECTION_HEADER &header = listHeaders.at(i);
            qint64 nStart = header.VirtualAddress;
            qint64 nSpan = qMax<qint64>(header.Misc.VirtualSize, header.SizeOfRawData);

            if (((qint64)nEntryPointRVA >= nStart) && ((qint64)nEntryPointRVA < nStart + nSpan)) {
                result.nEntryPointSection = i;
                listReal[i].bContainsEntryPoint = true;
                break;
            }
        }

        qint64 nOffset = XBinary::relAddressToOffset(&memoryMap, nEntryPointRVA);

        if ((nOffset < 0) || (nOffset >= nFileSize)) {
            nOffset = -1;

            // Fallback: compute from the section table
            if (result.nEntryPointSection != -1) {
                const SECTION &section = listReal.at(result.nEntryPointSection);
                qint64 nDelta = (qint64)nEntryPointRVA - section.nRVA;

                if ((nDelta >= 0) && (nDelta < section.nRawSize)) {
                    nOffset = section.nRawOffset + nDelta;
                }
            } else if ((qint64)nEntryPointRVA < nHeadersSize) {
                nOffset = nEntryPointRVA;
            }
        }

        result.nEntryPointOffset = nOffset;

        if (nOffset != -1) {
            result.baEntryPointBytes = pe.read_array(nOffset, qMin<qint64>(N_EP_BYTES, nFileSize - nOffset));
        }
    }

    // ---- overlay
    if (XBinary::isOverlayPresent(&memoryMap, nullptr)) {
        qint64 nOverlayOffset = XBinary::getOverlayOffset(&memoryMap, nullptr);
        qint64 nOverlaySize = XBinary::getOverlaySize(&memoryMap, nullptr);

        if ((nOverlayOffset >= 0) && (nOverlayOffset < nFileSize) && (nOverlaySize > 0)) {
            result.nOverlayOffset = nOverlayOffset;
            result.nOverlaySize = qMin<qint64>(nOverlaySize, nFileSize - nOverlayOffset);
        }
    }

    // ---- layout in file order: Headers, sections..., Overlay
    {
        SECTION sectionHeaders = {};
        sectionHeaders.nIndex = -1;
        sectionHeaders.sName = "Headers";
        sectionHeaders.nRawOffset = 0;
        sectionHeaders.nRawSize = nHeadersSize;
        sectionHeaders.nRVA = -1;
        sectionHeaders.nVirtualSize = -1;
        sectionHeaders.nCharacteristics = 0;
        sectionHeaders.bRead = true;
        sectionHeaders.bWrite = false;
        sectionHeaders.bExecute = false;
        sectionHeaders.bContainsEntryPoint = bHasEntryPoint && (result.nEntryPointSection == -1) && ((qint64)nEntryPointRVA < nHeadersSize);
        sectionHeaders.bIsUnusualName = false;
        sectionHeaders.dEntropy = _getEntropy(&pe, 0, nHeadersSize);

        QList<SECTION> listOrdered;

        for (qint32 i = 0; i < nNumberOfSections; i++) {
            if (listReal.at(i).nRawSize > 0) {
                listOrdered.append(listReal.at(i));
            }
        }

        std::stable_sort(listOrdered.begin(), listOrdered.end(), [](const SECTION &section1, const SECTION &section2) {
            return section1.nRawOffset < section2.nRawOffset;
        });

        // Virtual-only sections ("UPX0") go before the first file-backed section with a higher RVA
        for (qint32 i = 0; i < nNumberOfSections; i++) {
            if (listReal.at(i).nRawSize <= 0) {
                qint32 nInsert = listOrdered.count();

                for (qint32 j = 0; j < listOrdered.count(); j++) {
                    if (listOrdered.at(j).nRVA > listReal.at(i).nRVA) {
                        nInsert = j;
                        break;
                    }
                }

                listOrdered.insert(nInsert, listReal.at(i));
            }
        }

        result.listSections.append(sectionHeaders);
        result.listSections.append(listOrdered);

        if (result.nOverlayOffset != -1) {
            SECTION sectionOverlay = {};
            sectionOverlay.nIndex = -1;
            sectionOverlay.sName = "Overlay";
            sectionOverlay.nRawOffset = result.nOverlayOffset;
            sectionOverlay.nRawSize = result.nOverlaySize;
            sectionOverlay.nRVA = -1;
            sectionOverlay.nVirtualSize = -1;
            sectionOverlay.nCharacteristics = 0;
            sectionOverlay.bRead = false;
            sectionOverlay.bWrite = false;
            sectionOverlay.bExecute = false;
            sectionOverlay.bContainsEntryPoint = false;
            sectionOverlay.bIsUnusualName = false;
            sectionOverlay.dEntropy = _getEntropy(&pe, result.nOverlayOffset, result.nOverlaySize);

            result.listSections.append(sectionOverlay);
        }
    }

    double dOverlayEntropy = -1;

    if (result.nOverlayOffset != -1) {
        dOverlayEntropy = result.listSections.last().dEntropy;
    }

    // ---- whole-file entropy (and image-only entropy when a big overlay would distort it)
    result.dFileEntropy = pe.getBinaryStatus(XBinary::BSTATUS_ENTROPY, 0, -1, nullptr);

    double dImageEntropy = result.dFileEntropy;

    if ((result.nOverlayOffset > 0) && (result.nOverlaySize * 10 > nFileSize)) {
        dImageEntropy = pe.getBinaryStatus(XBinary::BSTATUS_ENTROPY, 0, result.nOverlayOffset, nullptr);
    }

    // ---- strings: printable ASCII runs >= 5 that are NUL-terminated (C strings), or runs >= 16.
    // Random/compressed data yields ~4.5 unterminated 5-char runs per KiB, so the terminator is what separates real strings from noise.
    // .rsrc is skipped: large images/icons there would dilute the density of a perfectly normal program.
    {
        qint64 nScanned = 0;
        qint32 nStringCount = 0;

        for (qint32 i = 0; (i < nNumberOfSections) && (nScanned < N_STRINGS_SCAN_MAX); i++) {
            const SECTION &section = listReal.at(i);

            if ((section.nRawSize <= 0) || (section.sName == ".rsrc")) {
                continue;
            }

            qint64 nOffset = section.nRawOffset;
            qint64 nRemain = qMin<qint64>(section.nRawSize, N_STRINGS_SCAN_MAX - nScanned);
            qint32 nRun = 0;

            while (nRemain > 0) {
                QByteArray baChunk = pe.read_array(nOffset, qMin<qint64>(nRemain, N_READ_CHUNK));
                qint32 nChunkSize = baChunk.size();

                if (nChunkSize <= 0) {
                    break;
                }

                const char *pData = baChunk.constData();

                for (qint32 j = 0; j < nChunkSize; j++) {
                    quint8 nByte = (quint8)pData[j];

                    if ((nByte >= 0x20) && (nByte <= 0x7E)) {
                        nRun++;
                    } else {
                        if ((nRun >= 16) || ((nRun >= 5) && (nByte == 0))) {
                            nStringCount++;
                        }

                        nRun = 0;
                    }
                }

                nOffset += nChunkSize;
                nRemain -= nChunkSize;
                nScanned += nChunkSize;
            }

            if (nRun >= 16) {
                nStringCount++;
            }
        }

        result.nStringCount = nStringCount;
        result.dStringDensity = (nScanned > 0) ? ((double)nStringCount / ((double)nScanned / 1024.0)) : 0;
    }

    qint64 nRawSectionsSize = 0;

    for (qint32 i = 0; i < nNumberOfSections; i++) {
        if (listReal.at(i).sName != ".rsrc") {
            nRawSectionsSize += qMax<qint64>(listReal.at(i).nRawSize, 0);
        }
    }

    // ---- imports
    // Loader set of a typical packer stub; everything else (ordinals included) counts as "other"
    static const QSet<QString> setLoader = {"LoadLibraryA",   "LoadLibraryW",           "LoadLibraryExA", "LoadLibraryExW", "LdrLoadDll",
                                            "GetProcAddress", "LdrGetProcedureAddress", "VirtualProtect", "VirtualAlloc",   "VirtualFree",
                                            "ExitProcess",    "GetModuleHandleA",       "GetModuleHandleW"};

    QSet<QString> setFunctions;
    qint32 nOtherFunctions = 0;
    {
        QList<XPE::IMPORT_HEADER> listImports = pe.getImports(&memoryMap, nullptr);

        result.nImportLibraries = listImports.count();
        result.nImportFunctions = 0;

        for (qint32 i = 0; i < listImports.count(); i++) {
            const XPE::IMPORT_HEADER &importHeader = listImports.at(i);

            result.nImportFunctions += importHeader.listPositions.count();

            for (qint32 j = 0; j < importHeader.listPositions.count(); j++) {
                const QString &sFunction = importHeader.listPositions.at(j).sFunction;

                if (!sFunction.isEmpty()) {
                    setFunctions.insert(sFunction);
                }

                if (sFunction.isEmpty() || !setLoader.contains(sFunction)) {
                    nOtherFunctions++;
                }
            }
        }

        static const QStringList listNotable = {"LoadLibraryA",
                                                "LoadLibraryW",
                                                "LoadLibraryExA",
                                                "LoadLibraryExW",
                                                "LdrLoadDll",
                                                "GetProcAddress",
                                                "LdrGetProcedureAddress",
                                                "VirtualAlloc",
                                                "VirtualAllocEx",
                                                "VirtualProtect",
                                                "VirtualProtectEx",
                                                "NtProtectVirtualMemory",
                                                "NtAllocateVirtualMemory",
                                                "WriteProcessMemory",
                                                "CreateRemoteThread",
                                                "NtUnmapViewOfSection",
                                                "ZwUnmapViewOfSection",
                                                "IsDebuggerPresent",
                                                "CheckRemoteDebuggerPresent",
                                                "NtQueryInformationProcess",
                                                "ZwQueryInformationProcess",
                                                "OutputDebugStringA",
                                                "OutputDebugStringW",
                                                "NtSetInformationThread",
                                                "ZwSetInformationThread",
                                                "GetTickCount",
                                                "GetTickCount64",
                                                "QueryPerformanceCounter",
                                                "FindWindowA",
                                                "FindWindowW",
                                                "CreateToolhelp32Snapshot",
                                                "CryptDecrypt",
                                                "RtlDecompressBuffer"};

        result.listNotableImports = _presentFunctions(setFunctions, listNotable);
    }

    // ---- TLS
    if (pe.isTLSPresent()) {
        result.listTLSCallbacks = pe.getTLS_CallbacksList(&memoryMap, nullptr);
    }

    // ---- .NET metadata names (TypeDef + MethodDef via XCLIAssembly)
    qint32 nNetNamesExamined = 0;

    if (result.bIsNET) {
        XCLIAssembly *pCliAssembly = pe.getCliAssembly(nullptr);

        if (pCliAssembly) {
            XCLIAssembly::CLI_INFO cliInfo = pCliAssembly->getCliInfo(false, nullptr);

            if (cliInfo.bValid) {
                const QByteArray &baStrings = cliInfo.metaData.baStrings;
                quint32 nTypes = qMin<quint32>(cliInfo.metaData.Tables_TablesNumberOfIndexes[XCLIASSEMBLY_DEF::metadata_TypeDef], N_NET_MAX_TYPES);
                quint32 nMethods = qMin<quint32>(cliInfo.metaData.Tables_TablesNumberOfIndexes[XCLIASSEMBLY_DEF::metadata_MethodDef], N_NET_MAX_METHODS);
                QSet<QString> setSamples;

                result.nNetTypes = (qint32)nTypes;

                for (quint32 i = 0; i < nTypes + nMethods; i++) {
                    quint32 nNameIndex = 0;

                    if (i < nTypes) {
                        nNameIndex = pCliAssembly->getMetadataTypeDef(&cliInfo, (qint32)i).nTypeName;
                    } else {
                        nNameIndex = pCliAssembly->getMetadataMethodDef(&cliInfo, (qint32)(i - nTypes)).nName;
                    }

                    QString sName = _readNetString(baStrings, nNameIndex);
                    qint32 nClass = _classifyNetName(sName);

                    if (nClass == 0) {
                        continue;
                    }

                    nNetNamesExamined++;

                    if (nClass == 2) {
                        result.nNetObfuscatedNames++;

                        if (result.listNetSampleNames.count() < N_NET_SAMPLE_NAMES) {
                            QString sEscaped = _escapeName(sName);

                            if (!setSamples.contains(sEscaped)) {
                                setSamples.insert(sEscaped);
                                result.listNetSampleNames.append(sEscaped);
                            }
                        }
                    }
                }
            }

            delete pCliAssembly;
        }
    }

    file.close();

    // ======== indicators
    const SECTION *pEntryPointSection = (result.nEntryPointSection != -1) ? &(listReal.at(result.nEntryPointSection)) : nullptr;
    const qint32 nEntryPointBytes = result.baEntryPointBytes.size();
    const XADDR nEntryPointAddress = result.nEntryPointAddress;
    const LOCATION entryPointLocation = (result.nEntryPointOffset != -1) ? LOCATION_DISASM : LOCATION_NONE;

    QString sEntryPointSectionText;

    if (pEntryPointSection) {
        sEntryPointSectionText = QString("%1 (#%2 of %3, %4)")
                                     .arg(_sectionLabel(*pEntryPointSection), QString::number(pEntryPointSection->nIndex), QString::number(nNumberOfSections),
                                          _flagsToString(pEntryPointSection->bRead, pEntryPointSection->bWrite, pEntryPointSection->bExecute));
    }

    // ---- PACKING: section entropy
    QList<qint32> listPendingCodeEntropy;  // executable sections with entropy 6.5..7.0, decided at the end
    double dMaxSectionEntropy = -1;

    for (qint32 i = 0; i < nNumberOfSections; i++) {
        const SECTION &section = listReal.at(i);

        if ((section.dEntropy < 0) || (section.nRawSize < N_ENTROPY_MIN_SIZE)) {
            continue;
        }

        bool bIsResources = (section.sName == ".rsrc");

        if (!bIsResources) {
            dMaxSectionEntropy = qMax(dMaxSectionEntropy, section.dEntropy);
        }

        QString sDetails = QString("%1: %2, entropy %3, %4")
                               .arg(_sectionLabel(section), _rawRangeToString(section), _entropyToString(section.dEntropy),
                                    _flagsToString(section.bRead, section.bWrite, section.bExecute));

        if (bIsResources) {
            if ((section.dEntropy >= D_ENTROPY_RESOURCES) && (section.nRawSize >= 0x40000)) {
                _addIndicator(&result, "high_entropy_section", CATEGORY_PACKING, SEVERITY_MEDIUM, 8, QString("High entropy resources (%1)").arg(_sectionLabel(section)),
                              sDetails + ", resources are compressed or encrypted", LOCATION_HEX, section.nRawOffset, section.nRawSize);
            }
        } else if (section.dEntropy >= D_ENTROPY_HIGH) {
            bool bBig = (section.nRawSize >= 0x1000);
            _addIndicator(&result, "high_entropy_section", CATEGORY_PACKING, bBig ? SEVERITY_HIGH : SEVERITY_MEDIUM, bBig ? 20 : 10,
                          QString("High entropy: %1").arg(_sectionLabel(section)), sDetails + ", compressed or encrypted data", LOCATION_HEX, section.nRawOffset,
                          section.nRawSize);
        } else if (section.dEntropy >= D_ENTROPY_MEDIUM) {
            if (section.bExecute || (section.nCharacteristics & N_SCN_CNT_CODE)) {
                // plain 32-bit x86 compiler output is denser than x64 and commonly reaches 6.5..6.7: start at 6.75
                if (section.dEntropy >= 6.75) {
                    listPendingCodeEntropy.append(i);
                }
            } else {
                _addIndicator(&result, "high_entropy_section", CATEGORY_PACKING, SEVERITY_MEDIUM, 10, QString("Elevated entropy: %1").arg(_sectionLabel(section)),
                              sDetails, LOCATION_HEX, section.nRawOffset, section.nRawSize);
            }
        }
    }

    if ((nNumberOfSections >= 1) && (nNumberOfSections <= 2) && (dMaxSectionEntropy >= D_ENTROPY_HIGH)) {
        _addIndicator(&result, "few_sections_high_entropy", CATEGORY_PACKING, SEVERITY_HIGH, 10, "Few sections, high entropy",
                      QString("%1 section(s) only, max section entropy %2").arg(nNumberOfSections).arg(_entropyToString(dMaxSectionEntropy)));
    }

    // ---- PACKING: whole-file entropy
    {
        bool bOverlayExcluded = (result.nOverlayOffset > 0) && (result.nOverlaySize * 10 > nFileSize);
        QString sDetails = bOverlayExcluded ? QString("Image entropy %1 (0x0..%2, overlay excluded), whole file %3")
                                                  .arg(_entropyToString(dImageEntropy), _hex(result.nOverlayOffset), _entropyToString(result.dFileEntropy))
                                            : QString("Whole file entropy %1 over %2 bytes").arg(_entropyToString(result.dFileEntropy), _hex(nFileSize));

        if (dImageEntropy >= 7.2) {
            _addIndicator(&result, "high_file_entropy", CATEGORY_PACKING, SEVERITY_HIGH, 15, "High file entropy", sDetails);
        } else if (dImageEntropy >= 6.8) {
            _addIndicator(&result, "high_file_entropy", CATEGORY_PACKING, SEVERITY_MEDIUM, 8, "Elevated file entropy", sDetails);
        }
    }

    // ---- PACKING: entry point placement
    if (bHasEntryPoint) {
        QString sEntryPointText = QString("EP RVA %1 (VA %2)").arg(_hex(nEntryPointRVA), _hex(nEntryPointAddress));

        if (!pEntryPointSection) {
            QString sWhere = ((qint64)nEntryPointRVA < nHeadersSize) ? QString("inside the PE headers (SizeOfHeaders %1)").arg(_hex(nHeadersSize))
                                                                     : QString("outside every section");
            _addIndicator(&result, "ep_outside_sections", CATEGORY_PACKING, SEVERITY_HIGH, 15, "EP outside sections", QString("%1 is %2").arg(sEntryPointText, sWhere),
                          entryPointLocation, result.nEntryPointOffset, nEntryPointBytes, nEntryPointAddress);
        } else {
            qint32 nFirstCodeSection = -1;

            for (qint32 i = 0; i < nNumberOfSections; i++) {
                if (listReal.at(i).bExecute || (listReal.at(i).nCharacteristics & N_SCN_CNT_CODE)) {
                    nFirstCodeSection = i;
                    break;
                }
            }

            bool bEntryPointExecutable = pEntryPointSection->bExecute || (pEntryPointSection->nCharacteristics & N_SCN_CNT_CODE);

            if ((nNumberOfSections >= 2) && (result.nEntryPointSection == nNumberOfSections - 1)) {
                _addIndicator(&result, "ep_last_section", CATEGORY_PACKING, SEVERITY_MEDIUM, 12, "EP in last section",
                              QString("%1 in %2").arg(sEntryPointText, sEntryPointSectionText), entryPointLocation, result.nEntryPointOffset, nEntryPointBytes,
                              nEntryPointAddress);
            }

            if (!bEntryPointExecutable) {
                _addIndicator(&result, "ep_not_executable", CATEGORY_PACKING, SEVERITY_MEDIUM, 10, "EP in non-executable section",
                              QString("%1 in %2, section has neither MEM_EXECUTE nor CNT_CODE").arg(sEntryPointText, sEntryPointSectionText), entryPointLocation,
                              result.nEntryPointOffset, nEntryPointBytes, nEntryPointAddress);
            } else if ((nFirstCodeSection != -1) && (nFirstCodeSection != result.nEntryPointSection) && (pEntryPointSection->sName != ".itext")) {
                _addIndicator(&result, "ep_not_first_code_section", CATEGORY_PACKING, SEVERITY_MEDIUM, 8, "EP not in first code section",
                              QString("%1 in %2, first code section is %3").arg(sEntryPointText, sEntryPointSectionText, _sectionLabel(listReal.at(nFirstCodeSection))),
                              entryPointLocation, result.nEntryPointOffset, nEntryPointBytes, nEntryPointAddress);
            }

            if (pEntryPointSection->bWrite && pEntryPointSection->bExecute) {
                _addIndicator(&result, "ep_rwx_section", CATEGORY_PACKING, SEVERITY_HIGH, 15, "EP in RWX section",
                              QString("%1 in %2, characteristics %3").arg(sEntryPointText, sEntryPointSectionText, _hex(pEntryPointSection->nCharacteristics)),
                              entryPointLocation, result.nEntryPointOffset, nEntryPointBytes, nEntryPointAddress);
            } else if (pEntryPointSection->bWrite) {
                _addIndicator(&result, "ep_writable_section", CATEGORY_PACKING, SEVERITY_MEDIUM, 10, "EP in writable section",
                              QString("%1 in %2, characteristics %3").arg(sEntryPointText, sEntryPointSectionText, _hex(pEntryPointSection->nCharacteristics)),
                              entryPointLocation, result.nEntryPointOffset, nEntryPointBytes, nEntryPointAddress);
            }
        }

        // ---- PACKING: stub patterns at EP
        if (nEntryPointBytes > 0) {
            const quint8 *pBytes = (const quint8 *)result.baEntryPointBytes.constData();
            QStringList listPatterns;
            qint32 nStubWeight = 0;

            if (!result.bIs64 && (nEntryPointBytes >= 2) && (pBytes[0] == 0x9C) && (pBytes[1] == 0x60)) {
                listPatterns.append("PUSHFD; PUSHAD (9C 60)");
                nStubWeight = qMax(nStubWeight, 15);
            } else if (!result.bIs64 && (pBytes[0] == 0x60)) {
                listPatterns.append("PUSHAD (60)");
                nStubWeight = qMax(nStubWeight, 15);
            }

            if ((nEntryPointBytes >= 5) && (pBytes[0] == 0xE8) && (pBytes[1] == 0x00) && (pBytes[2] == 0x00) && (pBytes[3] == 0x00) && (pBytes[4] == 0x00)) {
                listPatterns.append("CALL $+5 (E8 00 00 00 00)");
                nStubWeight = qMax(nStubWeight, 10);
            }

            if (!result.bIs64 && (nEntryPointBytes >= 6) && (pBytes[0] == 0x68) && (pBytes[5] == 0xC3)) {
                listPatterns.append("PUSH imm32; RET (68 .. .. .. .. C3)");
                nStubWeight = qMax(nStubWeight, 10);
            }

            if (!result.bIs64 && (pBytes[0] == 0xEA)) {
                listPatterns.append("JMP FAR (EA)");
                nStubWeight = qMax(nStubWeight, 10);
            }

            if ((nEntryPointBytes >= 5) && (pBytes[0] == 0xE9) && pEntryPointSection) {
                qint32 nRel = (qint32)((quint32)pBytes[1] | ((quint32)pBytes[2] << 8) | ((quint32)pBytes[3] << 16) | ((quint32)pBytes[4] << 24));
                qint64 nTarget = (qint64)nEntryPointRVA + 5 + nRel;
                qint64 nStart = pEntryPointSection->nRVA;
                qint64 nSpan = qMax<qint64>(pEntryPointSection->nVirtualSize, listHeaders.at(pEntryPointSection->nIndex).SizeOfRawData);

                if ((nTarget < nStart) || (nTarget >= nStart + nSpan)) {
                    listPatterns.append(QString("JMP rel32 to RVA %1 outside the EP section").arg(_hex((quint64)qMax<qint64>(nTarget, 0))));
                    nStubWeight = qMax(nStubWeight, 8);
                }
            }

            if (!listPatterns.isEmpty()) {
                _addIndicator(&result, "ep_stub_pattern", CATEGORY_PACKING, (nStubWeight >= 15) ? SEVERITY_HIGH : SEVERITY_MEDIUM, nStubWeight, "Unpacking stub at EP",
                              QString("At EP offset %1: %2; bytes %3")
                                  .arg(_hex(result.nEntryPointOffset), listPatterns.join(", "),
                                       QString::fromLatin1(result.baEntryPointBytes.left(8).toHex(' ').toUpper())),
                              LOCATION_DISASM, result.nEntryPointOffset, nEntryPointBytes, nEntryPointAddress);
            }
        }
    }

    // ---- PACKING: section layout
    {
        QStringList listRWX;
        qint32 nFirstRWX = -1;
        QStringList listUnusual;

        for (qint32 i = 0; i < nNumberOfSections; i++) {
            const SECTION &section = listReal.at(i);
            const XPE_DEF::IMAGE_SECTION_HEADER &header = listHeaders.at(i);

            if (section.bWrite && section.bExecute && (section.sName != ".textbss")) {
                listRWX.append(QString("%1 (%2)").arg(_sectionLabel(section), _hex(section.nCharacteristics)));

                if ((nFirstRWX == -1) && (section.nRawSize > 0)) {
                    nFirstRWX = i;
                }
            }

            if (section.bIsUnusualName && !listUnusual.contains(_sectionLabel(section))) {
                listUnusual.append(_sectionLabel(section));
            }

            // virtual-only section
            if ((header.SizeOfRawData == 0) && (section.nVirtualSize > 0x1000)) {
                QString sDetails = QString("%1: RVA %2, virtual size %3, no raw data, %4")
                                       .arg(_sectionLabel(section), _hex(section.nRVA), _hex(section.nVirtualSize),
                                            _flagsToString(section.bRead, section.bWrite, section.bExecute));

                if (section.bExecute) {
                    _addIndicator(&result, "virtual_only_section", CATEGORY_PACKING, SEVERITY_HIGH, 15, QString("Virtual-only code section: %1").arg(_sectionLabel(section)),
                                  sDetails + ", filled at run time (unpacking target)");
                } else if (!_isBssLikeName(section.sName)) {
                    _addIndicator(&result, "virtual_only_section", CATEGORY_PACKING, SEVERITY_MEDIUM, 8, QString("Virtual-only section: %1").arg(_sectionLabel(section)),
                                  sDetails);
                }
            } else if ((section.nRawSize > 0) && (section.nVirtualSize > section.nRawSize * 4) && (section.nVirtualSize >= 0x10000)) {
                // raw much smaller than virtual
                if (section.bExecute || !_isBssLikeName(section.sName)) {
                    _addIndicator(&result, "raw_smaller_than_virtual", CATEGORY_PACKING, section.bExecute ? SEVERITY_MEDIUM : SEVERITY_LOW, section.bExecute ? 10 : 5,
                                  QString("Raw << virtual: %1").arg(_sectionLabel(section)),
                                  QString("%1: %2, virtual size %3 (%4x raw)")
                                      .arg(_sectionLabel(section), _rawRangeToString(section), _hex(section.nVirtualSize),
                                           QString::number(section.nVirtualSize / section.nRawSize)),
                                  LOCATION_HEX, section.nRawOffset, section.nRawSize);
                }
            }
        }

        if ((nNumberOfSections > 0) && (listHeaders.at(0).SizeOfRawData == 0) && (listReal.at(0).sName != ".textbss")) {
            _addIndicator(&result, "first_section_empty", CATEGORY_PACKING, SEVERITY_MEDIUM, 10, "Empty first section",
                          QString("%1: RVA %2, virtual size %3, SizeOfRawData 0")
                              .arg(_sectionLabel(listReal.at(0)), _hex(listReal.at(0).nRVA), _hex(listReal.at(0).nVirtualSize)));
        }

        if (!listRWX.isEmpty()) {
            if (nFirstRWX != -1) {
                _addIndicator(&result, "rwx_section", CATEGORY_PACKING, SEVERITY_MEDIUM, 10, "RWX section", QString("Writable + executable: %1").arg(listRWX.join(", ")),
                              LOCATION_HEX, listReal.at(nFirstRWX).nRawOffset, listReal.at(nFirstRWX).nRawSize);
            } else {
                _addIndicator(&result, "rwx_section", CATEGORY_PACKING, SEVERITY_MEDIUM, 10, "RWX section", QString("Writable + executable: %1").arg(listRWX.join(", ")));
            }
        }

        if (!listUnusual.isEmpty()) {
            _addIndicator(&result, "unusual_section_names", CATEGORY_PACKING, SEVERITY_LOW, 6, "Unusual section names",
                          QString("Not emitted by common compilers: %1").arg(listUnusual.join(", ")));
        }
    }

    // ---- PACKING / OBFUSCATION: imports
    bool bHasLoadLibrary = setFunctions.contains("LoadLibraryA") || setFunctions.contains("LoadLibraryW") || setFunctions.contains("LoadLibraryExA") ||
                           setFunctions.contains("LoadLibraryExW") || setFunctions.contains("LdrLoadDll");
    bool bHasGetModuleHandle = setFunctions.contains("GetModuleHandleA") || setFunctions.contains("GetModuleHandleW");
    bool bHasGetProcAddress = setFunctions.contains("GetProcAddress") || setFunctions.contains("LdrGetProcedureAddress");

    if (!result.bIsNET) {
        bool bLoader = bHasLoadLibrary || (bHasGetModuleHandle && (result.nImportFunctions <= 4));
        bool bRebuilt = false;

        if (bLoader && bHasGetProcAddress && (result.nImportFunctions <= 32) && (nOtherFunctions <= result.nImportLibraries + 1)) {
            bRebuilt = true;
            _addIndicator(&result, "imports_rebuilt", CATEGORY_PACKING, SEVERITY_HIGH, 20, "Imports rebuilt at run time",
                          QString("Only %1 function(s) from %2 librar(y/ies), loader set: %3")
                              .arg(result.nImportFunctions)
                              .arg(result.nImportLibraries)
                              .arg(_presentFunctions(setFunctions, {"LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "LdrLoadDll", "GetModuleHandleA",
                                                                    "GetModuleHandleW", "GetProcAddress", "LdrGetProcedureAddress", "VirtualProtect", "VirtualAlloc",
                                                                    "VirtualFree"})
                                       .join(", ")));
        }

        bool bResourceOnlyDll = result.bIsDll && !bHasEntryPoint;

        if ((result.nImportFunctions == 0) && !bResourceOnlyDll) {
            _addIndicator(&result, "no_imports", CATEGORY_PACKING, SEVERITY_HIGH, 15, "No imports",
                          "The import table is empty or invalid: APIs are resolved manually at run time");
        } else if (!bRebuilt && (result.nImportFunctions > 0) && (result.nImportFunctions <= 5)) {
            QStringList listFunctions = setFunctions.values();
            listFunctions.sort();

            _addIndicator(&result, "few_imports", CATEGORY_PACKING, SEVERITY_MEDIUM, 10, "Very few imports",
                          QString("%1 function(s) from %2 librar(y/ies): %3")
                              .arg(result.nImportFunctions)
                              .arg(result.nImportLibraries)
                              .arg(listFunctions.join(", ")));
        }

        if (bHasGetProcAddress && (result.nImportFunctions <= 20)) {
            _addIndicator(&result, "dynamic_api_resolution", CATEGORY_OBFUSCATION, SEVERITY_MEDIUM, 10, "Dynamic API resolution",
                          QString("GetProcAddress imported with only %1 static import(s)").arg(result.nImportFunctions));
        }
    }

    // ---- PACKING: overlay
    if (result.nOverlayOffset != -1) {
        if ((result.nOverlaySize >= 0x1000) && (dOverlayEntropy >= D_ENTROPY_HIGH)) {
            bool bVeryHigh = (dOverlayEntropy >= D_ENTROPY_RESOURCES);
            _addIndicator(&result, "overlay_high_entropy", CATEGORY_PACKING, bVeryHigh ? SEVERITY_MEDIUM : SEVERITY_LOW, bVeryHigh ? 8 : 4, "High entropy overlay",
                          QString("Overlay: raw %1..%2, entropy %3, compressed/encrypted payload appended to the image")
                              .arg(_hex(result.nOverlayOffset), _hex(result.nOverlayOffset + result.nOverlaySize), _entropyToString(dOverlayEntropy)),
                          LOCATION_HEX, result.nOverlayOffset, result.nOverlaySize);
        }
    }

    // ---- executable sections with entropy 6.5..7.0: packed-image part or obfuscated code
    if (!listPendingCodeEntropy.isEmpty()) {
        qint32 nPackingSoFar = 0;

        for (qint32 i = 0; i < result.listIndicators.count(); i++) {
            if (result.listIndicators.at(i).category == CATEGORY_PACKING) {
                nPackingSoFar += result.listIndicators.at(i).nWeight;
            }
        }

        for (qint32 i = 0; i < listPendingCodeEntropy.count(); i++) {
            const SECTION &section = listReal.at(listPendingCodeEntropy.at(i));
            QString sDetails = QString("%1: %2, entropy %3, %4")
                                   .arg(_sectionLabel(section), _rawRangeToString(section), _entropyToString(section.dEntropy),
                                        _flagsToString(section.bRead, section.bWrite, section.bExecute));

            if (nPackingSoFar >= 20) {
                _addIndicator(&result, "high_entropy_section", CATEGORY_PACKING, SEVERITY_MEDIUM, 10, QString("Elevated entropy: %1").arg(_sectionLabel(section)), sDetails,
                              LOCATION_HEX, section.nRawOffset, section.nRawSize);
            } else {
                _addIndicator(&result, "code_entropy_elevated", CATEGORY_OBFUSCATION, SEVERITY_MEDIUM, 8, QString("Dense code: %1").arg(_sectionLabel(section)),
                              sDetails + " (normal compiled code is about 5.5..6.7): possibly encrypted or obfuscated code", LOCATION_HEX, section.nRawOffset,
                              section.nRawSize);
            }
        }
    }

    // ---- OBFUSCATION: strings
    if ((nRawSectionsSize > 32 * 1024) && (result.dStringDensity < 0.5)) {
        bool bVeryLow = (result.dStringDensity < 0.1);
        _addIndicator(&result, "low_string_density", CATEGORY_OBFUSCATION, bVeryLow ? SEVERITY_HIGH : SEVERITY_MEDIUM, bVeryLow ? 15 : 10, "Very few strings",
                      QString("%1 string(s) in %2 KiB of section data (%3 per KiB): strings are encrypted or packed")
                          .arg(result.nStringCount)
                          .arg(nRawSectionsSize / 1024)
                          .arg(QString::number(result.dStringDensity, 'f', 2)));
    }

    // ---- OBFUSCATION: decryption/decompression APIs
    {
        QStringList listCrypt = _presentFunctions(setFunctions, {"CryptDecrypt", "RtlDecompressBuffer"});

        if (!listCrypt.isEmpty()) {
            _addIndicator(&result, "decryption_apis", CATEGORY_OBFUSCATION, SEVERITY_LOW, 5, "Run-time decryption APIs", QString("Imports %1").arg(listCrypt.join(", ")));
        }
    }

    // ---- OBFUSCATION: .NET
    if (result.bIsNET) {
        if ((result.nNetObfuscatedNames > 0) && (nNetNamesExamined > 0)) {
            double dRatio = (double)result.nNetObfuscatedNames / (double)nNetNamesExamined;
            QString sDetails = QString("%1 of %2 type/method names look obfuscated (%3%), %4 TypeDef rows; e.g. %5")
                                   .arg(result.nNetObfuscatedNames)
                                   .arg(nNetNamesExamined)
                                   .arg(QString::number(dRatio * 100.0, 'f', 0))
                                   .arg(result.nNetTypes)
                                   .arg(result.listNetSampleNames.join(", "));

            if ((result.nNetObfuscatedNames >= 5) && (dRatio >= 0.25)) {
                _addIndicator(&result, "net_obfuscated_names", CATEGORY_OBFUSCATION, SEVERITY_HIGH, 25, "Obfuscated .NET names", sDetails);
            } else if ((result.nNetObfuscatedNames >= 3) && (dRatio >= 0.08)) {
                _addIndicator(&result, "net_obfuscated_names", CATEGORY_OBFUSCATION, SEVERITY_MEDIUM, 15, "Obfuscated .NET names", sDetails);
            } else if (result.nNetObfuscatedNames >= 3) {
                _addIndicator(&result, "net_obfuscated_names", CATEGORY_OBFUSCATION, SEVERITY_LOW, 6, "Some odd .NET names", sDetails);
            }
        }

        QStringList listHigh;
        qint64 nFirstHighOffset = -1;
        qint64 nFirstHighSize = 0;

        for (qint32 i = 0; i < nNumberOfSections; i++) {
            const SECTION &section = listReal.at(i);

            if ((section.dEntropy >= D_ENTROPY_HIGH) && (section.nRawSize >= N_ENTROPY_MIN_SIZE)) {
                listHigh.append(QString("%1 (%2, entropy %3)").arg(_sectionLabel(section), _rawRangeToString(section), _entropyToString(section.dEntropy)));

                if (nFirstHighOffset == -1) {
                    nFirstHighOffset = section.nRawOffset;
                    nFirstHighSize = section.nRawSize;
                }
            }
        }

        if (!listHigh.isEmpty()) {
            _addIndicator(&result, "net_high_entropy", CATEGORY_OBFUSCATION, SEVERITY_MEDIUM, 12, ".NET with encrypted data",
                          QString("High entropy in a .NET image: %1 (encrypted resources or embedded payload)").arg(listHigh.join(", ")), LOCATION_HEX, nFirstHighOffset,
                          nFirstHighSize);
        }
    }

    // ---- ANTIANALYSIS: imports
    {
        QStringList listStrong = _presentFunctions(setFunctions, {"CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "ZwQueryInformationProcess",
                                                                  "NtSetInformationThread", "ZwSetInformationThread"});
        QStringList listWeak = _presentFunctions(setFunctions, {"IsDebuggerPresent", "OutputDebugStringA", "OutputDebugStringW"});

        if (!listStrong.isEmpty()) {
            _addIndicator(&result, "antidebug_imports", CATEGORY_ANTIANALYSIS, SEVERITY_MEDIUM, 10, "Anti-debug APIs",
                          QString("Imports %1").arg((listStrong + listWeak).join(", ")));

            QStringList listTiming = _presentFunctions(setFunctions, {"GetTickCount", "GetTickCount64", "QueryPerformanceCounter"});

            if (!listTiming.isEmpty()) {
                _addIndicator(&result, "timing_checks", CATEGORY_ANTIANALYSIS, SEVERITY_LOW, 5, "Timing checks",
                              QString("%1 together with anti-debug APIs").arg(listTiming.join(", ")));
            }
        } else if (!listWeak.isEmpty()) {
            // IsDebuggerPresent is imported by every MSVC CRT: weak evidence only
            _addIndicator(&result, "antidebug_imports", CATEGORY_ANTIANALYSIS, SEVERITY_LOW, 3, "Debugger check",
                          QString("Imports %1 (also used by the MSVC runtime)").arg(listWeak.join(", ")));
        }

        QStringList listInjection =
            _presentFunctions(setFunctions, {"WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "VirtualAllocEx"});

        if (_presentFunctions(setFunctions, {"WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection", "ZwUnmapViewOfSection"}).count() > 0) {
            _addIndicator(&result, "injection_apis", CATEGORY_ANTIANALYSIS, SEVERITY_MEDIUM, 10, "Process injection APIs",
                          QString("Imports %1 (process hollowing / injection)").arg(listInjection.join(", ")));
        }

        QStringList listEnum = _presentFunctions(setFunctions, {"FindWindowA", "FindWindowW", "CreateToolhelp32Snapshot"});

        if (!listEnum.isEmpty()) {
            _addIndicator(&result, "enumeration_apis", CATEGORY_ANTIANALYSIS, SEVERITY_LOW, 4, "Window/process enumeration",
                          QString("Imports %1 (can be used to look for debuggers and analysis tools)").arg(listEnum.join(", ")));
        }
    }

    // ---- ANTIANALYSIS: TLS callbacks
    if (!result.listTLSCallbacks.isEmpty()) {
        QStringList listAddresses;

        for (qint32 i = 0; (i < result.listTLSCallbacks.count()) && (i < 8); i++) {
            listAddresses.append(_hex(result.listTLSCallbacks.at(i)));
        }

        if (result.listTLSCallbacks.count() > 8) {
            listAddresses.append("...");
        }

        XADDR nFirstCallback = result.listTLSCallbacks.at(0);
        qint64 nCallbackOffset = XBinary::addressToOffset(&memoryMap, nFirstCallback);

        if ((nCallbackOffset < 0) || (nCallbackOffset >= nFileSize)) {
            nCallbackOffset = -1;
        }

        _addIndicator(&result, "tls_callbacks", CATEGORY_ANTIANALYSIS, SEVERITY_MEDIUM, 8, "TLS callbacks",
                      QString("%1 callback(s), code runs before the EP: %2").arg(result.listTLSCallbacks.count()).arg(listAddresses.join(", ")),
                      (nCallbackOffset != -1) ? LOCATION_DISASM : LOCATION_NONE, nCallbackOffset, 0, nFirstCallback);
    }

    // ---- INFO
    if (bHasEntryPoint) {
        QString sSection;

        if (pEntryPointSection) {
            sSection = QString("section %1 (%2)").arg(_sectionLabel(*pEntryPointSection),
                                                      _flagsToString(pEntryPointSection->bRead, pEntryPointSection->bWrite, pEntryPointSection->bExecute));
        } else {
            sSection = "no section";
        }

        QString sOffset = (result.nEntryPointOffset != -1) ? _hex(result.nEntryPointOffset) : QString("none (not in file)");

        _addIndicator(&result, "entry_point", CATEGORY_INFO, SEVERITY_INFO, 2, "Entry point",
                      QString("RVA %1, offset %2, %3").arg(_hex(nEntryPointRVA), sOffset, sSection), entryPointLocation, result.nEntryPointOffset, nEntryPointBytes,
                      nEntryPointAddress);
    } else {
        _addIndicator(&result, "entry_point", CATEGORY_INFO, SEVERITY_INFO, 2, "No native entry point",
                      result.bIsNET ? QString("AddressOfEntryPoint is 0 (IL-only .NET image)") : QString("AddressOfEntryPoint is 0 (resource-only DLL)"));
    }

    {
        QString sDetails = QString("%1 librar(y/ies), %2 function(s)").arg(result.nImportLibraries).arg(result.nImportFunctions);

        if (!result.listNotableImports.isEmpty()) {
            sDetails += QString("; notable: %1").arg(result.listNotableImports.join(", "));
        }

        _addIndicator(&result, "imports_summary", CATEGORY_INFO, SEVERITY_INFO, 1, "Imports", sDetails);
    }

    if (result.bIsDll) {
        _addIndicator(&result, "is_dll", CATEGORY_INFO, SEVERITY_INFO, 0, "DLL", "The file is a dynamic-link library");
    }

    if (result.bIsNET) {
        _addIndicator(&result, "is_net", CATEGORY_INFO, SEVERITY_INFO, 0, ".NET",
                      QString("CLI header present, %1 TypeDef rows").arg(result.nNetTypes));
    }

    if (result.nOverlayOffset != -1) {
        _addIndicator(&result, "overlay_present", CATEGORY_INFO, SEVERITY_INFO, 0, "Overlay",
                      QString("Data after the image: raw %1..%2 (%3 bytes), entropy %4")
                          .arg(_hex(result.nOverlayOffset), _hex(result.nOverlayOffset + result.nOverlaySize))
                          .arg(result.nOverlaySize)
                          .arg(_entropyToString(dOverlayEntropy)),
                      LOCATION_HEX, result.nOverlayOffset, result.nOverlaySize);
    }

    // ---- rank and score
    std::stable_sort(result.listIndicators.begin(), result.listIndicators.end(), [](const INDICATOR &indicator1, const INDICATOR &indicator2) {
        return indicator1.nWeight > indicator2.nWeight;
    });

    qint32 nPacking = 0;
    qint32 nObfuscation = 0;

    for (qint32 i = 0; i < result.listIndicators.count(); i++) {
        const INDICATOR &indicator = result.listIndicators.at(i);

        if (indicator.category == CATEGORY_PACKING) {
            nPacking += indicator.nWeight;
        } else if ((indicator.category == CATEGORY_OBFUSCATION) || (indicator.category == CATEGORY_ANTIANALYSIS)) {
            nObfuscation += indicator.nWeight;
        }
    }

    result.nPackingScore = qMin(nPacking, 100);
    result.nObfuscationScore = qMin(nObfuscation, 100);

    return result;
}

QString HelperEvidence::severityToString(SEVERITY severity)
{
    QString sResult;

    switch (severity) {
        case SEVERITY_INFO: sResult = "Info"; break;
        case SEVERITY_LOW: sResult = "Low"; break;
        case SEVERITY_MEDIUM: sResult = "Medium"; break;
        case SEVERITY_HIGH: sResult = "High"; break;
    }

    return sResult;
}

QString HelperEvidence::categoryToString(CATEGORY category)
{
    QString sResult;

    switch (category) {
        case CATEGORY_PACKING: sResult = "Packing"; break;
        case CATEGORY_OBFUSCATION: sResult = "Obfuscation"; break;
        case CATEGORY_ANTIANALYSIS: sResult = "Anti-analysis"; break;
        case CATEGORY_INFO: sResult = "Info"; break;
    }

    return sResult;
}
