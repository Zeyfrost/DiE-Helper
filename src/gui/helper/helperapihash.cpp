// DiE Helper (fork addition): finds API-hashing constants (ror13, Metasploit block_api ror13+module, crc32, djb2, fnv1a32, sdbm) and dynamic API resolution call sites.
#include "helperapihash.h"

#include <QDir>
#include <QFile>
#include <QHash>
#include <QMap>
#include <QSet>
#include <QVector>

#include <algorithm>

#include "xdisasmcore.h"
#include "xpe.h"

static const qint64 N_CODE_SCAN_MAX = 8 * 1024 * 1024;
static const qint64 N_DATA_SCAN_MAX = 8 * 1024 * 1024;
static const qint32 N_DISASM_CHUNK = 0x8000;
static const qint32 N_DISASM_TAIL = 16;
static const qint32 N_MAX_CANDIDATES = 4;     // per hash value (collisions between algorithms/names)
static const qint32 N_MAX_HITS = 5000;
static const qint32 N_MAX_CALLSITES = 2000;
static const qint32 N_DATA_CLUSTER = 64;      // a data hash needs a second one within this many bytes
static const qint32 N_MAX_PUSHES = 16;
static const qint32 N_MAX_ARGUMENT = 260;
static const quint32 N_SCN_CNT_CODE = 0x00000020;

static const qint32 N_REG_SP = 4;
static const qint32 N_REG_BP = 5;
static const qint32 N_REG_RIP = 16;
static const qint32 N_REG_COUNT = 17;

enum ALGORITHM {
    ALGORITHM_ROR13 = 0,
    ALGORITHM_ROR13_MODULE,
    ALGORITHM_CRC32,
    ALGORITHM_DJB2,
    ALGORITHM_FNV1A32,
    ALGORITHM_SDBM
};

static const char *g_pszAlgorithms[] = {"ror13", "ror13+module", "crc32", "djb2", "fnv1a32", "sdbm"};

// Order matters: module-independent hashes report the first DLL that exports the name
static const char *g_pszLibraries[] = {"kernel32.dll", "kernelbase.dll", "ntdll.dll",  "user32.dll",  "advapi32.dll", "ws2_32.dll", "wininet.dll",  "winhttp.dll",
                                       "shell32.dll",  "ole32.dll",      "crypt32.dll", "urlmon.dll", "shlwapi.dll",  "psapi.dll",  "iphlpapi.dll", "bcrypt.dll"};
static const qint32 N_LIBRARIES = (qint32)(sizeof(g_pszLibraries) / sizeof(g_pszLibraries[0]));

struct DBENTRY {
    quint32 nHash;
    quint32 nName;  // index into APIDB::listNames
    quint8 nLibrary;
    quint8 nAlgorithm;
};

struct APIDB {
    QVector<QString> listNames;
    QVector<DBENTRY> listEntries;  // sorted by nHash
    qint32 nLibrariesLoaded;
};

// ---- hash functions (ASCII names, no terminator unless stated)
static quint32 _ror32(quint32 nValue, qint32 nBits)
{
    return (nValue >> nBits) | (nValue << (32 - nBits));
}

static quint32 _hashRor13(const QByteArray &baName, bool bWithTerminator)
{
    quint32 nHash = 0;

    for (qint32 i = 0; i < baName.size(); i++) {
        nHash = _ror32(nHash, 13) + (quint8)baName.at(i);
    }

    if (bWithTerminator) {
        nHash = _ror32(nHash, 13);  // + 0
    }

    return nHash;
}

// block_api module hash: BaseDllName as UTF-16LE including the terminating NUL, bytes >= 'a' upper-cased (-0x20)
static quint32 _hashModule(const QString &sModule)
{
    quint32 nHash = 0;
    QString sName = sModule + QChar(0);

    for (qint32 i = 0; i < sName.length(); i++) {
        ushort nChar = sName.at(i).unicode();
        quint8 nBytes[2] = {(quint8)(nChar & 0xFF), (quint8)(nChar >> 8)};

        for (qint32 j = 0; j < 2; j++) {
            quint32 nByte = nBytes[j];

            if (nByte >= 0x61) {
                nByte -= 0x20;
            }

            nHash = _ror32(nHash, 13) + nByte;
        }
    }

    return nHash;
}

static quint32 _hashCrc32(const QByteArray &baName)
{
    static const QVector<quint32> listTable = []() {
        QVector<quint32> listResult(256);

        for (quint32 i = 0; i < 256; i++) {
            quint32 nValue = i;

            for (qint32 j = 0; j < 8; j++) {
                nValue = (nValue & 1) ? ((nValue >> 1) ^ 0xEDB88320) : (nValue >> 1);
            }

            listResult[i] = nValue;
        }

        return listResult;
    }();

    quint32 nCrc = 0xFFFFFFFF;

    for (qint32 i = 0; i < baName.size(); i++) {
        nCrc = listTable.at((nCrc ^ (quint8)baName.at(i)) & 0xFF) ^ (nCrc >> 8);
    }

    return nCrc ^ 0xFFFFFFFF;
}

static quint32 _hashDjb2(const QByteArray &baName)
{
    quint32 nHash = 5381;

    for (qint32 i = 0; i < baName.size(); i++) {
        nHash = (nHash << 5) + nHash + (quint8)baName.at(i);
    }

    return nHash;
}

static quint32 _hashFnv1a32(const QByteArray &baName)
{
    quint32 nHash = 0x811C9DC5;

    for (qint32 i = 0; i < baName.size(); i++) {
        nHash ^= (quint8)baName.at(i);
        nHash *= 0x01000193;
    }

    return nHash;
}

static quint32 _hashSdbm(const QByteArray &baName)
{
    quint32 nHash = 0;

    for (qint32 i = 0; i < baName.size(); i++) {
        nHash = (quint8)baName.at(i) + (nHash << 6) + (nHash << 16) - nHash;
    }

    return nHash;
}

static void _addEntry(APIDB *pDb, quint32 nHash, quint32 nName, qint32 nLibrary, ALGORITHM algorithm)
{
    DBENTRY entry = {};
    entry.nHash = nHash;
    entry.nName = nName;
    entry.nLibrary = (quint8)nLibrary;
    entry.nAlgorithm = (quint8)algorithm;

    pDb->listEntries.append(entry);
}

static APIDB _buildDb()
{
    APIDB db = {};

    QString sSystemRoot = qEnvironmentVariable("SystemRoot");

    if (sSystemRoot.isEmpty()) {
        sSystemRoot = "C:/Windows";
    }

    QDir dirSystem(QDir(sSystemRoot).filePath("System32"));
    QHash<QString, quint32> mapNames;

    for (qint32 i = 0; i < N_LIBRARIES; i++) {
        QString sLibrary = QString::fromLatin1(g_pszLibraries[i]);
        QFile file(dirSystem.filePath(sLibrary));

        if (!file.open(QIODevice::ReadOnly)) {
            continue;
        }

        // export names are read from the file as data; the DLL is never loaded
        XPE pe(&file);

        if (pe.isValid()) {
            XBinary::_MEMORY_MAP memoryMap = pe.getMemoryMap();
            XPE::EXPORT_HEADER exportHeader = pe.getExport(&memoryMap, false, nullptr);
            quint32 nModuleHash = _hashModule(sLibrary);

            for (qint32 j = 0; j < exportHeader.listPositions.count(); j++) {
                const QString &sFunction = exportHeader.listPositions.at(j).sFunctionName;

                if (sFunction.isEmpty()) {
                    continue;
                }

                QByteArray baName = sFunction.toLatin1();
                QHash<QString, quint32>::const_iterator iter = mapNames.constFind(sFunction);
                quint32 nName = 0;

                if (iter == mapNames.constEnd()) {
                    nName = (quint32)db.listNames.count();
                    db.listNames.append(sFunction);
                    mapNames.insert(sFunction, nName);

                    _addEntry(&db, _hashRor13(baName, false), nName, i, ALGORITHM_ROR13);
                    _addEntry(&db, _hashCrc32(baName), nName, i, ALGORITHM_CRC32);
                    _addEntry(&db, _hashDjb2(baName), nName, i, ALGORITHM_DJB2);
                    _addEntry(&db, _hashFnv1a32(baName), nName, i, ALGORITHM_FNV1A32);
                    _addEntry(&db, _hashSdbm(baName), nName, i, ALGORITHM_SDBM);
                } else {
                    nName = iter.value();
                }

                // block_api: module hash + ror13 of the name including its NUL terminator
                _addEntry(&db, nModuleHash + _hashRor13(baName, true), nName, i, ALGORITHM_ROR13_MODULE);
            }

            db.nLibrariesLoaded++;
        }

        file.close();
    }

    std::sort(db.listEntries.begin(), db.listEntries.end(), [](const DBENTRY &entry1, const DBENTRY &entry2) {
        if (entry1.nHash != entry2.nHash) {
            return entry1.nHash < entry2.nHash;
        }

        return entry1.nAlgorithm < entry2.nAlgorithm;
    });

    return db;
}

// Built on first use; C++11 guarantees thread-safe initialization of function-local statics
static const APIDB &_getDb()
{
    static const APIDB g_db = _buildDb();

    return g_db;
}

static QList<DBENTRY> _lookup(const APIDB &db, quint32 nHash)
{
    QList<DBENTRY> listResult;

    DBENTRY key = {};
    key.nHash = nHash;

    QVector<DBENTRY>::const_iterator iterBegin =
        std::lower_bound(db.listEntries.constBegin(), db.listEntries.constEnd(), key, [](const DBENTRY &entry1, const DBENTRY &entry2) { return entry1.nHash < entry2.nHash; });

    for (QVector<DBENTRY>::const_iterator iter = iterBegin; (iter != db.listEntries.constEnd()) && (iter->nHash == nHash) && (listResult.count() < N_MAX_CANDIDATES); ++iter) {
        listResult.append(*iter);
    }

    return listResult;
}

static void _addHits(QList<HelperApiHash::HIT> *pListHits, const APIDB &db, const QList<DBENTRY> &listEntries, qint64 nOffset, XADDR nAddress)
{
    for (qint32 i = 0; (i < listEntries.count()) && (pListHits->count() < N_MAX_HITS); i++) {
        const DBENTRY &entry = listEntries.at(i);

        HelperApiHash::HIT hit = {};
        hit.nOffset = nOffset;
        hit.nAddress = nAddress;
        hit.nHash = entry.nHash;
        hit.sAlgorithm = QString::fromLatin1(g_pszAlgorithms[entry.nAlgorithm]);
        hit.sLibrary = QString::fromLatin1(g_pszLibraries[entry.nLibrary]);
        hit.sFunction = db.listNames.at((qint32)entry.nName);

        pListHits->append(hit);
    }
}

// ---- x86 helpers (same conventions as helperstrings.cpp)
static quint64 _readLE(const quint8 *pData, qint32 nSize)
{
    quint64 nResult = 0;

    for (qint32 i = nSize - 1; i >= 0; i--) {
        nResult = (nResult << 8) | pData[i];
    }

    return nResult;
}

static qint64 _signExtend(quint64 nValue, qint32 nSize)
{
    qint64 nResult = (qint64)nValue;

    if (nSize == 1) {
        nResult = (qint8)nValue;
    } else if (nSize == 2) {
        nResult = (qint16)nValue;
    } else if (nSize == 4) {
        nResult = (qint32)nValue;
    }

    return nResult;
}

static qint32 _regFamily(const QString &sName, qint32 *pnSize)
{
    static const QHash<QString, qint32> mapRegs = []() {
        QHash<QString, qint32> mapResult;
        const char *pszLegacy[8][5] = {{"rax", "eax", "ax", "al", "ah"},   {"rcx", "ecx", "cx", "cl", "ch"},   {"rdx", "edx", "dx", "dl", "dh"},
                                       {"rbx", "ebx", "bx", "bl", "bh"},   {"rsp", "esp", "sp", "spl", ""},    {"rbp", "ebp", "bp", "bpl", ""},
                                       {"rsi", "esi", "si", "sil", ""},    {"rdi", "edi", "di", "dil", ""}};
        const qint32 nSizes[5] = {8, 4, 2, 1, -1};

        for (qint32 i = 0; i < 8; i++) {
            for (qint32 j = 0; j < 5; j++) {
                if (pszLegacy[i][j][0]) {
                    mapResult.insert(QString(pszLegacy[i][j]), (i << 8) | (nSizes[j] & 0xFF));
                }
            }
        }

        for (qint32 i = 8; i < 16; i++) {
            QString sBase = QString("r%1").arg(i);
            mapResult.insert(sBase, (i << 8) | 8);
            mapResult.insert(sBase + "d", (i << 8) | 4);
            mapResult.insert(sBase + "w", (i << 8) | 2);
            mapResult.insert(sBase + "b", (i << 8) | 1);
        }

        mapResult.insert("rip", (N_REG_RIP << 8) | 8);
        mapResult.insert("eip", (N_REG_RIP << 8) | 4);

        return mapResult;
    }();

    qint32 nResult = -1;
    qint32 nSize = 0;

    QHash<QString, qint32>::const_iterator iter = mapRegs.constFind(sName);

    if (iter != mapRegs.constEnd()) {
        nResult = iter.value() >> 8;
        nSize = (qint8)(iter.value() & 0xFF);
    }

    if (pnSize) {
        *pnSize = nSize;
    }

    return nResult;
}

struct OPERAND {
    bool bIsReg;
    bool bIsMem;
    qint32 nReg;
    qint32 nRegSize;
    qint32 nMemSize;
    qint32 nBase;
    bool bHasIndex;
    bool bHasSegment;
};

static OPERAND _parseOperand(const QString &sOperand)
{
    OPERAND result = {};
    result.nReg = -1;
    result.nBase = -1;

    QString sText = sOperand.trimmed();
    qint32 nBracket = sText.indexOf(QChar('['));

    if (nBracket >= 0) {
        result.bIsMem = true;

        if (sText.startsWith("byte")) {
            result.nMemSize = 1;
        } else if (sText.startsWith("word")) {
            result.nMemSize = 2;
        } else if (sText.startsWith("dword")) {
            result.nMemSize = 4;
        } else if (sText.startsWith("qword")) {
            result.nMemSize = 8;
        }

        result.bHasSegment = sText.left(nBracket).contains(QChar(':'));

        qint32 nEnd = sText.indexOf(QChar(']'), nBracket);
        QString sInner = sText.mid(nBracket + 1, (nEnd > nBracket) ? (nEnd - nBracket - 1) : -1);
        QStringList listTokens = sInner.split(QChar(' '), Qt::SkipEmptyParts);

        for (qint32 i = 0; i < listTokens.count(); i++) {
            const QString &sToken = listTokens.at(i);

            if (sToken.contains(QChar('*'))) {
                result.bHasIndex = true;
                continue;
            }

            qint32 nFamily = _regFamily(sToken, nullptr);

            if (nFamily != -1) {
                if (result.nBase == -1) {
                    result.nBase = nFamily;
                } else {
                    result.bHasIndex = true;
                }
            }
        }
    } else {
        qint32 nSize = 0;
        qint32 nFamily = _regFamily(sText, &nSize);

        if (nFamily != -1) {
            result.bIsReg = true;
            result.nReg = nFamily;
            result.nRegSize = nSize;
        }
    }

    return result;
}

static void _splitOperands(const QString &sOperands, QString *psFirst, QString *psSecond)
{
    qint32 nComma = sOperands.indexOf(QChar(','));

    if (nComma >= 0) {
        *psFirst = sOperands.left(nComma).trimmed();
        *psSecond = sOperands.mid(nComma + 1).trimmed();
    } else {
        *psFirst = sOperands.trimmed();
        psSecond->clear();
    }
}

static bool _isExecutable(const XPE_DEF::IMAGE_SECTION_HEADER &header)
{
    return (header.Characteristics & XPE_DEF::S_IMAGE_SCN_MEM_EXECUTE) || (header.Characteristics & N_SCN_CNT_CODE);
}

// Linear sweep over executable sections; calls processInstruction(result, bytes, available, fileOffset, bNewSection)
template <typename T>
static void _walkCode(XPE *pPE, const QList<XPE_DEF::IMAGE_SECTION_HEADER> &listHeaders, XADDR nImageBase, bool bIs64, qint64 nFileSize, XBinary::PDSTRUCT *pPdStruct,
                      T processInstruction)
{
    XDisasmCore disasmCore;  // no setOptions(): never pass a null XOptions
    disasmCore.setMode(bIs64 ? XBinary::DM_X86_64 : XBinary::DM_X86_32);

    XDisasmAbstract::DISASM_OPTIONS disasmOptions = {};
    disasmOptions.bIsUppercase = false;
    disasmOptions.bNoStrings = true;

    qint64 nTotal = 0;

    for (qint32 i = 0; (i < listHeaders.count()) && (nTotal < N_CODE_SCAN_MAX) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        const XPE_DEF::IMAGE_SECTION_HEADER &header = listHeaders.at(i);

        if (!_isExecutable(header)) {
            continue;
        }

        qint64 nRawOffset = header.PointerToRawData;
        qint64 nRawSize = header.SizeOfRawData;

        if ((nRawOffset <= 0) || (nRawOffset >= nFileSize) || (nRawSize <= 0)) {
            continue;
        }

        nRawSize = qMin(nRawSize, nFileSize - nRawOffset);

        if ((header.Misc.VirtualSize > 0) && ((qint64)header.Misc.VirtualSize < nRawSize)) {
            nRawSize = header.Misc.VirtualSize;
        }

        XADDR nSectionAddress = nImageBase + header.VirtualAddress;
        qint64 nPos = 0;
        bool bNewSection = true;

        while ((nPos < nRawSize) && (nTotal < N_CODE_SCAN_MAX) && XBinary::isPdStructNotCanceled(pPdStruct)) {
            qint64 nReadSize = qMin<qint64>(N_DISASM_CHUNK + N_DISASM_TAIL, nRawSize - nPos);
            QByteArray baChunk = pPE->read_array(nRawOffset + nPos, nReadSize);
            qint32 nChunkSize = baChunk.size();

            if (nChunkSize <= 0) {
                break;
            }

            bool bLast = (nPos + nChunkSize >= nRawSize);
            qint32 nAccept = bLast ? nChunkSize : qMin(N_DISASM_CHUNK, nChunkSize);
            XADDR nChunkAddress = nSectionAddress + nPos;

            QList<XDisasmAbstract::DISASM_RESULT> listResults = disasmCore.disAsmList(baChunk.data(), nChunkSize, nChunkAddress, disasmOptions, -1, pPdStruct);

            qint64 nConsumed = 0;

            for (qint32 j = 0; j < listResults.count(); j++) {
                const XDisasmAbstract::DISASM_RESULT &disasmResult = listResults.at(j);
                qint64 nDelta = (qint64)(disasmResult.nAddress - nChunkAddress);

                if ((nDelta < 0) || (nDelta >= nAccept) || (disasmResult.nSize <= 0)) {
                    break;
                }

                processInstruction(disasmResult, (const quint8 *)baChunk.constData() + nDelta, (qint32)(nChunkSize - nDelta), nRawOffset + nPos + nDelta, bNewSection);
                bNewSection = false;
                nConsumed = nDelta + disasmResult.nSize;
            }

            if (nConsumed <= 0) {
                nConsumed = nAccept;
            }

            nPos += nConsumed;
            nTotal += nConsumed;
        }
    }
}

// ---- call-site argument tracking
enum SRC {
    SRC_NONE = 0,
    SRC_IMM,      // constant that is not an address in the image
    SRC_ADDRESS,  // pointer into the image (lea reg, [rip+X] / push offset X / mov reg, offset X)
    SRC_STACK,    // pointer to a stack slot (lea reg, [rsp+X])
    SRC_IMPORT    // value loaded from an IAT slot (mov reg, [__imp_X])
};

struct ARGSOURCE {
    SRC src;
    quint64 nValue;  // constant / address / stack key
    QString sImport; // "KERNEL32.dll!GetProcAddress" for SRC_IMPORT
};

enum ARGKIND {
    ARGKIND_ANSI = 0,
    ARGKIND_WIDE,
    ARGKIND_ANSI_OR_ORDINAL,
    ARGKIND_PANSI_STRING,
    ARGKIND_PUNICODE_STRING
};

struct RESOLVER {
    const char *pszFunction;
    qint32 nArgument;
    ARGKIND argKind;
};

static const RESOLVER g_resolvers[] = {{"GetProcAddress", 1, ARGKIND_ANSI_OR_ORDINAL},
                                       {"LoadLibraryA", 0, ARGKIND_ANSI},
                                       {"LoadLibraryW", 0, ARGKIND_WIDE},
                                       {"LoadLibraryExA", 0, ARGKIND_ANSI},
                                       {"LoadLibraryExW", 0, ARGKIND_WIDE},
                                       {"GetModuleHandleA", 0, ARGKIND_ANSI},
                                       {"GetModuleHandleW", 0, ARGKIND_WIDE},
                                       {"GetModuleHandleExA", 1, ARGKIND_ANSI},
                                       {"GetModuleHandleExW", 1, ARGKIND_WIDE},
                                       {"LdrGetProcedureAddress", 1, ARGKIND_PANSI_STRING},
                                       {"LdrLoadDll", 2, ARGKIND_PUNICODE_STRING},
                                       {"LdrGetDllHandle", 2, ARGKIND_PUNICODE_STRING}};

struct TRACKSTATE {
    ARGSOURCE aRegs[N_REG_COUNT];
    QList<ARGSOURCE> listPushes;   // x86 arguments pushed since the last call
    QMap<qint64, quint8> mapStack; // key: (base family << 33) + displacement
};

static void _resetRegs(TRACKSTATE *pState, bool bKeepCalleeSaved, bool bIs64)
{
    for (qint32 i = 0; i < N_REG_COUNT; i++) {
        bool bCalleeSaved = (i == 3) || (i == N_REG_SP) || (i == N_REG_BP) || (i == 6) || (i == 7) || (bIs64 && (i >= 12) && (i <= 15));

        if (!(bKeepCalleeSaved && bCalleeSaved)) {
            pState->aRegs[i].src = SRC_NONE;
            pState->aRegs[i].nValue = 0;
            pState->aRegs[i].sImport.clear();
        }
    }
}

static QString _quote(const QString &sText)
{
    return QString("\"%1\"").arg(sText);
}

static QString _readTextAt(XPE *pPE, XBinary::_MEMORY_MAP *pMemoryMap, XADDR nAddress, bool bWide)
{
    QString sResult;
    qint64 nOffset = XBinary::addressToOffset(pMemoryMap, nAddress);

    if (nOffset < 0) {
        return sResult;
    }

    QByteArray baData = pPE->read_array(nOffset, bWide ? (2 * N_MAX_ARGUMENT) : N_MAX_ARGUMENT);
    const quint8 *pData = (const quint8 *)baData.constData();
    qint32 nSize = baData.size();
    qint32 nStep = bWide ? 2 : 1;
    bool bTerminated = false;

    for (qint32 i = 0; i + nStep <= nSize; i += nStep) {
        ushort nChar = bWide ? (ushort)(pData[i] | (pData[i + 1] << 8)) : pData[i];

        if (nChar == 0) {
            bTerminated = true;
            break;
        }

        if ((nChar < 0x20) || (nChar == 0x7F)) {
            return QString();
        }

        sResult.append(QChar(nChar));
    }

    if (!bTerminated) {
        sResult.clear();
    }

    return sResult;
}

// ANSI_STRING / UNICODE_STRING { USHORT Length; USHORT MaximumLength; PVOID Buffer; } stored in the image
static QString _readCountedTextAt(XPE *pPE, XBinary::_MEMORY_MAP *pMemoryMap, XADDR nAddress, bool bWide, bool bIs64)
{
    QString sResult;
    qint64 nOffset = XBinary::addressToOffset(pMemoryMap, nAddress);

    if (nOffset >= 0) {
        quint16 nLength = pPE->read_uint16(nOffset);
        XADDR nBuffer = bIs64 ? pPE->read_uint64(nOffset + 8) : pPE->read_uint32(nOffset + 4);
        QString sText = _readTextAt(pPE, pMemoryMap, nBuffer, bWide);

        if (!sText.isEmpty()) {
            sResult = sText.left(bWide ? (nLength / 2) : nLength);
        }
    }

    return sResult;
}

static QString _readStackText(const TRACKSTATE &state, qint64 nKey, bool bWide)
{
    QString sResult;
    qint32 nStep = bWide ? 2 : 1;

    for (qint32 i = 0; i < N_MAX_ARGUMENT; i++) {
        qint64 nCharKey = nKey + (qint64)i * nStep;

        if (!state.mapStack.contains(nCharKey) || (bWide && !state.mapStack.contains(nCharKey + 1))) {
            return QString();  // not (fully) built from constants
        }

        ushort nChar = state.mapStack.value(nCharKey);

        if (bWide) {
            nChar |= (ushort)(state.mapStack.value(nCharKey + 1) << 8);
        }

        if (nChar == 0) {
            return sResult;
        }

        if ((nChar < 0x20) || (nChar == 0x7F)) {
            return QString();
        }

        sResult.append(QChar(nChar));
    }

    return QString();
}

static QString _stackKeyToString(qint64 nKey)
{
    qint32 nBase = (qint32)((nKey + ((qint64)1 << 32)) >> 33);
    qint64 nDisp = nKey - ((qint64)nBase << 33);
    QString sBase = (nBase == N_REG_BP) ? QString("bp") : QString("sp");

    return QString("[%1%2%3]").arg(sBase, (nDisp < 0) ? QString("-") : QString("+"), QString("0x%1").arg(QString::number(qAbs(nDisp), 16).toUpper()));
}

static QString _describeArgument(const ARGSOURCE &source, ARGKIND argKind, const TRACKSTATE &state, XPE *pPE, XBinary::_MEMORY_MAP *pMemoryMap, bool bIs64)
{
    QString sResult = "? (computed at run time)";
    bool bWide = (argKind == ARGKIND_WIDE) || (argKind == ARGKIND_PUNICODE_STRING);

    if (source.src == SRC_ADDRESS) {
        QString sText;

        if ((argKind == ARGKIND_PANSI_STRING) || (argKind == ARGKIND_PUNICODE_STRING)) {
            sText = _readCountedTextAt(pPE, pMemoryMap, source.nValue, bWide, bIs64);
        } else {
            sText = _readTextAt(pPE, pMemoryMap, source.nValue, bWide);
        }

        if (!sText.isEmpty()) {
            sResult = _quote(sText);
        } else {
            sResult = QString("pointer 0x%1 (not a plain string: encoded or filled at run time)").arg(QString::number(source.nValue, 16).toUpper());
        }
    } else if (source.src == SRC_STACK) {
        QString sText;

        if ((argKind != ARGKIND_PANSI_STRING) && (argKind != ARGKIND_PUNICODE_STRING)) {
            sText = _readStackText(state, (qint64)source.nValue, bWide);
        }

        if (!sText.isEmpty()) {
            sResult = _quote(sText) + " (stack string)";
        } else {
            sResult = QString("stack buffer %1 (built or decoded at run time)").arg(_stackKeyToString((qint64)source.nValue));
        }
    } else if (source.src == SRC_IMM) {
        if ((argKind == ARGKIND_ANSI_OR_ORDINAL) && (source.nValue < 0x10000)) {
            sResult = QString("ordinal %1").arg(source.nValue);
        } else if (source.nValue == 0) {
            sResult = "NULL";
        } else {
            sResult = QString("0x%1").arg(QString::number(source.nValue, 16).toUpper());
        }
    } else if (source.src == SRC_IMPORT) {
        sResult = QString("result of %1").arg(source.sImport);
    }

    return sResult;
}

HelperApiHash::RESULT HelperApiHash::scan(const QString &sFileName, XBinary::PDSTRUCT *pPdStruct)
{
    RESULT result = {};
    result.bIsValid = false;
    result.nKnownApis = 0;

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

    const APIDB &db = _getDb();
    result.nKnownApis = db.listNames.count();

    if (db.listEntries.isEmpty()) {
        result.sError = "No System32 export names could be read: hash constants are not matched (call sites are still listed)";
    }

    if (pe.isNETPresent()) {
        // IL is not x86 code: nothing to disassemble (mixed-mode C++/CLI images are not handled)
        file.close();
        return result;
    }

    const qint64 nFileSize = pe.getSize();
    const bool bIs64 = pe.is64();
    const XADDR nImageBase = pe.getOptionalHeader_ImageBase();
    const quint64 nSizeOfImage = pe.getOptionalHeader_SizeOfImage();

    XBinary::_MEMORY_MAP memoryMap = pe.getMemoryMap();
    QList<XPE_DEF::IMAGE_SECTION_HEADER> listHeaders = pe.getSectionHeaders(nullptr);

    // ---- IAT slots: VA -> "LIB!Function"
    QHash<XADDR, QString> mapIat;
    QHash<XADDR, QString> mapIatFunction;
    {
        QList<XPE::IMPORT_HEADER> listImports = pe.getImports(&memoryMap, nullptr);

        for (qint32 i = 0; i < listImports.count(); i++) {
            const XPE::IMPORT_HEADER &importHeader = listImports.at(i);

            for (qint32 j = 0; j < importHeader.listPositions.count(); j++) {
                const XPE::IMPORT_POSITION &position = importHeader.listPositions.at(j);
                QString sFunction = position.sFunction;

                if (sFunction.isEmpty()) {
                    sFunction = position.sName.isEmpty() ? QString("#%1").arg(position.nOrdinal) : position.sName;
                }

                XADDR nSlot = nImageBase + (XADDR)position.nThunkRVA;
                mapIat.insert(nSlot, importHeader.sName + "!" + sFunction);
                mapIatFunction.insert(nSlot, sFunction);
            }
        }
    }

    // ---- import thunks: jmp [IAT slot] (FF 25), found by a raw byte scan so calls before the thunk resolve too
    QHash<XADDR, XADDR> mapThunks;  // thunk address -> IAT slot
    {
        qint64 nScanned = 0;

        for (qint32 i = 0; (i < listHeaders.count()) && (nScanned < N_CODE_SCAN_MAX) && !mapIat.isEmpty(); i++) {
            const XPE_DEF::IMAGE_SECTION_HEADER &header = listHeaders.at(i);
            qint64 nRawOffset = header.PointerToRawData;
            qint64 nRawSize = header.SizeOfRawData;

            if (!_isExecutable(header) || (nRawOffset <= 0) || (nRawOffset >= nFileSize) || (nRawSize <= 0)) {
                continue;
            }

            nRawSize = qMin(qMin(nRawSize, nFileSize - nRawOffset), N_CODE_SCAN_MAX - nScanned);

            QByteArray baData = pe.read_array(nRawOffset, nRawSize);
            const quint8 *pData = (const quint8 *)baData.constData();
            qint32 nSize = baData.size();
            XADDR nSectionAddress = nImageBase + header.VirtualAddress;

            for (qint32 j = 0; j + 6 <= nSize; j++) {
                if ((pData[j] != 0xFF) || (pData[j + 1] != 0x25)) {
                    continue;
                }

                quint32 nValue = (quint32)_readLE(pData + j + 2, 4);
                XADDR nSlot = bIs64 ? (XADDR)((qint64)(nSectionAddress + j + 6) + (qint32)nValue) : (XADDR)nValue;

                if (mapIat.contains(nSlot)) {
                    mapThunks.insert(nSectionAddress + j, nSlot);

                    if (bIs64 && (j > 0) && (pData[j - 1] == 0x48)) {
                        mapThunks.insert(nSectionAddress + j - 1, nSlot);  // REX.W jmp
                    }
                }
            }

            nScanned += nSize;
        }
    }

    QList<HIT> listHits;
    QList<CALLSITE> listCallSites;

    // ---- code: hash immediates + resolver call sites
    {
        TRACKSTATE state;
        _resetRegs(&state, false, bIs64);

        auto isImageAddress = [&](quint64 nValue) { return (nValue >= nImageBase) && (nValue < nImageBase + nSizeOfImage); };

        _walkCode(&pe, listHeaders, nImageBase, bIs64, nFileSize, pPdStruct,
                  [&](const XDisasmAbstract::DISASM_RESULT &disasmResult, const quint8 *pBytes, qint32 nAvailable, qint64 nOffset, bool bNewSection) {
                      if (bNewSection) {
                          _resetRegs(&state, false, bIs64);
                          state.listPushes.clear();
                          state.mapStack.clear();
                      }

                      if (!disasmResult.bIsValid) {
                          return;
                      }

                      quint32 nOpcode = disasmResult.nOpcode;
                      bool bBranch = disasmResult.bIsCall || disasmResult.bIsJmp || disasmResult.bIsCondJmp || (disasmResult.relType != XDisasmAbstract::RELTYPE_NONE);
                      bool bImmediate = (disasmResult.nImmSize > 0) && ((qint32)(disasmResult.nImmOffset + disasmResult.nImmSize) <= nAvailable);
                      qint32 nImmSize = (qint32)disasmResult.nImmSize;
                      quint64 nImmediate = bImmediate ? _readLE(pBytes + disasmResult.nImmOffset, nImmSize) : 0;

                      // hash constants
                      if (bImmediate && !bBranch && !db.listEntries.isEmpty() && ((nImmSize == 4) || ((nImmSize == 8) && (nImmediate <= 0xFFFFFFFF)))) {
                          quint32 nValue = (quint32)nImmediate;

                          if ((nValue >= 0x10000) && (nValue < 0xFFFF0000) && !isImageAddress(nValue)) {
                              QList<DBENTRY> listEntries = _lookup(db, nValue);

                              if (!listEntries.isEmpty()) {
                                  _addHits(&listHits, db, listEntries, nOffset, disasmResult.nAddress);
                              }
                          }
                      }

                      if ((nOpcode == X86_INS_RET) || (nOpcode == X86_INS_RETF) || (nOpcode == X86_INS_INT3)) {
                          _resetRegs(&state, false, bIs64);
                          state.listPushes.clear();
                          state.mapStack.clear();
                          return;
                      }

                      QString sFirst;
                      QString sSecond;
                      _splitOperands(disasmResult.sOperands, &sFirst, &sSecond);
                      OPERAND opDst = _parseOperand(sFirst);

                      if (disasmResult.bIsCall) {
                          QString sCallee;
                          QString sFunction;

                          if ((disasmResult.relType == XDisasmAbstract::RELTYPE_CALL) && mapThunks.contains(disasmResult.nXrefToRelative)) {
                              XADDR nSlot = mapThunks.value(disasmResult.nXrefToRelative);
                              sCallee = mapIat.value(nSlot);
                              sFunction = mapIatFunction.value(nSlot);
                          } else if (opDst.bIsMem && (disasmResult.memType != XDisasmAbstract::MEMTYPE_NONE) && mapIat.contains(disasmResult.nXrefToMemory)) {
                              sCallee = mapIat.value(disasmResult.nXrefToMemory);
                              sFunction = mapIatFunction.value(disasmResult.nXrefToMemory);
                          } else if (opDst.bIsReg && (state.aRegs[opDst.nReg].src == SRC_IMPORT)) {
                              sCallee = state.aRegs[opDst.nReg].sImport;
                              sFunction = sCallee.section(QChar('!'), 1);
                          }

                          if (!sFunction.isEmpty() && (listCallSites.count() < N_MAX_CALLSITES)) {
                              for (const RESOLVER &resolver : g_resolvers) {
                                  if (sFunction != QLatin1String(resolver.pszFunction)) {
                                      continue;
                                  }

                                  ARGSOURCE source = {};

                                  if (bIs64) {
                                      static const qint32 nArgRegs[4] = {1, 2, 8, 9};  // rcx, rdx, r8, r9
                                      source = state.aRegs[nArgRegs[resolver.nArgument]];
                                  } else if (resolver.nArgument < state.listPushes.count()) {
                                      source = state.listPushes.at(state.listPushes.count() - 1 - resolver.nArgument);
                                  }

                                  CALLSITE callSite = {};
                                  callSite.nAddress = disasmResult.nAddress;
                                  callSite.sCallee = sCallee;
                                  callSite.sArgument = _describeArgument(source, resolver.argKind, state, &pe, &memoryMap, bIs64);
                                  listCallSites.append(callSite);
                                  break;
                              }
                          }

                          _resetRegs(&state, true, bIs64);
                          state.aRegs[0].src = SRC_NONE;  // the return value; tracked further only via mov reg, [IAT]
                          state.listPushes.clear();
                          return;
                      }

                      OPERAND opSrc = _parseOperand(sSecond);

                      auto sourceFromImmediate = [&](quint64 nValue) {
                          ARGSOURCE source = {};
                          source.src = isImageAddress(nValue) ? SRC_ADDRESS : SRC_IMM;
                          source.nValue = nValue;
                          return source;
                      };

                      auto stackKey = [&](const OPERAND &operand) {
                          qint64 nDisp = 0;

                          if ((disasmResult.nDispSize > 0) && ((qint32)(disasmResult.nDispOffset + disasmResult.nDispSize) <= nAvailable)) {
                              nDisp = _signExtend(_readLE(pBytes + disasmResult.nDispOffset, disasmResult.nDispSize), disasmResult.nDispSize);
                          }

                          return ((qint64)operand.nBase << 33) + nDisp;
                      };

                      auto isStackOperand = [&](const OPERAND &operand) {
                          return operand.bIsMem && !operand.bHasIndex && !operand.bHasSegment && ((operand.nBase == N_REG_SP) || (operand.nBase == N_REG_BP));
                      };

                      if ((nOpcode == X86_INS_MOV) || (nOpcode == X86_INS_MOVABS)) {
                          if (isStackOperand(opDst) && (opDst.nMemSize > 0)) {
                              qint64 nKey = stackKey(opDst);
                              bool bKnown = false;
                              quint64 nValue = 0;

                              if (bImmediate) {
                                  bKnown = true;
                                  nValue = (quint64)_signExtend(nImmediate, nImmSize);
                              } else if (opSrc.bIsReg && (opSrc.nRegSize > 0) && (state.aRegs[opSrc.nReg].src == SRC_IMM)) {
                                  bKnown = true;
                                  nValue = state.aRegs[opSrc.nReg].nValue;
                              }

                              for (qint32 i = 0; i < opDst.nMemSize; i++) {
                                  if (bKnown) {
                                      state.mapStack.insert(nKey + i, (quint8)(nValue >> (8 * i)));
                                  } else {
                                      state.mapStack.remove(nKey + i);
                                  }
                              }

                              return;
                          }

                          if (opDst.bIsReg) {
                              ARGSOURCE &target = state.aRegs[opDst.nReg];

                              if (bImmediate && !opSrc.bIsMem && (opDst.nRegSize >= 4)) {
                                  quint64 nValue = (opDst.nRegSize == 8) ? (quint64)_signExtend(nImmediate, nImmSize) : (quint64)(quint32)nImmediate;
                                  target = sourceFromImmediate(nValue);
                              } else if (opSrc.bIsMem && (disasmResult.memType != XDisasmAbstract::MEMTYPE_NONE) && mapIat.contains(disasmResult.nXrefToMemory)) {
                                  target = ARGSOURCE();
                                  target.src = SRC_IMPORT;
                                  target.sImport = mapIat.value(disasmResult.nXrefToMemory);
                              } else if (opSrc.bIsReg && (opSrc.nRegSize >= 4) && (opDst.nRegSize >= 4)) {
                                  target = state.aRegs[opSrc.nReg];
                              } else {
                                  target = ARGSOURCE();
                              }
                          }

                          return;
                      }

                      if ((nOpcode == X86_INS_LEA) && opDst.bIsReg) {
                          ARGSOURCE &target = state.aRegs[opDst.nReg];
                          target = ARGSOURCE();

                          if (opSrc.bIsMem && !opSrc.bHasIndex && ((opSrc.nBase == N_REG_RIP) || (opSrc.nBase == -1)) &&
                              (disasmResult.memType != XDisasmAbstract::MEMTYPE_NONE)) {
                              target.src = SRC_ADDRESS;
                              target.nValue = disasmResult.nXrefToMemory;
                          } else if (isStackOperand(opSrc)) {
                              target.src = SRC_STACK;
                              target.nValue = (quint64)stackKey(opSrc);
                          }

                          return;
                      }

                      if ((nOpcode == X86_INS_XOR) && opDst.bIsReg && (sFirst == sSecond)) {
                          state.aRegs[opDst.nReg] = sourceFromImmediate(0);
                          return;
                      }

                      if (nOpcode == X86_INS_PUSH) {
                          ARGSOURCE source = {};

                          if (bImmediate) {
                              source = sourceFromImmediate((quint64)(quint32)_signExtend(nImmediate, nImmSize));
                          } else if (opDst.bIsReg) {
                              source = state.aRegs[opDst.nReg];
                          } else if (opDst.bIsMem && (disasmResult.memType != XDisasmAbstract::MEMTYPE_NONE) && mapIat.contains(disasmResult.nXrefToMemory)) {
                              source.src = SRC_IMPORT;
                              source.sImport = mapIat.value(disasmResult.nXrefToMemory);
                          }

                          state.listPushes.append(source);

                          if (state.listPushes.count() > N_MAX_PUSHES) {
                              state.listPushes.removeFirst();
                          }

                          return;
                      }

                      if (opDst.bIsReg) {
                          state.aRegs[opDst.nReg] = ARGSOURCE();
                      }
                  });
    }

    // ---- data: dword tables of hashes (a single random match is likely noise, so a second one must be close by)
    if (!db.listEntries.isEmpty()) {
        qint64 nBudget = N_DATA_SCAN_MAX;

        for (qint32 i = 0; (i < listHeaders.count()) && (nBudget > 0) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            const XPE_DEF::IMAGE_SECTION_HEADER &header = listHeaders.at(i);
            QString sName = QString::fromLatin1((const char *)header.Name, qstrnlen((const char *)header.Name, XPE_DEF::S_IMAGE_SIZEOF_SHORT_NAME));
            qint64 nRawOffset = header.PointerToRawData;
            qint64 nRawSize = header.SizeOfRawData;

            if (_isExecutable(header) || (sName == ".rsrc") || (sName == ".reloc") || (sName == ".pdata") || (nRawOffset <= 0) || (nRawOffset >= nFileSize) ||
                (nRawSize <= 0)) {
                continue;
            }

            nRawSize = qMin(qMin(nRawSize, nFileSize - nRawOffset), nBudget);

            QByteArray baData = pe.read_array(nRawOffset, nRawSize);
            const quint8 *pData = (const quint8 *)baData.constData();
            qint32 nSize = baData.size();

            struct MATCH {
                qint32 nPos;
                QList<DBENTRY> listEntries;
            };

            QList<MATCH> listMatches;

            for (qint32 j = 0; j + 4 <= nSize; j += 4) {
                quint32 nValue = (quint32)_readLE(pData + j, 4);

                if ((nValue < 0x10000) || (nValue >= 0xFFFF0000) || ((nValue >= nImageBase) && (nValue < nImageBase + nSizeOfImage))) {
                    continue;
                }

                QList<DBENTRY> listEntries = _lookup(db, nValue);

                if (!listEntries.isEmpty()) {
                    MATCH match = {};
                    match.nPos = j;
                    match.listEntries = listEntries;
                    listMatches.append(match);
                }
            }

            for (qint32 j = 0; j < listMatches.count(); j++) {
                bool bNear = ((j > 0) && (listMatches.at(j).nPos - listMatches.at(j - 1).nPos <= N_DATA_CLUSTER)) ||
                             ((j + 1 < listMatches.count()) && (listMatches.at(j + 1).nPos - listMatches.at(j).nPos <= N_DATA_CLUSTER));

                if (bNear) {
                    qint64 nOffset = nRawOffset + listMatches.at(j).nPos;
                    _addHits(&listHits, db, listMatches.at(j).listEntries, nOffset, XBinary::offsetToAddress(&memoryMap, nOffset));
                }
            }

            nBudget -= nSize;
        }
    }

    file.close();

    std::stable_sort(listHits.begin(), listHits.end(), [](const HIT &hit1, const HIT &hit2) { return hit1.nOffset < hit2.nOffset; });

    result.listHits = listHits;
    result.listCallSites = listCallSites;

    return result;
}
