// DiE Helper (fork addition): static OEP finder - bounded disassembly walk of the unpacking stub from the entry point plus
// tail-transfer rules (pushad/popad + jmp, push/ret, mov reg/jmp reg, jmp [mem], raw packer tails). Nothing is executed or emulated.
// STATUS: done, not compiled yet (not in helper.cmake)
#include "helperoepfinder.h"

#include <QFile>
#include <QHash>
#include <QSet>

#include <algorithm>
#include <cstring>

#include "xdisasmcore.h"
#include "xpe.h"

static const qint32 N_MAX_INSTRUCTIONS = 20000;
static const qint32 N_MAX_QUEUE = 4096;
static const qint32 N_MAX_TRACE = 200;
static const qint32 N_MAX_CANDIDATES = 32;
static const qint64 N_STUB_READ_MAX = 32 * 1024 * 1024;
static const qint32 N_PAD = 16;          // zero bytes after the stub buffer, Capstone may look ahead
static const qint32 N_DECODE_SIZE = 16;  // longest x86 instruction is 15 bytes
static const qint32 N_TAIL_WINDOW = 12;  // max instructions between popad / pop run and the transfer
static const qint32 N_CONFIDENT = 50;    // below this the EP of a clean-looking file wins
static const quint32 N_SCN_CNT_CODE = 0x00000020;

static const QString S_RULE_FAR_JUMP = "far jump out of stub";
static const QString S_RULE_LAST_FAR_JUMP = "last far jump out of stub";

namespace {

struct _SECTION {
    qint32 nIndex;
    QString sName;
    qint64 nRVA;
    qint64 nSpan;            // mapped size: virtual size rounded up to SectionAlignment
    qint64 nRawOffset;
    qint64 nFileBackedSize;  // leading part of nSpan that comes from the file
    bool bExecute;           // MEM_EXECUTE or CNT_CODE
    bool bWrite;
};

struct _REG {
    bool bValid;
    XADDR nValue;
    XADDR nSite;
};

// State of one walk path. Copied on every branch; only an approximation (the visited set merges paths).
struct _PATH {
    XADDR nAddress;
    qint32 nIndex;  // instructions walked on this path so far
    qint32 nPushadIndex;
    XADDR nPushadAddress;
    qint32 nPopadIndex;
    XADDR nPopadAddress;
    qint32 nPushRun;  // consecutive register pushes
    qint32 nMaxPushRun;
    XADDR nPushRunAddress;
    XADDR nMaxPushRunAddress;
    qint32 nPopRun;  // consecutive pops
    XADDR nPopRunAddress;
    qint32 nLastPopRunIndex;  // index of the last pop of the last run of >= 2 pops
    qint32 nLastPopRunCount;
    XADDR nLastPopRunAddress;
    qint32 nPushImmIndex;  // push imm32 / push tracked register
    XADDR nPushImmValue;
    XADDR nPushImmSite;
    qint32 nPushImmOffset;  // imm offset inside the push instruction (0 for push reg)
    QString sPushImmFrom;   // register name for "push reg", empty for push imm
    XADDR nPushImmFromSite;
    _REG regs[16];
};

enum TARGET {
    TARGET_INVALID = 0,
    TARGET_STUB,       // file-backed part of the stub region: keep walking
    TARGET_STUB_TAIL,  // not-file-backed tail of the stub section
    TARGET_SECTION,    // another section
    TARGET_HEADERS
};

struct _TARGETINFO {
    TARGET target;
    qint64 nRVA;
    qint32 nSection;  // index into listSections, -1 if none
    bool bVirtualOnly;
    bool bFirstCode;
    bool bBelowStub;
    bool bExecute;
};

enum KIND {
    KIND_JMP_REL = 0,
    KIND_JCC,
    KIND_JMP_REG,
    KIND_JMP_MEM,
    KIND_PUSH_RET
};

struct HELPEROEPFINDER_CONTEXT {
    XPE *pPE;
    HelperOepFinder::RESULT *pResult;
    bool bIs64;
    XADDR nImageBase;
    qint64 nSizeOfImage;
    qint64 nHeadersSize;
    QList<_SECTION> listSections;
    qint32 nFirstCodeSection;
    qint32 nStubSection;  // -1: PE headers (FSG style)
    QString sStubName;
    qint64 nStubRVA;
    qint64 nStubFileBackedEnd;  // RVA
    qint64 nStubEnd;            // RVA
    QByteArray baStub;          // file-backed part of the stub region + N_PAD zero bytes
    qint32 nStubSize;           // real bytes in baStub
    QSet<qint64> setImportSlots;
    qint64 nIatRVA;
    qint64 nIatSize;
    bool bPECompact;
    QList<HelperOepFinder::CANDIDATE> listRaw;  // unsorted, not deduplicated
};

}  // namespace

static QString _hex(quint64 nValue)
{
    return QString("0x%1").arg(QString::number(nValue, 16).toUpper());
}

static void _trace(HELPEROEPFINDER_CONTEXT *pContext, const QString &sLine)
{
    qint32 nCount = pContext->pResult->listTrace.count();

    if (nCount < N_MAX_TRACE - 1) {
        pContext->pResult->listTrace.append(sLine);
    } else if (nCount == N_MAX_TRACE - 1) {
        pContext->pResult->listTrace.append("... (trace truncated)");
    }
}

static XADDR _mask(const HELPEROEPFINDER_CONTEXT *pContext, XADDR nValue)
{
    return pContext->bIs64 ? nValue : (nValue & 0xFFFFFFFF);
}

static quint64 _readLE(const char *pData, qint32 nSize)
{
    quint64 nResult = 0;

    for (qint32 i = nSize - 1; i >= 0; i--) {
        nResult = (nResult << 8) | (quint8)pData[i];
    }

    return nResult;
}

static quint64 _signExtend(quint64 nValue, qint32 nSize)
{
    if ((nSize > 0) && (nSize < 8)) {
        quint64 nSign = 1ULL << (nSize * 8 - 1);

        if (nValue & nSign) {
            nValue |= ~((nSign << 1) - 1);
        }
    }

    return nValue;
}

static qint64 _alignUp(qint64 nValue, qint64 nAlignment)
{
    if (nAlignment > 1) {
        nValue = ((nValue + nAlignment - 1) / nAlignment) * nAlignment;
    }

    return nValue;
}

static QString _getSectionName(const XPE_DEF::IMAGE_SECTION_HEADER &header)
{
    qint32 nLength = 0;

    while ((nLength < XPE_DEF::S_IMAGE_SIZEOF_SHORT_NAME) && (header.Name[nLength] != 0)) {
        nLength++;
    }

    return QString::fromLatin1((const char *)header.Name, nLength);
}

static QString _sectionLabel(const _SECTION &section)
{
    return section.sName.isEmpty() ? QString("#%1").arg(section.nIndex) : section.sName;
}

// 0..15 for general purpose registers (any width), -1 otherwise
static qint32 _regIndex(const QString &sRegister)
{
    // magic static: thread-safe initialization (the finder runs on worker threads)
    static const QHash<QString, qint32> mapRegisters = []() {
        static const char *pszLegacy[8] = {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di"};
        static const char *pszLow[8] = {"al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil"};
        static const char *pszHigh[4] = {"ah", "ch", "dh", "bh"};
        QHash<QString, qint32> mapTemp;

        for (qint32 i = 0; i < 8; i++) {
            QString sBase = QString::fromLatin1(pszLegacy[i]);
            mapTemp.insert(sBase, i);
            mapTemp.insert("e" + sBase, i);
            mapTemp.insert("r" + sBase, i);
            mapTemp.insert(QString::fromLatin1(pszLow[i]), i);
        }

        for (qint32 i = 0; i < 4; i++) {
            mapTemp.insert(QString::fromLatin1(pszHigh[i]), i);
        }

        for (qint32 i = 8; i < 16; i++) {
            QString sBase = QString("r%1").arg(i);
            mapTemp.insert(sBase, i);
            mapTemp.insert(sBase + "d", i);
            mapTemp.insert(sBase + "w", i);
            mapTemp.insert(sBase + "b", i);
        }

        return mapTemp;
    }();

    return mapRegisters.value(sRegister, -1);
}

static bool _is64BitRegisterName(const QString &sRegister)
{
    return sRegister.startsWith(QChar('r')) && !sRegister.endsWith(QChar('d')) && !sRegister.endsWith(QChar('w')) && !sRegister.endsWith(QChar('b')) &&
           (_regIndex(sRegister) >= 0);
}

static QString _operand(const QString &sOperands, qint32 nIndex)
{
    return sOperands.section(QChar(','), nIndex, nIndex).trimmed();
}

static void _invalidateRegisters(_PATH *pPath)
{
    for (qint32 i = 0; i < 16; i++) {
        pPath->regs[i].bValid = false;
    }
}

static void _resetPath(_PATH *pPath, XADDR nAddress)
{
    pPath->nAddress = nAddress;
    pPath->nIndex = 0;
    pPath->nPushadIndex = -1;
    pPath->nPushadAddress = 0;
    pPath->nPopadIndex = -1;
    pPath->nPopadAddress = 0;
    pPath->nPushRun = 0;
    pPath->nMaxPushRun = 0;
    pPath->nPushRunAddress = 0;
    pPath->nMaxPushRunAddress = 0;
    pPath->nPopRun = 0;
    pPath->nPopRunAddress = 0;
    pPath->nLastPopRunIndex = -1;
    pPath->nLastPopRunCount = 0;
    pPath->nLastPopRunAddress = 0;
    pPath->nPushImmIndex = -10;
    pPath->nPushImmValue = 0;
    pPath->nPushImmSite = 0;
    pPath->nPushImmOffset = 0;
    pPath->sPushImmFrom.clear();
    pPath->nPushImmFromSite = 0;
    _invalidateRegisters(pPath);
}

static qint64 _rvaToOffset(const HELPEROEPFINDER_CONTEXT *pContext, qint64 nRVA)
{
    if (nRVA < 0) {
        return -1;
    }

    for (qint32 i = 0; i < pContext->listSections.count(); i++) {
        const _SECTION &section = pContext->listSections.at(i);

        if ((nRVA >= section.nRVA) && (nRVA < section.nRVA + section.nFileBackedSize)) {
            return section.nRawOffset + (nRVA - section.nRVA);
        }
    }

    if (nRVA < pContext->nHeadersSize) {
        return nRVA;
    }

    return -1;
}

static _TARGETINFO _classify(const HELPEROEPFINDER_CONTEXT *pContext, XADDR nAddress)
{
    _TARGETINFO info = {};
    info.target = TARGET_INVALID;
    info.nRVA = -1;
    info.nSection = -1;

    if (nAddress < pContext->nImageBase) {
        return info;
    }

    quint64 nDelta = nAddress - pContext->nImageBase;

    if (nDelta >= (quint64)pContext->nSizeOfImage) {
        return info;
    }

    qint64 nRVA = (qint64)nDelta;
    info.nRVA = nRVA;
    info.bBelowStub = (nRVA < pContext->nStubRVA);

    if ((nRVA >= pContext->nStubRVA) && (nRVA < pContext->nStubFileBackedEnd)) {
        info.target = TARGET_STUB;
        info.nSection = pContext->nStubSection;
    } else if ((nRVA >= pContext->nStubFileBackedEnd) && (nRVA < pContext->nStubEnd)) {
        info.target = TARGET_STUB_TAIL;
        info.nSection = pContext->nStubSection;
    } else {
        for (qint32 i = 0; i < pContext->listSections.count(); i++) {
            const _SECTION &section = pContext->listSections.at(i);

            if ((nRVA >= section.nRVA) && (nRVA < section.nRVA + section.nSpan)) {
                info.target = TARGET_SECTION;
                info.nSection = i;
                break;
            }
        }

        if ((info.target == TARGET_INVALID) && (nRVA < pContext->nHeadersSize)) {
            info.target = TARGET_HEADERS;
        }
    }

    if (info.nSection != -1) {
        const _SECTION &section = pContext->listSections.at(info.nSection);
        info.bVirtualOnly = (section.nFileBackedSize == 0);
        info.bFirstCode = (info.nSection == pContext->nFirstCodeSection);
        info.bExecute = section.bExecute;
    }

    return info;
}

static QString _targetSectionName(const HELPEROEPFINDER_CONTEXT *pContext, const _TARGETINFO &info)
{
    QString sResult;

    if (info.nSection != -1) {
        sResult = _sectionLabel(pContext->listSections.at(info.nSection));
    } else if ((info.target == TARGET_HEADERS) || ((info.target == TARGET_STUB) && (pContext->nStubSection == -1))) {
        sResult = "Headers";
    }

    return sResult;
}

static QString _targetText(const HELPEROEPFINDER_CONTEXT *pContext, const _TARGETINFO &info)
{
    if (info.target == TARGET_INVALID) {
        return "outside the image";
    }

    QStringList listParts;
    listParts.append(QString("RVA %1").arg(_hex((quint64)info.nRVA)));

    if (info.target == TARGET_HEADERS) {
        listParts.append("PE headers");
    } else if (info.target == TARGET_STUB_TAIL) {
        listParts.append(QString("not-file-backed tail of stub section %1").arg(pContext->sStubName));
    } else if (info.target == TARGET_STUB) {
        listParts.append(QString("stub region %1").arg(pContext->sStubName));
    } else if (info.nSection != -1) {
        listParts.append(QString("section %1").arg(_targetSectionName(pContext, info)));

        if (info.bVirtualOnly) {
            listParts.append("virtual-only");
        }

        if (info.bFirstCode) {
            listParts.append("first code section");
        }

        if (!info.bExecute) {
            listParts.append("not executable");
        }
    }

    if (info.bBelowStub && (info.target != TARGET_HEADERS)) {
        listParts.append("below the stub section");
    }

    return listParts.join(", ");
}

static const char *_stubPointer(const HELPEROEPFINDER_CONTEXT *pContext, XADDR nAddress, qint32 *pnAvailable)
{
    *pnAvailable = 0;

    if (nAddress < pContext->nImageBase) {
        return nullptr;
    }

    quint64 nDelta = nAddress - pContext->nImageBase;

    if ((nDelta < (quint64)pContext->nStubRVA) || (nDelta >= (quint64)pContext->nStubFileBackedEnd)) {
        return nullptr;
    }

    qint32 nPosition = (qint32)(nDelta - (quint64)pContext->nStubRVA);
    *pnAvailable = pContext->nStubSize - nPosition;

    return pContext->baStub.constData() + nPosition;
}

// true if the bytes just before nAddress equal baPattern
static bool _bytesBefore(const HELPEROEPFINDER_CONTEXT *pContext, XADDR nAddress, const QByteArray &baPattern)
{
    qint32 nLength = baPattern.size();

    if (nAddress < (XADDR)nLength) {
        return false;
    }

    qint32 nAvailable = 0;
    const char *pData = _stubPointer(pContext, nAddress - nLength, &nAvailable);

    return pData && (nAvailable >= nLength) && (memcmp(pData, baPattern.constData(), nLength) == 0);
}

static const QByteArray &_upx32Tail()
{
    // popad; lea eax,[esp-0x80]; push 0; cmp esp,eax; jne $-4; sub esp,-0x80   (followed by E9 rel32)
    static const QByteArray baResult = QByteArray::fromHex("618D4424806A0039C475FA83EC80");
    return baResult;
}

static const QByteArray &_upx64Tail()
{
    // lea rax,[rsp-0x80]; push 0; cmp rsp,rax; jne $-5; sub rsp,-0x80   (followed by E9 rel32)
    static const QByteArray baResult = QByteArray::fromHex("488D4424806A004839C475F94883EC80");
    return baResult;
}

static const QByteArray &_upx64DllRestore()
{
    // DLL stubs reload the DllMain arguments: mov r8,[rsp+0x18]; mov rdx,[rsp+0x10]; mov rcx,[rsp+8]
    static const QByteArray baResult = QByteArray::fromHex("4C8B442418488B542410488B4C2408");
    return baResult;
}

static const QByteArray &_nsPackTail()
{
    // popad; popfd   (followed by E9 rel32)
    static const QByteArray baResult = QByteArray::fromHex("619D");
    return baResult;
}

static const QByteArray &_asPackTail()
{
    // popad; jnz +8; mov eax,1; retn 0x0C   (followed by push imm32; ret)
    static const QByteArray baResult = QByteArray::fromHex("617508B801000000C20C00");
    return baResult;
}

static HelperOepFinder::CANDIDATE _makeCandidate(const HELPEROEPFINDER_CONTEXT *pContext, XADDR nAddress, XADDR nJumpSite, const QString &sRule, qint32 nConfidence,
                                                 const QString &sDetails)
{
    HelperOepFinder::CANDIDATE candidate = {};
    _TARGETINFO info = _classify(pContext, nAddress);

    candidate.nAddress = nAddress;
    candidate.nRVA = (nAddress >= pContext->nImageBase) ? (qint64)(nAddress - pContext->nImageBase) : -1;
    candidate.nOffset = _rvaToOffset(pContext, info.nRVA);
    candidate.sSection = _targetSectionName(pContext, info);
    candidate.sRule = sRule;
    candidate.sDetails = sDetails;
    candidate.nJumpSiteAddress = nJumpSite;
    candidate.nConfidence = qBound(0, nConfidence, 100);

    return candidate;
}

// OEP candidate (target of a transfer): confidence adjusted by where the target lands
static void _addCandidate(HELPEROEPFINDER_CONTEXT *pContext, XADDR nAddress, XADDR nJumpSite, const QString &sRule, qint32 nConfidence, const QString &sDetails)
{
    _TARGETINFO info = _classify(pContext, nAddress);

    if ((info.target == TARGET_INVALID) || (info.target == TARGET_STUB)) {
        return;
    }

    if (info.target == TARGET_HEADERS) {
        nConfidence -= 20;
    } else if (info.target == TARGET_SECTION) {
        if (info.bVirtualOnly && (sRule != "jump into virtual-only section")) {
            nConfidence += 5;
        }

        if (info.bFirstCode) {
            nConfidence += 5;
        }

        if (!info.bExecute && !info.bVirtualOnly) {
            nConfidence -= 15;
        }
    }

    if (info.bBelowStub && (info.target != TARGET_HEADERS)) {
        nConfidence += 3;
    }

    pContext->listRaw.append(_makeCandidate(pContext, nAddress, nJumpSite, sRule, nConfidence, sDetails));
}

// The stub writes the real OEP into this slot at run time: the address is the slot, not the OEP
static void _addSlotCandidate(HELPEROEPFINDER_CONTEXT *pContext, XADDR nSlot, XADDR nJumpSite, const QString &sRule, qint32 nConfidence, const QString &sDetails)
{
    pContext->listRaw.append(_makeCandidate(pContext, nSlot, nJumpSite, sRule, nConfidence, sDetails));
}

static QString _pathContext(const _PATH &path, bool bPopad, bool bPopMany)
{
    QString sResult;

    if (path.nPushadIndex >= 0) {
        sResult += QString("; pushad at %1").arg(_hex(path.nPushadAddress));
    }

    if (bPopad) {
        sResult += QString("; popad at %1 (%2 instruction(s) before the transfer)").arg(_hex(path.nPopadAddress)).arg(path.nIndex - path.nPopadIndex);
    }

    if (bPopMany) {
        qint32 nPops = (path.nPopRun >= 2) ? path.nPopRun : path.nLastPopRunCount;
        XADDR nPopAddress = (path.nPopRun >= 2) ? path.nPopRunAddress : path.nLastPopRunAddress;
        sResult += QString("; %1 register pushes at %2, %3 pops at %4").arg(path.nMaxPushRun).arg(_hex(path.nMaxPushRunAddress)).arg(nPops).arg(_hex(nPopAddress));
    }

    return sResult;
}

static void _onTransferOut(HELPEROEPFINDER_CONTEXT *pContext, const _PATH &path, KIND kind, XADDR nSite, const QString &sInstruction, XADDR nTarget, const QString &sExtra)
{
    _TARGETINFO info = _classify(pContext, nTarget);
    bool bPopad = (path.nPopadIndex >= 0) && (path.nIndex - path.nPopadIndex <= N_TAIL_WINDOW);
    bool bPopMany = !bPopad && (path.nMaxPushRun >= 2) &&
                    ((path.nPopRun >= 2) || ((path.nLastPopRunIndex >= 0) && (path.nIndex - path.nLastPopRunIndex <= N_TAIL_WINDOW)));

    QString sDetails = QString("%1 at %2 -> %3 (%4)%5%6").arg(sInstruction, _hex(nSite), _hex(nTarget), _targetText(pContext, info), sExtra, _pathContext(path, bPopad, bPopMany));

    QString sRule;
    qint32 nConfidence = 0;

    if (kind == KIND_JMP_REL) {
        if (!pContext->bIs64 && _bytesBefore(pContext, nSite, _upx32Tail())) {
            sRule = "UPX tail";
            nConfidence = 95;
            sDetails += "; UPX stack-zeroing loop before the jump";
        } else if (pContext->bIs64 && (_bytesBefore(pContext, nSite, _upx64Tail()) || _bytesBefore(pContext, nSite, _upx64Tail() + _upx64DllRestore()))) {
            sRule = "UPX tail";
            nConfidence = 95;
            sDetails += "; UPX stack-zeroing loop before the jump";
        } else if (!pContext->bIs64 && _bytesBefore(pContext, nSite, _nsPackTail())) {
            sRule = "NsPack popad/popfd/jmp";
            nConfidence = 90;
        } else if (bPopad) {
            sRule = "popad; jmp far";
            nConfidence = 85;
        } else if (bPopMany) {
            sRule = "push-many/pop-many; jmp far";
            nConfidence = 75;
        } else if ((info.target == TARGET_SECTION) && info.bVirtualOnly) {
            sRule = "jump into virtual-only section";
            nConfidence = 60;
        } else if (info.target == TARGET_STUB_TAIL) {
            sRule = "jump into not-file-backed tail of the stub section";
            nConfidence = 55;
        } else {
            sRule = S_RULE_FAR_JUMP;
            nConfidence = 40;
        }
    } else if (kind == KIND_JCC) {
        sRule = "conditional jump out of stub";
        nConfidence = 25;
    } else if (kind == KIND_PUSH_RET) {
        if (!pContext->bIs64 && (path.nPushImmOffset > 0) && _bytesBefore(pContext, path.nPushImmSite, _asPackTail())) {
            sRule = "ASPack push/ret";
            nConfidence = 85;
        } else if (bPopad) {
            sRule = "popad; push imm; ret";
            nConfidence = 85;
        } else if (bPopMany) {
            sRule = "pop-many; push imm; ret";
            nConfidence = 75;
        } else {
            sRule = "push imm; ret";
            nConfidence = 75;
        }
    } else if (kind == KIND_JMP_REG) {
        bool bAccumulator = sInstruction.endsWith("eax") || sInstruction.endsWith("rax");
        sRule = (pContext->bPECompact && bAccumulator) ? "PECompact jmp eax" : "mov reg,imm; jmp reg";
        nConfidence = 70 + ((bPopad || bPopMany) ? 10 : 0);
    } else if (kind == KIND_JMP_MEM) {
        sRule = "jmp [mem]";
        nConfidence = 55 + ((bPopad || bPopMany) ? 10 : 0);
    }

    _trace(pContext, QString("Transfer out: %1 -> %2 [%3]").arg(sInstruction + " at " + _hex(nSite), _hex(nTarget), sRule));
    _addCandidate(pContext, nTarget, nSite, sRule, nConfidence, sDetails);
}

// Patterns that do not depend on the walk reaching them (the stub may be self-modifying or reached through a computed jump)
static void _scanRawTails(HELPEROEPFINDER_CONTEXT *pContext)
{
    const char *pData = pContext->baStub.constData();
    const qint32 nSize = pContext->nStubSize;
    const XADDR nBase = pContext->nImageBase + (XADDR)pContext->nStubRVA;

    struct _JMP_PATTERN {
        QByteArray baPattern;
        QString sRule;
        qint32 nConfidence;
        QString sText;
    };

    QList<_JMP_PATTERN> listPatterns;

    auto addPattern = [&listPatterns](const QByteArray &baPattern, const QString &sRule, qint32 nConfidence, const QString &sText) {
        _JMP_PATTERN pattern = {};
        pattern.baPattern = baPattern;
        pattern.sRule = sRule;
        pattern.nConfidence = nConfidence;
        pattern.sText = sText;
        listPatterns.append(pattern);
    };

    if (pContext->bIs64) {
        addPattern(_upx64Tail() + _upx64DllRestore(), "UPX tail", 90, "UPX amd64 DLL tail (stack-zeroing loop, DllMain args reloaded)");
        addPattern(_upx64Tail(), "UPX tail", 90, "UPX amd64 tail (lea rax,[rsp-0x80]; push 0; cmp rsp,rax; jne; sub rsp,-0x80)");
    } else {
        addPattern(_upx32Tail(), "UPX tail", 90, "UPX i386 tail (popad; lea eax,[esp-0x80]; push 0; cmp esp,eax; jne; sub esp,-0x80)");
        addPattern(_nsPackTail(), "NsPack popad/popfd/jmp", 60, "popad; popfd; jmp rel32");
    }

    QSet<qint32> setSites;

    for (qint32 i = 0; i < listPatterns.count(); i++) {
        const _JMP_PATTERN &pattern = listPatterns.at(i);
        qint32 nLength = pattern.baPattern.size();
        qint32 nPosition = pContext->baStub.indexOf(pattern.baPattern);

        while ((nPosition != -1) && (nPosition + nLength + 5 <= nSize)) {
            qint32 nSitePosition = nPosition + nLength;

            if (((quint8)pData[nSitePosition] == 0xE9) && !setSites.contains(nSitePosition)) {
                setSites.insert(nSitePosition);

                XADDR nSite = nBase + (XADDR)nSitePosition;
                qint64 nRel = (qint64)_signExtend(_readLE(pData + nSitePosition + 1, 4), 4);
                XADDR nTarget = _mask(pContext, nSite + 5 + (XADDR)nRel);
                _TARGETINFO info = _classify(pContext, nTarget);

                if ((info.target != TARGET_INVALID) && (info.target != TARGET_STUB)) {
                    _trace(pContext, QString("Raw pattern: %1 at %2, jmp -> %3").arg(pattern.sRule, _hex(nBase + nPosition), _hex(nTarget)));
                    _addCandidate(pContext, nTarget, nSite, pattern.sRule, pattern.nConfidence,
                                  QString("%1 at %2 (raw byte match), jmp at %3 -> %4 (%5)")
                                      .arg(pattern.sText, _hex(nBase + nPosition), _hex(nSite), _hex(nTarget), _targetText(pContext, info)));
                }
            }

            nPosition = pContext->baStub.indexOf(pattern.baPattern, nPosition + 1);
        }
    }

    // ASPack: popad; jnz +8; mov eax,1; retn 0Ch; push imm32 (0 in the file, patched at run time); ret
    if (!pContext->bIs64) {
        QByteArray baPattern = _asPackTail() + QByteArray::fromHex("68");
        qint32 nLength = baPattern.size();
        qint32 nPosition = pContext->baStub.indexOf(baPattern);

        while ((nPosition != -1) && (nPosition + nLength + 5 <= nSize)) {
            if ((quint8)pData[nPosition + nLength + 4] == 0xC3) {
                XADDR nSlot = nBase + (XADDR)(nPosition + nLength);
                XADDR nSite = nSlot + 4;
                XADDR nValue = (XADDR)_readLE(pData + nPosition + nLength, 4);
                _TARGETINFO info = _classify(pContext, nValue);

                _trace(pContext, QString("Raw pattern: ASPack push/ret at %1, imm32 = %2").arg(_hex(nBase + nPosition), _hex(nValue)));

                if ((nValue != 0) && (info.target != TARGET_INVALID) && (info.target != TARGET_STUB)) {
                    _addCandidate(pContext, nValue, nSite, "ASPack push/ret", 80,
                                  QString("ASPack tail at %1 (raw byte match): push %2; ret at %3 -> %4").arg(_hex(nBase + nPosition), _hex(nValue), _hex(nSite), _targetText(pContext, info)));
                } else {
                    _addSlotCandidate(pContext, nSlot, nSite, "ASPack push/ret slot", 20,
                                      QString("ASPack tail at %1: push imm32; ret at %2. The imm32 at VA %3 is %4 in the file; the stub writes the OEP there at run time. "
                                              "Address shown is the slot, not the OEP (read it after unpacking or set a write breakpoint on it)")
                                          .arg(_hex(nBase + nPosition), _hex(nSite), _hex(nSlot), _hex(nValue)));
                }
            }

            nPosition = pContext->baStub.indexOf(baPattern, nPosition + 1);
        }
    }
}

static void _finalize(HELPEROEPFINDER_CONTEXT *pContext, bool bLooksClean, XADDR nEntryPointAddress, qint32 nInstructions)
{
    HelperOepFinder::RESULT *pResult = pContext->pResult;
    QList<HelperOepFinder::CANDIDATE> &listRaw = pContext->listRaw;

    // generic rule: the far jump with the highest site address is the most likely tail
    qint32 nLast = -1;

    for (qint32 i = 0; i < listRaw.count(); i++) {
        if ((listRaw.at(i).sRule == S_RULE_FAR_JUMP) && ((nLast == -1) || (listRaw.at(i).nJumpSiteAddress > listRaw.at(nLast).nJumpSiteAddress))) {
            nLast = i;
        }
    }

    if (nLast != -1) {
        listRaw[nLast].sRule = S_RULE_LAST_FAR_JUMP;
        listRaw[nLast].nConfidence = qMin(listRaw.at(nLast).nConfidence + 10, 100);
    }

    // dedup by address: keep the strongest, independent rules agreeing add a small bonus
    QList<HelperOepFinder::CANDIDATE> listMerged;
    QList<QSet<QString>> listRules;

    for (qint32 i = 0; i < listRaw.count(); i++) {
        const HelperOepFinder::CANDIDATE &candidate = listRaw.at(i);
        qint32 nFound = -1;

        for (qint32 j = 0; j < listMerged.count(); j++) {
            if (listMerged.at(j).nAddress == candidate.nAddress) {
                nFound = j;
                break;
            }
        }

        if (nFound == -1) {
            listMerged.append(candidate);
            listRules.append(QSet<QString>({candidate.sRule}));
            continue;
        }

        HelperOepFinder::CANDIDATE &merged = listMerged[nFound];
        bool bNewRule = !listRules.at(nFound).contains(candidate.sRule);

        if (candidate.nConfidence > merged.nConfidence) {
            HelperOepFinder::CANDIDATE old = merged;
            merged = candidate;

            if (bNewRule || (old.nJumpSiteAddress != candidate.nJumpSiteAddress)) {
                merged.sDetails += QString("; also: %1 (site %2)").arg(old.sRule, _hex(old.nJumpSiteAddress));
            }
        } else if (bNewRule || (merged.nJumpSiteAddress != candidate.nJumpSiteAddress)) {
            merged.sDetails += QString("; also: %1 (site %2)").arg(candidate.sRule, _hex(candidate.nJumpSiteAddress));
        }

        if (bNewRule) {
            listRules[nFound].insert(candidate.sRule);
            merged.nConfidence = qMin(merged.nConfidence + 5, 100);
        }
    }

    std::stable_sort(listMerged.begin(), listMerged.end(), [](const HelperOepFinder::CANDIDATE &candidate1, const HelperOepFinder::CANDIDATE &candidate2) {
        return candidate1.nConfidence > candidate2.nConfidence;
    });

    qint32 nMaxConfidence = listMerged.isEmpty() ? 0 : listMerged.at(0).nConfidence;

    if (bLooksClean && (nMaxConfidence < N_CONFIDENT)) {
        QString sDetails = QString("EP %1 is in the first code section %2 (not writable); no confident transfer out of it in %3 walked instruction(s)")
                               .arg(_hex(nEntryPointAddress), pContext->sStubName)
                               .arg(nInstructions);

        if (!listMerged.isEmpty()) {
            sDetails += QString("; %1 weak candidate(s) dropped").arg(listMerged.count());
        }

        listMerged.clear();
        listMerged.append(_makeCandidate(pContext, nEntryPointAddress, nEntryPointAddress, "entry point is already the OEP", 10, sDetails));
        _trace(pContext, "Looks unpacked: the entry point is reported as the OEP (low confidence)");
    }

    while (listMerged.count() > N_MAX_CANDIDATES) {
        listMerged.removeLast();
    }

    pResult->listCandidates = listMerged;
}

HelperOepFinder::RESULT HelperOepFinder::find(const QString &sFileName, XBinary::PDSTRUCT *pPdStruct)
{
    RESULT result = {};
    result.bIsValid = false;

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

    HELPEROEPFINDER_CONTEXT context = {};
    context.pPE = &pe;
    context.pResult = &result;
    context.bIs64 = pe.is64();
    context.nImageBase = pe.getOptionalHeader_ImageBase();
    context.nFirstCodeSection = -1;
    context.nStubSection = -1;
    context.nIatRVA = 0;
    context.nIatSize = 0;
    context.bPECompact = false;

    const qint64 nFileSize = pe.getSize();
    const quint32 nEntryPointRVA = pe.getOptionalHeader_AddressOfEntryPoint();
    const XADDR nEntryPointAddress = context.nImageBase + nEntryPointRVA;

    // ---- .NET: an IL-only image has no native stub to walk
    if (pe.isNETPresent()) {
        quint32 nFlags = pe.getNetHeader_Flags();

        if ((nFlags & XPE_DEF::COMIMAGE_FLAGS_ILONLY) || (nEntryPointRVA == 0)) {
            _trace(&context, QString(".NET IL-only image (COR20 flags %1, managed entry token %2): the native EP is only the CLR loader thunk, there is no "
                                     "native OEP to find; use a .NET unpacker/deobfuscator instead")
                                 .arg(_hex(nFlags), _hex(pe.getNetHeader_EntryPoint())));
            file.close();
            return result;
        }

        _trace(&context, "Mixed-mode .NET image: walking the native entry point");
    }

    if (nEntryPointRVA == 0) {
        _trace(&context, "AddressOfEntryPoint is 0 (resource-only DLL): nothing to walk");
        file.close();
        return result;
    }

    // ---- layout
    qint64 nSectionAlignment = pe.getOptionalHeader_SectionAlignment();
    context.nHeadersSize = pe.getOptionalHeader_SizeOfHeaders();

    if ((context.nHeadersSize <= 0) || (context.nHeadersSize > nFileSize)) {
        context.nHeadersSize = qMin<qint64>(nFileSize, 0x1000);
    }

    QList<XPE_DEF::IMAGE_SECTION_HEADER> listHeaders = pe.getSectionHeaders(nullptr);
    qint64 nMaxEnd = context.nHeadersSize;

    for (qint32 i = 0; i < listHeaders.count(); i++) {
        const XPE_DEF::IMAGE_SECTION_HEADER &header = listHeaders.at(i);

        _SECTION section = {};
        section.nIndex = i;
        section.sName = _getSectionName(header);
        section.nRVA = header.VirtualAddress;

        qint64 nVirtualSize = header.Misc.VirtualSize ? header.Misc.VirtualSize : header.SizeOfRawData;
        section.nSpan = _alignUp(nVirtualSize, nSectionAlignment);
        section.nRawOffset = header.PointerToRawData;

        qint64 nRawSize = header.SizeOfRawData;

        if (section.nRawOffset >= nFileSize) {
            nRawSize = 0;
        } else if (section.nRawOffset + nRawSize > nFileSize) {
            nRawSize = nFileSize - section.nRawOffset;
        }

        section.nFileBackedSize = qMin(nRawSize, section.nSpan);
        section.bExecute = (header.Characteristics & XPE_DEF::S_IMAGE_SCN_MEM_EXECUTE) || (header.Characteristics & N_SCN_CNT_CODE);
        section.bWrite = (header.Characteristics & XPE_DEF::S_IMAGE_SCN_MEM_WRITE) != 0;

        if (section.bExecute && (context.nFirstCodeSection == -1)) {
            context.nFirstCodeSection = i;
        }

        nMaxEnd = qMax(nMaxEnd, section.nRVA + section.nSpan);
        context.listSections.append(section);
    }

    context.nSizeOfImage = pe.getOptionalHeader_SizeOfImage();

    if (context.nSizeOfImage <= 0) {
        context.nSizeOfImage = nMaxEnd;
    }

    // ---- stub region = section holding the EP (or the headers)
    for (qint32 i = 0; i < context.listSections.count(); i++) {
        const _SECTION &section = context.listSections.at(i);

        if (((qint64)nEntryPointRVA >= section.nRVA) && ((qint64)nEntryPointRVA < section.nRVA + section.nSpan)) {
            context.nStubSection = i;
            break;
        }
    }

    qint64 nStubRawOffset = 0;
    qint64 nStubFileBacked = 0;

    if (context.nStubSection != -1) {
        const _SECTION &section = context.listSections.at(context.nStubSection);
        context.sStubName = _sectionLabel(section);
        context.nStubRVA = section.nRVA;
        context.nStubEnd = section.nRVA + section.nSpan;
        nStubRawOffset = section.nRawOffset;
        nStubFileBacked = section.nFileBackedSize;
    } else if ((qint64)nEntryPointRVA < context.nHeadersSize) {
        context.sStubName = "Headers";
        context.nStubRVA = 0;
        context.nStubEnd = context.listSections.isEmpty() ? _alignUp(context.nHeadersSize, nSectionAlignment) : context.listSections.at(0).nRVA;
        context.nStubEnd = qMax(context.nStubEnd, context.nHeadersSize);
        nStubRawOffset = 0;
        nStubFileBacked = context.nHeadersSize;
    } else {
        _trace(&context, QString("EP RVA %1 is outside every section and the headers: nothing to walk").arg(_hex(nEntryPointRVA)));
        file.close();
        return result;
    }

    if (nStubFileBacked > N_STUB_READ_MAX) {
        _trace(&context, QString("Stub section is larger than %1 bytes: only its start is walked").arg(N_STUB_READ_MAX));
        nStubFileBacked = N_STUB_READ_MAX;
    }

    context.baStub = pe.read_array(nStubRawOffset, nStubFileBacked);
    context.nStubSize = context.baStub.size();
    context.nStubFileBackedEnd = context.nStubRVA + context.nStubSize;
    context.baStub.append(QByteArray(N_PAD, 0));

    // ---- imports: jmp [slot] through the IAT is an API thunk, not a tail
    {
        XBinary::_MEMORY_MAP memoryMap = pe.getMemoryMap();
        QList<XPE::IMPORT_HEADER> listImports = pe.getImports(&memoryMap, pPdStruct);

        for (qint32 i = 0; i < listImports.count(); i++) {
            for (qint32 j = 0; j < listImports.at(i).listPositions.count(); j++) {
                context.setImportSlots.insert(listImports.at(i).listPositions.at(j).nThunkRVA);
            }
        }

        XPE_DEF::IMAGE_DATA_DIRECTORY iat = pe.getOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_IAT);
        context.nIatRVA = iat.VirtualAddress;
        context.nIatSize = iat.Size;
    }

    _trace(&context, QString("EP VA %1 (RVA %2), %3, stub region %4: RVA %5..%6, file-backed up to %7")
                         .arg(_hex(nEntryPointAddress), _hex(nEntryPointRVA), context.bIs64 ? QString("x64") : QString("x86"), context.sStubName,
                              _hex((quint64)context.nStubRVA), _hex((quint64)context.nStubEnd), _hex((quint64)context.nStubFileBackedEnd)));

    if (context.nFirstCodeSection != -1) {
        _trace(&context, QString("First code section: %1").arg(_sectionLabel(context.listSections.at(context.nFirstCodeSection))));
    }

    if ((qint64)nEntryPointRVA >= context.nStubFileBackedEnd) {
        _trace(&context, "The EP is not file-backed (code is written there at run time): nothing to walk statically");
        file.close();
        return result;
    }

    // PECompact 2: mov eax, handler; push eax; push dword fs:[0] - the loader continues in the SEH handler
    XADDR nExtraRoot = 0;
    {
        qint32 nAvailable = 0;
        const quint8 *pEntry = (const quint8 *)_stubPointer(&context, nEntryPointAddress, &nAvailable);

        if (!context.bIs64 && pEntry && (nAvailable >= 13) && (pEntry[0] == 0xB8) && (pEntry[5] == 0x50) &&
            (memcmp(pEntry + 6, QByteArray::fromHex("64FF3500000000").constData(), 7) == 0)) {
            context.bPECompact = true;
            nExtraRoot = (XADDR)_readLE((const char *)pEntry + 1, 4);
            _trace(&context, QString("PECompact 2 style SEH entry: the loader continues in the handler at %1 (walked as a second root)").arg(_hex(nExtraRoot)));
        }
    }

    // ---- walk
    XDisasmCore disasmCore;
    disasmCore.setMode(context.bIs64 ? XBinary::DM_X86_64 : XBinary::DM_X86_32);

    XDisasmAbstract::DISASM_OPTIONS disasmOptions = {};
    disasmOptions.bIsUppercase = false;
    disasmOptions.bNoStrings = true;

    char *pStubData = context.baStub.data();
    QSet<XADDR> setVisited;
    QSet<XADDR> setTraced;
    QList<_PATH> listQueue;
    qint32 nInstructions = 0;
    qint32 nPaths = 0;
    bool bQueueFull = false;

    {
        _PATH path;
        _resetPath(&path, nEntryPointAddress);
        listQueue.append(path);

        if (nExtraRoot && (_classify(&context, nExtraRoot).target == TARGET_STUB)) {
            _PATH pathExtra;
            _resetPath(&pathExtra, nExtraRoot);
            listQueue.append(pathExtra);
        }
    }

    auto enqueue = [&](const _PATH &pathFrom, XADDR nAddress) {
        if (setVisited.contains(nAddress)) {
            return;
        }

        if (listQueue.count() >= N_MAX_QUEUE) {
            if (!bQueueFull) {
                bQueueFull = true;
                _trace(&context, QString("Walk queue limit (%1) reached, some branches are skipped").arg(N_MAX_QUEUE));
            }

            return;
        }

        _PATH pathNew = pathFrom;
        pathNew.nAddress = nAddress;
        listQueue.append(pathNew);
    };

    const qint32 nVolatile64[] = {0, 1, 2, 8, 9, 10, 11};
    const qint32 nVolatile32[] = {0, 1, 2};

    while (!listQueue.isEmpty() && (nInstructions < N_MAX_INSTRUCTIONS) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        _PATH path = listQueue.takeLast();
        nPaths++;

        while ((nInstructions < N_MAX_INSTRUCTIONS) && !setVisited.contains(path.nAddress)) {
            XADDR nAddress = path.nAddress;
            qint32 nAvailable = 0;
            const char *pInsn = _stubPointer(&context, nAddress, &nAvailable);

            if (!pInsn) {
                _TARGETINFO info = _classify(&context, nAddress);
                _trace(&context, QString("Fall-through leaves the file-backed stub at %1 (%2)").arg(_hex(nAddress), _targetText(&context, info)));
                break;
            }

            setVisited.insert(nAddress);
            nInstructions++;

            qint32 nDecodeSize = qMin(nAvailable + N_PAD, N_DECODE_SIZE);
            XDisasmAbstract::DISASM_RESULT disasmResult = disasmCore.disAsm(pStubData + (pInsn - context.baStub.constData()), nDecodeSize, nAddress, disasmOptions);

            if (!disasmResult.bIsValid || (disasmResult.nSize <= 0) || (disasmResult.nSize > nAvailable)) {
                _trace(&context, QString("Undecodable or truncated instruction at %1, path ends").arg(_hex(nAddress)));
                break;
            }

            const qint32 nCurrent = path.nIndex;
            const quint32 nOpcode = disasmResult.nOpcode;
            const XADDR nNext = _mask(&context, nAddress + disasmResult.nSize);
            const QString sInstruction = disasmResult.sOperands.isEmpty() ? disasmResult.sMnemonic : (disasmResult.sMnemonic + " " + disasmResult.sOperands);
            const QString sOperand1 = _operand(disasmResult.sOperands, 0);
            const qint32 nRegister1 = _regIndex(sOperand1);
            const bool bMemoryOperand = disasmResult.sOperands.contains(QChar('['));
            bool bEndPath = false;
            XADDR nContinue = nNext;

            // ---- push / pop runs (x64 stubs save registers one by one)
            bool bRegisterPush = ((nOpcode == X86_INS_PUSH) && (nRegister1 >= 0)) || (nOpcode == X86_INS_PUSHFD) || (nOpcode == X86_INS_PUSHFQ);
            bool bPop = (nOpcode == X86_INS_POP) || (nOpcode == X86_INS_POPFD) || (nOpcode == X86_INS_POPFQ);

            if (bRegisterPush) {
                if (path.nPushRun == 0) {
                    path.nPushRunAddress = nAddress;
                }

                path.nPushRun++;

                if (path.nPushRun > path.nMaxPushRun) {
                    path.nMaxPushRun = path.nPushRun;
                    path.nMaxPushRunAddress = path.nPushRunAddress;
                }
            } else {
                path.nPushRun = 0;
            }

            if (bPop) {
                if (path.nPopRun == 0) {
                    path.nPopRunAddress = nAddress;
                }

                path.nPopRun++;
            } else {
                if (path.nPopRun >= 2) {
                    path.nLastPopRunIndex = nCurrent - 1;
                    path.nLastPopRunCount = path.nPopRun;
                    path.nLastPopRunAddress = path.nPopRunAddress;
                }

                path.nPopRun = 0;
            }

            // ---- register tracking and stub markers
            if ((nOpcode == X86_INS_PUSHAL) || (nOpcode == X86_INS_PUSHAW)) {
                path.nPushadIndex = nCurrent;
                path.nPushadAddress = nAddress;

                if (!setTraced.contains(nAddress)) {
                    setTraced.insert(nAddress);
                    _trace(&context, QString("pushad at %1").arg(_hex(nAddress)));
                }
            } else if ((nOpcode == X86_INS_POPAL) || (nOpcode == X86_INS_POPAW)) {
                path.nPopadIndex = nCurrent;
                path.nPopadAddress = nAddress;
                _invalidateRegisters(&path);

                if (!setTraced.contains(nAddress)) {
                    setTraced.insert(nAddress);
                    _trace(&context, QString("popad at %1").arg(_hex(nAddress)));
                }
            } else if (nOpcode == X86_INS_PUSH) {
                if ((disasmResult.nImmSize > 0) && !bMemoryOperand && (nRegister1 < 0)) {
                    quint64 nValue = _readLE(pInsn + disasmResult.nImmOffset, (qint32)qMin<quint32>(disasmResult.nImmSize, 8));
                    path.nPushImmIndex = nCurrent;
                    path.nPushImmValue = _mask(&context, _signExtend(nValue, (qint32)disasmResult.nImmSize));
                    path.nPushImmSite = nAddress;
                    path.nPushImmOffset = (qint32)disasmResult.nImmOffset;
                    path.sPushImmFrom.clear();
                } else if ((nRegister1 >= 0) && path.regs[nRegister1].bValid) {
                    path.nPushImmIndex = nCurrent;
                    path.nPushImmValue = path.regs[nRegister1].nValue;
                    path.nPushImmSite = nAddress;
                    path.nPushImmOffset = 0;
                    path.sPushImmFrom = sOperand1;
                    path.nPushImmFromSite = path.regs[nRegister1].nSite;
                }
            } else if (((nOpcode == X86_INS_MOV) || (nOpcode == X86_INS_MOVABS)) && (nRegister1 >= 0) && (disasmResult.nImmSize > 0) && !bMemoryOperand) {
                qint32 nImmSize = (qint32)qMin<quint32>(disasmResult.nImmSize, 8);
                quint64 nValue = _readLE(pInsn + disasmResult.nImmOffset, nImmSize);

                if ((nImmSize < 8) && context.bIs64 && _is64BitRegisterName(sOperand1)) {
                    nValue = _signExtend(nValue, nImmSize);  // mov r64, imm32 (C7 /0)
                }

                path.regs[nRegister1].bValid = true;
                path.regs[nRegister1].nValue = _mask(&context, nValue);
                path.regs[nRegister1].nSite = nAddress;
            } else if ((nOpcode == X86_INS_LEA) && (nRegister1 >= 0) && (disasmResult.memType != XDisasmAbstract::MEMTYPE_NONE)) {
                path.regs[nRegister1].bValid = true;  // lea reg, [abs] / [rip+disp]
                path.regs[nRegister1].nValue = _mask(&context, disasmResult.nXrefToMemory);
                path.regs[nRegister1].nSite = nAddress;
            } else if ((nRegister1 >= 0) && (nOpcode != X86_INS_CMP) && (nOpcode != X86_INS_TEST) && (nOpcode != X86_INS_BT) && (nOpcode != X86_INS_JMP) &&
                       (nOpcode != X86_INS_CALL)) {
                path.regs[nRegister1].bValid = false;  // any other write to the first operand (pop included)
            }

            if (nOpcode == X86_INS_XCHG) {
                qint32 nRegister2 = _regIndex(_operand(disasmResult.sOperands, 1));

                if (nRegister2 >= 0) {
                    path.regs[nRegister2].bValid = false;
                }
            }

            // ---- control flow
            if ((nOpcode == X86_INS_RET) || (nOpcode == X86_INS_RETF)) {
                if ((nOpcode == X86_INS_RET) && (path.nPushImmIndex == nCurrent - 1)) {
                    XADDR nTarget = path.nPushImmValue;
                    _TARGETINFO info = _classify(&context, nTarget);
                    QString sPush = path.sPushImmFrom.isEmpty() ? QString("push %1").arg(_hex(nTarget))
                                                                 : QString("push %1 (= %2 set at %3)").arg(path.sPushImmFrom, _hex(nTarget), _hex(path.nPushImmFromSite));

                    if (info.target == TARGET_STUB) {
                        nContinue = nTarget;  // push/ret used as an obfuscated jmp inside the stub
                    } else if ((nTarget != 0) && (info.target != TARGET_INVALID)) {
                        path.nIndex = nCurrent;
                        _onTransferOut(&context, path, KIND_PUSH_RET, nAddress, QString("%1 at %2; ret").arg(sPush, _hex(path.nPushImmSite)), nTarget, QString());
                        bEndPath = true;
                    } else {
                        if (path.nPushImmOffset > 0) {
                            XADDR nSlot = path.nPushImmSite + (XADDR)path.nPushImmOffset;
                            bool bASPack = !context.bIs64 && _bytesBefore(&context, path.nPushImmSite, _asPackTail());
                            QString sRule = bASPack ? QString("ASPack push/ret slot") : QString("push imm; ret (patched at runtime)");

                            _trace(&context, QString("push %1; ret at %2: imm is not a valid address, slot at %3 [%4]").arg(_hex(nTarget), _hex(nAddress), _hex(nSlot), sRule));
                            _addSlotCandidate(&context, nSlot, nAddress, sRule, bASPack ? 20 : 10,
                                              QString("push %1 at %2; ret at %3: the imm32 at VA %4 is not a valid address in the file, so the stub writes the OEP "
                                                      "there at run time. Address shown is the slot, not the OEP")
                                                  .arg(_hex(nTarget), _hex(path.nPushImmSite), _hex(nAddress), _hex(nSlot)));
                        }

                        bEndPath = true;
                    }
                } else {
                    bEndPath = true;  // ordinary return of a stub routine
                }
            } else if ((nOpcode == X86_INS_JMP) || (nOpcode == X86_INS_LJMP)) {
                if (disasmResult.relType != XDisasmAbstract::RELTYPE_NONE) {
                    XADDR nTarget = _mask(&context, disasmResult.nXrefToRelative);
                    _TARGETINFO info = _classify(&context, nTarget);

                    if (info.target == TARGET_STUB) {
                        nContinue = nTarget;
                    } else {
                        if (info.target != TARGET_INVALID) {
                            path.nIndex = nCurrent;
                            _onTransferOut(&context, path, KIND_JMP_REL, nAddress, sInstruction, nTarget, QString());
                        } else {
                            _trace(&context, QString("%1 at %2 jumps outside the image").arg(sInstruction, _hex(nAddress)));
                        }

                        bEndPath = true;
                    }
                } else if (bMemoryOperand) {
                    if (disasmResult.memType != XDisasmAbstract::MEMTYPE_NONE) {
                        XADDR nSlot = _mask(&context, disasmResult.nXrefToMemory);
                        qint64 nSlotRVA = (nSlot >= context.nImageBase) ? (qint64)(nSlot - context.nImageBase) : -1;
                        bool bImport = context.setImportSlots.contains(nSlotRVA) ||
                                       ((context.nIatSize > 0) && (nSlotRVA >= context.nIatRVA) && (nSlotRVA < context.nIatRVA + context.nIatSize));

                        if (bImport) {
                            _trace(&context, QString("%1 at %2 is an import thunk, ignored").arg(sInstruction, _hex(nAddress)));
                            bEndPath = true;
                        } else {
                            qint32 nPointerSize = context.bIs64 ? 8 : 4;
                            qint64 nSlotOffset = _rvaToOffset(&context, nSlotRVA);
                            XADDR nTarget = 0;

                            if ((nSlotOffset >= 0) && (nSlotOffset + nPointerSize <= nFileSize)) {
                                QByteArray baPointer = pe.read_array(nSlotOffset, nPointerSize);

                                if (baPointer.size() == nPointerSize) {
                                    nTarget = (XADDR)_readLE(baPointer.constData(), nPointerSize);
                                }
                            }

                            _TARGETINFO info = _classify(&context, nTarget);

                            if (info.target == TARGET_STUB) {
                                nContinue = nTarget;
                            } else if ((nTarget != 0) && (info.target != TARGET_INVALID)) {
                                path.nIndex = nCurrent;
                                _onTransferOut(&context, path, KIND_JMP_MEM, nAddress, sInstruction, nTarget,
                                               QString("; pointer read from slot %1 (offset %2)").arg(_hex(nSlot), _hex((quint64)nSlotOffset)));
                                bEndPath = true;
                            } else if (_classify(&context, nSlot).target != TARGET_INVALID) {
                                _trace(&context, QString("%1 at %2: slot %3 holds %4 in the file, patched at run time").arg(sInstruction, _hex(nAddress), _hex(nSlot), _hex(nTarget)));
                                _addSlotCandidate(&context, nSlot, nAddress, "jmp [mem] (patched at runtime)", 8,
                                                  QString("%1 at %2: the pointer slot at VA %3 holds %4 in the file, so the stub stores the OEP there at run time. "
                                                          "Address shown is the slot, not the OEP")
                                                      .arg(sInstruction, _hex(nAddress), _hex(nSlot), _hex(nTarget)));
                                bEndPath = true;
                            } else {
                                bEndPath = true;
                            }
                        }
                    } else {
                        _trace(&context, QString("%1 at %2: register-based indirect jump, not resolvable statically").arg(sInstruction, _hex(nAddress)));
                        bEndPath = true;
                    }
                } else if (nRegister1 >= 0) {
                    if (path.regs[nRegister1].bValid) {
                        XADDR nTarget = path.regs[nRegister1].nValue;
                        _TARGETINFO info = _classify(&context, nTarget);

                        if (info.target == TARGET_STUB) {
                            nContinue = nTarget;
                        } else if (info.target != TARGET_INVALID) {
                            path.nIndex = nCurrent;
                            _onTransferOut(&context, path, KIND_JMP_REG, nAddress, sInstruction, nTarget,
                                           QString("; %1 = %2 set at %3").arg(sOperand1, _hex(nTarget), _hex(path.regs[nRegister1].nSite)));
                            bEndPath = true;
                        } else {
                            _trace(&context, QString("%1 at %2: %3 = %4 is outside the image").arg(sInstruction, _hex(nAddress), sOperand1, _hex(nTarget)));
                            bEndPath = true;
                        }
                    } else {
                        _trace(&context, QString("%1 at %2: register value computed at run time%3")
                                             .arg(sInstruction, _hex(nAddress), context.bPECompact ? QString(" (PECompact: the OEP is computed by the unpacked loader)") : QString()));
                        bEndPath = true;
                    }
                } else {
                    _trace(&context, QString("%1 at %2: far/absolute jump not followed").arg(sInstruction, _hex(nAddress)));
                    bEndPath = true;
                }
            } else if (disasmResult.bIsCondJmp) {
                if (disasmResult.relType != XDisasmAbstract::RELTYPE_NONE) {
                    XADDR nTarget = _mask(&context, disasmResult.nXrefToRelative);
                    _TARGETINFO info = _classify(&context, nTarget);

                    if (info.target == TARGET_STUB) {
                        _PATH pathBranch = path;
                        pathBranch.nIndex = nCurrent + 1;
                        enqueue(pathBranch, nTarget);
                    } else if (info.target != TARGET_INVALID) {
                        path.nIndex = nCurrent;
                        _onTransferOut(&context, path, KIND_JCC, nAddress, sInstruction, nTarget, QString());
                    }
                }
            } else if (nOpcode == X86_INS_CALL) {
                if (disasmResult.relType == XDisasmAbstract::RELTYPE_CALL) {
                    XADDR nTarget = _mask(&context, disasmResult.nXrefToRelative);
                    _TARGETINFO info = _classify(&context, nTarget);

                    if (info.target == TARGET_STUB) {
                        _PATH pathCall = path;
                        pathCall.nIndex = nCurrent + 1;
                        enqueue(pathCall, nTarget);
                    } else if ((info.target != TARGET_INVALID) && !setTraced.contains(nAddress)) {
                        setTraced.insert(nAddress);
                        _trace(&context, QString("%1 at %2 calls out of the stub (%3)").arg(sInstruction, _hex(nAddress), _targetText(&context, info)));
                    }
                }

                const qint32 *pVolatile = context.bIs64 ? &nVolatile64[0] : &nVolatile32[0];
                qint32 nVolatileCount = context.bIs64 ? 7 : 3;

                for (qint32 i = 0; i < nVolatileCount; i++) {
                    path.regs[pVolatile[i]].bValid = false;
                }
            } else if ((nOpcode == X86_INS_INT3) || (nOpcode == X86_INS_HLT) || (nOpcode == X86_INS_UD2)) {
                bEndPath = true;
            }

            if (bEndPath) {
                break;
            }

            path.nIndex = nCurrent + 1;
            path.nAddress = nContinue;
        }
    }

    _trace(&context, QString("Walk: %1 instruction(s), %2 path(s)%3%4")
                         .arg(nInstructions)
                         .arg(nPaths)
                         .arg((nInstructions >= N_MAX_INSTRUCTIONS) ? QString(", instruction limit reached") : QString())
                         .arg(XBinary::isPdStructNotCanceled(pPdStruct) ? QString() : QString(", canceled")));

    // ---- raw tails anywhere in the stub
    _scanRawTails(&context);

    bool bLooksClean = false;

    if (context.nStubSection != -1) {
        const _SECTION &section = context.listSections.at(context.nStubSection);
        bLooksClean = (context.nStubSection == context.nFirstCodeSection) && !section.bWrite && (section.nFileBackedSize > 0);
    }

    _finalize(&context, bLooksClean, nEntryPointAddress, nInstructions);

    if (result.listCandidates.isEmpty()) {
        _trace(&context, "No tail transfer out of the stub was found statically (the stub may be encrypted, virtualized or compute the OEP at run time)");
    }

    file.close();

    return result;
}
