// DiE Helper (fork addition): static recovery of hidden strings (stack strings, single-byte XOR/ADD/ROL and rolling-XOR encoded strings, .NET #US).
#include "helperstrings.h"

#include <QFile>
#include <QHash>
#include <QMap>
#include <QSet>

#include <algorithm>

#include "xcliassembly.h"
#include "xdisasmcore.h"
#include "xpe.h"

static const qint32 N_MAX_RECORDS = 2000;
static const qint64 N_CODE_SCAN_MAX = 8 * 1024 * 1024;   // bytes of executable section data that are disassembled
static const qint64 N_BRUTE_SCAN_MAX = 2 * 1024 * 1024;  // bytes of data sections that are brute forced (517 transforms each)
static const qint32 N_DISASM_CHUNK = 0x8000;
static const qint32 N_DISASM_TAIL = 16;  // longest x86 instruction is 15 bytes
static const qint32 N_MIN_STACK_LENGTH = 4;
static const qint32 N_MIN_ENCODED_LENGTH = 6;
static const qint32 N_MIN_SOFT_LENGTH = 8;  // encoded string not preceded by a NUL / encoded NUL
static const qint32 N_MAX_STRING_LENGTH = 512;
static const qint32 N_SCORE_STACK = 40;     // after the stack bonus
static const qint32 N_SCORE_ENCODED = 50;   // decoded text must reach this ...
static const qint32 N_SCORE_ROLLING = 60;   // (rolling XOR has 256 keys per start: stricter)
static const qint32 N_SCORE_ADVANTAGE = 15; // ... and beat the raw bytes read as text by this much
static const qint32 N_SCORE_RAW_MAX = 30;   // raw bytes that already read like a string are plain data, not an encoded string
static const qint32 N_STACK_BONUS = 20;     // a string built byte by byte on the stack is strong evidence by itself
static const qint32 N_STACK_MAP_MAX = 4096;
static const quint32 N_SCN_CNT_CODE = 0x00000020;  // IMAGE_SCN_CNT_CODE

// x86 register families (index into STACKSTATE::aRegs)
static const qint32 N_REG_SP = 4;
static const qint32 N_REG_BP = 5;
static const qint32 N_REG_RIP = 16;
static const qint32 N_REG_COUNT = 17;

static QString _hex2(quint32 nValue)
{
    return QString("0x%1").arg(QString::number(nValue, 16).toUpper().rightJustified(2, QChar('0')));
}

static bool _isTextByte(quint8 nByte)
{
    return ((nByte >= 0x20) && (nByte <= 0x7E)) || (nByte == 0x09) || (nByte == 0x0A) || (nByte == 0x0D);
}

static bool _isPrintableByte(quint8 nByte)
{
    return (nByte >= 0x20) && (nByte <= 0x7E);
}

// 0..100: how much a piece of text looks like a real string (path, URL, API/DLL name, sentence) rather than random bytes
static qint32 _scoreText(const QString &sText)
{
    qint32 nLength = sText.length();

    if (nLength < 3) {
        return 0;
    }

    static const QString sVowels = "aeiouyAEIOUY";
    static const QString sCommon = ".,:;/\\-_%()'\"!?@=&+#*";

    qint32 nLower = 0;
    qint32 nUpper = 0;
    qint32 nDigits = 0;
    qint32 nSpaces = 0;
    qint32 nCommon = 0;
    qint32 nControl = 0;
    qint32 nVowels = 0;

    for (qint32 i = 0; i < nLength; i++) {
        QChar cChar = sText.at(i);
        ushort nChar = cChar.unicode();

        if ((nChar == 0x09) || (nChar == 0x0A) || (nChar == 0x0D)) {
            nControl++;
        } else if ((nChar < 0x20) || (nChar == 0x7F)) {
            return 0;
        } else if (cChar.isLetter()) {
            if (cChar.isUpper()) {
                nUpper++;
            } else {
                nLower++;
            }

            if (sVowels.contains(cChar)) {
                nVowels++;
            }
        } else if ((nChar >= '0') && (nChar <= '9')) {
            nDigits++;
        } else if (nChar == ' ') {
            nSpaces++;
        } else if (sCommon.contains(cChar)) {
            nCommon++;
        }
    }

    qint32 nLetters = nLower + nUpper;
    qint32 nGood = nLetters + nDigits + nSpaces + nCommon + nControl;
    qint32 nScore = qMin(nLength, 24);

    if (nLetters == 0) {
        nScore -= 15;
    }

    // {}[]|~^`<>$ and non-ASCII symbols are rare in real strings and common in decoded noise
    nScore -= ((nLength - nGood) * 60) / nLength;

    if (nLetters >= 4) {
        qint32 nRatio = (nVowels * 100) / nLetters;

        if ((nRatio >= 15) && (nRatio <= 65)) {
            nScore += 15;
        } else if (nRatio < 8) {
            nScore -= 15;
        }
    }

    // Case-inverted text ("gETpROCaDDRESS", typical for a wrong XOR 0x20 key); only when upper case dominates,
    // so that camelCase + acronyms ("DirectUI", "tagRECT") are not punished
    if (nUpper > nLower) {
        qint32 nInverted = 0;

        for (qint32 i = 0; i + 2 < nLength; i++) {
            if (sText.at(i).isLower() && sText.at(i + 1).isUpper() && sText.at(i + 2).isUpper()) {
                nInverted++;
            }
        }

        nScore -= qMin(nInverted * 8, 30);
    }

    // Word-likeness: ASCII tokens of 4+ letters (split at non-letters and camelCase humps) that contain a vowel
    {
        qint32 nTokens = 0;
        qint32 nGoodTokens = 0;
        qint32 nTokenLength = 0;
        bool bTokenVowel = false;

        for (qint32 i = 0; i <= nLength; i++) {
            bool bLetter = (i < nLength) && (sText.at(i).unicode() < 0x80) && sText.at(i).isLetter();
            bool bBreak = !bLetter;

            if (bLetter && (nTokenLength > 0)) {
                bool bPrevUpper = sText.at(i - 1).isUpper();
                bool bUpper = sText.at(i).isUpper();
                bool bNextLower = (i + 1 < nLength) && (sText.at(i + 1).unicode() < 0x80) && sText.at(i + 1).isLower();

                // "getProc" -> get|Proc, "RECTOffsets" -> RECT|Offsets
                if ((!bPrevUpper && bUpper) || (bPrevUpper && bUpper && bNextLower)) {
                    bBreak = true;
                }
            }

            if (bBreak) {
                if (nTokenLength >= 4) {
                    nTokens++;

                    if (bTokenVowel) {
                        nGoodTokens++;
                    }
                }

                nTokenLength = 0;
                bTokenVowel = false;
            }

            if (bLetter) {
                nTokenLength++;

                if (sVowels.contains(sText.at(i))) {
                    bTokenVowel = true;
                }
            }
        }

        if ((nTokens >= 2) && (nGoodTokens * 10 >= nTokens * 8)) {
            nScore += 10;
        }
    }

    // Letter pairs that are common in English / API names; decoded noise has few of them
    {
        static const QVector<bool> listBigrams = []() {
            const char *pszList = "th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch "
                                  "ll be ma si om ur ca el ta la ns di fo ho pe ec pr no ct us ac ot il tr ly nc et ut ss so rs un lo wa ge ie wh ee wi em ad ol rt po "
                                  "we na ul ni ts mo ow pa im mi ai sh ir su id os iv ia am fi ci vi pl ig tu ev ld ry mp fe bl ab ty op ex ke fr oo av ag ap gr od sp "
                                  "rd do uc ov rm ep tt oc ef cu rn sc da cr cl qu ff ls va um pp up lu ht ru lt pi rc eg ck pt ak dl xe";
            QVector<bool> listResult(26 * 26, false);

            for (const char *p = pszList; p[0] && p[1]; p++) {
                if ((p[0] >= 'a') && (p[0] <= 'z') && (p[1] >= 'a') && (p[1] <= 'z')) {
                    listResult[(p[0] - 'a') * 26 + (p[1] - 'a')] = true;
                    p++;
                }
            }

            return listResult;
        }();

        qint32 nPairs = 0;
        qint32 nCommonPairs = 0;

        for (qint32 i = 0; i + 1 < nLength; i++) {
            ushort nChar1 = sText.at(i).unicode() | 0x20;
            ushort nChar2 = sText.at(i + 1).unicode() | 0x20;
            bool bLetter1 = (sText.at(i).unicode() < 0x80) && (nChar1 >= 'a') && (nChar1 <= 'z');
            bool bLetter2 = (sText.at(i + 1).unicode() < 0x80) && (nChar2 >= 'a') && (nChar2 <= 'z');

            if (bLetter1 && bLetter2) {
                nPairs++;

                if (listBigrams.at((nChar1 - 'a') * 26 + (nChar2 - 'a'))) {
                    nCommonPairs++;
                }
            }
        }

        if (nPairs >= 5) {
            qint32 nRatio = (nCommonPairs * 100) / nPairs;

            if (nRatio >= 45) {
                nScore += 10;
            } else if (nRatio < 20) {
                nScore -= 15;
            }
        }
    }

    // Well-known fragments
    {
        static const QStringList listKeywords = {"http",         "://",          ".dll",           ".exe",          ".sys",        ".bat",          ".ps1",
                                                 ".vbs",         "kernel32",     "ntdll",          "user32",        "advapi32",    "ws2_32",        "wininet",
                                                 "winhttp",      "software\\",   "microsoft",      "windows",       "currentversion", "hkey_",       "cmd.exe",
                                                 "powershell",   "c:\\",         "www.",           ".com",          ".net",        ".org",          "mozilla",
                                                 "user-agent",   "password",     "appdata",        "system32",      "virtualalloc", "virtualprotect", "loadlibrary",
                                                 "getprocaddress", "createprocess", "createthread", "writeprocessmemory", "\\run"};

        QString sLower = sText.toLower();
        qint32 nBonus = 0;

        for (qint32 i = 0; i < listKeywords.count(); i++) {
            if (sLower.contains(listKeywords.at(i))) {
                nBonus += 10;
            }
        }

        nScore += qMin(nBonus, 40);
    }

    return qBound(0, nScore, 100);
}

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

// Register family (0 a, 1 c, 2 d, 3 b, 4 sp, 5 bp, 6 si, 7 di, 8..15 r8..r15, 16 rip) and access size in bytes (-1: ah/bh/ch/dh)
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
    qint32 nReg;      // register family when bIsReg
    qint32 nRegSize;  // 1/2/4/8, -1 for ah..dh
    qint32 nMemSize;  // byte/word/dword/qword ptr, 0 if unknown
    qint32 nBase;     // base register family of a memory operand, -1 if none
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

static void _addRecord(QList<HelperStrings::RECORD> *pListRecords, const QString &sMethod, qint64 nOffset, XBinary::_MEMORY_MAP *pMemoryMap, const QString &sString,
                       qint32 nScore)
{
    HelperStrings::RECORD record = {};
    record.sMethod = sMethod;
    record.nOffset = nOffset;
    record.nAddress = (nOffset >= 0) ? XBinary::offsetToAddress(pMemoryMap, nOffset) : (XADDR)-1;
    record.sString = sString;
    record.nScore = qBound(0, nScore, 100);

    pListRecords->append(record);
}

// Best single-byte XOR key for bytes that are not text themselves; -1 if no key gives a convincing string
static qint32 _bestXorKey(const QByteArray &baData, qint32 *pnScore, QString *psText)
{
    qint32 nResult = -1;
    qint32 nBest = 0;
    qint32 nSize = baData.size();
    const quint8 *pData = (const quint8 *)baData.constData();

    for (qint32 nKey = 1; nKey < 256; nKey++) {
        bool bText = true;

        for (qint32 i = 0; (i < nSize) && bText; i++) {
            bText = _isTextByte(pData[i] ^ nKey);
        }

        if (!bText) {
            continue;
        }

        QByteArray baDecoded = baData;

        for (qint32 i = 0; i < nSize; i++) {
            baDecoded[i] = (char)(pData[i] ^ nKey);
        }

        QString sText = QString::fromLatin1(baDecoded);
        qint32 nScore = _scoreText(sText);

        if (nScore > nBest) {
            nBest = nScore;
            nResult = nKey;
            *psText = sText;
        }
    }

    *pnScore = nBest;

    return nResult;
}

// ---- stack strings: immediate stores to [rsp/rbp/esp/ebp + disp], directly or through a register holding a known constant
struct STACKBYTE {
    quint8 nValue;
    qint64 nOffset;  // file offset of the store instruction
};

struct REGVALUE {
    bool bKnown;
    quint64 nValue;
};

struct STACKSTATE {
    QMap<qint64, STACKBYTE> mapBytes;  // key: (base family << 33) + displacement
    REGVALUE aRegs[N_REG_COUNT];
};

static void _resetRegs(STACKSTATE *pState)
{
    for (qint32 i = 0; i < N_REG_COUNT; i++) {
        pState->aRegs[i].bKnown = false;
        pState->aRegs[i].nValue = 0;
    }
}

static void _emitStackRun(const QList<STACKBYTE> &listRun, QList<HelperStrings::RECORD> *pListRecords, XBinary::_MEMORY_MAP *pMemoryMap)
{
    qint32 nCount = listRun.count();
    qint32 i = 0;

    while (i < nCount) {
        // UTF-16LE: printable, 0, printable, 0, ...
        qint32 nWide = 0;

        while ((i + 2 * nWide + 1 < nCount) && _isPrintableByte(listRun.at(i + 2 * nWide).nValue) && (listRun.at(i + 2 * nWide + 1).nValue == 0)) {
            nWide++;
        }

        if (nWide >= N_MIN_STACK_LENGTH) {
            QString sText;
            qint64 nOffset = listRun.at(i).nOffset;

            for (qint32 j = 0; (j < nWide) && (j < N_MAX_STRING_LENGTH); j++) {
                sText.append(QChar((ushort)listRun.at(i + 2 * j).nValue));
                nOffset = qMin(nOffset, listRun.at(i + 2 * j).nOffset);
            }

            qint32 nScore = _scoreText(sText) + N_STACK_BONUS;

            if (nScore >= N_SCORE_STACK) {
                _addRecord(pListRecords, "stack string", nOffset, pMemoryMap, sText, nScore);
            }

            i += 2 * nWide;
            continue;
        }

        if (listRun.at(i).nValue == 0) {
            i++;
            continue;
        }

        qint32 j = i;

        while ((j < nCount) && (listRun.at(j).nValue != 0)) {
            j++;
        }

        qint32 nLength = j - i;

        if (nLength >= N_MIN_STACK_LENGTH) {
            QByteArray baSegment;
            qint64 nOffset = listRun.at(i).nOffset;
            bool bPrintable = true;

            for (qint32 k = i; (k < j) && (baSegment.size() < N_MAX_STRING_LENGTH); k++) {
                baSegment.append((char)listRun.at(k).nValue);
                nOffset = qMin(nOffset, listRun.at(k).nOffset);

                if (!_isTextByte(listRun.at(k).nValue)) {
                    bPrintable = false;
                }
            }

            if (bPrintable) {
                QString sText = QString::fromLatin1(baSegment);
                qint32 nScore = _scoreText(sText) + N_STACK_BONUS;

                if (nScore >= N_SCORE_STACK) {
                    _addRecord(pListRecords, "stack string", nOffset, pMemoryMap, sText, nScore);
                }
            } else {
                qint32 nScore = 0;
                QString sText;
                qint32 nKey = _bestXorKey(baSegment, &nScore, &sText);

                if ((nKey != -1) && (nScore >= N_SCORE_ENCODED)) {
                    _addRecord(pListRecords, QString("stack string, xor %1").arg(_hex2(nKey)), nOffset, pMemoryMap, sText, nScore + N_STACK_BONUS);
                }
            }
        }

        i = j;
    }
}

static void _flushStack(STACKSTATE *pState, QList<HelperStrings::RECORD> *pListRecords, XBinary::_MEMORY_MAP *pMemoryMap)
{
    QList<STACKBYTE> listRun;
    qint64 nPrevKey = 0;

    for (QMap<qint64, STACKBYTE>::const_iterator iter = pState->mapBytes.constBegin(); iter != pState->mapBytes.constEnd(); ++iter) {
        if (!listRun.isEmpty() && (iter.key() != nPrevKey + 1)) {
            _emitStackRun(listRun, pListRecords, pMemoryMap);
            listRun.clear();
        }

        listRun.append(iter.value());
        nPrevKey = iter.key();
    }

    if (!listRun.isEmpty()) {
        _emitStackRun(listRun, pListRecords, pMemoryMap);
    }

    pState->mapBytes.clear();
}

static void _stackInstruction(STACKSTATE *pState, const XDisasmAbstract::DISASM_RESULT &disasmResult, const quint8 *pBytes, qint32 nAvailable, qint64 nOffset, bool bIs64,
                              QList<HelperStrings::RECORD> *pListRecords, XBinary::_MEMORY_MAP *pMemoryMap)
{
    Q_UNUSED(bIs64)

    if (!disasmResult.bIsValid) {
        return;
    }

    quint32 nOpcode = disasmResult.nOpcode;

    if ((nOpcode == X86_INS_RET) || (nOpcode == X86_INS_RETF) || (nOpcode == X86_INS_INT3)) {
        _flushStack(pState, pListRecords, pMemoryMap);
        _resetRegs(pState);
        return;
    }

    if (disasmResult.bIsCall) {
        _resetRegs(pState);  // volatile registers are clobbered; the stack bytes stay
        return;
    }

    QString sFirst;
    QString sSecond;
    _splitOperands(disasmResult.sOperands, &sFirst, &sSecond);

    OPERAND opDst = _parseOperand(sFirst);
    bool bImmediate = (disasmResult.nImmSize > 0) && ((qint32)(disasmResult.nImmOffset + disasmResult.nImmSize) <= nAvailable);
    quint64 nImmediate = 0;
    qint32 nImmSize = (qint32)disasmResult.nImmSize;

    if (bImmediate) {
        nImmediate = _readLE(pBytes + disasmResult.nImmOffset, nImmSize);
    }

    if ((nOpcode == X86_INS_MOV) || (nOpcode == X86_INS_MOVABS)) {
        if (opDst.bIsMem && !opDst.bHasIndex && !opDst.bHasSegment && ((opDst.nBase == N_REG_SP) || (opDst.nBase == N_REG_BP)) &&
            ((opDst.nMemSize == 1) || (opDst.nMemSize == 2) || (opDst.nMemSize == 4) || (opDst.nMemSize == 8))) {
            bool bKnown = false;
            quint64 nValue = 0;

            if (bImmediate) {
                bKnown = true;
                nValue = (quint64)_signExtend(nImmediate, nImmSize);
            } else {
                OPERAND opSrc = _parseOperand(sSecond);

                if (opSrc.bIsReg && (opSrc.nRegSize > 0) && pState->aRegs[opSrc.nReg].bKnown) {
                    bKnown = true;
                    nValue = pState->aRegs[opSrc.nReg].nValue;
                }
            }

            qint64 nDisp = 0;

            if ((disasmResult.nDispSize > 0) && ((qint32)(disasmResult.nDispOffset + disasmResult.nDispSize) <= nAvailable)) {
                nDisp = _signExtend(_readLE(pBytes + disasmResult.nDispOffset, disasmResult.nDispSize), disasmResult.nDispSize);
            }

            qint64 nKeyBase = ((qint64)opDst.nBase << 33) + nDisp;

            if (bKnown) {
                // the slot is reused for another string: report what was built so far first
                for (qint32 i = 0; i < opDst.nMemSize; i++) {
                    if (pState->mapBytes.contains(nKeyBase + i)) {
                        _flushStack(pState, pListRecords, pMemoryMap);
                        break;
                    }
                }

                for (qint32 i = 0; i < opDst.nMemSize; i++) {
                    STACKBYTE stackByte = {};
                    stackByte.nValue = (quint8)(nValue >> (8 * i));
                    stackByte.nOffset = nOffset;
                    pState->mapBytes.insert(nKeyBase + i, stackByte);
                }

                if (pState->mapBytes.count() > N_STACK_MAP_MAX) {
                    _flushStack(pState, pListRecords, pMemoryMap);
                }
            } else {
                for (qint32 i = 0; i < opDst.nMemSize; i++) {
                    pState->mapBytes.remove(nKeyBase + i);
                }
            }

            return;
        }

        if (opDst.bIsReg) {
            REGVALUE &regValue = pState->aRegs[opDst.nReg];
            OPERAND opSrc = _parseOperand(sSecond);

            if (bImmediate && !opSrc.bIsMem) {
                if ((opDst.nRegSize == 8) || (opDst.nRegSize == 4)) {
                    // 32-bit writes zero the upper half in long mode
                    regValue.bKnown = true;
                    regValue.nValue = (opDst.nRegSize == 8) ? (quint64)_signExtend(nImmediate, nImmSize) : (quint64)(quint32)nImmediate;
                } else if (((opDst.nRegSize == 2) || (opDst.nRegSize == 1)) && regValue.bKnown) {
                    quint64 nMask = (opDst.nRegSize == 2) ? 0xFFFF : 0xFF;
                    regValue.nValue = (regValue.nValue & ~nMask) | (nImmediate & nMask);
                } else {
                    regValue.bKnown = false;
                }
            } else if (opSrc.bIsReg && (opSrc.nRegSize > 0) && pState->aRegs[opSrc.nReg].bKnown && (opDst.nRegSize >= 4)) {
                quint64 nValue = pState->aRegs[opSrc.nReg].nValue;
                regValue.bKnown = true;
                regValue.nValue = (opSrc.nRegSize == 4) ? (quint64)(quint32)nValue : nValue;
            } else {
                regValue.bKnown = false;
            }

            return;
        }

        return;
    }

    if ((nOpcode == X86_INS_XOR) && opDst.bIsReg && (opDst.nRegSize >= 4) && (sFirst == sSecond)) {
        pState->aRegs[opDst.nReg].bKnown = true;
        pState->aRegs[opDst.nReg].nValue = 0;
        return;
    }

    // anything else that writes a register makes its value unknown
    if (opDst.bIsReg) {
        pState->aRegs[opDst.nReg].bKnown = false;
    }
}

// Linear sweep over executable sections; calls processInstruction(result, bytes, available, fileOffset, bNewSection)
template <typename T>
static void _walkCode(XPE *pPE, const QList<XPE_DEF::IMAGE_SECTION_HEADER> &listHeaders, XADDR nImageBase, bool bIs64, qint64 nFileSize, XBinary::PDSTRUCT *pPdStruct,
                      T processInstruction)
{
    XDisasmCore disasmCore;  // no setOptions(): colors are not needed and it must never get a null XOptions
    disasmCore.setMode(bIs64 ? XBinary::DM_X86_64 : XBinary::DM_X86_32);

    XDisasmAbstract::DISASM_OPTIONS disasmOptions = {};
    disasmOptions.bIsUppercase = false;
    disasmOptions.bNoStrings = true;

    qint64 nTotal = 0;

    for (qint32 i = 0; (i < listHeaders.count()) && (nTotal < N_CODE_SCAN_MAX) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        const XPE_DEF::IMAGE_SECTION_HEADER &header = listHeaders.at(i);

        if (!((header.Characteristics & XPE_DEF::S_IMAGE_SCN_MEM_EXECUTE) || (header.Characteristics & N_SCN_CNT_CODE))) {
            continue;
        }

        qint64 nRawOffset = header.PointerToRawData;
        qint64 nRawSize = header.SizeOfRawData;

        if ((nRawOffset <= 0) || (nRawOffset >= nFileSize) || (nRawSize <= 0)) {
            continue;
        }

        nRawSize = qMin(nRawSize, nFileSize - nRawOffset);

        if ((header.Misc.VirtualSize > 0) && ((qint64)header.Misc.VirtualSize < nRawSize)) {
            nRawSize = header.Misc.VirtualSize;  // the rest is file alignment padding
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

// ---- single-byte transforms over data: XOR K, ADD K, ROL N
// Cheap filter before the full score: at least half letters and a plausible vowel ratio
static bool _quickLooksLikeText(const QByteArray &baDecoded)
{
    qint32 nSize = baDecoded.size();
    qint32 nLetters = 0;
    qint32 nVowels = 0;

    for (qint32 i = 0; i < nSize; i++) {
        char cChar = (char)(baDecoded.at(i) | 0x20);

        if ((cChar >= 'a') && (cChar <= 'z')) {
            nLetters++;

            if ((cChar == 'a') || (cChar == 'e') || (cChar == 'i') || (cChar == 'o') || (cChar == 'u') || (cChar == 'y')) {
                nVowels++;
            }
        }
    }

    return (nLetters * 2 >= nSize) && (nVowels * 100 >= nLetters * 10) && (nVowels * 100 <= nLetters * 70);
}

struct CANDIDATE {
    HelperStrings::RECORD record;
    qint32 nLength;  // encoded bytes
};

// Structured tables decode to repetitive text: "CCCCEEEE", "ACAGACAOAC", "c7c9i;Q=Q?eAeC"
static bool _isDiverse(const QByteArray &baDecoded)
{
    qint32 nLength = baDecoded.size();
    qint32 nRun = 1;
    qint32 nPeriod2 = 0;
    qint32 nDistinct = 0;
    bool bSeen[256] = {};

    for (qint32 i = 0; i < nLength; i++) {
        quint8 nByte = (quint8)baDecoded.at(i);

        if (!bSeen[nByte]) {
            bSeen[nByte] = true;
            nDistinct++;
        }

        if (i > 0) {
            nRun = (baDecoded.at(i) == baDecoded.at(i - 1)) ? (nRun + 1) : 1;

            if (nRun >= 5) {
                return false;
            }
        }

        if ((i + 2 < nLength) && (baDecoded.at(i) == baDecoded.at(i + 2))) {
            nPeriod2++;
        }
    }

    if ((nLength >= 8) && (nPeriod2 * 100 >= (nLength - 2) * 25)) {
        return false;
    }

    return nDistinct * 3 >= qMin(nLength, 30);
}

static void _considerCandidate(const quint8 *pRaw, const QByteArray &baDecoded, qint64 nOffset, const QString &sMethod, qint32 nMinScore,
                               QHash<qint64, CANDIDATE> *pMapBest, XBinary::_MEMORY_MAP *pMemoryMap)
{
    if (!_isDiverse(baDecoded) || !_quickLooksLikeText(baDecoded)) {
        return;
    }

    qint32 nLength = baDecoded.size();

    // byte ramps (CRT ctype/case tables) decode to "pqrstuvw...": too many neighbours differing by 1 or 2
    {
        qint32 nSteps = 0;

        for (qint32 i = 0; i + 1 < nLength; i++) {
            qint32 nDiff = qAbs((qint32)(quint8)baDecoded.at(i + 1) - (qint32)(quint8)baDecoded.at(i));

            if ((nDiff == 1) || (nDiff == 2)) {
                nSteps++;
            }
        }

        if (nSteps * 10 >= (nLength - 1) * 4) {
            return;
        }
    }

    QString sText = QString::fromLatin1(baDecoded);
    qint32 nScore = _scoreText(sText);

    if (nScore < nMinScore) {
        return;
    }

    QHash<qint64, CANDIDATE>::iterator iter = pMapBest->find(nOffset);

    if ((iter != pMapBest->end()) && (iter.value().record.nScore >= nScore)) {
        return;
    }

    // the raw bytes must not already be a (better) plain string; stray non-text bytes (e.g. the hint before an
    // import name) are ignored as long as at least 80% of the bytes are text
    QByteArray baRawText;

    for (qint32 i = 0; i < nLength; i++) {
        if (_isTextByte(pRaw[i])) {
            baRawText.append((char)pRaw[i]);
        }
    }

    qint32 nRawScore = (baRawText.size() * 5 >= nLength * 4) ? _scoreText(QString::fromLatin1(baRawText)) : 0;

    if ((nRawScore >= N_SCORE_RAW_MAX) || (nScore < nRawScore + N_SCORE_ADVANTAGE)) {
        return;
    }

    CANDIDATE candidate = {};
    candidate.record.sMethod = sMethod;
    candidate.record.nOffset = nOffset;
    candidate.record.nAddress = XBinary::offsetToAddress(pMemoryMap, nOffset);
    candidate.record.sString = sText;
    candidate.record.nScore = nScore;
    candidate.nLength = nLength;
    pMapBest->insert(nOffset, candidate);
}

static void _bruteForceTable(const QByteArray &baData, qint64 nBaseOffset, const quint8 *pTable, quint8 nZeroRaw, const QString &sMethod, QHash<qint64, CANDIDATE> *pMapBest,
                             XBinary::_MEMORY_MAP *pMemoryMap)
{
    bool bText[256];

    for (qint32 i = 0; i < 256; i++) {
        bText[i] = _isTextByte(pTable[i]);
    }

    const quint8 *pData = (const quint8 *)baData.constData();
    qint32 nSize = baData.size();
    qint32 nRunStart = 0;
    bool bSoftStart = false;  // the run starts after an undecodable byte instead of an (encoded) NUL: needs to be longer

    for (qint32 i = 0; i <= nSize; i++) {
        bool bBoundary = (i == nSize) || (pData[i] == 0) || (pData[i] == nZeroRaw);

        if (bBoundary) {
            qint32 nLength = i - nRunStart;
            qint32 nMinLength = bSoftStart ? N_MIN_SOFT_LENGTH : N_MIN_ENCODED_LENGTH;

            if ((nLength >= nMinLength) && (nLength <= N_MAX_STRING_LENGTH)) {
                QByteArray baDecoded(nLength, 0);

                for (qint32 j = 0; j < nLength; j++) {
                    baDecoded[j] = (char)pTable[pData[nRunStart + j]];
                }

                _considerCandidate(pData + nRunStart, baDecoded, nBaseOffset + nRunStart, sMethod, N_SCORE_ENCODED, pMapBest, pMemoryMap);
            }

            nRunStart = i + 1;
            bSoftStart = false;
        } else if (!bText[pData[i]]) {
            nRunStart = i + 1;
            bSoftStart = true;
        }
    }
}

// plaintext[i] = raw[i] ^ ((K + i) & 0xFF), strings start right after a NUL byte
static void _bruteForceRolling(const QByteArray &baData, qint64 nBaseOffset, QHash<qint64, CANDIDATE> *pMapBest, XBinary::_MEMORY_MAP *pMemoryMap,
                               XBinary::PDSTRUCT *pPdStruct)
{
    const quint8 *pData = (const quint8 *)baData.constData();
    qint32 nSize = baData.size();

    for (qint32 nStart = 0; (nStart < nSize) && XBinary::isPdStructNotCanceled(pPdStruct); nStart++) {
        if ((pData[nStart] == 0) || ((nStart > 0) && (pData[nStart - 1] != 0))) {
            continue;
        }

        for (qint32 nKey = 0; nKey < 256; nKey++) {
            qint32 nLength = 0;
            bool bTerminated = false;

            while ((nStart + nLength < nSize) && (nLength <= N_MAX_STRING_LENGTH)) {
                quint8 nRaw = pData[nStart + nLength];
                quint8 nDecoded = nRaw ^ (quint8)((nKey + nLength) & 0xFF);

                if ((nRaw == 0) || (nDecoded == 0)) {
                    bTerminated = true;
                    break;
                }

                if (!_isTextByte(nDecoded)) {
                    break;
                }

                nLength++;
            }

            if (!bTerminated && (nStart + nLength == nSize)) {
                bTerminated = true;
            }

            if (!bTerminated || (nLength < N_MIN_ENCODED_LENGTH) || (nLength > N_MAX_STRING_LENGTH)) {
                continue;
            }

            QByteArray baDecoded(nLength, 0);

            for (qint32 j = 0; j < nLength; j++) {
                baDecoded[j] = (char)(pData[nStart + j] ^ (quint8)((nKey + j) & 0xFF));
            }

            _considerCandidate(pData + nStart, baDecoded, nBaseOffset + nStart, QString("xor rolling %1").arg(_hex2(nKey)), N_SCORE_ROLLING, pMapBest, pMemoryMap);
        }
    }
}

static void _bruteForceRegion(const QByteArray &baData, qint64 nBaseOffset, QHash<qint64, CANDIDATE> *pMapBest, XBinary::_MEMORY_MAP *pMemoryMap,
                              XBinary::PDSTRUCT *pPdStruct)
{
    quint8 table[256];

    // XOR K: the encoded NUL terminator is K itself
    for (qint32 nKey = 1; (nKey < 256) && XBinary::isPdStructNotCanceled(pPdStruct); nKey++) {
        for (qint32 i = 0; i < 256; i++) {
            table[i] = (quint8)(i ^ nKey);
        }

        _bruteForceTable(baData, nBaseOffset, table, (quint8)nKey, QString("xor %1").arg(_hex2(nKey)), pMapBest, pMemoryMap);
    }

    // ADD K (0x80 is the same as XOR 0x80)
    for (qint32 nKey = 1; (nKey < 256) && XBinary::isPdStructNotCanceled(pPdStruct); nKey++) {
        if (nKey == 0x80) {
            continue;
        }

        for (qint32 i = 0; i < 256; i++) {
            table[i] = (quint8)((i + nKey) & 0xFF);
        }

        _bruteForceTable(baData, nBaseOffset, table, (quint8)((256 - nKey) & 0xFF), QString("add %1").arg(_hex2(nKey)), pMapBest, pMemoryMap);
    }

    // ROL N (ROR N == ROL 8-N)
    for (qint32 nBits = 1; (nBits < 8) && XBinary::isPdStructNotCanceled(pPdStruct); nBits++) {
        for (qint32 i = 0; i < 256; i++) {
            table[i] = (quint8)(((i << nBits) | (i >> (8 - nBits))) & 0xFF);
        }

        _bruteForceTable(baData, nBaseOffset, table, 0, QString("rol %1").arg(nBits), pMapBest, pMemoryMap);
    }

    _bruteForceRolling(baData, nBaseOffset, pMapBest, pMemoryMap, pPdStruct);
}

// ---- .NET #US heap: compressed length (ECMA-335 II.24.2.4), UTF-16LE text, one trailing flag byte
static void _scanUserStrings(const QByteArray &baUS, qint64 nHeapOffset, QList<HelperStrings::RECORD> *pListRecords, XBinary::_MEMORY_MAP *pMemoryMap,
                             XBinary::PDSTRUCT *pPdStruct)
{
    const quint8 *pData = (const quint8 *)baUS.constData();
    qint32 nSize = baUS.size();
    qint32 i = 1;  // index 0 is the empty string

    while ((i < nSize) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        quint8 nByte0 = pData[i];
        qint32 nLength = 0;
        qint32 nHeader = 0;

        if ((nByte0 & 0x80) == 0) {
            nLength = nByte0;
            nHeader = 1;
        } else if ((nByte0 & 0xC0) == 0x80) {
            if (i + 1 >= nSize) {
                break;
            }

            nLength = ((nByte0 & 0x3F) << 8) | pData[i + 1];
            nHeader = 2;
        } else if ((nByte0 & 0xE0) == 0xC0) {
            if (i + 3 >= nSize) {
                break;
            }

            nLength = ((nByte0 & 0x1F) << 24) | (pData[i + 1] << 16) | (pData[i + 2] << 8) | pData[i + 3];
            nHeader = 4;
        } else {
            break;
        }

        if ((nLength < 0) || ((qint64)i + nHeader + nLength > nSize)) {
            break;
        }

        qint32 nChars = nLength / 2;

        if (nChars >= 3) {
            QString sText;
            qint32 nTake = qMin(nChars, N_MAX_STRING_LENGTH);
            const quint8 *pText = pData + i + nHeader;

            sText.reserve(nTake);

            for (qint32 j = 0; j < nTake; j++) {
                sText.append(QChar((ushort)(pText[2 * j] | (pText[2 * j + 1] << 8))));
            }

            qint32 nScore = _scoreText(sText);

            if (nScore > 0) {
                _addRecord(pListRecords, ".NET #US", nHeapOffset + i + nHeader, pMemoryMap, sText, nScore);
            }
        }

        i += nHeader + nLength;

        if (nHeader + nLength == 0) {
            i++;
        }
    }
}

HelperStrings::RESULT HelperStrings::recover(const QString &sFileName, XBinary::PDSTRUCT *pPdStruct)
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

    const qint64 nFileSize = pe.getSize();
    const bool bIs64 = pe.is64();
    const bool bIsNET = pe.isNETPresent();
    const XADDR nImageBase = pe.getOptionalHeader_ImageBase();

    XBinary::_MEMORY_MAP memoryMap = pe.getMemoryMap();
    QList<XPE_DEF::IMAGE_SECTION_HEADER> listHeaders = pe.getSectionHeaders(nullptr);
    QList<RECORD> listRecords;

    if (bIsNET) {
        // ---- .NET: user strings; IL is not x86 and its data is metadata, so the native passes are skipped
        XCLIAssembly *pCliAssembly = pe.getCliAssembly(nullptr);

        if (pCliAssembly) {
            XCLIAssembly::CLI_INFO cliInfo = pCliAssembly->getCliInfo(false, nullptr);

            if (cliInfo.bValid) {
                _scanUserStrings(cliInfo.metaData.baUS, cliInfo.metaData.osUS.nOffset, &listRecords, &memoryMap, pPdStruct);
            }

            delete pCliAssembly;
        }
    } else {
        // ---- stack strings
        {
            STACKSTATE state;
            _resetRegs(&state);

            _walkCode(&pe, listHeaders, nImageBase, bIs64, nFileSize, pPdStruct,
                      [&](const XDisasmAbstract::DISASM_RESULT &disasmResult, const quint8 *pBytes, qint32 nAvailable, qint64 nOffset, bool bNewSection) {
                          if (bNewSection) {
                              _flushStack(&state, &listRecords, &memoryMap);
                              _resetRegs(&state);
                          }

                          _stackInstruction(&state, disasmResult, pBytes, nAvailable, nOffset, bIs64, &listRecords, &memoryMap);
                      });

            _flushStack(&state, &listRecords, &memoryMap);
        }

        // ---- encoded strings in data sections
        {
            struct REGION {
                qint64 nOffset;
                qint64 nSize;
            };

            QList<REGION> listData;
            QList<REGION> listAll;

            for (qint32 i = 0; i < listHeaders.count(); i++) {
                const XPE_DEF::IMAGE_SECTION_HEADER &header = listHeaders.at(i);
                QString sName = QString::fromLatin1((const char *)header.Name, qstrnlen((const char *)header.Name, XPE_DEF::S_IMAGE_SIZEOF_SHORT_NAME));
                qint64 nOffset = header.PointerToRawData;
                qint64 nSize = header.SizeOfRawData;

                if ((nOffset <= 0) || (nOffset >= nFileSize) || (nSize <= 0)) {
                    continue;
                }

                nSize = qMin(nSize, nFileSize - nOffset);

                if ((sName == ".rsrc") || (sName == ".reloc") || (sName == ".pdata")) {
                    continue;
                }

                REGION region = {nOffset, nSize};
                listAll.append(region);

                if (!((header.Characteristics & XPE_DEF::S_IMAGE_SCN_MEM_EXECUTE) || (header.Characteristics & N_SCN_CNT_CODE))) {
                    listData.append(region);
                }
            }

            // packed/odd layouts: one RWX section holds everything
            const QList<REGION> &listRegions = listData.isEmpty() ? listAll : listData;
            QHash<qint64, CANDIDATE> mapBest;
            qint64 nBudget = N_BRUTE_SCAN_MAX;

            for (qint32 i = 0; (i < listRegions.count()) && (nBudget > 0) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
                qint64 nSize = qMin(listRegions.at(i).nSize, nBudget);
                QByteArray baData = pe.read_array(listRegions.at(i).nOffset, nSize);

                if (baData.isEmpty()) {
                    continue;
                }

                _bruteForceRegion(baData, listRegions.at(i).nOffset, &mapBest, &memoryMap, pPdStruct);
                nBudget -= baData.size();
            }

            // overlapping decodes of the same bytes (another key on a tail of the string): keep the best one
            QList<CANDIDATE> listCandidates = mapBest.values();

            std::stable_sort(listCandidates.begin(), listCandidates.end(), [](const CANDIDATE &candidate1, const CANDIDATE &candidate2) {
                if (candidate1.record.nScore != candidate2.record.nScore) {
                    return candidate1.record.nScore > candidate2.record.nScore;
                }

                return candidate1.record.nOffset < candidate2.record.nOffset;
            });

            QMap<qint64, qint64> mapAccepted;  // start -> end of accepted ranges

            for (qint32 i = 0; i < listCandidates.count(); i++) {
                const CANDIDATE &candidate = listCandidates.at(i);
                qint64 nStart = candidate.record.nOffset;
                qint64 nEnd = nStart + candidate.nLength;
                bool bOverlap = false;

                QMap<qint64, qint64>::const_iterator iterNext = mapAccepted.lowerBound(nStart);

                if ((iterNext != mapAccepted.constEnd()) && (iterNext.key() < nEnd)) {
                    bOverlap = true;
                }

                if (!bOverlap && (iterNext != mapAccepted.constBegin())) {
                    QMap<qint64, qint64>::const_iterator iterPrev = iterNext;
                    --iterPrev;

                    if (iterPrev.value() > nStart) {
                        bOverlap = true;
                    }
                }

                if (!bOverlap) {
                    mapAccepted.insert(nStart, nEnd);
                    listRecords.append(candidate.record);
                }
            }
        }
    }

    file.close();

    // ---- dedup by text (keep the best score), sort, cap
    {
        QHash<QString, qint32> mapIndex;
        QList<RECORD> listUnique;

        for (qint32 i = 0; i < listRecords.count(); i++) {
            const RECORD &record = listRecords.at(i);
            QHash<QString, qint32>::const_iterator iter = mapIndex.constFind(record.sString);

            if (iter == mapIndex.constEnd()) {
                mapIndex.insert(record.sString, listUnique.count());
                listUnique.append(record);
            } else if (listUnique.at(iter.value()).nScore < record.nScore) {
                listUnique[iter.value()] = record;
            }
        }

        std::stable_sort(listUnique.begin(), listUnique.end(), [](const RECORD &record1, const RECORD &record2) {
            if (record1.nScore != record2.nScore) {
                return record1.nScore > record2.nScore;
            }

            return record1.nOffset < record2.nOffset;
        });

        if (listUnique.count() > N_MAX_RECORDS) {
            listUnique.erase(listUnique.begin() + N_MAX_RECORDS, listUnique.end());
        }

        result.listRecords = listUnique;
    }

    return result;
}
