// DiE Helper (fork addition): turns the entry point code of a PE file into a DiE detection rule
// (PE.compareEP pattern with wildcarded addresses, followed jumps) and saves it to the custom database.
#include "helpersignaturemaker.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QSaveFile>
#include <QSet>
#include <cctype>

#include "xdisasmcore.h"
#include "xoptions.h"
#include "xpe.h"

static const qint32 N_MAX_INSTRUCTIONS = 256;
static const qint32 N_MIN_LITERAL_BYTES = 4;  // fewer fixed bytes than this would match half of all files
static const qint32 N_MAX_NAME_LENGTH = 64;

static QString _hexAddress(XADDR nValue)
{
    return QString("0x%1").arg(QString::number((quint64)nValue, 16).toUpper());
}

static QString _normalizeType(const QString &sType)
{
    // DiE record types are single lower-case words: packer, protector, cryptor, installer, ...
    QString sResult = sType.trimmed().toLower();

    static const QRegularExpression regExp(QString("^[a-z][a-z0-9]{0,31}$"));

    if (!regExp.match(sResult).hasMatch()) {
        sResult.clear();
    }

    return sResult;
}

static QString _getFileNamePart(const QString &sName)
{
    QString sResult;
    QString sValue = sName.trimmed();

    for (qint32 i = 0; i < sValue.size(); i++) {
        QChar c = sValue.at(i);
        bool bAllowed = ((c >= QChar('a')) && (c <= QChar('z'))) || ((c >= QChar('A')) && (c <= QChar('Z'))) || ((c >= QChar('0')) && (c <= QChar('9'))) ||
                        (c == QChar('.')) || (c == QChar('+')) || (c == QChar('-'));

        if (bAllowed) {
            sResult.append(c);
        } else if (!sResult.endsWith(QChar('_'))) {
            sResult.append(QChar('_'));
        }
    }

    // no leading/trailing separators, no ".." tricks, bounded length
    while (sResult.contains(QString(".."))) {
        sResult.replace(QString(".."), QString("."));
    }

    sResult = sResult.left(N_MAX_NAME_LENGTH);

    while (!sResult.isEmpty() && ((sResult.at(0) == QChar('_')) || (sResult.at(0) == QChar('.')))) {
        sResult.remove(0, 1);
    }

    while (!sResult.isEmpty() && ((sResult.endsWith(QChar('_'))) || (sResult.endsWith(QChar('.'))))) {
        sResult.chop(1);
    }

    return sResult;
}

static QString _getPlainText(const QString &sText)
{
    // one line, no control characters, no JS line terminators (U+2028/U+2029 end an ES5 string literal)
    QString sResult;

    for (qint32 i = 0; i < sText.size(); i++) {
        QChar c = sText.at(i);

        if ((c.unicode() < 0x20) || (c.unicode() == 0x7F) || (c.unicode() == 0x2028) || (c.unicode() == 0x2029)) {
            sResult.append(QChar(' '));
        } else {
            sResult.append(c);
        }
    }

    return sResult.simplified();
}

static QString _getJsString(const QString &sText)
{
    QString sResult = _getPlainText(sText);
    sResult.replace(QString("\\"), QString("\\\\"));
    sResult.replace(QString("\""), QString("\\\""));

    return sResult;
}

static qint32 _countLiteralBytes(const QString &sPattern)
{
    qint32 nResult = 0;

    for (qint32 i = 0; i + 1 < sPattern.size(); i += 2) {
        if (isxdigit((unsigned char)sPattern.at(i).toLatin1()) && isxdigit((unsigned char)sPattern.at(i + 1).toLatin1())) {
            nResult++;
        }
    }

    return nResult;
}

static QString _buildScript(const QString &sPattern, const QString &sType, const QString &sName, const QString &sSourceFileName, qint32 nInstructions)
{
    QString sResult;

    sResult += QString("// Detect It Easy: detection rule file\n");
    sResult += QString("// Author: DiE Helper (generated)\n");
    sResult += QString("\n");

    if (!sSourceFileName.isEmpty()) {
        sResult += QString("// Entry point rule generated from: %1\n").arg(_getPlainText(sSourceFileName));
    }

    if (nInstructions > 0) {
        sResult += QString("// %1 instructions from the entry point.\n").arg(nInstructions);
    }

    sResult += QString("// Addresses, 32-bit displacements/immediates and branch offsets are wildcarded (..);\n");
    sResult += QString("// unconditional jumps are followed ($$ / $$$$$$$$). Built from one sample: check it on more files.\n");
    sResult += QString("\n");
    sResult += QString("meta(\"%1\", \"%2\");\n").arg(sType, _getJsString(sName));
    sResult += QString("\n");
    sResult += QString("function detect() {\n");
    sResult += QString("    if (PE.compareEP(\"%1\")) {\n").arg(sPattern);
    sResult += QString("        bDetected = true;\n");
    sResult += QString("    }\n");
    sResult += QString("\n");
    sResult += QString("    return result();\n");
    sResult += QString("}\n");

    return sResult;
}

HelperSignatureMaker::RESULT HelperSignatureMaker::makeFromEntryPoint(const QString &sFileName, const QString &sType, const QString &sName, qint32 nInstructions)
{
    RESULT result = {};
    result.bIsValid = false;

    QString _sType = _normalizeType(sType);

    if (_sType.isEmpty()) {
        result.sError = QString("Invalid type \"%1\": use one lower-case word such as packer, protector or cryptor").arg(_getPlainText(sType));
        return result;
    }

    if (_getFileNamePart(sName).isEmpty()) {
        result.sError = QString("Invalid name: it needs at least one letter or digit");
        return result;
    }

    nInstructions = qBound(1, nInstructions, N_MAX_INSTRUCTIONS);

    QFile file(sFileName);

    if (!file.open(QIODevice::ReadOnly)) {
        result.sError = QString("Cannot open file: %1").arg(file.errorString());
        return result;
    }

    XPE pe(&file);

    if (!pe.isValid()) {
        result.sError = QString("Not a valid PE file");
        return result;
    }

    if (pe.getOptionalHeader_AddressOfEntryPoint() == 0) {
        result.sError = QString("The file has no entry point (IL-only .NET image or resource-only DLL)");
        return result;
    }

    XBinary::_MEMORY_MAP memoryMap = pe.getMemoryMap();
    XBinary::DM disasmMode = XBinary::getDisasmMode(&memoryMap);

    if (XBinary::getDisasmFamily(disasmMode) != XBinary::DMFAMILY_X86) {
        result.sError = QString("Only x86 / x64 entry points are supported");
        return result;
    }

    XADDR nAddress = pe.getEntryPointAddress(&memoryMap);

    if (XBinary::addressToOffset(&memoryMap, nAddress) == -1) {
        result.sError = QString("The entry point is not backed by file data (the code is created at run time), so an entry point rule cannot match");
        return result;
    }

    XDisasmCore disasmCore;  // no setOptions(): colors/syntax are not needed and it must not get a null XOptions
    disasmCore.setMode(disasmMode);

    XDisasmAbstract::DISASM_OPTIONS disasmOptions = {};

    QSet<XADDR> stVisited;
    QString sPattern;
    QString sStopReason;
    qint32 nCount = 0;
    qint32 nWildDisp = 0;
    qint32 nWildImm = 0;
    qint32 nWildBranch = 0;

    while (nCount < nInstructions) {
        if (stVisited.contains(nAddress)) {
            sStopReason = QString("code loops back to %1").arg(_hexAddress(nAddress));
            break;
        }

        stVisited.insert(nAddress);

        qint64 nOffset = XBinary::addressToOffset(&memoryMap, nAddress);

        if (nOffset < 0) {
            sStopReason = QString("%1 is not backed by file data").arg(_hexAddress(nAddress));
            break;
        }

        QByteArray baData = XBinary::read_array(&file, nOffset, 16);
        qint32 nAvailable = baData.size();
        baData.append(QByteArray(16, 0));  // padding: Capstone never reads past the buffer

        XDisasmAbstract::DISASM_RESULT disasmResult = disasmCore.disAsm(baData.data(), baData.size(), nAddress, disasmOptions);

        if ((!disasmResult.bIsValid) || (disasmResult.nSize <= 0) || (disasmResult.nSize > nAvailable)) {
            sStopReason = QString("no valid instruction at %1").arg(_hexAddress(nAddress));
            break;
        }

        if (XBinary::addressToOffset(&memoryMap, nAddress + disasmResult.nSize - 1) != nOffset + disasmResult.nSize - 1) {
            sStopReason = QString("instruction at %1 crosses the end of file data").arg(_hexAddress(nAddress));
            break;
        }

        QString sHex = QString::fromLatin1(baData.left(disasmResult.nSize).toHex().toUpper());
        QString sInstruction = (disasmResult.sMnemonic + QString(" ") + disasmResult.sOperands).trimmed();
        XADDR nNext = nAddress + disasmResult.nSize;
        bool bStop = false;

        qint32 nImmOffset = (qint32)disasmResult.nImmOffset;
        qint32 nImmSize = (qint32)disasmResult.nImmSize;
        qint32 nDispOffset = (qint32)disasmResult.nDispOffset;
        qint32 nDispSize = (qint32)disasmResult.nDispSize;

        if (disasmResult.relType != XDisasmAbstract::RELTYPE_NONE) {
            // relative branch: the displacement is the immediate field
            if ((nImmSize <= 0) || (nImmOffset <= 0) || (nImmOffset + nImmSize > disasmResult.nSize)) {
                sStopReason = QString("cannot locate the branch offset of \"%1\" at %2").arg(sInstruction, _hexAddress(nAddress));
                break;
            }

            if (disasmResult.relType == XDisasmAbstract::RELTYPE_JMP_UNCOND) {
                XADDR nTarget = disasmResult.nXrefToRelative;

                // a jump that leaves the entry point's region (e.g. the tail jump of an unpacking stub into the
                // original code) ends the signature: the bytes behind it differ for every packed program
                auto regionOf = [&](XADDR nVA) -> qint32 {
                    for (qint32 r = 0; r < memoryMap.listRecords.count(); r++) {
                        const XBinary::_MEMORY_RECORD &record = memoryMap.listRecords.at(r);

                        if ((nVA >= record.nAddress) && (nVA < record.nAddress + (XADDR)record.nSize)) {
                            return r;
                        }
                    }

                    return -1;
                };

                bool bSameRegion = (regionOf(nTarget) != -1) && (regionOf(nTarget) == regionOf(nAddress));

                if (!bSameRegion) {
                    sHex = XDisasmCore::replaceWildChar(sHex, nImmOffset, nImmSize, QChar('.'));
                    nWildBranch++;
                    bStop = true;
                    sStopReason = QString("jump at %1 leaves the entry point's section (-> %2): stub ends here").arg(_hexAddress(nAddress), _hexAddress(nTarget));
                } else if ((XBinary::addressToOffset(&memoryMap, nTarget) != -1) && (!stVisited.contains(nTarget))) {
                    sHex = XDisasmCore::replaceWildChar(sHex, nImmOffset, nImmSize, QChar('$'));
                    nNext = nTarget;
                    result.listNotes.append(QString("Followed \"%1\" at %2 -> %3").arg(sInstruction, _hexAddress(nAddress), _hexAddress(nTarget)));
                } else {
                    sHex = XDisasmCore::replaceWildChar(sHex, nImmOffset, nImmSize, QChar('.'));
                    nWildBranch++;
                    bStop = true;
                    sStopReason = QString("jump target %1 is not in the file or was already visited").arg(_hexAddress(nTarget));
                }
            } else if ((disasmResult.relType == XDisasmAbstract::RELTYPE_CALL) && (disasmResult.nXrefToRelative == nNext)) {
                // CALL $+5 (E8 00000000, get-PC idiom): the zero offset is part of the stub, keep it literal
                result.listNotes.append(QString("Kept \"%1\" at %2 literal (call to the next instruction)").arg(sInstruction, _hexAddress(nAddress)));
            } else {
                // calls and conditional jumps: wildcard the offset, continue with the next instruction
                sHex = XDisasmCore::replaceWildChar(sHex, nImmOffset, nImmSize, QChar('.'));
                nWildBranch++;
            }
        } else {
            // addresses/offsets differ between builds; small constants and stack offsets are kept
            if (nDispSize >= 4) {
                sHex = XDisasmCore::replaceWildChar(sHex, nDispOffset, nDispSize, QChar('.'));
                nWildDisp++;
            }

            if (nImmSize >= 4) {
                sHex = XDisasmCore::replaceWildChar(sHex, nImmOffset, nImmSize, QChar('.'));
                nWildImm++;
            }

            if (disasmResult.bIsRet) {
                bStop = true;
                sStopReason = QString("return at %1").arg(_hexAddress(nAddress));
            } else if (disasmResult.bIsJmp) {
                bStop = true;
                sStopReason = QString("indirect jump \"%1\" at %2 cannot be followed statically").arg(sInstruction, _hexAddress(nAddress));
            } else if (XDisasmAbstract::isInt3Opcode(XBinary::DMFAMILY_X86, disasmResult.nOpcode)) {
                bStop = true;
                sStopReason = QString("int3 at %1").arg(_hexAddress(nAddress));
            }
        }

        sPattern += sHex;
        nCount++;

        if (bStop) {
            break;
        }

        nAddress = nNext;
    }

    if (sStopReason.isEmpty()) {
        sStopReason = QString("instruction limit (%1) reached").arg(nInstructions);
    }

    // trailing "any byte" wildcards add nothing
    while (sPattern.endsWith(QChar('.'))) {
        sPattern.chop(1);
    }

    if (sPattern.size() % 2) {
        sPattern.chop(1);  // never happens for whole bytes; keep the pattern well-formed anyway
    }

    result.listNotes.prepend(QString("Stopped: %1").arg(sStopReason));

    qint32 nLiteralBytes = _countLiteralBytes(sPattern);

    result.listNotes.prepend(QString("%1 instructions, %2 fixed bytes; wildcarded %3 displacement(s), %4 immediate(s), %5 branch offset(s)")
                                 .arg(nCount)
                                 .arg(nLiteralBytes)
                                 .arg(nWildDisp)
                                 .arg(nWildImm)
                                 .arg(nWildBranch));

    if (nLiteralBytes < N_MIN_LITERAL_BYTES) {
        result.sError = QString("The pattern is too generic (%1 fixed bytes)").arg(nLiteralBytes);

        if (pe.isNETPresent()) {
            result.sError += QString(": the native entry point of a .NET file is only a jump to mscoree; use a .NET rule instead");
        }

        result.sPattern = sPattern;
        return result;
    }

    // self-check with the same matcher PE.compareEP falls back to for patterns with '$'
    if (!pe.compareEntryPoint(&memoryMap, sPattern)) {
        result.sError = QString("Self-check failed: the pattern does not match this file's own entry point");
        result.sPattern = sPattern;
        return result;
    }

    result.listNotes.append(QString("Self-check: the pattern matches this file's entry point"));

    result.bIsValid = true;
    result.sPattern = sPattern;
    result.sScript = _buildScript(sPattern, _sType, sName, QFileInfo(sFileName).fileName(), nCount);

    return result;
}

bool HelperSignatureMaker::save(const QString &sDbCustomPath, const RESULT &result, const QString &sType, const QString &sName, bool bOverwrite, QString *psFileName,
                                QString *psError)
{
    QString sError;
    bool bResult = false;

    QString _sType = _normalizeType(sType);
    QString sNamePart = _getFileNamePart(sName);

    if (psFileName) {
        psFileName->clear();
    }

    if (_sType.isEmpty()) {
        sError = QString("Invalid type: use one lower-case word such as packer, protector or cryptor");
    } else if (sNamePart.isEmpty()) {
        sError = QString("Invalid name: it needs at least one letter or digit");
    } else if (sDbCustomPath.trimmed().isEmpty()) {
        sError = QString("The custom database path is empty (Options -> Scan)");
    } else {
        QString sRoot = XOptions::convertPathName(sDbCustomPath.trimmed());
        QString sDirectory = QDir(sRoot).filePath(QString("PE"));
        QString sFileName = QDir(sDirectory).filePath(QString("%1_%2.2.sg").arg(_sType, sNamePart));

        if (psFileName) {
            *psFileName = QDir::toNativeSeparators(sFileName);
        }

        QString sScript = result.sScript;

        if (sScript.trimmed().isEmpty() && (!result.sPattern.isEmpty())) {
            sScript = _buildScript(result.sPattern, _sType, sName, QString(), 0);
        }

        if (sScript.trimmed().isEmpty()) {
            sError = QString("Nothing to save: no pattern was generated");
        } else if (QFileInfo::exists(sFileName) && !bOverwrite) {
            sError = QString("%1 already exists").arg(QDir::toNativeSeparators(sFileName));
        } else if (!QDir().mkpath(sDirectory)) {
            sError = QString("Cannot create %1").arg(QDir::toNativeSeparators(sDirectory));
        } else {
            QSaveFile file(sFileName);

            if (!file.open(QIODevice::WriteOnly)) {
                sError = QString("Cannot write %1: %2").arg(QDir::toNativeSeparators(sFileName), file.errorString());
            } else {
                QByteArray baData = sScript.toUtf8();

                if (file.write(baData) != baData.size()) {
                    sError = QString("Cannot write %1: %2").arg(QDir::toNativeSeparators(sFileName), file.errorString());
                    file.cancelWriting();
                } else if (!file.commit()) {
                    sError = QString("Cannot write %1: %2").arg(QDir::toNativeSeparators(sFileName), file.errorString());
                } else {
                    bResult = true;
                }
            }
        }
    }

    if (psError) {
        *psError = sError;
    }

    return bResult;
}
