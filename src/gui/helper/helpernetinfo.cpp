// DiE Helper (fork addition): static .NET metadata review: obfuscated names with readable aliases, protector markers, high-entropy IL bodies, user strings.
// STATUS: done (written, not compiled yet)
#include "helpernetinfo.h"

#include <QFile>
#include <QHash>
#include <QSet>
#include <QVector>

#include <algorithm>
#include <cmath>

#include "xcliassembly.h"
#include "xpe.h"

static const quint32 N_MAX_ROWS = 0x40000;       // per table
static const qint32 N_MAX_NAMES = 50000;
static const qint32 N_TOP_METHODS = 20;
static const qint64 N_MIN_METHOD_SIZE = 64;      // entropy of fewer bytes says little
static const qint64 N_MAX_METHOD_SIZE = 1024 * 1024;
static const qint32 N_MAX_USER_STRINGS = 5000;
static const qint32 N_MAX_USER_STRING_LENGTH = 1000;
static const double D_ENTROPY_IL_HIGH = 6.8;      // normal IL is about 4.5..6.0
static const qint64 N_ENTROPY_IL_HIGH_SIZE = 256;
static const double D_ENTROPY_RESOURCE_HIGH = 7.5;
static const qint64 N_MAX_RESOURCE_SAMPLE = 4 * 1024 * 1024;

static QString _hex(quint64 nValue)
{
    return QString("0x%1").arg(QString::number(nValue, 16).toUpper());
}

// Same heuristics as helperevidence.cpp
static QString _escapeName(const QString &sName)
{
    QString sResult;
    qint32 nLength = sName.length();

    for (qint32 i = 0; (i < nLength) && (sResult.length() < 96); i++) {
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

// 0 - ignore (empty/compiler generated), 1 - looks normal, 2 - looks obfuscated (copy of helperevidence.cpp)
static qint32 _classifyNetName(const QString &sName)
{
    if (sName.isEmpty()) {
        return 0;
    }

    qint32 nLength = sName.length();

    for (qint32 i = 0; i < nLength; i++) {
        ushort nChar = sName.at(i).unicode();

        if ((nChar < 0x20) || (nChar > 0x7E)) {
            return 2;
        }
    }

    if (sName.startsWith(QChar('<')) || (sName == ".ctor") || (sName == ".cctor") || sName.startsWith("__StaticArrayInitTypeSize") || sName.startsWith("$")) {
        return 0;
    }

    QString sBase = sName;

    qint32 nTick = sBase.lastIndexOf(QChar('`'));

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

    if ((nBaseLength >= 4) && (nConfusable == nBaseLength)) {
        return 2;
    }

    if ((nBaseLength >= 16) && (nHex == nBaseLength) && (nDigits >= 4) && (nLetters >= 4)) {
        return 2;
    }

    if ((nLetters >= 8) && (nUpper < nLetters) && ((nVowels * 100) < (nLetters * 12))) {
        return 2;
    }

    return 1;
}

static double _entropy(const QByteArray &baData)
{
    qint64 nSize = baData.size();

    if (nSize <= 0) {
        return 0;
    }

    qint64 nCounts[256] = {};
    const quint8 *pData = (const quint8 *)baData.constData();

    for (qint64 i = 0; i < nSize; i++) {
        nCounts[pData[i]]++;
    }

    double dResult = 0;

    for (qint32 i = 0; i < 256; i++) {
        if (nCounts[i]) {
            double dP = (double)nCounts[i] / (double)nSize;
            dResult -= dP * std::log2(dP);
        }
    }

    return dResult;
}

// Row field reader for tables XCLIAssembly has no getter for. Table offsets are file offsets; baMetadata starts at osMetadata.nOffset.
static quint32 _readRowValue(const XCLIAssembly::CLI_INFO &cliInfo, qint32 nTable, quint32 nRow, qint32 nFieldOffset, qint32 nFieldSize)
{
    quint32 nResult = 0;
    qint64 nPos = cliInfo.metaData.Tables_TablesOffsets[nTable] + cliInfo.metaData.Tables_TableElementSizes[nTable] * (qint64)nRow - cliInfo.metaData.osMetadata.nOffset +
                  nFieldOffset;
    const QByteArray &baMetadata = cliInfo.metaData.baMetadata;

    if ((nPos >= 0) && (nPos + nFieldSize <= baMetadata.size())) {
        const quint8 *pData = (const quint8 *)baMetadata.constData() + nPos;

        if (nFieldSize == 4) {
            nResult = (quint32)pData[0] | ((quint32)pData[1] << 8) | ((quint32)pData[2] << 16) | ((quint32)pData[3] << 24);
        } else if (nFieldSize == 2) {
            nResult = (quint32)pData[0] | ((quint32)pData[1] << 8);
        } else if (nFieldSize == 1) {
            nResult = pData[0];
        }
    }

    return nResult;
}

static quint32 _rowCount(const XCLIAssembly::CLI_INFO &cliInfo, qint32 nTable)
{
    quint32 nResult = 0;

    if (cliInfo.metaData.Tables_TableElementSizes[nTable] > 0) {
        nResult = qMin<quint32>(cliInfo.metaData.Tables_TablesNumberOfIndexes[nTable], N_MAX_ROWS);
    }

    return nResult;
}

// #US: compressed length (ECMA-335 II.24.2.4), UTF-16LE text, one trailing flag byte
static QStringList _readUserStrings(const QByteArray &baUS, XBinary::PDSTRUCT *pPdStruct)
{
    QStringList listResult;
    const quint8 *pData = (const quint8 *)baUS.constData();
    qint32 nSize = baUS.size();
    qint32 i = 1;

    while ((i < nSize) && (listResult.count() < N_MAX_USER_STRINGS) && XBinary::isPdStructNotCanceled(pPdStruct)) {
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

        if (nChars > 0) {
            QString sText;
            qint32 nTake = qMin(nChars, N_MAX_USER_STRING_LENGTH);
            const quint8 *pText = pData + i + nHeader;

            sText.reserve(nTake);

            for (qint32 j = 0; j < nTake; j++) {
                sText.append(QChar((ushort)(pText[2 * j] | (pText[2 * j + 1] << 8))));
            }

            listResult.append(sText);
        }

        i += nHeader + nLength;
    }

    return listResult;
}

static void _addMarker(HelperNetInfo::RESULT *pResult, const QString &sName, const QString &sDetails)
{
    HelperNetInfo::MARKER marker = {};
    marker.sName = sName;
    marker.sDetails = sDetails;

    pResult->listMarkers.append(marker);
}

HelperNetInfo::RESULT HelperNetInfo::analyze(const QString &sFileName, XBinary::PDSTRUCT *pPdStruct)
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

    if (!pe.isNETPresent()) {
        result.sError = "Not a .NET assembly (no CLI header)";
        file.close();
        return result;
    }

    XCLIAssembly *pCliAssembly = pe.getCliAssembly(nullptr);

    if (!pCliAssembly) {
        result.sError = "Cannot read the CLI header";
        file.close();
        return result;
    }

    XCLIAssembly::CLI_INFO cliInfo = pCliAssembly->getCliInfo(false, nullptr);

    if (!cliInfo.bValid) {
        result.sError = "The .NET metadata is invalid or unreadable";
        delete pCliAssembly;
        file.close();
        return result;
    }

    result.bIsValid = true;

    const qint64 nFileSize = pe.getSize();
    XBinary::_MEMORY_MAP memoryMap = pe.getMemoryMap();
    const QByteArray &baStrings = cliInfo.metaData.baStrings;
    const qint32 nStringIndexSize = cliInfo.metaData.nStringIndexSize;

    const quint32 nTypes = _rowCount(cliInfo, XCLIASSEMBLY_DEF::metadata_TypeDef);
    const quint32 nMethods = _rowCount(cliInfo, XCLIASSEMBLY_DEF::metadata_MethodDef);
    const quint32 nFields = _rowCount(cliInfo, XCLIASSEMBLY_DEF::metadata_Field);
    const quint32 nProperties = _rowCount(cliInfo, XCLIASSEMBLY_DEF::metadata_Property);
    const quint32 nEvents = _rowCount(cliInfo, XCLIASSEMBLY_DEF::metadata_Event);

    // ---- names
    qint32 nExamined = 0;
    qint32 nObfuscated = 0;
    QStringList listSamples;
    QVector<QString> listTypeOfMethod(nMethods);  // escaped owning type name per MethodDef row

    {
        qint32 nCounters[5] = {};
        static const char *pszKinds[5] = {"Type", "Method", "Field", "Property", "Event"};
        static const char *pszAliases[5] = {"Class_%1", "method_%1", "field_%1", "prop_%1", "event_%1"};

        auto addName = [&](qint32 nKind, const QString &sName, const QString &sNamespace) {
            qint32 nClass = _classifyNetName(sName);

            if (nClass == 0) {
                return;
            }

            if (!sNamespace.isEmpty() && (_classifyNetName(sNamespace) == 2)) {
                nClass = 2;
            }

            nExamined++;

            if (result.listNames.count() >= N_MAX_NAMES) {
                if (nClass == 2) {
                    nObfuscated++;
                }

                return;
            }

            NAME name = {};
            name.sKind = QString::fromLatin1(pszKinds[nKind]);
            name.sOriginal = sNamespace.isEmpty() ? _escapeName(sName) : (_escapeName(sNamespace) + "." + _escapeName(sName));
            name.bObfuscated = (nClass == 2);

            if (name.bObfuscated) {
                nObfuscated++;
                nCounters[nKind]++;
                name.sAlias = QString(pszAliases[nKind]).arg(nCounters[nKind], 4, 10, QChar('0'));

                if (listSamples.count() < 5) {
                    listSamples.append(name.sOriginal);
                }
            }

            result.listNames.append(name);
        };

        for (quint32 i = 0; (i < nTypes) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            XCLIASSEMBLY_DEF::S_METADATA_TYPEDEF typeDef = pCliAssembly->getMetadataTypeDef(&cliInfo, (qint32)i);
            QString sName = _readNetString(baStrings, typeDef.nTypeName);
            QString sNamespace = _readNetString(baStrings, typeDef.nTypeNamespace);

            addName(0, sName, sNamespace);

            // method ownership: MethodList (1-based) up to the next type's MethodList
            quint32 nFirst = typeDef.nMethodList ? (typeDef.nMethodList - 1) : 0;
            quint32 nLast = nMethods;

            if (i + 1 < nTypes) {
                XCLIASSEMBLY_DEF::S_METADATA_TYPEDEF nextTypeDef = pCliAssembly->getMetadataTypeDef(&cliInfo, (qint32)(i + 1));

                if (nextTypeDef.nMethodList) {
                    nLast = qMin(nLast, nextTypeDef.nMethodList - 1);
                }
            }

            QString sTypeLabel = sNamespace.isEmpty() ? _escapeName(sName) : (_escapeName(sNamespace) + "." + _escapeName(sName));

            for (quint32 j = nFirst; j < nLast; j++) {
                listTypeOfMethod[(qint32)j] = sTypeLabel;
            }
        }

        for (quint32 i = 0; (i < nMethods) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            addName(1, _readNetString(baStrings, pCliAssembly->getMetadataMethodDef(&cliInfo, (qint32)i).nName), QString());
        }

        for (quint32 i = 0; (i < nFields) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            addName(2, _readNetString(baStrings, pCliAssembly->getMetadataField(&cliInfo, (qint32)i).nName), QString());
        }

        // Property: Flags (2), Name (string index), Type (blob index)
        for (quint32 i = 0; (i < nProperties) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            addName(3, _readNetString(baStrings, _readRowValue(cliInfo, XCLIASSEMBLY_DEF::metadata_Property, i, 2, nStringIndexSize)), QString());
        }

        // Event: EventFlags (2), Name (string index), EventType (coded index)
        for (quint32 i = 0; (i < nEvents) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            addName(4, _readNetString(baStrings, _readRowValue(cliInfo, XCLIASSEMBLY_DEF::metadata_Event, i, 2, nStringIndexSize)), QString());
        }
    }

    // ---- #Strings heap as a set (DiE's isNetObjectPresent() matches whole heap strings the same way)
    QSet<QString> setHeapStrings;
    {
        const char *pData = baStrings.constData();
        qint32 nSize = baStrings.size();
        qint32 nStart = 0;

        for (qint32 i = 0; i < nSize; i++) {
            if (pData[i] == 0) {
                if (i > nStart) {
                    setHeapStrings.insert(QString::fromUtf8(pData + nStart, i - nStart));
                }

                nStart = i + 1;
            }
        }
    }

    // ---- user strings
    result.listUserStrings = _readUserStrings(cliInfo.metaData.baUS, pPdStruct);

    // ---- markers: names taken from DiE's own protector rules (db/PE/protector_*.sg)
    {
        struct NETMARKER {
            const char *pszString;
            const char *pszProtector;
        };

        static const NETMARKER markers[] = {{"ConfusedByAttribute", "ConfuserEx / Confuser"},
                                            {"DotNetPatcherPackerAttribute", "DotNetPatcher"},
                                            {"DotfuscatorAttribute", "Dotfuscator"},
                                            {"SmartAssembly.Attributes", "SmartAssembly"},
                                            {"Powered by SmartAssembly", "SmartAssembly"},
                                            {"Powered by {smartassembly}", "SmartAssembly"},
                                            {"BabelAttribute", "Babel .NET"},
                                            {"BabelObfuscatorAttribute", "Babel .NET"},
                                            {"ObfuscatedByAgileDotNetAttribute", "Agile.NET (CliSecure)"},
                                            {"<AgileDotNetRT>", "Agile.NET (CliSecure)"},
                                            {"AgileDotNetRT.dll", "Agile.NET (CliSecure)"},
                                            {"AgileDotNetRT64.dll", "Agile.NET (CliSecure)"},
                                            {"ObfuscatedByCliSecureAttribute", "CliSecure"},
                                            {"ObfuscatedByGoliath", "Goliath .NET"},
                                            {"YanoAttribute", "Yano"},
                                            {"Xenocode.Client.Attributes.AssemblyAttributes", "Xenocode Postbuild"},
                                            {"NineRays.Obfuscator", "Spices.Net"},
                                            {"ZYXDNGuarder", "DNGuard HVM"},
                                            {"HVMRuntm.dll", "DNGuard HVM"},
                                            {"Protect32.dll", "ILProtector"},
                                            {"Protect64.dll", "ILProtector"},
                                            {"MRuntime3.dll", "MaxtoCode"},
                                            {"NecroVM.Runtime", ".NET Reactor (NecroBit VM)"},
                                            {"OneVM.Runtime", "OneVM"},
                                            {"XerinFuscator", "XerinFuscator"},
                                            {"Xerin.Runtime", "XerinFuscator"},
                                            {"RustemSoft.Skater", "Skater .NET"},
                                            {"SuppressIldasmAttribute", "Anti-ILDASM attribute (many protectors)"}};

        for (const NETMARKER &marker : markers) {
            QString sString = QString::fromLatin1(marker.pszString);

            if (setHeapStrings.contains(sString)) {
                _addMarker(&result, QString::fromLatin1(marker.pszProtector), QString("#Strings contains \"%1\"").arg(sString));
            }
        }

        for (qint32 i = 0; i < result.listUserStrings.count(); i++) {
            const QString &sText = result.listUserStrings.at(i);

            if (sText.contains("Eziriz")) {
                _addMarker(&result, ".NET Reactor", QString("#US contains \"%1\"").arg(_escapeName(sText.left(80))));
                break;
            }
        }
    }

    if ((nObfuscated > 0) && (nExamined > 0)) {
        _addMarker(&result, "Obfuscated names",
                   QString("%1 of %2 type/member names look obfuscated (%3%); e.g. %4")
                       .arg(nObfuscated)
                       .arg(nExamined)
                       .arg(QString::number((double)nObfuscated * 100.0 / (double)nExamined, 'f', 0))
                       .arg(listSamples.join(", ")));
    }

    // ---- module initializer: methods of the <Module> type (row 0), .cctor runs before any other managed code
    if (nTypes >= 1) {
        XCLIASSEMBLY_DEF::S_METADATA_TYPEDEF moduleType = pCliAssembly->getMetadataTypeDef(&cliInfo, 0);
        quint32 nFirst = moduleType.nMethodList ? (moduleType.nMethodList - 1) : 0;
        quint32 nLast = nMethods;

        if (nTypes >= 2) {
            XCLIASSEMBLY_DEF::S_METADATA_TYPEDEF nextType = pCliAssembly->getMetadataTypeDef(&cliInfo, 1);

            if (nextType.nMethodList) {
                nLast = qMin(nLast, nextType.nMethodList - 1);
            }
        }

        qint32 nGlobalMethods = (nLast > nFirst) ? (qint32)(nLast - nFirst) : 0;
        bool bCctor = false;

        for (quint32 i = nFirst; i < nLast; i++) {
            if (_readNetString(baStrings, pCliAssembly->getMetadataMethodDef(&cliInfo, (qint32)i).nName) == ".cctor") {
                bCctor = true;
                break;
            }
        }

        if (bCctor) {
            _addMarker(&result, "Module initializer",
                       QString("<Module>.cctor present (%1 global method(s)): runs before Main; protectors put anti-tamper / string decryption / resource "
                               "decryption setup here")
                           .arg(nGlobalMethods));
        }
    }

    // ---- IL bodies: header validity + entropy
    {
        qint32 nWithBody = 0;
        qint32 nInvalidHeaders = 0;
        qint32 nHighEntropy = 0;
        QList<METHOD> listMethods;

        for (quint32 i = 0; (i < nMethods) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            XCLIASSEMBLY_DEF::S_METADATA_METHODDEF methodDef = pCliAssembly->getMetadataMethodDef(&cliInfo, (qint32)i);

            if ((methodDef.nRVA == 0) || ((methodDef.nImplFlags & 0x0003) != 0)) {
                continue;  // abstract / extern / native / runtime-provided
            }

            nWithBody++;

            qint64 nHeaderOffset = XBinary::relAddressToOffset(&memoryMap, methodDef.nRVA);

            if ((nHeaderOffset < 0) || (nHeaderOffset >= nFileSize)) {
                nInvalidHeaders++;
                continue;
            }

            quint8 nFirstByte = pe.read_uint8(nHeaderOffset);
            qint64 nCodeOffset = -1;
            qint64 nCodeSize = 0;

            if ((nFirstByte & 0x03) == 0x02) {
                // tiny header: size in the upper 6 bits
                nCodeOffset = nHeaderOffset + 1;
                nCodeSize = nFirstByte >> 2;
            } else if ((nFirstByte & 0x03) == 0x03) {
                // fat header: Flags/Size (2), MaxStack (2), CodeSize (4), LocalVarSigTok (4)
                quint16 nFlags = pe.read_uint16(nHeaderOffset);
                qint64 nHeaderSize = ((nFlags >> 12) & 0x0F) * 4;

                if (nHeaderSize >= 12) {
                    nCodeOffset = nHeaderOffset + nHeaderSize;
                    nCodeSize = pe.read_uint32(nHeaderOffset + 4);
                }
            }

            if ((nCodeOffset < 0) || (nCodeSize > N_MAX_METHOD_SIZE) || (nCodeOffset + nCodeSize > nFileSize)) {
                nInvalidHeaders++;
                continue;
            }

            if (nCodeSize < N_MIN_METHOD_SIZE) {
                continue;
            }

            METHOD method = {};
            QString sMethodName = _escapeName(_readNetString(baStrings, methodDef.nName));
            method.sName = listTypeOfMethod.at((qint32)i).isEmpty() ? sMethodName : (listTypeOfMethod.at((qint32)i) + "::" + sMethodName);
            method.nOffset = nCodeOffset;
            method.nSize = nCodeSize;
            method.dEntropy = _entropy(pe.read_array(nCodeOffset, nCodeSize));

            if ((method.dEntropy >= D_ENTROPY_IL_HIGH) && (nCodeSize >= N_ENTROPY_IL_HIGH_SIZE)) {
                nHighEntropy++;
            }

            listMethods.append(method);
        }

        std::stable_sort(listMethods.begin(), listMethods.end(), [](const METHOD &method1, const METHOD &method2) { return method1.dEntropy > method2.dEntropy; });

        result.listTopEntropyMethods = listMethods.mid(0, N_TOP_METHODS);

        // a random first byte is a valid tiny/fat header only half of the time
        if ((nInvalidHeaders >= 3) && (nInvalidHeaders * 10 >= nWithBody)) {
            _addMarker(&result, "Encrypted method bodies",
                       QString("%1 of %2 IL method bodies have an invalid header: bodies are encrypted in the file and restored at run time (anti-tamper)")
                           .arg(nInvalidHeaders)
                           .arg(nWithBody));
        }

        if (nHighEntropy > 0) {
            _addMarker(&result, "High-entropy IL",
                       QString("%1 method body(ies) of %2+ bytes with entropy >= %3 (normal IL is about 4.5..6.0): encrypted or virtualized code")
                           .arg(nHighEntropy)
                           .arg(N_ENTROPY_IL_HIGH_SIZE)
                           .arg(QString::number(D_ENTROPY_IL_HIGH, 'f', 1)));
        }
    }

    // ---- manifest resources (table 0x28: Offset (4), Flags (4), Name (string index), Implementation (coded index))
    {
        const qint32 nTable = XCLIASSEMBLY_DEF::metadata_ManifestResource;
        quint32 nResources = _rowCount(cliInfo, nTable);
        qint64 nResourceBase = -1;

        if (cliInfo.header.Resources.VirtualAddress) {
            nResourceBase = XBinary::relAddressToOffset(&memoryMap, cliInfo.header.Resources.VirtualAddress);
        }

        QStringList listCostura;
        QStringList listEncrypted;

        for (quint32 i = 0; (i < nResources) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            quint32 nRelativeOffset = _readRowValue(cliInfo, nTable, i, 0, 4);
            QString sName = _readNetString(baStrings, _readRowValue(cliInfo, nTable, i, 8, nStringIndexSize));
            quint32 nImplementation = _readRowValue(cliInfo, nTable, i, 8 + nStringIndexSize, cliInfo.metaData.nImplementationSize);

            if (sName.toLower().startsWith("costura.")) {
                listCostura.append(_escapeName(sName));
            }

            // Implementation 0: data embedded in the CLI resources directory, prefixed by a 4-byte length
            if ((nImplementation != 0) || (nResourceBase < 0)) {
                continue;
            }

            qint64 nLengthOffset = nResourceBase + nRelativeOffset;

            if ((nLengthOffset < 0) || (nLengthOffset + 4 > nFileSize)) {
                continue;
            }

            qint64 nDataSize = pe.read_uint32(nLengthOffset);

            if ((nDataSize < 1024) || (nLengthOffset + 4 + nDataSize > nFileSize)) {
                continue;
            }

            quint32 nMagic = pe.read_uint32(nLengthOffset + 4);

            if (nMagic == 0xBEEFCACE) {
                continue;  // a .resources container (images inside are compressed anyway)
            }

            double dEntropy = pe.getBinaryStatus(XBinary::BSTATUS_ENTROPY, nLengthOffset + 4, qMin(nDataSize, N_MAX_RESOURCE_SAMPLE), nullptr);

            if (dEntropy >= D_ENTROPY_RESOURCE_HIGH) {
                listEncrypted.append(QString("%1 (offset %2, %3 bytes, entropy %4)")
                                         .arg(_escapeName(sName), _hex(nLengthOffset + 4))
                                         .arg(nDataSize)
                                         .arg(QString::number(dEntropy, 'f', 2)));
            }
        }

        if (!listCostura.isEmpty()) {
            _addMarker(&result, "Costura.Fody", QString("Embedded (compressed) assemblies: %1").arg(listCostura.mid(0, 10).join(", ")));
        }

        if (!listEncrypted.isEmpty()) {
            _addMarker(&result, "Encrypted resources", QString("Raw (non-.resources) high-entropy manifest resources: %1").arg(listEncrypted.mid(0, 10).join(", ")));
        }
    }

    // ---- P/Invoke (ImplMap 0x1C: MappingFlags (2), MemberForwarded (coded), ImportName (string index), ImportScope (ModuleRef index))
    {
        const qint32 nTable = XCLIASSEMBLY_DEF::metadata_ImplMap;
        quint32 nRows = _rowCount(cliInfo, nTable);
        qint32 nForwardedSize = cliInfo.metaData.nMemberForwardedSize;
        qint32 nModuleRefSize = (qint32)cliInfo.metaData.indexSize[XCLIASSEMBLY_DEF::metadata_ModuleRef];
        quint32 nModuleRefs = cliInfo.metaData.Tables_TablesNumberOfIndexes[XCLIASSEMBLY_DEF::metadata_ModuleRef];

        static const QSet<QString> setSuspicious = {"VirtualProtect",      "VirtualAlloc",      "VirtualAllocEx",           "WriteProcessMemory",
                                                    "CreateRemoteThread",  "LoadLibrary",       "LoadLibraryA",             "LoadLibraryW",
                                                    "GetProcAddress",      "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
                                                    "NtSetInformationThread", "ZwSetInformationThread", "RtlDecompressBuffer", "NtUnmapViewOfSection"};

        QStringList listAll;
        QStringList listFlagged;

        if ((nForwardedSize > 0) && ((nModuleRefSize == 2) || (nModuleRefSize == 4))) {
            for (quint32 i = 0; i < nRows; i++) {
                QString sImport = _readNetString(baStrings, _readRowValue(cliInfo, nTable, i, 2 + nForwardedSize, nStringIndexSize));
                quint32 nScope = _readRowValue(cliInfo, nTable, i, 2 + nForwardedSize + nStringIndexSize, nModuleRefSize);
                QString sModule;

                if ((nScope >= 1) && (nScope <= nModuleRefs)) {
                    sModule = _readNetString(baStrings, pCliAssembly->getMetadataModuleRef(&cliInfo, (qint32)(nScope - 1)).nName);
                }

                QString sEntry = sModule.isEmpty() ? _escapeName(sImport) : (_escapeName(sModule) + "!" + _escapeName(sImport));

                listAll.append(sEntry);

                if (setSuspicious.contains(sImport)) {
                    listFlagged.append(sEntry);
                }
            }
        }

        if (!listFlagged.isEmpty()) {
            _addMarker(&result, "Suspicious P/Invoke", QString("Native APIs used by managed code: %1").arg(listFlagged.mid(0, 20).join(", ")));
        } else if (!listAll.isEmpty()) {
            _addMarker(&result, "P/Invoke", QString("%1 native import(s): %2").arg(listAll.count()).arg(listAll.mid(0, 12).join(", ")));
        }
    }

    delete pCliAssembly;
    file.close();

    return result;
}
