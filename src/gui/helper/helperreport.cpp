// DiE Helper (fork addition): exports one file's analysis (verdict, DiE detections, sections, entry point,
// ranked indicators, extra tables) as Markdown, JSON or a self-contained HTML page.
#include "helperreport.h"

#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QPair>
#include <QSaveFile>

#include "helperverdict.h"
#include "xformats.h"

typedef QList<QPair<QString, QString>> FACTS;

// ---------------------------------------------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------------------------------------------

static QString _hex(qint64 nValue)
{
    if (nValue < 0) {
        return QString("-");
    }

    return QString("0x%1").arg(QString::number((quint64)nValue, 16).toUpper());
}

static QString _hexAddress(XADDR nValue)
{
    return QString("0x%1").arg(QString::number((quint64)nValue, 16).toUpper());
}

static QString _bytesToHex(const QByteArray &baData)
{
    QStringList listBytes;

    for (qint32 i = 0; i < baData.size(); i++) {
        listBytes.append(QString("%1").arg((uint)(quint8)baData.at(i), 2, 16, QChar('0')).toUpper());
    }

    return listBytes.join(QChar(' '));
}

static QString _getFileType(const QString &sFileName, const HelperEvidence::RESULT &evidence)
{
    if (!evidence.bIsValid) {
        XBinary::FT fileType = XFormats::getPrefFileType(sFileName, XBinary::FT_FLAG_FORMATS);
        return XBinary::fileTypeIdToString(fileType);
    }

    QString sResult = QString("%1 %2").arg(evidence.bIs64 ? "PE64" : "PE32", evidence.bIsDll ? "DLL" : "EXE");

    if (evidence.bIsNET) {
        sResult += QString(" (.NET)");
    }

    return sResult;
}

static QString _getFlags(const HelperEvidence::SECTION &section)
{
    if (section.nIndex < 0) {
        return QString("-");
    }

    return QString("%1%2%3 (0x%4)")
        .arg(section.bRead ? "R" : "-", section.bWrite ? "W" : "-", section.bExecute ? "X" : "-")
        .arg(QString::number(section.nCharacteristics, 16).toUpper(), 8, QChar('0'));
}

static QString _getEntropy(double dEntropy)
{
    return (dEntropy < 0) ? QString("-") : QString::number(dEntropy, 'f', 2);
}

static QString _getLocation(const HelperEvidence::INDICATOR &indicator)
{
    if (indicator.location == HelperEvidence::LOCATION_HEX) {
        if (indicator.nSize > 0) {
            return QString("offset %1, %2 bytes").arg(_hex(indicator.nOffset)).arg(indicator.nSize);
        }

        return QString("offset %1").arg(_hex(indicator.nOffset));
    } else if (indicator.location == HelperEvidence::LOCATION_DISASM) {
        return QString("VA %1").arg(_hexAddress(indicator.nAddress));
    }

    return QString();
}

static QString _getLevel(HelperVerdict::LEVEL level)
{
    if (level == HelperVerdict::LEVEL_PACKED) {
        return QString("packed");
    } else if (level == HelperVerdict::LEVEL_SUSPICIOUS) {
        return QString("suspicious");
    }

    return QString("clean");
}

static QString _getSignatureSource(const XScanEngine::SCANSTRUCT &record)
{
    if (record.varInfo2.isEmpty()) {
        return QString();
    }

    QString sPath = QDir::fromNativeSeparators(record.varInfo2);
    QString sDatabase = sPath.contains("/db_custom/", Qt::CaseInsensitive) ? QString("custom DB") : QString("main DB");

    return QString("%1 (%2)").arg(QFileInfo(sPath).fileName(), sDatabase);
}

static QString _getEntryPointSectionName(const HelperEvidence::RESULT &evidence)
{
    for (qint32 i = 0; i < evidence.listSections.count(); i++) {
        if ((evidence.nEntryPointSection != -1) && (evidence.listSections.at(i).nIndex == evidence.nEntryPointSection)) {
            return QString("%1 (#%2)").arg(evidence.listSections.at(i).sName).arg(evidence.nEntryPointSection);
        }
    }

    return QString("-");
}

static bool _hasEntryPoint(const HelperEvidence::RESULT &evidence)
{
    return evidence.bIsValid && (evidence.nEntryPointRVA > 0);
}

// ---------------------------------------------------------------------------------------------------------------
// common content model: facts (key/value) and tables, rendered as Markdown or HTML
// ---------------------------------------------------------------------------------------------------------------

struct REPORT_CONTEXT {
    QString sFileName;
    QString sFilePath;
    qint64 nFileSize;
    QString sSha256;
    QString sType;
    QString sGenerated;
    HelperVerdict::RESULT verdict;
    QString sVerdict;  // plain one-liner, "n/a ..." for non-PE files
    QList<XScanEngine::SCANSTRUCT> listDetections;  // non-empty names only
};

static REPORT_CONTEXT _createContext(const QString &sFileName, const HelperEvidence::RESULT &evidence, const QList<XScanEngine::SCANSTRUCT> &listDetections)
{
    REPORT_CONTEXT result = {};

    QFileInfo fileInfo(sFileName);
    result.sFileName = fileInfo.fileName();
    result.sFilePath = QDir::toNativeSeparators(fileInfo.absoluteFilePath());
    result.nFileSize = evidence.bIsValid ? evidence.nFileSize : fileInfo.size();
    result.sSha256 = XBinary::getHash(XBinary::HASH_SHA256, sFileName).toUpper();
    result.sType = _getFileType(sFileName, evidence);
    result.sGenerated = QDateTime::currentDateTime().toString(Qt::ISODate);
    result.verdict = HelperVerdict::compute(evidence, listDetections);

    if (evidence.bIsValid) {
        result.sVerdict = result.verdict.sShort;
    } else {
        result.sVerdict = evidence.sError.isEmpty() ? QString("n/a (not a PE file)") : QString("n/a (%1)").arg(evidence.sError);
    }

    for (qint32 i = 0; i < listDetections.count(); i++) {
        if (!listDetections.at(i).sName.isEmpty()) {
            result.listDetections.append(listDetections.at(i));
        }
    }

    return result;
}

static FACTS _getFileFacts(const REPORT_CONTEXT &context, const HelperEvidence::RESULT &evidence)
{
    FACTS listResult;

    listResult.append(qMakePair(QString("File"), context.sFileName));
    listResult.append(qMakePair(QString("Path"), context.sFilePath));
    listResult.append(qMakePair(QString("Size"), QString("%1 bytes (%2)").arg(context.nFileSize).arg(_hex(context.nFileSize))));
    listResult.append(qMakePair(QString("SHA-256"), context.sSha256.isEmpty() ? QString("-") : context.sSha256));
    listResult.append(qMakePair(QString("Type"), context.sType));

    if (evidence.bIsValid) {
        listResult.append(qMakePair(QString("Image base"), _hexAddress(evidence.nImageBase)));
        listResult.append(qMakePair(QString("File entropy"), _getEntropy(evidence.dFileEntropy)));
        listResult.append(qMakePair(QString("Imports"), QString("%1 functions from %2 libraries").arg(evidence.nImportFunctions).arg(evidence.nImportLibraries)));

        if (evidence.nOverlayOffset >= 0) {
            listResult.append(qMakePair(QString("Overlay"), QString("offset %1, %2 bytes").arg(_hex(evidence.nOverlayOffset)).arg(evidence.nOverlaySize)));
        }

        if (!evidence.listTLSCallbacks.isEmpty()) {
            listResult.append(qMakePair(QString("TLS callbacks"), QString::number(evidence.listTLSCallbacks.count())));
        }
    }

    listResult.append(qMakePair(QString("Generated"), context.sGenerated));

    return listResult;
}

static FACTS _getVerdictFacts(const REPORT_CONTEXT &context, const HelperEvidence::RESULT &evidence)
{
    FACTS listResult;

    if (evidence.bIsValid) {
        listResult.append(qMakePair(QString("Level"), _getLevel(context.verdict.level)));
        listResult.append(qMakePair(QString("Packing score"), QString("%1 / 100").arg(context.verdict.nPackingScore)));
        listResult.append(qMakePair(QString("Obfuscation score"), QString("%1 / 100").arg(context.verdict.nObfuscationScore)));
        listResult.append(
            qMakePair(QString("Named packers / protectors"), context.verdict.listNamedPackers.isEmpty() ? QString("-") : context.verdict.listNamedPackers.join(", ")));
        listResult.append(
            qMakePair(QString("Named obfuscators"), context.verdict.listNamedObfuscators.isEmpty() ? QString("-") : context.verdict.listNamedObfuscators.join(", ")));
    }

    return listResult;
}

static FACTS _getEntryPointFacts(const HelperEvidence::RESULT &evidence)
{
    FACTS listResult;

    if (!_hasEntryPoint(evidence)) {
        return listResult;
    }

    listResult.append(qMakePair(QString("RVA"), _hex(evidence.nEntryPointRVA)));
    listResult.append(qMakePair(QString("Address"), _hexAddress(evidence.nEntryPointAddress)));
    listResult.append(qMakePair(QString("File offset"), (evidence.nEntryPointOffset >= 0) ? _hex(evidence.nEntryPointOffset) : QString("not backed by file data")));
    listResult.append(qMakePair(QString("Section"), _getEntryPointSectionName(evidence)));
    listResult.append(qMakePair(QString("Bytes"), evidence.baEntryPointBytes.isEmpty() ? QString("-") : _bytesToHex(evidence.baEntryPointBytes)));

    return listResult;
}

static HelperReport::EXTRA _getDetectionsTable(const REPORT_CONTEXT &context)
{
    HelperReport::EXTRA result;
    result.sTitle = QString("DiE detections");
    result.listHeaders = QStringList({"#", "Detection", "Info", "Signature"});

    for (qint32 i = 0; i < context.listDetections.count(); i++) {
        const XScanEngine::SCANSTRUCT &record = context.listDetections.at(i);
        result.listRows.append(QStringList({QString::number(i + 1), HelperVerdict::getRecordTitle(record), record.sInfo, _getSignatureSource(record)}));
    }

    return result;
}

static HelperReport::EXTRA _getSectionsTable(const HelperEvidence::RESULT &evidence)
{
    HelperReport::EXTRA result;
    result.sTitle = QString("Sections");
    result.listHeaders = QStringList({"#", "Name", "Raw offset", "Raw size", "RVA", "Virtual size", "Flags", "Entropy", "EP"});

    for (qint32 i = 0; i < evidence.listSections.count(); i++) {
        const HelperEvidence::SECTION &section = evidence.listSections.at(i);

        QStringList listRow;
        listRow.append((section.nIndex >= 0) ? QString::number(section.nIndex) : QString("-"));
        listRow.append(section.sName);
        listRow.append(_hex(section.nRawOffset));
        listRow.append(_hex(section.nRawSize));
        listRow.append(_hex(section.nRVA));
        listRow.append(_hex(section.nVirtualSize));
        listRow.append(_getFlags(section));
        listRow.append(_getEntropy(section.dEntropy));
        listRow.append(section.bContainsEntryPoint ? QString("EP") : QString());

        result.listRows.append(listRow);
    }

    return result;
}

static HelperReport::EXTRA _getIndicatorsTable(const REPORT_CONTEXT &context)
{
    HelperReport::EXTRA result;
    result.sTitle = QString("Indicators (ranked)");
    result.listHeaders = QStringList({"#", "Severity", "Category", "Weight", "Indicator", "Details", "Location"});

    for (qint32 i = 0; i < context.verdict.listIndicators.count(); i++) {
        const HelperEvidence::INDICATOR &indicator = context.verdict.listIndicators.at(i);

        result.listRows.append(QStringList({QString::number(i + 1), HelperEvidence::severityToString(indicator.severity), HelperEvidence::categoryToString(indicator.category),
                                            QString::number(indicator.nWeight), indicator.sTitle, indicator.sDetails, _getLocation(indicator)}));
    }

    return result;
}

// ---------------------------------------------------------------------------------------------------------------
// Markdown
// ---------------------------------------------------------------------------------------------------------------

static QString _mdEscape(const QString &sText)
{
    // CommonMark allows a backslash before any ASCII punctuation; escape what could start markup, a table cell
    // boundary or raw HTML. Line breaks would end a table row, so they become spaces.
    QString sResult;
    sResult.reserve(sText.size() + 8);

    for (qint32 i = 0; i < sText.size(); i++) {
        QChar c = sText.at(i);

        if ((c == QChar('\r')) || (c == QChar('\n')) || (c == QChar('\t'))) {
            sResult.append(QChar(' '));
        } else if (c.unicode() < 0x20) {
            // drop other control characters
        } else if (QString("\\`*_[]<>|#~&!").contains(c)) {
            sResult.append(QChar('\\'));
            sResult.append(c);
        } else {
            sResult.append(c);
        }
    }

    return sResult.trimmed();
}

static QString _mdTable(const QStringList &listHeaders, const QList<QStringList> &listRows)
{
    if (listHeaders.isEmpty()) {
        return QString();
    }

    QString sResult;
    qint32 nColumns = listHeaders.count();

    QStringList listCells;
    QStringList listRule;

    for (qint32 i = 0; i < nColumns; i++) {
        listCells.append(_mdEscape(listHeaders.at(i)));
        listRule.append(QString("---"));
    }

    sResult += QString("| %1 |\n").arg(listCells.join(" | "));
    sResult += QString("| %1 |\n").arg(listRule.join(" | "));

    for (qint32 i = 0; i < listRows.count(); i++) {
        listCells.clear();

        for (qint32 j = 0; j < nColumns; j++) {
            listCells.append((j < listRows.at(i).count()) ? _mdEscape(listRows.at(i).at(j)) : QString());
        }

        sResult += QString("| %1 |\n").arg(listCells.join(" | "));
    }

    return sResult;
}

static QString _mdFacts(const FACTS &listFacts)
{
    QList<QStringList> listRows;

    for (qint32 i = 0; i < listFacts.count(); i++) {
        listRows.append(QStringList({listFacts.at(i).first, listFacts.at(i).second}));
    }

    return _mdTable(QStringList({"Field", "Value"}), listRows);
}

static QString _mdSection(const HelperReport::EXTRA &table)
{
    QString sResult = QString("## %1\n\n").arg(_mdEscape(table.sTitle));

    if (table.listRows.isEmpty()) {
        sResult += QString("None.\n\n");
    } else {
        sResult += _mdTable(table.listHeaders, table.listRows) + QString("\n");
    }

    return sResult;
}

static QString _buildMarkdown(const REPORT_CONTEXT &context, const HelperEvidence::RESULT &evidence, const QList<HelperReport::EXTRA> &listExtras)
{
    QString sResult;

    sResult += QString("# DiE Helper report: %1\n\n").arg(_mdEscape(context.sFileName));
    sResult += _mdFacts(_getFileFacts(context, evidence)) + QString("\n");

    sResult += QString("## Verdict\n\n");
    sResult += QString("**%1**\n\n").arg(_mdEscape(context.sVerdict));

    FACTS listVerdict = _getVerdictFacts(context, evidence);

    if (!listVerdict.isEmpty()) {
        sResult += _mdFacts(listVerdict) + QString("\n");
    }

    sResult += _mdSection(_getDetectionsTable(context));

    if (evidence.bIsValid) {
        sResult += _mdSection(_getSectionsTable(evidence));

        sResult += QString("## Entry point\n\n");
        FACTS listEntryPoint = _getEntryPointFacts(evidence);

        if (listEntryPoint.isEmpty()) {
            sResult += QString("No entry point (AddressOfEntryPoint is 0).\n\n");
        } else {
            sResult += _mdFacts(listEntryPoint) + QString("\n");
        }

        sResult += _mdSection(_getIndicatorsTable(context));
    }

    for (qint32 i = 0; i < listExtras.count(); i++) {
        sResult += _mdSection(listExtras.at(i));
    }

    sResult += QString("---\n\nGenerated by DiE Helper (static analysis only; nothing was executed).\n");

    return sResult;
}

// ---------------------------------------------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------------------------------------------

static QString _htmlEscape(const QString &sText)
{
    QString sResult;
    sResult.reserve(sText.size() + 8);

    for (qint32 i = 0; i < sText.size(); i++) {
        QChar c = sText.at(i);

        if (c == QChar('&')) {
            sResult += QString("&amp;");
        } else if (c == QChar('<')) {
            sResult += QString("&lt;");
        } else if (c == QChar('>')) {
            sResult += QString("&gt;");
        } else if (c == QChar('"')) {
            sResult += QString("&quot;");
        } else if (c == QChar('\'')) {
            sResult += QString("&#39;");
        } else if ((c.unicode() < 0x20) && (c != QChar('\n')) && (c != QChar('\t'))) {
            // drop control characters
        } else {
            sResult.append(c);
        }
    }

    return sResult;
}

static QString _htmlTable(const QStringList &listHeaders, const QList<QStringList> &listRows, const QString &sClass)
{
    QString sResult = QString("<table class=\"%1\">\n<thead><tr>").arg(sClass);

    for (qint32 i = 0; i < listHeaders.count(); i++) {
        sResult += QString("<th>%1</th>").arg(_htmlEscape(listHeaders.at(i)));
    }

    sResult += QString("</tr></thead>\n<tbody>\n");

    for (qint32 i = 0; i < listRows.count(); i++) {
        sResult += QString("<tr>");

        for (qint32 j = 0; j < listHeaders.count(); j++) {
            sResult += QString("<td>%1</td>").arg((j < listRows.at(i).count()) ? _htmlEscape(listRows.at(i).at(j)) : QString());
        }

        sResult += QString("</tr>\n");
    }

    sResult += QString("</tbody>\n</table>\n");

    return sResult;
}

static QString _htmlFacts(const FACTS &listFacts)
{
    QString sResult = QString("<table class=\"facts\">\n<tbody>\n");

    for (qint32 i = 0; i < listFacts.count(); i++) {
        sResult += QString("<tr><th>%1</th><td>%2</td></tr>\n").arg(_htmlEscape(listFacts.at(i).first), _htmlEscape(listFacts.at(i).second));
    }

    sResult += QString("</tbody>\n</table>\n");

    return sResult;
}

static QString _htmlSection(const HelperReport::EXTRA &table)
{
    QString sResult = QString("<h2>%1</h2>\n").arg(_htmlEscape(table.sTitle));

    if (table.listRows.isEmpty()) {
        sResult += QString("<p class=\"muted\">None.</p>\n");
    } else {
        sResult += QString("<div class=\"scroll\">\n%1</div>\n").arg(_htmlTable(table.listHeaders, table.listRows, QString("grid")));
    }

    return sResult;
}

static QString _buildHtml(const REPORT_CONTEXT &context, const HelperEvidence::RESULT &evidence, const QList<HelperReport::EXTRA> &listExtras)
{
    QString sColor = evidence.bIsValid ? context.verdict.color.name() : QString("#808080");

    QString sResult;
    sResult += QString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    sResult += QString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    sResult += QString("<title>DiE Helper report - %1</title>\n").arg(_htmlEscape(context.sFileName));
    sResult += QString(
        "<style>\n"
        ":root { --bg: #ffffff; --fg: #1d1d1f; --muted: #6e6e73; --line: #d9d9de; --head: #f2f2f5; --stripe: #fafafc; }\n"
        "@media (prefers-color-scheme: dark) { :root { --bg: #1b1b1d; --fg: #e8e8ea; --muted: #9a9aa0; --line: #3a3a3e; --head: #26262a; --stripe: #202023; } }\n"
        "body { background: var(--bg); color: var(--fg); font: 14px/1.45 -apple-system, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 24px 16px; }\n"
        "main { max-width: 1200px; margin: 0 auto; }\n"
        "h1 { font-size: 22px; margin: 0 0 16px; word-break: break-all; }\n"
        "h2 { font-size: 17px; margin: 28px 0 8px; border-bottom: 1px solid var(--line); padding-bottom: 4px; }\n"
        "table { border-collapse: collapse; width: 100%; }\n"
        "th, td { border: 1px solid var(--line); padding: 4px 8px; text-align: left; vertical-align: top; }\n"
        "thead th, table.facts th { background: var(--head); font-weight: 600; }\n"
        "table.facts th { width: 200px; white-space: nowrap; }\n"
        "table.grid tbody tr:nth-child(even) { background: var(--stripe); }\n"
        "td { word-break: break-word; }\n"
        ".scroll { overflow-x: auto; }\n"
        ".mono, table.facts td, table.grid td { font-family: Consolas, 'Cascadia Mono', Menlo, monospace; font-size: 13px; }\n"
        ".verdict { border-left: 6px solid; padding: 8px 12px; margin: 8px 0 12px; font-size: 16px; font-weight: 600; background: var(--head); }\n"
        ".muted { color: var(--muted); }\n"
        "footer { margin-top: 32px; color: var(--muted); font-size: 12px; }\n"
        "</style>\n</head>\n<body>\n<main>\n");

    sResult += QString("<h1>DiE Helper report: %1</h1>\n").arg(_htmlEscape(context.sFileName));
    sResult += _htmlFacts(_getFileFacts(context, evidence));

    sResult += QString("<h2>Verdict</h2>\n");
    sResult += QString("<div class=\"verdict\" style=\"border-color: %1\">%2</div>\n").arg(sColor, _htmlEscape(context.sVerdict));

    FACTS listVerdict = _getVerdictFacts(context, evidence);

    if (!listVerdict.isEmpty()) {
        sResult += _htmlFacts(listVerdict);
    }

    sResult += _htmlSection(_getDetectionsTable(context));

    if (evidence.bIsValid) {
        sResult += _htmlSection(_getSectionsTable(evidence));

        sResult += QString("<h2>Entry point</h2>\n");
        FACTS listEntryPoint = _getEntryPointFacts(evidence);

        if (listEntryPoint.isEmpty()) {
            sResult += QString("<p class=\"muted\">No entry point (AddressOfEntryPoint is 0).</p>\n");
        } else {
            sResult += _htmlFacts(listEntryPoint);
        }

        sResult += _htmlSection(_getIndicatorsTable(context));
    }

    for (qint32 i = 0; i < listExtras.count(); i++) {
        sResult += _htmlSection(listExtras.at(i));
    }

    sResult += QString("<footer>Generated by DiE Helper on %1 (static analysis only; nothing was executed).</footer>\n").arg(_htmlEscape(context.sGenerated));
    sResult += QString("</main>\n</body>\n</html>\n");

    return sResult;
}

// ---------------------------------------------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------------------------------------------

static QJsonArray _jsonStringList(const QStringList &listStrings)
{
    QJsonArray result;

    for (qint32 i = 0; i < listStrings.count(); i++) {
        result.append(listStrings.at(i));
    }

    return result;
}

static QString _buildJson(const REPORT_CONTEXT &context, const HelperEvidence::RESULT &evidence, const QList<HelperReport::EXTRA> &listExtras)
{
    QJsonObject jsonRoot;
    jsonRoot["generator"] = QString("DiE Helper");
    jsonRoot["generated"] = context.sGenerated;

    {
        QJsonObject jsonFile;
        jsonFile["name"] = context.sFileName;
        jsonFile["path"] = context.sFilePath;
        jsonFile["size"] = context.nFileSize;
        jsonFile["sha256"] = context.sSha256;
        jsonFile["type"] = context.sType;
        jsonFile["isPE"] = evidence.bIsValid;

        if (evidence.bIsValid) {
            jsonFile["is64"] = evidence.bIs64;
            jsonFile["isDll"] = evidence.bIsDll;
            jsonFile["isNET"] = evidence.bIsNET;
            jsonFile["imageBase"] = _hexAddress(evidence.nImageBase);
            jsonFile["entropy"] = evidence.dFileEntropy;
            jsonFile["importLibraries"] = evidence.nImportLibraries;
            jsonFile["importFunctions"] = evidence.nImportFunctions;
            jsonFile["notableImports"] = _jsonStringList(evidence.listNotableImports);
            jsonFile["tlsCallbacks"] = evidence.listTLSCallbacks.count();
            jsonFile["overlayOffset"] = evidence.nOverlayOffset;
            jsonFile["overlaySize"] = evidence.nOverlaySize;
        } else if (!evidence.sError.isEmpty()) {
            jsonFile["error"] = evidence.sError;
        }

        jsonRoot["file"] = jsonFile;
    }

    {
        QJsonObject jsonVerdict;
        jsonVerdict["summary"] = context.sVerdict;

        if (evidence.bIsValid) {
            jsonVerdict["level"] = _getLevel(context.verdict.level);
            jsonVerdict["packingScore"] = context.verdict.nPackingScore;
            jsonVerdict["obfuscationScore"] = context.verdict.nObfuscationScore;
            jsonVerdict["namedPackers"] = _jsonStringList(context.verdict.listNamedPackers);
            jsonVerdict["namedObfuscators"] = _jsonStringList(context.verdict.listNamedObfuscators);
        } else {
            jsonVerdict["level"] = QString("n/a");
        }

        jsonRoot["verdict"] = jsonVerdict;
    }

    {
        QJsonArray jsonDetections;

        for (qint32 i = 0; i < context.listDetections.count(); i++) {
            const XScanEngine::SCANSTRUCT &record = context.listDetections.at(i);

            QJsonObject jsonRecord;
            jsonRecord["title"] = HelperVerdict::getRecordTitle(record);
            jsonRecord["type"] = record.sType;
            jsonRecord["name"] = record.sName;
            jsonRecord["version"] = record.sVersion;
            jsonRecord["info"] = record.sInfo;
            jsonRecord["heuristic"] = (record.bIsHeuristic || record.bIsAHeuristic);
            jsonRecord["signature"] = _getSignatureSource(record);

            jsonDetections.append(jsonRecord);
        }

        jsonRoot["detections"] = jsonDetections;
    }

    if (evidence.bIsValid) {
        QJsonArray jsonSections;

        for (qint32 i = 0; i < evidence.listSections.count(); i++) {
            const HelperEvidence::SECTION &section = evidence.listSections.at(i);

            QJsonObject jsonSection;
            jsonSection["index"] = section.nIndex;
            jsonSection["name"] = section.sName;
            jsonSection["rawOffset"] = section.nRawOffset;
            jsonSection["rawSize"] = section.nRawSize;
            jsonSection["rva"] = section.nRVA;
            jsonSection["virtualSize"] = section.nVirtualSize;
            jsonSection["characteristics"] = (qint64)section.nCharacteristics;
            jsonSection["flags"] = QString("%1%2%3").arg(section.bRead ? "R" : "-", section.bWrite ? "W" : "-", section.bExecute ? "X" : "-");
            jsonSection["entropy"] = (section.dEntropy < 0) ? QJsonValue() : QJsonValue(section.dEntropy);
            jsonSection["containsEntryPoint"] = section.bContainsEntryPoint;
            jsonSection["unusualName"] = section.bIsUnusualName;

            jsonSections.append(jsonSection);
        }

        jsonRoot["sections"] = jsonSections;

        if (_hasEntryPoint(evidence)) {
            QJsonObject jsonEntryPoint;
            jsonEntryPoint["rva"] = evidence.nEntryPointRVA;
            jsonEntryPoint["address"] = _hexAddress(evidence.nEntryPointAddress);
            jsonEntryPoint["offset"] = evidence.nEntryPointOffset;
            jsonEntryPoint["section"] = evidence.nEntryPointSection;
            jsonEntryPoint["bytes"] = QString::fromLatin1(evidence.baEntryPointBytes.toHex().toUpper());

            jsonRoot["entryPoint"] = jsonEntryPoint;
        } else {
            jsonRoot["entryPoint"] = QJsonValue();
        }

        QJsonArray jsonIndicators;

        for (qint32 i = 0; i < context.verdict.listIndicators.count(); i++) {
            const HelperEvidence::INDICATOR &indicator = context.verdict.listIndicators.at(i);

            QJsonObject jsonIndicator;
            jsonIndicator["rank"] = i + 1;
            jsonIndicator["id"] = indicator.sId;
            jsonIndicator["category"] = HelperEvidence::categoryToString(indicator.category);
            jsonIndicator["severity"] = HelperEvidence::severityToString(indicator.severity);
            jsonIndicator["weight"] = indicator.nWeight;
            jsonIndicator["title"] = indicator.sTitle;
            jsonIndicator["details"] = indicator.sDetails;

            if (indicator.location == HelperEvidence::LOCATION_HEX) {
                jsonIndicator["offset"] = indicator.nOffset;
                jsonIndicator["size"] = indicator.nSize;
            } else if (indicator.location == HelperEvidence::LOCATION_DISASM) {
                jsonIndicator["address"] = _hexAddress(indicator.nAddress);
            }

            jsonIndicators.append(jsonIndicator);
        }

        jsonRoot["indicators"] = jsonIndicators;
    }

    {
        QJsonArray jsonExtras;

        for (qint32 i = 0; i < listExtras.count(); i++) {
            const HelperReport::EXTRA &extra = listExtras.at(i);

            QJsonArray jsonRows;

            for (qint32 j = 0; j < extra.listRows.count(); j++) {
                jsonRows.append(_jsonStringList(extra.listRows.at(j)));
            }

            QJsonObject jsonExtra;
            jsonExtra["title"] = extra.sTitle;
            jsonExtra["headers"] = _jsonStringList(extra.listHeaders);
            jsonExtra["rows"] = jsonRows;

            jsonExtras.append(jsonExtra);
        }

        jsonRoot["extras"] = jsonExtras;
    }

    return QString::fromUtf8(QJsonDocument(jsonRoot).toJson(QJsonDocument::Indented));
}

// ---------------------------------------------------------------------------------------------------------------
// public
// ---------------------------------------------------------------------------------------------------------------

QString HelperReport::build(FORMAT format, const QString &sFileName, const HelperEvidence::RESULT &evidence, const QList<XScanEngine::SCANSTRUCT> &listDetections,
                            const QList<EXTRA> &listExtras)
{
    REPORT_CONTEXT context = _createContext(sFileName, evidence, listDetections);

    if (format == FORMAT_JSON) {
        return _buildJson(context, evidence, listExtras);
    } else if (format == FORMAT_HTML) {
        return _buildHtml(context, evidence, listExtras);
    }

    return _buildMarkdown(context, evidence, listExtras);
}

bool HelperReport::save(const QString &sOutputFileName, const QString &sContent)
{
    QSaveFile file(sOutputFileName);

    if (!file.open(QIODevice::WriteOnly)) {
        return false;
    }

    QByteArray baData = sContent.toUtf8();

    if (file.write(baData) != baData.size()) {
        file.cancelWriting();
        return false;
    }

    return file.commit();
}

HelperReport::FORMAT HelperReport::formatFromFileName(const QString &sFileName)
{
    QString sSuffix = QFileInfo(sFileName).suffix().toLower();

    if (sSuffix == QString("json")) {
        return FORMAT_JSON;
    } else if ((sSuffix == QString("html")) || (sSuffix == QString("htm"))) {
        return FORMAT_HTML;
    }

    return FORMAT_MARKDOWN;
}
