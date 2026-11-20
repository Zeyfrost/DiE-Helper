// DiE Helper (fork addition): loads unpacking hints from a JSON file and looks them up by DiE detection name.
#include "helperhints.h"

#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>

static QStringList _toStringList(const QJsonValue &value)
{
    QStringList listResult;

    if (value.isArray()) {
        const QJsonArray array = value.toArray();

        for (qint32 i = 0; i < array.count(); i++) {
            QString sValue = array.at(i).toString().trimmed();

            if (!sValue.isEmpty()) {
                listResult.append(sValue);
            }
        }
    } else if (value.isString()) {
        QString sValue = value.toString().trimmed();

        if (!sValue.isEmpty()) {
            listResult.append(sValue);
        }
    }

    return listResult;
}

HelperHints::HelperHints()
{
    clear();
}

void HelperHints::clear()
{
    m_listHints.clear();
    m_mapIndex.clear();
    m_nGenericIndex = -1;
    m_bIsLoaded = false;
    m_sFileName.clear();
    m_sLastError.clear();
}

bool HelperHints::load(const QString &sFileName)
{
    clear();
    m_sFileName = sFileName;

    QFile file(sFileName);

    if (!file.open(QIODevice::ReadOnly)) {
        m_sLastError = QString("Cannot open hints file: %1 (%2)").arg(sFileName, file.errorString());
        return false;
    }

    QByteArray baData = file.readAll();
    file.close();

    QJsonParseError parseError = {};
    QJsonDocument document = QJsonDocument::fromJson(baData, &parseError);

    if (parseError.error != QJsonParseError::NoError) {
        // Report line/column as well as the offset: editors show those
        qint32 nLine = 1;
        qint32 nColumn = 1;

        for (qint32 i = 0; (i < parseError.offset) && (i < baData.size()); i++) {
            if (baData.at(i) == '\n') {
                nLine++;
                nColumn = 1;
            } else {
                nColumn++;
            }
        }

        m_sLastError = QString("JSON error in %1 at line %2, column %3: %4").arg(sFileName).arg(nLine).arg(nColumn).arg(parseError.errorString());
        return false;
    }

    if (!document.isObject()) {
        m_sLastError = QString("%1: the top level must be a JSON object keyed by detection name").arg(sFileName);
        return false;
    }

    const QJsonObject root = document.object();
    const QStringList listKeys = root.keys();

    for (qint32 i = 0; i < listKeys.count(); i++) {
        const QString sKey = listKeys.at(i);

        if (sKey.startsWith(QChar('_'))) {
            continue;  // "_format", "_comment", ...
        }

        const QJsonValue value = root.value(sKey);

        if (!value.isObject()) {
            continue;
        }

        const QJsonObject object = value.toObject();

        HINT hint = {};
        hint.sKey = sKey;
        hint.sName = object.value("name").toString(sKey);
        hint.sCategory = object.value("category").toString();
        hint.listAliases = _toStringList(object.value("aliases"));
        hint.sWhatItDoes = object.value("what_it_does").toString();
        hint.sOepPattern = object.value("oep_pattern").toString();
        hint.listTryFirst = _toStringList(object.value("try_first"));
        hint.listTools = _toStringList(object.value("tools"));
        hint.listPitfalls = _toStringList(object.value("pitfalls"));
        hint.sNotes = object.value("notes").toString();
        hint.sDllNotes = object.value("dll_notes").toString();

        qint32 nIndex = m_listHints.count();
        m_listHints.append(hint);

        if ((m_nGenericIndex == -1) && (hint.sCategory.compare("generic", Qt::CaseInsensitive) == 0)) {
            m_nGenericIndex = nIndex;
        }
    }

    // Index keys first, then names, then aliases, so an explicit key always wins a collision
    for (qint32 i = 0; i < m_listHints.count(); i++) {
        _addIndex(m_listHints.at(i).sKey, i);
    }

    for (qint32 i = 0; i < m_listHints.count(); i++) {
        _addIndex(m_listHints.at(i).sName, i);
    }

    for (qint32 i = 0; i < m_listHints.count(); i++) {
        for (qint32 j = 0; j < m_listHints.at(i).listAliases.count(); j++) {
            _addIndex(m_listHints.at(i).listAliases.at(j), i);
        }
    }

    m_bIsLoaded = true;

    return true;
}

void HelperHints::_addIndex(const QString &sName, qint32 nIndex)
{
    QString sNormalized = normalize(sName);

    if (!sNormalized.isEmpty() && !m_mapIndex.contains(sNormalized)) {
        m_mapIndex.insert(sNormalized, nIndex);
    }

    // "Themida/Winlicense" is also reachable as "Themida" and "Winlicense"
    if (sName.contains(QChar('/'))) {
        const QStringList listParts = sName.split(QChar('/'), Qt::SkipEmptyParts);

        for (qint32 i = 0; i < listParts.count(); i++) {
            QString sPart = normalize(listParts.at(i));

            if (!sPart.isEmpty() && !m_mapIndex.contains(sPart)) {
                m_mapIndex.insert(sPart, nIndex);
            }
        }
    }
}

qint32 HelperHints::count() const
{
    return m_listHints.count();
}

bool HelperHints::isLoaded() const
{
    return m_bIsLoaded;
}

QString HelperHints::getFileName() const
{
    return m_sFileName;
}

QString HelperHints::getLastError() const
{
    return m_sLastError;
}

bool HelperHints::lookup(const QString &sName, HINT *pHint) const
{
    QString sNormalized = normalize(sName);

    if (sNormalized.isEmpty()) {
        return false;
    }

    qint32 nIndex = m_mapIndex.value(sNormalized, -1);

    if (nIndex == -1) {
        const QStringList listParts = sName.split(QChar('/'), Qt::SkipEmptyParts);

        for (qint32 i = 0; (i < listParts.count()) && (nIndex == -1); i++) {
            nIndex = m_mapIndex.value(normalize(listParts.at(i)), -1);
        }
    }

    if (nIndex == -1) {
        return false;
    }

    if (pHint) {
        *pHint = m_listHints.at(nIndex);
    }

    return true;
}

bool HelperHints::getGeneric(HINT *pHint) const
{
    if (m_nGenericIndex == -1) {
        return false;
    }

    if (pHint) {
        *pHint = m_listHints.at(m_nGenericIndex);
    }

    return true;
}

QString HelperHints::normalize(const QString &sName)
{
    static const QRegularExpression regExpBrackets("\\([^)]*\\)|\\[[^\\]]*\\]");
    // v1.2, 3.x, 2.0b, 1.10.4, 5 ... (a word that is only a version)
    static const QRegularExpression regExpVersion("(?<![\\w.])v?\\d+(?:\\.(?:\\d+|x))*[a-z]?(?![\\w])", QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression regExpSpaces("\\s+");

    QString sResult = sName.toLower();
    sResult.remove(regExpBrackets);
    sResult.replace(QChar('_'), QChar(' '));
    sResult.remove(regExpVersion);
    sResult.replace(regExpSpaces, " ");
    sResult = sResult.trimmed();

    // trim leftover punctuation at both ends ("upx -", ": themida"), but keep a leading '.' (".net reactor")
    while (!sResult.isEmpty() && QString("-:,;/").contains(sResult.at(sResult.size() - 1))) {
        sResult.chop(1);
        sResult = sResult.trimmed();
    }

    while (!sResult.isEmpty() && QString("-:,;/").contains(sResult.at(0))) {
        sResult.remove(0, 1);
        sResult = sResult.trimmed();
    }

    return sResult;
}

bool HelperHints::isPackingType(const QString &sType)
{
    QString sValue = sType.trimmed().toLower();

    while (sValue.startsWith(QChar('~')) || sValue.startsWith(QChar('!'))) {
        sValue.remove(0, 1);
    }

    static const char *pszTypes[] = {"packer", "protector", "protection", "cryptor", "crypter", "obfuscator", "compressor", "virtualizer"};

    for (const char *pszType : pszTypes) {
        if (sValue.contains(QLatin1String(pszType))) {
            return true;
        }
    }

    return false;
}
