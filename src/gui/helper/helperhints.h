// DiE Helper (fork addition): loads unpacking hints from a JSON file and looks them up by DiE detection name.
#ifndef HELPERHINTS_H
#define HELPERHINTS_H

#include <QHash>
#include <QList>
#include <QString>
#include <QStringList>

class HelperHints {
public:
    struct HINT {
        QString sKey;
        QString sName;
        QString sCategory;
        QStringList listAliases;
        QString sWhatItDoes;
        QString sOepPattern;
        QStringList listTryFirst;
        QStringList listTools;
        QStringList listPitfalls;
        QString sNotes;
        QString sDllNotes;
    };

    HelperHints();

    bool load(const QString &sFileName);
    void clear();
    qint32 count() const;
    bool isLoaded() const;
    QString getFileName() const;
    QString getLastError() const;

    // Matches the detection name (case-insensitive, versions ignored, each "a/b" part tried).
    bool lookup(const QString &sName, HINT *pHint) const;
    // The entry whose category is "generic" (fallback for unknown packers).
    bool getGeneric(HINT *pHint) const;

    static QString normalize(const QString &sName);
    // true for packer / protector / cryptor / obfuscator ... types, heuristic prefixes ('~', '!') included
    static bool isPackingType(const QString &sType);

private:
    void _addIndex(const QString &sName, qint32 nIndex);

    QList<HINT> m_listHints;
    QHash<QString, qint32> m_mapIndex;
    qint32 m_nGenericIndex;
    bool m_bIsLoaded;
    QString m_sFileName;
    QString m_sLastError;
};

#endif  // HELPERHINTS_H
