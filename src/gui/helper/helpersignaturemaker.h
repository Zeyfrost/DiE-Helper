// DiE Helper (fork addition): turns the entry point code of a PE file into a DiE detection rule
// (PE.compareEP pattern with wildcarded addresses, followed jumps) and saves it to the custom database.
#ifndef HELPERSIGNATUREMAKER_H
#define HELPERSIGNATUREMAKER_H

#include <QString>
#include <QStringList>

class HelperSignatureMaker {
public:
    struct RESULT {
        bool bIsValid;
        QString sError;
        QString sPattern;        // compareEP pattern: hex, ".." = any byte, "$$"/"$$$$$$$$" = follow rel8/rel32 jump
        QString sScript;         // complete .sg file text (ES5)
        QStringList listNotes;   // what was wildcarded/followed, why the walk stopped, self-check result
    };

    // Static only: reads the file, disassembles from the entry point, never executes anything.
    static RESULT makeFromEntryPoint(const QString &sFileName, const QString &sType, const QString &sName, qint32 nInstructions = 16);
    // Writes <sDbCustomPath>/PE/<type>_<Name>.2.sg ($data is expanded). result.sScript is written as is (the caller may
    // have edited it); if it is empty, a script is generated from result.sPattern. *psFileName gets the target path
    // even on failure (e.g. "exists" when bOverwrite is false).
    static bool save(const QString &sDbCustomPath, const RESULT &result, const QString &sType, const QString &sName, bool bOverwrite, QString *psFileName,
                     QString *psError);
};

#endif  // HELPERSIGNATUREMAKER_H
