// DiE Helper (fork addition): small PE edits, always applied to a NEW copy of the file
// (set entry point, strip/save overlay, save a byte range, restore section flags, rename a section,
// remove the TLS directory, fix the checksum). The input file is only read.
#ifndef HELPERPESURGERY_H
#define HELPERPESURGERY_H

#include <QStringList>

#include "xbinary.h"

class HelperPeSurgery {
public:
    struct RESULT {
        bool bSuccess;
        QString sError;
        QStringList listLog;
    };

    static RESULT setEntryPoint(const QString &sInput, const QString &sOutput, qint64 nRVA);
    static RESULT stripOverlay(const QString &sInput, const QString &sOutput);
    static RESULT saveRange(const QString &sInput, const QString &sOutput, qint64 nOffset, qint64 nSize);
    // W+X sections: drop W from code sections (EP / ".text" / "CODE"), drop X from well-known data sections
    static RESULT restoreSectionFlags(const QString &sInput, const QString &sOutput);
    static RESULT renameSection(const QString &sInput, const QString &sOutput, qint32 nSection, const QString &sName);
    // Clears the TLS data directory so TLS callbacks are not run by the loader (anti-debug tricks live there)
    static RESULT removeTls(const QString &sInput, const QString &sOutput);
    static RESULT fixChecksum(const QString &sInput, const QString &sOutput);

private:
    static bool _openCopy(const QString &sInput, const QString &sOutput, class QFile *pFile, RESULT *pResult);
};

#endif  // HELPERPESURGERY_H
