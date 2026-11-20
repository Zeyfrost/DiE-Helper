// DiE Helper (fork addition): exports one file's analysis (verdict, DiE detections, sections, entry point,
// ranked indicators, extra tables) as Markdown, JSON or a self-contained HTML page.
#ifndef HELPERREPORT_H
#define HELPERREPORT_H

#include <QList>
#include <QString>
#include <QStringList>

#include "helperevidence.h"
#include "xscanengine.h"

class HelperReport {
public:
    enum FORMAT {
        FORMAT_MARKDOWN = 0,
        FORMAT_JSON,
        FORMAT_HTML
    };

    // An additional table appended to the report (e.g. OEP candidates, decoded strings, action log)
    struct EXTRA {
        QString sTitle;
        QStringList listHeaders;
        QList<QStringList> listRows;
    };

    // Computes the verdict itself (HelperVerdict::compute). Reads the file once for the SHA-256.
    static QString build(FORMAT format, const QString &sFileName, const HelperEvidence::RESULT &evidence, const QList<XScanEngine::SCANSTRUCT> &listDetections,
                         const QList<EXTRA> &listExtras);
    static bool save(const QString &sOutputFileName, const QString &sContent);  // UTF-8, atomic (QSaveFile)
    static FORMAT formatFromFileName(const QString &sFileName);                 // .json / .htm(l) / anything else = Markdown
};

#endif  // HELPERREPORT_H
