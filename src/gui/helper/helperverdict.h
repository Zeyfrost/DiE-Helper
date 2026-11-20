// DiE Helper (fork addition): turns DiE's detections + the file evidence into one ranked indicator list,
// the packing / obfuscation scores and a verdict. Shared by the Packing tab and the batch scan.
#ifndef HELPERVERDICT_H
#define HELPERVERDICT_H

#include <QColor>
#include <QCoreApplication>
#include <QStringList>

#include "helperevidence.h"
#include "xscanengine.h"

class HelperVerdict {
    Q_DECLARE_TR_FUNCTIONS(HelperVerdict)

public:
    enum LEVEL {
        LEVEL_CLEAN = 0,     // green
        LEVEL_SUSPICIOUS,    // orange: possibly packed / obfuscation or anti-analysis signs
        LEVEL_PACKED         // red: named packer/protector/obfuscator or likely packed
    };

    struct RESULT {
        LEVEL level;
        QColor color;
        QString sHeadlineHtml;   // "PACKED / PROTECTED: UPX 5.30<br>..." (HTML)
        QString sShort;          // plain one-liner for tables/CSV: "Packed: UPX 5.30 + anti-analysis"
        QString sTabTitle;       // "Packing: UPX 5.30"
        qint32 nPackingScore;    // 0..100
        qint32 nObfuscationScore;
        QStringList listNamedPackers;      // non-heuristic packer/protector/cryptor detections ("UPX 5.30")
        QStringList listNamedObfuscators;  // non-heuristic obfuscator detections
        QList<HelperEvidence::INDICATOR> listIndicators;  // DiE detections + evidence, ranked (facts last)
    };

    static RESULT compute(const HelperEvidence::RESULT &evidence, const QList<XScanEngine::SCANSTRUCT> &listRecords);

    static QList<HelperEvidence::INDICATOR> getDetectionIndicators(const QList<XScanEngine::SCANSTRUCT> &listRecords);
    static QString getRecordTitle(const XScanEngine::SCANSTRUCT &scanStruct);  // "(Heur) Packer: UPX (5.30)"
    static bool isObfuscatorType(const QString &sType, const QString &sName);
};

#endif  // HELPERVERDICT_H
