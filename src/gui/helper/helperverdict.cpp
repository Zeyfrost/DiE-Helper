// DiE Helper (fork addition): turns DiE's detections + the file evidence into one ranked indicator list,
// the packing / obfuscation scores and a verdict. Shared by the Packing tab and the batch scan.
#include "helperverdict.h"

#include <QDir>
#include <QSet>
#include <algorithm>

#include "helperhints.h"

static const qint32 N_WEIGHT_DETECTION = 50;            // a named signature match from DiE
static const qint32 N_WEIGHT_DETECTION_HEURISTIC = 20;  // a DiE heuristic match

static void _rank(QList<HelperEvidence::INDICATOR> *pList)
{
    std::stable_sort(pList->begin(), pList->end(), [](const HelperEvidence::INDICATOR &a, const HelperEvidence::INDICATOR &b) {
        bool bInfoA = (a.category == HelperEvidence::CATEGORY_INFO);
        bool bInfoB = (b.category == HelperEvidence::CATEGORY_INFO);

        if (bInfoA != bInfoB) {
            return !bInfoA;  // facts last
        }

        return a.nWeight > b.nWeight;
    });
}

bool HelperVerdict::isObfuscatorType(const QString &sType, const QString &sName)
{
    return sType.contains("obfusc", Qt::CaseInsensitive) || sName.contains("obfusc", Qt::CaseInsensitive);
}

QString HelperVerdict::getRecordTitle(const XScanEngine::SCANSTRUCT &scanStruct)
{
    QString sResult;

    if (scanStruct.bIsHeuristic) {
        sResult += "(Heur) ";
    } else if (scanStruct.bIsAHeuristic) {
        sResult += "(A-Heur) ";
    }

    QString sType = XScanEngine::translateType(scanStruct.sType);

    if (!sType.isEmpty()) {
        sResult += sType + ": ";
    }

    sResult += scanStruct.sName;

    if (!scanStruct.sVersion.isEmpty()) {
        sResult += QString(" (%1)").arg(scanStruct.sVersion);
    }

    return sResult;
}

QList<HelperEvidence::INDICATOR> HelperVerdict::getDetectionIndicators(const QList<XScanEngine::SCANSTRUCT> &listRecords)
{
    // DiE's own detections are the strongest evidence; heuristic ones carry their reasons in sInfo
    QList<HelperEvidence::INDICATOR> listResult;

    for (qint32 i = 0; i < listRecords.count(); i++) {
        const XScanEngine::SCANSTRUCT &record = listRecords.at(i);

        if (record.sName.isEmpty()) {
            continue;
        }

        bool bIsObfuscator = isObfuscatorType(record.sType, record.sName);
        bool bIsAnti = record.sType.contains("anti", Qt::CaseInsensitive);

        if (!bIsObfuscator && !bIsAnti && !HelperHints::isPackingType(record.sType)) {
            continue;
        }

        bool bIsHeuristic = record.bIsHeuristic || record.bIsAHeuristic;

        HelperEvidence::INDICATOR indicator = {};
        indicator.sId = QString("die_detection");
        indicator.category = bIsAnti ? HelperEvidence::CATEGORY_ANTIANALYSIS : (bIsObfuscator ? HelperEvidence::CATEGORY_OBFUSCATION : HelperEvidence::CATEGORY_PACKING);
        indicator.severity = bIsHeuristic ? HelperEvidence::SEVERITY_MEDIUM : HelperEvidence::SEVERITY_HIGH;
        indicator.nWeight = bIsHeuristic ? N_WEIGHT_DETECTION_HEURISTIC : N_WEIGHT_DETECTION;
        indicator.sTitle = QString("DiE: %1").arg(getRecordTitle(record));

        QStringList listDetails;

        if (!record.sInfo.isEmpty()) {
            listDetails.append(record.sInfo);
        }

        if (!record.varInfo.isEmpty()) {
            QString sPath = QDir::fromNativeSeparators(record.varInfo2);
            listDetails.append(tr("signature %1 (%2)").arg(record.varInfo, sPath.contains("/db_custom/", Qt::CaseInsensitive) ? tr("custom DB") : tr("main DB")));
        }

        indicator.sDetails = listDetails.join(QString(" - "));
        indicator.location = HelperEvidence::LOCATION_NONE;
        indicator.nOffset = -1;

        listResult.append(indicator);
    }

    return listResult;
}

HelperVerdict::RESULT HelperVerdict::compute(const HelperEvidence::RESULT &evidence, const QList<XScanEngine::SCANSTRUCT> &listRecords)
{
    RESULT result = {};

    // --- merge DiE detections with the file evidence, rank everything by weight
    QList<HelperEvidence::INDICATOR> listDetections = getDetectionIndicators(listRecords);
    QList<HelperEvidence::INDICATOR> listAll = listDetections + evidence.listIndicators;
    _rank(&listAll);

    qint32 nPackingScore = evidence.nPackingScore;

    for (qint32 i = 0; i < listRecords.count(); i++) {
        const XScanEngine::SCANSTRUCT &record = listRecords.at(i);

        if (record.sName.isEmpty() || record.bIsHeuristic || record.bIsAHeuristic) {
            continue;
        }

        QString sLabel = record.sName + (record.sVersion.isEmpty() ? QString() : QString(" %1").arg(record.sVersion));

        if (isObfuscatorType(record.sType, record.sName)) {
            result.listNamedObfuscators.append(sLabel);
        } else if (HelperHints::isPackingType(record.sType)) {
            result.listNamedPackers.append(sLabel);
        }
    }

    for (qint32 i = 0; i < listDetections.count(); i++) {
        if (listDetections.at(i).category == HelperEvidence::CATEGORY_PACKING) {
            nPackingScore += listDetections.at(i).nWeight;
        }
    }

    nPackingScore = qMin(100, nPackingScore);

    // While the file is packed, some "obfuscation" facts are just side effects of the packing: the stub
    // resolves imports itself and the strings are compressed. Keep them visible, but do not let them
    // claim the file is obfuscated on top of being packed.
    if (!result.listNamedPackers.isEmpty() || (nPackingScore >= 50)) {
        static const QSet<QString> stExplainedByPacking = {"dynamic_api_resolution", "low_string_density", "code_entropy_elevated"};

        for (qint32 i = 0; i < listAll.count(); i++) {
            HelperEvidence::INDICATOR &indicator = listAll[i];

            if (stExplainedByPacking.contains(indicator.sId)) {
                indicator.severity = HelperEvidence::SEVERITY_LOW;
                indicator.nWeight = qMin(indicator.nWeight, 2);
                indicator.sDetails += tr(" (expected while the file is packed)");
            }
        }

        _rank(&listAll);
    }

    qint32 nObfuscationScore = 0;

    for (qint32 i = 0; i < listAll.count(); i++) {
        if ((listAll.at(i).category == HelperEvidence::CATEGORY_OBFUSCATION) || (listAll.at(i).category == HelperEvidence::CATEGORY_ANTIANALYSIS)) {
            nObfuscationScore += listAll.at(i).nWeight;
        }
    }

    nObfuscationScore = qMin(100, nObfuscationScore);

    // --- verdict
    const QColor colorRed(220, 60, 60);
    const QColor colorOrange(230, 150, 30);
    const QColor colorGreen(70, 170, 90);

    QString sHeadline;
    QString sShort;
    QString sTabTitle;

    if (!result.listNamedPackers.isEmpty()) {
        sHeadline = tr("PACKED / PROTECTED: %1").arg(result.listNamedPackers.join(", "));
        sShort = tr("Packed: %1").arg(result.listNamedPackers.join(", "));
        sTabTitle = tr("Packing: %1").arg(result.listNamedPackers.first());
        result.level = LEVEL_PACKED;
    } else if (nPackingScore >= 50) {
        sHeadline = tr("LIKELY PACKED - unknown packer (no signature matched)");
        sShort = tr("Likely packed (unknown packer)");
        sTabTitle = tr("Packing: likely packed");
        result.level = LEVEL_PACKED;
    } else if (nPackingScore >= 25) {
        sHeadline = tr("POSSIBLY PACKED - weak indicators only");
        sShort = tr("Possibly packed");
        sTabTitle = tr("Packing: possibly packed");
        result.level = LEVEL_SUSPICIOUS;
    } else {
        sHeadline = tr("NOT PACKED");
        sShort = tr("Not packed");
        sTabTitle = tr("Packing: none");
        result.level = LEVEL_CLEAN;
    }

    if (!result.listNamedObfuscators.isEmpty()) {
        sHeadline += QString("<br>") + tr("OBFUSCATED: %1").arg(result.listNamedObfuscators.join(", "));
        sShort += tr(" + obfuscated (%1)").arg(result.listNamedObfuscators.join(", "));
        sTabTitle = result.listNamedPackers.isEmpty() ? tr("Packing: obfuscated (%1)").arg(result.listNamedObfuscators.first()) : sTabTitle + tr(" + obfuscated");
        result.level = LEVEL_PACKED;
    } else {
        // name what was found instead of only a score: "ANTI-ANALYSIS: Anti-debug APIs, TLS callbacks"
        QStringList listObfuscation;
        QStringList listAnti;

        for (qint32 i = 0; i < listAll.count(); i++) {
            const HelperEvidence::INDICATOR &indicator = listAll.at(i);

            if (indicator.severity < HelperEvidence::SEVERITY_MEDIUM) {
                continue;
            }

            if (indicator.category == HelperEvidence::CATEGORY_OBFUSCATION) {
                listObfuscation.append(indicator.sTitle);
            } else if (indicator.category == HelperEvidence::CATEGORY_ANTIANALYSIS) {
                listAnti.append(indicator.sTitle);
            }
        }

        QStringList listParts;

        if (!listObfuscation.isEmpty()) {
            listParts.append(tr("OBFUSCATION: %1").arg(QStringList(listObfuscation.mid(0, 3)).join(", ")));
        }

        if (!listAnti.isEmpty()) {
            listParts.append(tr("ANTI-ANALYSIS: %1").arg(QStringList(listAnti.mid(0, 3)).join(", ")));
        }

        if (!listParts.isEmpty()) {
            sHeadline += QString("<br><span style='color:%1'>%2</span>").arg(colorOrange.name(), listParts.join(QString(" | ")).toHtmlEscaped());
            sShort += listObfuscation.isEmpty() ? tr(" + anti-analysis") : tr(" + obfuscation");

            if (result.listNamedPackers.isEmpty() && (nPackingScore < 25)) {
                sTabTitle = listObfuscation.isEmpty() ? tr("Packing: none, anti-analysis") : tr("Packing: none, obfuscated");
                result.level = LEVEL_SUSPICIOUS;
            } else {
                sTabTitle += listObfuscation.isEmpty() ? tr(" + anti-analysis") : tr(" + obfuscation");
            }
        }
    }

    result.color = (result.level == LEVEL_PACKED) ? colorRed : ((result.level == LEVEL_SUSPICIOUS) ? colorOrange : colorGreen);
    result.sHeadlineHtml = sHeadline;
    result.sShort = sShort;
    result.sTabTitle = sTabTitle;
    result.nPackingScore = nPackingScore;
    result.nObfuscationScore = nObfuscationScore;
    result.listIndicators = listAll;

    return result;
}
