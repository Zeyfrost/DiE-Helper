// DiE Helper (fork addition): the "Packing" tab beside DiE's detection list. Shows at a glance HOW an
// EXE/DLL is packed or obfuscated: verdict, section map, ranked indicators with clickable locations,
// and a collapsible "How to unpack" hint.
#ifndef HELPERPACKINGVIEW_H
#define HELPERPACKINGVIEW_H

#include <QFutureWatcher>
#include <QWidget>

#include "helperactions.h"
#include "helperevidence.h"
#include "helperhints.h"
#include "helperverdict.h"
#include "xscanengine.h"

class QLabel;
class QPlainTextEdit;
class QSplitter;
class QTabWidget;
class QTextBrowser;
class QToolButton;
class QTreeWidget;
class QTreeWidgetItem;
class HelperSectionMap;
class XOptions;
class XShortcuts;

class HelperPackingView : public QWidget {
    Q_OBJECT

public:
    explicit HelperPackingView(QWidget *pParent = nullptr);

    void setGlobal(XShortcuts *pShortcuts, XOptions *pOptions);
    void setFileName(const QString &sFileName);
    void reloadHints();

public slots:
    void onResultsReady(const XScanEngine::SCAN_RESULT &scanResult);
    void onResultSelected(const XScanEngine::SCANSTRUCT &scanStruct);
    void onScanCleared();

signals:
    void summaryChanged(const QString &sTabTitle, const QColor &color);
    void openFileRequested(const QString &sFileName);  // "Open in DiE" on an action result

private slots:
    void onTableReady(const HelperActions::TABLE &table);
    void onEvidenceFinished();
    void onSectionClicked(qint32 nSectionIndex);
    void onEntryPointClicked();
    void onIndicatorClicked(QTreeWidgetItem *pItem, int nColumn);
    void onIndicatorDoubleClicked(QTreeWidgetItem *pItem, int nColumn);
    void onLinkActivated(const QString &sLink);
    void onHowToToggled(bool bChecked);

private:
    enum COLUMN {
        COLUMN_SEVERITY = 0,
        COLUMN_CATEGORY,
        COLUMN_INDICATOR,
        COLUMN_DETAILS,
        COLUMN_LOCATION,
        __COLUMN_SIZE
    };

    void _refresh();
    void _updateHint();
    void _openLocation(const HelperEvidence::INDICATOR &indicator);
    void _openHex(qint64 nOffset, qint64 nSize);
    void _openDisasm(XADDR nAddress);
    qint32 _getBestDetectionIndex() const;
    QString _getHintHtml(const XScanEngine::SCANSTRUCT *pRecord, const HelperHints::HINT &hint, bool bIsFallback) const;

    static QString _listToHtml(const QStringList &listItems, bool bOrdered);
    static QString _textToHtml(const QString &sText);
    static QColor _severityColor(HelperEvidence::SEVERITY severity);

    XShortcuts *m_pShortcuts;
    XOptions *m_pOptions;

    QLabel *m_pLabelVerdict;
    HelperSectionMap *m_pSectionMap;
    QLabel *m_pLabelLegend;
    QLabel *m_pLabelEntryPoint;
    QSplitter *m_pSplitter;
    QTabWidget *m_pTabWidgetResults;
    QPlainTextEdit *m_pTextEditLog;
    HelperActions *m_pActions;
    QTreeWidget *m_pTreeIndicators;
    QToolButton *m_pToolButtonHowTo;
    QTextBrowser *m_pTextBrowserHint;

    QFutureWatcher<HelperEvidence::RESULT> m_watcher;
    QString m_sFileName;
    HelperEvidence::RESULT m_evidence;
    bool m_bEvidenceReady;
    QList<XScanEngine::SCANSTRUCT> m_listRecords;
    bool m_bResultsReady;
    XScanEngine::SCANSTRUCT m_selectedRecord;
    bool m_bHasSelectedRecord;
    QList<HelperEvidence::INDICATOR> m_listShownIndicators;  // same order as the tree rows
    HelperVerdict::RESULT m_verdict;                         // last computed verdict (reports, actions)
    HelperHints m_hints;
};

#endif  // HELPERPACKINGVIEW_H
