// DiE Helper (fork addition): the "Actions" toolbar of the Packing tab - static unpacking, OEP finding,
// generic decompression + rebuild, string / API-hash / .NET deobfuscation views, PE surgery on copies,
// reports, signature maker, batch scan and optional external tools. Every action reads the original file
// and writes NEW files only; nothing is ever executed (external tools run on copies, by the user's choice).
#ifndef HELPERACTIONS_H
#define HELPERACTIONS_H

#include <QObject>
#include <QStringList>
#include <functional>

#include "helperevidence.h"
#include "xscanengine.h"

class QMenu;
class QToolButton;
class QWidget;
class XOptions;
class XShortcuts;

class HelperActions : public QObject {
    Q_OBJECT

public:
    // A result table for the Packing tab; each row may carry a location (hex offset or disasm address)
    struct TABLE {
        QString sTitle;
        QStringList listHeaders;
        QList<QStringList> listRows;
        QList<HelperEvidence::INDICATOR> listLocations;  // same length as listRows; LOCATION_NONE = no link
    };

    explicit HelperActions(QWidget *pParent);

    QWidget *createToolBar(QWidget *pParent);
    void setGlobal(XShortcuts *pShortcuts, XOptions *pOptions);
    void setFileName(const QString &sFileName);
    void setContext(const HelperEvidence::RESULT &evidence, const QList<XScanEngine::SCANSTRUCT> &listRecords);

signals:
    void tableReady(const HelperActions::TABLE &table);
    void logMessage(const QString &sText);
    void openFileRequested(const QString &sFileName);

private slots:
    void onUnpack();
    void onRepairUpx();
    void onFindOep();
    void onDecompress();
    void onStrings();
    void onApiHashes();
    void onNetInfo();
    void onSetEntryPoint();
    void onStripOverlay();
    void onSaveOverlay();
    void onSaveSection();
    void onRestoreFlags();
    void onRenameSection();
    void onRemoveTls();
    void onFixChecksum();
    void onRebuildImports();
    void onExtract();
    void onReport();
    void onSignature();
    void onBatch();
    void onExternalTool(qint32 nTool);

private:
    bool _run(const QString &sTitle, const std::function<void(XBinary::PDSTRUCT *)> &function);
    QString _getOutputFileName(const QString &sSuffix, const QString &sFilter);
    void _finishFileAction(const QString &sTitle, bool bSuccess, const QString &sError, const QStringList &listLog, const QString &sOutput);
    void _log(const QString &sTitle, const QStringList &listLines);
    void _emitTable(const TABLE &table);
    void _updateButtons();
    qint64 _getBestOepRVA();
    bool _isReady(const QString &sTitle);

    QWidget *m_pParentWidget;
    XShortcuts *m_pShortcuts;
    XOptions *m_pOptions;
    QString m_sFileName;
    HelperEvidence::RESULT m_evidence;
    bool m_bHasEvidence;
    QList<XScanEngine::SCANSTRUCT> m_listRecords;
    QList<TABLE> m_listTables;      // results of this file's actions (for the report)
    QList<qint64> m_listOepRVAs;    // last "Find OEP" result, best first
    bool m_bUnpackerAvailable;
    bool m_bBrokenUpx;
    QString m_sUnpacker;

    QToolButton *m_pButtonUnpack;
    QToolButton *m_pButtonRepairUpx;
    QToolButton *m_pButtonOep;
    QToolButton *m_pButtonDecompress;
    QToolButton *m_pButtonStrings;
    QToolButton *m_pButtonApiHashes;
    QToolButton *m_pButtonNet;
    QToolButton *m_pButtonPeTools;
    QToolButton *m_pButtonMore;
    QToolButton *m_pButtonTools;
    QMenu *m_pMenuTools;
};

#endif  // HELPERACTIONS_H
