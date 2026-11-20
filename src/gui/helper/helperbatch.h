// DiE Helper (fork addition): batch scan of a folder. For every file: Helper evidence + DiE scan + verdict in one
// table row, exportable as CSV. The work runs off the GUI thread; nothing is ever executed.
#ifndef HELPERBATCH_H
#define HELPERBATCH_H

#include <QColor>
#include <QDialog>
#include <QFuture>
#include <QMutex>
#include <QStringList>
#include <atomic>
#include <memory>

#include "xscanengine.h"

class QCheckBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;
class XOptions;

class HelperBatchDialog : public QDialog {
    Q_OBJECT

public:
    explicit HelperBatchDialog(QWidget *pParent, XOptions *pOptions);
    ~HelperBatchDialog() override;

public slots:
    void reject() override;

private slots:
    void onBrowseClicked();
    void onStartClicked();
    void onStopClicked();
    void onExportClicked();

private:
    enum COLUMN {
        COLUMN_FILE = 0,
        COLUMN_TYPE,
        COLUMN_VERDICT,
        COLUMN_PACKING,
        COLUMN_OBFUSCATION,
        COLUMN_DETECTIONS,
        COLUMN_INDICATORS,
        __COLUMN_SIZE
    };

    // Everything the worker needs, captured on the GUI thread before it starts (XOptions is not touched off-thread)
    struct SETTINGS {
        QString sFolder;
        QStringList listMasks;
        bool bRecursive;
        XScanEngine::SCAN_OPTIONS scanOptions;
    };

    struct ROW {
        QString sFileName;   // absolute path
        QString sType;       // "PE32 EXE", "PE64 DLL (.NET)", "ZIP", ...
        QString sVerdict;    // HelperVerdict::RESULT::sShort, "n/a" for non-PE files
        QColor colorVerdict; // invalid for "n/a"
        qint32 nPackingScore;      // -1 = n/a
        qint32 nObfuscationScore;  // -1 = n/a
        QString sDetections;
        QString sTopIndicators;
    };

    // Shared by the dialog and one worker run: the stop flag and the PDSTRUCT the worker is currently using
    struct CONTROL {
        std::atomic<bool> bStop{false};
        QMutex mutex;
        XBinary::PDSTRUCT *pCurrentPdStruct = nullptr;
    };

    static void _scan(HelperBatchDialog *pDialog, const SETTINGS &settings, std::shared_ptr<CONTROL> pControl);
    static void _setCurrentPdStruct(CONTROL *pControl, XBinary::PDSTRUCT *pPdStruct);
    static ROW _scanFile(const QString &sFileName, XScanEngine *pScanEngine, bool bDatabaseLoaded, XScanEngine::SCAN_OPTIONS *pScanOptions, CONTROL *pControl);
    static QString _csvField(const QString &sText);

    void _addRow(const ROW &row);
    void _setProgress(const QString &sText);
    void _onFinished(qint32 nScanned, qint32 nTotal, bool bStopped, qint64 nElapsedMs);
    void _setRunning(bool bRunning);
    void _stopAndWait();

    XOptions *m_pOptions;

    QLineEdit *m_pLineEditFolder;
    QPushButton *m_pPushButtonBrowse;
    QCheckBox *m_pCheckBoxRecursive;
    QLineEdit *m_pLineEditMask;
    QPushButton *m_pPushButtonStart;
    QPushButton *m_pPushButtonStop;
    QPushButton *m_pPushButtonExport;
    QPushButton *m_pPushButtonClose;
    QTableWidget *m_pTableWidget;
    QLabel *m_pLabelProgress;

    QFuture<void> m_future;
    std::shared_ptr<CONTROL> m_pControl;
    bool m_bRunning;
    QString m_sRootFolder;
    QList<ROW> m_listRows;  // scan order, for the CSV export
};

#endif  // HELPERBATCH_H
