// DiE Helper (fork addition): batch scan of a folder. For every file: Helper evidence + DiE scan + verdict in one
// table row, exportable as CSV. The work runs off the GUI thread; nothing is ever executed.
#include "helperbatch.h"

#include <QCheckBox>
#include <QDir>
#include <QDirIterator>
#include <QElapsedTimer>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMutexLocker>
#include <QPushButton>
#include <QRegularExpression>
#include <QSaveFile>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QtConcurrent>
#include <functional>

#include "die_script.h"
#include "helperevidence.h"
#include "helperverdict.h"
#include "xformats.h"
#include "xoptions.h"

static const qint64 N_FILE_TIMEOUT_MS = 120000;  // DiE scan budget per file; a stuck file must not stall the batch
static const qint32 N_TOP_INDICATORS = 3;

HelperBatchDialog::HelperBatchDialog(QWidget *pParent, XOptions *pOptions) : QDialog(pParent)
{
    m_pOptions = pOptions;
    m_bRunning = false;

    setWindowTitle(tr("Helper: batch scan"));
    setWindowFlags(windowFlags() | Qt::WindowMaximizeButtonHint);
    resize(1100, 600);

    m_pLineEditFolder = new QLineEdit(this);
    m_pLineEditFolder->setPlaceholderText(tr("Folder to scan"));
    m_pPushButtonBrowse = new QPushButton(tr("Browse..."), this);

    m_pCheckBoxRecursive = new QCheckBox(tr("Recursive"), this);
    m_pCheckBoxRecursive->setChecked(true);
    m_pLineEditMask = new QLineEdit(this);
    m_pLineEditMask->setText(QString("*.exe;*.dll;*.sys;*.ocx;*.scr;*.bin;*"));
    m_pLineEditMask->setToolTip(tr("File name masks separated by ';'"));

    m_pPushButtonStart = new QPushButton(tr("Start"), this);
    m_pPushButtonStop = new QPushButton(tr("Stop"), this);
    m_pPushButtonExport = new QPushButton(tr("Export CSV..."), this);
    m_pPushButtonClose = new QPushButton(tr("Close"), this);

    m_pTableWidget = new QTableWidget(this);
    m_pTableWidget->setColumnCount(__COLUMN_SIZE);
    m_pTableWidget->setHorizontalHeaderLabels({tr("File"), tr("Type"), tr("Verdict"), tr("Packing"), tr("Obfuscation"), tr("DiE detections"), tr("Top indicators")});
    m_pTableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_pTableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_pTableWidget->setAlternatingRowColors(true);
    m_pTableWidget->setWordWrap(false);
    m_pTableWidget->verticalHeader()->setVisible(false);
    m_pTableWidget->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    m_pTableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_pTableWidget->horizontalHeader()->setStretchLastSection(true);
    m_pTableWidget->setColumnWidth(COLUMN_FILE, 260);
    m_pTableWidget->setColumnWidth(COLUMN_TYPE, 110);
    m_pTableWidget->setColumnWidth(COLUMN_VERDICT, 220);
    m_pTableWidget->setColumnWidth(COLUMN_PACKING, 70);
    m_pTableWidget->setColumnWidth(COLUMN_OBFUSCATION, 90);
    m_pTableWidget->setColumnWidth(COLUMN_DETECTIONS, 260);

    m_pLabelProgress = new QLabel(this);
    m_pLabelProgress->setTextFormat(Qt::PlainText);
    m_pLabelProgress->setText(tr("Choose a folder and press Start. Files are only read, never executed."));

    QHBoxLayout *pLayoutFolder = new QHBoxLayout;
    pLayoutFolder->addWidget(new QLabel(tr("Folder:"), this));
    pLayoutFolder->addWidget(m_pLineEditFolder, 1);
    pLayoutFolder->addWidget(m_pPushButtonBrowse);

    QHBoxLayout *pLayoutMask = new QHBoxLayout;
    pLayoutMask->addWidget(m_pCheckBoxRecursive);
    pLayoutMask->addSpacing(12);
    pLayoutMask->addWidget(new QLabel(tr("Mask:"), this));
    pLayoutMask->addWidget(m_pLineEditMask, 1);

    QHBoxLayout *pLayoutButtons = new QHBoxLayout;
    pLayoutButtons->addWidget(m_pPushButtonStart);
    pLayoutButtons->addWidget(m_pPushButtonStop);
    pLayoutButtons->addStretch(1);
    pLayoutButtons->addWidget(m_pPushButtonExport);
    pLayoutButtons->addWidget(m_pPushButtonClose);

    QVBoxLayout *pLayout = new QVBoxLayout(this);
    pLayout->addLayout(pLayoutFolder);
    pLayout->addLayout(pLayoutMask);
    pLayout->addLayout(pLayoutButtons);
    pLayout->addWidget(m_pTableWidget, 1);
    pLayout->addWidget(m_pLabelProgress);

    connect(m_pPushButtonBrowse, SIGNAL(clicked()), this, SLOT(onBrowseClicked()));
    connect(m_pPushButtonStart, SIGNAL(clicked()), this, SLOT(onStartClicked()));
    connect(m_pPushButtonStop, SIGNAL(clicked()), this, SLOT(onStopClicked()));
    connect(m_pPushButtonExport, SIGNAL(clicked()), this, SLOT(onExportClicked()));
    connect(m_pPushButtonClose, SIGNAL(clicked()), this, SLOT(reject()));

    m_pPushButtonStart->setDefault(true);
    _setRunning(false);
}

HelperBatchDialog::~HelperBatchDialog()
{
    _stopAndWait();
}

void HelperBatchDialog::reject()
{
    _stopAndWait();

    QDialog::reject();
}

void HelperBatchDialog::onBrowseClicked()
{
    QString sDirectory = QFileDialog::getExistingDirectory(this, tr("Open directory") + QString("..."), m_pLineEditFolder->text().trimmed(), QFileDialog::ShowDirsOnly);

    if (!sDirectory.isEmpty()) {
        m_pLineEditFolder->setText(QDir::toNativeSeparators(sDirectory));
    }
}

void HelperBatchDialog::onStartClicked()
{
    if (m_bRunning) {
        return;
    }

    QString sFolder = m_pLineEditFolder->text().trimmed();

    if (sFolder.isEmpty() || !QFileInfo(sFolder).isDir()) {
        QMessageBox::warning(this, tr("Batch scan"), tr("Choose an existing folder."));
        return;
    }

    m_future.waitForFinished();  // the previous run has already posted its "finished"; this returns at once

    // --- read every option here, on the GUI thread
    SETTINGS settings;
    settings.sFolder = QDir(sFolder).absolutePath();
    settings.bRecursive = m_pCheckBoxRecursive->isChecked();
    settings.listMasks = m_pLineEditMask->text().split(QRegularExpression(QString("[;,\\s]+")), Qt::SkipEmptyParts);

    if (settings.listMasks.isEmpty()) {
        settings.listMasks.append(QString("*"));
    }

    quint64 nFlags = XScanEngine::SF_HEURISTICSCAN | XScanEngine::SF_VERBOSE;
    quint64 nDatabases = XScanEngine::DATABASE_MAIN;
    QString sMainDatabasePath = QString("$data/db");
    QString sCustomDatabasePath = QString("$data/db_custom");

    if (m_pOptions) {
        nFlags |= XScanEngine::getScanFlagsFromGlobalOptions(m_pOptions);
        nDatabases = XScanEngine::getDatabasesFromGlobalOptions(m_pOptions);

        if (m_pOptions->isIDPresent(XOptions::ID_SCAN_DIE_DATABASE_MAIN_PATH)) {
            sMainDatabasePath = m_pOptions->getValue(XOptions::ID_SCAN_DIE_DATABASE_MAIN_PATH).toString();
        }

        if (m_pOptions->isIDPresent(XOptions::ID_SCAN_DIE_DATABASE_CUSTOM_PATH)) {
            sCustomDatabasePath = m_pOptions->getValue(XOptions::ID_SCAN_DIE_DATABASE_CUSTOM_PATH).toString();
        }
    }

    settings.scanOptions = XScanEngine::getDefaultOptions(nFlags);  // bShowType/Version/Info = true
    XScanEngine::setDatabases(&settings.scanOptions, nDatabases);
    settings.scanOptions.sMainDatabasePath = sMainDatabasePath;
    settings.scanOptions.sCustomDatabasePath = sCustomDatabasePath;

    // --- reset the view
    m_sRootFolder = settings.sFolder;
    m_listRows.clear();
    m_pTableWidget->setSortingEnabled(false);
    m_pTableWidget->setRowCount(0);
    _setRunning(true);
    _setProgress(tr("Collecting files..."));

    m_pControl = std::make_shared<CONTROL>();
    std::shared_ptr<CONTROL> pControl = m_pControl;

    m_future = QtConcurrent::run([this, settings, pControl]() { _scan(this, settings, pControl); });
}

void HelperBatchDialog::onStopClicked()
{
    if (m_pControl) {
        m_pControl->bStop.store(true);

        QMutexLocker locker(&m_pControl->mutex);

        if (m_pControl->pCurrentPdStruct) {
            XBinary::setPdStructStopped(m_pControl->pCurrentPdStruct);
        }
    }

    if (m_bRunning) {
        _setProgress(tr("Stopping..."));
    }
}

void HelperBatchDialog::onExportClicked()
{
    if (m_listRows.isEmpty()) {
        QMessageBox::information(this, tr("Export CSV"), tr("Nothing to export yet."));
        return;
    }

    QString sDefault = QDir(m_sRootFolder.isEmpty() ? QDir::homePath() : m_sRootFolder).filePath(QString("die_helper_batch.csv"));
    QString sFileName = QFileDialog::getSaveFileName(this, tr("Export CSV"), sDefault, QString("CSV (*.csv);;%1 (*)").arg(tr("All files")));

    if (sFileName.isEmpty()) {
        return;
    }

    // RFC 4180: CRLF line ends, fields quoted when needed, quotes doubled. UTF-8 with BOM so Excel detects the encoding.
    QStringList listHeaders = {tr("File"), tr("Type"), tr("Verdict"), tr("Packing"), tr("Obfuscation"), tr("DiE detections"), tr("Top indicators")};
    QStringList listLines;

    {
        QStringList listFields;

        for (qint32 i = 0; i < listHeaders.count(); i++) {
            listFields.append(_csvField(listHeaders.at(i)));
        }

        listLines.append(listFields.join(QChar(',')));
    }

    for (qint32 i = 0; i < m_listRows.count(); i++) {
        const ROW &row = m_listRows.at(i);

        QStringList listFields;
        listFields.append(_csvField(QDir::toNativeSeparators(row.sFileName)));
        listFields.append(_csvField(row.sType));
        listFields.append(_csvField(row.sVerdict));
        listFields.append((row.nPackingScore >= 0) ? QString::number(row.nPackingScore) : QString());
        listFields.append((row.nObfuscationScore >= 0) ? QString::number(row.nObfuscationScore) : QString());
        listFields.append(_csvField(row.sDetections));
        listFields.append(_csvField(row.sTopIndicators));

        listLines.append(listFields.join(QChar(',')));
    }

    QByteArray baData("\xEF\xBB\xBF");
    baData.append(listLines.join(QString("\r\n")).toUtf8());
    baData.append("\r\n");

    QSaveFile file(sFileName);
    bool bSuccess = false;

    if (file.open(QIODevice::WriteOnly)) {
        if (file.write(baData) == baData.size()) {
            bSuccess = file.commit();
        } else {
            file.cancelWriting();
        }
    }

    if (bSuccess) {
        _setProgress(tr("Exported %1 rows to %2").arg(m_listRows.count()).arg(QDir::toNativeSeparators(sFileName)));
    } else {
        QMessageBox::critical(this, tr("Export CSV"), tr("Cannot write %1").arg(QDir::toNativeSeparators(sFileName)));
    }
}

QString HelperBatchDialog::_csvField(const QString &sText)
{
    QString sResult = sText;

    // A cell starting with = + - @ is run as a formula by spreadsheet programs; file names and DiE strings come from
    // untrusted samples, so such cells get a leading apostrophe (shown as text, not evaluated).
    if ((sResult.size() > 1) && QString("=+-@").contains(sResult.at(0))) {
        sResult.prepend(QChar('\''));
    } else if (sResult.startsWith(QChar('\t')) || sResult.startsWith(QChar('\r'))) {
        sResult.prepend(QChar('\''));
    }

    if (sResult.contains(QChar('"')) || sResult.contains(QChar(',')) || sResult.contains(QChar('\r')) || sResult.contains(QChar('\n'))) {
        sResult.replace(QString("\""), QString("\"\""));
        sResult = QString("\"%1\"").arg(sResult);
    }

    return sResult;
}

void HelperBatchDialog::_setCurrentPdStruct(CONTROL *pControl, XBinary::PDSTRUCT *pPdStruct)
{
    QMutexLocker locker(&pControl->mutex);

    pControl->pCurrentPdStruct = pPdStruct;

    if (pPdStruct && pControl->bStop.load()) {
        XBinary::setPdStructStopped(pPdStruct);
    }
}

HelperBatchDialog::ROW HelperBatchDialog::_scanFile(const QString &sFileName, XScanEngine *pScanEngine, bool bDatabaseLoaded, XScanEngine::SCAN_OPTIONS *pScanOptions,
                                                    CONTROL *pControl)
{
    ROW result = {};
    result.sFileName = sFileName;
    result.nPackingScore = -1;
    result.nObfuscationScore = -1;

    // One PDSTRUCT per file: a per-file deadline that expires sets bIsStop, which must not stop the next files
    XBinary::PDSTRUCT pdStruct = XBinary::createPdStruct();
    XBinary::setPdStructDeadline(&pdStruct, N_FILE_TIMEOUT_MS);
    _setCurrentPdStruct(pControl, &pdStruct);

    HelperEvidence::RESULT evidence = HelperEvidence::analyze(sFileName);

    QList<XScanEngine::SCANSTRUCT> listRecords;
    bool bTimedOut = false;

    if (bDatabaseLoaded && !pControl->bStop.load()) {
        XScanEngine::SCAN_RESULT scanResult = pScanEngine->scanFile(sFileName, pScanOptions, &pdStruct);
        listRecords = scanResult.listRecords;
        bTimedOut = XBinary::isPdStructDeadlineExpired(&pdStruct);
    }

    if (evidence.bIsValid) {
        result.sType = QString("%1 %2").arg(evidence.bIs64 ? "PE64" : "PE32", evidence.bIsDll ? "DLL" : "EXE");

        if (evidence.bIsNET) {
            result.sType += QString(" (.NET)");
        }

        HelperVerdict::RESULT verdict = HelperVerdict::compute(evidence, listRecords);

        result.sVerdict = verdict.sShort;
        result.colorVerdict = verdict.color;
        result.nPackingScore = verdict.nPackingScore;
        result.nObfuscationScore = verdict.nObfuscationScore;

        QStringList listTop;

        for (qint32 i = 0; (i < verdict.listIndicators.count()) && (listTop.count() < N_TOP_INDICATORS); i++) {
            if (verdict.listIndicators.at(i).category != HelperEvidence::CATEGORY_INFO) {
                listTop.append(verdict.listIndicators.at(i).sTitle);
            }
        }

        result.sTopIndicators = listTop.join(QString("; "));
    } else {
        XBinary::FT fileType = XFormats::getPrefFileType(sFileName, XBinary::FT_FLAG_FORMATS, &pdStruct);
        result.sType = XBinary::fileTypeIdToString(fileType);
        result.sVerdict = QString("n/a");
    }

    _setCurrentPdStruct(pControl, nullptr);  // before pdStruct goes out of scope

    QStringList listDetections;

    for (qint32 i = 0; i < listRecords.count(); i++) {
        if (!listRecords.at(i).sName.isEmpty()) {
            QString sTitle = HelperVerdict::getRecordTitle(listRecords.at(i));

            if (!listDetections.contains(sTitle)) {
                listDetections.append(sTitle);
            }
        }
    }

    if (!bDatabaseLoaded) {
        listDetections.append(QString("(DiE database not loaded)"));
    } else if (bTimedOut) {
        listDetections.append(QString("(DiE scan timed out)"));
    }

    result.sDetections = listDetections.join(QString("; "));

    return result;
}

void HelperBatchDialog::_scan(HelperBatchDialog *pDialog, const SETTINGS &settings, std::shared_ptr<CONTROL> pControl)
{
    // Runs on a QtConcurrent pool thread. Talks to the dialog only through queued calls; a queued call whose
    // context object is gone is dropped by Qt, and the dialog waits for this function before it dies anyway.
    auto post = [pDialog](std::function<void()> function) { QMetaObject::invokeMethod(pDialog, function, Qt::QueuedConnection); };

    QElapsedTimer timer;
    timer.start();

    // --- 1. collect the files
    QStringList listFiles;
    {
        QDirIterator::IteratorFlags iteratorFlags = settings.bRecursive ? QDirIterator::Subdirectories : QDirIterator::NoIteratorFlags;
        QDirIterator it(settings.sFolder, settings.listMasks, QDir::Files | QDir::Hidden | QDir::System | QDir::NoSymLinks, iteratorFlags);

        while (it.hasNext() && !pControl->bStop.load()) {
            listFiles.append(it.next());

            if ((listFiles.count() % 500) == 0) {
                qint32 nCount = listFiles.count();
                post([pDialog, nCount]() { pDialog->_setProgress(tr("Collecting files... %1").arg(nCount)); });
            }
        }
    }

    listFiles.sort(Qt::CaseInsensitive);
    qint32 nTotal = listFiles.count();

    // --- 2. load the DiE database once
    DiE_Script dieScript;
    XScanEngine::SCAN_OPTIONS scanOptions = settings.scanOptions;
    bool bDatabaseLoaded = false;

    if (!pControl->bStop.load() && (nTotal > 0)) {
        post([pDialog, nTotal]() { pDialog->_setProgress(tr("Loading the DiE database... (%1 files to scan)").arg(nTotal)); });

        XBinary::PDSTRUCT pdStruct = XBinary::createPdStruct();
        _setCurrentPdStruct(pControl.get(), &pdStruct);
        bDatabaseLoaded = dieScript.loadDatabase(&scanOptions, &pdStruct);
        _setCurrentPdStruct(pControl.get(), nullptr);
    }

    // --- 3. scan
    qint32 nScanned = 0;

    for (qint32 i = 0; (i < nTotal) && !pControl->bStop.load(); i++) {
        const QString &sFileName = listFiles.at(i);
        QString sShortName = QFileInfo(sFileName).fileName();

        post([pDialog, i, nTotal, sShortName]() { pDialog->_setProgress(tr("Scanning %1 / %2: %3").arg(i + 1).arg(nTotal).arg(sShortName)); });

        ROW row = _scanFile(sFileName, &dieScript, bDatabaseLoaded, &scanOptions, pControl.get());

        if (pControl->bStop.load()) {
            break;  // the last file may be half-scanned: do not show a partial result
        }

        nScanned++;
        post([pDialog, row]() { pDialog->_addRow(row); });
    }

    bool bStopped = pControl->bStop.load();
    qint64 nElapsedMs = timer.elapsed();

    post([pDialog, nScanned, nTotal, bStopped, nElapsedMs]() { pDialog->_onFinished(nScanned, nTotal, bStopped, nElapsedMs); });
}

void HelperBatchDialog::_addRow(const ROW &row)
{
    m_listRows.append(row);

    qint32 nRow = m_pTableWidget->rowCount();
    m_pTableWidget->insertRow(nRow);

    QString sRelative = QDir(m_sRootFolder).relativeFilePath(row.sFileName);

    QTableWidgetItem *pItemFile = new QTableWidgetItem(QDir::toNativeSeparators(sRelative));
    pItemFile->setToolTip(QDir::toNativeSeparators(row.sFileName));
    m_pTableWidget->setItem(nRow, COLUMN_FILE, pItemFile);

    m_pTableWidget->setItem(nRow, COLUMN_TYPE, new QTableWidgetItem(row.sType));

    QTableWidgetItem *pItemVerdict = new QTableWidgetItem(row.sVerdict);
    pItemVerdict->setToolTip(row.sVerdict);

    if (row.colorVerdict.isValid()) {
        pItemVerdict->setForeground(QBrush(row.colorVerdict));
    }

    m_pTableWidget->setItem(nRow, COLUMN_VERDICT, pItemVerdict);

    // numbers as data so the column sorts numerically; n/a stays empty
    QTableWidgetItem *pItemPacking = new QTableWidgetItem;
    QTableWidgetItem *pItemObfuscation = new QTableWidgetItem;

    if (row.nPackingScore >= 0) {
        pItemPacking->setData(Qt::DisplayRole, row.nPackingScore);
    }

    if (row.nObfuscationScore >= 0) {
        pItemObfuscation->setData(Qt::DisplayRole, row.nObfuscationScore);
    }

    m_pTableWidget->setItem(nRow, COLUMN_PACKING, pItemPacking);
    m_pTableWidget->setItem(nRow, COLUMN_OBFUSCATION, pItemObfuscation);

    QTableWidgetItem *pItemDetections = new QTableWidgetItem(row.sDetections);
    pItemDetections->setToolTip(row.sDetections.split(QString("; ")).join(QChar('\n')));
    m_pTableWidget->setItem(nRow, COLUMN_DETECTIONS, pItemDetections);

    QTableWidgetItem *pItemIndicators = new QTableWidgetItem(row.sTopIndicators);
    pItemIndicators->setToolTip(row.sTopIndicators.split(QString("; ")).join(QChar('\n')));
    m_pTableWidget->setItem(nRow, COLUMN_INDICATORS, pItemIndicators);
}

void HelperBatchDialog::_setProgress(const QString &sText)
{
    m_pLabelProgress->setText(sText);
}

void HelperBatchDialog::_onFinished(qint32 nScanned, qint32 nTotal, bool bStopped, qint64 nElapsedMs)
{
    _setRunning(false);
    m_pTableWidget->setSortingEnabled(true);

    QString sTime = QString::number((double)nElapsedMs / 1000.0, 'f', 1);

    if (bStopped) {
        _setProgress(tr("Stopped: %1 of %2 files scanned in %3 s").arg(nScanned).arg(nTotal).arg(sTime));
    } else if (nTotal == 0) {
        _setProgress(tr("No files match the mask"));
    } else {
        _setProgress(tr("Done: %1 files scanned in %2 s").arg(nScanned).arg(sTime));
    }
}

void HelperBatchDialog::_setRunning(bool bRunning)
{
    m_bRunning = bRunning;

    m_pLineEditFolder->setEnabled(!bRunning);
    m_pPushButtonBrowse->setEnabled(!bRunning);
    m_pCheckBoxRecursive->setEnabled(!bRunning);
    m_pLineEditMask->setEnabled(!bRunning);
    m_pPushButtonStart->setEnabled(!bRunning);
    m_pPushButtonStop->setEnabled(bRunning);
    m_pPushButtonExport->setEnabled(!bRunning);
}

void HelperBatchDialog::_stopAndWait()
{
    if (m_pControl) {
        m_pControl->bStop.store(true);

        QMutexLocker locker(&m_pControl->mutex);

        if (m_pControl->pCurrentPdStruct) {
            XBinary::setPdStructStopped(m_pControl->pCurrentPdStruct);
        }
    }

    // The worker only posts queued calls to this thread, so blocking here cannot deadlock
    m_future.waitForFinished();
}
