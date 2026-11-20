// DiE Helper (fork addition): the "Actions" toolbar of the Packing tab - static unpacking, OEP finding,
// generic decompression + rebuild, string / API-hash / .NET deobfuscation views, PE surgery on copies,
// reports, signature maker, batch scan and optional external tools. Every action reads the original file
// and writes NEW files only; nothing is ever executed (external tools run on copies, by the user's choice).
#include "helperactions.h"

#include <QDesktopServices>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QMenu>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QRegularExpression>
#include <QToolButton>
#include <QUrl>
#include <QVBoxLayout>

#include "dialogpe.h"
#include "helperapihash.h"
#include "helperbatch.h"
#include "helperdecompressor.h"
#include "helpernetinfo.h"
#include "helperoepfinder.h"
#include "helperpesurgery.h"
#include "helperrebuild.h"
#include "helperreport.h"
#include "helpersectionmap.h"
#include "helpersettings.h"
#include "helpersignaturemaker.h"
#include "helperstrings.h"
#include "helperunpacker.h"
#include "helperupx.h"
#include "helperverdict.h"
#include "xoptions.h"
#include "xshortcuts.h"
#include "xthreadobject.h"
#include "xdialogprocess.h"

// ---------------------------------------------------------------------------------------------------------------
// Background runner: one std::function on a worker thread under DiE's progress dialog (Cancel supported)

class HelperTask : public XThreadObject {
public:
    HelperTask(const QString &sTitle, const std::function<void(XBinary::PDSTRUCT *)> &function) : m_sTitle(sTitle), m_function(function), m_pPdStruct(nullptr)
    {
    }

    // the progress dialog owns the PDSTRUCT; it exists only after the dialog is constructed with this task
    void setPdStruct(XBinary::PDSTRUCT *pPdStruct)
    {
        m_pPdStruct = pPdStruct;
    }

    QString getTitle() override
    {
        return m_sTitle;
    }

    void process() override
    {
        qint32 nIndex = XBinary::getFreeIndex(m_pPdStruct);
        XBinary::setPdStructInit(m_pPdStruct, nIndex, 0);
        XBinary::setPdStructStatus(m_pPdStruct, nIndex, m_sTitle);

        m_function(m_pPdStruct);

        XBinary::setPdStructFinished(m_pPdStruct, nIndex);
    }

private:
    QString m_sTitle;
    std::function<void(XBinary::PDSTRUCT *)> m_function;
    XBinary::PDSTRUCT *m_pPdStruct;
};

// ---------------------------------------------------------------------------------------------------------------
// Before / after comparison of two files (section maps + scores from the static evidence)

static QWidget *_createCompareColumn(QWidget *pParent, const QString &sTitle, const QString &sFileName)
{
    HelperEvidence::RESULT evidence = HelperEvidence::analyze(sFileName);
    HelperVerdict::RESULT verdict = HelperVerdict::compute(evidence, QList<XScanEngine::SCANSTRUCT>());

    QWidget *pWidget = new QWidget(pParent);
    QVBoxLayout *pLayout = new QVBoxLayout(pWidget);
    QLabel *pLabel = new QLabel(pWidget);
    pLabel->setTextFormat(Qt::RichText);
    pLabel->setWordWrap(true);

    if (evidence.bIsValid) {
        pLabel->setText(QString("<b>%1</b>: %2<br><span style='color:%3; font-weight:bold'>%4</span><br><small>packing %5/100 &middot; obfuscation %6/100 &middot; "
                                "%7 section(s) &middot; %8 import function(s) &middot; entropy %9 &middot; %10 bytes</small>")
                            .arg(sTitle, QFileInfo(sFileName).fileName().toHtmlEscaped(), verdict.color.name(), verdict.sHeadlineHtml)
                            .arg(verdict.nPackingScore)
                            .arg(verdict.nObfuscationScore)
                            .arg(evidence.listSections.count())
                            .arg(evidence.nImportFunctions)
                            .arg(evidence.dFileEntropy, 0, 'f', 2)
                            .arg(evidence.nFileSize));
    } else {
        pLabel->setText(QString("<b>%1</b>: %2<br>%3").arg(sTitle, QFileInfo(sFileName).fileName().toHtmlEscaped(), evidence.sError.toHtmlEscaped()));
    }

    HelperSectionMap *pMap = new HelperSectionMap(pWidget);
    pMap->setData(evidence);

    pLayout->addWidget(pLabel);
    pLayout->addWidget(pMap);

    return pWidget;
}

static void _showCompareDialog(QWidget *pParent, const QString &sBefore, const QString &sAfter)
{
    QDialog dialog(pParent);
    dialog.setWindowTitle(QObject::tr("Before / after"));
    dialog.resize(1000, 380);

    QVBoxLayout *pLayout = new QVBoxLayout(&dialog);
    pLayout->addWidget(_createCompareColumn(&dialog, QObject::tr("Before"), sBefore));
    pLayout->addWidget(_createCompareColumn(&dialog, QObject::tr("After"), sAfter));
    pLayout->addStretch();

    QDialogButtonBox *pButtons = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    QObject::connect(pButtons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    pLayout->addWidget(pButtons);

    dialog.exec();
}

// ---------------------------------------------------------------------------------------------------------------

static QString _hex(qint64 nValue)
{
    return QString("0x%1").arg(nValue, 0, 16);
}

static HelperEvidence::INDICATOR _location(HelperEvidence::LOCATION location, qint64 nOffset, qint64 nSize, XADDR nAddress)
{
    HelperEvidence::INDICATOR result = {};
    result.location = location;
    result.nOffset = nOffset;
    result.nSize = nSize;
    result.nAddress = nAddress;

    return result;
}

HelperActions::HelperActions(QWidget *pParent) : QObject(pParent)
{
    m_pParentWidget = pParent;
    m_pShortcuts = nullptr;
    m_pOptions = nullptr;
    m_evidence = {};
    m_bHasEvidence = false;
    m_bUnpackerAvailable = false;
    m_bBrokenUpx = false;

    m_pButtonUnpack = nullptr;
    m_pButtonRepairUpx = nullptr;
    m_pButtonOep = nullptr;
    m_pButtonDecompress = nullptr;
    m_pButtonStrings = nullptr;
    m_pButtonApiHashes = nullptr;
    m_pButtonNet = nullptr;
    m_pButtonPeTools = nullptr;
    m_pButtonMore = nullptr;
    m_pButtonTools = nullptr;
    m_pMenuTools = nullptr;
}

QWidget *HelperActions::createToolBar(QWidget *pParent)
{
    QWidget *pBar = new QWidget(pParent);
    QHBoxLayout *pLayout = new QHBoxLayout(pBar);
    pLayout->setContentsMargins(0, 0, 0, 0);
    pLayout->setSpacing(3);

    auto addButton = [&](const QString &sText, const QString &sToolTip, const char *pszSlot) {
        QToolButton *pButton = new QToolButton(pBar);
        pButton->setText(sText);
        pButton->setToolTip(sToolTip);
        pButton->setToolButtonStyle(Qt::ToolButtonTextOnly);

        if (pszSlot) {
            connect(pButton, SIGNAL(clicked()), this, pszSlot);
        }

        pLayout->addWidget(pButton);

        return pButton;
    };

    m_pButtonUnpack = addButton(tr("Unpack"), tr("Static unpack with DiE's built-in unpackers (UPX, ASPack, FSG, MEW, NsPack, Petite, yC)"), SLOT(onUnpack()));
    m_pButtonRepairUpx = addButton(tr("Repair UPX"), tr("Restore renamed UPX0/UPX1 sections and the wiped \"UPX!\" magic in a copy, then unpack it"), SLOT(onRepairUpx()));
    m_pButtonOep = addButton(tr("Find OEP"), tr("Walk the unpacking stub statically and rank original-entry-point candidates"), SLOT(onFindOep()));
    m_pButtonDecompress = addButton(tr("Decompress"), tr("Unknown packer: try NRV2B/D/E, LZMA, aPLib, zlib, LZNT1 on the blobs the stub points at, then rebuild a PE"), SLOT(onDecompress()));
    m_pButtonStrings = addButton(tr("Strings"), tr("Recover obfuscated strings statically: stack strings, XOR/ADD/ROL brute force, .NET user strings"), SLOT(onStrings()));
    m_pButtonApiHashes = addButton(tr("API hashes"), tr("Resolve API-hash constants (ror13, crc32, djb2, fnv1a, sdbm) and GetProcAddress call sites"), SLOT(onApiHashes()));
    m_pButtonNet = addButton(tr(".NET"), tr(".NET deobfuscation view: obfuscated names, obfuscator markers, encrypted method bodies, user strings"), SLOT(onNetInfo()));

    // PE surgery: always on a copy
    m_pButtonPeTools = addButton(tr("PE tools"), tr("Edits applied to a NEW copy of the file"), nullptr);
    m_pButtonPeTools->setPopupMode(QToolButton::InstantPopup);
    {
        QMenu *pMenu = new QMenu(m_pButtonPeTools);
        pMenu->addAction(tr("Set entry point..."), this, SLOT(onSetEntryPoint()));
        pMenu->addAction(tr("Rebuild imports (static)"), this, SLOT(onRebuildImports()));
        pMenu->addAction(tr("Restore section flags (drop RWX)"), this, SLOT(onRestoreFlags()));
        pMenu->addAction(tr("Rename section..."), this, SLOT(onRenameSection()));
        pMenu->addAction(tr("Remove TLS callbacks"), this, SLOT(onRemoveTls()));
        pMenu->addSeparator();
        pMenu->addAction(tr("Strip overlay"), this, SLOT(onStripOverlay()));
        pMenu->addAction(tr("Save overlay as..."), this, SLOT(onSaveOverlay()));
        pMenu->addAction(tr("Save section as..."), this, SLOT(onSaveSection()));
        pMenu->addSeparator();
        pMenu->addAction(tr("Fix checksum"), this, SLOT(onFixChecksum()));
        m_pButtonPeTools->setMenu(pMenu);
    }

    m_pButtonMore = addButton(tr("More"), QString(), nullptr);
    m_pButtonMore->setPopupMode(QToolButton::InstantPopup);
    {
        QMenu *pMenu = new QMenu(m_pButtonMore);
        pMenu->addAction(tr("Extract embedded files..."), this, SLOT(onExtract()));
        pMenu->addAction(tr("Export report..."), this, SLOT(onReport()));
        pMenu->addAction(tr("Make custom signature..."), this, SLOT(onSignature()));
        pMenu->addSeparator();
        pMenu->addAction(tr("Batch scan a folder..."), this, SLOT(onBatch()));
        m_pButtonMore->setMenu(pMenu);
    }

    // external tools: only those configured in Options -> Helper
    m_pButtonTools = addButton(tr("Tools"), tr("External tools configured in Options -> Helper (run on a copy)"), nullptr);
    m_pButtonTools->setPopupMode(QToolButton::InstantPopup);
    m_pMenuTools = new QMenu(m_pButtonTools);
    m_pButtonTools->setMenu(m_pMenuTools);

    pLayout->addStretch();

    _updateButtons();

    return pBar;
}

void HelperActions::setGlobal(XShortcuts *pShortcuts, XOptions *pOptions)
{
    m_pShortcuts = pShortcuts;
    m_pOptions = pOptions;
}

void HelperActions::setFileName(const QString &sFileName)
{
    m_sFileName = sFileName;
    m_evidence = {};
    m_bHasEvidence = false;
    m_listRecords.clear();
    m_listTables.clear();
    m_listOepRVAs.clear();

    HelperUnpacker::INFO info = sFileName.isEmpty() ? HelperUnpacker::INFO() : HelperUnpacker::detect(sFileName);
    m_bUnpackerAvailable = info.bAvailable;
    m_bBrokenUpx = info.bLooksLikeBrokenUpx;
    m_sUnpacker = info.sPacker;

    _updateButtons();
}

void HelperActions::setContext(const HelperEvidence::RESULT &evidence, const QList<XScanEngine::SCANSTRUCT> &listRecords)
{
    m_evidence = evidence;
    m_bHasEvidence = evidence.bIsValid;
    m_listRecords = listRecords;

    // "UPX (modified)" / renamed sections from DiE also qualify for the repair
    for (qint32 i = 0; i < listRecords.count(); i++) {
        if (listRecords.at(i).sName.startsWith("UPX", Qt::CaseInsensitive) && !m_bUnpackerAvailable) {
            m_bBrokenUpx = true;
        }
    }

    _updateButtons();
}

void HelperActions::_updateButtons()
{
    if (!m_pButtonUnpack) {
        return;
    }

    bool bPE = m_bHasEvidence;

    m_pButtonUnpack->setEnabled(bPE && m_bUnpackerAvailable);
    m_pButtonUnpack->setText(m_bUnpackerAvailable ? tr("Unpack %1").arg(m_sUnpacker) : tr("Unpack"));
    m_pButtonRepairUpx->setVisible(m_bBrokenUpx);
    m_pButtonRepairUpx->setEnabled(bPE);
    m_pButtonOep->setEnabled(bPE && !m_evidence.bIsNET);
    m_pButtonDecompress->setEnabled(bPE && !m_evidence.bIsNET);
    m_pButtonStrings->setEnabled(bPE);
    m_pButtonApiHashes->setEnabled(bPE && !m_evidence.bIsNET);
    m_pButtonNet->setVisible(bPE && m_evidence.bIsNET);
    m_pButtonPeTools->setEnabled(bPE);
    m_pButtonMore->setEnabled(!m_sFileName.isEmpty());

    // external tools
    m_pMenuTools->clear();

    struct TOOL {
        HelperSettings::TOOL tool;
        QString sTitle;
    };

    QList<TOOL> listTools = {{HelperSettings::TOOL_UPX, tr("upx -d (unpack copy)")},
                             {HelperSettings::TOOL_DE4DOT, tr("de4dot (deobfuscate .NET copy)")},
                             {HelperSettings::TOOL_CUSTOM, HelperSettings::getCustomToolName().isEmpty() ? tr("Custom tool") : HelperSettings::getCustomToolName()}};

    for (const TOOL &tool : listTools) {
        if (!HelperSettings::getToolPath(tool.tool).isEmpty()) {
            HelperSettings::TOOL nTool = tool.tool;
            m_pMenuTools->addAction(tool.sTitle, this, [this, nTool]() { onExternalTool(nTool); });
        }
    }

    m_pButtonTools->setVisible(!m_pMenuTools->isEmpty());
    m_pButtonTools->setEnabled(!m_sFileName.isEmpty());
}

bool HelperActions::_isReady(const QString &sTitle)
{
    if (m_sFileName.isEmpty() || !QFileInfo::exists(m_sFileName)) {
        QMessageBox::information(m_pParentWidget, sTitle, tr("Open a file first."));
        return false;
    }

    return true;
}

bool HelperActions::_run(const QString &sTitle, const std::function<void(XBinary::PDSTRUCT *)> &function)
{
    // declared before the dialog so it outlives it (the dialog waits for its thread in the destructor)
    HelperTask task(sTitle, function);
    XDialogProcess dialogProcess(m_pParentWidget, &task);
    task.setPdStruct(dialogProcess.getPdStruct());

    if (m_pShortcuts && m_pOptions) {
        dialogProcess.setGlobal(m_pShortcuts, m_pOptions);
    }

    dialogProcess.start();
    dialogProcess.showDialogDelay();

    return dialogProcess.isSuccess();
}

QString HelperActions::_getOutputFileName(const QString &sSuffix, const QString &sFilter)
{
    QFileInfo fileInfo(m_sFileName);
    QString sBaseName = fileInfo.completeBaseName();
    QString sExt = fileInfo.suffix().isEmpty() ? QString() : QString(".") + fileInfo.suffix();

    // sSuffix like "unpacked" -> name.unpacked.exe; sSuffix with its own extension ("report.html") -> name.report.html
    QString sFileName = sSuffix.contains('.') ? QString("%1.%2").arg(sBaseName, sSuffix) : QString("%1.%2%3").arg(sBaseName, sSuffix, sExt);

    QString sFolder = HelperSettings::getOutputFolder();

    if (!sFolder.isEmpty()) {
        QDir().mkpath(sFolder);
        QString sResult = QDir(sFolder).filePath(sFileName);
        QFileInfo resultInfo(sResult);

        for (qint32 i = 1; QFileInfo::exists(sResult) && (i < 1000); i++) {
            sResult = QDir(sFolder).filePath(QString("%1_%2.%3").arg(resultInfo.completeBaseName()).arg(i).arg(resultInfo.suffix()));
        }

        return sResult;
    }

    QString sResult = QFileDialog::getSaveFileName(m_pParentWidget, tr("Save result as"), fileInfo.dir().filePath(sFileName), sFilter);

    if (!sResult.isEmpty() && (QFileInfo(sResult).absoluteFilePath() == fileInfo.absoluteFilePath())) {
        QMessageBox::warning(m_pParentWidget, tr("Save result as"), tr("The original file is never overwritten. Choose another name."));
        return QString();
    }

    return sResult;
}

void HelperActions::_log(const QString &sTitle, const QStringList &listLines)
{
    QString sText = QString("[%1] %2").arg(sTitle, listLines.join(QString("\n    ")));
    emit logMessage(sText);
}

void HelperActions::_emitTable(const TABLE &table)
{
    for (qint32 i = 0; i < m_listTables.count(); i++) {
        if (m_listTables.at(i).sTitle == table.sTitle) {
            m_listTables.removeAt(i);
            break;
        }
    }

    m_listTables.append(table);
    emit tableReady(table);
}

void HelperActions::_finishFileAction(const QString &sTitle, bool bSuccess, const QString &sError, const QStringList &listLog, const QString &sOutput)
{
    QStringList listLines = listLog;

    if (!bSuccess) {
        listLines.append(tr("FAILED: %1").arg(sError));
        _log(sTitle, listLines);
        QMessageBox::warning(m_pParentWidget, sTitle, sError + (listLog.isEmpty() ? QString() : QString("\n\n") + listLog.join("\n")));
        return;
    }

    listLines.append(tr("Result: %1").arg(QDir::toNativeSeparators(sOutput)));
    _log(sTitle, listLines);

    QMessageBox messageBox(m_pParentWidget);
    messageBox.setWindowTitle(sTitle);
    messageBox.setIcon(QMessageBox::Information);
    messageBox.setText(tr("Done: %1").arg(QDir::toNativeSeparators(sOutput)));
    messageBox.setDetailedText(listLog.join("\n"));
    QPushButton *pButtonOpen = messageBox.addButton(tr("Open in DiE"), QMessageBox::AcceptRole);
    QPushButton *pButtonCompare = messageBox.addButton(tr("Compare before/after"), QMessageBox::ActionRole);
    QPushButton *pButtonFolder = messageBox.addButton(tr("Show folder"), QMessageBox::ActionRole);
    messageBox.addButton(QMessageBox::Close);
    messageBox.exec();

    if (messageBox.clickedButton() == pButtonOpen) {
        emit openFileRequested(sOutput);
    } else if (messageBox.clickedButton() == pButtonCompare) {
        _showCompareDialog(m_pParentWidget, m_sFileName, sOutput);
    } else if (messageBox.clickedButton() == pButtonFolder) {
        QDesktopServices::openUrl(QUrl::fromLocalFile(QFileInfo(sOutput).absolutePath()));
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Tier 1

void HelperActions::onUnpack()
{
    const QString sTitle = tr("Unpack %1").arg(m_sUnpacker);

    if (!_isReady(sTitle)) {
        return;
    }

    QString sOutput = _getOutputFileName(QString("unpacked"), tr("Executables (*.exe *.dll);;All files (*)"));

    if (sOutput.isEmpty()) {
        return;
    }

    HelperUnpacker::RESULT result = {};
    QString sInput = m_sFileName;
    _run(sTitle, [&](XBinary::PDSTRUCT *pPdStruct) { result = HelperUnpacker::unpack(sInput, sOutput, pPdStruct); });

    _finishFileAction(sTitle, result.bSuccess, result.sError, result.listLog, sOutput);
}

void HelperActions::onRepairUpx()
{
    const QString sTitle = tr("Repair UPX header");

    if (!_isReady(sTitle)) {
        return;
    }

    QString sOutput = _getOutputFileName(QString("unpacked"), tr("Executables (*.exe *.dll);;All files (*)"));

    if (sOutput.isEmpty()) {
        return;
    }

    HelperUnpacker::RESULT result = {};
    QString sInput = m_sFileName;
    _run(sTitle, [&](XBinary::PDSTRUCT *pPdStruct) { result = HelperUnpacker::repairUpx(sInput, sOutput, pPdStruct); });

    _finishFileAction(sTitle, result.bSuccess, result.sError, result.listLog, sOutput);
}

void HelperActions::onFindOep()
{
    const QString sTitle = tr("Find OEP");

    if (!_isReady(sTitle)) {
        return;
    }

    HelperOepFinder::RESULT result = {};
    QString sInput = m_sFileName;
    _run(sTitle, [&](XBinary::PDSTRUCT *pPdStruct) { result = HelperOepFinder::find(sInput, pPdStruct); });

    if (!result.bIsValid) {
        QMessageBox::warning(m_pParentWidget, sTitle, result.sError);
        return;
    }

    TABLE table = {};
    table.sTitle = tr("OEP candidates");
    table.listHeaders = {tr("Confidence"), tr("OEP (VA)"), tr("RVA"), tr("Section"), tr("Rule"), tr("Details"), tr("Jump site")};
    m_listOepRVAs.clear();

    for (const HelperOepFinder::CANDIDATE &candidate : result.listCandidates) {
        table.listRows.append({QString("%1%").arg(candidate.nConfidence), _hex(candidate.nAddress), _hex(candidate.nRVA), candidate.sSection, candidate.sRule,
                               candidate.sDetails, _hex(candidate.nJumpSiteAddress)});
        table.listLocations.append(_location(HelperEvidence::LOCATION_DISASM, candidate.nOffset, 1, candidate.nJumpSiteAddress ? candidate.nJumpSiteAddress : candidate.nAddress));
        m_listOepRVAs.append(candidate.nRVA);
    }

    if (result.listCandidates.isEmpty()) {
        table.listRows.append({QString(), QString(), QString(), QString(), tr("no candidate"), result.listTrace.isEmpty() ? QString() : result.listTrace.last(), QString()});
        table.listLocations.append(HelperEvidence::INDICATOR());
    }

    _emitTable(table);
    _log(sTitle, QStringList(tr("%1 candidate(s); walk log:").arg(result.listCandidates.count())) + result.listTrace.mid(0, 60));
}

qint64 HelperActions::_getBestOepRVA()
{
    if (m_listOepRVAs.isEmpty() && m_bHasEvidence) {
        HelperOepFinder::RESULT result = HelperOepFinder::find(m_sFileName);

        for (const HelperOepFinder::CANDIDATE &candidate : result.listCandidates) {
            m_listOepRVAs.append(candidate.nRVA);
        }
    }

    return m_listOepRVAs.isEmpty() ? -1 : m_listOepRVAs.first();
}

// ---------------------------------------------------------------------------------------------------------------
// Tier 2

void HelperActions::onDecompress()
{
    const QString sTitle = tr("Decompress (generic)");

    if (!_isReady(sTitle)) {
        return;
    }

    HelperDecompressor::RESULT result = {};
    QString sInput = m_sFileName;
    _run(sTitle, [&](XBinary::PDSTRUCT *pPdStruct) { result = HelperDecompressor::scan(sInput, pPdStruct); });

    if (!result.bIsValid) {
        QMessageBox::warning(m_pParentWidget, sTitle, result.sError);
        return;
    }

    TABLE table = {};
    table.sTitle = tr("Compressed blobs");
    table.listHeaders = {tr("Score"), tr("Algorithm"), tr("Offset"), tr("Section"), tr("Packed size"), tr("Unpacked size"), tr("Details")};

    for (const HelperDecompressor::BLOB &blob : result.listBlobs) {
        table.listRows.append({QString::number(blob.nScore), HelperDecompressor::algoToString(blob.algo), _hex(blob.nOffset), blob.sSection,
                               (blob.nCompressedSize >= 0) ? _hex(blob.nCompressedSize) : QString("?"), _hex(blob.baData.size()), blob.sDetails});
        table.listLocations.append(_location(HelperEvidence::LOCATION_HEX, blob.nOffset, qMax<qint64>(blob.nCompressedSize, 1), 0));
    }

    _emitTable(table);
    _log(sTitle, result.listLog.mid(0, 60));

    if (result.listBlobs.isEmpty()) {
        QMessageBox::information(m_pParentWidget, sTitle, tr("No compressed stream recognised (tried NRV2B/D/E, LZMA, aPLib, zlib, deflate, LZNT1)."));
        return;
    }

    // choose a blob, then rebuild a PE with it (or just save the raw data)
    QStringList listItems;

    for (const HelperDecompressor::BLOB &blob : result.listBlobs) {
        listItems.append(QString("%1 at %2 -> %3 bytes (score %4)").arg(HelperDecompressor::algoToString(blob.algo), _hex(blob.nOffset)).arg(blob.baData.size()).arg(blob.nScore));
    }

    bool bOK = false;
    QString sItem = QInputDialog::getItem(m_pParentWidget, sTitle, tr("Decompressed stream to use:"), listItems, 0, false, &bOK);

    if (!bOK) {
        return;
    }

    const HelperDecompressor::BLOB &blob = result.listBlobs.at(listItems.indexOf(sItem));

    QMessageBox messageBox(m_pParentWidget);
    messageBox.setWindowTitle(sTitle);
    messageBox.setText(tr("Rebuild a PE with this data placed back into the image (entry point = best OEP candidate), or save the raw decompressed bytes?"));
    QPushButton *pButtonRebuild = messageBox.addButton(tr("Rebuild PE"), QMessageBox::AcceptRole);
    QPushButton *pButtonRaw = messageBox.addButton(tr("Save raw data"), QMessageBox::ActionRole);
    messageBox.addButton(QMessageBox::Cancel);
    messageBox.exec();

    if (messageBox.clickedButton() == pButtonRaw) {
        QString sOutput = _getOutputFileName(QString("blob.bin"), tr("Binary (*.bin);;All files (*)"));

        if (!sOutput.isEmpty()) {
            QFile file(sOutput);
            bool bSaved = file.open(QIODevice::WriteOnly) && (file.write(blob.baData) == blob.baData.size());
            _finishFileAction(sTitle, bSaved, tr("Cannot write %1").arg(sOutput), QStringList(blob.sDetails), sOutput);
        }
    } else if (messageBox.clickedButton() == pButtonRebuild) {
        QString sOutput = _getOutputFileName(QString("rebuilt"), tr("Executables (*.exe *.dll);;All files (*)"));

        if (sOutput.isEmpty()) {
            return;
        }

        qint64 nOepRVA = _getBestOepRVA();

        HelperRebuild::OPTIONS options = {};
        options.nOEP = (nOepRVA >= 0) ? (XADDR)(m_evidence.nImageBase + nOepRVA) : 0;
        options.nTargetRVA = -1;
        options.bRebuildImports = true;
        options.bFixChecksum = true;
        options.bRestoreCharacteristics = true;

        HelperRebuild::RESULT rebuild = {};
        QByteArray baData = blob.baData;
        QStringList listUpxLog;
        QList<HelperUpx::ORIGINAL_SECTION> listOriginalSections;

        // UPX: the stream is the UPX payload when its size matches the pack header -> undo the call/jump filter
        // on the original code and keep the original section names (both come from headers stored in the stream)
        HelperUpx::PACKINFO packInfo = HelperUpx::readPackHeader(sInput);
        qint64 nUpxStreamRVA = -1;
        bool bIsUpxStream = false;

        if (packInfo.bIsValid && ((qint64)packInfo.nUncompressedSize == baData.size())) {
            for (const HelperEvidence::SECTION &section : m_evidence.listSections) {
                if ((section.nIndex >= 0) && (section.nRawSize == 0)) {
                    nUpxStreamRVA = section.nRVA;
                    break;
                }
            }

            if (nUpxStreamRVA > 0) {
                bIsUpxStream = HelperUpx::unfilter(&baData, nUpxStreamRVA, packInfo, &listOriginalSections, &listUpxLog);
            }
        }

        if (bIsUpxStream) {
            options.bRebuildImports = false;  // UPX's own packed import list is used instead (finishRebuiltFile)
        }

        _run(sTitle, [&](XBinary::PDSTRUCT *pPdStruct) { rebuild = HelperRebuild::rebuildWithBlob(sInput, sOutput, baData, options, pPdStruct); });

        if (rebuild.bSuccess && bIsUpxStream) {
            HelperUpx::finishRebuiltFile(sOutput, sInput, baData, nUpxStreamRVA, listOriginalSections, &listUpxLog);
        }

        QStringList listLog = listUpxLog + rebuild.listLog;
        listLog.prepend(tr("OEP: %1").arg((nOepRVA >= 0) ? _hex(options.nOEP) : tr("unchanged (no candidate)")));
        _finishFileAction(sTitle, rebuild.bSuccess, rebuild.sError, listLog, sOutput);
    }
}

void HelperActions::onRebuildImports()
{
    const QString sTitle = tr("Rebuild imports");

    if (!_isReady(sTitle)) {
        return;
    }

    QString sOutput = _getOutputFileName(QString("imports"), tr("Executables (*.exe *.dll);;All files (*)"));

    if (sOutput.isEmpty()) {
        return;
    }

    HelperRebuild::RESULT result = {};
    QString sInput = m_sFileName;
    _run(sTitle, [&](XBinary::PDSTRUCT *pPdStruct) { result = HelperRebuild::reconstructImports(sInput, sOutput, pPdStruct); });

    _finishFileAction(sTitle, result.bSuccess, result.sError, result.listLog, sOutput);
}

// ---------------------------------------------------------------------------------------------------------------
// Tier 3

void HelperActions::onStrings()
{
    const QString sTitle = tr("Recover strings");

    if (!_isReady(sTitle)) {
        return;
    }

    HelperStrings::RESULT result = {};
    QString sInput = m_sFileName;
    _run(sTitle, [&](XBinary::PDSTRUCT *pPdStruct) { result = HelperStrings::recover(sInput, pPdStruct); });

    if (!result.bIsValid) {
        QMessageBox::warning(m_pParentWidget, sTitle, result.sError);
        return;
    }

    TABLE table = {};
    table.sTitle = tr("Recovered strings");
    table.listHeaders = {tr("Score"), tr("Method"), tr("Offset"), tr("Address"), tr("String")};

    for (const HelperStrings::RECORD &record : result.listRecords) {
        table.listRows.append({QString::number(record.nScore), record.sMethod, (record.nOffset >= 0) ? _hex(record.nOffset) : QString(), record.nAddress ? _hex(record.nAddress) : QString(),
                               record.sString});
        table.listLocations.append((record.nOffset >= 0) ? _location(HelperEvidence::LOCATION_HEX, record.nOffset, qMax(1, (int)record.sString.size()), 0)
                                                         : HelperEvidence::INDICATOR());
    }

    _emitTable(table);
    _log(sTitle, QStringList(tr("%1 string(s) recovered").arg(result.listRecords.count())));
}

void HelperActions::onApiHashes()
{
    const QString sTitle = tr("API hashes");

    if (!_isReady(sTitle)) {
        return;
    }

    HelperApiHash::RESULT result = {};
    QString sInput = m_sFileName;
    _run(sTitle, [&](XBinary::PDSTRUCT *pPdStruct) { result = HelperApiHash::scan(sInput, pPdStruct); });

    if (!result.bIsValid) {
        QMessageBox::warning(m_pParentWidget, sTitle, result.sError);
        return;
    }

    TABLE table = {};
    table.sTitle = tr("API hashes");
    table.listHeaders = {tr("Kind"), tr("Address"), tr("Value"), tr("Algorithm / callee"), tr("API")};

    for (const HelperApiHash::HIT &hit : result.listHits) {
        table.listRows.append({tr("hash"), hit.nAddress ? _hex(hit.nAddress) : _hex(hit.nOffset), QString("0x%1").arg(hit.nHash, 8, 16, QChar('0')), hit.sAlgorithm,
                               hit.sLibrary.isEmpty() ? hit.sFunction : QString("%1!%2").arg(hit.sLibrary, hit.sFunction)});
        table.listLocations.append(hit.nAddress ? _location(HelperEvidence::LOCATION_DISASM, hit.nOffset, 4, hit.nAddress) : _location(HelperEvidence::LOCATION_HEX, hit.nOffset, 4, 0));
    }

    for (const HelperApiHash::CALLSITE &callSite : result.listCallSites) {
        table.listRows.append({tr("call site"), _hex(callSite.nAddress), QString(), callSite.sCallee, callSite.sArgument});
        table.listLocations.append(_location(HelperEvidence::LOCATION_DISASM, -1, 1, callSite.nAddress));
    }

    _emitTable(table);
    _log(sTitle, QStringList(tr("%1 hash hit(s), %2 call site(s); %3 known API names").arg(result.listHits.count()).arg(result.listCallSites.count()).arg(result.nKnownApis)));
}

void HelperActions::onNetInfo()
{
    const QString sTitle = tr(".NET deobfuscation view");

    if (!_isReady(sTitle)) {
        return;
    }

    HelperNetInfo::RESULT result = {};
    QString sInput = m_sFileName;
    _run(sTitle, [&](XBinary::PDSTRUCT *pPdStruct) { result = HelperNetInfo::analyze(sInput, pPdStruct); });

    if (!result.bIsValid) {
        QMessageBox::warning(m_pParentWidget, sTitle, result.sError);
        return;
    }

    TABLE table = {};
    table.sTitle = tr(".NET");
    table.listHeaders = {tr("Kind"), tr("Name / marker"), tr("Readable alias / details"), tr("Offset"), tr("Entropy")};

    for (const HelperNetInfo::MARKER &marker : result.listMarkers) {
        table.listRows.append({tr("marker"), marker.sName, marker.sDetails, QString(), QString()});
        table.listLocations.append(HelperEvidence::INDICATOR());
    }

    for (const HelperNetInfo::METHOD &method : result.listTopEntropyMethods) {
        table.listRows.append({tr("method body"), method.sName, tr("%1 bytes").arg(method.nSize), _hex(method.nOffset), QString::number(method.dEntropy, 'f', 2)});
        table.listLocations.append(_location(HelperEvidence::LOCATION_HEX, method.nOffset, method.nSize, 0));
    }

    for (const HelperNetInfo::NAME &name : result.listNames) {
        if (name.bObfuscated) {
            table.listRows.append({name.sKind, name.sOriginal, name.sAlias, QString(), QString()});
            table.listLocations.append(HelperEvidence::INDICATOR());
        }
    }

    for (const QString &sString : result.listUserStrings) {
        table.listRows.append({tr("user string"), sString, QString(), QString(), QString()});
        table.listLocations.append(HelperEvidence::INDICATOR());
    }

    _emitTable(table);
    _log(sTitle, QStringList(tr("%1 marker(s), %2 name(s), %3 user string(s)").arg(result.listMarkers.count()).arg(result.listNames.count()).arg(result.listUserStrings.count())));
}

// ---------------------------------------------------------------------------------------------------------------
// PE surgery (copies)

void HelperActions::onSetEntryPoint()
{
    const QString sTitle = tr("Set entry point");

    if (!_isReady(sTitle)) {
        return;
    }

    qint64 nDefault = m_listOepRVAs.isEmpty() ? m_evidence.nEntryPointRVA : m_listOepRVAs.first();
    bool bOK = false;
    QString sValue = QInputDialog::getText(m_pParentWidget, sTitle, tr("New entry point RVA (hex). Pre-filled with the best OEP candidate if \"Find OEP\" ran:"),
                                           QLineEdit::Normal, QString::number(nDefault, 16), &bOK);

    if (!bOK) {
        return;
    }

    qint64 nRVA = sValue.trimmed().remove("0x", Qt::CaseInsensitive).toLongLong(&bOK, 16);

    if (!bOK) {
        QMessageBox::warning(m_pParentWidget, sTitle, tr("Not a hex number: %1").arg(sValue));
        return;
    }

    QString sOutput = _getOutputFileName(QString("ep"), tr("Executables (*.exe *.dll);;All files (*)"));

    if (!sOutput.isEmpty()) {
        HelperPeSurgery::RESULT result = HelperPeSurgery::setEntryPoint(m_sFileName, sOutput, nRVA);
        _finishFileAction(sTitle, result.bSuccess, result.sError, result.listLog, sOutput);
    }
}

void HelperActions::onStripOverlay()
{
    const QString sTitle = tr("Strip overlay");

    if (!_isReady(sTitle)) {
        return;
    }

    QString sOutput = _getOutputFileName(QString("nooverlay"), tr("Executables (*.exe *.dll);;All files (*)"));

    if (!sOutput.isEmpty()) {
        HelperPeSurgery::RESULT result = HelperPeSurgery::stripOverlay(m_sFileName, sOutput);
        _finishFileAction(sTitle, result.bSuccess, result.sError, result.listLog, sOutput);
    }
}

void HelperActions::onSaveOverlay()
{
    const QString sTitle = tr("Save overlay");

    if (!_isReady(sTitle)) {
        return;
    }

    if (m_evidence.nOverlayOffset < 0) {
        QMessageBox::information(m_pParentWidget, sTitle, tr("The file has no overlay."));
        return;
    }

    QString sOutput = _getOutputFileName(QString("overlay.bin"), tr("Binary (*.bin);;All files (*)"));

    if (!sOutput.isEmpty()) {
        HelperPeSurgery::RESULT result = HelperPeSurgery::saveRange(m_sFileName, sOutput, m_evidence.nOverlayOffset, m_evidence.nOverlaySize);
        _finishFileAction(sTitle, result.bSuccess, result.sError, result.listLog, sOutput);
    }
}

void HelperActions::onSaveSection()
{
    const QString sTitle = tr("Save section");

    if (!_isReady(sTitle)) {
        return;
    }

    QStringList listItems;
    QList<qint32> listIndexes;

    for (qint32 i = 0; i < m_evidence.listSections.count(); i++) {
        const HelperEvidence::SECTION &section = m_evidence.listSections.at(i);

        if (section.nRawSize > 0) {
            listItems.append(QString("%1 (offset %2, %3 bytes, entropy %4)").arg(section.sName, _hex(section.nRawOffset)).arg(section.nRawSize).arg(section.dEntropy, 0, 'f', 2));
            listIndexes.append(i);
        }
    }

    bool bOK = false;
    QString sItem = QInputDialog::getItem(m_pParentWidget, sTitle, tr("Section:"), listItems, 0, false, &bOK);

    if (!bOK || sItem.isEmpty()) {
        return;
    }

    const HelperEvidence::SECTION &section = m_evidence.listSections.at(listIndexes.at(listItems.indexOf(sItem)));
    QString sSafeName = section.sName;
    sSafeName.replace(QRegularExpression("[^A-Za-z0-9_]"), "_");
    QString sOutput = _getOutputFileName(QString("%1.bin").arg(sSafeName.isEmpty() ? QString("section") : sSafeName), tr("Binary (*.bin);;All files (*)"));

    if (!sOutput.isEmpty()) {
        HelperPeSurgery::RESULT result = HelperPeSurgery::saveRange(m_sFileName, sOutput, section.nRawOffset, section.nRawSize);
        _finishFileAction(sTitle, result.bSuccess, result.sError, result.listLog, sOutput);
    }
}

void HelperActions::onRestoreFlags()
{
    const QString sTitle = tr("Restore section flags");

    if (!_isReady(sTitle)) {
        return;
    }

    QString sOutput = _getOutputFileName(QString("flags"), tr("Executables (*.exe *.dll);;All files (*)"));

    if (!sOutput.isEmpty()) {
        HelperPeSurgery::RESULT result = HelperPeSurgery::restoreSectionFlags(m_sFileName, sOutput);
        _finishFileAction(sTitle, result.bSuccess, result.sError, result.listLog, sOutput);
    }
}

void HelperActions::onRenameSection()
{
    const QString sTitle = tr("Rename section");

    if (!_isReady(sTitle)) {
        return;
    }

    QStringList listItems;
    QList<qint32> listHeaderIndexes;

    for (const HelperEvidence::SECTION &section : m_evidence.listSections) {
        if (section.nIndex >= 0) {
            listItems.append(QString("#%1 %2").arg(section.nIndex).arg(section.sName));
            listHeaderIndexes.append(section.nIndex);
        }
    }

    bool bOK = false;
    QString sItem = QInputDialog::getItem(m_pParentWidget, sTitle, tr("Section:"), listItems, 0, false, &bOK);

    if (!bOK || sItem.isEmpty()) {
        return;
    }

    QString sName = QInputDialog::getText(m_pParentWidget, sTitle, tr("New name (max 8 characters):"), QLineEdit::Normal, QString(), &bOK);

    if (!bOK || sName.isEmpty()) {
        return;
    }

    QString sOutput = _getOutputFileName(QString("renamed"), tr("Executables (*.exe *.dll);;All files (*)"));

    if (!sOutput.isEmpty()) {
        HelperPeSurgery::RESULT result = HelperPeSurgery::renameSection(m_sFileName, sOutput, listHeaderIndexes.at(listItems.indexOf(sItem)), sName);
        _finishFileAction(sTitle, result.bSuccess, result.sError, result.listLog, sOutput);
    }
}

void HelperActions::onRemoveTls()
{
    const QString sTitle = tr("Remove TLS callbacks");

    if (!_isReady(sTitle)) {
        return;
    }

    QString sOutput = _getOutputFileName(QString("notls"), tr("Executables (*.exe *.dll);;All files (*)"));

    if (!sOutput.isEmpty()) {
        HelperPeSurgery::RESULT result = HelperPeSurgery::removeTls(m_sFileName, sOutput);
        _finishFileAction(sTitle, result.bSuccess, result.sError, result.listLog, sOutput);
    }
}

void HelperActions::onFixChecksum()
{
    const QString sTitle = tr("Fix checksum");

    if (!_isReady(sTitle)) {
        return;
    }

    QString sOutput = _getOutputFileName(QString("checksum"), tr("Executables (*.exe *.dll);;All files (*)"));

    if (!sOutput.isEmpty()) {
        HelperPeSurgery::RESULT result = HelperPeSurgery::fixChecksum(m_sFileName, sOutput);
        _finishFileAction(sTitle, result.bSuccess, result.sError, result.listLog, sOutput);
    }
}

// ---------------------------------------------------------------------------------------------------------------
// More

void HelperActions::onExtract()
{
    if (!_isReady(tr("Extract"))) {
        return;
    }

    QFile file(m_sFileName);

    if (!file.open(QIODevice::ReadOnly)) {
        return;
    }

    FW_DEF::OPTIONS options = {};
    options.nStartType = SPE::TYPE_EXTRACTOR;
    options.nImageBase = -1;

    DialogPE dialog(m_pParentWidget);

    if (m_pShortcuts && m_pOptions) {
        dialog.setGlobal(m_pShortcuts, m_pOptions);
    }

    dialog.setData(&file, options);
    dialog.exec();

    file.close();
}

void HelperActions::onReport()
{
    const QString sTitle = tr("Export report");

    if (!_isReady(sTitle)) {
        return;
    }

    QString sOutput = _getOutputFileName(QString("report.html"), tr("HTML (*.html);;Markdown (*.md);;JSON (*.json)"));

    if (sOutput.isEmpty()) {
        return;
    }

    QList<HelperReport::EXTRA> listExtras;

    for (const TABLE &table : m_listTables) {
        HelperReport::EXTRA extra = {};
        extra.sTitle = table.sTitle;
        extra.listHeaders = table.listHeaders;
        extra.listRows = table.listRows;
        listExtras.append(extra);
    }

    HelperEvidence::RESULT evidence = m_bHasEvidence ? m_evidence : HelperEvidence::analyze(m_sFileName);
    QString sContent = HelperReport::build(HelperReport::formatFromFileName(sOutput), m_sFileName, evidence, m_listRecords, listExtras);
    bool bSaved = HelperReport::save(sOutput, sContent);

    _finishFileAction(sTitle, bSaved, tr("Cannot write %1").arg(sOutput), QStringList(tr("%1 result table(s) included").arg(listExtras.count())), sOutput);
}

void HelperActions::onSignature()
{
    const QString sTitle = tr("Make custom signature");

    if (!_isReady(sTitle)) {
        return;
    }

    bool bOK = false;
    QString sType = QInputDialog::getItem(m_pParentWidget, sTitle, tr("Type:"), {"packer", "protector", "cryptor", "joiner", "installer", "malware", "tool"}, 0, true, &bOK);

    if (!bOK || sType.isEmpty()) {
        return;
    }

    QString sName = QInputDialog::getText(m_pParentWidget, sTitle, tr("Name (shown by DiE):"), QLineEdit::Normal, QFileInfo(m_sFileName).completeBaseName(), &bOK);

    if (!bOK || sName.isEmpty()) {
        return;
    }

    HelperSignatureMaker::RESULT result = HelperSignatureMaker::makeFromEntryPoint(m_sFileName, sType, sName);

    if (!result.bIsValid) {
        QMessageBox::warning(m_pParentWidget, sTitle, result.sError);
        return;
    }

    QString sDbCustom = m_pOptions ? XOptions::convertPathName(m_pOptions->getValue(XOptions::ID_SCAN_DIE_DATABASE_CUSTOM_PATH).toString()) : QString();

    if (sDbCustom.isEmpty()) {
        sDbCustom = XOptions::convertPathName(QString("$data/db_custom"));
    }

    QMessageBox messageBox(m_pParentWidget);
    messageBox.setWindowTitle(sTitle);
    messageBox.setText(tr("Pattern: %1\n\nSave to the custom database (%2)?").arg(result.sPattern, QDir::toNativeSeparators(sDbCustom)));
    messageBox.setDetailedText(result.sScript + QString("\n\n") + result.listNotes.join("\n"));
    messageBox.setStandardButtons(QMessageBox::Save | QMessageBox::Cancel);

    if (messageBox.exec() != QMessageBox::Save) {
        return;
    }

    QString sSavedFileName;
    QString sError;
    bool bSaved = HelperSignatureMaker::save(sDbCustom, result, sType, sName, false, &sSavedFileName, &sError);

    if (!bSaved && QFileInfo::exists(sSavedFileName) &&
        (QMessageBox::question(m_pParentWidget, sTitle, tr("%1 exists. Overwrite?").arg(QDir::toNativeSeparators(sSavedFileName))) == QMessageBox::Yes)) {
        bSaved = HelperSignatureMaker::save(sDbCustom, result, sType, sName, true, &sSavedFileName, &sError);
    }

    QStringList listLog = result.listNotes;
    listLog.append(tr("Rescan (or restart DiE) to load it. To keep it across rebuilds, also copy it into the repo's db_custom/PE folder."));
    _finishFileAction(sTitle, bSaved, sError, listLog, sSavedFileName);
}

void HelperActions::onBatch()
{
    HelperBatchDialog dialog(m_pParentWidget, m_pOptions);
    dialog.exec();
}

// ---------------------------------------------------------------------------------------------------------------
// External tools (optional; the user configures the executables; they only see copies)

void HelperActions::onExternalTool(qint32 nTool)
{
    HelperSettings::TOOL tool = (HelperSettings::TOOL)nTool;
    QString sProgram = HelperSettings::getToolPath(tool);
    QString sTitle = (tool == HelperSettings::TOOL_UPX) ? QString("upx -d") : ((tool == HelperSettings::TOOL_DE4DOT) ? QString("de4dot") : HelperSettings::getCustomToolName());

    if (!_isReady(sTitle)) {
        return;
    }

    if (!QFileInfo(sProgram).isFile()) {
        QMessageBox::warning(m_pParentWidget, sTitle, tr("Tool not found: %1 (Options -> Helper)").arg(sProgram));
        return;
    }

    QString sOutput = _getOutputFileName((tool == HelperSettings::TOOL_DE4DOT) ? QString("cleaned") : QString("unpacked"), tr("Executables (*.exe *.dll);;All files (*)"));

    if (sOutput.isEmpty()) {
        return;
    }

    // the tool only ever gets a copy: the original stays untouched even if the tool misbehaves
    QString sCopy = QDir(QFileInfo(sOutput).absolutePath()).filePath(QFileInfo(m_sFileName).fileName() + QString(".input.tmp"));
    QFile::remove(sCopy);
    QFile::remove(sOutput);

    if (!QFile::copy(m_sFileName, sCopy)) {
        QMessageBox::warning(m_pParentWidget, sTitle, tr("Cannot create a working copy in %1").arg(QFileInfo(sOutput).absolutePath()));
        return;
    }

    QStringList listArguments;

    if (tool == HelperSettings::TOOL_UPX) {
        listArguments = {"-d", "-o", sOutput, sCopy};
    } else if (tool == HelperSettings::TOOL_DE4DOT) {
        listArguments = {"-f", sCopy, "-o", sOutput};
    } else {
        QString sTemplate = HelperSettings::getCustomToolArguments();
        sTemplate.replace("%in%", sCopy).replace("%out%", sOutput);
        listArguments = QProcess::splitCommand(sTemplate);
    }

    QStringList listLog;
    listLog.append(QString("%1 %2").arg(QDir::toNativeSeparators(sProgram), listArguments.join(' ')));
    qint32 nExitCode = -1;
    bool bFinished = false;

    _run(sTitle, [&](XBinary::PDSTRUCT *pPdStruct) {
        QProcess process;
        process.setProcessChannelMode(QProcess::MergedChannels);
        process.start(sProgram, listArguments);

        if (!process.waitForStarted(10000)) {
            listLog.append(tr("Cannot start: %1").arg(process.errorString()));
            return;
        }

        while (!process.waitForFinished(200)) {
            if (!XBinary::isPdStructNotCanceled(pPdStruct)) {
                process.kill();
                process.waitForFinished(2000);
                listLog.append(tr("Cancelled"));
                return;
            }
        }

        bFinished = true;
        nExitCode = process.exitCode();
        listLog.append(QString::fromLocal8Bit(process.readAll()).trimmed().split('\n'));
    });

    QFile::remove(sCopy);

    bool bSuccess = bFinished && (nExitCode == 0) && QFileInfo::exists(sOutput);
    _finishFileAction(sTitle, bSuccess, tr("%1 failed (exit code %2)").arg(sTitle).arg(nExitCode), listLog, sOutput);
}
