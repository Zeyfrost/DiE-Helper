// DiE Helper (fork addition): the "Packing" tab beside DiE's detection list. Shows at a glance HOW an
// EXE/DLL is packed or obfuscated: verdict, section map, ranked indicators with clickable locations,
// and a collapsible "How to unpack" hint.
#include "helperpackingview.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <algorithm>
#include <QHeaderView>
#include <QLabel>
#include <QRegularExpression>
#include <QPlainTextEdit>
#include <QSet>
#include <QSplitter>
#include <QTabWidget>
#include <QTime>
#include <QTextBrowser>
#include <QToolButton>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <QtConcurrent>

#include "dialoghexview.h"
#include "dialogmultidisasm.h"
#include "helpersectionmap.h"
#include "helpersettings.h"
#include "xoptions.h"
#include "xshortcuts.h"


HelperPackingView::HelperPackingView(QWidget *pParent) : QWidget(pParent)
{
    m_pShortcuts = nullptr;
    m_pOptions = nullptr;
    m_evidence = {};
    m_bEvidenceReady = false;
    m_bResultsReady = false;
    m_selectedRecord = {};
    m_bHasSelectedRecord = false;

    QVBoxLayout *pLayout = new QVBoxLayout(this);
    pLayout->setContentsMargins(4, 4, 4, 4);
    pLayout->setSpacing(4);

    m_pLabelVerdict = new QLabel(this);
    m_pLabelVerdict->setWordWrap(true);
    m_pLabelVerdict->setTextFormat(Qt::RichText);

    m_pSectionMap = new HelperSectionMap(this);

    m_pLabelLegend = new QLabel(this);
    m_pLabelLegend->setTextFormat(Qt::RichText);
    {
        auto swatch = [](const QColor &color, const QString &sText) {
            return QString("<span style='color:%1'>&#9632;</span>&nbsp;%2").arg(color.name(), sText);
        };
        QStringList listParts;
        listParts.append(tr("Entropy:"));
        listParts.append(swatch(HelperSectionMap::entropyToColor(4.0), tr("data &lt;5")));
        listParts.append(swatch(HelperSectionMap::entropyToColor(6.0), tr("code 5-6.5")));
        listParts.append(swatch(HelperSectionMap::entropyToColor(6.8), tr("suspicious 6.5-7.2")));
        listParts.append(swatch(HelperSectionMap::entropyToColor(7.5), tr("packed/encrypted &ge;7.2")));
        listParts.append(QString("&#9636;&nbsp;%1").arg(tr("virtual only")));
        listParts.append(QString("<span style='color:#ffdc00'>&#9650;</span>&nbsp;%1").arg(tr("entry point")));
        m_pLabelLegend->setText(QString("<small>%1</small>").arg(listParts.join("&nbsp;&nbsp; ")));
    }

    m_pLabelEntryPoint = new QLabel(this);
    m_pLabelEntryPoint->setTextFormat(Qt::RichText);
    m_pLabelEntryPoint->setWordWrap(true);
    m_pLabelEntryPoint->setTextInteractionFlags(Qt::TextBrowserInteraction);

    m_pTreeIndicators = new QTreeWidget(this);
    m_pTreeIndicators->setColumnCount(__COLUMN_SIZE);
    m_pTreeIndicators->setHeaderLabels({tr("Severity"), tr("Category"), tr("Indicator"), tr("Details"), tr("Location")});
    m_pTreeIndicators->setRootIsDecorated(false);
    m_pTreeIndicators->setAlternatingRowColors(true);
    m_pTreeIndicators->setUniformRowHeights(true);
    m_pTreeIndicators->setSelectionMode(QAbstractItemView::SingleSelection);
    m_pTreeIndicators->header()->setStretchLastSection(false);
    m_pTreeIndicators->header()->setSectionResizeMode(COLUMN_SEVERITY, QHeaderView::ResizeToContents);
    m_pTreeIndicators->header()->setSectionResizeMode(COLUMN_CATEGORY, QHeaderView::ResizeToContents);
    m_pTreeIndicators->header()->setSectionResizeMode(COLUMN_INDICATOR, QHeaderView::ResizeToContents);
    m_pTreeIndicators->header()->setSectionResizeMode(COLUMN_DETAILS, QHeaderView::Stretch);
    m_pTreeIndicators->header()->setSectionResizeMode(COLUMN_LOCATION, QHeaderView::ResizeToContents);

    // "How to unpack": a header button under the table; the text only takes space once expanded
    m_pToolButtonHowTo = new QToolButton(this);
    m_pToolButtonHowTo->setCheckable(true);
    m_pToolButtonHowTo->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    m_pToolButtonHowTo->setArrowType(Qt::RightArrow);
    m_pToolButtonHowTo->setAutoRaise(true);
    m_pToolButtonHowTo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_pTextBrowserHint = new QTextBrowser(this);
    m_pTextBrowserHint->setOpenLinks(false);
    m_pTextBrowserHint->setVisible(false);

    // results: the indicator list first, then one tab per action result, then the action log
    m_pTabWidgetResults = new QTabWidget(this);
    m_pTabWidgetResults->setDocumentMode(true);
    m_pTabWidgetResults->addTab(m_pTreeIndicators, tr("Indicators"));
    m_pTextEditLog = new QPlainTextEdit(this);
    m_pTextEditLog->setReadOnly(true);
    m_pTextEditLog->setLineWrapMode(QPlainTextEdit::NoWrap);
    m_pTabWidgetResults->addTab(m_pTextEditLog, tr("Action log"));

    m_pSplitter = new QSplitter(Qt::Vertical, this);
    m_pSplitter->addWidget(m_pTabWidgetResults);
    m_pSplitter->addWidget(m_pTextBrowserHint);
    m_pSplitter->setStretchFactor(0, 1);
    m_pSplitter->setStretchFactor(1, 1);
    m_pSplitter->setChildrenCollapsible(false);

    // actions: unpack / find OEP / decompress / deobfuscate / PE tools ... (all static, all on copies)
    m_pActions = new HelperActions(this);
    QWidget *pToolBar = m_pActions->createToolBar(this);

    pLayout->addWidget(m_pLabelVerdict);
    pLayout->addWidget(m_pSectionMap);
    pLayout->addWidget(m_pLabelLegend);
    pLayout->addWidget(m_pLabelEntryPoint);
    pLayout->addWidget(pToolBar);
    pLayout->addWidget(m_pSplitter, 1);
    pLayout->addWidget(m_pToolButtonHowTo);

    connect(m_pActions, &HelperActions::tableReady, this, &HelperPackingView::onTableReady);
    connect(m_pActions, &HelperActions::logMessage, this, [this](const QString &sText) {
        m_pTextEditLog->appendPlainText(QString("%1  %2").arg(QTime::currentTime().toString("HH:mm:ss"), sText));
    });
    connect(m_pActions, &HelperActions::openFileRequested, this, &HelperPackingView::openFileRequested);

    connect(&m_watcher, SIGNAL(finished()), this, SLOT(onEvidenceFinished()));
    connect(m_pSectionMap, SIGNAL(sectionClicked(qint32)), this, SLOT(onSectionClicked(qint32)));
    connect(m_pSectionMap, SIGNAL(entryPointClicked()), this, SLOT(onEntryPointClicked()));
    connect(m_pTreeIndicators, SIGNAL(itemClicked(QTreeWidgetItem *, int)), this, SLOT(onIndicatorClicked(QTreeWidgetItem *, int)));
    connect(m_pTreeIndicators, SIGNAL(itemDoubleClicked(QTreeWidgetItem *, int)), this, SLOT(onIndicatorDoubleClicked(QTreeWidgetItem *, int)));
    connect(m_pLabelEntryPoint, SIGNAL(linkActivated(QString)), this, SLOT(onLinkActivated(QString)));
    connect(m_pToolButtonHowTo, SIGNAL(toggled(bool)), this, SLOT(onHowToToggled(bool)));

    m_hints.load(HelperSettings::resolveHintsPath());
    _refresh();
}

void HelperPackingView::setGlobal(XShortcuts *pShortcuts, XOptions *pOptions)
{
    m_pShortcuts = pShortcuts;
    m_pOptions = pOptions;
    m_pActions->setGlobal(pShortcuts, pOptions);
}

void HelperPackingView::onTableReady(const HelperActions::TABLE &table)
{
    // one tab per result kind; a new run of the same action replaces its tab
    QTreeWidget *pTree = nullptr;

    for (qint32 i = 0; i < m_pTabWidgetResults->count(); i++) {
        if (m_pTabWidgetResults->tabText(i).startsWith(table.sTitle + QString(" ("))) {
            pTree = qobject_cast<QTreeWidget *>(m_pTabWidgetResults->widget(i));
            m_pTabWidgetResults->setTabText(i, QString("%1 (%2)").arg(table.sTitle).arg(table.listRows.count()));
            break;
        }
    }

    if (!pTree) {
        pTree = new QTreeWidget(m_pTabWidgetResults);
        pTree->setRootIsDecorated(false);
        pTree->setAlternatingRowColors(true);
        pTree->setUniformRowHeights(true);
        pTree->setSortingEnabled(false);
        m_pTabWidgetResults->insertTab(m_pTabWidgetResults->count() - 1, pTree, QString("%1 (%2)").arg(table.sTitle).arg(table.listRows.count()));

        // the last column holds the clickable location; same behaviour as the indicator list
        connect(pTree, &QTreeWidget::itemClicked, this, [this, pTree](QTreeWidgetItem *pItem, int nColumn) {
            if (nColumn == pTree->columnCount() - 1) {
                _openLocation(pItem->data(0, Qt::UserRole).value<HelperEvidence::INDICATOR>());
            }
        });
        connect(pTree, &QTreeWidget::itemDoubleClicked, this,
                [this](QTreeWidgetItem *pItem, int) { _openLocation(pItem->data(0, Qt::UserRole).value<HelperEvidence::INDICATOR>()); });
    }

    pTree->clear();
    pTree->setColumnCount(table.listHeaders.count() + 1);
    pTree->setHeaderLabels(table.listHeaders + QStringList(tr("Location")));

    for (qint32 i = 0; i < table.listRows.count(); i++) {
        QTreeWidgetItem *pItem = new QTreeWidgetItem(pTree, table.listRows.at(i));
        HelperEvidence::INDICATOR location = (i < table.listLocations.count()) ? table.listLocations.at(i) : HelperEvidence::INDICATOR();
        qint32 nLocationColumn = table.listHeaders.count();

        for (qint32 j = 0; j < table.listRows.at(i).count(); j++) {
            pItem->setToolTip(j, table.listRows.at(i).at(j));
        }

        if (location.location == HelperEvidence::LOCATION_HEX) {
            pItem->setText(nLocationColumn, tr("hex 0x%1").arg(location.nOffset, 0, 16));
        } else if (location.location == HelperEvidence::LOCATION_DISASM) {
            pItem->setText(nLocationColumn, tr("disasm 0x%1").arg(location.nAddress, 0, 16));
        }

        if (location.location != HelperEvidence::LOCATION_NONE) {
            QFont font = pItem->font(nLocationColumn);
            font.setUnderline(true);
            pItem->setFont(nLocationColumn, font);
            pItem->setForeground(nLocationColumn, palette().color(QPalette::Link));
        }

        pItem->setData(0, Qt::UserRole, QVariant::fromValue(location));
    }

    for (qint32 i = 0; i < pTree->columnCount(); i++) {
        pTree->resizeColumnToContents(i);
    }

    m_pTabWidgetResults->setCurrentWidget(pTree);
}

void HelperPackingView::setFileName(const QString &sFileName)
{
    // results of the previous file's actions no longer apply
    while (m_pTabWidgetResults->count() > 2) {
        QWidget *pWidget = m_pTabWidgetResults->widget(1);
        m_pTabWidgetResults->removeTab(1);
        delete pWidget;
    }

    m_pActions->setFileName(sFileName);

    m_sFileName = sFileName;
    m_evidence = {};
    m_bEvidenceReady = false;
    m_listRecords.clear();
    m_bResultsReady = false;
    m_bHasSelectedRecord = false;

    if (!sFileName.isEmpty()) {
        // parsing + entropy of big files takes a moment: keep the GUI responsive
        m_watcher.setFuture(QtConcurrent::run(&HelperEvidence::analyze, sFileName));
    }

    _refresh();
}

void HelperPackingView::reloadHints()
{
    m_hints.load(HelperSettings::resolveHintsPath());
    _updateHint();
}

void HelperPackingView::onResultsReady(const XScanEngine::SCAN_RESULT &scanResult)
{
    m_listRecords = scanResult.listRecords;
    m_bResultsReady = true;
    m_bHasSelectedRecord = false;
    _refresh();
}

void HelperPackingView::onResultSelected(const XScanEngine::SCANSTRUCT &scanStruct)
{
    if (scanStruct.sName.isEmpty()) {
        return;  // file type header row
    }

    m_selectedRecord = scanStruct;
    m_bHasSelectedRecord = true;
    _updateHint();
}

void HelperPackingView::onScanCleared()
{
    // a (re)scan started: DiE's detections are gone, the file evidence stays valid
    m_listRecords.clear();
    m_bResultsReady = false;
    m_bHasSelectedRecord = false;
    _refresh();
}

void HelperPackingView::onEvidenceFinished()
{
    HelperEvidence::RESULT result = m_watcher.result();

    if (result.sFileName != m_sFileName) {
        return;  // stale: the file changed while it was being analysed
    }

    m_evidence = result;
    m_bEvidenceReady = true;
    _refresh();
}

void HelperPackingView::_refresh()
{
    m_pTreeIndicators->clear();
    m_listShownIndicators.clear();

    if (m_sFileName.isEmpty()) {
        m_pLabelVerdict->setText(tr("Open a file to see how it is packed or obfuscated."));
        m_pSectionMap->clear();
        m_pLabelEntryPoint->clear();
        emit summaryChanged(tr("Packing"), palette().color(QPalette::WindowText));
        _updateHint();
        return;
    }

    if (!m_bEvidenceReady) {
        m_pLabelVerdict->setText(tr("Analysing %1 ...").arg(QFileInfo(m_sFileName).fileName().toHtmlEscaped()));
        m_pSectionMap->clear();
        m_pLabelEntryPoint->clear();
        emit summaryChanged(tr("Packing ..."), palette().color(QPalette::WindowText));
        _updateHint();
        return;
    }

    if (!m_evidence.bIsValid) {
        m_pLabelVerdict->setText(tr("Packing analysis is available for PE files (EXE/DLL) only.") +
                                 (m_evidence.sError.isEmpty() ? QString() : QString(" <small>(%1)</small>").arg(m_evidence.sError.toHtmlEscaped())));
        m_pSectionMap->clear();
        m_pLabelEntryPoint->clear();
        emit summaryChanged(tr("Packing: n/a"), palette().color(QPalette::WindowText));
        _updateHint();
        return;
    }

    // --- DiE detections + file evidence -> ranked indicators, scores and verdict (shared with the batch scan)
    HelperVerdict::RESULT verdict = HelperVerdict::compute(m_evidence, m_listRecords);
    const QList<HelperEvidence::INDICATOR> &listAll = verdict.listIndicators;
    qint32 nPackingScore = verdict.nPackingScore;
    qint32 nObfuscationScore = verdict.nObfuscationScore;
    QString sHeadline = verdict.sHeadlineHtml;
    QString sTabTitle = verdict.sTabTitle;
    QColor colorVerdict = verdict.color;
    m_verdict = verdict;
    m_pActions->setContext(m_evidence, m_listRecords);  // enables the buttons that apply to this file

    QStringList listFacts;
    listFacts.append(m_evidence.bIs64 ? "PE64" : "PE32");
    listFacts.append(m_evidence.bIsDll ? "DLL" : "EXE");

    if (m_evidence.bIsNET) {
        listFacts.append(".NET");
    }

    listFacts.append(tr("packing score %1/100").arg(nPackingScore));
    listFacts.append(tr("obfuscation/anti-analysis score %1/100").arg(nObfuscationScore));
    listFacts.append(tr("file entropy %1").arg(m_evidence.dFileEntropy, 0, 'f', 2));

    m_pLabelVerdict->setText(QString("<span style='font-size:large; font-weight:bold; color:%1'>%2</span><br><small>%3</small>")
                                 .arg(colorVerdict.name(), sHeadline, listFacts.join(QString(" &middot; "))));

    m_pSectionMap->setData(m_evidence);

    // --- entry point line
    {
        QString sSection = tr("no section");

        if ((m_evidence.nEntryPointSection >= 0)) {
            for (qint32 i = 0; i < m_evidence.listSections.count(); i++) {
                const HelperEvidence::SECTION &section = m_evidence.listSections.at(i);

                if (section.nIndex == m_evidence.nEntryPointSection) {
                    sSection = QString("%1 [%2%3%4]").arg(section.sName.toHtmlEscaped(), section.bRead ? "R" : "-", section.bWrite ? "W" : "-", section.bExecute ? "X" : "-");
                    break;
                }
            }
        }

        QStringList listBytes;

        for (qint32 i = 0; i < qMin(16, m_evidence.baEntryPointBytes.size()); i++) {
            listBytes.append(QString("%1").arg((quint8)m_evidence.baEntryPointBytes.at(i), 2, 16, QChar('0')).toUpper());
        }

        QString sOffset = (m_evidence.nEntryPointOffset >= 0) ? QString("0x%1").arg(m_evidence.nEntryPointOffset, 0, 16) : tr("not in file");

        m_pLabelEntryPoint->setText(tr("<b>Entry point</b> RVA 0x%1 (offset %2) in %3 &nbsp; <code>%4</code> &nbsp; <a href='ep:disasm'>disassemble</a> &middot; <a href='ep:hex'>hex</a>")
                                        .arg(m_evidence.nEntryPointRVA, 0, 16)
                                        .arg(sOffset, sSection, listBytes.join(' ')));
    }

    // --- indicator table
    for (qint32 i = 0; i < listAll.count(); i++) {
        const HelperEvidence::INDICATOR &indicator = listAll.at(i);

        QTreeWidgetItem *pItem = new QTreeWidgetItem(m_pTreeIndicators);
        pItem->setText(COLUMN_SEVERITY, HelperEvidence::severityToString(indicator.severity));
        pItem->setForeground(COLUMN_SEVERITY, _severityColor(indicator.severity));
        pItem->setText(COLUMN_CATEGORY, HelperEvidence::categoryToString(indicator.category));
        pItem->setText(COLUMN_INDICATOR, indicator.sTitle);
        pItem->setText(COLUMN_DETAILS, indicator.sDetails);
        pItem->setToolTip(COLUMN_DETAILS, indicator.sDetails);
        pItem->setToolTip(COLUMN_INDICATOR, tr("weight %1").arg(indicator.nWeight));

        if (indicator.severity == HelperEvidence::SEVERITY_HIGH) {
            QFont font = pItem->font(COLUMN_INDICATOR);
            font.setBold(true);
            pItem->setFont(COLUMN_INDICATOR, font);
        }

        if (indicator.location == HelperEvidence::LOCATION_HEX) {
            pItem->setText(COLUMN_LOCATION, tr("hex 0x%1").arg(indicator.nOffset, 0, 16));
        } else if (indicator.location == HelperEvidence::LOCATION_DISASM) {
            pItem->setText(COLUMN_LOCATION, tr("disasm 0x%1").arg(indicator.nAddress, 0, 16));
        }

        if (indicator.location != HelperEvidence::LOCATION_NONE) {
            QFont font = pItem->font(COLUMN_LOCATION);
            font.setUnderline(true);
            pItem->setFont(COLUMN_LOCATION, font);
            pItem->setForeground(COLUMN_LOCATION, palette().color(QPalette::Link));
            pItem->setToolTip(COLUMN_LOCATION, tr("Click to open"));
        }

        m_listShownIndicators.append(indicator);
    }

    emit summaryChanged(sTabTitle, colorVerdict);

    _updateHint();
}

qint32 HelperPackingView::_getBestDetectionIndex() const
{
    // named signature > heuristic, and a detection with a hint > one without
    qint32 nBestIndex = -1;
    qint32 nBestScore = -1;

    for (qint32 i = 0; i < m_listRecords.count(); i++) {
        const XScanEngine::SCANSTRUCT &record = m_listRecords.at(i);

        if (record.sName.isEmpty()) {
            continue;
        }

        if (!HelperHints::isPackingType(record.sType) && !HelperVerdict::isObfuscatorType(record.sType, record.sName)) {
            continue;
        }

        qint32 nScore = 0;

        if (!record.bIsHeuristic && !record.bIsAHeuristic) {
            nScore += 2;
        }

        if (m_hints.lookup(record.sName, nullptr)) {
            nScore += 1;
        }

        if (nScore > nBestScore) {
            nBestScore = nScore;
            nBestIndex = i;
        }
    }

    return nBestIndex;
}

void HelperPackingView::_updateHint()
{
    const XScanEngine::SCANSTRUCT *pRecord = nullptr;

    if (m_bHasSelectedRecord) {
        pRecord = &m_selectedRecord;
    } else {
        qint32 nIndex = _getBestDetectionIndex();

        if (nIndex != -1) {
            pRecord = &m_listRecords.at(nIndex);
        }
    }

    HelperHints::HINT hint = {};
    bool bFound = false;
    bool bIsFallback = false;

    if (pRecord) {
        bFound = m_hints.lookup(pRecord->sName, &hint);

        if (!bFound && (HelperHints::isPackingType(pRecord->sType) || HelperVerdict::isObfuscatorType(pRecord->sType, pRecord->sName))) {
            bFound = m_hints.getGeneric(&hint);
            bIsFallback = bFound;
        }
    } else if (m_bEvidenceReady && (m_evidence.nPackingScore >= 25)) {
        // packed by something DiE does not know: the generic approach
        bFound = m_hints.getGeneric(&hint);
        bIsFallback = bFound;
    }

    if (!m_hints.isLoaded()) {
        m_pToolButtonHowTo->setText(tr("How to unpack: hints file not loaded (Options -> Helper)"));
        m_pToolButtonHowTo->setEnabled(true);
        m_pTextBrowserHint->setHtml(QString("<p style='color:#d9534f'>%1</p>").arg(m_hints.getLastError().toHtmlEscaped()));
        return;
    }

    if (!bFound) {
        QString sText = pRecord ? tr("How to unpack: no hint for \"%1\"").arg(pRecord->sName) : tr("How to unpack: nothing to unpack");
        m_pToolButtonHowTo->setText(sText);
        m_pTextBrowserHint->setHtml(pRecord ? QString("<p>%1</p>").arg(tr("Add an entry named \"%1\" to hints.json (Options &rarr; Helper shows which file is used).").arg(pRecord->sName.toHtmlEscaped()))
                                            : QString());
        m_pToolButtonHowTo->setEnabled(pRecord != nullptr);
        return;
    }

    m_pToolButtonHowTo->setEnabled(true);
    m_pToolButtonHowTo->setText(bIsFallback ? tr("How to unpack: generic approach (%1)").arg(pRecord ? pRecord->sName : tr("unknown packer")) : tr("How to unpack: %1").arg(hint.sName));
    m_pTextBrowserHint->setHtml(_getHintHtml(pRecord, hint, bIsFallback));
}

void HelperPackingView::onHowToToggled(bool bChecked)
{
    m_pToolButtonHowTo->setArrowType(bChecked ? Qt::DownArrow : Qt::RightArrow);
    m_pTextBrowserHint->setVisible(bChecked);
}

QString HelperPackingView::_getHintHtml(const XScanEngine::SCANSTRUCT *pRecord, const HelperHints::HINT &hint, bool bIsFallback) const
{
    QString sHtml;

    if (pRecord) {
        sHtml += QString("<p style='margin-bottom:2px'><b>%1</b></p>").arg(HelperVerdict::getRecordTitle(*pRecord).toHtmlEscaped());
    }

    if (bIsFallback) {
        sHtml += QString("<p style='color:#e0a000'>%1</p>").arg(tr("No specific hint; showing the generic unpacking approach."));
    }

    QString sHeader = hint.sName.toHtmlEscaped();

    if (!hint.sCategory.isEmpty()) {
        sHeader += QString(" <span style='color:gray'>(%1)</span>").arg(hint.sCategory.toHtmlEscaped());
    }

    sHtml += QString("<h4 style='margin-bottom:2px'>%1</h4>").arg(sHeader);

    struct SECTION {
        QString sTitle;
        QString sBody;
        bool bIsList;
    };

    QList<SECTION> listSections;
    listSections.append({tr("What it does"), _textToHtml(hint.sWhatItDoes), false});
    listSections.append({tr("OEP pattern"), _textToHtml(hint.sOepPattern), false});
    listSections.append({tr("Try first"), _listToHtml(hint.listTryFirst, true), true});
    listSections.append({tr("Tools"), _listToHtml(hint.listTools, false), true});
    listSections.append({tr("Pitfalls"), _listToHtml(hint.listPitfalls, false), true});

    if (m_bEvidenceReady && m_evidence.bIsDll && !hint.sDllNotes.isEmpty()) {
        listSections.append({tr("This is a DLL"), _textToHtml(hint.sDllNotes), false});
    }

    listSections.append({tr("Notes"), _textToHtml(hint.sNotes), false});

    for (qint32 i = 0; i < listSections.count(); i++) {
        if (listSections.at(i).sBody.isEmpty()) {
            continue;
        }

        sHtml += QString("<p style='margin-bottom:0'><b>%1</b></p>").arg(listSections.at(i).sTitle);
        sHtml += listSections.at(i).bIsList ? listSections.at(i).sBody : QString("<p style='margin-top:0'>%1</p>").arg(listSections.at(i).sBody);
    }

    return sHtml;
}

void HelperPackingView::onSectionClicked(qint32 nSectionIndex)
{
    if ((nSectionIndex < 0) || (nSectionIndex >= m_evidence.listSections.count())) {
        return;
    }

    const HelperEvidence::SECTION &section = m_evidence.listSections.at(nSectionIndex);

    if (section.nRawSize > 0) {
        _openHex(section.nRawOffset, section.nRawSize);
    } else if (section.nRVA >= 0) {
        // virtual-only: nothing in the file, show where it will live in memory instead
        _openDisasm(m_evidence.nImageBase + section.nRVA);
    }
}

void HelperPackingView::onEntryPointClicked()
{
    if (m_bEvidenceReady && m_evidence.bIsValid) {
        _openDisasm(m_evidence.nEntryPointAddress);
    }
}

void HelperPackingView::onLinkActivated(const QString &sLink)
{
    if (sLink == QString("ep:disasm")) {
        onEntryPointClicked();
    } else if ((sLink == QString("ep:hex")) && (m_evidence.nEntryPointOffset >= 0)) {
        _openHex(m_evidence.nEntryPointOffset, qMax(1, m_evidence.baEntryPointBytes.size()));
    }
}

void HelperPackingView::onIndicatorClicked(QTreeWidgetItem *pItem, int nColumn)
{
    // a single click opens only on the "Location" cell, so selecting rows stays harmless
    if (nColumn == COLUMN_LOCATION) {
        qint32 nIndex = m_pTreeIndicators->indexOfTopLevelItem(pItem);

        if ((nIndex >= 0) && (nIndex < m_listShownIndicators.count())) {
            _openLocation(m_listShownIndicators.at(nIndex));
        }
    }
}

void HelperPackingView::onIndicatorDoubleClicked(QTreeWidgetItem *pItem, int nColumn)
{
    if (nColumn != COLUMN_LOCATION) {
        onIndicatorClicked(pItem, COLUMN_LOCATION);
    }
}

void HelperPackingView::_openLocation(const HelperEvidence::INDICATOR &indicator)
{
    if (indicator.location == HelperEvidence::LOCATION_HEX) {
        _openHex(indicator.nOffset, indicator.nSize);
    } else if (indicator.location == HelperEvidence::LOCATION_DISASM) {
        _openDisasm(indicator.nAddress);
    }
}

void HelperPackingView::_openHex(qint64 nOffset, qint64 nSize)
{
    QFile file(m_sFileName);

    if (!file.open(QIODevice::ReadOnly)) {
        return;
    }

    XHexViewWidget::OPTIONS options = {};
    options.nStartSelectionOffset = nOffset;
    options.nSizeOfSelection = qMax<qint64>(nSize, 1);
    options.sTitle = QFileInfo(m_sFileName).fileName();

    DialogHexView dialog(this);

    if (m_pShortcuts && m_pOptions) {
        dialog.setGlobal(m_pShortcuts, m_pOptions);
    }

    dialog.setData(&file, options);
    dialog.exec();

    file.close();
}

void HelperPackingView::_openDisasm(XADDR nAddress)
{
    QFile file(m_sFileName);

    if (!file.open(QIODevice::ReadOnly)) {
        return;
    }

    XMultiDisasmWidget::OPTIONS options = {};
    options.fileType = m_evidence.bIs64 ? XBinary::FT_PE64 : XBinary::FT_PE32;
    options.nInitAddress = nAddress;
    options.sTitle = QFileInfo(m_sFileName).fileName();
    options.bMenu_Hex = true;

    DialogMultiDisasm dialog(this);

    if (m_pShortcuts && m_pOptions) {
        dialog.setGlobal(m_pShortcuts, m_pOptions);
    }

    dialog.setData(&file, options);
    dialog.exec();

    file.close();
}


QString HelperPackingView::_listToHtml(const QStringList &listItems, bool bOrdered)
{
    if (listItems.isEmpty()) {
        return QString();
    }

    QString sTag = bOrdered ? "ol" : "ul";
    QString sResult = QString("<%1 style='margin-top:0'>").arg(sTag);

    for (qint32 i = 0; i < listItems.count(); i++) {
        sResult += QString("<li>%1</li>").arg(_textToHtml(listItems.at(i)));
    }

    sResult += QString("</%1>").arg(sTag);

    return sResult;
}

QString HelperPackingView::_textToHtml(const QString &sText)
{
    // escape, then render `code` spans the way hints.json writes commands
    static const QRegularExpression regExpCode("`([^`]+)`");

    QString sResult = sText.toHtmlEscaped();
    sResult.replace(regExpCode, QString("<code>\\1</code>"));

    return sResult.replace(QChar('\n'), QString("<br>"));
}

QColor HelperPackingView::_severityColor(HelperEvidence::SEVERITY severity)
{
    switch (severity) {
        case HelperEvidence::SEVERITY_HIGH: return QColor(220, 60, 60);
        case HelperEvidence::SEVERITY_MEDIUM: return QColor(230, 150, 30);
        case HelperEvidence::SEVERITY_LOW: return QColor(200, 190, 60);
        default: return QColor(130, 130, 130);
    }
}
