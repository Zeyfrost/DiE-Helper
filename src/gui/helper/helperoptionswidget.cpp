// DiE Helper (fork addition): "Helper" page of the Options dialog (hints file, output folder, external tools).
#include "helperoptionswidget.h"

#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

#include "helperhints.h"
#include "helpersettings.h"
#include "xoptions.h"

HelperOptionsWidget::HelperOptionsWidget(QWidget *pParent) : QWidget(pParent)
{
    QVBoxLayout *pMainLayout = new QVBoxLayout(this);

    // --- hints file
    QGroupBox *pGroupHints = new QGroupBox(tr("Hints file (JSON)"), this);
    QVBoxLayout *pHintsLayout = new QVBoxLayout(pGroupHints);
    QHBoxLayout *pPathLayout = new QHBoxLayout;
    m_pLineEditHintsPath = new QLineEdit(pGroupHints);
    m_pLineEditHintsPath->setToolTip(tr("\"$data\" is the folder of die.exe"));
    QPushButton *pButtonBrowse = new QPushButton(tr("Browse..."), pGroupHints);
    QPushButton *pButtonReset = new QPushButton(tr("Default"), pGroupHints);
    pPathLayout->addWidget(m_pLineEditHintsPath, 1);
    pPathLayout->addWidget(pButtonBrowse);
    pPathLayout->addWidget(pButtonReset);
    m_pLabelStatus = new QLabel(pGroupHints);
    m_pLabelStatus->setWordWrap(true);
    m_pLabelStatus->setTextInteractionFlags(Qt::TextSelectableByMouse);
    pHintsLayout->addLayout(pPathLayout);
    pHintsLayout->addWidget(m_pLabelStatus);

    // --- output
    QGroupBox *pGroupOutput = new QGroupBox(tr("Results of actions (unpacked / patched copies, reports)"), this);
    QGridLayout *pOutputLayout = new QGridLayout(pGroupOutput);
    m_pLineEditOutputFolder = _addPathRow(pGroupOutput, pOutputLayout, 0, tr("Auto folder"), true, QString());
    m_pLineEditOutputFolder->setPlaceholderText(tr("empty = ask with Save as... every time"));
    QLabel *pLabelOutputNote = new QLabel(tr("The original file is never modified. Samples are never executed."), pGroupOutput);
    pLabelOutputNote->setWordWrap(true);
    pOutputLayout->addWidget(pLabelOutputNote, 1, 0, 1, 3);

    // --- external tools
    QGroupBox *pGroupTools = new QGroupBox(tr("External tools (optional, run on a copy)"), this);
    QGridLayout *pToolsLayout = new QGridLayout(pGroupTools);
    const QString sExeFilter = tr("Programs") + QString(" (*.exe);;") + tr("All files") + QString(" (*)");
    m_pLineEditUpx = _addPathRow(pGroupTools, pToolsLayout, 0, QString("upx.exe"), false, sExeFilter);
    m_pLineEditDe4dot = _addPathRow(pGroupTools, pToolsLayout, 1, QString("de4dot.exe"), false, sExeFilter);
    m_pLineEditCustomTool = _addPathRow(pGroupTools, pToolsLayout, 2, tr("Custom tool"), false, sExeFilter);
    m_pLineEditCustomName = new QLineEdit(pGroupTools);
    m_pLineEditCustomName->setPlaceholderText(tr("button name"));
    m_pLineEditCustomArguments = new QLineEdit(pGroupTools);
    m_pLineEditCustomArguments->setToolTip(tr("%in% = input copy, %out% = output file"));
    pToolsLayout->addWidget(new QLabel(tr("Custom name"), pGroupTools), 3, 0);
    pToolsLayout->addWidget(m_pLineEditCustomName, 3, 1, 1, 2);
    pToolsLayout->addWidget(new QLabel(tr("Custom arguments"), pGroupTools), 4, 0);
    pToolsLayout->addWidget(m_pLineEditCustomArguments, 4, 1, 1, 2);
    m_pLineEditUpx->setPlaceholderText(tr("empty = button hidden"));
    m_pLineEditDe4dot->setPlaceholderText(tr("empty = button hidden"));
    m_pLineEditCustomTool->setPlaceholderText(tr("empty = button hidden"));

    pMainLayout->addWidget(pGroupHints);
    pMainLayout->addWidget(pGroupOutput);
    pMainLayout->addWidget(pGroupTools);
    pMainLayout->addStretch();

    connect(pButtonBrowse, SIGNAL(clicked()), this, SLOT(browseSlot()));
    connect(pButtonReset, SIGNAL(clicked()), this, SLOT(resetSlot()));
    connect(m_pLineEditHintsPath, SIGNAL(textChanged(QString)), this, SLOT(updateStatus()));

    reload();
}

QLineEdit *HelperOptionsWidget::_addPathRow(QWidget *pParent, QGridLayout *pLayout, qint32 nRow, const QString &sLabel, bool bFolder, const QString &sFilter)
{
    QLineEdit *pLineEdit = new QLineEdit(pParent);
    QPushButton *pButton = new QPushButton(tr("Browse..."), pParent);

    pLayout->addWidget(new QLabel(sLabel, pParent), nRow, 0);
    pLayout->addWidget(pLineEdit, nRow, 1);
    pLayout->addWidget(pButton, nRow, 2);
    pLayout->setColumnStretch(1, 1);

    connect(pButton, &QPushButton::clicked, this, [this, pLineEdit, bFolder, sFilter, sLabel]() {
        QString sResult;

        if (bFolder) {
            sResult = QFileDialog::getExistingDirectory(this, sLabel, pLineEdit->text());
        } else {
            sResult = QFileDialog::getOpenFileName(this, sLabel, QFileInfo(pLineEdit->text()).absolutePath(), sFilter);
        }

        if (!sResult.isEmpty()) {
            pLineEdit->setText(QDir::toNativeSeparators(sResult));
        }
    });

    return pLineEdit;
}

void HelperOptionsWidget::save()
{
    HelperSettings::setHintsPath(m_pLineEditHintsPath->text());
    HelperSettings::setOutputFolder(m_pLineEditOutputFolder->text());
    HelperSettings::setToolPath(HelperSettings::TOOL_UPX, m_pLineEditUpx->text());
    HelperSettings::setToolPath(HelperSettings::TOOL_DE4DOT, m_pLineEditDe4dot->text());
    HelperSettings::setToolPath(HelperSettings::TOOL_CUSTOM, m_pLineEditCustomTool->text());
    HelperSettings::setCustomToolName(m_pLineEditCustomName->text());
    HelperSettings::setCustomToolArguments(m_pLineEditCustomArguments->text());
}

void HelperOptionsWidget::reload()
{
    QString sPath = HelperSettings::getHintsPath();

    if (sPath.isEmpty()) {
        sPath = HelperSettings::getDefaultHintsPath();
    }

    m_pLineEditHintsPath->setText(sPath);
    m_pLineEditOutputFolder->setText(HelperSettings::getOutputFolder());
    m_pLineEditUpx->setText(HelperSettings::getToolPath(HelperSettings::TOOL_UPX));
    m_pLineEditDe4dot->setText(HelperSettings::getToolPath(HelperSettings::TOOL_DE4DOT));
    m_pLineEditCustomTool->setText(HelperSettings::getToolPath(HelperSettings::TOOL_CUSTOM));
    m_pLineEditCustomName->setText(HelperSettings::getCustomToolName());
    m_pLineEditCustomArguments->setText(HelperSettings::getCustomToolArguments());
    updateStatus();
}

void HelperOptionsWidget::browseSlot()
{
    QString sCurrent = XOptions::convertPathName(m_pLineEditHintsPath->text());
    QString sFileName = QFileDialog::getOpenFileName(this, tr("Hints file"), QFileInfo(sCurrent).absolutePath(), tr("JSON files") + QString(" (*.json);;") + tr("All files") + QString(" (*)"));

    if (!sFileName.isEmpty()) {
        m_pLineEditHintsPath->setText(QDir::toNativeSeparators(sFileName));
    }
}

void HelperOptionsWidget::resetSlot()
{
    m_pLineEditHintsPath->setText(HelperSettings::getDefaultHintsPath());
}

void HelperOptionsWidget::updateStatus()
{
    QString sPath = m_pLineEditHintsPath->text().trimmed();

    if (sPath.isEmpty()) {
        sPath = HelperSettings::getDefaultHintsPath();
    }

    QString sResolved = XOptions::convertPathName(sPath);

    HelperHints hints;

    if (hints.load(sResolved)) {
        m_pLabelStatus->setText(tr("%1 hints loaded from %2").arg(hints.count()).arg(QDir::toNativeSeparators(sResolved)));
        m_pLabelStatus->setStyleSheet(QString());
    } else {
        m_pLabelStatus->setText(hints.getLastError());
        m_pLabelStatus->setStyleSheet(QString("color: #d9534f"));
    }
}
