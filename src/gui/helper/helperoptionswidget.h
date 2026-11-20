// DiE Helper (fork addition): "Helper" page of the Options dialog (hints file, output folder, external tools).
#ifndef HELPEROPTIONSWIDGET_H
#define HELPEROPTIONSWIDGET_H

#include <QWidget>

class QLabel;
class QLineEdit;

class HelperOptionsWidget : public QWidget {
    Q_OBJECT

public:
    explicit HelperOptionsWidget(QWidget *pParent = nullptr);

public slots:
    // called by XOptionsWidget (addPage connects saveSignal/reloadSignal to these)
    void save();
    void reload();

private slots:
    void browseSlot();
    void resetSlot();
    void updateStatus();

private:
    QLineEdit *_addPathRow(QWidget *pParent, class QGridLayout *pLayout, qint32 nRow, const QString &sLabel, bool bFolder, const QString &sFilter);

    QLineEdit *m_pLineEditHintsPath;
    QLabel *m_pLabelStatus;
    QLineEdit *m_pLineEditOutputFolder;
    QLineEdit *m_pLineEditUpx;
    QLineEdit *m_pLineEditDe4dot;
    QLineEdit *m_pLineEditCustomTool;
    QLineEdit *m_pLineEditCustomName;
    QLineEdit *m_pLineEditCustomArguments;
};

#endif  // HELPEROPTIONSWIDGET_H
