// DiE Helper (fork addition): painted map of the PE layout - one block per section, colored by entropy,
// with W/X flags, virtual-only sections hatched, the overlay, and an entry point marker.
#ifndef HELPERSECTIONMAP_H
#define HELPERSECTIONMAP_H

#include <QWidget>

#include "helperevidence.h"

class HelperSectionMap : public QWidget {
    Q_OBJECT

public:
    explicit HelperSectionMap(QWidget *pParent = nullptr);

    void setData(const HelperEvidence::RESULT &result);
    void clear();

    QSize sizeHint() const override;
    QSize minimumSizeHint() const override;

    static QColor entropyToColor(double dEntropy);

signals:
    void sectionClicked(qint32 nSectionIndex);  // index into RESULT::listSections
    void entryPointClicked();

protected:
    void paintEvent(QPaintEvent *pEvent) override;
    void mouseMoveEvent(QMouseEvent *pEvent) override;
    void mousePressEvent(QMouseEvent *pEvent) override;
    void resizeEvent(QResizeEvent *pEvent) override;
    bool event(QEvent *pEvent) override;

private:
    void _layout();
    qint32 _sectionAt(const QPoint &pos) const;
    bool _isOnEntryPoint(const QPoint &pos) const;
    QString _getToolTip(qint32 nSectionIndex) const;

    HelperEvidence::RESULT m_result;
    bool m_bHasData;
    QList<QRect> m_listRects;  // one per listSections entry
    QRect m_rectEntryPoint;
    qint32 m_nHover;
};

#endif  // HELPERSECTIONMAP_H
