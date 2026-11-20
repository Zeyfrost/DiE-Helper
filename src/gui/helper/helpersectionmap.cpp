// DiE Helper (fork addition): painted map of the PE layout - one block per section, colored by entropy,
// with W/X flags, virtual-only sections hatched, the overlay, and an entry point marker.
#include "helpersectionmap.h"

#include <QHelpEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QToolTip>
#include <QtMath>

static const qint32 N_BAR_HEIGHT = 52;
static const qint32 N_MARKER_HEIGHT = 16;
static const qint32 N_MIN_BLOCK = 46;
static const qint32 N_GAP = 2;

HelperSectionMap::HelperSectionMap(QWidget *pParent) : QWidget(pParent)
{
    m_result = {};
    m_bHasData = false;
    m_nHover = -1;

    setMouseTracking(true);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
}

QSize HelperSectionMap::sizeHint() const
{
    return QSize(600, N_BAR_HEIGHT + N_MARKER_HEIGHT + 4);
}

QSize HelperSectionMap::minimumSizeHint() const
{
    return QSize(200, N_BAR_HEIGHT + N_MARKER_HEIGHT + 4);
}

void HelperSectionMap::setData(const HelperEvidence::RESULT &result)
{
    m_result = result;
    m_bHasData = result.bIsValid;
    m_nHover = -1;
    _layout();
    update();
}

void HelperSectionMap::clear()
{
    m_result = {};
    m_bHasData = false;
    m_listRects.clear();
    m_rectEntryPoint = QRect();
    m_nHover = -1;
    update();
}

QColor HelperSectionMap::entropyToColor(double dEntropy)
{
    if (dEntropy < 0) {
        return QColor(90, 90, 90);  // no raw data
    } else if (dEntropy < 5.0) {
        return QColor(52, 101, 164);  // plain data / headers
    } else if (dEntropy < 6.5) {
        return QColor(46, 139, 87);  // normal code
    } else if (dEntropy < 7.2) {
        return QColor(214, 137, 16);  // suspicious: encrypted / obfuscated / compressed resources
    }

    return QColor(200, 40, 40);  // compressed or encrypted
}

void HelperSectionMap::_layout()
{
    m_listRects.clear();
    m_rectEntryPoint = QRect();

    qint32 nCount = m_result.listSections.count();

    if (!m_bHasData || (nCount == 0)) {
        return;
    }

    // Width per block: a minimum so every section stays readable, the rest shared by sqrt(size)
    // (raw size for file-backed sections, virtual size for virtual-only ones) so one huge section
    // does not squash the others.
    qint32 nTotalWidth = width() - 1;
    qint32 nFree = nTotalWidth - nCount * (N_MIN_BLOCK + N_GAP);
    QList<double> listWeights;
    double dWeightSum = 0;

    for (qint32 i = 0; i < nCount; i++) {
        const HelperEvidence::SECTION &section = m_result.listSections.at(i);
        qint64 nSize = (section.nRawSize > 0) ? section.nRawSize : qMax<qint64>(section.nVirtualSize, 0);
        double dWeight = qSqrt((double)qMax<qint64>(nSize, 1));
        listWeights.append(dWeight);
        dWeightSum += dWeight;
    }

    qint32 nX = 0;

    for (qint32 i = 0; i < nCount; i++) {
        qint32 nWidth = N_MIN_BLOCK;

        if (nFree > 0) {
            nWidth += (qint32)(nFree * listWeights.at(i) / dWeightSum);
        } else {
            nWidth = qMax(8, nTotalWidth / nCount - N_GAP);
        }

        if (i == nCount - 1) {
            nWidth = qMax(8, nTotalWidth - nX);  // absorb rounding
        }

        m_listRects.append(QRect(nX, 0, nWidth, N_BAR_HEIGHT));
        nX += nWidth + N_GAP;
    }

    // Entry point marker: inside the block of the section that contains it, at its relative position
    for (qint32 i = 0; i < nCount; i++) {
        const HelperEvidence::SECTION &section = m_result.listSections.at(i);

        if (section.bContainsEntryPoint) {
            const QRect &rect = m_listRects.at(i);
            qint64 nSpan = qMax<qint64>(qMax(section.nVirtualSize, section.nRawSize), 1);
            double dRel = (double)(m_result.nEntryPointRVA - section.nRVA) / (double)nSpan;
            dRel = qBound(0.0, dRel, 1.0);
            qint32 nMarkerX = rect.left() + 4 + (qint32)((rect.width() - 8) * dRel);
            m_rectEntryPoint = QRect(nMarkerX - 14, N_BAR_HEIGHT + 1, 28, N_MARKER_HEIGHT);
            break;
        }
    }
}

void HelperSectionMap::resizeEvent(QResizeEvent *pEvent)
{
    QWidget::resizeEvent(pEvent);
    _layout();
}

void HelperSectionMap::paintEvent(QPaintEvent *pEvent)
{
    Q_UNUSED(pEvent)

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);

    if (!m_bHasData || m_listRects.isEmpty()) {
        painter.setPen(palette().color(QPalette::PlaceholderText));
        painter.drawText(rect(), Qt::AlignCenter, m_result.sError.isEmpty() ? tr("No PE layout to show") : m_result.sError);
        return;
    }

    QFont fontName = font();
    fontName.setBold(true);
    QFont fontSmall = font();
    fontSmall.setPointSizeF(qMax(6.5, font().pointSizeF() - 1.0));

    for (qint32 i = 0; i < m_listRects.count(); i++) {
        const HelperEvidence::SECTION &section = m_result.listSections.at(i);
        QRect rect = m_listRects.at(i);
        bool bVirtualOnly = (section.nIndex >= 0) && (section.nRawSize == 0);

        QColor color = entropyToColor(section.dEntropy);

        if (section.nIndex < 0 && section.sName == QString("Headers")) {
            color = QColor(110, 110, 120);
        }

        QPainterPath path;
        path.addRoundedRect(QRectF(rect).adjusted(0.5, 0.5, -0.5, -0.5), 4, 4);
        painter.fillPath(path, bVirtualOnly ? QColor(60, 60, 66) : color);

        if (bVirtualOnly) {
            // memory reserved at load time, nothing in the file: typical unpacking target (UPX0)
            painter.fillPath(path, QBrush(QColor(160, 160, 170), Qt::BDiagPattern));
        }

        QPen pen((i == m_nHover) ? palette().color(QPalette::Highlight) : QColor(20, 20, 20), (i == m_nHover) ? 2 : 1);

        if (section.bContainsEntryPoint) {
            pen = QPen(QColor(255, 220, 0), 2);
        }

        painter.setPen(pen);
        painter.drawPath(path);

        // text: name / entropy or "virtual" / flags
        QRect rectText = rect.adjusted(4, 3, -4, -3);
        painter.setPen(Qt::white);
        painter.setFont(fontName);
        QFontMetrics fmName(fontName);
        painter.drawText(rectText, Qt::AlignLeft | Qt::AlignTop, fmName.elidedText(section.sName, Qt::ElideRight, rectText.width()));

        painter.setFont(fontSmall);
        QFontMetrics fmSmall(fontSmall);
        QString sLine2;

        if (bVirtualOnly) {
            sLine2 = tr("virtual only");
        } else if (section.dEntropy >= 0) {
            sLine2 = QString("H %1").arg(section.dEntropy, 0, 'f', 2);
        }

        QRect rectLine2 = rectText.adjusted(0, fmName.height(), 0, 0);
        painter.drawText(rectLine2, Qt::AlignLeft | Qt::AlignTop, fmSmall.elidedText(sLine2, Qt::ElideRight, rectText.width()));

        if (section.nIndex >= 0) {
            // flags, with W and X highlighted: W+X together is the classic "unpacks itself in place"
            QString sFlags = QString("%1%2%3").arg(section.bRead ? "R" : "-", section.bWrite ? "W" : "-", section.bExecute ? "X" : "-");
            QRect rectLine3 = rectLine2.adjusted(0, fmSmall.height(), 0, 0);
            bool bRWX = section.bWrite && section.bExecute;
            painter.setPen(bRWX ? QColor(255, 230, 120) : QColor(235, 235, 235));
            painter.drawText(rectLine3, Qt::AlignLeft | Qt::AlignTop, sFlags + (bRWX ? QString(" !") : QString()));
        }
    }

    // entry point marker: triangle + "EP"
    if (!m_rectEntryPoint.isNull()) {
        QRect rectMarker = m_rectEntryPoint;
        QPainterPath triangle;
        qint32 nCenter = rectMarker.center().x();
        triangle.moveTo(nCenter, rectMarker.top());
        triangle.lineTo(nCenter - 6, rectMarker.top() + 8);
        triangle.lineTo(nCenter + 6, rectMarker.top() + 8);
        triangle.closeSubpath();
        painter.fillPath(triangle, QColor(255, 220, 0));

        painter.setPen(QColor(255, 220, 0));
        painter.setFont(fontName);
        painter.drawText(QRect(nCenter - 30, rectMarker.top() + 6, 60, N_MARKER_HEIGHT - 4), Qt::AlignHCenter | Qt::AlignTop, QString("EP"));
    }
}

qint32 HelperSectionMap::_sectionAt(const QPoint &pos) const
{
    for (qint32 i = 0; i < m_listRects.count(); i++) {
        if (m_listRects.at(i).contains(pos)) {
            return i;
        }
    }

    return -1;
}

bool HelperSectionMap::_isOnEntryPoint(const QPoint &pos) const
{
    return !m_rectEntryPoint.isNull() && m_rectEntryPoint.adjusted(-6, 0, 6, 0).contains(pos);
}

void HelperSectionMap::mouseMoveEvent(QMouseEvent *pEvent)
{
    qint32 nHover = _sectionAt(pEvent->pos());
    bool bClickable = (nHover != -1) || _isOnEntryPoint(pEvent->pos());

    setCursor(bClickable ? Qt::PointingHandCursor : Qt::ArrowCursor);

    if (nHover != m_nHover) {
        m_nHover = nHover;
        update();
    }

    QWidget::mouseMoveEvent(pEvent);
}

void HelperSectionMap::mousePressEvent(QMouseEvent *pEvent)
{
    if (pEvent->button() == Qt::LeftButton) {
        if (_isOnEntryPoint(pEvent->pos())) {
            emit entryPointClicked();
            return;
        }

        qint32 nIndex = _sectionAt(pEvent->pos());

        if (nIndex != -1) {
            emit sectionClicked(nIndex);
            return;
        }
    }

    QWidget::mousePressEvent(pEvent);
}

bool HelperSectionMap::event(QEvent *pEvent)
{
    if (pEvent->type() == QEvent::ToolTip) {
        QHelpEvent *pHelpEvent = static_cast<QHelpEvent *>(pEvent);

        if (_isOnEntryPoint(pHelpEvent->pos())) {
            QToolTip::showText(pHelpEvent->globalPos(),
                               tr("Entry point: RVA 0x%1, VA 0x%2\nClick to disassemble").arg(m_result.nEntryPointRVA, 0, 16).arg(m_result.nEntryPointAddress, 0, 16),
                               this);
            return true;
        }

        qint32 nIndex = _sectionAt(pHelpEvent->pos());

        if (nIndex != -1) {
            QToolTip::showText(pHelpEvent->globalPos(), _getToolTip(nIndex), this);
        } else {
            QToolTip::hideText();
            pEvent->ignore();
        }

        return true;
    }

    if (pEvent->type() == QEvent::Leave) {
        m_nHover = -1;
        update();
    }

    return QWidget::event(pEvent);
}

QString HelperSectionMap::_getToolTip(qint32 nSectionIndex) const
{
    const HelperEvidence::SECTION &section = m_result.listSections.at(nSectionIndex);

    QStringList listLines;
    listLines.append(QString("<b>%1</b>").arg(section.sName.toHtmlEscaped()));

    if (section.nRawSize > 0) {
        listLines.append(tr("File: 0x%1 .. 0x%2 (%3 bytes)").arg(section.nRawOffset, 0, 16).arg(section.nRawOffset + section.nRawSize, 0, 16).arg(section.nRawSize));
    } else {
        listLines.append(tr("File: no raw data"));
    }

    if (section.nIndex >= 0) {
        listLines.append(tr("Memory: RVA 0x%1, virtual size 0x%2").arg(section.nRVA, 0, 16).arg(section.nVirtualSize, 0, 16));
        listLines.append(tr("Flags: %1%2%3 (0x%4)")
                             .arg(section.bRead ? "R" : "-", section.bWrite ? "W" : "-", section.bExecute ? "X" : "-")
                             .arg(section.nCharacteristics, 8, 16, QChar('0')));

        if ((section.nRawSize > 0) && (section.nVirtualSize > section.nRawSize * 4)) {
            listLines.append(tr("Virtual size is %1x the raw size").arg(section.nVirtualSize / qMax<qint64>(section.nRawSize, 1)));
        }
    }

    if (section.dEntropy >= 0) {
        QString sMeaning;

        if (section.dEntropy >= 7.2) {
            sMeaning = tr("compressed or encrypted");
        } else if (section.dEntropy >= 6.5) {
            sMeaning = tr("suspicious (packed, encrypted or obfuscated?)");
        } else if (section.dEntropy >= 5.0) {
            sMeaning = tr("typical code");
        } else {
            sMeaning = tr("plain data");
        }

        listLines.append(tr("Entropy: %1 - %2").arg(section.dEntropy, 0, 'f', 3).arg(sMeaning));
    }

    if (section.bContainsEntryPoint) {
        listLines.append(tr("<b>Contains the entry point</b>"));
    }

    if (section.bIsUnusualName) {
        listLines.append(tr("Unusual section name"));
    }

    listLines.append(tr("<i>Click to open in hex view</i>"));

    return listLines.join(QString("<br>"));
}
