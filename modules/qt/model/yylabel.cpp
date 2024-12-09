//
// Created by fuwei on 12/9/24.
//

#include "yylabel.h"
#include <QPainter>
#include <QStyleOption>
#include <QResizeEvent>

YYLabel::YYLabel(QWidget* parent)
    : QLabel(parent) {
}

void YYLabel::setMaximumWidth(int maxWidth) {
    m_maxWidth = maxWidth;
    updateGeometry();
}
int YYLabel::maximumWidth() const {
    return m_maxWidth;
}
void YYLabel::resizeEvent(QResizeEvent* event) {
    QLabel::resizeEvent(event);

    updateTextLayout();
}
void YYLabel::paintEvent(QPaintEvent* event) {
    QLabel::paintEvent(event);
}
QSize YYLabel::sizeHint() const {
    return textSize();
}
QSize YYLabel::minimumSizeHint() const {
    return textSize();
}
QSize YYLabel::textSize() const {
    QFontMetrics fm = this->fontMetrics();
    int height = fm.boundingRect(0, 0, m_maxWidth, INT_MAX, Qt::TextWordWrap, text()).height();
    return QSize(m_maxWidth, height);
}
void YYLabel::updateTextLayout() {
    // 重新计算文本尺寸并更新高度
    int newHeight = textSize().height();
    if (newHeight != height()) {
        resize(width(), newHeight);
    }
}
