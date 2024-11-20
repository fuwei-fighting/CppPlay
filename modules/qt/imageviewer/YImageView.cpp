//
// Created by fuwei on 11/18/24.
//

#include "YImageView.h"
#include <QGraphicsScene>
#include <QResizeEvent>
#include <QWheelEvent>
#include <QDebug>

using namespace ImageView;

YYImageView::YYImageView(QWidget* parent)
    : QGraphicsView(parent) {
    init();
}

void YYImageView::init() {
    setWindowTitle("Image Viewer");                                                                    // 窗口标题
    setScene(new QGraphicsScene());                                                                    // 设置场景
    setViewportMargins(-2, -2, -2, -2);                                                                // 消除边缘间距
    setMinimumSize(QSize(502, 420));                                                                   //视图最小尺寸
    setBackgroundBrush(QColor('#242424'));                                                             // 设置背景
    setFrameShape(QGraphicsView::Shape::NoFrame);                                                      // 移除边框
    setDragMode(QGraphicsView::DragMode::ScrollHandDrag);                                              // 启用拖拽模式
    setResizeAnchor(QGraphicsView::ViewportAnchor::NoAnchor);                                          // 清除视图锚点
    setRenderHints(QPainter::RenderHint::Antialiasing | QPainter::RenderHint::SmoothPixmapTransform);  // 平滑渲染图片
    setCacheMode(QGraphicsView::CacheModeFlag::CacheBackground);                                       // 缓存背景
    setVerticalScrollBarPolicy(Qt::ScrollBarPolicy::ScrollBarAlwaysOff);                               // 隐藏垂直滚动条
    setHorizontalScrollBarPolicy(Qt::ScrollBarPolicy::ScrollBarAlwaysOff);                             //隐藏水平滚动条
    setOptimizationFlags(QGraphicsView::OptimizationFlag::DontSavePainterState);                       // 不要自动保存绘制状态
    setViewportUpdateMode(QGraphicsView::ViewportUpdateMode::SmartViewportUpdate);                     // 智能渲染视口的显示内容
}

void YYImageView::loadImage(const QString& fileName) {
    if (QPixmap(fileName).isNull()) {
        return;
    }

    m_zoomTotal = 1.0;  // 重置缩放倍率
    resetTransform();   // 重置变换
    scene()->clear();   // 清除场景内容

    m_pixmap = new QGraphicsPixmapItem(m_pixmap);
    m_pixmap->setTransformationMode(Qt::TransformationMode::SmoothTransformation);  // 平滑变换

    scene()->addItem(m_pixmap);  // 添加场景内容
    if (ratio() < 1) {           // 原图的宽或高 > 当前窗口
        fitInView(m_pixmap, Qt::AspectRatioMode::KeepAspectRatio);
    }
}

qreal YYImageView::ratio() {
    auto scene = sceneRect();
    qreal pw = width() / scene.width();
    qreal ph = height() / scene.height();
    return std::min(pw, ph);
}
void YYImageView::wheelEvent(QWheelEvent* event) {
    qreal angle = event->angleDelta().y();  //正值表示向前滚动 (放大)
    if (angle < 0 && m_zoomTotal == 1) {    // 限制缩小尺寸
        qDebug() << "cannot narrow";
        return;
    }
    m_zoomOrigin = event->pos();
    m_zoomSceneOrigin = mapToScene(m_zoomOrigin);
    zoom((angle > 0) ? 1.1 : 0.9);

    QGraphicsView::wheelEvent(event);
}
void YYImageView::resizeEvent(QResizeEvent* event) {
    QGraphicsView::resizeEvent(event);

    if (!m_pixmap) {
        return;
    }
    qreal factor = ratio() * m_zoomTotal / m11();
    scale(factor, factor);
}
void YYImageView::zoom(float factor) {
    bool running = m_zoomAnimation.state() == QVariantAnimation::State::Running;
    if (running) {
        factor *= factor;
    }
    m_zoomAnimation.setStartValue(m_zoomTotal);
    m_zoomAnimation.setEndValue(std::max(1.f, m_zoomTotal * factor));
    m_zoomAnimation.start();
}
void YYImageView::onZoom(float value) {
    float factor = value / m_zoomTotal;
    if (factor == m_zoomTotal) {
        return;
    }
    m_zoomTotal = value;
    scale(factor, factor);

    QPointF delta = mapToScene(m_zoomOrigin) - m_zoomSceneOrigin;
    translate(delta.x(), delta.y());
}
void YYImageView::enterEvent(QEvent* event) {
    setTransformationAnchor(QGraphicsView::ViewportAnchor::NoAnchor);
    QWidget::enterEvent(event);
}
void YYImageView::leaveEvent(QEvent* event) {
    setTransformationAnchor(QGraphicsView::ViewportAnchor::AnchorUnderMouse);
    QWidget::leaveEvent(event);
}
qreal YYImageView::m11() {
    return transform().m11();
}
