//
// Created by fuwei on 11/18/24.
//

#ifndef IMAGEVIEW_YIMAGEVIEW_H
#define IMAGEVIEW_YIMAGEVIEW_H

#include <QGraphicsView>
#include <QPoint>
#include <QPixmap>
#include <QGraphicsPixmapItem>
#include <QVariantAnimation>

namespace ImageView {

class YYImageView : public QGraphicsView {
    Q_OBJECT
   public:
    YYImageView(QWidget* parent = Q_NULLPTR);
    virtual ~YYImageView() = default;

   public:
    void loadImage(const QString& fileName);

   private:
    void init();

    /**
     * 图片与当前窗口大小宽高比。
* 缩放图片不影响该值，只有调整大小时才会影响。
* pw, ph 使用 self 而不用 viewport，是因为 viewport 已经调整过 margins，
* 其大小会比 self 大 4，而 self 才是整个可视区域。
     * @return
     */
    qreal ratio();
    /**
     * 图片自己的水平缩放系数，该值为 1 时表示图片未缩放，为原图大小。\n
     *  注意，是原图的大小，与当前窗口大小无关。
     * @return
     */
    qreal m11();

    void zoom(float factor);

    void wheelEvent(QWheelEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void enterEvent(QEvent* event) override;
    void leaveEvent(QEvent* event) override;

   private slots:
    void onZoom(float value);

   private:
    float m_zoomTotal = 1.f;                    // 图片总缩放倍率
    QPoint m_zoomOrigin;                        // 滚动开始时的视图锚点
    QPointF m_zoomSceneOrigin;                  // 滚动开始时的场景锚点
    QGraphicsPixmapItem* m_pixmap = Q_NULLPTR;  // 当前图片项目
    QVariantAnimation m_zoomAnimation;          // 缩放动画
};

}  // namespace ImageView
#endif  // IMAGEVIEW_YIMAGEVIEW_H
