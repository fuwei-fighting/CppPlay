//
// Created by fuwei on 12/9/24.
//

#ifndef CAST_YYLABELWIDGET_H
#define CAST_YYLABELWIDGET_H

#include <QLabel>

class YYLabel : public QLabel {
    Q_OBJECT
   public:
    explicit YYLabel(QWidget* parent = nullptr);
    ~YYLabel(){};

   public:
    void setMaximumWidth(int maxWidth);
    int maximumWidth() const;

   protected:
    void resizeEvent(QResizeEvent* event) override;
    void paintEvent(QPaintEvent* event) override;

    QSize sizeHint() const override;
    QSize minimumSizeHint() const override;

   private:
    QSize textSize() const;
    void updateTextLayout();

   private:
    int m_maxWidth = INT_MAX;
};

#endif  // CAST_YYLABELWIDGET_H
