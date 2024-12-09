//
// Created by fuwei on 11/25/24.
//
#include "yylabel.h"

#include <QApplication>
#include <QVBoxLayout>
#include <QMainWindow>
#include <QDebug>

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    QWidget* mainWidget = new QWidget;
    mainWidget->setMaximumWidth(200);

    QVBoxLayout* vLayout = new QVBoxLayout(mainWidget);
    {
        QLabel* label = new QLabel();
        label->setText("1 这是一段很长的文本，需要自动换行");
        label->setWordWrap(true);
        label->setMaximumWidth(200);  // 设置最大宽度

        vLayout->addWidget(label);
    }
    {
        QLabel* label = new QLabel();
        label->setText("1 这是一段很长的文本，需要自动换行");
        label->setWordWrap(true);
        label->setMaximumWidth(200);  // 设置最大宽度

        vLayout->addWidget(label);
    }

    //    {
    //        YYLabel* label = new YYLabel();
    //        label->setText("1 这是一段很长的文本，需要自动换行，2 这是一段很长的文本，需要自动换行，3 这是一段很长的文本，需要自动换行1 这是一段很长的文本，需要自动换行，2 这是一段很长的文本，需要自动换行，3 这是一段很长的文本，需要自动换行");
    //        label->setWordWrap(true);
    //        label->setMaximumWidth(200);  // 设置最大宽度
    //
    //        vLayout->addWidget(label);
    //    }
    vLayout->addStretch();
    mainWidget->show();

    return app.exec();
}