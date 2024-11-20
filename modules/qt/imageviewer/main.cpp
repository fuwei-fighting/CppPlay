//
// Created by fuwei on 11/18/24.
//
#include <QApplication>
#include <QWidget>
#include <QMainWindow>
#include "YImageView.h"

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);

    QMainWindow w;
    w.show();

    ImageView::YYImageView imageView;
    //    imageView.loadImage();

    return app.exec();
}