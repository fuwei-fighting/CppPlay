//
// Created by fuwei on 5/5/25.
//

#include "FuncTemplates.h"

#include <QString>
#include "dbg.h"


/** @brief normal functional
 */
void func1(int a, const QString &str) {
    dbg("normal func1: ");
    dbg(a, str.toStdString());
}

void func2(int a, const QString &str) {
    dbg("normal func2: ");
    dbg(a, str.toStdString());
}

void FuncTemplates::normalFuncPtrTest() {
    setValue(func1, func2, true, 10, "Hello");
    setValue(func1, func2, false, 10, "Hello");
}

void FuncTemplates::lambdaFuncTest() {
    int outParam = 20;

    auto block1 = [=](int a, const QString& str) {
        dbg("lambda block1: ");
        dbg(a, str.toStdString());
        dbg(outParam);

    };

    auto block2 = [=](int a, const QString& str) {
        dbg("lambda block2: ");
        dbg(a, str.toStdString());
        dbg(outParam);
    };

    setValue(block1, block2, true, 30, "C++");
    setValue(block1, block2, false, 30, "C++");
}
