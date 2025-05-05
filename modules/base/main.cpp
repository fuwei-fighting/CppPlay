//
// Created by fuwei on 5/5/25.
//
#include "template/FuncTemplates.h"

int main(int argc, char* argv[]) {
    {
        FuncTemplates funcTemplates;
        funcTemplates.normalFuncPtrTest();
    }
    {
        FuncTemplates funcTemplates;
        funcTemplates.lambdaFuncTest();
    }
}