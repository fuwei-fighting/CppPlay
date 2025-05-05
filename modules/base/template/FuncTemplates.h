//
// Created by fuwei on 5/5/25.
//

#ifndef TPM2_FUNCTEMPLATES_H
#define TPM2_FUNCTEMPLATES_H

#include <functional>

class FuncTemplates {
   public:

    template <typename Func1, typename Func2, typename... Args>
    void setValue(Func1 func1, Func2 func2, bool isUsedParam, Args&&... args) {
        if (isUsedParam) {
            func1(std::forward<Args>(args)...);
        } else {
            func2(std::forward<Args>(args)...);
        }
    }

    // normal funcs.
    void normalFuncPtrTest();

    void lambdaFuncTest();
};

#endif  // TPM2_FUNCTEMPLATES_H
