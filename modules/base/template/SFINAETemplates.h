//
// Created by fuwei on 5/5/25.
//

#ifndef BASE_SFINAETEMPLATES_H
#define BASE_SFINAETEMPLATES_H

#include <type_traits>

/**
 * @brief SFINAE 机制
 * @defination 编译器根据名称找出所有适用的函数或者函数模板，根据实际情况对模板形参进行替换。
 */
class SFINAETemplates {
   public:
    void enableIfTestDemo();
    void simpleSFINAEDemo();
    void simpleSFINAEDemo2();
    void enableIfTestDemo2();
};

#endif  // BASE_SFINAETEMPLATES_H
