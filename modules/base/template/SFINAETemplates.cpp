//
// Created by fuwei on 5/5/25.
//

#include "SFINAETemplates.h"

#include <dbg.h>


/**
 * @brief (1) enableIfTestDemo
 */
template <typename T, typename std::enable_if<std::is_integral<T>::value>::type* = nullptr>
void print(T value) {
    dbg("=== print integral ===");
    dbg(value);
}

template <typename T, typename std::enable_if<std::is_floating_point<T>::value>::type* = nullptr>
void print(T value) {
    dbg("=== print floating_point ===");
    dbg(value);
}

template <typename T, typename std::enable_if<std::is_integral<T>::value, int>::type = 0>
void process(T value) {
    dbg("=== process intergral ===");
    dbg( value);
}

template <typename T, typename std::enable_if<std::is_floating_point<T>::value, int>::type = 0>
void process(T value) {
    dbg("=== process floating ===");
    dbg( value);
}

void SFINAETemplates::enableIfTestDemo() {
    print(42);
    print(3.14);

    process(52);
    process(6.66);
}

/**
 * @brief (2) simpleSFINAEDemo
 */
struct test_struct {
    typedef int foo;
};

template <typename T>
void func(typename T::foo) {
    dbg("=== func has T::foo ===");
} // 要求T类型中包含foo内嵌类型

template <typename T>
void func(T) {
    dbg("=== func has no limit ===");
}

void SFINAETemplates::simpleSFINAEDemo() {
    func<test_struct>(10);
    func<int>(20); // 因为SFINAE的存在，即使没有int::foo，这个也不报错。
}

/**
 * @brief (3) simpleSFINAEDemo2
 */
template <typename T>
struct has_reserve_struct {
    struct good { char dummy; };
    struct bad { char dummy[2]; };

    template <class U, float (U::*)()>
    struct sfinae {};

    template <typename U>
    static good test(sfinae<U, &U::reserve>*);

    template <typename>
    static bad test(...);

    static const bool value = sizeof(test<T>(nullptr)) == sizeof(good);
};

class TestReserve {
   public:
    float reserve();
};

class Bar {
   public:
    int type;
};


void SFINAETemplates::simpleSFINAEDemo2() {
    std::cout << "has_reserve<TestReserve>::value = " << has_reserve_struct<TestReserve>::value << std::endl;

    std::cout << "has_reserve_struct<Bar>::value = "  << has_reserve_struct<Bar>::value<<std::endl;
}

/**
 * @brief (4) enableIfTestDemo2
 */
template <typename T>
typename std::enable_if<has_reserve_struct<T>::value, void>::type
    reserve_test1() {
    std::cout << "reserve_test1." << std::endl;
}

template <typename T,
          typename = typename std::enable_if<has_reserve_struct<T>::value>::type>
void reserve_test2() {
    std::cout << "reserve_test2." << std::endl;
}


void SFINAETemplates::enableIfTestDemo2() {
    reserve_test1<TestReserve>();
    reserve_test2<TestReserve>();
}
