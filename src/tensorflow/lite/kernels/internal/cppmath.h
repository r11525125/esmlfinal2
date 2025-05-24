/* Copyright 2020 The TensorFlow Authors. All Rights Reserved.
   Licensed under the Apache License, Version 2.0 (the "License"); */

#ifndef TENSORFLOW_LITE_KERNELS_INTERNAL_CPPMATH_H_
#define TENSORFLOW_LITE_KERNELS_INTERNAL_CPPMATH_H_

// 直接包含 C 的 math 头，保证全局符号可用
#include <math.h>

namespace tflite {

// 统一用全局命名空间的函数 ::round/::expm1
template <class T>
inline T TfLiteRound(const T x) {
  // 对 float 和 double 都能调用
  return ::round(x);
}
template <class T>
inline T TfLiteExpm1(const T x) {
  return ::expm1(x);
}

}  // namespace tflite

#endif  // TENSORFLOW_LITE_KERNELS_INTERNAL_CPPMATH_H_
