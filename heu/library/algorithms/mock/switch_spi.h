// Copyright 2022 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

/*
 * To algorithm developers:
 * What is Smart SPI?
 *
 * HEU supports two distinct SPIs: scalar spi and vectorized spi. The
 * encryptor/decryptor/evaluator of each algorithm only needs to implement one
 * set of SPI. The HEU dispatch layer will automatically decide which SPI to
 * call. The SPI dispatch work is done at compile time with no runtime overhead.
 *
 * A little hands-on experiment: You can turn the following two macros on or off
 * to control whether the relevant code would delete. You will find that if you
 * keep any set of SPI, the compilation will succeed; only if you delete
 * both sets of SPIs at the same time, the compilation will fail; And when you
 * keep both sets of SPIs, your program will get the best performance.
 *
 * The following two macros are only to simulate the effect of code deletion.
 * The switching of smart SPI does not depend on these two macros. In your
 * algorithm, you do not need to define these two macros, and you can directly
 * implement the functions corresponding to the SPI.
 *
 *
 * To 算法开发者：
 * 什么是智能型 SPI？
 *
 * HEU 支持两种截然不同的 SPI，即 scalar spi 和 vectorized spi。每一种算法的
 * encryptor/decryptor/evaluator 只需要实现其中一套 spi 即可。HEU dispatch
 * 层会根据您实际实现的 SPI 而自动决定调用哪一套 SPI。HEU 的 SPI dispatch
 * 工作在编译期完成，无运行时开销。
 *
 * 动手做小实验：您可以打开或关闭以下两个宏，从而控制相关代码是否要删去。您会发现只要保留任意一套
 * SPI，编译都将成功；只有将两套 SPI 同时删去，编译才会失败；当您同时实现两套
 * SPI 时，您的程序将获得最佳性能。
 *
 * 以下两个宏仅仅是为了模拟代码删除的效果，智能型 SPI
 * 的切换并不依赖这两个宏，在您的算法中，您无需定义这两个宏，直接实现所述 SPI
 * 对应的函数即可，至少一套，两套都实现更好。
 */
#define IMPL_SCALAR_SPI
#define IMPL_VECTORIZED_SPI

/*
 * About SPI LEVEL:
 * For each public method that belongs to SPI, we label the SPI importance level
 * above it:
 * [SPI: Critical] : A method required by the core business (such as LR, XGB),
 * which you must implement immediately.
 * [SPI: Important] : A method that is not used by core business, but needs to
 * be implemented as part of functional integrity; If it is not implemented, the
 * user experience will be affected. If you don't want to implement these
 * methods, keep the function declarations and throw exceptions at the
 * implementations.
 *
 * 关于 SPI LEVEL:
 * 对于每一个属于 SPI 的 public method，我们在其上方标注了 SPI 重要性级别：
 * [SPI: Critical]：核心业务（LR、XGB）需要用到的方法，您必须立即实现该接口。
 * [SPI: Important]：核心业务暂未使用，但作为功能完整性的一环需要实现的方法，
 *     不实现将会影响用户体验。该类方法的签名必须保留，实现处可以抛一个异常。
 */
