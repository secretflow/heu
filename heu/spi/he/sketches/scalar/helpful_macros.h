// Copyright 2024 Ant Group Co., Ltd.
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

namespace heu::lib::spi {

#define GetItemType(T) \
  std::is_same_v<CiphertextT, T> ? ItemType::Ciphertext : ItemType::Plaintext

// Call:
//   virtual auto FuncName(const T& x) const = 0;
//   virtual auto FuncName(const T& x, ...) const = 0;
#define CallUnaryFunc(FuncName, T, x, ...)                                    \
  do {                                                                        \
    using RES_T = decltype(FuncName(std::declval<const T>(), ##__VA_ARGS__)); \
                                                                              \
    if (x.IsArray()) {                                                        \
      auto xsp = x.AsSpan<T>();                                               \
      std::vector<RES_T> res;                                                 \
      res.resize(xsp.length());                                               \
      yacl::parallel_for(0, xsp.length(), [&](int64_t beg, int64_t end) {     \
        for (int64_t i = beg; i < end; ++i) {                                 \
          res[i] = FuncName(xsp[i], ##__VA_ARGS__);                           \
        }                                                                     \
      });                                                                     \
      return Item::Take(std::move(res), GetItemType(RES_T));                  \
    } else {                                                                  \
      return {FuncName(x.As<T>(), ##__VA_ARGS__), GetItemType(RES_T)};        \
    }                                                                         \
  } while (0)

// Call:
//   virtual void FuncName(T* x) const = 0;
//   virtual void FuncName(T* x, ...) const = 0;
#define CallUnaryInplaceFunc(FuncName, T, x, ...)                         \
  do {                                                                    \
    if (x->IsArray()) {                                                   \
      auto xsp = x->AsSpan<T>();                                          \
      yacl::parallel_for(0, xsp.length(), [&](int64_t beg, int64_t end) { \
        for (int64_t i = beg; i < end; ++i) {                             \
          FuncName(&xsp[i], ##__VA_ARGS__);                               \
        }                                                                 \
      });                                                                 \
    } else {                                                              \
      FuncName(x->As<T*>(), ##__VA_ARGS__);                               \
    }                                                                     \
  } while (0)

// Call:
//   virtual T FuncName(const TX& x, const TY& y) const = 0;
#define CallBinaryFunc(FuncName, TX, TY)                                      \
  do {                                                                        \
    using RES_T = decltype(FuncName(std::declval<const TX>(),                 \
                                    std::declval<const TY>()));               \
                                                                              \
    switch (x, y) {                                                           \
      case yacl::OperandType::Scalar2Scalar: {                                \
        return {FuncName(x.As<TX>(), y.As<TY>()), GetItemType(RES_T)};        \
      }                                                                       \
      case yacl::OperandType::Vector2Vector: {                                \
        auto xsp = x.AsSpan<TX>();                                            \
        auto ysp = y.AsSpan<TY>();                                            \
        YACL_ENFORCE_EQ(                                                      \
            xsp.length(), ysp.length(),                                       \
            "operands must have the same length, x.len={}, y.len={}",         \
            xsp.length(), ysp.length());                                      \
                                                                              \
        std::vector<RES_T> res;                                               \
        res.resize(xsp.length());                                             \
        yacl::parallel_for(0, xsp.length(), [&](int64_t beg, int64_t end) {   \
          for (int64_t i = beg; i < end; ++i) {                               \
            res[i] = FuncName(xsp[i], ysp[i]);                                \
          }                                                                   \
        });                                                                   \
        return Item::Take(std::move(res), GetItemType(RES_T));                \
      }                                                                       \
      default:                                                                \
        YACL_THROW("Scalar sketch method [{}] doesn't support broadcast now", \
                   #FuncName);                                                \
    }                                                                         \
  } while (0)

// Call:
//   virtual void FuncName(TX* x, const TY& y) const = 0;
#define CallBinaryInplaceFunc(FuncName, TX, TY)                               \
  do {                                                                        \
    switch (*x, y) {                                                          \
      case yacl::OperandType::Scalar2Scalar: {                                \
        FuncName(x->As<TX*>(), y.As<TY>());                                   \
        return;                                                               \
      }                                                                       \
      case yacl::OperandType::Vector2Vector: {                                \
        auto xsp = x->AsSpan<TX>();                                           \
        auto ysp = y.AsSpan<TY>();                                            \
        YACL_ENFORCE_EQ(                                                      \
            xsp.length(), ysp.length(),                                       \
            "operands must have the same length, x.len={}, y.len={}",         \
            xsp.length(), ysp.length());                                      \
        yacl::parallel_for(0, xsp.length(), [&](int64_t beg, int64_t end) {   \
          for (int64_t i = beg; i < end; ++i) {                               \
            FuncName(&xsp[i], ysp[i]);                                        \
          }                                                                   \
        });                                                                   \
        return;                                                               \
      }                                                                       \
      default:                                                                \
        YACL_THROW("Scalar sketch method [{}] doesn't support broadcast now", \
                   #FuncName);                                                \
    }                                                                         \
  } while (0)

//==================================//
//      Define whole function       //
//==================================//

// From:
//   virtual Item FuncName(const Item& x) const = 0;
// To:
//   virtual T FuncName(const T& x) const = 0;
#define DefineUnaryFuncBoth(FuncName)           \
  Item FuncName(const Item& x) const override { \
    if (x.IsCiphertext()) {                     \
      CallUnaryFunc(FuncName, CiphertextT, x);  \
    } else {                                    \
      CallUnaryFunc(FuncName, PlaintextT, x);   \
    }                                           \
  }

#define DefineUnaryFuncCT(FuncName)                                          \
  Item FuncName(const Item& x) const override {                              \
    YACL_ENFORCE(x.IsCiphertext(), "input arg must be a cipher, real is {}", \
                 x.ToString());                                              \
    CallUnaryFunc(FuncName, CiphertextT, x);                                 \
  }

#define DefineUnaryFuncPT(FuncName)                                            \
  Item FuncName(const Item& x) const override {                                \
    YACL_ENFORCE(x.IsPlaintext(), "input arg must be a plaintext, real is {}", \
                 x.ToString());                                                \
    CallUnaryFunc(FuncName, PlaintextT, x);                                    \
  }

// From:
//   virtual void FuncName(const Item &x, Item *out) const = 0;
// To:
//   virtual void FuncName(const TX& x, TY *out) const = 0;
#define DefineUnaryFuncCStyle(FuncName, TX, TY)                           \
  void FuncName(const Item& x, Item* out) const override {                \
    if (x.IsArray()) {                                                    \
      auto xsp = x.AsSpan<TX>();                                          \
      auto ysp = out->ResizeAndSpan<TY>(xsp.size());                      \
      yacl::parallel_for(0, xsp.length(), [&](int64_t beg, int64_t end) { \
        for (int64_t i = beg; i < end; ++i) {                             \
          FuncName(xsp[i], &ysp[i]);                                      \
        }                                                                 \
      });                                                                 \
    } else {                                                              \
      FuncName(x.As<TX>(), out->As<TY*>());                               \
    };                                                                    \
    out->MarkAs(GetItemType(TY));                                         \
  }

// From:
//   virtual void FuncName(Item* x) const = 0;
// To:
//   virtual void FuncName(T* x) const = 0;
#define DefineUnaryInplaceFunc(FuncName)              \
  void FuncName(Item* x) const override {             \
    if (x->IsCiphertext()) {                          \
      CallUnaryInplaceFunc(FuncName, CiphertextT, x); \
    } else {                                          \
      CallUnaryInplaceFunc(FuncName, PlaintextT, x);  \
    }                                                 \
  }

#define DefineUnaryInplaceFuncOnlyCipher(FuncName)                            \
  void FuncName(Item* x) const override {                                     \
    YACL_ENFORCE(x->IsCiphertext(), "input arg must be a cipher, real is {}", \
                 x->ToString());                                              \
    CallUnaryInplaceFunc(FuncName, CiphertextT, x);                           \
  }

// From:
//   virtual Item FuncName(const Item& x, const Item& y) const = 0;
// To:
//   virtual T FuncName(const T& x, const T& y) const = 0;
#define DefineBinaryFunc(FuncName)                             \
  Item FuncName(const Item& x, const Item& y) const override { \
    if (x.IsCiphertext()) {                                    \
      if (y.IsCiphertext()) {                                  \
        CallBinaryFunc(FuncName, CiphertextT, CiphertextT);    \
      } else {                                                 \
        CallBinaryFunc(FuncName, CiphertextT, PlaintextT);     \
      }                                                        \
    } else { /* x is plaintext */                              \
      if (y.IsCiphertext()) {                                  \
        CallBinaryFunc(FuncName, PlaintextT, CiphertextT);     \
      } else {                                                 \
        CallBinaryFunc(FuncName, PlaintextT, PlaintextT);      \
      }                                                        \
    }                                                          \
  }

// From:
//   virtual void FuncName(Item* x, const Item& y) const = 0;
// To:
//   virtual void FuncName(T* x, const T& y) const = 0;
#define DefineBinaryInplaceFunc(FuncName)                          \
  void FuncName(Item* x, const Item& y) const override {           \
    if (x->IsCiphertext()) {                                       \
      if (y.IsCiphertext()) {                                      \
        CallBinaryInplaceFunc(FuncName, CiphertextT, CiphertextT); \
      } else {                                                     \
        CallBinaryInplaceFunc(FuncName, CiphertextT, PlaintextT);  \
      }                                                            \
    } /* no plaintext branch */                                    \
  }

}  // namespace heu::lib::spi
