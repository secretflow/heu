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

#pragma once

#include <cstddef>
#include <cstdint>
#include <experimental/type_traits>
#include <string>
#include <vector>

#include "yacl/base/buffer.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/utils/spi/sketch/scalar_tools.h"

#include "heu/spi/he/item.h"
#include "heu/spi/he/item_tool.h"
#include "heu/spi/he/sketches/common/placeholder.h"

// Suppress the superfluous warnings from clang
#if defined(__clang__)
#pragma clang diagnostic ignored "-Woverloaded-virtual"
#endif

namespace heu::spi {

namespace internal {

template <typename T>
using kHasToStringMethod = decltype(std::declval<T>().ToString());

template <typename T>
using SupportsEqualsCompare = decltype(std::declval<T>() == std::declval<T>());

template <typename T>
using kHasSerMethod =
    decltype(std::declval<T>().Serialize(std::declval<uint8_t *>(), size_t()));
template <typename T>
using kHasDeserMethod = decltype(std::declval<T>().Deserialize(
    std::declval<yacl::ByteContainerView>()));

}  // namespace internal

template <typename PlaintextT, typename CiphertextT, typename SecretKeyT,
          typename PublicKeyT = NoPk, typename RelinKeyT = NoRlk,
          typename GaloisKeyT = NoGlk, typename BootstrapKeyT = NoBsk>
class ItemToolSketch : public ItemTool {
 public:
  virtual ~ItemToolSketch() = default;

  //===   Item operations   ===//

  // To human-readable string
  virtual std::string ToString(const PlaintextT &pt) const {
    if constexpr (std::experimental::is_detected_v<internal::kHasToStringMethod,
                                                   PlaintextT>) {
      return pt.ToString();
    } else {
      YACL_THROW(
          "You must add a ToString() method to Plaintext type or override the "
          "ToString(const PlaintextT &) method in the subclass of ItemTool. "
          "type_info={}",
          typeid(pt).name());
    }
  }

  virtual std::string ToString(const CiphertextT &ct) const {
    if constexpr (std::experimental::is_detected_v<internal::kHasToStringMethod,
                                                   CiphertextT>) {
      // Square brackets indicate that the object is a HE ciphertext.
      return fmt::format("[{}]", ct.ToString());
    } else {
      YACL_THROW(
          "You must add a ToString() method to Ciphertext type or override the "
          "ToString(const CiphertextT &) method in the subclass of ItemTool. "
          "type_info={}",
          typeid(ct).name());
    }
  }

  virtual bool Equal(const PlaintextT &x, const PlaintextT &y) const {
    if constexpr (std::experimental::is_detected_v<
                      internal::SupportsEqualsCompare, PlaintextT>) {
      return x == y;
    } else {
      YACL_THROW(
          "Cannot compare two plaintexts. You must implement the '==' operator "
          "for Plaintext, or override the Equal() method in the subclass of "
          "ItemTool. type_info={}",
          typeid(x).name());
    }
  }

  virtual bool Equal(const CiphertextT &x, const CiphertextT &y) const {
    if constexpr (std::experimental::is_detected_v<
                      internal::SupportsEqualsCompare, CiphertextT>) {
      return x == y;
    } else {
      YACL_THROW(
          "Cannot compare two ciphertexts. You must implement the '==' "
          "operator for Ciphertext, or override the Equal() method in the "
          "subclass of ItemTool. type_info={}",
          typeid(x).name());
    }
  }

  //===   I/O for HE Objects   ===//

  // serialize plaintext/ciphertext to already allocated buffer.
  // if buf is nullptr, then calc serialize size only
  // @return: the actual size of serialized buffer
  //
  // 对于某些算法例如 EC-Elgamal 等，序列化 Plaintext 需要用到 HeKit
  // 中的公共参数，因此不能直接在 PlaintextT 中定义 Serialize
  // 方法，此时应该在子类中覆盖本方法
  // For certain algorithms such as EC-Elgamal, serializing Plaintext requires
  // using public parameters from HeKit. Therefore, the Serialize method cannot
  // be directly defined in PlaintextT type. Instead, it should be overridden in
  // the subclass of ItemToolSketch.
  virtual size_t Serialize(const PlaintextT &pt, uint8_t *buf,
                           size_t buf_len) const {
    if constexpr (std::experimental::is_detected_v<internal::kHasSerMethod,
                                                   PlaintextT>) {
      return pt.Serialize(buf, buf_len);
    } else {
      YACL_THROW(
          "You must add a Serialize(uint8_t *, size_t) method to Plaintext "
          "type or override the Serialize(const PlaintextT &, uint8_t *, "
          "size_t) method in the subclass of ItemTool. type_info={}",
          typeid(pt).name());
    }
  }

  // For certain algorithms such as EC-Elgamal, serializing Ciphertext requires
  // using public parameters from HeKit. Therefore, the Serialize method cannot
  // be directly defined in CiphertextT type. Instead, it should be overridden
  // in the subclass of ItemToolSketch.
  virtual size_t Serialize(const CiphertextT &ct, uint8_t *buf,
                           size_t buf_len) const {
    if constexpr (std::experimental::is_detected_v<internal::kHasSerMethod,
                                                   CiphertextT>) {
      return ct.Serialize(buf, buf_len);
    } else {
      YACL_THROW(
          "You must add a Serialize(uint8_t *, size_t) method to Ciphertext "
          "type or override the Serialize(const CiphertextT &, uint8_t *, "
          "size_t) method in the subclass of ItemTool. type_info={}",
          typeid(ct).name());
    }
  }

  // 对于某些算法例如 EC-Elgamal 等，反序列化 Plaintext 需要用到 HeKit
  // 中的公共参数，因此不能直接在 PlaintextT 中定义 Deserialize
  // 方法，此时应该在子类中覆盖本方法
  // For certain algorithms such as EC-Elgamal, deserializing Plaintext requires
  // using public parameters from HeKit. Therefore, the Deserialize method
  // cannot be directly defined in PlaintextT type. Instead, it should be
  // overridden in the subclass of ItemToolSketch.
  virtual PlaintextT DeserializePT(yacl::ByteContainerView buffer) const {
    if constexpr (std::experimental::is_detected_v<internal::kHasDeserMethod,
                                                   PlaintextT>) {
      PlaintextT pt;
      pt.Deserialize(buffer);
      return pt;
    } else {
      YACL_THROW(
          "You must add a Deserialize(yacl::ByteContainerView) method to "
          "Plaintext type or override the "
          "DeserializePT(yacl::ByteContainerView) method in the subclass of "
          "ItemTool. type_info={}",
          typeid(PlaintextT).name());
    }
  }

  // For certain algorithms such as EC-Elgamal, deserializing Ciphertext
  // requires using public parameters from HeKit. Therefore, the Deserialize
  // method cannot be directly defined in CiphertextT type. Instead, it should
  // be overridden in the subclass of ItemToolSketch.
  virtual CiphertextT DeserializeCT(yacl::ByteContainerView buffer) const {
    if constexpr (std::experimental::is_detected_v<internal::kHasDeserMethod,
                                                   CiphertextT>) {
      CiphertextT ct;
      ct.Deserialize(buffer);
      return ct;
    } else {
      YACL_THROW(
          "You must add a Deserialize(yacl::ByteContainerView) method to "
          "Ciphertext type or override the "
          "DeserializeCT(yacl::ByteContainerView) method in the subclass of "
          "ItemTool. type_info={}",
          typeid(CiphertextT).name());
    }
  }

 protected:
#define SWITCH_TYPE(item, method, ...)                          \
  switch (item.GetContentType()) {                              \
    case ContentType::Plaintext:                                \
      return item.method<PlaintextT>(__VA_ARGS__);              \
    case ContentType::Ciphertext:                               \
      return item.method<CiphertextT>(__VA_ARGS__);             \
    case ContentType::SecretKey:                                \
      return item.method<SecretKeyT>(__VA_ARGS__);              \
    case ContentType::PublicKey:                                \
      return item.method<PublicKeyT>(__VA_ARGS__);              \
    case ContentType::RelinKeys:                                \
      return item.method<RelinKeyT>(__VA_ARGS__);               \
    case ContentType::GaloisKeys:                               \
      return item.method<GaloisKeyT>(__VA_ARGS__);              \
    case ContentType::BootstrapKey:                             \
      return item.method<BootstrapKeyT>(__VA_ARGS__);           \
    default:                                                    \
      YACL_THROW("Unsupported content type '{}', please check", \
                 item.GetContentType());                        \
  }

  size_t ItemSize(const Item &item) const override { SWITCH_TYPE(item, Size); }

  Item SubItem(const Item &item, size_t pos, size_t len) const override {
    SWITCH_TYPE(item, SubItem, pos, len);
  }

  Item SubItem(Item &item, size_t pos, size_t len) const override {
    SWITCH_TYPE(item, SubItem, pos, len);
  }

  Item SubItem(const Item &item, size_t pos) const override {
    SWITCH_TYPE(item, SubItem, pos);
  }

  Item SubItem(Item &item, size_t pos) const override {
    SWITCH_TYPE(item, SubItem, pos);
  }

  void AppendItem(Item *, const Item &) const override {
    // todo
  }

  Item CombineItem(const Item &, const Item &) const override {
    // todo
    YACL_THROW("todo");
  }

  template <class T>
  std::string CallToString(const Item &item) const {
    if (item.IsArray()) {
      auto xsp = item.AsSpan<T>();
      std::vector<std::string> res;
      res.resize(xsp.length());
      yacl::parallel_for(0, xsp.length(), [&](int64_t beg, int64_t end) {
        for (int64_t i = beg; i < end; ++i) {
          res[i] = ToString(xsp[i]);
        }
      });
      return fmt::format("Array {{{}}}", fmt::join(res, ", "));
    } else {
      return ToString(item.As<T>());
    }
  }

  std::string ToString(const Item &item) const override {
    switch (item.GetContentType()) {
      case ContentType::Plaintext:
        return CallToString<PlaintextT>(item);
      case ContentType::Ciphertext:
        return CallToString<CiphertextT>(item);
      case ContentType::SecretKey:
        // All keys have a default ToString() implement
        // defined in heu/spi/he/sketches/common/keys.h
        return item.As<SecretKeyT>().ToString();
      case ContentType::PublicKey:
        return item.As<PublicKeyT>().ToString();
      case ContentType::RelinKeys:
        return item.As<RelinKeyT>().ToString();
      case ContentType::GaloisKeys:
        return item.As<GaloisKeyT>().ToString();
      case ContentType::BootstrapKey:
        return item.As<BootstrapKeyT>().ToString();
      default:
        YACL_THROW("Unsupported content type '{}', please check",
                   item.GetContentType());
    }
  }

  template <class T>
  bool CheckEquality(const heu::spi::Item &x, const heu::spi::Item &y) const {
    auto xsp = x.AsSpan<T>();
    auto ysp = y.AsSpan<T>();
    if (xsp.size() != ysp.size()) {
      return false;
    }
    for (size_t i = 0; i < xsp.size(); ++i) {
      if (!Equal(xsp.at(i), ysp.at(i))) {
        return false;
      }
    }
    return true;
  }

  bool Equal(const heu::spi::Item &x, const heu::spi::Item &y) const override {
    if (x.GetContentType() != y.GetContentType()) {
      return false;
    }

    switch (x.GetContentType()) {
      case ContentType::Plaintext:
        return CheckEquality<PlaintextT>(x, y);
      case ContentType::Ciphertext:
        return CheckEquality<CiphertextT>(x, y);
      case ContentType::SecretKey:
      case ContentType::PublicKey:
      case ContentType::RelinKeys:
      case ContentType::GaloisKeys:
      case ContentType::BootstrapKey:
        // Hekit->ListKeyParams() has low performance, so we do not provide
        // equality test
        YACL_THROW(
            "Cannot compare the equality of two keys, please compare the "
            "content of Hekit->ListKeyParams(HeKeyType::{}) instead.",
            x.GetContentType());
      default:
        YACL_THROW("Unsupported content type '{}', please check",
                   x.GetContentType());
    }
  }

  // THE MSGPACK SERIALIZE FORMAT: | 1bytes header | body |
  size_t Serialize(const Item &item, uint8_t *buf,
                   size_t buf_len) const override {
    switch (item.GetContentType()) {
      case ContentType::Plaintext:
        return yacl::ScalarSketchTools::Serialize<PlaintextT>(
            this, item, buf, buf_len,
            static_cast<int8_t>(item.GetContentType()));
      case ContentType::Ciphertext:
        return yacl::ScalarSketchTools::Serialize<CiphertextT>(
            this, item, buf, buf_len,
            static_cast<int8_t>(item.GetContentType()));
      case ContentType::SecretKey:
      case ContentType::PublicKey:
      case ContentType::RelinKeys:
      case ContentType::GaloisKeys:
      case ContentType::BootstrapKey:
        // do not support serializing keys, use HeKit instead.
        YACL_THROW(
            "Serialize a key item is no longer supported, please use "
            "hekit->Serialize(key_type) instead.");
      default:
        YACL_THROW("Unsupported content type '{}', please check",
                   item.GetContentType());
    }
  }

  yacl::Buffer Serialize(const Item &item) const override {
    switch (item.GetContentType()) {
      case ContentType::Plaintext:
        return yacl::ScalarSketchTools::Serialize<PlaintextT>(
            this, item, static_cast<int8_t>(item.GetContentType()));
      case ContentType::Ciphertext:
        return yacl::ScalarSketchTools::Serialize<CiphertextT>(
            this, item, static_cast<int8_t>(item.GetContentType()));
      case ContentType::SecretKey:
      case ContentType::PublicKey:
      case ContentType::RelinKeys:
      case ContentType::GaloisKeys:
      case ContentType::BootstrapKey:
        // do not support serializing keys, use HeKit instead.
        YACL_THROW(
            "Serialize a key item is no longer supported, please use "
            "hekit->Serialize(key_type) instead.");
      default:
        YACL_THROW("Unsupported content type '{}', please check",
                   item.GetContentType());
    }
  }

  // parse body
  template <typename RES_T>
  Item DeserializeBody(
      ContentType content_type, yacl::ByteContainerView buffer, size_t offset,
      RES_T (ItemToolSketch::*deser_func)(yacl::ByteContainerView)
          const) const {
    msgpack::object_handle msg = msgpack::unpack(
        reinterpret_cast<const char *>(buffer.data()), buffer.size(), offset);

    auto obj = msg.get();
    switch (obj.type) {
      case msgpack::type::STR:
        // scalar case
        return {(this->*deser_func)({obj.via.str.ptr, obj.via.str.size}),
                content_type};
      case msgpack::type::ARRAY: {
        // vector case
        std::vector<RES_T> res;
        res.resize(obj.via.array.size);
        yacl::parallel_for(0, obj.via.array.size,
                           [&](int64_t beg, int64_t end) {
                             for (int64_t i = beg; i < end; ++i) {
                               auto str_obj = obj.via.array.ptr[i];
                               YACL_ENFORCE(str_obj.type == msgpack::type::STR,
                                            "Deserialize: illegal format");
                               res[i] = (this->*deser_func)(
                                   {str_obj.via.str.ptr, str_obj.via.str.size});
                             }
                           });
        return Item::Take(std::move(res), content_type);
      }
      default:
        YACL_THROW("Deserialize: unexpected type");
    }
  }

  Item Deserialize(yacl::ByteContainerView buffer) const override {
    // parse header
    std::size_t off = 0;
    bool referenced;
    msgpack::object_handle header =
        msgpack::unpack(reinterpret_cast<const char *>(buffer.data()),
                        buffer.size(), off, referenced);
    auto obj = header.get();
    YACL_ENFORCE(off == 1 && obj.type == msgpack::type::POSITIVE_INTEGER,
                 "unexpected buffer header. header size={}", off);

    ContentType item_ct = (ContentType)obj.via.i64;
    switch (item_ct) {
      case ContentType::Plaintext:
        return DeserializeBody(item_ct, buffer, off,
                               &ItemToolSketch::DeserializePT);
      case ContentType::Ciphertext:
        return DeserializeBody(item_ct, buffer, off,
                               &ItemToolSketch::DeserializeCT);
      case ContentType::SecretKey:
      case ContentType::PublicKey:
      case ContentType::RelinKeys:
      case ContentType::GaloisKeys:
      case ContentType::BootstrapKey:
        YACL_THROW(
            "Deserialize a key is no longer supported, please directly pass "
            "the buffer to factory to get a new HeKit with the same Key");
      default:
        YACL_THROW("Unsupported content type '{}', please check", item_ct);
    }
  }
};

}  // namespace heu::spi
