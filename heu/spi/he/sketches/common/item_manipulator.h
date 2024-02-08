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
#include <string>
#include <vector>

#include "yacl/base/buffer.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/utils/spi/sketch/scalar_tools.h"

#include "heu/spi/he/item.h"
#include "heu/spi/he/item_manipulator.h"
#include "heu/spi/he/sketches/common/placeholder.h"

// Suppress the superfluous warnings from clang
#if defined(__clang__)
#pragma clang diagnostic ignored "-Woverloaded-virtual"
#endif

namespace heu::lib::spi {

template <typename PlaintextT, typename CiphertextT, typename SecretKeyT,
          typename PublicKeyT = NoPk, typename RelinKeyT = NoRlk,
          typename GaloisKeyT = NoGlK, typename BootstrapKeyT = NoBsk>
class ItemManipulatorCommon : public ItemManipulator {
 public:
  virtual ~ItemManipulatorCommon() = default;

  //===   Item operations   ===//

  virtual SecretKeyT Clone(const SecretKeyT& key) const = 0;

  virtual PublicKeyT Clone(const PublicKeyT&) const {
    YACL_ENFORCE((std::is_same_v<PublicKeyT, NoPk>),
                 "If you see this message, it means that the subclass misses "
                 "this interface. Please override the Clone(const "
                 "PublicKeyT&) method in the subclass.");
    YACL_THROW("There is no public key in the current setting");
  }

  virtual RelinKeyT Clone(const RelinKeyT&) const {
    YACL_ENFORCE((std::is_same_v<RelinKeyT, NoRlk>),
                 "If you see this message, it means that the subclass misses "
                 "this interface. Please override the Clone(const "
                 "RelinKeyT&) method in the subclass.");
    YACL_THROW("There is no relin key in the current setting");
  }

  virtual GaloisKeyT Clone(const GaloisKeyT&) const {
    YACL_ENFORCE((std::is_same_v<GaloisKeyT, NoGlK>),
                 "If you see this message, it means that the subclass misses "
                 "this interface. Please override the Clone(const "
                 "GaloisKeyT&) method in the subclass.");
    YACL_THROW("There is no galois key in the current setting");
  }

  virtual BootstrapKeyT Clone(const BootstrapKeyT&) const {
    YACL_ENFORCE((std::is_same_v<BootstrapKeyT, NoBsk>),
                 "If you see this message, it means that the subclass misses "
                 "this interface. Please override the Clone(const "
                 "BootstrapKeyT&) method in the subclass.");
    YACL_THROW("There is no bootstrapping key in the current setting");
  }

  // Clone Plaintext/Ciphertext is defined in subclass

  // To human-readable string
  virtual std::string ToString(const SecretKeyT& key) const = 0;

  virtual std::string ToString(const PublicKeyT&) const {
    YACL_ENFORCE((std::is_same_v<PublicKeyT, NoPk>),
                 "If you see this message, it means that the subclass misses "
                 "this interface. Please override the ToString(const "
                 "PublicKeyT&) method in the subclass.");
    YACL_THROW("There is no public key in the current setting");
  }

  virtual std::string ToString(const RelinKeyT&) const {
    YACL_ENFORCE((std::is_same_v<RelinKeyT, NoRlk>),
                 "If you see this message, it means that the subclass misses "
                 "this interface. Please override the ToString(const "
                 "RelinKeyT&) method in the subclass.");
    YACL_THROW("There is no relin key in the current setting");
  }

  virtual std::string ToString(const GaloisKeyT&) const {
    YACL_ENFORCE((std::is_same_v<GaloisKeyT, NoGlK>),
                 "If you see this message, it means that the subclass misses "
                 "this interface. Please override the ToString(const "
                 "GaloisKeyT&) method in the subclass.");
    YACL_THROW("There is no galois key in the current setting");
  }

  virtual std::string ToString(const BootstrapKeyT&) const {
    YACL_ENFORCE((std::is_same_v<BootstrapKeyT, NoBsk>),
                 "If you see this message, it means that the subclass misses "
                 "this interface. Please override the ToString(const "
                 "BootstrapKeyT&) method in the subclass.");
    YACL_THROW("There is no bootstrapping key in the current setting");
  }

  virtual std::string ToString(const PlaintextT& pt) const = 0;
  virtual std::string ToString(const CiphertextT& ct) const = 0;

  //===   I/O for HE Objects   ===//

  // serialize plaintext/ciphertext to already allocated buffer.
  // if buf is nullptr, then calc serialize size only
  // @return: the actual size of serialized buffer
  virtual size_t Serialize(const PlaintextT& pt, uint8_t* buf,
                           size_t buf_len) const = 0;
  virtual size_t Serialize(const CiphertextT& ct, uint8_t* buf,
                           size_t buf_len) const = 0;

  virtual PlaintextT DeserializePT(yacl::ByteContainerView buffer) const = 0;
  virtual CiphertextT DeserializeCT(yacl::ByteContainerView buffer) const = 0;

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

  size_t ItemSize(const heu::lib::spi::Item& item) const override {
    SWITCH_TYPE(item, Size);
  }

  Item SubItem(const Item& item, size_t pos, size_t len) const override {
    SWITCH_TYPE(item, SubItem, pos, len);
  }

  Item SubItem(Item& item, size_t pos, size_t len) const override {
    SWITCH_TYPE(item, SubItem, pos, len);
  }

  Item SubItem(const Item& item, size_t pos) const override {
    SWITCH_TYPE(item, SubItem, pos);
  }

  Item SubItem(Item& item, size_t pos) const override {
    SWITCH_TYPE(item, SubItem, pos);
  }

  void AppendItem(heu::lib::spi::Item*,
                  const heu::lib::spi::Item&) const override {
    // todo
  }

  Item CombineItem(const heu::lib::spi::Item&,
                   const heu::lib::spi::Item&) const override {
    // todo
    YACL_THROW("todo");
  }

  Item Clone(const Item& item) const override {
    switch (item.GetContentType()) {
      case ContentType::SecretKey:
        return {Clone(item.As<SecretKeyT>()), ContentType::SecretKey};
      case ContentType::PublicKey:
        return {Clone(item.As<PublicKeyT>()), ContentType::PublicKey};
      case ContentType::RelinKeys:
        return {Clone(item.As<RelinKeyT>()), ContentType::RelinKeys};
      case ContentType::GaloisKeys:
        return {Clone(item.As<GaloisKeyT>()), ContentType::GaloisKeys};
      case ContentType::BootstrapKey:
        return {Clone(item.As<BootstrapKeyT>()), ContentType::BootstrapKey};
      default:
        YACL_THROW("Unsupported content type '{}', please check",
                   item.GetContentType());
    }
  }

  template <class T>
  std::string CallToString(const Item& item) const {
    if (item.IsArray()) {
      auto xsp = item.AsSpan<T>();
      std::vector<std::string> res;
      res.resize(xsp.length());
      yacl::parallel_for(0, xsp.length(), [&](int64_t beg, int64_t end) {
        for (int64_t i = beg; i < end; ++i) {
          res[i] = ToString(xsp[i]);
        }
      });
      return fmt::format("Array \\{{}\\}", fmt::join(res, ", "));
    } else {
      return ToString(item.As<T>());
    }
  }

  std::string ToString(const Item& item) const override {
    switch (item.GetContentType()) {
      case ContentType::Plaintext:
        return CallToString<PlaintextT>(item);
      case ContentType::Ciphertext:
        return CallToString<CiphertextT>(item);
      case ContentType::SecretKey:
        return ToString(item.As<SecretKeyT>());
      case ContentType::PublicKey:
        return ToString(item.As<PublicKeyT>());
      case ContentType::RelinKeys:
        return ToString(item.As<RelinKeyT>());
      case ContentType::GaloisKeys:
        return ToString(item.As<GaloisKeyT>());
      case ContentType::BootstrapKey:
        return ToString(item.As<BootstrapKeyT>());
      default:
        YACL_THROW("Unsupported content type '{}', please check",
                   item.GetContentType());
    }
  }

  // THE MSGPACK SERIALIZE FORMAT: | 1bytes header | body |
  size_t Serialize(const Item& item, uint8_t* buf,
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

  yacl::Buffer Serialize(const Item& item) const override {
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
      RES_T (ItemManipulatorCommon::*deser_func)(yacl::ByteContainerView)
          const) const {
    msgpack::object_handle msg = msgpack::unpack(
        reinterpret_cast<const char*>(buffer.data()), buffer.size(), offset);

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
        msgpack::unpack(reinterpret_cast<const char*>(buffer.data()),
                        buffer.size(), off, referenced);
    auto obj = header.get();
    YACL_ENFORCE(off == 1 && obj.type == msgpack::type::POSITIVE_INTEGER,
                 "unexpected buffer header. header size={}", off);

    ContentType item_ct = (ContentType)obj.via.i64;
    switch (item_ct) {
      case ContentType::Plaintext:
        return DeserializeBody(item_ct, buffer, off,
                               &ItemManipulatorCommon::DeserializePT);
      case ContentType::Ciphertext:
        return DeserializeBody(item_ct, buffer, off,
                               &ItemManipulatorCommon::DeserializeCT);
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

}  // namespace heu::lib::spi
