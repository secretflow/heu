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

#include "heu/pylib/phe_binding/bind_phe.h"

#include "fmt/compile.h"
#include "pybind11/operators.h"
#include "pybind11/pybind11.h"
#include "yacl/base/exception.h"

#include "heu/library/phe/base/key_def.h"
#include "heu/pylib/common/py_utils.h"
#include "heu/pylib/phe_binding/py_encoders.h"

namespace heu::pylib {

namespace py = ::pybind11;
namespace phe = ::heu::lib::phe;

void PyBindPhe(pybind11::module &m) {
  py::register_local_exception<yacl::Exception>(m, "PheRuntimeError",
                                                PyExc_RuntimeError);

  /****** Basic types ******/
  auto st_bind = py::enum_<phe::SchemaType>(m, "SchemaType");
  for (const auto &schema : phe::GetAllSchema()) {
    st_bind.value(phe::SchemaToString(schema).c_str(), schema);
  }
  st_bind.export_values();
  m.def("parse_schema_type", &phe::ParseSchemaType,
        "Parse schema string. (string -> SchemaType)");

  py::class_<phe::Plaintext>(m, "Plaintext")
      .def(py::init([](const phe::SchemaType &schema_type, const py::int_ &p) {
             return PyUtils::PyIntToPlaintext(schema_type, p);
           }),
           py::arg("schema"), py::arg("int_num"),
           "Create a plaintext from int without bit size limit")
      .def(PyUtils::PickleSupport<phe::Plaintext>())
      .def(-py::self)
      .def(py::self + py::self)
      .def(py::self - py::self)
      .def(py::self * py::self)
      .def(py::self / py::self)
      .def(py::self % py::self)
      .def(py::self & py::self)
      .def(py::self | py::self)
      .def(py::self ^ py::self)
      .def(py::self >> size_t())
      .def(py::self << size_t())
      .def(py::self += py::self)
      .def(py::self -= py::self)
      .def(py::self *= py::self)
      .def(py::self /= py::self)
      .def(py::self %= py::self)
      .def(py::self &= py::self)
      .def(py::self |= py::self)
      .def(py::self ^= py::self)
      .def(py::self >>= size_t())
      .def(py::self <<= size_t())
      .def(py::self < py::self)
      .def(py::self > py::self)
      .def(py::self <= py::self)
      .def(py::self >= py::self)
      .def(py::self == py::self)
      .def(py::self != py::self)
      .def("is_compatible", &phe::Plaintext::IsCompatible,
           "Is this plaintext compatible with schema type 'x'")
      .def("bit_count", &phe::Plaintext::BitCount, "Bit size of this plaintext")
      .def(
          "__int__",
          [](const phe::Plaintext &mp) {
            return PyUtils::PlaintextToPyInt(mp);
          },
          "Convert to python int without bit size limit")
      .def("__index__",  // PEP3100: use __index__ in oct() and hex() instead.
           [](const phe::Plaintext &mp) {
             return PyUtils::PlaintextToPyInt(mp);
           })
      .def("__str__", [](const phe::Plaintext &mp) { return mp.ToString(); })
      .def("__repr__",
           [](const phe::Plaintext &mp) {
             return fmt::format(FMT_COMPILE("Plaintext({})"), mp.ToString());
           })
      .def(
          "to_bytes",
          [](const phe::Plaintext &pt, size_t length,
             const std::string &byteorder) {
            auto buf = pt.ToBytes(length, PyUtils::PyEndianToCpp(byteorder));
            return py::bytes(buf.data<char>(), buf.size());  // this is a copy
          },
          py::arg("length"), py::arg("byteorder"),
          "Return an array of bytes representing an integer.\n\nThe byteorder "
          "argument determines the byte order used to represent the integer. "
          "If byteorder is \"big\", the most significant byte is at the "
          "beginning of the byte array. If byteorder is \"little\", the most "
          "significant byte is at the end of the byte array. To request the "
          "native byte order of the host system, use sys.byteorder as the byte "
          "order value.");

  py::class_<phe::Ciphertext>(m, "Ciphertext")
      .def("__str__", [](const phe::Ciphertext &ct) { return ct.ToString(); })
      .def(PyUtils::PickleSupport<phe::Ciphertext>());

  /****** key management ******/
  py::class_<phe::PublicKey, std::shared_ptr<phe::PublicKey>>(m, "PublicKey")
      .def("__str__", [](const phe::PublicKey &pk) { return pk.ToString(); })
      .def(PyUtils::PickleSupport<phe::PublicKey>())
      .def("plaintext_bound", &phe::PublicKey::PlaintextBound,
           "Get max_int, so valid plaintext range is [max_int_, -max_int_]")
      .def(
          "serialize",
          [](const phe::PublicKey &pk) {
            auto buffer = pk.Serialize();
            return pybind11::bytes(buffer.template data<char>(), buffer.size());
          },
          "serialize public key to bytes")
      .def_static(
          "load_from",
          [](const pybind11::bytes &buffer) {
            phe::PublicKey pk;
            pk.Deserialize(static_cast<std::string_view>(buffer));
            return pk;
          },
          py::arg("bytes_buffer"), "deserialize matrix from bytes");
  py::class_<phe::SecretKey, std::shared_ptr<phe::SecretKey>>(m, "SecretKey")
      .def("__str__", [](const phe::SecretKey &sk) { return sk.ToString(); })
      .def(PyUtils::PickleSupport<phe::SecretKey>());

  /****** He kit ******/
  py::class_<phe::HeKitPublicBase>(m, "HeKitPublicBase")
      .def("public_key", &phe::HeKitPublicBase::GetPublicKey, "Get public key")
      .def("get_schema", &phe::HeKitPublicBase::GetSchemaType,
           "Get schema type")
      .def(
          "batch_integer_encoder",
          [](const phe::HeKitPublicBase &kpb, int64_t scale,
             size_t padding_bits) {
            return PyBatchIntegerEncoder(kpb.GetSchemaType(), scale,
                                         padding_bits);
          },
          py::arg("scale") = 1, py::arg("padding_bits") = 32,
          "Get an instance of BatchIntegerEncoder, equal to "
          "`phe.BatchIntegerEncoder(schema, scale, padding_size)`")
      .def(
          "batch_float_encoder",
          [](const phe::HeKitPublicBase &kpb, int64_t scale,
             size_t padding_bits) {
            return PyBatchFloatEncoder(kpb.GetSchemaType(), scale,
                                       padding_bits);
          },
          py::arg("scale") = (int64_t)1e6, py::arg("padding_bits") = 32,
          "Get an instance of BatchIntegerEncoder, equal to "
          "`phe.BatchFloatEncoder(schema, scale, padding_size)`")
      .def(
          "bigint_encoder",
          [](const phe::HeKitPublicBase &kpb) {
            return PyBigintEncoder(kpb.GetSchemaType());
          },
          "Get an instance of BigintEncoder, equal to "
          "`phe.BigintEncoder(schema)`")
      .def(
          "float_encoder",
          [](const phe::HeKitPublicBase &kpb, int64_t scale) {
            return PyFloatEncoder(kpb.GetSchemaType(), scale);
          },
          py::arg("scale") = (int64_t)1e6,
          "Get an instance of FloatEncoder, equal to `phe.FloatEncoder(schema, "
          "scale)`")
      .def(
          "integer_encoder",
          [](const phe::HeKitPublicBase &kpb, int64_t scale) {
            return PyIntegerEncoder(kpb.GetSchemaType(), scale);
          },
          py::arg("scale") = (int64_t)1e6,
          "Get an instance of IntegerEncoder, equal to "
          "`phe.IntegerEncoder(schema, scale)`")
      .def(
          "plaintext",
          [](const phe::HeKitPublicBase &kpb, const py::int_ &p) {
            return PyUtils::PyIntToPlaintext(kpb.GetSchemaType(), p);
          },
          py::arg("int_num"),
          "Create a plaintext from int without bit size limit, equal to "
          "heu.phe.Plaintext(schema, int_num)");

  py::class_<phe::HeKitSecretBase, phe::HeKitPublicBase>(m, "HeKitSecretBase")
      .def("secret_key", &phe::HeKit::GetSecretKey, "Get secret key");

  py::class_<phe::HeKit, phe::HeKitSecretBase>(m, "HeKit")
      .def("encryptor", &phe::HeKit::GetEncryptor, "Get encryptor")
      .def("decryptor", &phe::HeKit::GetDecryptor, "Get decryptor")
      .def("evaluator", &phe::HeKit::GetEvaluator, "Get evaluator");

  m.def(
      "setup",
      [](phe::SchemaType schema_type, size_t key_size) -> phe::HeKit {
        return {schema_type, key_size};
      },
      py::arg("schema_type"), py::arg("key_size"),
      py::return_value_policy::move,
      "Setup phe environment by schema type and key size");

  m.def(
      "setup",
      [](const std::string &schema_string, size_t key_size) -> phe::HeKit {
        return {phe::ParseSchemaType(schema_string), key_size};
      },
      py::arg("schema_string"), py::arg("key_size"),
      py::return_value_policy::move,
      "Setup phe environment by schema string and key size");

  m.def(
      "setup",
      [](phe::SchemaType schema_type) { return phe::HeKit(schema_type); },
      py::arg("schema_type") = phe::SchemaType::ZPaillier,
      py::return_value_policy::move, "Setup phe environment by schema type");

  m.def(
      "setup",
      [](const std::string &schema_string) -> phe::HeKit {
        return phe::HeKit(phe::ParseSchemaType(schema_string));
      },
      py::arg("schema_string") = "z-paillier", py::return_value_policy::move,
      "Setup phe environment by schema string");

  m.def(
      "setup",
      [](std::shared_ptr<phe::PublicKey> pk, std::shared_ptr<phe::SecretKey> sk)
          -> phe::HeKit { return phe::HeKit(std::move(pk), std::move(sk)); },
      py::arg("public_key"), py::arg("secret_key"),
      py::return_value_policy::move,
      "Setup phe environment by pre-generated pk and sk");

  // api for evaluator party
  py::class_<phe::DestinationHeKit, phe::HeKitPublicBase>(m, "DestinationHeKit")
      .def("encryptor", &phe::DestinationHeKit::GetEncryptor, "Get encryptor")
      .def("evaluator", &phe::DestinationHeKit::GetEvaluator, "Get evaluator");

  m.def(
      "setup",
      [](std::shared_ptr<phe::PublicKey> pk) {
        return phe::DestinationHeKit(std::move(pk));
      },
      py::arg("public_key"), py::return_value_policy::move,
      "Setup phe environment by an already generated public key");

  /****** encryption ******/
  py::class_<phe::Encryptor, std::shared_ptr<phe::Encryptor>>(m, "Encryptor")
      .def("encrypt", &phe::Encryptor::Encrypt, py::arg("plaintext"),
           "Encrypt plaintext to ciphertext")
      .def(
          "encrypt_raw",
          [](const phe::Encryptor &encryptor, const py::int_ &num) {
            return encryptor.Encrypt(
                PyUtils::PyIntToPlaintext(encryptor.GetSchemaType(), num));
          },
          py::arg("cleartext"),
          "Encode and encrypt an integer cleartext. The encoding behavior is "
          "similar to BigintEncoder")
      .def("encrypt_with_audit", &phe::Encryptor::EncryptWithAudit,
           py::arg("plaintext"),
           "Encrypt and build audit string including "
           "plaintext/random/ciphertext");

  /****** decryption ******/
  py::class_<phe::Decryptor, std::shared_ptr<phe::Decryptor>>(m, "Decryptor")
      .def("decrypt",
           py::overload_cast<const phe::Ciphertext &>(&phe::Decryptor::Decrypt,
                                                      py::const_),
           py::arg("ciphertext"), "Decrypt ciphertext to plaintext")
      .def("decrypt_in_range", &phe::Decryptor::DecryptInRange,
           py::arg("ciphertext"), py::arg("range_bits") = 128,
           "Decrypt ciphertext and make sure plaintext is in range "
           "(-2^range_bits, 2^range_bits). Range checking is used to block OU "
           "plaintext overflow attack, see HEU documentation for details.\n"
           "throws an exception if plaintext is out of range.")
      .def(
          "decrypt_raw",
          [](const phe::Decryptor &decryptor, const phe::Ciphertext &ct) {
            return PyUtils::PlaintextToPyInt(decryptor.Decrypt(ct));
          },
          py::arg("ciphertext"),
          "Decrypt and decoding. The decoding behavior is similar to "
          "BigintEncoder");

  /****** evaluation ******/
  py::class_<phe::Evaluator, std::shared_ptr<phe::Evaluator>>(m, "Evaluator")
      .def("add",
           py::overload_cast<const phe::Ciphertext &, const phe::Plaintext &>(
               &phe::Evaluator::Add, py::const_))
      .def("add",
           py::overload_cast<const phe::Plaintext &, const phe::Ciphertext &>(
               &phe::Evaluator::Add, py::const_))
      .def("add",
           py::overload_cast<const phe::Ciphertext &, const phe::Ciphertext &>(
               &phe::Evaluator::Add, py::const_))
      .def("add_inplace",
           py::overload_cast<phe::Ciphertext *, const phe::Plaintext &>(
               &phe::Evaluator::AddInplace, py::const_))
      .def("add_inplace",
           py::overload_cast<phe::Ciphertext *, const phe::Ciphertext &>(
               &phe::Evaluator::AddInplace, py::const_))

      .def("sub",
           py::overload_cast<const phe::Ciphertext &, const phe::Plaintext &>(
               &phe::Evaluator::Sub, py::const_))
      .def("sub",
           py::overload_cast<const phe::Plaintext &, const phe::Ciphertext &>(
               &phe::Evaluator::Sub, py::const_))
      .def("sub",
           py::overload_cast<const phe::Ciphertext &, const phe::Ciphertext &>(
               &phe::Evaluator::Sub, py::const_))
      .def("sub_inplace",
           py::overload_cast<phe::Ciphertext *, const phe::Plaintext &>(
               &phe::Evaluator::SubInplace, py::const_))
      .def("sub_inplace",
           py::overload_cast<phe::Ciphertext *, const phe::Ciphertext &>(
               &phe::Evaluator::SubInplace, py::const_))

      .def(
          "mul",
          [](const phe::Evaluator &evaluator, const phe::Ciphertext &ct,
             int64_t p) -> phe::Ciphertext {
            return evaluator.Mul(ct,
                                 phe::Plaintext(evaluator.GetSchemaType(), p));
          },
          py::arg("ciphertext"), py::arg("times"))
      .def(
          "mul",
          [](const phe::Evaluator &evaluator, int64_t p,
             const phe::Ciphertext &ct) -> phe::Ciphertext {
            return evaluator.Mul(phe::Plaintext(evaluator.GetSchemaType(), p),
                                 ct);
          },
          py::arg("ciphertext"), py::arg("times"))
      .def(
          "mul_inplace",
          [](const phe::Evaluator &evaluator, phe::Ciphertext *ct, int64_t p) {
            evaluator.MulInplace(ct,
                                 phe::Plaintext(evaluator.GetSchemaType(), p));
          },
          py::arg("ciphertext"), py::arg("times"))

      .def("negate", py::overload_cast<const phe::Ciphertext &>(
                         &phe::Evaluator::Negate, py::const_))
      .def("negate_inplace", py::overload_cast<phe::Ciphertext *>(
                                 &phe::Evaluator::NegateInplace, py::const_));
}
}  // namespace heu::pylib
