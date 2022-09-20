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

#include "pybind11/operators.h"
#include "pybind11/pybind11.h"
#include "yasl/base/exception.h"

#include "heu/pylib/common/py_encoders.h"

namespace heu::pylib {

namespace py = ::pybind11;
namespace phe = ::heu::lib::phe;

void PyBindPhe(pybind11::module& m) {
  py::register_local_exception<yasl::Exception>(m, "PheRuntimeError",
                                                PyExc_RuntimeError);

  /****** Basic types ******/
  py::enum_<phe::SchemaType>(m, "SchemaType")
      .value("Mock", phe::SchemaType::None, "No encryption, only for debugging")
      .value("ZPaillier", phe::SchemaType::ZPaillier)
      .value("FPaillier", phe::SchemaType::FPaillier)
      .export_values();

  py::class_<phe::Plaintext>(m, "Plaintext")
      .def(py::init(
               [](const py::int_& p) { return PyUtils::PyIntToPlaintext(p); }),
           "Create a plaintext from int without bit size limit")
      .def(py::init<double>(), "Create a plaintext from float")
      .def(PyUtils::PickleSupport<phe::Plaintext>())
      .def(-py::self)
      .def(py::self + py::self)
      .def(py::self - py::self)
      .def(py::self * py::self)
      .def(py::self / py::self)
      .def(py::self % py::self)
      .def(py::self >> size_t())
      .def(py::self << size_t())
      .def(py::self += py::self)
      .def(py::self -= py::self)
      .def(py::self *= py::self)
      .def(py::self /= py::self)
      .def(py::self %= py::self)
      .def(py::self >>= size_t())
      .def(py::self <<= size_t())
      .def(py::self < py::self)
      .def(py::self > py::self)
      .def(py::self <= py::self)
      .def(py::self >= py::self)
      .def(py::self == py::self)
      .def(py::self != py::self)
      .def(
          "__int__",
          [](const phe::Plaintext& mp) {
            return PyUtils::PlaintextToPyInt(mp);
          },
          "Convert to python int without bit size limit")
      .def("__str__", [](const phe::Plaintext& mp) { return mp.ToString(); })
      .def("__repr__",
           [](const phe::Plaintext& mp) {
             return fmt::format("Plaintext({})", mp.ToString());
           })
      .def(
          "to_bytes",
          [](const phe::Plaintext& pt, size_t length,
             const std::string& byteorder) {
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
      .def("__str__", [](const phe::Ciphertext& ct) { return ct.ToString(); })
      .def(PyUtils::PickleSupport<phe::Ciphertext>());

  /****** key management ******/
  py::class_<phe::PublicKey, std::shared_ptr<phe::PublicKey>>(m, "PublicKey")
      .def("__str__", [](const phe::PublicKey& pk) { return pk.ToString(); })
      .def(PyUtils::PickleSupport<phe::PublicKey>())
      .def("plaintext_bound", &phe::PublicKey::PlaintextBound,
           "Get max_int, so valid plaintext range is (max_int, -max_int)");
  py::class_<phe::SecretKey, std::shared_ptr<phe::SecretKey>>(m, "SecretKey")
      .def("__str__", [](const phe::SecretKey& sk) { return sk.ToString(); })
      .def(PyUtils::PickleSupport<phe::SecretKey>());

  // api for sk_keeper party
  py::class_<phe::HeKit>(m, "HeKit")
      .def("public_key", &phe::HeKit::GetPublicKey, "Get public key")
      .def("secret_key", &phe::HeKit::GetSecretKey, "Get secret key")
      .def("encryptor", &phe::HeKit::GetEncryptor, "Get encryptor")
      .def("decryptor", &phe::HeKit::GetDecryptor, "Get decryptor")
      .def("evaluator", &phe::HeKit::GetEvaluator, "Get evaluator");

  m.def(
      "setup",
      [](phe::SchemaType schema_type, size_t key_size) {
        phe::HeKit ahe(schema_type, key_size);
        return ahe;
      },
      py::arg("schema_type") = phe::SchemaType::ZPaillier,
      py::arg("key_size") = 2048, py::return_value_policy::move,
      "Setup phe environment by schema type and key size");

  m.def(
      "setup",
      [](const std::string& schema_string, size_t key_size) {
        phe::HeKit ahe(phe::ParseSchemaType(schema_string), key_size);
        return ahe;
      },
      py::arg("schema_string") = "z-paillier", py::arg("key_size") = 2048,
      py::return_value_policy::move,
      "Setup phe environment by schema string and key size");

  // api for evaluator party
  py::class_<phe::DestinationHeKit>(m, "DestinationHeKit")
      .def("public_key", &phe::DestinationHeKit::GetPublicKey, "Get public key")
      .def("encryptor", &phe::DestinationHeKit::GetEncryptor, "Get encryptor")
      .def("evaluator", &phe::DestinationHeKit::GetEvaluator, "Get evaluator");

  m.def(
      "setup",
      [](std::shared_ptr<phe::PublicKey> pk) {
        phe::DestinationHeKit ahe(std::move(pk));
        return ahe;
      },
      py::arg("public_key"), py::return_value_policy::move,
      "Setup phe environment by an already generated public key");

  /****** encryption ******/
  py::class_<phe::Encryptor, std::shared_ptr<phe::Encryptor>>(m, "Encryptor")
      .def("encrypt", &phe::Encryptor::Encrypt, py::arg("plaintext"),
           "Encrypt plaintext to ciphertext")
      .def(
          "encrypt_raw",
          [](const phe::Encryptor& encryptor, const py::int_& num) {
            return encryptor.Encrypt(PyUtils::PyIntToPlaintext(num));
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
           py::overload_cast<const phe::Ciphertext&>(&phe::Decryptor::Decrypt,
                                                     py::const_),
           py::arg("ciphertext"), "Decrypt ciphertext to plaintext")
      .def(
          "decrypt_raw",
          [](const phe::Decryptor& decryptor, const phe::Ciphertext& ct) {
            return PyUtils::PlaintextToPyInt(decryptor.Decrypt(ct));
          },
          py::arg("ciphertext"),
          "Decrypt and decoding. The decoding behavior is similar to "
          "BigintEncoder");

  /****** evaluation ******/
  py::class_<phe::Evaluator, std::shared_ptr<phe::Evaluator>>(m, "Evaluator")
      .def("add",
           py::overload_cast<const phe::Ciphertext&, const phe::Plaintext&>(
               &phe::Evaluator::Add, py::const_))
      .def("add",
           py::overload_cast<const phe::Plaintext&, const phe::Ciphertext&>(
               &phe::Evaluator::Add, py::const_))
      .def("add",
           py::overload_cast<const phe::Ciphertext&, const phe::Ciphertext&>(
               &phe::Evaluator::Add, py::const_))
      .def("add_inplace",
           py::overload_cast<phe::Ciphertext*, const phe::Plaintext&>(
               &phe::Evaluator::AddInplace, py::const_))
      .def("add_inplace",
           py::overload_cast<phe::Ciphertext*, const phe::Ciphertext&>(
               &phe::Evaluator::AddInplace, py::const_))

      .def("sub",
           py::overload_cast<const phe::Ciphertext&, const phe::Plaintext&>(
               &phe::Evaluator::Sub, py::const_))
      .def("sub",
           py::overload_cast<const phe::Plaintext&, const phe::Ciphertext&>(
               &phe::Evaluator::Sub, py::const_))
      .def("sub",
           py::overload_cast<const phe::Ciphertext&, const phe::Ciphertext&>(
               &phe::Evaluator::Sub, py::const_))
      .def("sub_inplace",
           py::overload_cast<phe::Ciphertext*, const phe::Plaintext&>(
               &phe::Evaluator::SubInplace, py::const_))
      .def("sub_inplace",
           py::overload_cast<phe::Ciphertext*, const phe::Ciphertext&>(
               &phe::Evaluator::SubInplace, py::const_))

      .def(
          "mul",
          [](const phe::Evaluator& evaluator, const phe::Ciphertext& ct,
             int64_t p) -> phe::Ciphertext {
            return evaluator.Mul(ct, phe::Plaintext(p));
          },
          py::arg("ciphertext"), py::arg("times"))
      .def(
          "mul",
          [](const phe::Evaluator& evaluator, int64_t p,
             const phe::Ciphertext& ct) -> phe::Ciphertext {
            return evaluator.Mul(phe::Plaintext(p), ct);
          },
          py::arg("ciphertext"), py::arg("times"))
      .def(
          "mul_inplace",
          [](const phe::Evaluator& evaluator, phe::Ciphertext* ct, int64_t p) {
            evaluator.MulInplace(ct, phe::Plaintext(p));
          },
          py::arg("ciphertext"), py::arg("times"))

      .def("negate", py::overload_cast<const phe::Ciphertext&>(
                         &phe::Evaluator::Negate, py::const_))
      .def("negate_inplace", py::overload_cast<phe::Ciphertext*>(
                                 &phe::Evaluator::NegateInplace, py::const_));
}
}  // namespace heu::pylib
