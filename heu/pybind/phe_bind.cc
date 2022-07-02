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

#include <pybind11/operators.h>
#include <pybind11/pybind11.h>

#include <utility>

#include "yasl/base/exception.h"

#include "heu/library/phe/encoding/encoding.h"
#include "heu/library/phe/phe.h"

namespace heu::pybind {

namespace py = ::pybind11;
namespace phe = ::heu::lib::phe;

// const PyObject values
const static auto kPyObjValue64 =
    py::reinterpret_steal<py::object>(PyLong_FromLong(64));
const static auto kPyObjUint64Mask = py::reinterpret_steal<py::object>(
    PyLong_FromUnsignedLongLong(~uint64_t{0}));

template <typename T>
decltype(auto) PickleSupport() {
  return py::pickle(
      [](const T& obj) {  // __getstate__
        auto buffer = obj.Serialize();
        return py::bytes(buffer.template data<char>(), buffer.size());
      },
      [](const py::bytes& buffer) {  // __setstate__
        T obj;
        obj.Deserialize(static_cast<std::string_view>(buffer));
        return obj;
      });
}

// py::int_ -> int128_t
// return value 1: the int128 value
// return value 2: is overflow (p is larger than int128)
std::tuple<int128_t, bool> PyIntToCppInt128(const py::int_& p) {
  // ref python c api: https://docs.python.org/3/c-api/long.html
  int is_overflow;
  int64_t n64 = PyLong_AsLongLongAndOverflow(p.ptr(), &is_overflow);
  if (is_overflow == 0) {
    return {n64, false};
  }

  auto lo_obj = py::reinterpret_steal<py::object>(
      PyNumber_And(p.ptr(), kPyObjUint64Mask.ptr()));
  auto lo = PyLong_AsUnsignedLongLong(lo_obj.ptr());

  auto hi_obj = py::reinterpret_steal<py::object>(
      PyNumber_Rshift(p.ptr(), kPyObjValue64.ptr()));
  auto hi = PyLong_AsLongLongAndOverflow(hi_obj.ptr(), &is_overflow);

  return {yasl::MakeInt128(hi, lo), is_overflow};
}

// int128_t -> py::int_
py::int_ CppInt128ToPyInt(int128_t num_128) {
  auto hi_obj = py::reinterpret_steal<py::object>(
      PyLong_FromLongLong(static_cast<int64_t>(
          static_cast<uint64_t>(static_cast<uint128_t>(num_128) >> 64))));
  auto hi = py::reinterpret_steal<py::object>(
      PyNumber_Lshift(hi_obj.ptr(), kPyObjValue64.ptr()));
  auto lo = py::reinterpret_steal<py::object>(PyLong_FromUnsignedLongLong(
      static_cast<uint64_t>(num_128 & ~uint64_t{0})));

  return py::reinterpret_steal<py::int_>(PyNumber_Add(hi.ptr(), lo.ptr()));
}

// py::int_ -> phe::Plaintext
// no bit size limit
phe::Plaintext PyIntToPlaintext(const py::int_& p) {
  auto [v, overflow] = PyIntToCppInt128(p);
  return overflow ? phe::Plaintext(py::str(static_cast<py::object>(p)), 10)
                  : phe::Plaintext(v);
}

// phe::Plaintext -> py::int_
// no bit size limit
py::int_ PlaintextToPyInt(const phe::Plaintext& mp) {
  if (mp.BitCount() < 64) {  // Up to 63bit regardless of sign bit
    return {mp.As<int64_t>()};
  }

  if (mp.BitCount() < 127) {
    return CppInt128ToPyInt(mp.As<int128_t>());
  }

  return py::reinterpret_steal<py::int_>(
      PyLong_FromString(mp.ToHexString().c_str(), nullptr, 16));
}

void BindPhe(pybind11::module& m) {
  m.doc() = "A high-performance partial homomorphic encryption library";
  py::register_local_exception<yasl::Exception>(m, "PheRuntimeError",
                                                PyExc_RuntimeError);

  /****** Basic types ******/
  py::enum_<phe::SchemaType>(m, "SchemaType")
      .value("None", phe::SchemaType::None)
      .value("ZPaillier", phe::SchemaType::ZPaillier)
      .value("FPaillier", phe::SchemaType::FPaillier)
      .export_values();

  py::class_<phe::Plaintext>(m, "Plaintext")
      .def(py::init([](const py::int_& p) { return PyIntToPlaintext(p); }),
           "Create a plaintext from int without bit size limit")
      .def(py::init<double>(), "Create a plaintext from float")
      .def(py::pickle(
          [](const phe::Plaintext& obj) {  // __getstate__
            std::string buffer;
            obj.Serialize(&buffer);
            return py::bytes(buffer);
          },
          [](const py::bytes& buffer) {  // __setstate__
            phe::Plaintext obj;
            YASL_ENFORCE(phe::Plaintext::Deserialize(buffer, &obj),
                         "Plaintext deserialize fail");
            return obj;
          }))
      .def(py::self + py::self)
      .def(py::self - py::self)
      .def(py::self * py::self)
      .def(py::self / py::self)
      .def(py::self % py::self)
      .def(py::self += py::self)
      .def(py::self -= py::self)
      .def(py::self *= py::self)
      .def(py::self /= py::self)
      .def(py::self %= py::self)
      .def(py::self < py::self)
      .def(py::self > py::self)
      .def(py::self <= py::self)
      .def(py::self >= py::self)
      .def(py::self == py::self)
      .def(py::self != py::self)
      .def(
          "__int__",
          [](const phe::Plaintext& mp) { return PlaintextToPyInt(mp); },
          "Convert to python int without bit size limit")
      .def("__str__", [](const phe::Plaintext& mp) { return mp.ToString(); })
      .def("__repr__", [](const phe::Plaintext& mp) {
        return fmt::format("Plaintext({})", mp.ToString());
      });

  py::class_<phe::Ciphertext>(m, "Ciphertext", py::module_local())
      .def("__str__", [](const phe::Ciphertext& ct) { return ct.ToString(); })
      .def(PickleSupport<phe::Ciphertext>());

  /****** key management ******/
  py::class_<phe::PublicKey, std::shared_ptr<phe::PublicKey>>(
      m, "PublicKey", py::module_local())
      .def("__str__", [](const phe::PublicKey& pk) { return pk.ToString(); })
      .def(PickleSupport<phe::PublicKey>())
      .def("plaintext_bound", &phe::PublicKey::PlaintextBound,
           "Get max_int, so valid plaintext range is (max_int, -max_int)");
  py::class_<phe::SecretKey, std::shared_ptr<phe::SecretKey>>(
      m, "SecretKey", py::module_local())
      .def("__str__", [](const phe::SecretKey& sk) { return sk.ToString(); })
      .def(PickleSupport<phe::SecretKey>());

  py::class_<phe::HeKit>(m, "HeKit", py::module_local())
      .def("public_key", &phe::HeKit::GetPublicKey, "Get public key")
      .def("secret_key", &phe::HeKit::GetSecretKey, "Get secret key")
      .def("encryptor", &phe::HeKit::GetEncryptor, "Get encryptor")
      .def("decryptor", &phe::HeKit::GetDecryptor, "Get decryptor")
      .def("evaluator", &phe::HeKit::GetEvaluator, "Get evaluator");

  m.def(
      "setup",
      [](phe::SchemaType schema_type, size_t key_size) {
        phe::HeKit ahe;
        ahe.Setup(schema_type, key_size);
        return ahe;
      },
      py::arg("schema_type") = phe::SchemaType::ZPaillier, py::arg("key_size") = 2048,
      py::return_value_policy::move,
      "Setup phe environment by schema type and key size");

  m.def(
      "setup",
      [](const std::string& schema_string, size_t key_size) {
        phe::HeKit ahe;
        ahe.Setup(phe::ParseSchemaType(schema_string), key_size);
        return ahe;
      },
      py::arg("schema_string") = "z-paillier", py::arg("key_size") = 2048,
      py::return_value_policy::move,
      "Setup phe environment by schema string and key size");

  py::class_<phe::DestinationHeKit>(m, "DestinationHeKit", py::module_local())
      .def("public_key", &phe::DestinationHeKit::GetPublicKey, "Get public key")
      .def("encryptor", &phe::DestinationHeKit::GetEncryptor, "Get encryptor")
      .def("evaluator", &phe::DestinationHeKit::GetEvaluator, "Get evaluator");

  m.def(
      "setup",
      [](std::shared_ptr<phe::PublicKey> pk) {
        phe::DestinationHeKit ahe;
        ahe.Setup(std::move(pk));
        return ahe;
      },
      py::arg("public_key"), py::return_value_policy::move,
      "Setup phe environment by already generated public key");

  /****** encoding ******/
  py::class_<phe::PlainEncoder>(m, "PlainEncoder", py::module_local())
      .def(py::init<int64_t>(), py::arg("scale"))
      .def(py::init<>(), "Create a plain encoder using default scale")
      .def("__str__", [](const phe::PlainEncoder& pe) { return pe.ToString(); })
      .def(
          "encode",
          [](const heu::lib::phe::PlainEncoder& pe, double p) {
            return pe.Encode(p);
          },
          py::arg("cleartext"), "Encode a float number into plaintext")
      .def(
          "encode",
          [](const heu::lib::phe::PlainEncoder& pe, const py::int_& p) {
            return pe.Encode(std::get<0>(PyIntToCppInt128(p)));
          },
          py::arg("cleartext"), "Encode an int128 number into plaintext")
      .def(
          "decode",
          [](const heu::lib::phe::PlainEncoder& pe, const phe::Plaintext& mp) {
            return pe.Decode<double>(mp);
          },
          py::arg("plaintext"), "Decode plaintext to float number")
      .def(
          "decode_int",
          [](const heu::lib::phe::PlainEncoder& pe, const phe::Plaintext& mp) {
            if (mp.BitCount() < 64) {  // Up to 63bit regardless of sign bit
              return py::int_(pe.Decode<int64_t>(mp));
            }

            return CppInt128ToPyInt(pe.Decode<int128_t>(mp));
          },
          py::arg("plaintext"), "Decode plaintext to int128 number")
      .def(PickleSupport<phe::PlainEncoder>());

  py::class_<phe::BatchEncoder>(m, "BatchEncoder", py::module_local())
      .def(py::init<size_t>(), py::arg("padding_size") = 32)
      .def("__str__", [](const phe::BatchEncoder& bn) { return bn.ToString(); })
      .def(
          "encode",
          [](const heu::lib::phe::BatchEncoder& bn, int64_t a, int64_t b) {
            return bn.Encode(a, b);
          },
          py::arg("cleartext_1"), py::arg("cleartext_2"),
          "Batch encode two cleartexts into one plaintext")
      .def(
          "decode",
          [](const heu::lib::phe::BatchEncoder& bn, const phe::Plaintext& mp) {
            return py::make_tuple(bn.Get<int64_t, 0>(mp),
                                  bn.Get<int64_t, 1>(mp));
          },
          py::arg("plaintext"), "Decode plaintext and return two cleartexts")
      .def(PickleSupport<phe::BatchEncoder>());

  /****** encryption ******/
  py::class_<phe::Encryptor, std::shared_ptr<phe::Encryptor>>(
      m, "Encryptor", py::module_local())
      .def("encrypt", &phe::Encryptor::Encrypt, py::arg("plaintext"),
           "Encrypt plaintext to ciphertext")
      .def(
          "encrypt_raw",
          [](const phe::Encryptor& encryptor, const py::int_& num) {
            return encryptor.Encrypt(PyIntToPlaintext(num));
          },
          py::arg("cleartext"), "Encrypt without encoding")
      .def("encrypt_with_audit", &phe::Encryptor::EncryptWithAudit,
           py::arg("plaintext"),
           "Encrypt and build audit string include plaintext/random/ciphertex");

  /****** decryption ******/
  py::class_<phe::Decryptor, std::shared_ptr<phe::Decryptor>>(
      m, "Decryptor", py::module_local())
      .def("decrypt",
           py::overload_cast<const phe::Ciphertext&>(&phe::Decryptor::Decrypt,
                                                     py::const_),
           py::arg("ciphertext"), "Decrypt ciphertext to plaintext")
      .def(
          "decrypt_raw",
          [](const phe::Decryptor& decryptor, const phe::Ciphertext& ct) {
            return PlaintextToPyInt(decryptor.Decrypt(ct));
          },
          py::arg("ciphertext"), "Decrypt without decoding");

  /****** evaluation ******/
  py::class_<phe::Evaluator, std::shared_ptr<phe::Evaluator>>(
      m, "Evaluator", py::module_local())
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

PYBIND11_MODULE(phe, m) { BindPhe(m); }

}  // namespace heu::pybind
