#pragma once

#include <vector>
#include "heu/library/algorithms/paillier_zahlen/ciphertext.h"
#include "heu/library/algorithms/paillier_zahlen/public_key.h"
#include "heu/library/algorithms/paillier_zahlen/secret_key.h"
#include "heu/library/algorithms/util/spi_traits.h"

namespace heu::lib::algorithms::paillier_z {

class PublicKey;
class SecretKey;
class Ciphertext;

class CGBNWrapper {
    public:
        static void Encrypt(const MPInt m, const PublicKey pk, MPInt &rn, Ciphertext &ct);
        static void Encrypt(absl::Span<const Plaintext> pts, const PublicKey pk, std::vector<MPInt> &rns, std::vector<Ciphertext> &cts);
        static void Decrypt(const Ciphertext& ct, const SecretKey sk, const PublicKey pk, MPInt* out);
        static void Decrypt(absl::Span<const Ciphertext>& cts, const SecretKey sk, const PublicKey pk, absl::Span<Plaintext>* pts);
        static void DevMalloc(PublicKey *pk);
        static void DevMalloc(SecretKey *sk);
        static void DevFree(PublicKey *pk);
        static void DevFree(SecretKey *sk);
        static void StoreToDev(PublicKey *pk);
        static void StoreToDev(SecretKey *sk);
//        static void Add(const Ciphertext& a, const Ciphertext& b, Ciphertext& c);
};

} // namespace heu::lib::algorithms::paillier_z