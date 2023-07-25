#pragma once
#include "heu/library/algorithms/leichi_paillier/ciphertext.h"
#include "heu/library/algorithms/leichi_paillier/plaintext.h"
#include "heu/library/algorithms/leichi_paillier/public_key.h"
#include "heu/library/algorithms/leichi_paillier/utils.h"
namespace heu::lib::algorithms::leichi_paillier {
        class Encryptor {
            public:
            explicit Encryptor(const PublicKey& pk): pk_(std::move(pk)){max_plaintext = pk.max_plaintext_;}
            std::vector<Ciphertext> EncryptZero(int64_t size) const;
            std::vector<Ciphertext> Encrypt(ConstSpan<Plaintext> pts) const;
            std::pair<std::vector<Ciphertext>, std::vector<std::string>> EncryptWithAudit(
                ConstSpan<Plaintext> pts) const;
         private:
            PublicKey pk_;
            Plaintext max_plaintext;
    };
}
