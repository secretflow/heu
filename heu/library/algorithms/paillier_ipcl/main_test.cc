
#include <iostream>

#include "heu/library/algorithms/paillier_ipcl/ipcl.h"
#include "heu/library/algorithms/paillier_ipcl/utils.h"
#include "heu/library/algorithms/util/spi_traits.h"

// tmp
#include "ipcl/ipcl.hpp"
// tmp
using namespace heu::lib::algorithms::paillier_ipcl;
using namespace heu::lib::algorithms;

int main(int argc, char* argv[]) {
  // int key_size = 1024;
  // SecretKey seckey;
  // PublicKey pubkey;
  // KeyGenerator::Generate(key_size, &seckey, &pubkey);
  // Encryptor enc = Encryptor(pubkey);
  // Decryptor dec = Decryptor(pubkey, seckey);
  // Evaluator eval = Evaluator(pubkey);

  // auto buffer = pubkey.Serialize();
  // PublicKey des_key;
  // yacl::ByteContainerView buf_view(buffer);
  // std::cout << buffer << std::endl;
  // des_key.Deserialize(buf_view);
  // std::cout << pubkey.ToString() << std::endl;
  // std::cout << des_key.ToString() << std::endl;
  int64_t a2 = -123456789123456789;
  Plaintext pt2;
  pt2.Set<int64_t>(a2);
  int64_t b2 = pt2.Get<int64_t>();
  std::cout << b2 << std::endl;
  return 0;
}
