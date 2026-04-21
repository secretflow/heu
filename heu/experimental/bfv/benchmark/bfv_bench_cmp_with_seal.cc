#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <numeric>
#include <random>
#include <string>
#include <vector>
#ifdef __linux__
#include <sched.h>
#include <unistd.h>
#endif

// Our BFV headers
#include "crypto/bfv_parameters.h"
#include "crypto/ciphertext.h"
#include "crypto/encoding.h"
#include "crypto/evaluation_key.h"
#include "crypto/galois_key.h"
#include "crypto/operators.h"
#include "crypto/plaintext.h"
#include "crypto/public_key.h"
#include "crypto/relinearization_key.h"
#include "crypto/secret_key.h"
#include "math/residue_transfer_engine.h"
#include "util/profiler.h"

// SEAL
#include <seal/seal.h>
using namespace crypto::bfv;

using namespace std;
using namespace crypto;

// Simple timer and stats utilities
class Timer {
 public:
  void reset() { start_ = chrono::steady_clock::now(); }

  double elapsed_us() const {
    auto end = chrono::steady_clock::now();
    auto duration = end - start_;
    // Use steady_clock which is monotonic and won't go backwards
    return chrono::duration_cast<chrono::nanoseconds>(duration).count() /
           1000.0;
  }

 private:
  chrono::steady_clock::time_point start_ = chrono::steady_clock::now();
};

struct Stats {
  vector<double> xs;

  void add(double v) { xs.push_back(v); }

  double mean() const {
    if (xs.empty()) return 0.0;
    return accumulate(xs.begin(), xs.end(), 0.0) / xs.size();
  }

  double min() const {
    return xs.empty() ? 0.0 : *min_element(xs.begin(), xs.end());
  }

  double max() const {
    return xs.empty() ? 0.0 : *max_element(xs.begin(), xs.end());
  }

  double median() const {
    if (xs.empty()) return 0.0;
    auto v = xs;
    sort(v.begin(), v.end());
    size_t n = v.size();
    return (n % 2) ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2.0;
  }
};

struct ParamConfig {
  size_t degree;
  vector<int> coeff_bits;
  uint64_t plain_modulus;
  size_t vector_size;
  const char *name;
};

static Stats run_bench(function<void()> f, int iters = 100) {
  constexpr int kWarmupIters = 5;
  for (int i = 0; i < kWarmupIters; ++i) {
    try {
      f();
    } catch (const std::exception &e) {
      cerr << "Warmup failed: " << e.what() << endl;
      throw;
    }
  }

  Timer t;
  Stats s;
  for (int i = 0; i < iters; ++i) {
    try {
      t.reset();
      f();
      double elapsed = t.elapsed_us();
      if (elapsed < 0) {
        cerr << "Warning: negative elapsed time: " << elapsed << " us" << endl;
        continue;  // Skip this measurement
      }
      s.add(elapsed);
    } catch (const std::exception &e) {
      cerr << "Iteration " << i << " failed: " << e.what() << endl;
      // Continue with next iteration
    }
  }
  return s;
}

static void maybe_pin_benchmark_cpu() {
#ifdef __linux__
  const char *env = std::getenv("HEU_BFV_BENCH_CPU");
  int cpu = 0;
  if (env && env[0] != '\0') {
    cpu = std::atoi(env);
    if (cpu < 0) {
      return;
    }
  }

  cpu_set_t cpu_set;
  CPU_ZERO(&cpu_set);
  CPU_SET(cpu, &cpu_set);
  (void)sched_setaffinity(0, sizeof(cpu_set), &cpu_set);
#endif
}

static void print_row(const string &op, const string &params_desc, double ours,
                      double seal) {
  cout << fixed << setprecision(2);
  cout << left << setw(24) << op << left << setw(18) << params_desc << right
       << setw(12) << ours << " us" << right << setw(14) << seal << " us"
       << right << setw(14) << (ours > 0.0 ? seal / ours : 0.0)
       << "x (SEAL/Our)\n";
}

static bool bench_print_moduli_enabled() {
  const char *env = std::getenv("HEU_BFV_BENCH_PRINT_MODULI");
  return env && env[0] != '\0' && env[0] != '0';
}

static void print_moduli_once(const seal::SEALContext &sctx,
                              const shared_ptr<BfvParameters> &params,
                              const char *name) {
  if (!bench_print_moduli_enabled()) {
    return;
  }

  const auto &seal_moduli = sctx.key_context_data()->parms().coeff_modulus();
  cout << "CoeffModulus[" << name << "]\n";
  cout << "  our :";
  for (uint64_t q : params->moduli()) {
    cout << ' ' << q;
  }
  cout << "\n";
  cout << "  seal:";
  for (const auto &q : seal_moduli) {
    cout << ' ' << q.value();
  }
  cout << "\n";
}

int main() {
  try {
    maybe_pin_benchmark_cpu();

    vector<ParamConfig> configs = {
        {8192, {60, 50, 50, 58}, 1032193, 16, "n=8192,logq~218,vec=16"},
    };

    cout << "BFV Performance Comparison (Our vs SEAL)" << endl;
    cout << string(90, '=') << endl;
    cout << left << setw(24) << "Operation" << left << setw(18) << "Params"
         << right << setw(12) << "Our (μs)" << right << setw(14) << "SEAL (μs)"
         << right << setw(16) << "Speedup" << "\n";
    cout << string(94, '-') << "\n";

    // Global RNGs for reproducibility
    std::mt19937_64 rng(12345);

    for (const auto &pc : configs) {
      // 1) SEAL parameter construction
      seal::EncryptionParameters sp(seal::scheme_type::bfv);
      sp.set_poly_modulus_degree(pc.degree);
      sp.set_coeff_modulus(
          seal::CoeffModulus::Create(pc.degree, pc.coeff_bits));
      sp.set_plain_modulus(pc.plain_modulus);
      seal::SEALContext sctx(sp);

      // 2) Our BFV parameters
      BfvParametersBuilder builder;
      builder.set_degree(pc.degree)
          .set_plaintext_modulus(pc.plain_modulus)
          .set_moduli_sizes(
              vector<size_t>(pc.coeff_bits.begin(), pc.coeff_bits.end()));
      auto params = builder.build_arc();
      print_moduli_once(sctx, params, pc.name);

      // SEAL components
      seal::KeyGenerator s_keygen(sctx);
      auto s_sk = s_keygen.secret_key();
      seal::PublicKey s_pk;
      s_keygen.create_public_key(s_pk);
      seal::RelinKeys s_rk;
      s_keygen.create_relin_keys(s_rk);
      seal::Encryptor s_encryptor(sctx, s_pk);
      seal::Evaluator s_evaluator(sctx);
      seal::Decryptor s_decryptor(sctx, s_sk);
      seal::BatchEncoder s_batch(sctx);

      // Prepare data vectors
      vector<uint64_t> v1(pc.vector_size, 1);
      vector<uint64_t> v2(pc.vector_size, 2);

      // Use SIMD encoding
      auto encoding = Encoding::simd_at_level(0);
      auto our_pt1 = Plaintext::encode(v1, encoding, params);
      auto our_pt2 = Plaintext::encode(v2, encoding, params);

      // For SEAL, pad vectors to slot_count for BatchEncoder
      size_t slot_count = s_batch.slot_count();
      vector<uint64_t> v1_padded(slot_count, 0);
      vector<uint64_t> v2_padded(slot_count, 0);
      copy(v1.begin(), v1.end(), v1_padded.begin());
      copy(v2.begin(), v2.end(), v2_padded.begin());

      seal::Plaintext s_pt1, s_pt2;
      s_batch.encode(v1_padded, s_pt1);
      s_batch.encode(v2_padded, s_pt2);

      // Key Generation benchmark
      auto st_keygen_our = run_bench(
          [&]() {
            auto sk = SecretKey::random(params, rng);
            auto pk = PublicKey::from_secret_key(sk, rng);
            (void)pk;
          },
          10);  // Reduced iterations for stability
      auto st_keygen_seal = run_bench(
          [&]() {
            seal::KeyGenerator keygen(sctx);
            auto sk = keygen.secret_key();
            seal::PublicKey pk;
            keygen.create_public_key(pk);
            (void)sk;
          },
          10);
      print_row("Key Generation", pc.name, st_keygen_our.mean(),
                st_keygen_seal.mean());

      // Our BFV components for encryption/decryption tests
      auto our_sk = SecretKey::random(params, rng);
      auto our_pk = PublicKey::from_secret_key(our_sk, rng);

      // Encryption benchmark
      auto st_enc_our = run_bench(
          [&]() {
            auto ct = our_pk.encrypt(our_pt1, rng);
            (void)ct;
          },
          50);  // Reduced iterations
      auto st_enc_seal = run_bench(
          [&]() {
            seal::Ciphertext ct;
            s_encryptor.encrypt(s_pt1, ct);
          },
          50);
      print_row("Encryption", pc.name, st_enc_our.mean(), st_enc_seal.mean());

      // Prepare ciphertexts for other operations
      auto our_ct1 = our_pk.encrypt(our_pt1, rng);
      auto our_ct2 = our_pk.encrypt(our_pt2, rng);
      seal::Ciphertext s_ct1, s_ct2;
      s_encryptor.encrypt(s_pt1, s_ct1);
      s_encryptor.encrypt(s_pt2, s_ct2);

      // Decryption benchmark
      Plaintext our_dec_out;
      seal::Plaintext s_dec_out;
      auto st_dec_our = run_bench(
          [&]() {
            our_sk.decrypt(our_ct1, our_dec_out);
            (void)our_dec_out;
          },
          50);  // Reduced iterations
      auto st_dec_seal =
          run_bench([&]() { s_decryptor.decrypt(s_ct1, s_dec_out); }, 50);
      print_row("Decryption", pc.name, st_dec_our.mean(), st_dec_seal.mean());

      // Addition benchmark
      auto st_add_our = run_bench(
          [&]() {
            auto r = our_ct1 + our_ct2;
            (void)r;
          },
          100);  // Keep 100 for fast operations
      auto st_add_seal = run_bench(
          [&]() {
            seal::Ciphertext r;
            s_evaluator.add(s_ct1, s_ct2, r);
          },
          100);
      print_row("Addition", pc.name, st_add_our.mean(), st_add_seal.mean());

      // ==========================================
      // Key Generation Benchmarks & Setup
      // ==========================================

      // Relinearization Key Generation benchmark
      auto st_rk_gen_our = run_bench(
          [&]() { RelinearizationKey::from_secret_key(our_sk, rng); }, 10);
      auto st_rk_gen_seal = run_bench(
          [&]() {
            seal::RelinKeys rk;
            s_keygen.create_relin_keys(rk);
          },
          10);
      print_row("Relin Key Gen", pc.name, st_rk_gen_our.mean(),
                st_rk_gen_seal.mean());

      // Galois Key Generation benchmark
      auto st_gk_gen_our = run_bench(
          [&]() {
            auto builder = EvaluationKeyBuilder::create(our_sk);
            builder.enable_column_rotation(1);
            builder.build(rng);
          },
          50);
      auto st_gk_gen_seal = run_bench(
          [&]() {
            seal::GaloisKeys gk;
            std::vector<uint32_t> elts = {static_cast<uint32_t>(3)};
            s_keygen.create_galois_keys(elts, gk);
          },
          50);
      print_row("Galois Key Gen", pc.name, st_gk_gen_our.mean(),
                st_gk_gen_seal.mean());

      // Generate keys for usage in Op benchmarks
      auto our_rk = RelinearizationKey::from_secret_key(our_sk, rng);
      auto our_evk =
          EvaluationKeyBuilder::create(our_sk).enable_column_rotation(1).build(
              rng);
      seal::GaloisKeys s_gk;
      s_keygen.create_galois_keys(
          std::vector<uint32_t>{static_cast<uint32_t>(3)}, s_gk);

      // ==========================================
      // Operation Benchmarks
      // ==========================================

      // Multiplication (No Relin) - Pure tensor product check
      auto st_mul_norelin_our = run_bench(
          [&]() {
            auto r = our_ct1 * our_ct2;
            (void)r;
          },
          10);
      auto st_mul_norelin_seal = run_bench(
          [&]() {
            seal::Ciphertext r;
            s_evaluator.multiply(s_ct1, s_ct2, r);
          },
          10);
      print_row("Multiply (No Relin)", pc.name, st_mul_norelin_our.mean(),
                st_mul_norelin_seal.mean());

      // Multiplication (Mul + Relin) - Full multiplication
      auto st_mul_relin_our = run_bench(
          [&]() {
            auto r = our_ct1 * our_ct2;
            our_rk.relinearize(r);
          },
          30);
      auto st_mul_relin_seal = run_bench(
          [&]() {
            seal::Ciphertext r;
            s_evaluator.multiply(s_ct1, s_ct2, r);
            s_evaluator.relinearize_inplace(r, s_rk);
          },
          30);
      print_row("Multiply (Mul+Relin)", pc.name, st_mul_relin_our.mean(),
                st_mul_relin_seal.mean());

      // Relinearization benchmark (isolated)
      // Note: Needs a degree-2 ciphertext.
      auto our_ct_mul = our_ct1 * our_ct2;  // degree 2
      seal::Ciphertext s_ct_mul;
      s_evaluator.multiply(s_ct1, s_ct2, s_ct_mul);  // degree 2

      auto st_relin_our = run_bench(
          [&]() {
            auto res = our_rk.relinearize_new(our_ct_mul);
            (void)res;
          },
          50);
      auto st_relin_seal = run_bench(
          [&]() {
            seal::Ciphertext res;
            s_evaluator.relinearize(s_ct_mul, s_rk, res);
          },
          50);
      print_row("Relinearization", pc.name, st_relin_our.mean(),
                st_relin_seal.mean());

      // Rotation benchmark
      // Rotate rows by 1
      auto st_rot_our = run_bench(
          [&]() {
            auto res = our_evk.rotates_columns_by(our_ct1, 1);
            (void)res;
          },
          50);
      auto st_rot_seal = run_bench(
          [&]() {
            seal::Ciphertext res;
            s_evaluator.rotate_rows(s_ct1, 1, s_gk, res);
          },
          50);
      print_row("Rotation (Rows)", pc.name, st_rot_our.mean(),
                st_rot_seal.mean());

      // Optional: verify correctness (not timed)
      {
        auto r_our = our_sk.decrypt(our_ct1 + our_ct2).decode_uint64(encoding);
        seal::Ciphertext s_sum;
        s_evaluator.add(s_ct1, s_ct2, s_sum);
        seal::Plaintext s_dec;
        s_decryptor.decrypt(s_sum, s_dec);
        vector<uint64_t> v_dec;
        s_batch.decode(s_dec, v_dec);
        if (!v_dec.empty() && !r_our.empty()) {
          cout << "    Check[" << pc.name << "] sample slot: our=" << r_our[0]
               << ", seal=" << v_dec[0] << " (expected=3)\n";
        }
      }
    }

    cout << string(90, '=') << endl;
    cout << "Parameters:" << endl;
    cout << "- Polynomial degree: 8192" << endl;
    cout << "- Plain modulus: 1032193" << endl;
    cout << "- Coeff modulus bits: [60, 50, 50, 58]" << endl;
    cout << "- Vector size: 16" << endl;
    cout << "Done." << endl;
    crypto::bfv::Profiler::Get().Print();
    crypto::bfv::Profiler::Get().Clear();

    return 0;
  } catch (const std::exception &e) {
    cerr << "Exception: " << e.what() << endl;
    return 1;
  }
}
