# BFV Homomorphic Encryption Library

This directory contains an experimental BFV (Brakerski-Fan-Vercauteren)
implementation focused on SecretFlow HEU integration and integer homomorphic
workloads. The stack is BFV-first rather than a generic multi-scheme framework,
and the README below is written to match the current code, tests, demos, and
benchmarks in `heu/experimental/bfv`.

## Current Highlights

*   **RNS-native BFV runtime**: The core ciphertext/plaintext/key paths are built
    around RNS arithmetic to avoid large-integer hot paths.
*   **Performance-oriented math backend**: The tree contains AVX2-specialized
    fast paths on x86_64, along with portable code paths for the rest of the
    arithmetic stack.
*   **Planning and integration utilities**: `BfvParamAdvisor`,
    `KeysetPlanner`, `BfvDeploymentPlanner`, and `BulkSerializer` are part of
    the repository rather than external glue code.
*   **Runnable validation entry points**: End-to-end demos live in
    [`examples/README.md`](examples/README.md), and benchmark targets live under
    `benchmark/`.

---

## Module Architecture

The implementation is organized into three layers so the arithmetic backend,
cryptographic objects, and planning utilities can evolve somewhat
independently.

### 1. Math Backend (`math/`)
This layer owns modular arithmetic, polynomial representations, and basis /
context transfer.
*   **Modular arithmetic and primes**: `modulus.*`, `biguint.*`, `primes.*`,
    and `prime_search.*` provide scalar modular operations, Shoup helpers, and
    modulus selection support.
*   **Polynomial and NTT machinery**: `poly*`, `representation.*`, `ntt*`, and
    `poly_transform.cc` implement polynomial storage, representation changes,
    NTT transforms, and automorphisms.
*   **RNS contexts and transfer planning**: `rns_context.*`,
    `scaling_factor.*`, `base_converter.*`, `basis_mapper.*`,
    `context_transfer.*`, `basis_transfer_route.*`, and
    `residue_transfer_engine.h` / `rns_scaler.cc` handle residue transfer,
    context dropping, and batched remapping.

### 2. Cryptographic Core (`crypto/`)
This layer implements BFV objects, keys, serialization, and homomorphic
building blocks.
*   **Primitives**: `Ciphertext`, `Plaintext`, `SecretKey`, `PublicKey`,
    `EvaluationKey`, `RelinearizationKey`, `GaloisKey`, `KeySwitchingKey`, and
    the experimental `RGSWCiphertext`.
*   **Key generation and transforms**: Key builders and key-derived operations
    live alongside the BFV objects instead of in a separate evaluator class.
*   **Serialization**: Per-object msgpack serialization exists for the BFV
    objects, and `BulkSerializer` adds batch-oriented bundling for integration
    paths that move multiple objects together.

### 3. Operations and Planning (`crypto/` + `util/`)
This layer contains the user-facing BFV workflow helpers.
*   **Arithmetic operators**: `operators.h` provides overloaded BFV arithmetic
    for ciphertext/plaintext combinations.
*   **`Multiplicator`**: Explicit ciphertext-ciphertext multiplication planning
    with configurable scaling, extended bases, relinearization, and optional
    modulus switching.
*   **Planning utilities**: `BfvParamAdvisor`, `KeysetPlanner`,
    `BfvDeploymentPlanner`, and `BackendAutotuner` connect workload hints to
    parameter selection, keyset planning, and heuristic backend recommendations.

---

## What Differentiates This BFV Stack

This implementation is intentionally optimized for a narrower goal: a BFV-first
backend with planning, transfer, and integration hooks aimed at SecretFlow HEU
style integer homomorphic workloads.

### Architectural Differentiators

*   **BFV-first architecture for HEU**: The codebase is centered on BFV runtime
    flows, parameter chains, basis remapping, relinearization, and automorphism
    support instead of trying to unify multiple schemes behind one generic
    evaluator model. The high-level math API also speaks in HEU-native terms
    such as `remap_to_context`, `remap_to_basis`, `drop_to_context`, and
    `apply_automorphism`.
*   **Layered residue-transfer pipeline**: Basis conversion is not treated as a
    single monolithic helper. It is organized as `BasisMapper` /
    `ContextTransfer` over `BasisTransferRoute`, with
    `ResidueTransferEngine` handling backend selection and execution. This split
    keeps crypto code independent from low-level kernels and makes transfer hot
    paths easier to evolve.
*   **Plan/backend decomposition for fast-path optimization**: The transfer
    stack separates planning from execution through dedicated components for
    projection terms, carry windows, decode bridges, and auxiliary-basis
    support. Compared with a one-piece RNS helper, this gives clearer control
    over where precomputation lives and where batch kernels execute.
*   **Batch throughput is a first-class concern**: The transfer engine exposes scalar, polynomial, batch, and multi-polynomial remapping interfaces, and the route layer can bypass shared residue prefixes before invoking the backend. This is a good fit for HEU-style batched ciphertext workflows where mapping cost matters as much as single-call latency.

### Functional Differentiators

*   **Integrated parameter recommendation and validation**: `BfvParamAdvisor` supports operation-profile input (`num_mul`, `num_relin`, `num_rot`), multiple optimization strategies (`kFast`, `kBalanced`, `kSafe`), memory estimates, JSON reports, and `BfvParameters::SelfTest()`. The current advisor can also infer a conservative effective multiplication depth from `num_mul` when `mul_depth` is omitted, while still treating explicit `mul_depth` as the strongest correctness signal.
*   **Early deployment planning workflow**: The repository also includes a
    first-step `BfvDeploymentPlanner` that connects parameter recommendation
    with workload-aware keyset planning. Given plaintext requirements and a
    workload profile, it can produce a deployment-oriented report containing
    parameters, a minimal keyset plan, estimated key/ciphertext memory, a
    heuristic backend recommendation from `BackendAutotuner`, and a
    machine-readable JSON summary for higher-level tooling.
*   **Explicit multiplication planning**: `Multiplicator` is more than a generic "multiply then clean up" helper. It can be configured with custom scaling factors, extended multiplication bases, post-multiplication scaling, and optional relinearization or modulus switching, which gives tighter control over BFV multiplication pipelines.
*   **Selective evaluation-key construction with workload-aware planning**: `EvaluationKeyBuilder` can enable row rotation, specific column rotations, inner sum, and oblivious expansion independently, and `KeysetPlanner` can now derive a minimal keyset plan from either an explicit request or a `WorkloadProfile` with rotation histograms, multiplication counts, batch size, and ciphertext fan-out metadata. This is a concrete step toward workload-driven key planning instead of manually enabling a broad set of capabilities.
*   **Noise and execution observability hooks**: The stack already exposes `SecretKey::measure_noise()` for debugging and validation, and hot paths can emit fine-grained profiling data when profiling is enabled. This makes it easier to inspect why a parameter set or an execution path behaves poorly.
*   **Integration-oriented bulk serialization**: Besides per-object serialization, the library now provides `BulkSerializer` batch APIs for plaintexts, ciphertexts, and the BFV key family (`SecretKey`, `PublicKey`, `EvaluationKey`, `RelinearizationKey`, `GaloisKey`, `KeySwitchingKey`). These bundles embed shared BFV parameters once, attach bundle version/type metadata, validate per-payload checksums, and support arena-backed ciphertext batch deserialization. This is a more realistic transport path for integration than treating every object as a separate message.
*   **Experimental extension path beyond vanilla BFV**: The repository already contains an experimental `RGSWCiphertext` type and external-product support. While this path is not yet presented as production-ready, it provides a concrete starting point for more advanced protocols such as selector-style operations, PIR helpers, and future bootstrapping-oriented work.
*   **Concrete integration and benchmarking hooks**: The repository already contains some operational scaffolding that is directly usable in embedding and performance work: arena-backed scratch allocation (`ArenaHandle::Shared()` / `Create()`), compile-time profiling gates (`--define bfv_profile=1` with `PROFILE_BLOCK(...)` in hot paths), structured single-object and bulk serialization modules, and Bazel targets for focused tests, demos, and benchmarks. This should be read as engineering support for integration and measurement, not as a claim of full production hardening, service orchestration, or mature observability infrastructure.

In short, the differentiation is not only in low-level arithmetic kernels. It is also in deployment-oriented functionality: parameter planning, selective key construction, transfer throughput, observability, and system integration.

---

## Parameter Advisor

Choosing the right cryptographic parameters (polynomial degree, moduli chain) is critical for both security and performance. The **BFV Parameter Advisor** automates this process using advanced heuristics and safety checks.

### Features
*   **Security Guardrail**: Enforces a **128-bit** selection guardrail through
    per-degree `logQ` limits in the advisor.
*   **Profile-Aware Heuristics**: Besides multiplicative depth, you can provide operation counts (`OpProfile`) to refine estimation. The current implementation uses `num_mul` to infer a conservative effective depth when needed and applies sublinear penalties for additional multiplications, relinearizations, and rotations. It is still a heuristic model, not a full circuit analyzer.
*   **Tunable Optimization**: Choose between **Performance** (`kFast`), **Balance** (`kBalanced`), or **Stability** (`kSafe`) strategies.
*   **Active Verification**: Includes `SelfTest` functionality to mathematically verify that generated parameters work correctly before use.
*   **Guardrails**: Prevents the selection of insecure or invalid parameters (e.g., non-NTT-friendly moduli).

### Usage

#### 1. Basic (Depth-based)
For simple use cases where you know the circuit depth:

```cpp
#include "heu/experimental/bfv/util/bfv_param_advisor.h"

// Define requirements
crypto::bfv::ParamAdvisorRequest req;
req.plaintext_nbits = 20;   // Data size
req.mul_depth = 2;          // Computation depth

// Get secure parameters
auto result = crypto::bfv::BfvParamAdvisor::Recommend(req);
```

#### 2. Advanced (Profile-based)
For optimized parameters tuned to your specific circuit:

```cpp
crypto::bfv::ParamAdvisorRequest req;
req.plaintext_nbits = 20;
req.strategy = crypto::bfv::OptimizationStrategy::kSafe; // Conservative margins

// Define operation counts
req.op_profile = {
    .num_mul = 8,
    .num_relin = 4,
    .num_rot = 12
};
// Optional: set req.mul_depth if you know the critical-path depth.
// If omitted, the advisor will infer a conservative effective depth from num_mul.

auto result = crypto::bfv::BfvParamAdvisor::Recommend(req);

// verify parameters are usable
if (!result.params->SelfTest()) {
    throw std::runtime_error("Generated parameters failed self-test");
}

std::cout << result.report.ToJson() << std::endl;
```

---

## Core API Usage

While the Parameter Advisor handles setup, here is how to use the core BFV objects for encryption and computation.

### Batch Serialization

For integration paths that move multiple BFV objects together, use
`BulkSerializer` instead of serializing each object independently:

```cpp
#include "heu/experimental/bfv/crypto/bulk_serialization.h"

std::vector<crypto::bfv::Ciphertext> ciphertexts = {ct0, ct1, ct2};
auto bundle =
    crypto::bfv::BulkSerializer::SerializeCiphertexts(ciphertexts);

auto restored = crypto::bfv::BulkSerializer::DeserializeCiphertexts(
    bundle, params, ::bfv::util::ArenaHandle::Shared());

std::vector<crypto::bfv::EvaluationKey> evaluation_keys = {evk0, evk1};
auto eval_bundle =
    crypto::bfv::BulkSerializer::SerializeEvaluationKeys(evaluation_keys);
auto restored_eval =
    crypto::bfv::BulkSerializer::DeserializeEvaluationKeys(eval_bundle, params);

std::vector<crypto::bfv::PublicKey> public_keys = {pk0, pk1};
auto public_bundle =
    crypto::bfv::BulkSerializer::SerializePublicKeys(public_keys);
auto restored_public =
    crypto::bfv::BulkSerializer::DeserializePublicKeys(public_bundle, params);
```

The bundle carries the shared BFV parameters once, records a schema version and
object-type tag, and validates each payload during deserialization.

### 1. Key Generation

```cpp
#include "heu/experimental/bfv/crypto/bfv_parameters.h"
#include "heu/experimental/bfv/crypto/secret_key.h"
#include "heu/experimental/bfv/crypto/public_key.h"
#include "heu/experimental/bfv/crypto/relinearization_key.h"
#include "heu/experimental/bfv/crypto/evaluation_key.h"

// Assume 'params' is obtained via BfvParamAdvisor or constructed manually
std::shared_ptr<BfvParameters> params = ...;
std::mt19937_64 rng(std::random_device{}());

// 1. Secret Key (the root of trust)
auto sk = SecretKey::random(params, rng);

// 2. Public Key (for encryption)
auto pk = PublicKey::from_secret_key(sk, rng);

// 3. Relinearization Key (for reducing ciphertext size after multiplication)
auto rk = RelinearizationKey::from_secret_key(sk, rng);

// 4. Evaluation Key (for row/column rotations, inner sums, expansion)
// Here we enable row rotation support.
auto evk = EvaluationKeyBuilder::create(sk).enable_row_rotation().build(rng);
```

### 2. Encoding & Encryption

BFV works on vectors of integers. We use `SIMD` encoding to pack multiple integers into a single ciphertext.

```cpp
#include "heu/experimental/bfv/crypto/plaintext.h"
#include "heu/experimental/bfv/crypto/encoding.h"

// Initialize SIMD encoder
// level 0 means encoding for fresh ciphertexts (max noise budget)
auto encoding = Encoding::simd_at_level(0);

// Prepare data: a vector of items
std::vector<uint64_t> data = {1, 2, 3, 4, 5};

// Encode to Plaintext
auto pt = Plaintext::encode(data, encoding, params);

// Encrypt to Ciphertext
auto ct = pk.encrypt(pt, rng);
```

### 3. Homomorphic Operations

Standard operators are overloaded for intuitive usage.

```cpp
#include "heu/experimental/bfv/crypto/operators.h"

// Addition
auto ct_sum = ct1 + ct2;
auto ct_inc = ct1 + pt1; // Ciphertext + Plaintext

// Multiplication
auto ct_prod = ct1 * ct2;

// Relinearization (Required after multiplication to keep ciphertext size constant)
// ct_prod usually has 3 components; relinearization reduces it back to 2.
rk.relinearize(ct_prod);

// Rotation (Shift data slots within the vector)
// Rotate rows by 1 step
auto ct_rot = evk.rotates_rows(ct1);
```

### 4. Decryption

```cpp
// Decrypt
Plaintext pt_res;
sk.decrypt(ct_sum, pt_res);

// Decode back to vector
auto res_vec = pt_res.decode_uint64(encoding);

std::cout << "Result[0]: " << res_vec[0] << std::endl;
```

---

## Directory Structure

```text
heu/experimental/bfv/
├── benchmark/          # Microbenchmarks and BFV-vs-SEAL comparison
├── crypto/             # BFV objects, operators, keys, serialization, tests
│   ├── serialization/  # Msgpack adaptors and serialization exceptions
│   └── test/           # Crypto-focused unit tests
├── examples/           # Runnable demos for differentiating features
├── math/               # Arithmetic, NTT, RNS transfer, basis/context remap
└── util/               # Advisors, deployment planning, profiling utilities
```

## Quick Start

### Running Tests
To verify the implementation and the parameter advisor:

```bash
bazel test //heu/experimental/bfv/...
```

### Operational Hooks

The current codebase already exposes a few concrete engineering hooks that are
useful in integration and performance work:

*   **Arena-backed allocation**: `ArenaHandle::Shared()` and
    `ArenaHandle::Create()` provide 64-byte-aligned scratch allocation with a
    thread-local cache. This path is used in polynomial storage, basis
    remapping, ciphertext deserialization, and `BulkSerializer` batch decode.
*   **Compile-time profiling**: Profiling is gated by Bazel
    `--define bfv_profile=1`. Hot paths such as decryption, multiplication, and
    relinearization already contain `PROFILE_BLOCK(...)` instrumentation.
*   **Bazel-native operational targets**: The tree already includes focused
    `cc_test` targets, runnable demos under `examples/`, and benchmark targets
    under `benchmark/`.

Representative commands:

```bash
# Focused serialization / crypto round-trip checks
bazel test //heu/experimental/bfv:crypto_test \
  --test_arg=--gtest_filter=PublicKeyTest.SerializationRoundTrip:SecretKeyTest.SerializationPlaceholders:EvaluationKeyTest.SerializationRoundTrip:RelinearizationKeyTest.SerializationRoundTrip:GaloisKeyTest.SerializationRoundTrip:KeySwitchingKeyTest.Serialization

# Runnable end-to-end demo for data + key-family bulk serialization
bazel run //heu/experimental/bfv:bulk_serialization_demo

# Enable compile-time profiling and print collected timing blocks from the
# BFV-vs-SEAL benchmark target
bazel run --define bfv_profile=1 //heu/experimental/bfv:bfv_benchmark
```

These hooks make the stack easier to profile and embed, but they are still
developer-facing mechanisms. They do not yet amount to a full deployment
runtime, automatic telemetry pipeline, or hardened service packaging story.
