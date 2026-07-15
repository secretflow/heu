# BFV Examples

This directory contains small runnable demos for the BFV experimental stack.
They are meant to complement the unit tests with user-facing, end-to-end entry
points.

## How to Run

From the repository root:

```bash
bazel run //heu/experimental/bfv:param_advisor_demo
bazel run //heu/experimental/bfv:deployment_planner_demo
bazel run //heu/experimental/bfv:keyset_planner_demo
bazel run //heu/experimental/bfv:multiplicator_demo
bazel run //heu/experimental/bfv:rgsw_demo
bazel run //heu/experimental/bfv:bulk_serialization_demo
```

All demos use fixed RNG seeds so their outputs are deterministic and easy to
compare across runs.

## Demos

### `param_advisor_demo.cc`

What it shows:
- Basic depth-based parameter recommendation.
- Profile-based recommendation using `OpProfile`.
- `SelfTest()` validation of the generated parameter set.
- The inferred/effective multiplicative depth and any advisor warnings.

Typical effect:
- Prints the recommended degree, memory estimates, and a machine-readable JSON
  report.
- In the advanced scenario, the advisor can infer a conservative depth from
  `num_mul` even when `mul_depth` is not provided.

### `deployment_planner_demo.cc`

What it shows:
- End-to-end `BfvDeploymentPlanner` usage.
- Mapping from workload profile to parameters, keyset plan, backend hint, and
  working-set estimates.
- Materializing the suggested evaluation and relinearization keys.
- Executing planned operations after the plan is generated.

Typical effect:
- Prints the deployment summary and JSON report.
- Runs an inner sum and a ciphertext-ciphertext multiplication to confirm the
  plan is actionable.

### `keyset_planner_demo.cc`

What it shows:
- Planning a selective evaluation-key set from both `KeysetRequest` and
  `WorkloadProfile`.
- Building evaluation and relinearization keys from the resulting plan.
- Running representative operations that depend on the selected keys.

Typical effect:
- Prints the minimized keyset summary.
- Demonstrates column rotation, inner sum, and expansion capability checks.

### `multiplicator_demo.cc`

What it shows:
- Default ciphertext multiplication with relinearization.
- Optional modulus switching after multiplication.
- Explicit multiplication planning with a custom extended basis and scaling
  factors.

Typical effect:
- Prints ciphertext size and level for each multiplication mode.
- Verifies the decrypted products match the expected slot-wise products.

### `rgsw_demo.cc`

What it shows:
- Constructing an `RGSWCiphertext`.
- Serialization round-trip for the RGSW object.
- External product between a BFV ciphertext and an RGSW ciphertext.

Typical effect:
- Confirms that serialized/deserialized RGSW ciphertexts remain usable.
- Shows that `ct * rgsw` and `rgsw * ct` decrypt to the same result.

### `bulk_serialization_demo.cc`

What it shows:
- Batch serialization for `Plaintext`, `Ciphertext`, and the full BFV key
  family: `SecretKey`, `PublicKey`, `EvaluationKey`, `RelinearizationKey`,
  `GaloisKey`, and `KeySwitchingKey`.
- Round-trip recovery for multiple objects from a single bundle.
- Arena-backed batch ciphertext deserialization.
- Parameter mismatch detection when a caller supplies the wrong BFV parameters.

Typical effect:
- Prints the serialized bundle sizes for data objects and all key-family
  bundles.
- Verifies that restored plaintexts, decrypted ciphertexts, and restored key
  capabilities match the originals, including encrypt/decrypt and automorphism
  behavior.
- Shows the failure mode when batch data is opened with incompatible
  parameters.

## Notes

- These examples intentionally focus on stable, reproducible API paths already
  covered by tests.
- The RGSW demo reflects the current experimental external-product semantics;
  it is not presented as a drop-in replacement for standard BFV ciphertext
  multiplication.
- The bulk-serialization demo reflects the current batch API scope:
  plaintexts, ciphertexts, and the BFV key family are bundled with shared
  parameters, versioning, and checksum validation, but streaming/chunked
  transport is still out of scope.
