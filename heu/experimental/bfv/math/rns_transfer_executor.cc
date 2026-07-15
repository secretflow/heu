#include "math/rns_transfer_executor.h"

// Execution entry points for residue-transfer are intentionally split across
// focused kernel files:
//   - rns_scalar_transfer_kernel.cc
//   - rns_batch_transfer_kernel.cc
//
// This translation unit remains as the stable module anchor for the executor
// interface.
