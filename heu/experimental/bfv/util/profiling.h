#ifndef PULSAR_UTIL_PROFILING_H
#define PULSAR_UTIL_PROFILING_H

#include <atomic>

namespace bfv {
namespace util {

struct Profiling {
  static std::atomic<uint64_t> g_ntt_forward_count;
  static std::atomic<uint64_t> g_ntt_backward_count;
  static std::atomic<uint64_t> g_rns_scale_count;
  static std::atomic<uint64_t> g_mem_pool_alloc_count;

  static void Reset() {
    g_ntt_forward_count = 0;
    g_ntt_backward_count = 0;
    g_rns_scale_count = 0;
    g_mem_pool_alloc_count = 0;
  }
};

}  // namespace util
}  // namespace bfv

#endif  // PULSAR_UTIL_PROFILING_H
