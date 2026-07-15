#pragma once

#include <array>
#include <cstdint>
#include <random>
#include <type_traits>
#include <utility>

namespace crypto {
namespace bfv {
namespace detail {

template <typename RNG>
std::mt19937_64 MakeMt19937_64(RNG &rng) {
  std::array<uint32_t, 16> seed_words{};
  for (size_t i = 0; i < seed_words.size(); i += 2) {
    const uint64_t word = static_cast<uint64_t>(rng());
    seed_words[i] = static_cast<uint32_t>(word);
    seed_words[i + 1] = static_cast<uint32_t>(word >> 32);
  }
  std::seed_seq seed(seed_words.begin(), seed_words.end());
  return std::mt19937_64(seed);
}

template <typename RNG, typename Fn>
decltype(auto) WithMt19937_64(RNG &rng, Fn &&fn) {
  if constexpr (std::is_same_v<std::decay_t<RNG>, std::mt19937_64>) {
    return std::forward<Fn>(fn)(rng);
  } else {
    auto bridged_rng = MakeMt19937_64(rng);
    return std::forward<Fn>(fn)(bridged_rng);
  }
}

}  // namespace detail
}  // namespace bfv
}  // namespace crypto
