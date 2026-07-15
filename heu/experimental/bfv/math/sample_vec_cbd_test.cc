#include "sample_vec_cbd.h"

#include <gtest/gtest.h>

#include <random>

using namespace bfv::math::utils;

double variance(const std::vector<int64_t> &values) {
  if (values.size() < 2) {
    throw std::invalid_argument("Length of values must be >= 2");
  }

  double mean = 0.0;
  for (int64_t val : values) {
    mean += static_cast<double>(val);
  }
  mean /= static_cast<double>(values.size());

  double sum_sq_diff = 0.0;
  for (int64_t val : values) {
    double diff = static_cast<double>(val) - mean;
    sum_sq_diff += diff * diff;
  }

  return sum_sq_diff / (static_cast<double>(values.size()) - 1.0);
}

TEST(SampleVecCbdTest, ErrorCases) {
  std::mt19937_64 rng;

  EXPECT_THROW(sample_vec_cbd(10, 0, rng), std::invalid_argument);

  EXPECT_THROW(sample_vec_cbd(10, 17, rng), std::invalid_argument);
}

TEST(SampleVecCbdTest, BasicProperties) {
  std::mt19937_64 rng;

  for (size_t var = 1; var <= 16; ++var) {
    for (size_t size = 0; size <= 100; ++size) {
      auto v = sample_vec_cbd(size, var, rng);
      EXPECT_EQ(v.size(), size);
    }

    auto v = sample_vec_cbd(100000, var, rng);

    int64_t max_abs = 0;
    for (int64_t val : v) {
      max_abs = std::max(max_abs, std::abs(val));
    }
    EXPECT_LE(max_abs, 2 * static_cast<int64_t>(var));

    double computed_variance = variance(v);
    EXPECT_NEAR(std::round(computed_variance), static_cast<double>(var), 0.1);
  }
}
