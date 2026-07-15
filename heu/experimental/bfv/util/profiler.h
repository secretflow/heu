#pragma once

#include <chrono>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <string>
#include <vector>

namespace crypto {
namespace bfv {

class Profiler {
 public:
  static Profiler &Get() {
    static Profiler instance;
    return instance;
  }

  void Start(const std::string &name) {
    starts_[name] = std::chrono::steady_clock::now();
  }

  void Stop(const std::string &name) {
    auto end = std::chrono::steady_clock::now();
    auto start = starts_[name];
    double us =
        std::chrono::duration_cast<std::chrono::nanoseconds>(end - start)
            .count() /
        1000.0;
    records_[name].push_back(us);
  }

  void Print() {
    std::cout << "\nFine-grained Profiling Results:\n";
    std::cout << std::string(80, '-') << "\n";
    std::cout << std::left << std::setw(30) << "Block Name" << std::right
              << std::setw(15) << "Calls" << std::setw(15) << "Total (us)"
              << std::setw(15) << "Mean (us)\n";
    std::cout << std::string(80, '-') << "\n";

    for (const auto &kv : records_) {
      double total = std::accumulate(kv.second.begin(), kv.second.end(), 0.0);
      double mean = total / kv.second.size();
      std::cout << std::left << std::setw(30) << kv.first << std::right
                << std::setw(15) << kv.second.size() << std::setw(15)
                << std::fixed << std::setprecision(2) << total << std::setw(15)
                << mean << "\n";
    }
  }

  void Clear() {
    starts_.clear();
    records_.clear();
  }

 private:
  std::map<std::string, std::chrono::steady_clock::time_point> starts_;
  std::map<std::string, std::vector<double>> records_;
};

class ProfilerScope {
 public:
  ProfilerScope(const std::string &name) : name_(name) {
    Profiler::Get().Start(name_);
  }

  ~ProfilerScope() { Profiler::Get().Stop(name_); }

 private:
  std::string name_;
};

#if defined(ENABLE_PROFILER) && ENABLE_PROFILER
#define PROFILE_BLOCK(name) ProfilerScope profiler_scope_##__LINE__(name)
#define PROFILE_START(name) Profiler::Get().Start(name)
#define PROFILE_STOP(name) Profiler::Get().Stop(name)
#else
#define PROFILE_BLOCK(name)
#define PROFILE_START(name)
#define PROFILE_STOP(name)
#endif

}  // namespace bfv
}  // namespace crypto
