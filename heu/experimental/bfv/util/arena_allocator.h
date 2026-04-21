#ifndef BFV_UTIL_ARENA_ALLOCATOR_H
#define BFV_UTIL_ARENA_ALLOCATOR_H

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <new>
#include <stdexcept>
#include <utility>
#include <vector>

namespace bfv {
namespace util {

using bfv_byte = uint8_t;

// ----------------------------------------------------------------------------
// Pointer<T> — RAII unique-ownership wrapper for arena-allocated buffers.
// ----------------------------------------------------------------------------
template <typename T>
class Pointer {
 public:
  Pointer() = default;

  Pointer(std::nullptr_t) noexcept : data_(nullptr), size_(0) {}

  Pointer(T *data, std::size_t count) noexcept : data_(data), size_(count) {}

  Pointer(Pointer &&o) noexcept : data_(o.data_), size_(o.size_) {
    o.data_ = nullptr;
    o.size_ = 0;
  }

  Pointer &operator=(Pointer &&o) noexcept {
    if (this != &o) {
      release();
      data_ = o.data_;
      size_ = o.size_;
      o.data_ = nullptr;
      o.size_ = 0;
    }
    return *this;
  }

  template <typename U>
  Pointer(Pointer<U> &&o) noexcept
      : data_(reinterpret_cast<T *>(o.data_)),
        size_(o.size_ * sizeof(U) / sizeof(T)) {
    o.data_ = nullptr;
    o.size_ = 0;
  }
  template <typename U>
  friend class Pointer;

  Pointer &operator=(std::nullptr_t) noexcept {
    release();
    return *this;
  }

  ~Pointer() { release(); }

  void release() noexcept;

  T *get() const noexcept { return data_; }

  T &operator*() const noexcept { return *data_; }

  T *operator->() const noexcept { return data_; }

  explicit operator bool() const noexcept { return data_ != nullptr; }

  T &operator[](std::size_t i) const noexcept { return data_[i]; }

 private:
  Pointer(const Pointer &) = delete;
  Pointer &operator=(const Pointer &) = delete;

  T *data_ = nullptr;
  std::size_t size_ = 0;
};

// ----------------------------------------------------------------------------
// ArenaAllocator — thin allocator wrapper
// ----------------------------------------------------------------------------
class ArenaAllocator {
 private:
  struct CacheParams {
    std::vector<std::vector<void *>> bins;
    std::size_t total_cached_entries = 0;

    ~CacheParams() {
      for (auto &bin : bins) {
        for (void *ptr : bin) {
          std::free(ptr);
        }
      }
    }
  };

  static inline CacheParams &GetThreadLocalCache() {
    thread_local CacheParams cache;
    return cache;
  }

 public:
  static constexpr std::size_t kDefaultAlignment = 64;
  static constexpr std::size_t kMaxCachedTotal = 4096;
  static constexpr std::size_t kMaxCachedPerSize = 128;
  static constexpr std::size_t kAlignmentShift = 6;

  ArenaAllocator() = default;
  ~ArenaAllocator() = default;

  static void *AllocateFast(std::size_t size) {
    auto &cache = GetThreadLocalCache();
    const std::size_t class_index = size >> kAlignmentShift;
    if (class_index < cache.bins.size()) {
      auto &bin = cache.bins[class_index];
      if (!bin.empty()) {
        void *p = bin.back();
        bin.pop_back();
        cache.total_cached_entries--;
        return p;
      }
    }

    void *p = std::aligned_alloc(kDefaultAlignment, size);
    if (!p) {
      throw std::bad_alloc();
    }
    return p;
  }

  static void FreeFast(void *ptr, std::size_t size) noexcept {
    if (!ptr) return;
    auto &cache = GetThreadLocalCache();
    if (cache.total_cached_entries >= kMaxCachedTotal) {
      std::free(ptr);
      return;
    }
    const std::size_t class_index = size >> kAlignmentShift;
    if (class_index >= cache.bins.size()) {
      cache.bins.resize(class_index + 1);
    }
    auto &bin = cache.bins[class_index];
    if (bin.size() >= kMaxCachedPerSize) {
      std::free(ptr);
      return;
    }
    bin.push_back(ptr);
    cache.total_cached_entries++;
  }

  Pointer<bfv_byte> get_for_byte_count(std::size_t byte_count) {
    if (byte_count == 0) {
      return Pointer<bfv_byte>(nullptr);
    }
    std::size_t aligned_size =
        (byte_count + kDefaultAlignment - 1) & ~(kDefaultAlignment - 1);

    void *ptr = AllocateFast(aligned_size);
    alloc_bytes_.fetch_add(aligned_size, std::memory_order_relaxed);
    return Pointer<bfv_byte>(static_cast<bfv_byte *>(ptr), aligned_size);
  }

  std::size_t alloc_byte_count() const noexcept {
    return alloc_bytes_.load(std::memory_order_relaxed);
  }

  std::size_t pool_count() const noexcept { return 0; }

 private:
  std::atomic<std::size_t> alloc_bytes_{0};
};

template <typename T>
void Pointer<T>::release() noexcept {
  if (data_) {
    ArenaAllocator::FreeFast(data_, size_ * sizeof(T));
    data_ = nullptr;
    size_ = 0;
  }
}

class ArenaHandle {
 public:
  ArenaHandle() = default;

  explicit ArenaHandle(ArenaAllocator *arena) : arena_(arena) {}

  ArenaHandle(std::shared_ptr<ArenaAllocator> arena)
      : owner_(std::move(arena)), arena_(owner_.get()) {}

  static ArenaHandle Shared() {
    static ArenaAllocator shared_arena;
    return ArenaHandle(&shared_arena);
  }

  static ArenaHandle Create(bool = false) {
    return ArenaHandle(std::make_shared<ArenaAllocator>());
  }

  explicit operator bool() const noexcept { return arena_ != nullptr; }

  template <typename T>
  Pointer<T> allocate(std::size_t count) {
    if (!arena_) throw std::logic_error("arena handle not initialized");
    auto raw = arena_->get_for_byte_count(count * sizeof(T));
    return Pointer<T>(std::move(raw));
  }

 private:
  std::shared_ptr<ArenaAllocator> owner_;
  ArenaAllocator *arena_ = nullptr;
};

}  // namespace util
}  // namespace bfv

#endif  // BFV_UTIL_ARENA_ALLOCATOR_H
