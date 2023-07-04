// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <mutex>
#include <vector>

#include "yacl/base/exception.h"

namespace heu::lib::algorithms::elgamal {

// A simple and fast hash map:
//  - concurrent insert: thread safe
//  - concurrent find: thread safe
//  - concurrent insert and find: not thread safe
template <typename KeyT, typename ValueT>
class HashMap {
 public:
  using HasherT = std::function<size_t(const KeyT& key)>;
  using EqualorT = std::function<bool(const KeyT& v1, const KeyT& v2)>;

  struct Node {
    Node(const KeyT& key, const ValueT& value) : key(key), value(value) {}

    KeyT key;
    ValueT value;
    Node* next = nullptr;
  };

  // do not allow copy and move, because the address in slots_ cannot change
  HashMap(const HashMap&) = delete;
  HashMap(HashMap&&) = delete;
  HashMap& operator=(const HashMap&) = delete;
  HashMap& operator=(HashMap&&) = delete;

  explicit HashMap(size_t slot_count, const HasherT& hash = std::hash<KeyT>(),
                   const EqualorT& equal = std::equal_to<KeyT>())
      : hasher_(hash), equalor_(equal) {
    slots_.resize(slot_count * 1.2);
    mem_pool_.resize(sizeof(Node) * slot_count);

    std::fill(slots_.begin(), slots_.end(), nullptr);
  }

  ~HashMap() {
    // the type of mem_pool_ is uint8_t, so we should call destructor explicitly
    for (size_t i = 0; i < used_; ++i) {
      Node* mem_pt = reinterpret_cast<Node*>(&mem_pool_[sizeof(Node) * i]);
      mem_pt->~Node();
    }
  }

  // The caller must make sure that the key is unique.
  // We will NOT CHECK is key is duplicate since call equalor_ is expensive
  void Insert(const KeyT& key, const ValueT& value) {
    Insert(hasher_(key) % slots_.size(), key, value);
  }

  // return the address of value. if key is not exist, then return nullptr
  ValueT* Find(const KeyT& key) const {
    auto idx = hasher_(key) % slots_.size();
    for (Node* p = slots_[idx]; p != nullptr; p = p->next) {
      if (equalor_(p->key, key)) {
        return &p->value;
      }
    }
    return nullptr;
  }

 private:
  void Insert(size_t slot_idx, const KeyT& key, const ValueT& value) {
    size_t mem_idx = sizeof(Node) * used_++;
    YACL_ENFORCE_LT(mem_idx, mem_pool_.size(),
                    "hashmap is full, cannot insert anymore");
    Node* mem_pt = new (&mem_pool_[mem_idx]) Node(key, value);

    std::lock_guard<std::mutex> guard(mutex_);
    if (slots_[slot_idx] == nullptr) {
      slots_[slot_idx] = mem_pt;
      return;
    }

    for (Node* p = slots_[slot_idx];; p = p->next) {
      if (p->next == nullptr) {
        // insert
        p->next = mem_pt;
        return;
      }
    }
  }

  std::mutex mutex_;

  HasherT hasher_;
  EqualorT equalor_;
  std::vector<Node*> slots_;

  std::atomic<size_t> used_ = 0;
  // we use uint8_t instead of Node to avoid run ctor on resize()
  std::vector<uint8_t> mem_pool_;
};

}  // namespace heu::lib::algorithms::elgamal
