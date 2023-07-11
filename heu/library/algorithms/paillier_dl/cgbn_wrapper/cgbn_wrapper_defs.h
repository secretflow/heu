
#pragma once

#define TPI 16 
#define BITS 4096

template<uint32_t bits>
struct dev_mem_t {
  public:
  uint32_t _limbs[(bits+31)/32];
};