#pragma once

namespace heu::lib::algorithms::paillier_dl {

template <typename T>
void ValueVecToPtsVec(std::vector<T>& value_vec, std::vector<T*>& pts_vec) {
  int size = value_vec.size();
  for (int i = 0; i < size; ++i) {
    pts_vec.push_back(&value_vec[i]);
  }
}

};