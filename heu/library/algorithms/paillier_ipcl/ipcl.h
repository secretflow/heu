// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#pragma once

#ifndef ENABLE_IPCL

#ifdef __x86_64__
#define ENABLE_IPCL true
#else
// IPCL do not support MAC(ARM) architecture
#define ENABLE_IPCL false
#endif

#endif

#if ENABLE_IPCL == true

#include "heu/library/algorithms/paillier_ipcl/ciphertext.h"
#include "heu/library/algorithms/paillier_ipcl/key_generator.h"
#include "heu/library/algorithms/paillier_ipcl/plaintext.h"
#include "heu/library/algorithms/paillier_ipcl/public_key.h"
#include "heu/library/algorithms/paillier_ipcl/secret_key.h"
#include "heu/library/algorithms/paillier_ipcl/vector_decryptor.h"
#include "heu/library/algorithms/paillier_ipcl/vector_encryptor.h"
#include "heu/library/algorithms/paillier_ipcl/vector_evaluator.h"

#endif
