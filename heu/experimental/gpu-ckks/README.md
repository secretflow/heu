# SEAL-GPU

SEAL-GPU is an easy-to-use SEAL library using GPU acceleration developed by the software and
hardware combination group at AntGroup. SEAL-GPU provides APIs similar with SEAL, and will provide
richer functions and interfaces later.

> Just for GPU Part

**//// Link GPULIB FIRST ////**

## Environment

* cmake version >= 3.24
* gnu version >= 9
* cuda version >= 11
* gmp required
* ntl required

## gpu_lib

This folder provides GPU library devolped by cuda.

## How to build

* `-DSEAL_USE_GPU` should be set `ON` to enhance GPU boost. If set `OFF`, SEAL-GPU will appear
  nothing different from the raw SEAL.
* `-DCMAKE_INSTALL_PREFIX` should be set as the SEAL-GPU's install path.
* `-DCMAKE_PREFIX_PATH` is the path where SEAL-GPU can find the `GPULIB` package.

Or simply build step-by-step:

```sh
cmake -S . -B build -DSEAL_USE_GPU=ON -DCMAKE_INSTALL_PREFIX=<INSTALL_PATH> -DCMAKE_PREFIX_PATH=<GPULIB_PATH>
cmake --build build
sudo cmake --install build
```

## Examples

* Calling GPULIB to do the `relinearization` in SEAL can be done in 3 steps:

    1. Use a `SEALContext` instance to construct the context used by GPULIB, and enable RMM based
       memory pool.

       ```c++
       auto gpu_context = context.convert2GPU();
       gpu_context.EnableMemoryPool();
       ```

    2. Copy the `RelinKeys` instance to GPU memory.

       ```c++
       auto gpu_evk = static_cast<const KSwitchKeys&>(relin_keys).convert2GPU(context);
       ```

    3. Suppose you have a `Ciphertext` instance in SEAL whose size is precisely 3,
       a `relinearize_inplace` or `relinearize` can reduce its size to 2 via GPULIB. The method
       needs aforementioned `gpu_context` and `gpu_evk` as arguments.

       > Test end-to-end performance in this step.

       ```C++
       evaluator.relinearize_inplace(x_encrypted, gpu_evk, gpu_context);
       ```

* Calling GPULIB to do the `rotation` in SEAL can be done in 3 steps:

    1. Use a `SEALContext` instance to construct the context used by GPULIB, and enable RMM based
       memory pool.

       ```c++
       auto gpu_context = context.convert2GPU();
       gpu_context.EnableMemoryPool();
       ```

    2. Copy the `GaloisKeys` instance to GPU memory. I store
       the `pair<size_t, ckks::EvaluationKey> (elt, gpu_evk)` in an `unordered_map`.

       ```C++
       std::unordered_map<size_t, ckks::EvaluationKey> gpu_evks;
  
       for (size_t i = 0; i < galois_keys.data().size(); i++)
       {
           if (galois_keys.has_key(i))
           {
               gpu_evks.insert(make_pair(i,
                   static_cast<const KSwitchKeys&>(galois_keys).convert2GPU(context, GaloisKeys::get_index(i))));
           }
       }
       ```

    3. Use the `rotate_vector` method to rotate a `Ciphertext` instance via GPULIB. The method needs
       aforementioned `gpu_context` and `gpu_evks` as arguments.

       > Test end-to-end performance in this step.

       ```c++
       evaluator.rotate_vector(encrypted, step, gpu_evks, rotated, gpu_context);
       ```

* `example` works when `poly_modulus_degree` is `8192` and `16384`. Other configurations have not
  been tested.
* Support rotation.
* A new example :matrix multiply vector is already add in SEAL-GPU examples, which is an end-to-end
  gpu compute example.

## Flaws & TODOs

* **The version is not completely end-to-end!**
* Some new functions will be finished.