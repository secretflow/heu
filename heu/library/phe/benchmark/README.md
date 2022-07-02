# PHE benchmark

## Fate Paillier
FATE version: `v1.8.0` 3ee02ea81c62d60353b2df40e141529b151d7c67

### How to run this benchmark
```
# python=3.7
pip install google-benchmark==1.6.1  numpy==1.18.4 pycryptodomex==3.6.6 \
    gmpy2 cachetools==3.0.0 ruamel-yaml==0.16.10
cp fate_paillier_bench.py <FATE work dir>/python
cd <FATE work dir>/python
python fate_paillier_bench.py
```
### Result
```
2022-05-09T11:14:38+08:00
Running fate_paillier_bench.py
Run on (8 X 3717.89 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x4)
  L1 Instruction 32 KiB (x4)
  L2 Unified 256 KiB (x4)
  L3 Unified 8192 KiB (x1)
Load Average: 0.21, 0.06, 0.02
--------------------------------------------------------------
Benchmark                    Time             CPU   Iterations
--------------------------------------------------------------
paillier_encrypt           920 ms          919 ms            1
paillier_add_cipher      0.956 ms        0.955 ms          740
paillier_sub_cipher       5.88 ms         5.87 ms          118
paillier_add_int          1.30 ms         1.30 ms          538
paillier_mul_int          4.53 ms         4.52 ms          155
paillier_decrypt           261 ms          261 ms            3
```

## Python Paillier

pip install google-benchmark==1.6.1 phe==1.5.0
### Result
```
2022-05-09T11:12:47+08:00
Running python_paillier_bench.py
Run on (8 X 3848.42 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x4)
  L1 Instruction 32 KiB (x4)
  L2 Unified 256 KiB (x4)
  L3 Unified 8192 KiB (x1)
Load Average: 0.00, 0.01, 0.00
--------------------------------------------------------------
Benchmark                    Time             CPU   Iterations
--------------------------------------------------------------
paillier_encrypt           906 ms          906 ms            1
paillier_add_cipher      0.975 ms        0.974 ms          722
paillier_sub_cipher       6.16 ms         6.15 ms          113
paillier_add_int          1.72 ms         1.72 ms          408
paillier_mul_int          4.76 ms         4.75 ms          148
paillier_decrypt           263 ms          263 ms            3
```