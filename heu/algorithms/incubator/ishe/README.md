# iSHE

## 简介

iSHE(improved SHE)，是一种对主流的对称同态加密技术的改进的对称同态加密技术(Symmetric Homomorphic Encryption,SHE)而提出的新的同态加密技术，它可以在不损害安全性的情况下提高原始SHE的性能，并在一些解决方案中作为加密原语。SHE被证明是CPA安全的，被广泛应用于可搜索的加密方案中，而iSHE是原始SHE在抵抗AGCD(Approximate Greatest Common Divisor)攻击的同时提高性能的一个新版本。


## 同态性质

### Mul-1

Ciphertext mul ciphertext:

iSHE.Dec(sk,(⟦m1⟧·⟦m_2⟧) mod N, d) = m1· m2

### Mul-2

Ciphertext mul plaintext:

iSHE.Dec(sk,(⟦m1⟧·m2) mod N, d) = m1·m2

### Add-1

Ciphertext add ciphertext:

iSHE.Dec(sk,(⟦m1⟧+ ⟦m2⟧) mod N, d) = m1+m2

### Add-2

Ciphertext add plaintext:

iSHE.Dec(sk,(⟦m1⟧+ m2) mod N, d) = m1+m2

## 相关文献

### 安全性和详细证明请参考文献：

https://ieeexplore.ieee.org/document/10517763

Performance Enhanced Secure Spatial Keyword Similarity Query With Arbitrary Spatial Ranges (TIFS’24)

section Ⅴ.A on page 5280

### AGCD攻击相关定义和理论：

https://eprint.iacr.org/2009/616.pdf

Fully Homomorphic Encryption over the Integers

https://eprint.iacr.org/2016/215.pdf

Algorithms for the Approximate Common Divisor Problem