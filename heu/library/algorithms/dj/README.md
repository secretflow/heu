Implementation of Damgard Jurik Algorithm

Setup:
- Plaintext space: $\mathbb{Z}_{n^s}$
- Ciphertext space: $\mathbb{Z}_{n^{s+1}}$

KeyGen($1^k$):

- Sample a $k$-bit semiprime $n = p \times q$ such that $\gcd(\lambda(n), n)=1$, where $\lambda(n) = \text{lcm}(p-1,q-1)$
- Sample $x \gets \mathbb{Z}_n^*$
- Compute $h = -x^2 \bmod n$ and $h_s = h^{n^s} \bmod n^{s+1}$
- The public key is $(n, h_s)$ and the private key is $\lambda$

Encryption(pk, m):

- Sample $r \gets \{0,1\}^{\lceil k/2 \rceil}$
- The ciphertext is $c = (1+n)^m \cdot h_s^r \bmod n^{s+1}$

Decryption(sk, c):

- For each $j=1$ to $s$, do the following:
  - Compute $l_j = L_j(c^\lambda \bmod n^j)$, where $L_j(z) = \frac{z-1}{n}\bmod n^{j+1}$
  - Compute $i_j=l_j-\sum_{k=2}^i{i_{j-1}\choose i}n^{i-1} \bmod n^i$
- The plaintext is $m=\lambda^{-1}i_s \bmod n^s$


Additive homomorphisms:

- Add $(c_1, c_2) = c_1 \cdot c_2 \bmod n^{s+1}$
- AddPlain $(c, m) = c \cdot (1+n)^m \bmod n^{s+1}$
- Negate $(c) = c^{-1} \bmod n^{s+1}$

Multiplicative homomorphism:

- ScalarMul $(c, s) = c^s \bmod n^{s+1}$

Reference:

- Damgård, I. and Jurik, M., 2001. A generalisation, a simplification and some applications of Paillier's probabilistic public-key system. In Public Key Cryptography: 4th International Workshop on Practice and Theory in Public Key Cryptosystems, PKC 2001 Cheju Island, Korea, February 13–15, 2001 Proceedings 4 (pp. 119-136). Springer Berlin Heidelberg.
