Paillier crypto system with DJN optimization

Key generation:

- Choose an admissible modulus $n=pq$ of length $k$ bits, where $p \equiv q \equiv 3 \pmod 4$ and $gcd(p-1, q-1)=2$
- Randomly select $x \leftarrow \mathbb Z_n^*$, compute $h = -x^2$ and $h_s = h^n \mod n^2$
- Compute $\lambda = (p-1)(q-1)/2$
- The public key is $(n, h_s)$ and secret key is $\lambda$

Encryption(pk, m):

- Sample random mask $r \leftarrow \mathbb Z_{2^{k/2}}$ where $k$ is the bits of $n$
- Compute $c = (1+mn)h_s^r \mod n^2$

Decryption(sk, $c$):

- Pre-compute $\mu = \lambda^{-1} \mod n$
- Compute $m = L(c^\lambda \mod {n^2}) \cdot \mu \mod n$ where function $L$ is defined as $L(x) = \frac{x-1}{n}$

AddHomo($c_1, c_2$):

- Compute $c = c_1 \cdot c_2 \mod n^2$

AddPlain($c_1, m$):

- Compute $c = c_1 \cdot (1+mn) \mod n^2$

SubHomo($c_1, c_2$):

- Compute $c = \dfrac{c_1}{c_2} \mod n^2$

SubPlain($c_1, m$):

- Compute $c = c_1 \cdot (1-mn) \mod n^2$

MulPlain($c_1, m$):

- Compute $c = c_1^m \mod n^2$

Negate($c_1$):

- Compute $c = \dfrac{1}{c_1} \mod n^2$

Randomize ciphertext($c_1$):

- Compute $c = c_1 h_s^r \mod n^2$

Reference:

- Jurik, M. (2003). Extensions to the paillier cryptosystem with applications to cryptological protocols. Brics, August. http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.4.2396&amp;rep=rep1&amp;type=pdf
- Damgård, I., Jurik, M., & Nielsen, J. B. (2010). A generalization of Paillier’s public-key system with applications to electronic voting. International Journal of Information Security, 9(6), 371–385. https://doi.org/10.1007/s10207-010-0119-9
