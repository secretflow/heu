Implementation of Damgard Geisler Krøigaard Algorithm

Setup:
- Plaintext space: $\Z_{u}$
- Ciphertext space: $\Z_{n}$

KeyGen($1^k$):

- Sample a $l$-bit (usually $l=16$) prime $u$
- Sample two $t$-bit (usually $t=160$) primes $v_p, v_q$
- Sample two $k/2$-bit numbers $p, q$ such that $u, v_p \mid p-1$ and $u, v_q \mid q-1$, also $\gcd(v_q, p-1) = 1$
- Sample an element $g$ of order $uv_pv_q$ modulo $n$
- Compute $h = g^u \bmod n$
- The public key is $(n, g, h, u)$ and the private key is $(p, q, v_p, v_q)$

Encryption(pk, m):

- Sample $r \gets \{0,1\}^{2.5t}$
- The ciphertext is $c = g^m \cdot h^r \bmod n$

Decryption(sk, c):

- Compute $d = c^{v_p} \bmod p$
- Find the discrete logarithm of $d$, i.e. $m=\log_{g^{v_p}}(d)$


Additive homomorphisms:

- Add$(c_1, c_2) = c_1 \cdot c_2 \bmod n$
- AddPlain$(c, m) = c \cdot g^m \bmod n$
- Negate$(c) = c^{-1} \bmod n$

Multiplicative homomorphism:

- ScalarMul$(c, s) = c^s \bmod n$

Reference:

- Damgård, I., Geisler, M. and Krøigaard, M., 2007. Efficient and secure comparison for on-line auctions. In Information Security and Privacy: 12th Australasian Conference, ACISP 2007, Townsville, Australia, July 2-4, 2007. Proceedings 12 (pp. 416-430). Springer Berlin Heidelberg.
- Damgard, I., Geisler, M. and Kroigard, M., 2009. A correction to'efficient and secure comparison for on-line auctions'. International Journal of Applied Cryptography, 1(4), pp.323-324.
