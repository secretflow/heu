Exponential EC Elgamal implementation

Algorithms:

- $E$ is an elliptic curve over $\mathbb F_p$
- $G$ is the generator of $E$

KeyGen($1^\lambda$):

- Sample $x \leftarrow \mathbb Z_p$
- Compute $h := xG$
- The public key is $(E, h)$ and private key is $x$

Encryption(pk, m):

- Sample random mask $r \leftarrow \mathbb Z_p$
- Compute $c_1 = rG$
- Compute $c_2 = mG + rh$
- Ciphertext is $(c_1, c_2)$

Decryption(sk, ciphertext):

- Compute $M = mG = c_2 - xc_1$
- Recover m from M using a lookup table

AddHomo($C_A, C_B$):

- Output $(C_{A1} + C_{B1}, C_{A2} + C_{B2})$

AddPlain($C, m_2$):

- Output $(C_1, C_2 + m_2G)$

SubHomo($C_A, C_B$):

- Output $(C_{A1} - C_{B1}, C_{A2} - C_{B2})$

SubPlain($C, m_2$):

- Output $(C_1, C_2 - m_2G)$

MulPlain($C, m_2$):

- Output $(m_2C_1, m_2C_2)$

Negate($C$):

- Output $(-C_1, -C_2)$

Reference:

- Chatzigiannis, P., Chalkias, K., & Nikolaenko, V. (2022). Homomorphic
  Decryption in Blockchains via Compressed Discrete-Log Lookup Tables. Lecture
  Notes in Computer Science (Including Subseries Lecture Notes in Artificial
  Intelligence and Lecture Notes in Bioinformatics), 13140 LNCS,
  328–339. https://doi.org/10.1007/978-3-030-93944-1_23
- Bauer, J. (2004). Elliptic EcGroup Cryptography Tutorial. 1–13.
- Logarithms, D. (1976). a Public Key Cryptosystem and a Signature based on
  Discrete Logarithms. System, 10–18.
