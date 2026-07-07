# Carry bounds for the field-acceleration limb equation (B1)

This note derives the magnitude bounds for the signed carry columns used by
the B1 batched sumcheck (`sumcheck.rs`), and enumerates the range checks that
B2 / Track C must enforce for the protocol to be sound against a malicious
prover. **B1 itself assumes the limb ranges hold (honest prover)** — the final
evaluations are sent in the clear and no range or commitment binding is
performed yet.

## Setup

Each record satisfies, over the integers, `x·y = w·q + z` with
`x, y, z, w < 2^253`. Every 253-bit value is decomposed into three 86-bit
limbs (`limbs_86`), so each limb column entry is `< 2^86`; the modulus limbs
`qL_i < 2^86` are public constants. Define the five product columns
(`k = 0..4`, `m_k` = number of `(i, j)` pairs with `i + j = k`, `i, j < 3`,
so `m_k = (1, 2, 3, 2, 1)`):

```
S_k^raw = Σ_{i+j=k, i,j<3} xL_i·yL_j − Σ_{i+j=k, i,j<3} wL_i·qL_j − zL_k·[k<3]
```

`x·y − w·q − z = Σ_k S_k^raw · 2^{86k}`, so the identity holds iff that
weighted sum is zero. The carries rebalance the columns individually:

```
T_0 = S_0^raw                       T_0 = carry_0 · 2^86
T_k = S_k^raw + carry_{k−1}         T_k = carry_k · 2^86    (k = 1, 2, 3)
T_4 = S_4^raw + carry_3             T_4 = 0  exactly        (carry_4 = 0)
```

`column_carries` (mod.rs) computes these and asserts divisibility by `2^86`
and exact balance of column 4. Carries are **signed** because `w·q` is
subtracted.

## Raw column bound

Each limb product is `< (2^86 − 1)^2 < 2^172`. Column `k` has `m_k ≤ 3`
positive products, `m_k ≤ 3` negative products, and (for `k < 3`) one
subtracted `zL_k < 2^86`:

```
|S_k^raw| < m_k · 2^172 + 2^86  ≤  3 · 2^172 + 2^86
```

## Carry bound (induction on the recurrence)

- **k = 0** (`m_0 = 1`):
  `|carry_0| = |S_0^raw| / 2^86 < (2^172 + 2^86) / 2^86 = 2^86 + 1`.
- **Inductive step** (assume `|carry_{k−1}| < 2^88`):
  ```
  |carry_k| = |S_k^raw + carry_{k−1}| / 2^86
            < (m_k · 2^172 + 2^86 + 2^88) / 2^86
            ≤ 3 · 2^86 + 1 + 4
            = 3 · 2^86 + 5
  ```
  and `3 · 2^86 + 5 = 1.5 · 2^87 + 5 < 2^88`, closing the induction
  (base case `2^86 + 1 < 2^88`).

**Result: every carry satisfies `|carry_k| < 3 · 2^86 + 5 < 2^88`.**

(Column by column, the tighter bounds are `|carry_0| < 2^86 + 1`,
`|carry_1| < 2^87 + 3`, `|carry_2| < 3·2^86 + 4`, `|carry_3| < 2^87 + 5`;
the uniform `2^88` bound is what B2 should enforce.)

## Why the field identity + range checks imply the integer identity

The sumcheck proves `S_k = 0` in BN254 `Fr` (via the alpha-batched,
eq-weighted zero-check, sound by Schwartz–Zippel), where

```
S_k = S_k^raw + carry_{k−1} − carry_k · 2^86 .
```

If the range checks below hold, every term of `S_k` is bounded in integer
magnitude by:

- limb products: `3 · 2^172` each direction,
- `zL_k < 2^86`, `|carry_{k−1}| < 2^88`,
- `|carry_k · 2^86| < 2^88 · 2^86 = 2^174`.

So `|S_k| < 3·2^172 + 2^174 + 2^88 + 2^86 < 2^175 ≪ 2^250 < r_BN254 ≈ 2^254`.
A field element known to equal zero whose integer preimage has magnitude
below the modulus **is** zero over the integers — no wraparound mod `Fr` is
possible. Given `S_k = 0` over ℤ for all `k`, summing `Σ_k S_k · 2^{86k}`
telescopes the carries away and yields `x·y − w·q − z = 0`, i.e. the integer
identity `x·y = w·q + z`.

## Range checks B2 / Track C MUST enforce

B1 is sound only for an honest prover. To defend against a malicious prover
(on top of PCS-binding the 16 columns — Track C), B2 must range-check the
committed columns:

1. **Each of the 12 limb columns** (`xL_0..2`, `yL_0..2`, `zL_0..2`,
   `wL_0..2`): every entry `< 2^86`.
2. **Each of the 4 carry columns**: every entry in `[−2^88, 2^88]`
   (equivalently, `carry + 2^88` is an 89-bit unsigned value).
3. **Final column exact balance**: `S_4^raw + carry_3 = 0` with **no** carry
   out — this is the `k = 4` term of the sumcheck constraint itself (there is
   no `carry_4` column), so it is enforced by B1 once the columns are bound;
   no extra check beyond (1) and (2) is needed for it.

Additionally, if callers require the *canonically reduced* result
(`z < q`, `x, y < q`), those are separate comparisons outside the limb
identity; the identity alone proves `x·y ≡ z (mod q)`.
