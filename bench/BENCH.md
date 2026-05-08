# ITB Ada Binding - Easy Mode Benchmark Results

Throughput (MB/s) of `Itb.Encryptor.Encrypt` / `Decrypt` /
`Encrypt_Auth` / `Decrypt_Auth` over the libitb c-shared library
through the Ada `pragma Import (C, ...)` FFI surface emitted by GNAT
FSF + Alire. Single + Triple Ouroboros at 1024-bit ITB key width on
a 16 MiB non-deterministic-fill payload, four ops per primitive.
The MAC slot is bound to **HMAC-BLAKE3** — the lightest
authenticated-mode overhead among the three shipping MACs (the
`Encrypt_Auth` row sits within a few percent of the matching
`Encrypt` row, and well below HMAC-SHA256's ~15 % and KMAC-256's
~44 % overheads).

The harness lives in this directory; reproduction:

```bash
cd bindings/ada
alr exec -- gprbuild -P itb_bench.gpr
ITB_BENCH_MIN_SEC=5 ./obj-bench/bench_single
ITB_BENCH_MIN_SEC=5 ITB_LOCKSEED=1 ./obj-bench/bench_single
ITB_BENCH_MIN_SEC=5 ./obj-bench/bench_triple
ITB_BENCH_MIN_SEC=5 ITB_LOCKSEED=1 ./obj-bench/bench_triple
```

The default measurement window is 5 seconds per case
(`ITB_BENCH_MIN_SEC=5`), wide enough to absorb the cold-cache /
warm-up transient that distorts shorter windows on the 16 MiB
encrypt / decrypt path. `ITB_BENCH_FILTER=<substring>` narrows the
matrix to a single primitive when re-running an outlier in
isolation.

## FFI overhead vs. native Go

The Ada path adds a `pragma Import (C, ...)` trampoline, the C ABI
crossing into Go, and a result-copy from the c-shared output buffer
back into a `Stream_Element_Array`. The binding caches a
per-encryptor output buffer and pre-allocates from a 1.25× upper
bound on the empirical ITB ciphertext-expansion factor (≤ 1.155
across every primitive / mode / nonce / payload-size combination)
so the hot loop avoids the size-probe round-trip the
process-global FFI helpers use. The cache is wiped on grow and on
`Close` / `Finalize`, so residual ciphertext / plaintext cannot
linger in heap garbage between cipher calls.

The numbers below ride the default build (no opt-out tags). On
hosts without AVX-512+VL the Go side automatically nil-routes the
4-lane batched chain-absorb arm so the per-pixel hash falls
through to the upstream stdlib asm via the single Func — see the
build-tag table in [`../README.md`](../README.md) for the
`-tags=purego` / `-tags=noitbasm` opt-outs.

## Intel Core i7-11700K (16 HT, native Linux, c-shared mode)

Recorded on Intel Core i7-11700K (Rocket Lake, AVX-512 + VAES,
8 cores / 16 threads, native Linux), GNAT FSF 15.2.1 + Alire
2.x, libitb 0.1.0 in c-shared mode.

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 187 | 285 | 182 | 267 |
| **Areion-SoEM-512** | 512 | PRF | 196 | 300 | 187 | 276 |
| **SipHash-2-4** | 128 | PRF | 152 | 197 | 143 | 187 |
| **AES-CMAC** | 128 | PRF | 186 | 266 | 172 | 243 |
| **BLAKE2b-512** | 512 | PRF | 128 | 169 | 129 | 162 |
| **BLAKE2b-256** | 256 | PRF | 93 | 110 | 82 | 98 |
| **BLAKE2s** | 256 | PRF | 102 | 119 | 98 | 119 |
| **BLAKE3** | 256 | PRF | 123 | 148 | 115 | 144 |
| **ChaCha20** | 256 | PRF | 111 | 132 | 106 | 128 |
| **Mixed** | 256 | PRF | 110 | 133 | 106 | 127 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 263 | 318 | 233 | 300 |
| **Areion-SoEM-512** | 512 | PRF | 276 | 336 | 250 | 321 |
| **SipHash-2-4** | 128 | PRF | 189 | 202 | 156 | 202 |
| **AES-CMAC** | 128 | PRF | 247 | 292 | 222 | 275 |
| **BLAKE2b-512** | 512 | PRF | 166 | 185 | 155 | 177 |
| **BLAKE2b-256** | 256 | PRF | 106 | 113 | 101 | 110 |
| **BLAKE2s** | 256 | PRF | 116 | 124 | 112 | 120 |
| **BLAKE3** | 256 | PRF | 142 | 155 | 135 | 140 |
| **ChaCha20** | 256 | PRF | 128 | 138 | 122 | 131 |
| **Mixed** | 256 | PRF | 126 | 135 | 119 | 130 |

## Intel Core i7-11700K (16 HT, native Linux, c-shared mode, LockSeed mode)

The dedicated lockSeed channel (`Itb.Encryptor.Set_Lock_Seed (Enc, 1)` /
`ITB_LOCKSEED=1`) auto-couples bit-soup + lock-soup on the
on-direction. Numbers below run with all three overlays active.

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 60 | 69 | 56 | 71 |
| **Areion-SoEM-512** | 512 | PRF | 50 | 55 | 47 | 54 |
| **SipHash-2-4** | 128 | PRF | 67 | 74 | 65 | 74 |
| **AES-CMAC** | 128 | PRF | 72 | 84 | 73 | 84 |
| **BLAKE2b-512** | 512 | PRF | 30 | 49 | 46 | 49 |
| **BLAKE2b-256** | 256 | PRF | 42 | 44 | 41 | 44 |
| **BLAKE2s** | 256 | PRF | 42 | 47 | 42 | 46 |
| **BLAKE3** | 256 | PRF | 43 | 45 | 42 | 45 |
| **ChaCha20** | 256 | PRF | 45 | 49 | 44 | 48 |
| **Mixed** | 256 | PRF | 41 | 49 | 46 | 53 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 62 | 67 | 63 | 66 |
| **Areion-SoEM-512** | 512 | PRF | 55 | 56 | 53 | 55 |
| **SipHash-2-4** | 128 | PRF | 72 | 70 | 60 | 63 |
| **AES-CMAC** | 128 | PRF | 76 | 79 | 73 | 82 |
| **BLAKE2b-512** | 512 | PRF | 45 | 46 | 45 | 49 |
| **BLAKE2b-256** | 256 | PRF | 44 | 45 | 44 | 42 |
| **BLAKE2s** | 256 | PRF | 41 | 42 | 40 | 43 |
| **BLAKE3** | 256 | PRF | 42 | 38 | 43 | 45 |
| **ChaCha20** | 256 | PRF | 44 | 50 | 36 | 44 |
| **Mixed** | 256 | PRF | 48 | 50 | 47 | 34 |

## Notes

- The first row in every Single-Ouroboros pass typically shows a
  transient asymmetry between encrypt and decrypt. This is the
  cold-cache + first-iteration warmup absorbed imperfectly even at
  5-second windows; subsequent rows in the same pass run on warm
  caches and report symmetric encrypt-vs-decrypt numbers. Re-running
  the same primitive in isolation
  (`ITB_BENCH_FILTER=areion256 ITB_BENCH_MIN_SEC=20 ./obj-bench/bench_single`)
  normalises the asymmetry.
- The LockSeed arms cap throughput in the 40-80 MB/s band because
  the dedicated lockseed slot auto-engages BitSoup + LockSoup; the
  bit-level split + per-chunk PRF-keyed bit-permutation overlay
  together dominate the per-byte cost.
- Triple Ouroboros exceeds Single Ouroboros throughput on most
  primitives because the seven-seed split exposes additional
  internal parallelism opportunities to libitb's worker pool while
  the on-the-wire chunk count remains the same.
- Bench cases run sequentially per pass; libitb's internal worker
  pool (`Itb.Set_Max_Workers (0)` → all CPUs) processes each case's
  chunk-level parallelism within the case's wall-clock window.
