# ITB Format-Deniability Wrapper Benchmark Results — Ada binding

The wrapper layer prefixes a fresh CSPRNG nonce and XORs every byte of an ITB ciphertext under one of three outer keystream ciphers — AES-128-CTR (Go stdlib AES-NI on the libitb side), ChaCha20 (RFC8439) (`golang.org/x/crypto/chacha20`), or SipHash-2-4 in CTR mode (`dchest/siphash` PRF + custom counter loop). The wire format becomes `nonce || keystream-XOR(bytestream)`, indistinguishable from any generic stream-cipher payload by surface pattern; ITB's own content-deniability is unchanged.

The numbers below isolate the **outer cipher cost** that the wrapper layer adds on top of ITB. Two test scopes:

* **Wrapper Only** — 16 MiB random buffer, no ITB call. Pure outer cipher round-trip throughput. The `Wrap_In_Place` row mutates the caller's buffer (zero allocation steady state); the `Wrap` row allocates a fresh output buffer per call.
* **Full ITB + wrapper** — encrypt and decrypt are timed **separately** (split sub-benches `…_encrypt` and `…_decrypt`) so the per-direction breakdown is visible. Both Single Ouroboros and Triple Ouroboros are reported. Single-message benches process a 16 MiB plaintext under one encrypt / wrap call (or one unwrap / decrypt call). Streaming benches process a 64 MiB plaintext through 16 MiB chunks via either ITB's stream pipeline (Streaming AEAD) or a User-Driven Loop emitting framed chunks through the wrapped writer (No MAC).

## Concurrency note — why outer cipher choice matters on big-iron Triple

Outer-cipher overhead on a 16-thread host with hardware AES-NI is effectively zero — the AES-CTR keystream finishes well ahead of every ITB-encrypt slot, and the `Wrap_In_Place` path adds no allocation pressure. **On larger Triple Ouroboros hosts (e.g. AMD EPYC 9655P, 192 hardware threads) the picture inverts for the non-AES outer ciphers**: ITB's per-pixel hashing scales across all available threads via the libitb worker pool, while the wrapper's keystream XOR runs single-threaded on one core. ChaCha20 (~700 MB/s peak on a single core via `x/crypto/chacha20`) and SipHash-CTR (~250-280 MB/s peak via the `dchest/siphash` PRF + 16-byte refill loop) become the bottleneck once ITB's Triple decrypt path approaches ~1 GB/s on big-iron. AES-128-CTR retains hardware acceleration on every thread the libitb keystream goroutine lands on and stays out of the critical path even there.

Reproduction:

```sh
alr exec -- gprbuild -P itb_bench.gpr -p
ulimit -s unlimited
ITB_BENCH_MIN_SEC=5 ./obj-bench/bench_wrapper
```

The `ulimit -s unlimited` is required because the bench harness builds a 64 MiB streaming transcript on the secondary stack and the default 8 MiB Linux thread stack does not accommodate it. Production callers that go through `Wrap_In_Place` / `Wrap_Stream_Writer` are unaffected — those paths heap-allocate their work buffers. The ulimit raise is only needed for the bench harness itself.

Filter by case-name substring via the `ITB_BENCH_FILTER` environment variable that the existing Common harness honours; this bench omits the filter logic by default, so a one-off filter is applied via `grep` on stdout.

## Configuration

* Outer cipher path: AES-128-CTR (libitb-side stdlib + AES-NI), ChaCha20 (RFC8439) (`golang.org/x/crypto/chacha20`), SipHash-2-4 in CTR mode (`dchest/siphash` + custom counter loop).
* ITB primitive: Areion-SoEM-512.
* ITB seed width: 1024 bits.
* ITB cipher config: `NonceBits=128`, `BarrierFill=1`, `BitSoup=0`, `LockSoup=0` (minimum config so the outer cipher delta is not masked by per-pixel feature cost).
* `Itb.Set_Max_Workers (0)` (use every available thread for the per-pixel hash kernels).
* MAC factory: HMAC-BLAKE3, 32-byte CSPRNG key (where applicable).
* Single-message plaintext: 16 MiB random.
* Streaming plaintext: 64 MiB random; chunk size 16 MiB.

## Wrapper only round-trip (16 MiB plaintext, encrypt + decrypt timed together)

| Outer cipher | `Wrap` (alloc) MB/s | `WrapInPlace` (zero alloc) MB/s |
|---|---|---|
| **AES-128-CTR** | 1634 | **2440** |
| **ChaCha20** | 298 | **314** |
| **SipHash-CTR** | 251 | **263** |

## Single Message — Single Ouroboros (16 MiB plaintext)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Easy** No MAC | 191 | 271 | 145 | 191 | 138 | 177 |
| **Easy** MAC Authenticated | 174 | 257 | 136 | 182 | 131 | 170 |
| **Low-Level** No MAC | 194 | 277 | 147 | 194 | 140 | 179 |
| **Low-Level** MAC Authenticated | 176 | 259 | 139 | 182 | 132 | 170 |

## Single Message — Triple Ouroboros (16 MiB plaintext)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Easy** No MAC | 264 | 316 | 187 | 211 | 174 | 196 |
| **Easy** MAC Authenticated | 236 | 292 | 171 | 201 | 157 | 186 |
| **Low-Level** No MAC | 264 | 319 | 188 | 212 | 176 | 197 |
| **Low-Level** MAC Authenticated | 238 | 295 | 173 | 202 | 162 | 188 |

## Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk size)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Streaming AEAD Easy** IO-Driven | 165 | 212 | 132 | 160 | 127 | 151 |
| **Streaming AEAD Low-Level** IO-Driven | 153 | 149 | 129 | 120 | 124 | 116 |
| **Streaming Easy** No MAC, User-Driven Loop | 153 | 273 | 124 | 191 | 118 | 181 |
| **Streaming Low-Level** No MAC, User-Driven Loop | 153 | 276 | 125 | 195 | 119 | 182 |

## Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk size)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Streaming AEAD Easy** IO-Driven | 224 | 253 | 166 | 181 | 156 | 171 |
| **Streaming AEAD Low-Level** IO-Driven | 215 | 168 | 162 | 134 | 153 | 127 |
| **Streaming Easy** No MAC, User-Driven Loop | 198 | 314 | 151 | 212 | 143 | 197 |
| **Streaming Low-Level** No MAC, User-Driven Loop | 200 | 317 | 153 | 214 | 144 | 198 |

## Sub-bench inventory

102 cases total:

* 6 wrapper only round-trip (`Wrap` + `Wrap_In_Place` × 3 ciphers).
* 24 Message Single Ouroboros (4 modes × 3 ciphers × 2 directions).
* 24 Message Triple Ouroboros (4 modes × 3 ciphers × 2 directions).
* 24 Streaming Single Ouroboros (4 modes × 3 ciphers × 2 directions; the binding has no `noaead-*-io` Streaming surface — only User-Driven Loop on the No MAC arm).
* 24 Streaming Triple Ouroboros.
