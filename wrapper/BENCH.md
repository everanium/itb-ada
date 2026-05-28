# ITB Format-Deniability Wrapper Benchmark Results — Ada binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

The wrapper layer prefixes a fresh CSPRNG nonce and XORs every byte of an ITB ciphertext under one of outer keystream ciphers, one per PRF-grade ITB registry primitive. The keystream construction is delegated libitb-side to the `ctr` package. The wire format becomes `nonce || keystream-XOR(bytestream)`, indistinguishable from any generic stream-cipher payload by surface pattern; ITB's own content-deniability is unchanged.

The numbers below isolate the **outer cipher cost** that the wrapper layer adds on top of ITB. Two test scopes:

* **Wrapper Only** — 16 MiB random buffer, no ITB call. Pure outer cipher round-trip throughput. The `Wrap_In_Place` row mutates the caller's buffer (no output-buffer allocation); the `Wrap` row allocates a fresh output buffer per call.
* **Full ITB + wrapper** — encrypt and decrypt are timed **separately** (split sub-benches `…_encrypt` and `…_decrypt`) so the per-direction breakdown is visible. Both Single Ouroboros and Triple Ouroboros are reported. Single-message benches process a 16 MiB plaintext under one encrypt / wrap call (or one unwrap / decrypt call). Streaming benches process a 64 MiB plaintext through 16 MiB chunks via either ITB's stream pipeline (Streaming AEAD) or a User-Driven Loop emitting framed chunks through the wrapped writer (No MAC).

The wrapper bench covers all outer ciphers — each in CTR mode.

## Concurrency note — why outer cipher choice matters on big-iron Triple

Outer-cipher overhead on a 16-thread host with hardware AES-NI is effectively zero — the AES-CTR keystream finishes well ahead of every ITB-encrypt slot, and the `Wrap_In_Place` path avoids output-buffer allocation. **On larger Triple Ouroboros hosts (e.g. AMD EPYC 9655P, 192 hardware threads) the picture inverts for the non-AES outer ciphers**: ITB's per-pixel hashing scales across all available threads via the libitb worker pool, while the wrapper's keystream XOR splits across up to 32 worker goroutines (`min(32, GOMAXPROCS, chunks)`) inside libitb for buffers at or above the 256 KiB threshold, each worker seeking its own keystream to its chunk offset via `ctr.NewAt`; buffers below the threshold run serially.

## Binding asymmetry note

The Ada binding's Streaming No MAC arm covers the User-Driven Loop variant only — there is no IO-Driven Streaming No MAC writer / reader pair. The Streaming AEAD path covers IO-Driven for both Easy and Low-Level.

## Reproduction

```sh
alr exec -- gprbuild -P itb_bench.gpr -p
ulimit -s unlimited
ITB_BENCH_MIN_SEC=5 ./obj-bench/bench_wrapper
```

The `ulimit -s unlimited` is required because the bench harness builds a 64 MiB streaming transcript on the secondary stack and the default 8 MiB Linux thread stack does not accommodate it. Production callers that go through `Wrap_In_Place` / `Wrap_Stream_Writer` are unaffected — those paths heap-allocate their work buffers. The ulimit raise is only needed for the bench harness itself.

Filter by case-name substring via the `ITB_BENCH_FILTER` environment variable that the existing Common harness honours; this bench omits the filter logic by default, so a one-off filter is applied via `grep` on stdout.

## Configuration

* Outer cipher path: all PRF-grade registry primitives, keystream built libitb-side via the `ctr` package.
* ITB primitive: Areion-SoEM-512.
* ITB seed width: 1024 bits.
* ITB cipher config: `NonceBits=128`, `BarrierFill=1`, `BitSoup=0`, `LockSoup=0` (minimum config so the outer cipher delta is not masked by per-pixel feature cost).
* `Itb.Set_Max_Workers (0)` (use every available thread for the per-pixel hash kernels).
* MAC factory: HMAC-BLAKE3, 32-byte CSPRNG key (where applicable).
* Single-message plaintext: 16 MiB random.
* Streaming plaintext: 64 MiB random; chunk size 16 MiB.

Column abbreviations in the Full ITB + wrapper tables: **LL** = Low-Level, **Loop** = User-Driven Loop, **IO** = IO-Driven, **NoMAC** = No MAC, **MAC** = MAC Authenticated, **Enc** / **Dec** = encrypt / decrypt direction. All throughput is MB/s, rounded.

### Wrapper only round-trip (16 MiB plaintext, encrypt + decrypt timed together)

| Outer cipher | `Wrap` (alloc) MB/s | `Wrap_In_Place` (no output-buffer alloc) MB/s |
|---|---|---|
| **Areion-SoEM-256** | 570 | 1532 |
| **Areion-SoEM-512** | 1289 | 1550 |
| **BLAKE2b-256** | 543 | 600 |
| **BLAKE2b-512** | 842 | 988 |
| **BLAKE2s** | 572 | 638 |
| **BLAKE3** | 971 | 1112 |
| **AES-128-CTR** | 1952 | 3064 |
| **SipHash-2-4** | 1519 | 1987 |
| **ChaCha20** | 1486 | 1874 |

### Single Message — Single Ouroboros (16 MiB plaintext)

| Cipher | Easy NoMAC Enc | Easy NoMAC Dec | Easy MAC Enc | Easy MAC Dec | LL NoMAC Enc | LL NoMAC Dec | LL MAC Enc | LL MAC Dec |
|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 185 | 272 | 176 | 259 | 192 | 271 | 178 | 258 |
| **Areion-SoEM-512** | 192 | 277 | 177 | 255 | 193 | 278 | 178 | 256 |
| **BLAKE2b-256** | 175 | 235 | 161 | 219 | 174 | 226 | 162 | 221 |
| **BLAKE2b-512** | 185 | 259 | 172 | 240 | 185 | 256 | 168 | 244 |
| **BLAKE2s** | 175 | 239 | 161 | 221 | 178 | 241 | 160 | 222 |
| **BLAKE3** | 186 | 263 | 175 | 248 | 189 | 262 | 175 | 252 |
| **AES-128-CTR** | 198 | 288 | 184 | 270 | 201 | 292 | 182 | 270 |
| **SipHash-2-4** | 194 | 282 | 179 | 259 | 196 | 288 | 179 | 262 |
| **ChaCha20** | 193 | 281 | 179 | 263 | 197 | 281 | 178 | 261 |

### Single Message — Triple Ouroboros (16 MiB plaintext)

| Cipher | Easy NoMAC Enc | Easy NoMAC Dec | Easy MAC Enc | Easy MAC Dec | LL NoMAC Enc | LL NoMAC Dec | LL MAC Enc | LL MAC Dec |
|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 258 | 306 | 233 | 285 | 261 | 305 | 234 | 285 |
| **Areion-SoEM-512** | 260 | 301 | 232 | 286 | 258 | 307 | 233 | 287 |
| **BLAKE2b-256** | 222 | 252 | 200 | 231 | 223 | 256 | 202 | 243 |
| **BLAKE2b-512** | 244 | 280 | 220 | 264 | 245 | 281 | 216 | 268 |
| **BLAKE2s** | 225 | 259 | 204 | 246 | 227 | 253 | 206 | 248 |
| **BLAKE3** | 249 | 292 | 226 | 272 | 251 | 293 | 227 | 274 |
| **AES-128-CTR** | 271 | 325 | 242 | 304 | 274 | 323 | 245 | 300 |
| **SipHash-2-4** | 263 | 314 | 238 | 290 | 266 | 312 | 236 | 295 |
| **ChaCha20** | 262 | 310 | 234 | 288 | 265 | 313 | 234 | 294 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk size) — AEAD

| Cipher | AEAD Easy IO Enc | AEAD Easy IO Dec | AEAD LL IO Enc | AEAD LL IO Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 169 | 217 | 151 | 151 |
| **Areion-SoEM-512** | 170 | 216 | 161 | 159 |
| **BLAKE2b-256** | 152 | 192 | 148 | 145 |
| **BLAKE2b-512** | 164 | 207 | 160 | 153 |
| **BLAKE2s** | 157 | 196 | 151 | 147 |
| **BLAKE3** | 163 | 206 | 158 | 154 |
| **AES-128-CTR** | 174 | 221 | 164 | 162 |
| **SipHash-2-4** | 170 | 222 | 167 | 160 |
| **ChaCha20** | 167 | 220 | 161 | 159 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk size) — Non-AEAD (User-Driven Loop)

| Cipher | Easy Loop Enc | Easy Loop Dec | LL Loop Enc | LL Loop Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 157 | 277 | 156 | 280 |
| **Areion-SoEM-512** | 158 | 280 | 157 | 280 |
| **BLAKE2b-256** | 146 | 239 | 145 | 237 |
| **BLAKE2b-512** | 152 | 263 | 153 | 261 |
| **BLAKE2s** | 145 | 237 | 146 | 244 |
| **BLAKE3** | 153 | 267 | 149 | 267 |
| **AES-128-CTR** | 159 | 286 | 159 | 290 |
| **SipHash-2-4** | 158 | 283 | 158 | 283 |
| **ChaCha20** | 156 | 282 | 156 | 285 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk size) — AEAD

| Cipher | AEAD Easy IO Enc | AEAD Easy IO Dec | AEAD LL IO Enc | AEAD LL IO Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 222 | 253 | 215 | 171 |
| **Areion-SoEM-512** | 222 | 250 | 213 | 180 |
| **BLAKE2b-256** | 197 | 218 | 190 | 161 |
| **BLAKE2b-512** | 212 | 237 | 206 | 171 |
| **BLAKE2s** | 200 | 223 | 189 | 164 |
| **BLAKE3** | 214 | 242 | 207 | 175 |
| **AES-128-CTR** | 231 | 259 | 220 | 184 |
| **SipHash-2-4** | 226 | 254 | 216 | 181 |
| **ChaCha20** | 225 | 252 | 216 | 181 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk size) — Non-AEAD (User-Driven Loop)

| Cipher | Easy Loop Enc | Easy Loop Dec | LL Loop Enc | LL Loop Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 201 | 304 | 202 | 306 |
| **Areion-SoEM-512** | 200 | 302 | 202 | 309 |
| **BLAKE2b-256** | 179 | 258 | 179 | 257 |
| **BLAKE2b-512** | 192 | 284 | 192 | 285 |
| **BLAKE2s** | 180 | 262 | 182 | 264 |
| **BLAKE3** | 194 | 294 | 194 | 296 |
| **AES-128-CTR** | 204 | 319 | 205 | 321 |
| **SipHash-2-4** | 202 | 314 | 203 | 318 |
| **ChaCha20** | 202 | 311 | 202 | 313 |

This file is updated by re-running the reproduction command and pasting the bench output into the tables. Numbers above are rounded to MB/s.
