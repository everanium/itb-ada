# ITB Format-Deniability Wrapper — Ada binding

Ada-idiomatic surface over the 12 `ITB_Wrap*` / `ITB_Unwrap*` / `ITB_WrapStream*` / `ITB_UnwrapStream*` / `ITB_WrapperKeySize` / `ITB_WrapperNonceSize` exports in `cmd/cshared/main.go`. Wraps an ITB ciphertext under one of three outer keystream ciphers (AES-128-CTR / ChaCha20 (RFC8439) / SipHash-2-4 in CTR mode) so the on-wire bytes carry no ITB-specific format pattern.

## Threat model

ITB encrypts content into RGBWYOPA pixel containers. The construction provides **content-deniability** unconditionally — no plaintext bit can be extracted from the wire. The wire pattern itself, however, is parseable by an observer who knows the ITB format:

- Non-AEAD path: per-chunk header carries width / height / container layout.
- Streaming AEAD path: a once per-stream 32-byte streamID prefix plus per-chunk `nonce || W || H || container || flag_byte`.

A passive observer who knows ITB ships with an 8-channel pixel container and a 32-byte streamID prefix can pattern-match the bytes. The format-deniability wrap hides that surface under a generic outer cipher: AES-128-CTR, ChaCha20 (RFC8439), or SipHash-2-4 in CTR mode. After wrapping, the wire is `nonce || keystream-XOR(bytestream)` — the same shape used by countless other protocols. An observer sees a small leading nonce followed by pseudorandom-looking bytes; pattern-matching does not distinguish ITB from any other stream cipher payload.

This is **not** a random-oracle indistinguishability claim. It is a "looks like a different well-known cipher" claim. The wrap exists for format-deniability ONLY; ITB already provides confidentiality (content-deniability) and the AEAD path already provides per-stream and per-chunk integrity. The Non-AEAD streaming path has no integrity by design and the wrap does not add any.

## Wrapper API

The `Itb.Wrapper` package exposes one `Cipher_Type` enumeration plus three usage shapes:

| Helper | Wire format | Use case |
|---|---|---|
| `Wrap` / `Unwrap` | `nonce` + keystream-XOR(blob) | Single Message Encrypt / Encrypt_Auth output, immutable inputs |
| `Wrap_In_Place` / `Unwrap_In_Place` | `nonce` + keystream-XOR(blob) | zero-allocation steady state on the hot path; mutates the caller's buffer |
| `Wrap_Stream_Writer` / `Unwrap_Stream_Reader` | `nonce` + keystream-XOR(continuous bytestream) | streaming use — IO-Driven Streaming AEAD or User-Driven Loop where caller-side framing (`u32_LE` length prefix + body) is written through the wrap-writer so the framing bytes also pass through the keystream XOR |

The single keystream advances monotonically across all bytes within one wrap session. A fresh CSPRNG nonce is generated per session on the libitb side; emitted once at stream start; never reused across sessions. This is standard CTR mode usage — within one stream, one nonce + counter is correct.

No length-prefix or other framing byte appears in cleartext on the wire in any wrap shape. The User-Driven Loop emits length prefixes through the wrap-writer so they get XORed into the keystream alongside the chunk bodies.

The wrap-stream handles (`Wrap_Stream_Writer` / `Unwrap_Stream_Reader`) inherit from `Ada.Finalization.Limited_Controlled` — leaving the value's scope releases the underlying libitb handle deterministically. `Close` is the explicit ASAP-release path.

## Outer ciphers

| Cipher | Key | Nonce | Notes |
|---|---|---|---|
| AES-128-CTR | 16 B | 16 B | Go stdlib `crypto/aes` + `crypto/cipher.NewCTR` on the libitb side. AES-NI accelerated. |
| ChaCha20 (RFC 8439) | 32 B | 12 B | `golang.org/x/crypto/chacha20`. No AES-NI dependency. |
| SipHash-2-4 in CTR mode | 16 B | 16 B | `github.com/dchest/siphash` PRF in custom CTR construction. Sound under the standard PRF assumption that justifies AES-CTR. |

The SipHash-CTR construction:
- 16-byte SipHash key = wrapper key.
- 16-byte nonce split into `(nonce_hi, nonce_lo)` 64-bit halves.
- Each keystream block: `siphash.Hash128(key, nonce_hi || (nonce_lo XOR counter_LE))` — 16-byte output, XORed with plaintext.
- Counter increments per block; nonce stays fixed for the stream.

## Quick Start

Run the matrix:

```sh
alr exec -- gprbuild -P itb_eitb.gpr -p
./eitb/eitb               # run every example × every cipher
./eitb/eitb --cipher aes  # filter to one cipher
./eitb/eitb --example aead -v
```

Per-example sketches below mirror `tools/eitb/main.go`.

### 1. Streaming AEAD Easy (MAC Authenticated, IO-Driven)

ITB Call: `Itb.Encryptor.Encrypt_Stream_Auth` / `Decrypt_Stream_Auth`. Wrap shape: `Wrap_Stream_Writer` / `Unwrap_Stream_Reader` over the continuous bytestream ITB emits.

```ada
declare
   Enc : Itb.Encryptor.Encryptor :=
     Itb.Encryptor.Make ("areion512", 1024, "hmac-blake3", 1);
   Outer_Key : constant Byte_Array :=
     Itb.Wrapper.Generate_Key (Itb.Wrapper.Aes_128_Ctr);
   Inner_Sink : aliased Memory_Stream;
   --  ... encrypt to Inner_Sink via Encrypt_Stream_Auth ...
   N_Len : constant Stream_Element_Offset :=
     Stream_Element_Offset
       (Itb.Wrapper.Nonce_Size (Itb.Wrapper.Aes_128_Ctr));
   Out_Nonce : Byte_Array (1 .. N_Len);
   W : Itb.Wrapper.Wrap_Stream_Writer;
   Last : Stream_Element_Offset;
begin
   Itb.Wrapper.Initialize
     (W, Itb.Wrapper.Aes_128_Ctr, Outer_Key, Out_Nonce);
   --  Wire = Out_Nonce | keystream-XOR(Inner_Sink contents)
   Itb.Wrapper.Update (W, Inner_Sink_Bytes, Body_Enc, Last);
   Itb.Wrapper.Close (W);
end;
```

### 2. Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)

ITB Call: `Itb.Streams.Encrypt_Stream_Auth` / `Decrypt_Stream_Auth` with three explicit `Itb.Seed.Seed` handles plus `Itb.MAC.Make ("hmac-blake3", Mac_Key)`. Wrap shape identical to example 1.

### 3. Streaming Easy (No MAC, User-Driven Loop)

ITB Call: per-chunk `Itb.Encryptor.Encrypt`. Wrap shape: `Wrap_Stream_Writer` driven by a caller loop that emits `u32_LE_len || ct` per chunk through the wrapped writer. Length prefix and chunk body both pass through the keystream XOR — no length appears in cleartext on the wire.

Ada has no `Ada.Streams.Stream_IO` adapter for Non-AEAD streaming wrap surfaces; only User-Driven Loop is exposed.

### 4. Streaming Low-Level (No MAC, User-Driven Loop)

Per-chunk `Itb.Cipher.Encrypt` / `Itb.Cipher.Decrypt` with caller-side framing. Wrap shape identical to example 3.

### 5. Single Message — Easy: Areion-SoEM-512 (No MAC)

ITB Call: `Itb.Encryptor.Encrypt` returns one ITB blob. Wrap shape: `Wrap_In_Place` (the default) — mutates the blob in place and returns the per-stream nonce, which the caller composes with the mutated blob to form the wire.

```ada
declare
   Enc : Itb.Encryptor.Encryptor :=
     Itb.Encryptor.Make ("areion512", 2048);
   Outer_Key : constant Byte_Array :=
     Itb.Wrapper.Generate_Key (Itb.Wrapper.Aes_128_Ctr);
   Encrypted : Byte_Array := Itb.Encryptor.Encrypt (Enc, Plaintext);
   N_Len : constant Stream_Element_Offset :=
     Stream_Element_Offset
       (Itb.Wrapper.Nonce_Size (Itb.Wrapper.Aes_128_Ctr));
   Out_Nonce : Byte_Array (1 .. N_Len);
begin
   --  Wrap respects immutability of Encrypted (allocates a fresh wire):
   --     declare
   --        Wire : constant Byte_Array :=
   --          Itb.Wrapper.Wrap (Itb.Wrapper.Aes_128_Ctr,
   --                            Outer_Key, Encrypted);
   --     begin ... end;
   Itb.Wrapper.Wrap_In_Place
     (Itb.Wrapper.Aes_128_Ctr, Outer_Key, Encrypted, Out_Nonce);
   --  Wire = Out_Nonce & Encrypted (now XORed in place)
end;
```

The allocating `Wrap` / `Unwrap` variants are commented out alongside the in-place defaults in `tools/eitb/main.go` and `eitb/eitb.adb` so a caller who needs immutability of the input buffer can switch shapes by uncommenting the alternative.

### 6. Single Message — Easy: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated)

ITB Call: `Itb.Encryptor.Encrypt_Auth` / `Decrypt_Auth`. Wrap shape: `Wrap_In_Place` over the whole authenticated ITB output. The ITB-internal 32-byte MAC tag remains inside the RGBWYOPA container; outer cipher contributes format-deniability only.

### 7. Single Message — Low-Level: Areion-SoEM-512 (No MAC)

Same wrap shape as example 5; the difference is that the seed material is held in caller-owned `Itb.Seed.Seed` handles rather than by an `Itb.Encryptor.Encryptor` instance.

### 8. Single Message — Low-Level: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated)

`Itb.Cipher.Encrypt_Auth` / `Decrypt_Auth` with three explicit Seeds plus the MAC closure constructed via `Itb.MAC.Make ("hmac-blake3", Mac_Key)`. Wrap shape mirrors the No MAC variant.

## Verification matrix

Every example × cipher combination round-trips against random plaintext (1 KiB for Single Message, 64 KiB for streaming) with byte-equality plus a short fingerprint cross-check.

```
[PASS] aead-easy-io               + aes        pt=65536 wire=90208
[PASS] aead-easy-io               + chacha     pt=65536 wire=90204
[PASS] aead-easy-io               + siphash    pt=65536 wire=90208
[PASS] aead-lowlevel-io           + aes        pt=65536 wire=90208
[PASS] aead-lowlevel-io           + chacha     pt=65536 wire=90204
[PASS] aead-lowlevel-io           + siphash    pt=65536 wire=90208
[PASS] noaead-easy-userloop       + aes        pt=65536 wire=90192
[PASS] noaead-easy-userloop       + chacha     pt=65536 wire=90188
[PASS] noaead-easy-userloop       + siphash    pt=65536 wire=90192
[PASS] noaead-lowlevel-userloop   + aes        pt=65536 wire=90192
[PASS] noaead-lowlevel-userloop   + chacha     pt=65536 wire=90188
[PASS] noaead-lowlevel-userloop   + siphash    pt=65536 wire=90192
[PASS] message-easy-nomac         + aes        pt=1024 wire=4316
[PASS] message-easy-nomac         + chacha     pt=1024 wire=4312
[PASS] message-easy-nomac         + siphash    pt=1024 wire=4316
[PASS] message-easy-auth          + aes        pt=1024 wire=8276
[PASS] message-easy-auth          + chacha     pt=1024 wire=8272
[PASS] message-easy-auth          + siphash    pt=1024 wire=8276
[PASS] message-lowlevel-nomac     + aes        pt=1024 wire=4316
[PASS] message-lowlevel-nomac     + chacha     pt=1024 wire=4312
[PASS] message-lowlevel-nomac     + siphash    pt=1024 wire=4316
[PASS] message-lowlevel-auth      + aes        pt=1024 wire=8276
[PASS] message-lowlevel-auth      + chacha     pt=1024 wire=8272
[PASS] message-lowlevel-auth      + siphash    pt=1024 wire=8276

=== Summary: 24 PASS, 0 FAIL ===
```

The wire-byte difference between cipher columns is exactly the per-stream nonce-size delta (16 vs 12 vs 16 bytes); the User-Driven Loop variants additionally include 4 bytes of keystream-XORed length prefix per chunk.

## Performance

Bench numbers across Single Ouroboros and Triple Ouroboros, message and streaming, encrypt and decrypt (split sub-benches) are tracked in [BENCH.md](BENCH.md).

## Notes on outer cipher key management

The wrapper itself does not address outer key distribution; the examples generate a fresh CSPRNG outer key per run for self-test purposes. In a real deployment the outer key is shared out-of-band (or derived via a separate key-exchange step) and is independent of the ITB seed material. The ITB state blob already carries the inner cipher's keying material; the outer key is the additional piece both endpoints need.

The outer key MAY be reused across many streams provided each stream uses a fresh CSPRNG nonce — this is the standard CTR mode safety contract. The wrapper helpers always generate a fresh nonce internally on the libitb side, so caller-side discipline is reduced to "do not reuse the same `(key, nonce)` across distinct streams" — a contract the helper enforces by construction.

## What this is not

- Not an integrity layer. The outer cipher is unauthenticated by design — adding a MAC at this layer would defeat the format-deniability goal (the resulting wire would pattern-match an AEAD construction's tag-bearing format, not a generic stream cipher). Use the ITB AEAD path when integrity is required.
- Not a substitute for ITB's content-deniability. ITB still provides the unconditional content-deniability; the wrap adds format-deniability on top.
