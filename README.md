# ITB Ada Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the libitb shared library's `ITB_Triple_*` surface
(`cmd/cshared`). Compile-time link against `libitb.so` with an rpath
into the repository's `dist/` tree — no loader-path setup for the
in-repo layout. Every hash-name / MAC-name / cipher-name /
profile-name is an opaque `String` passed through to Go for
validation; the binding carries no ITB construction logic. The public
surface is the `Itb.Pipeline.Pipeline` controlled type (Init / Open /
Rekey / Close, Single Message encrypt / decrypt, one-shot stream
ciphers, profile registration), incremental sessions in `Itb.Stream`,
the `Itb.Opts.Opts` query-string builder, and the Go runtime knobs in
`Itb.Runtime`. Controlled types free their Go-side handles at
finalization (libitb zeroes key material internally).

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go
# Alire (Ada package manager): https://alire.ada.dev
alr toolchain --select   # pick gnat_native + gprbuild
```

Generic Linux: a Go toolchain plus Alire with a selected
`gnat_native` and `gprbuild`.

## Build

The convenience driver builds `libitb.so` plus all four GNAT projects
(library, tests, bench, eitb) in one step:

```bash
./bindings/ada/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
cd bindings/ada
alr exec -- gprbuild -P itb.gpr
alr exec -- gprbuild -P itb_tests.gpr
alr exec -- gprbuild -P itb_bench.gpr
alr exec -- gprbuild -P itb_eitb.gpr
```

## Library lookup

Link-time resolution uses `-L<repo>/dist/linux-amd64` (override with
`gprbuild -XITB_DIST_DIR=/abs/path`); at runtime the binaries carry
an rpath resolving the same `dist/` subfolder relative to their own
location. Binaries installed outside the canonical layout need
`libitb.so` on a system loader path or `LD_LIBRARY_PATH` set.

## Usage example

```ada
with Itb;
with Itb.Opts;
with Itb.Pipeline;

procedure Round_Trip is
   Options          : Itb.Opts.Opts;
   Sender, Receiver : Itb.Pipeline.Pipeline;
begin
   Sender.Init ("singlemsg-triple-mac-v1", Options);
   Receiver.Open ("singlemsg-triple-mac-v1", Sender.Blob, Options);
   declare
      Wire  : constant Itb.Byte_Array :=
        Sender.Encrypt_Message (Itb.To_Byte_Array ("any text or binary data"));
      Plain : constant Itb.Byte_Array := Receiver.Decrypt_Message (Wire);
   begin
      pragma Assert (Itb.To_String (Plain) = "any text or binary data");
   end;
end Round_Trip;
```

`Itb.Opts` overrides the profile default per call (chunk size, outer
cipher, parallax on/off, wrapper on/off, MAC name, palette); every
setter mutates the `Opts` record in place:

```ada
Itb.Opts.Set_Chunk_Size (Options, 65536);
Itb.Opts.Set_With_Wrapper (Options, False);
Sender.Init ("singlemsg-triple-mac-v1", Options);
Receiver.Open ("singlemsg-triple-mac-v1", Sender.Blob, Options);
```

`Itb.Pipeline.Rekey` rotates the parallax + wrapper masters
mid-session (the eight ITB seeds and MAC key are fixed for the
session lifetime by design); the receiver picks up the new masters
through a fresh `Sender.Blob` handshake:

```ada
Sender.Rekey (Perm_Master => (1 .. 32 => 16#11#),
              Wrap_Master => (1 .. 32 => 16#22#));
Receiver.Open ("singlemsg-triple-mac-v1", Sender.Blob, Options);
```

For bounded-memory streaming, `Itb.Stream` exposes incremental
sessions (`Begin_Encrypt` / `Begin_Decrypt`, then `Write` / `Finish`
/ `Read` in a caller-driven loop); `Encrypt_Stream_One_Shot` /
`Decrypt_Stream_One_Shot` cover callers holding the whole payload in
memory.

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string raises `Itb.Error.Itb_Error` carrying
the status code plus the `ITB_LastError` diagnostic (decoded via
`Itb.Error.Status_Code` / `Itb.Error.Message`).

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable at
libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically:

```ada
Itb.Runtime.Set_Memory_Limit (536_870_912);  --  512 MiB soft cap
Itb.Runtime.Set_GC_Percent (20);
```

`Itb.Runtime.Memory_Limit` / `Itb.Runtime.GC_Percent` query without
changing.

A note on large payloads: `Encrypt_Message` and the other cipher
functions return unconstrained `Byte_Array` values. Receiving a
multi-megabyte result into a directly declared stack object can
overflow the default thread stack; receive into a heap object via the
build-in-place idiom instead —
`Wire : Itb.Byte_Array_Access := new Itb.Byte_Array'(Pipe.Encrypt_Message (Plain));`
— as the bench mains do.

## Testing

```bash
./bindings/ada/run_tests.sh
```

Runs the driver built by `itb_tests.gpr`; an optional argument
filters by test name (`./run_tests.sh smoke`). The suite covers
Single Message round trips per shipped profile, stream pumps,
incremental sessions with pathological batch sizes, tampered-wire
failure stickiness, mid-flight cancellation, rekey, profile
registration, error mapping, and opts rendering — surface parity
checks; the deep suite lives in Go under the shipped tree.

## Benchmarking

```bash
./bindings/ada/run_bench.sh
```

Runs `bench_message` (Single Message shape) and `bench_stream`
(incremental stream-pump shape) at 1 MiB / 16 MiB / 64 MiB, one
fixed-width table row per case. Defaults pin the canonical bench
shape (`ITB_INNER_HASH=areion512`, `ITB_KEY_BITS=1024`,
`ITB_NONCE_BITS=512`, parallax + wrapper off,
`ITB_BENCH_MIN_SEC=5`); override via env vars before invocation.

## eitb utility

A small CLI under `bindings/ada/eitb/` mirrors the shipped Go
`tools/eitb` scope for shell smoke tests:

```bash
./bindings/ada/eitb/eitb version
./bindings/ada/eitb/eitb hashes
./bindings/ada/eitb/eitb encrypt singlemsg-triple-mac-v1 in.bin out.bin  # blob hex on stderr
./bindings/ada/eitb/eitb decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- `ITB_LastError` is process-global last-write-wins; the textual
  diagnostic attached to an `Itb_Error` occurrence may belong to a
  different call under concurrent FFI use. The status code is always
  attributable.
- `Rekey` must not run concurrently with cipher calls or open stream
  sessions on the same `Pipeline`.
- A stream session borrows its parent `Pipeline` by handle only; the
  caller must not let a session outlive the Pipeline it was begun on.
