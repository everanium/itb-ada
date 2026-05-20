# ITB Ada Binding

Ada 2022 / Alire-managed wrapper over the libitb shared library
(`cmd/cshared`). Link-time C ABI integration via `pragma Import (C,
...)`; `Ada.Finalization.Limited_Controlled` for deterministic RAII
at scope exit. Two-layer architecture: `Itb.Sys` (raw FFI,
audit-friendly) plus `Itb.*` (safe wrappers).

**Path placeholder.** `<itb>` denotes the path to the local ITB
repository checkout (or this binding's mirror clone) — for example,
`/home/you/go/src/itb` or `~/projects/itb-ada`. Substitute the
literal token in the recipes below.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go go-tools gcc-ada
```

Plus Alire via the upstream binary release (NOT AUR — `yay -S alire`
does NOT work due to xmlada ↔ gprbuild ↔ python-e3-* circular
dependencies):

1. Install the GNAT FSF system compiler: `sudo pacman -S gcc-ada`.
2. Install Alire via the upstream binary release tarball:

   ```bash
   curl -L -o /tmp/alire.zip \
       'https://github.com/alire-project/alire/releases/latest/download/alr-2.1.0-bin-x86_64-linux.zip'
   sudo unzip /tmp/alire.zip 'bin/alr' -d /usr/local/
   ```

3. Initialise Alire's isolated toolchain: `alr toolchain --select`,
   then pick `gnat_native` and `gprbuild`.
4. Verify: `cd bindings/ada && alr exec -- gprbuild -P itb.gpr`
   should build cleanly.

## Build the shared library

The convenience driver `bindings/ada/build.sh` builds `libitb.so`
plus the Ada library project (and tests / benches via the extra
positional argument) in one step. Run it from anywhere:

```bash
./bindings/ada/build.sh
```

The driver expands to two underlying steps — building libitb from
the repo root, then `alr exec -- gprbuild -P itb.gpr` on the
binding side (filtering the cosmetic `.sframe` linker notice).
Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
cd bindings/ada && alr exec -- gprbuild -P itb.gpr
```

The driver also forwards arguments to `gprbuild` after `--`, useful
for compiling the test or bench projects in the same step:

```bash
./bindings/ada/build.sh -- -P itb_tests.gpr
./bindings/ada/build.sh --skip-libitb -- -P itb_bench.gpr -f
```

(macOS produces `libitb.dylib` under `dist/darwin-<arch>/`,
Windows produces `libitb.dll` under `dist/windows-<arch>/`.)

## Add to a project

The crate is published as `itb`. Until it lands in the Alire
community index, depend on it as a local-path crate from a
consuming `alire.toml`:

```toml
[[depends-on]]
itb = { path = "../path/to/bindings/ada" }
```

The consumer's own `.gpr` then withs the library project:

```ada
with "itb";

project My_App is
   for Source_Dirs use ("src");
   for Object_Dir  use "obj";
   for Main        use ("my_app.adb");
   for Languages   use ("Ada");
end My_App;
```

The linker switches in `itb.gpr`'s `Linker` package
(`-L../../dist/<os>-<arch>`, `-litb`, and the `-Wl,-rpath,$ORIGIN/...`
runtime search path) propagate to the consumer automatically — no
extra LDFLAGS or rpath plumbing is required.

Build once before running tests:

```bash
cd bindings/ada
alr exec -- gprbuild -P itb.gpr
```

Crate metadata: `name = "itb"`, `version = "0.1.1-dev"`,
`license = "MIT"`. The only runtime dependency declared in
`alire.toml` is `gnat >= 13`; the wrapper itself is pure Ada 2022
plus the standard library, with the libitb shared library located
through compile-time linker search paths and runtime rpath.

## Library lookup order

1. **Compile-time `-L` switch** in `itb.gpr`'s `Linker` package
   resolves `-litb` against `<repo>/dist/<os>-<arch>/`. The
   `ITB_DIST_DIR` external variable overrides the search prefix
   (`alr exec -- gprbuild -P itb.gpr -XITB_DIST_DIR=/abs/path`).
2. **Runtime `-Wl,-rpath,$ORIGIN/../../../dist/linux-amd64`** is
   baked into the resulting binary. `ld.so` searches the binary's
   RPATH first (resolving `$ORIGIN` to the binary's own directory),
   then the standard system loader path.
3. **System loader path** (`ld.so.cache`, `LD_LIBRARY_PATH`,
   `DYLD_LIBRARY_PATH`, `PATH`). Setting `LD_LIBRARY_PATH` to an
   absolute path overrides RPATH for diagnostic / installation use.

The link-time + rpath mechanism is the standard Ada idiom — no
runtime `dlopen`-style probe is performed at startup.

## Memory

Two process-wide knobs constrain Go runtime arena pacing. Both readable at libitb load time via env vars:

- `ITB_GOMEMLIMIT=512MiB` — soft memory limit in bytes; supports `B` / `KiB` / `MiB` / `GiB` / `TiB` suffixes.
- `ITB_GOGC=20` — GC trigger percentage; default `100`, lower triggers GC more aggressively.

Programmatic setters override env-set values at any time. Pass `-1` to either setter to query the current value without changing it.

```ada
Discard := Itb.Set_Memory_Limit (512 * 1024 * 1024);
Discard := Itb.Set_GC_Percent (20);
```

## Tests

```bash
./bindings/ada/build.sh -- -P itb_tests.gpr
./bindings/ada/run_tests.sh
```

The harness iterates every ELF binary produced by `itb_tests.gpr`
under `obj-tests/`, runs each one in turn, and reports pass / fail
counts in Go-test style. The integration test suite under
`bindings/ada/tests/` mirrors the cross-binding coverage:
Single + Triple Ouroboros, mixed primitives, authenticated paths,
blob round-trip, streaming chunked I/O, error paths, lockSeed
lifecycle. 30 standalone test executables, each a main procedure
that exits 0 on pass; total wall-clock is ~3 seconds. Per-process
isolation gives every test a fresh libitb global state, so tests
that mutate process-global config (`Set_Bit_Soup` /
`Set_Lock_Soup` / `Set_Max_Workers` / `Set_Nonce_Bits` /
`Set_Barrier_Fill`) save and restore at procedure boundaries
without a shared mutex.

`./run_tests.sh test_blake3` runs a single test by base name; the
default invocation iterates every test executable in `obj-tests/`.

## Benchmarks

A custom Go-bench-style harness lives under `bench/` and covers the
four ops (`Encrypt`, `Decrypt`, `Encrypt_Auth`, `Decrypt_Auth`)
across the nine PRF-grade primitives plus one mixed-primitive
variant for both Single and Triple Ouroboros at 1024-bit ITB key
width and 16 MiB payload. See [`bench/README.md`](bench/README.md)
for invocation / environment variables / output format and
[`bench/BENCH.md`](bench/BENCH.md) for recorded throughput results
across the canonical pass matrix.

The four-pass canonical sweep (Single + Triple × ±LockSeed) that
fills `bench/BENCH.md` is driven by the wrapper script in the
binding root:

```bash
./bindings/ada/run_bench.sh                  # full 4-pass canonical sweep
./bindings/ada/run_bench.sh --lockseed-only  # pass 3 + pass 4 only
```

The harness sets `LD_LIBRARY_PATH` to `dist/linux-amd64/`,
manages `ITB_LOCKSEED` per pass, and forwards `ITB_NONCE_BITS` /
`ITB_BENCH_FILTER` / `ITB_BENCH_MIN_SEC` straight through to the
underlying `obj-bench/bench_single` / `obj-bench/bench_triple`
binaries (built ahead of time via
`./bindings/ada/build.sh -- -P itb_bench.gpr`).

FFI overhead in the Ada binding is link-time: `pragma Import (C, ...,
External_Name => "ITB_*")` bakes the C symbol reference into the
compiled Ada object at compile time, and `ld.so` resolves the symbol
against the loaded `libitb.so` at process start. Per-call cost is
one C ABI crossing — comparable to a regular C function call, no
per-call FFI dispatch table lookup as in dlopen-style loaders.
The output-buffer cache on `Itb.Encryptor.Encryptor` skips the
size-probe round-trip
and a duplicate encrypt on every call; pre-allocation uses a 1.25×
upper bound (the empirical ITB ciphertext-expansion factor measured
at ≤ 1.155 across every primitive / mode / nonce / payload-size
combination) and the cache is wiped on grow, on `Close`, and on
`Finalize`.

## Streaming AEAD

**Streaming AEAD** authenticates a chunked stream end-to-end while preserving the deniability of the per-chunk MAC-Inside-Encrypt container. Each chunk's MAC binds the encrypted payload to a 32-byte CSPRNG stream anchor (written as a once-per-stream wire prefix), the cumulative pixel offset of preceding chunks, and a final-flag bit — defending against chunk reorder, replay within or across streams sharing the PRF / MAC key, silent mid-stream drop, and truncate-tail. The wire format adds 32 bytes of stream prefix plus one byte of encrypted trailing flag per chunk; no externally visible MAC tag.

**Easy Mode:**

`Itb.Encryptor.Encrypt_Stream_Auth` accepts any `Ada.Streams.Root_Stream_Type'Class` source and sink. `Ada.Streams.Stream_IO.Stream (File)` returns the corresponding `Stream_Access` for a file opened via `Stream_IO.Open` / `Stream_IO.Create`, which lets the binding stream directly between disk files. The MAC key is allocated CSPRNG-fresh inside the encryptor at constructor time.

```ada
with Ada.Streams;            use Ada.Streams;
with Ada.Streams.Stream_IO;
with Itb;
with Itb.Encryptor;
with Itb.Wrapper;

declare
   Enc        : Itb.Encryptor.Encryptor :=
     Itb.Encryptor.Make ("areion512", 1024, "hmac-blake3", 1);
   --  Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
   Outer_Key  : constant Itb.Byte_Array :=
     Itb.Wrapper.Generate_Key (Itb.Wrapper.Aes_128_Ctr);
   N_Len      : constant Stream_Element_Offset :=
     Stream_Element_Offset
       (Itb.Wrapper.Nonce_Size (Itb.Wrapper.Aes_128_Ctr));
   Plain_F    : Ada.Streams.Stream_IO.File_Type;
   Inner_F    : Ada.Streams.Stream_IO.File_Type;
   Cipher_F   : Ada.Streams.Stream_IO.File_Type;
begin
   --  Stage 1: encrypt plaintext into a buffered inner-transcript file.
   Ada.Streams.Stream_IO.Open
     (Plain_F, Ada.Streams.Stream_IO.In_File, "/tmp/64mb.src");
   Ada.Streams.Stream_IO.Create
     (Inner_F, Ada.Streams.Stream_IO.Out_File, "/tmp/64mb.inner");
   Itb.Encryptor.Encrypt_Stream_Auth
     (Enc,
      Ada.Streams.Stream_IO.Stream (Plain_F),
      Ada.Streams.Stream_IO.Stream (Inner_F),
      Stream_Element_Offset (16 * 1024 * 1024));
   Ada.Streams.Stream_IO.Close (Plain_F);
   Ada.Streams.Stream_IO.Close (Inner_F);

   --  Stage 2: pump the inner ITB transcript through one wrap-stream
   --  session so the on-wire bytes carry no ITB framing.
   Ada.Streams.Stream_IO.Open
     (Inner_F, Ada.Streams.Stream_IO.In_File, "/tmp/64mb.inner");
   Ada.Streams.Stream_IO.Create
     (Cipher_F, Ada.Streams.Stream_IO.Out_File, "/tmp/64mb.enc");
   declare
      --  Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
      W         : Itb.Wrapper.Wrap_Stream_Writer;
      Out_Nonce : Itb.Byte_Array (1 .. N_Len);
      Buf       : Itb.Byte_Array (1 .. 1 * 1024 * 1024);
      Last      : Stream_Element_Offset;
      Cipher_S  : constant access Ada.Streams.Root_Stream_Type'Class :=
        Ada.Streams.Stream_IO.Stream (Cipher_F);
   begin
      Itb.Wrapper.Initialize
        (W, Itb.Wrapper.Aes_128_Ctr, Outer_Key, Out_Nonce);
      Ada.Streams.Root_Stream_Type'Class (Cipher_S.all).Write (Out_Nonce);
      loop
         Ada.Streams.Stream_IO.Read
           (Inner_F, Buf, Last);
         exit when Last < Buf'First;
         declare
            Encoded : Itb.Byte_Array (Buf'First .. Last);
            Out_Last : Stream_Element_Offset;
         begin
            Itb.Wrapper.Update
              (W, Buf (Buf'First .. Last), Encoded, Out_Last);
            Ada.Streams.Root_Stream_Type'Class (Cipher_S.all).Write
              (Encoded);
         end;
         exit when Last < Buf'Last;
      end loop;
      Itb.Wrapper.Close (W);
   end;
   Ada.Streams.Stream_IO.Close (Inner_F);
   Ada.Streams.Stream_IO.Close (Cipher_F);
   Itb.Encryptor.Close (Enc);
end;
```

**Recommended idiom for Single Message non-streaming calls.** When a Single Message `Itb.Encryptor.Encrypt` / `Decrypt` (or `Encrypt_Auth` / `Decrypt_Auth`) is invoked on plaintext approaching or exceeding ~8 MiB, the function-result `Byte_Array` lands on the calling task's stack by default, which can overflow the standard 8 MiB main-thread stack. The Build-In-Place (BIP) idiom routes the result onto the heap instead:

```ada
declare
   CT : Itb.Byte_Array_Access :=
     new Itb.Byte_Array'(Itb.Encryptor.Encrypt_Auth (Enc, Plaintext));
begin
   ...
   Itb.Free (CT);
end;
```

The streaming entry points (`Encrypt_Stream` / `Decrypt_Stream` / `Encrypt_Stream_Auth` / `Decrypt_Stream_Auth`) heap-allocate their per-chunk staging buffers internally, so the default stack suffices regardless of plaintext size — they are the cleaner alternative for large-data flows. As a defense-in-depth alternative, `bindings/ada/build.sh` carries a commented `-Wl,-z,stack-size=67108864` switch and `bindings/ada/itb.gpr`'s `Linker` package carries the matching commented line; uncommenting either bumps the executable stack reservation to 64 MiB for users who keep the non-BIP idiom.

**Build + run:**

```ada
--  <itb>/itb_stream_auth_example/example.gpr
with "<itb>/bindings/ada/itb.gpr";

project Example is
   for Source_Dirs use (".");
   for Object_Dir use "obj";
   for Exec_Dir use "obj";
   for Main use ("main.adb");

   package Compiler is
      for Default_Switches ("Ada") use
        ("-O2", "-g", "-gnatwa", "-gnat2022");
   end Compiler;
end Example;
```

```sh
cd <itb>/itb_stream_auth_example
alr exec --manifest <itb>/bindings/ada/alire.toml -- \
   gprbuild -P <itb>/itb_stream_auth_example/example.gpr
./obj/main
```

**Output (verified):**

```
Easy Mode src sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
Easy Mode dst sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
[OK] Easy Mode: 64 MiB roundtrip via stream-auth verified
```

---

**Low-Level Mode:**

Free subprograms in `Itb.Streams` take three `Itb.Seed.Seed` records plus an `Itb.MAC.MAC` (32-byte key drawn from `/dev/urandom` via a `Stream_IO`-opened device read) and stream through the same chunked-AEAD construction.

```ada
declare
   Noise : constant Itb.Seed.Seed := Itb.Seed.Make ("areion512", 1024);
   Data  : constant Itb.Seed.Seed := Itb.Seed.Make ("areion512", 1024);
   Start : constant Itb.Seed.Seed := Itb.Seed.Make ("areion512", 1024);
   Mac   : constant Itb.MAC.MAC :=
     Itb.MAC.Make ("hmac-blake3", Random_MAC_Key);
   --  Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
   Outer_Key : constant Itb.Byte_Array :=
     Itb.Wrapper.Generate_Key (Itb.Wrapper.Aes_128_Ctr);
   N_Len     : constant Stream_Element_Offset :=
     Stream_Element_Offset
       (Itb.Wrapper.Nonce_Size (Itb.Wrapper.Aes_128_Ctr));
   Plain_F  : Ada.Streams.Stream_IO.File_Type;
   Inner_F  : Ada.Streams.Stream_IO.File_Type;
   Cipher_F : Ada.Streams.Stream_IO.File_Type;
begin
   --  Stage 1: encrypt plaintext into a buffered inner-transcript file.
   Ada.Streams.Stream_IO.Open
     (Plain_F,  Ada.Streams.Stream_IO.In_File,  "/tmp/64mb.src");
   Ada.Streams.Stream_IO.Create
     (Inner_F,  Ada.Streams.Stream_IO.Out_File, "/tmp/64mb.inner");
   Itb.Streams.Encrypt_Stream_Auth
     (Noise, Data, Start, Mac,
      Ada.Streams.Stream_IO.Stream (Plain_F),
      Ada.Streams.Stream_IO.Stream (Inner_F),
      Stream_Element_Offset (16 * 1024 * 1024));
   Ada.Streams.Stream_IO.Close (Plain_F);
   Ada.Streams.Stream_IO.Close (Inner_F);

   --  Stage 2: pump the inner ITB transcript through one wrap-stream
   --  session so the on-wire bytes carry no ITB framing.
   Ada.Streams.Stream_IO.Open
     (Inner_F, Ada.Streams.Stream_IO.In_File, "/tmp/64mb.inner");
   Ada.Streams.Stream_IO.Create
     (Cipher_F, Ada.Streams.Stream_IO.Out_File, "/tmp/64mb.enc");
   declare
      --  Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
      W         : Itb.Wrapper.Wrap_Stream_Writer;
      Out_Nonce : Itb.Byte_Array (1 .. N_Len);
      Buf       : Itb.Byte_Array (1 .. 1 * 1024 * 1024);
      Last      : Stream_Element_Offset;
      Cipher_S  : constant access Ada.Streams.Root_Stream_Type'Class :=
        Ada.Streams.Stream_IO.Stream (Cipher_F);
   begin
      Itb.Wrapper.Initialize
        (W, Itb.Wrapper.Aes_128_Ctr, Outer_Key, Out_Nonce);
      Ada.Streams.Root_Stream_Type'Class (Cipher_S.all).Write (Out_Nonce);
      loop
         Ada.Streams.Stream_IO.Read (Inner_F, Buf, Last);
         exit when Last < Buf'First;
         declare
            Encoded  : Itb.Byte_Array (Buf'First .. Last);
            Out_Last : Stream_Element_Offset;
         begin
            Itb.Wrapper.Update
              (W, Buf (Buf'First .. Last), Encoded, Out_Last);
            Ada.Streams.Root_Stream_Type'Class (Cipher_S.all).Write
              (Encoded);
         end;
         exit when Last < Buf'Last;
      end loop;
      Itb.Wrapper.Close (W);
   end;
   Ada.Streams.Stream_IO.Close (Inner_F);
   Ada.Streams.Stream_IO.Close (Cipher_F);
end;
```

**Build + run:**

```sh
cd <itb>/itb_stream_auth_example
alr exec --manifest <itb>/bindings/ada/alire.toml -- \
   gprbuild -P <itb>/itb_stream_auth_example/example.gpr
./obj/main
```

**Output (verified):**

```
Low-Level src sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
Low-Level dst sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
[OK] Low-Level Mode: 64 MiB roundtrip via stream-auth verified
```

## Quick Start — `Itb.Encryptor` + HMAC-BLAKE3 (MAC Authenticated)

The high-level `Encryptor` (mirroring the
`github.com/everanium/itb/easy` Go sub-package) replaces the
seven-line setup ceremony of the lower-level
`Seed` / `Itb.Cipher.Encrypt` / `Itb.Cipher.Decrypt` path with one
constructor call: the encryptor allocates its own three (Single) or
seven (Triple) seeds plus MAC closure, snapshots the global
configuration into a per-instance Config, and exposes setters that
mutate only its own state without touching the process-wide
`Itb.Set_*` accessors. Two encryptors with different settings can
run concurrently without cross-contamination.

The MAC primitive is bound at construction time — the `Mac_Name`
parameter selects one of the registry names (`hmac-blake3` —
recommended default, `hmac-sha256`, `kmac256`). The encryptor
allocates a fresh 32-byte CSPRNG MAC key alongside the per-seed PRF
keys; `Itb.Encryptor.Export_State (Enc)` carries all of them in a
single JSON blob. On the receiver side,
`Itb.Encryptor.Import_State (Dec, Blob)` restores the MAC key
together with the seeds, so the encrypt-today / decrypt-tomorrow
flow is one method call per side.

When the `Mac_Name` argument is `""` (the default) the binding
substitutes `hmac-blake3` rather than forwarding the empty string
through to libitb's own default — HMAC-BLAKE3 measures the lightest
authenticated-mode overhead across the Easy Mode bench surface.

```ada
--  Sender

with Ada.Streams; use Ada.Streams;
with Ada.Text_IO;

with Itb;
with Itb.Encryptor;
with Itb.Errors;
with Itb.Wrapper;

procedure Sender is

   --  Helper — pack a String literal into a Byte_Array. Real code
   --  reads bytes from a file / socket / buffer; this is the
   --  inline form for the example.
   function To_Bytes (S : String) return Itb.Byte_Array is
      Result : Itb.Byte_Array (1 .. S'Length);
   begin
      for I in S'Range loop
         Result (Stream_Element_Offset (I - S'First + 1)) :=
           Stream_Element (Character'Pos (S (I)));
      end loop;
      return Result;
   end To_Bytes;

   Plaintext : constant Itb.Byte_Array :=
     To_Bytes ("any text or binary data - including 0x00 bytes");

   --  Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
   Outer_Key : constant Itb.Byte_Array :=
     Itb.Wrapper.Generate_Key (Itb.Wrapper.Aes_128_Ctr);

begin
   --  Per-instance configuration — mutates only this encryptor's
   --  Config. Two encryptors built side-by-side carry independent
   --  settings; process-wide Itb.Set_* accessors are NOT consulted
   --  after construction. Mode => 1 selects Single Ouroboros
   --  (3 seeds); Mode => 3 selects Triple Ouroboros (7 seeds).
   declare
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make
          (Primitive => "areion512",
           Key_Bits  => 2048,
           Mac_Name  => "hmac-blake3",
           Mode      => 1);
   begin
      Itb.Encryptor.Set_Nonce_Bits   (Enc, 512);   --  512-bit nonce (default: 128-bit)
      Itb.Encryptor.Set_Barrier_Fill (Enc, 4);     --  CSPRNG fill margin (default: 1, valid: 1, 2, 4, 8, 16, 32)
      Itb.Encryptor.Set_Bit_Soup     (Enc, 1);     --  optional bit-level split ("bit-soup"; default: 0 = byte-level)
                                                   --  auto-enabled for Single Ouroboros if Set_Lock_Soup (1) is on
      Itb.Encryptor.Set_Lock_Soup    (Enc, 1);     --  optional Insane Interlocked Mode: per-chunk PRF-keyed
                                                   --  bit-permutation overlay on top of bit-soup;
                                                   --  auto-enabled for Single Ouroboros if Set_Bit_Soup (1) is on

      --  Itb.Encryptor.Set_Lock_Seed (Enc, 1);    --  optional dedicated lockSeed for the bit-permutation
                                                   --  derivation channel - separates that PRF's keying
                                                   --  material from the noiseSeed-driven noise-injection
                                                   --  channel; auto-couples Set_Lock_Soup (1) +
                                                   --  Set_Bit_Soup (1). Adds one extra seed slot
                                                   --  (3 -> 4 for Single, 7 -> 8 for Triple). Must be
                                                   --  called BEFORE the first Encrypt_Auth - switching
                                                   --  mid-session raises Itb_Error /
                                                   --  Easy_LockSeed_After_Encrypt.

      --  Persistence blob - carries seeds + PRF keys + MAC key
      --  (and the dedicated lockSeed material when Set_Lock_Seed (1)
      --  is active).
      declare
         Blob : constant Itb.Byte_Array :=
           Itb.Encryptor.Export_State (Enc);
      begin
         Ada.Text_IO.Put_Line
           ("state blob:" & Stream_Element_Offset'Image (Blob'Length) & " bytes");
         Ada.Text_IO.Put_Line
           ("primitive: " & Itb.Encryptor.Primitive (Enc) &
            ", key_bits:" & Integer'Image (Itb.Encryptor.Key_Bits (Enc)) &
            ", mode: "    & Integer'Image (Itb.Encryptor.Mode (Enc)) &
            ", mac: "     & Itb.Encryptor.MAC_Name (Enc));

         --  Authenticated encrypt - 32-byte tag is computed across
         --  the entire decrypted capacity and embedded inside the
         --  RGBWYOPA container, preserving oracle-free deniability.
         declare
            Encrypted : Itb.Byte_Array :=
              Itb.Encryptor.Encrypt_Auth (Enc, Plaintext);
            N_Len     : constant Stream_Element_Offset :=
              Stream_Element_Offset
                (Itb.Wrapper.Nonce_Size (Itb.Wrapper.Aes_128_Ctr));
            Out_Nonce : Itb.Byte_Array (1 .. N_Len);
         begin
            Ada.Text_IO.Put_Line
              ("encrypted:" & Stream_Element_Offset'Image (Encrypted'Length) & " bytes");

            --  Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
            Itb.Wrapper.Wrap_In_Place
              (Itb.Wrapper.Aes_128_Ctr, Outer_Key, Encrypted, Out_Nonce);
            declare
               Wire : Itb.Byte_Array (1 .. N_Len + Encrypted'Length);
            begin
               Wire (1 .. N_Len) := Out_Nonce;
               Wire (N_Len + 1 .. Wire'Last) := Encrypted;
               Ada.Text_IO.Put_Line
                 ("wire:" & Stream_Element_Offset'Image (Wire'Length) & " bytes");
               --  Send Wire payload + Blob to the receiver.
            end;
         end;
      end;
   end;  --  Enc.Finalize fires here, libitb handle released, key
         --  material zeroed on the Go side, per-instance output
         --  cache wiped on the Ada side.
end Sender;
```

```ada
--  Receiver

with Ada.Streams; use Ada.Streams;
with Ada.Text_IO;

with Itb;
with Itb.Encryptor;
with Itb.Errors;
with Itb.Status;
with Itb.Wrapper;

procedure Receiver is
   Wire      : Itb.Byte_Array := ...;   --  received from the sender
   Blob      : Itb.Byte_Array := ...;   --  received from the sender
   Outer_Key : Itb.Byte_Array := ...;   --  agreed out-of-band with the sender
begin
   Itb.Set_Max_Workers (8);   --  limit to 8 CPU cores (default: 0 = all CPUs)

   --  Optional: peek at the blob's metadata before constructing a
   --  matching encryptor. Useful when the receiver multiplexes
   --  blobs of different shapes (different primitive / mode / MAC
   --  choices).
   declare
      Cfg : constant Itb.Encryptor.Peeked_Config :=
        Itb.Encryptor.Peek_Config (Blob);

      Dec : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make
          (Primitive => Ada.Strings.Unbounded.To_String (Cfg.Primitive),
           Key_Bits  => Cfg.Key_Bits,
           Mac_Name  => Ada.Strings.Unbounded.To_String (Cfg.MAC_Name),
           Mode      => Cfg.Mode);
   begin
      --  Itb.Encryptor.Import_State below automatically restores the
      --  full per-instance configuration (Nonce_Bits, Barrier_Fill,
      --  Bit_Soup, Lock_Soup, and the dedicated lockSeed material
      --  when sender's Set_Lock_Seed (1) was active). The Set_*
      --  lines below are kept for documentation - they show the
      --  knobs available for explicit pre-Import override.
      --  Barrier_Fill is asymmetric: a receiver-set value > 1 takes
      --  priority over the blob's barrier_fill (the receiver's
      --  heavier CSPRNG margin is preserved across Import).
      Itb.Encryptor.Set_Nonce_Bits   (Dec, 512);
      Itb.Encryptor.Set_Barrier_Fill (Dec, 4);
      Itb.Encryptor.Set_Bit_Soup     (Dec, 1);
      Itb.Encryptor.Set_Lock_Soup    (Dec, 1);

      --  Restore PRF keys, seed components, MAC key, and the
      --  per-instance configuration overrides from the saved blob.
      Itb.Encryptor.Import_State (Dec, Blob);

      --  Strip the per-stream nonce, recover the inner ITB
      --  ciphertext.
      declare
         Body_First : Stream_Element_Offset;
      begin
         Itb.Wrapper.Unwrap_In_Place
           (Itb.Wrapper.Aes_128_Ctr, Outer_Key, Wire, Body_First);
      end;

      --  Authenticated decrypt - any single-bit tamper triggers
      --  MAC failure (no oracle leak about which byte was tampered).
      --  Mismatch surfaces as Itb_Error with Status_Code =
      --  MAC_Failure, not a corrupted plaintext.
      declare
         Plaintext : constant Itb.Byte_Array :=
           Itb.Encryptor.Decrypt_Auth
             (Dec,
              Wire (Wire'First +
                    Stream_Element_Offset
                      (Itb.Wrapper.Nonce_Size (Itb.Wrapper.Aes_128_Ctr))
                    .. Wire'Last));
      begin
         Ada.Text_IO.Put_Line
           ("decrypted:" & Stream_Element_Offset'Image (Plaintext'Length) & " bytes");
      end;
   exception
      when E : Itb.Errors.Itb_Error =>
         if Itb.Errors.Status_Code (E) = Itb.Status.MAC_Failure then
            Ada.Text_IO.Put_Line
              ("MAC verification failed - tampered or wrong key");
         else
            raise;
         end if;
   end;
end Receiver;
```

## Quick Start — Mixed primitives (Different PRF per seed slot)

`Itb.Encryptor.Mixed_Single` and `Itb.Encryptor.Mixed_Triple`
accept per-slot primitive names — the noise / data / start (and
optional dedicated lockSeed) seed slots can use different PRF
primitives within the same native hash width. The mix-and-match-PRF
freedom of the lower-level path, surfaced through the high-level
`Encryptor` without forcing the caller off the Easy Mode
constructor. The state blob carries per-slot primitives + per-slot
PRF keys; the receiver constructs a matching encryptor with the
same arguments and calls `Import_State` to restore.

```ada
--  Sender

with Ada.Text_IO;

with Itb;
with Itb.Encryptor;
with Itb.Wrapper;

procedure Mixed_Sender is
   Plaintext : constant Itb.Byte_Array := ...;   --  payload bytes
   --  Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
   Outer_Key : constant Itb.Byte_Array :=
     Itb.Wrapper.Generate_Key (Itb.Wrapper.Aes_128_Ctr);
begin
   --  Per-slot primitive selection (Single Ouroboros, 3 + 1 slots).
   --  Every name must share the same native hash width - mixing
   --  widths raises Itb_Error / Seed_Width_Mix at construction
   --  time. Triple Ouroboros mirror - Itb.Encryptor.Mixed_Triple
   --  takes seven per-slot names (noise + 3 data + 3 start) plus
   --  the optional Prim_L lockSeed.
   declare
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Mixed_Single
          (Prim_N   => "blake3",       --  noiseSeed:  BLAKE3
           Prim_D   => "blake2s",      --  dataSeed:   BLAKE2s
           Prim_S   => "areion256",    --  startSeed:  Areion-SoEM-256
           Prim_L   => "blake2b256",   --  dedicated lockSeed
                                       --   (pass "" for no lockSeed slot)
           Key_Bits => 1024,
           Mac_Name => "hmac-blake3");
   begin
      --  Per-instance configuration applies as for
      --  Itb.Encryptor.Make (...).
      Itb.Encryptor.Set_Nonce_Bits   (Enc, 512);
      Itb.Encryptor.Set_Barrier_Fill (Enc, 4);
      --  Bit_Soup + Lock_Soup are auto-coupled on the on-direction
      --  by Prim_L above; explicit calls below are unnecessary but
      --  harmless if added.
      --  Itb.Encryptor.Set_Bit_Soup  (Enc, 1);
      --  Itb.Encryptor.Set_Lock_Soup (Enc, 1);

      --  Per-slot introspection - Primitive returns the literal
      --  "mixed" sentinel; Primitive_At (slot) returns each slot's
      --  name; Is_Mixed is the typed predicate. Slot ordering is
      --  canonical: 0 = noiseSeed, 1 = dataSeed, 2 = startSeed,
      --  3 = lockSeed (Single); Triple grows the middle range to
      --  7 slots + lockSeed.
      Ada.Text_IO.Put_Line
        ("mixed=" & Boolean'Image (Itb.Encryptor.Is_Mixed (Enc)) &
         " primitive=" & Itb.Encryptor.Primitive (Enc));
      for I in 0 .. 3 loop
         Ada.Text_IO.Put_Line
           ("  slot" & Integer'Image (I) & ": " &
            Itb.Encryptor.Primitive_At (Enc, I));
      end loop;

      declare
         Blob      : constant Itb.Byte_Array :=
           Itb.Encryptor.Export_State (Enc);
         Encrypted : Itb.Byte_Array :=
           Itb.Encryptor.Encrypt_Auth (Enc, Plaintext);
         N_Len     : constant Stream_Element_Offset :=
           Stream_Element_Offset
             (Itb.Wrapper.Nonce_Size (Itb.Wrapper.Aes_128_Ctr));
         Out_Nonce : Itb.Byte_Array (1 .. N_Len);
      begin
         --  Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
         Itb.Wrapper.Wrap_In_Place
           (Itb.Wrapper.Aes_128_Ctr, Outer_Key, Encrypted, Out_Nonce);
         declare
            Wire : Itb.Byte_Array (1 .. N_Len + Encrypted'Length);
         begin
            Wire (1 .. N_Len) := Out_Nonce;
            Wire (N_Len + 1 .. Wire'Last) := Encrypted;
            null;  --  Send Wire payload + Blob to the receiver.
         end;
      end;
   end;  --  Enc.Finalize fires here.
end Mixed_Sender;
```

The receiver constructs a matching mixed encryptor with the same
per-slot primitive names plus `Key_Bits` and `Mac_Name`, then calls
`Itb.Encryptor.Import_State (Dec, Blob)`. `Import_State` validates
each per-slot primitive against the receiver's bound spec; mismatches
raise `Itb.Errors.Itb_Easy_Mismatch_Error` with the offending field
name reachable via `Itb.Errors.Field`.

## Quick Start — Triple Ouroboros

Triple Ouroboros (3× security: P × 2^(3×Key_Bits)) takes seven seeds
(one shared `noiseSeed` plus three `dataSeed` and three `startSeed`)
on the low-level path, all wrapped behind a single `Encryptor` call
when `Mode => 3` is passed to the constructor.

```ada
with Itb;
with Itb.Encryptor;
with Itb.Wrapper;

procedure Triple_Demo is
   Plaintext : constant Itb.Byte_Array := ...;   --  payload bytes

   --  Mode => 3 selects Triple Ouroboros. All other constructor
   --  arguments behave identically to the Single (Mode => 1) case
   --  shown above.
   Enc : Itb.Encryptor.Encryptor :=
     Itb.Encryptor.Make
       (Primitive => "areion512",
        Key_Bits  => 2048,
        Mac_Name  => "hmac-blake3",
        Mode      => 3);

   --  Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
   Outer_Key : constant Itb.Byte_Array :=
     Itb.Wrapper.Generate_Key (Itb.Wrapper.Aes_128_Ctr);

   Encrypted : Itb.Byte_Array :=
     Itb.Encryptor.Encrypt_Auth (Enc, Plaintext);
   N_Len     : constant Stream_Element_Offset :=
     Stream_Element_Offset
       (Itb.Wrapper.Nonce_Size (Itb.Wrapper.Aes_128_Ctr));
   Out_Nonce : Itb.Byte_Array (1 .. N_Len);
begin
   --  Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
   Itb.Wrapper.Wrap_In_Place
     (Itb.Wrapper.Aes_128_Ctr, Outer_Key, Encrypted, Out_Nonce);
   declare
      Wire       : Itb.Byte_Array (1 .. N_Len + Encrypted'Length);
      Body_First : Stream_Element_Offset;
   begin
      Wire (1 .. N_Len) := Out_Nonce;
      Wire (N_Len + 1 .. Wire'Last) := Encrypted;

      --  Receiver mirror — strip the per-stream nonce, recover the
      --  inner ITB ciphertext, decrypt.
      Itb.Wrapper.Unwrap_In_Place
        (Itb.Wrapper.Aes_128_Ctr, Outer_Key, Wire, Body_First);
      declare
         Decrypted : constant Itb.Byte_Array :=
           Itb.Encryptor.Decrypt_Auth
             (Enc, Wire (Body_First .. Wire'Last));
      begin
         pragma Assert (Decrypted = Plaintext);
      end;
   end;
end Triple_Demo;
```

The seven-seed split is internal to the encryptor; the on-wire
ciphertext format is identical in shape to Single Ouroboros — only
the internal payload split / interleave differs. Mixed-primitive
Triple is reachable via `Itb.Encryptor.Mixed_Triple`.

## Quick Start — Areion-SoEM-512 + HMAC-BLAKE3 (Low-Level, MAC Authenticated)

The lower-level path uses explicit `Itb.Seed.Seed` handles for the
noise / data / start trio plus an optional dedicated `Itb.Seed.Seed`
wired in through `Itb.Seed.Attach_Lock_Seed`. Useful when the caller
needs full control over per-slot keying (e.g. PRF material stored in
an HSM) or when slotting into the existing Go `itb.Encrypt` /
`itb.Decrypt` call surface from an Ada client. The high-level
`Itb.Encryptor.Encryptor` above wraps this same path with one
constructor call.

```ada
--  Sender

with Ada.Streams; use Ada.Streams;
with Ada.Text_IO;

with Itb;
with Itb.Blob;
with Itb.Cipher;
with Itb.MAC;
with Itb.Seed;
with Itb.Wrapper;

procedure Lowlevel_Sender is
   use type Itb.Blob.Export_Opts;

   Plaintext : constant Itb.Byte_Array := ...;   --  payload bytes
   Mac_Key   : constant Itb.Byte_Array (1 .. 32) := [others => 0];
   --  Real code should pull Mac_Key from a CSPRNG; the zero key here
   --  is for example purposes only.
   --  Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
   Outer_Key : constant Itb.Byte_Array :=
     Itb.Wrapper.Generate_Key (Itb.Wrapper.Aes_128_Ctr);
begin
   --  Optional: global configuration (all process-wide, atomic).
   Itb.Set_Max_Workers   (8);   --  limit to 8 CPU cores (default: 0 = all CPUs)
   Itb.Set_Nonce_Bits    (512); --  512-bit nonce (default: 128-bit)
   Itb.Set_Barrier_Fill  (4);   --  CSPRNG fill margin (default: 1, valid: 1, 2, 4, 8, 16, 32)
   Itb.Set_Bit_Soup      (1);   --  optional bit-level split ("bit-soup"; default: 0 = byte-level)
                                --  automatically enabled for Single Ouroboros if
                                --  Itb.Set_Lock_Soup (1) is enabled or vice versa
   Itb.Set_Lock_Soup     (1);   --  optional Insane Interlocked Mode: per-chunk PRF-keyed
                                --  bit-permutation overlay on top of bit-soup;
                                --  automatically enabled for Single Ouroboros if
                                --  Itb.Set_Bit_Soup (1) is enabled or vice versa

   declare
      --  Three independent CSPRNG-keyed Areion-SoEM-512 seeds. Each
      --  Seed pre-keys its primitive once at construction; the
      --  C ABI / FFI layer auto-wires the AVX-512 + VAES + ILP +
      --  ZMM-batched chain-absorb dispatch through Seed.BatchHash -
      --  no manual batched-arm attachment is required on the Ada
      --  side.
      Ns : constant Itb.Seed.Seed := Itb.Seed.Make ("areion512", 2048);
      Ds : constant Itb.Seed.Seed := Itb.Seed.Make ("areion512", 2048);
      Ss : constant Itb.Seed.Seed := Itb.Seed.Make ("areion512", 2048);

      --  Optional: dedicated lockSeed for the bit-permutation
      --  derivation channel. Separates that PRF's keying material
      --  from the noiseSeed-driven noise-injection channel without
      --  changing the public Encrypt / Decrypt signatures. The
      --  bit-permutation overlay must be engaged
      --  (Itb.Set_Bit_Soup (1) or Itb.Set_Lock_Soup (1) - both
      --  already on above) before the first encrypt; the build-PRF
      --  guard panics on encrypt-time when an attach is present
      --  without either flag.
      Ls : constant Itb.Seed.Seed := Itb.Seed.Make ("areion512", 2048);

      --  HMAC-BLAKE3 - 32-byte CSPRNG key, 32-byte tag.
      M : constant Itb.MAC.MAC := Itb.MAC.Make ("hmac-blake3", Mac_Key);
   begin
      Itb.Seed.Attach_Lock_Seed (Ns, Ls);

      --  Authenticated encrypt - 32-byte tag is computed across the
      --  entire decrypted capacity and embedded inside the RGBWYOPA
      --  container, preserving oracle-free deniability.
      declare
         Encrypted : Itb.Byte_Array :=
           Itb.Cipher.Encrypt_Auth (Ns, Ds, Ss, M, Plaintext);
         N_Len     : constant Stream_Element_Offset :=
           Stream_Element_Offset
             (Itb.Wrapper.Nonce_Size (Itb.Wrapper.Aes_128_Ctr));
         Out_Nonce : Itb.Byte_Array (1 .. N_Len);
      begin
         Ada.Text_IO.Put_Line
           ("encrypted:" & Stream_Element_Offset'Image (Encrypted'Length) & " bytes");

         --  Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
         Itb.Wrapper.Wrap_In_Place
           (Itb.Wrapper.Aes_128_Ctr, Outer_Key, Encrypted, Out_Nonce);
         declare
            Wire : Itb.Byte_Array (1 .. N_Len + Encrypted'Length);
         begin
            Wire (1 .. N_Len) := Out_Nonce;
            Wire (N_Len + 1 .. Wire'Last) := Encrypted;
            Ada.Text_IO.Put_Line
              ("wire:" & Stream_Element_Offset'Image (Wire'Length) & " bytes");
         end;

         --  Cross-process persistence: Itb.Blob.Blob512 packs every
         --  seed's hash key + components, the optional dedicated
         --  lockSeed, and the MAC key + name into one JSON blob
         --  alongside the captured process-wide globals.
         --  Opt_LockSeed / Opt_Mac opt the corresponding sections
         --  in. The Export_Opts type is modular - the `or` operator
         --  combines flags (`+` works as well; both come from the
         --  modular type).
         declare
            B : Itb.Blob.Blob512 := Itb.Blob.New_Blob512;
         begin
            Itb.Blob.Set_Key        (B, Itb.Blob.Slot_N, Itb.Seed.Get_Hash_Key (Ns));
            Itb.Blob.Set_Components (B, Itb.Blob.Slot_N, Itb.Seed.Get_Components (Ns));
            Itb.Blob.Set_Key        (B, Itb.Blob.Slot_D, Itb.Seed.Get_Hash_Key (Ds));
            Itb.Blob.Set_Components (B, Itb.Blob.Slot_D, Itb.Seed.Get_Components (Ds));
            Itb.Blob.Set_Key        (B, Itb.Blob.Slot_S, Itb.Seed.Get_Hash_Key (Ss));
            Itb.Blob.Set_Components (B, Itb.Blob.Slot_S, Itb.Seed.Get_Components (Ss));
            Itb.Blob.Set_Key        (B, Itb.Blob.Slot_L, Itb.Seed.Get_Hash_Key (Ls));
            Itb.Blob.Set_Components (B, Itb.Blob.Slot_L, Itb.Seed.Get_Components (Ls));
            Itb.Blob.Set_MAC_Key    (B, Mac_Key);
            Itb.Blob.Set_MAC_Name   (B, "hmac-blake3");

            declare
               Blob_Bytes : constant Itb.Byte_Array :=
                 Itb.Blob.Export
                   (B, Itb.Blob.Opt_LockSeed or Itb.Blob.Opt_Mac);
            begin
               Ada.Text_IO.Put_Line
                 ("persistence blob:" &
                  Stream_Element_Offset'Image (Blob_Bytes'Length) & " bytes");
               --  Send Encrypted payload + Blob_Bytes to the
               --  receiver.
            end;
         end;
      end;
   end;  --  Ns / Ds / Ss / Ls / M / B all finalised here, libitb
         --  handles released, key material zeroed.
end Lowlevel_Sender;
```

The receiver mirror: construct a fresh `Itb.Blob.Blob512`, call
`Itb.Blob.Import (B, Blob_Bytes)` to restore per-slot hash keys +
components AND apply the captured globals (`Nonce_Bits` /
`Barrier_Fill` / `Bit_Soup` / `Lock_Soup`) via the process-wide
setters; rebuild each `Itb.Seed.Seed` via `Itb.Seed.From_Components
(Hash_Name, Itb.Blob.Get_Components (B, Slot), Itb.Blob.Get_Key (B,
Slot))`; rebuild the MAC via `Itb.MAC.Make (Itb.Blob.Get_MAC_Name
(B), Itb.Blob.Get_MAC_Key (B))`; then `Itb.Cipher.Decrypt_Auth (Ns,
Ds, Ss, M, Encrypted)`.

## Streams — chunked I/O over Ada.Streams

`Itb.Streams.Stream_Encryptor` / `Stream_Decryptor` (and the
seven-seed counterparts `Stream_Encryptor_Triple` /
`Stream_Decryptor_Triple`) wrap the Single Message Encrypt / Decrypt API
behind a `Write_Plaintext` / `Read_Plaintext`-driven chunked I/O
surface. ITB ciphertexts cap at ~64 MB plaintext per chunk;
streaming larger payloads slices the input into chunks at the
binding layer, encrypts each chunk through the regular FFI path,
and concatenates the results. Memory peak is bounded by `Chunk_Size`
(default `Itb.Streams.Default_Chunk_Size` = 16 MiB) regardless of
the total payload length.

The wrappers do not derive from `Ada.Streams.Root_Stream_Type` —
that would overload the standard `Stream_IO` `Read` / `Write`
semantics ambiguously with the ITB encrypt / decrypt pipeline.
Instead they accept a caller-owned
`Ada.Streams.Root_Stream_Type'Class` access (the underlying
writable / readable byte sink / source) at construction and expose
explicit `Write_Plaintext` / `Read_Plaintext` primitives that flow
plaintext through the (encrypt → underlying stream) or (underlying
stream → decrypt) pipeline. The constructors take `Itb.Seed.Seed`
handles directly — not an `Encryptor` instance — mirroring the
low-level `(noise, data, start)` triple shape used by every other
binding's stream wrapper.

**Seed lifetime contract.** Every `Itb.Seed.Seed` passed to `Make`
/ `Make_Triple` (and to the convenience drivers `Encrypt_Stream` /
`Decrypt_Stream` / their Triple variants) must remain in scope —
un-finalized — for the entire lifetime of the resulting stream
wrapper. The wrappers cache the raw libitb handles internally;
finalising the originating Seed before the stream finishes its
work would free the handle while the stream is still using it (a
stochastic use-after-free). Ada relies on caller discipline, the
same way `Itb.Seed.Attach_Lock_Seed` already does for the dedicated
lockSeed channel.

```ada
with Ada.Streams; use Ada.Streams;
with Ada.Streams.Stream_IO;

with Itb;
with Itb.Seed;
with Itb.Streams;
with Itb.Wrapper;

procedure Stream_Demo is
   N : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
   D : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
   S : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);

   --  Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
   Outer_Key : constant Itb.Byte_Array :=
     Itb.Wrapper.Generate_Key (Itb.Wrapper.Aes_128_Ctr);
   N_Len : constant Stream_Element_Offset :=
     Stream_Element_Offset
       (Itb.Wrapper.Nonce_Size (Itb.Wrapper.Aes_128_Ctr));

   Inner_File : aliased Ada.Streams.Stream_IO.File_Type;
   Sink_File  : aliased Ada.Streams.Stream_IO.File_Type;
begin
   --  Stage 1: open an inner-transcript sink file, attach a
   --  Stream_Encryptor, push plaintext through Write_Plaintext,
   --  Finish to flush the trailing partial chunk.
   Ada.Streams.Stream_IO.Create
     (Inner_File, Ada.Streams.Stream_IO.Out_File, "ciphertext.inner");
   declare
      Inner : constant access Ada.Streams.Root_Stream_Type'Class :=
        Ada.Streams.Stream_IO.Stream (Inner_File);

      Enc : Itb.Streams.Stream_Encryptor :=
        Itb.Streams.Make
          (Noise      => N,
           Data       => D,
           Start      => S,
           Sink       => Inner,
           Chunk_Size => 1 * 1024 * 1024);   --  1 MiB chunks
   begin
      Itb.Streams.Write_Plaintext (Enc, Plaintext_Chunk_1);
      Itb.Streams.Write_Plaintext (Enc, Plaintext_Chunk_2);
      Itb.Streams.Finish (Enc);
   end;  --  Enc.Finalize fires here; final chunk already flushed.
   Ada.Streams.Stream_IO.Close (Inner_File);

   --  Stage 2: pump the inner ITB transcript through one wrap-stream
   --  session so the on-wire bytes carry no ITB framing.
   Ada.Streams.Stream_IO.Open
     (Inner_File, Ada.Streams.Stream_IO.In_File, "ciphertext.inner");
   Ada.Streams.Stream_IO.Create
     (Sink_File, Ada.Streams.Stream_IO.Out_File, "ciphertext.bin");
   declare
      --  Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
      W         : Itb.Wrapper.Wrap_Stream_Writer;
      Out_Nonce : Itb.Byte_Array (1 .. N_Len);
      Buf       : Itb.Byte_Array (1 .. 1 * 1024 * 1024);
      Last      : Stream_Element_Offset;
      Sink      : constant access Ada.Streams.Root_Stream_Type'Class :=
        Ada.Streams.Stream_IO.Stream (Sink_File);
   begin
      Itb.Wrapper.Initialize
        (W, Itb.Wrapper.Aes_128_Ctr, Outer_Key, Out_Nonce);
      Ada.Streams.Root_Stream_Type'Class (Sink.all).Write (Out_Nonce);
      loop
         Ada.Streams.Stream_IO.Read (Inner_File, Buf, Last);
         exit when Last < Buf'First;
         declare
            Encoded  : Itb.Byte_Array (Buf'First .. Last);
            Out_Last : Stream_Element_Offset;
         begin
            Itb.Wrapper.Update
              (W, Buf (Buf'First .. Last), Encoded, Out_Last);
            Ada.Streams.Root_Stream_Type'Class (Sink.all).Write (Encoded);
         end;
         exit when Last < Buf'Last;
      end loop;
      Itb.Wrapper.Close (W);
   end;
   Ada.Streams.Stream_IO.Close (Inner_File);
   Ada.Streams.Stream_IO.Close (Sink_File);
end Stream_Demo;
```

For driving an encrypt or decrypt straight off a source / sink stream
pair, the convenience wrappers `Itb.Streams.Encrypt_Stream` /
`Itb.Streams.Decrypt_Stream` (plus the
`Encrypt_Stream_Triple` / `Decrypt_Stream_Triple` counterparts) loop
until EOF internally — accept a `Source` access plus a `Sink`
access, do the chunked encrypt / decrypt, and return when the
source is drained.

Switching `Itb.Set_Nonce_Bits` mid-stream produces a chunk header
layout the paired decryptor (which snapshots `Itb.Header_Size` at
construction) cannot parse — the nonce size must be stable for the
lifetime of one stream pair.

## Native Blob — low-level state persistence

`Itb.Blob.Blob128` / `Blob256` / `Blob512` wrap the libitb Native
Blob C ABI: a width-specific container that packs the low-level
encryptor material (per-seed hash key + components + optional
dedicated lockSeed + optional MAC key + name) plus the captured
process-wide configuration into one self-describing JSON blob.
Used on the lower-level encrypt / decrypt path where each seed
slot may carry a different primitive — the high-level
`Itb.Encryptor.Export_State` wraps a narrower
one-primitive-per-encryptor surface that uses the same wire format
under the hood.

Slot identifiers are exposed as named constants on
`Itb.Blob`: `Slot_N` / `Slot_D` / `Slot_S` / `Slot_L` for the
Single Ouroboros + LockSeed surface; `Slot_D1` / `Slot_D2` /
`Slot_D3` / `Slot_S1` / `Slot_S2` / `Slot_S3` for the Triple
Ouroboros surface (with `Slot_N` and `Slot_L` shared between modes).

Export options use the modular `Itb.Blob.Export_Opts` type with
disjoint single-bit constants `Opt_None` / `Opt_LockSeed` /
`Opt_Mac`; consumers add `use type Itb.Blob.Export_Opts;` to bring
the `or` and `+` operators into scope and combine flags via either:

```ada
use type Itb.Blob.Export_Opts;
...
declare
   Opts_LS_Mac : constant Itb.Blob.Export_Opts :=
     Itb.Blob.Opt_LockSeed or Itb.Blob.Opt_Mac;
   Bytes : constant Itb.Byte_Array :=
     Itb.Blob.Export (B, Opts_LS_Mac);
begin
   ...
end;
```

The blob is mode-discriminated: `Itb.Blob.Export` packs Single
material; `Itb.Blob.Export_3` packs Triple material; the matching
`Itb.Blob.Import` / `Itb.Blob.Import_3` receivers reject the wrong
importer with `Itb.Errors.Itb_Blob_Mode_Mismatch_Error`.

## Hash primitives (Single / Triple)

Names match the canonical `hashes/` registry. Listed below in the
canonical primitive ordering used across ITB documentation —
**AES-CMAC**, **SipHash-2-4**, **ChaCha20**, **Areion-SoEM-256**,
**BLAKE2s**, **BLAKE3**, **BLAKE2b-256**, **BLAKE2b-512**,
**Areion-SoEM-512** — the FFI names are `aescmac`, `siphash24`,
`chacha20`, `areion256`, `blake2s`, `blake3`, `blake2b256`,
`blake2b512`, `areion512`. Triple Ouroboros (3× security) takes
seven seeds (one shared `noiseSeed` plus three `dataSeed` and three
`startSeed`) via `Itb.Cipher.Encrypt_Triple` /
`Itb.Cipher.Decrypt_Triple` and the authenticated counterparts
`Itb.Cipher.Encrypt_Auth_Triple` /
`Itb.Cipher.Decrypt_Auth_Triple`. Streaming counterparts:
`Itb.Streams.Stream_Encryptor_Triple` / `Stream_Decryptor_Triple` /
`Itb.Streams.Encrypt_Stream_Triple` /
`Itb.Streams.Decrypt_Stream_Triple`.

| Primitive | FFI name | Native width (bits) | Fixed key size (bytes) |
|---|---|---|---|
| **AES-CMAC** | `aescmac` | 128 | 16 |
| **SipHash-2-4** | `siphash24` | 128 | 0 (no internal fixed key) |
| **ChaCha20** | `chacha20` | 256 | 32 |
| **Areion-SoEM-256** | `areion256` | 256 | 32 |
| **BLAKE2s** | `blake2s` | 256 | 32 |
| **BLAKE3** | `blake3` | 256 | 32 |
| **BLAKE2b-256** | `blake2b256` | 256 | 32 |
| **BLAKE2b-512** | `blake2b512` | 512 | 64 |
| **Areion-SoEM-512** | `areion512` | 512 | 64 |

SipHash-2-4 is the one primitive without an internal fixed key —
its keying material is the seed components themselves. `Itb.Seed.
Get_Hash_Key (Self)` returns an empty `Byte_Array` for a SipHash-2-4
seed; check `Itb.Encryptor.Has_PRF_Keys (Self)` before calling
`Get_PRF_Key` on the per-slot encryptor accessor.

All seeds passed to one `Itb.Cipher.Encrypt` / `Decrypt` call must
share the same native hash width. Mixing widths raises
`Itb.Errors.Itb_Error` with `Status_Code = Itb.Status.Seed_Width_Mix`.

## MAC primitives

Names match the libitb MAC registry; ordering matches that registry's declaration order.

| MAC | Key bytes | Tag bytes | Underlying primitive |
|---|---|---|---|
| `kmac256` | 32 | 32 | KMAC256 (Keccak-derived) |
| `hmac-sha256` | 32 | 32 | HMAC over SHA-256 |
| `hmac-blake3` | 32 | 32 | HMAC over BLAKE3 |

`kmac256` and `hmac-sha256` accept keys 16 bytes and longer; the binding fleet's tests and examples use 32 bytes uniformly across primitives for cross-binding consistency. `hmac-blake3` requires exactly 32 bytes by construction.

## Process-wide configuration

Every setter takes effect for all subsequent encrypt / decrypt
calls in the process. Out-of-range values raise
`Itb.Errors.Itb_Error` with `Status_Code = Itb.Status.Bad_Input`
rather than crashing.

| Procedure | Accepted values | Default |
|---|---|---|
| `Itb.Set_Max_Workers (N)` | non-negative Integer | 0 (auto) |
| `Itb.Set_Nonce_Bits (N)` | 128, 256, 512 | 128 |
| `Itb.Set_Barrier_Fill (N)` | 1, 2, 4, 8, 16, 32 | 1 |
| `Itb.Set_Bit_Soup (Mode)` | 0 (off), non-zero (on) | 0 |
| `Itb.Set_Lock_Soup (Mode)` | 0 (off), non-zero (on) | 0 |

Mutating these affects every `Encryptor` constructed AFTER the
call; pre-existing `Encryptor` instances snapshot the configuration
at construction time and continue to use their per-instance Config
unaffected.

Read-only library metadata: `Itb.Max_Key_Bits`, `Itb.Channels`,
`Itb.Header_Size`, `Itb.Version`. For low-level chunk parsing (e.g.
when implementing custom file formats around ITB chunks):
`Itb.Parse_Chunk_Len (Header)` inspects the fixed-size chunk header
and returns the chunk's total on-the-wire length;
`Itb.Header_Size` returns the active header byte count
(20 / 36 / 68 for nonce sizes 128 / 256 / 512 bits).

MAC names available via `Itb.List_MACs`: `kmac256`, `hmac-sha256`,
`hmac-blake3`. Hash names via `Itb.List_Hashes`.

## Concurrency

The libitb shared library exposes process-wide configuration through
a small set of atomics (`Itb.Set_Nonce_Bits`,
`Itb.Set_Barrier_Fill`, `Itb.Set_Bit_Soup`, `Itb.Set_Lock_Soup`,
`Itb.Set_Max_Workers`). Multiple Ada tasks calling these setters
concurrently without external coordination will race for the final
value visible to subsequent encrypt / decrypt calls — serialise the
mutators behind a protected object (or set them once at startup
before the worker tasks are activated) when several tasks need to
touch them.

Per-encryptor configuration via `Itb.Encryptor.Set_Nonce_Bits` /
`Set_Barrier_Fill` / `Set_Bit_Soup` / `Set_Lock_Soup` mutates only
that handle's Config copy and is safe to call from the owning task
without affecting other `Encryptor` instances. The cipher methods
(`Itb.Encryptor.Encrypt` / `Decrypt` / `Encrypt_Auth` /
`Decrypt_Auth`) write into a per-instance output-buffer cache;
sharing one `Encryptor` across tasks requires external
synchronisation (a protected object wrapping the cipher call, or a
task-safe handle pool). Distinct `Encryptor` handles, each owned by
one task, run independently against the libitb worker pool.

By contrast, the low-level cipher free functions
(`Itb.Cipher.Encrypt` / `Decrypt` / `Encrypt_Auth` / `Decrypt_Auth`
plus the Triple counterparts) allocate output per call and are
**task-safe** under concurrent invocation on the same `Seed`
handles — libitb's worker pool dispatches them independently. Two
exceptions: `Itb.Seed.Attach_Lock_Seed` mutates the noise Seed and
must not race against an in-flight cipher call on it, and the
process-wide setters above stay process-global.

The `Itb.Seed.Seed`, `Itb.MAC.MAC`, `Itb.Encryptor.Encryptor`,
`Itb.Blob.Blob128` / `Blob256` / `Blob512` types are
`Limited_Controlled` — passed by reference, never copied. The
`Limited_Controlled` lifecycle is deterministic: `Finalize` fires
at scope exit on the task that owns the variable, releasing the
underlying libitb handle and zeroing key material. libitb's own
cgo handle table is internally mutex-protected, so crossing a
handle reference across tasks (e.g. via a protected object) is
sound at the FFI layer — the constraint is the binding-side
output-buffer cache, not the libitb handle itself.

The diagnostic accessors `Itb.Errors.Status_Code` /
`Itb.Errors.Field` / `Itb.Errors.Message` read structured payload
attached to the exception by `Itb.Errors.Raise_For` at the moment
of the failing call — task-safe by construction. The underlying
libitb diagnostic state read by `ITB_LastError` /
`ITB_Easy_LastMismatchField` follows the C `errno` discipline and
is racy; the Ada wrapper captures both at the failing call site
into the structured payload before any other task can overwrite
them.

## Error model

Every failure surfaces as one of the typed exceptions defined in
`Itb.Errors`:

| Exception | Surfaced when |
|---|---|
| `Itb_Error` | Base exception for every non-OK status that does not have a more specific typed exception below. |
| `Itb_Easy_Mismatch_Error` | Easy Mode encryptor: persisted-config field disagrees with the receiving encryptor on `Import_State` / `Peek_Config`. The mismatched JSON field name is reachable via `Itb.Errors.Field`. |
| `Itb_Blob_Mode_Mismatch_Error` | Native Blob: persisted mode (Single / Triple) or width does not match the receiving Blob. |
| `Itb_Blob_Malformed_Error` | Native Blob: payload fails internal sanity checks (magic / CRC / structural). |
| `Itb_Blob_Version_Too_New_Error` | Native Blob: persisted format version is newer than this build of libitb knows how to parse. |

The structured-payload accessors `Itb.Errors.Status_Code`,
`Itb.Errors.Field`, and `Itb.Errors.Message` decode the libitb
status code, the optional mismatch field name, and the textual
diagnostic from the exception occurrence. Match against the named
status constants exposed in `Itb.Status` (24 codes total —
`Itb.Status.OK`, `Bad_Hash`, `Bad_Input`, `MAC_Failure`,
`Easy_Mismatch`, `Blob_Malformed`, ...) for selective `exception`
handlers:

```ada
with Itb;
with Itb.Errors;
with Itb.MAC;
with Itb.Status;

procedure Demo is
begin
   declare
      M : constant Itb.MAC.MAC :=
        Itb.MAC.Make ("nonsense", [1 .. 32 => 0]);
   begin
      null;
   end;
exception
   when E : Itb.Errors.Itb_Error =>
      if Itb.Errors.Status_Code (E) = Itb.Status.Bad_MAC then
         --  e.code == STATUS_BAD_MAC
         null;
      else
         raise;
      end if;
end Demo;
```

The structured payload attaches at the moment of the failing call,
so `Status_Code (E)` / `Field (E)` / `Message (E)` are stable across
intervening task-induced reads of libitb's own diagnostic globals.

**Note:** empty plaintext / ciphertext is rejected by libitb itself
with `Itb_Error` carrying `Status_Code = Encrypt_Failed`
("itb: empty data") on every cipher entry point. Pass at least one
byte.

### Status codes

| Code | Name | Description |
|---|---|---|
| 0 | `Itb.Status.OK` | Success — the only non-failure return value |
| 1 | `Itb.Status.Bad_Hash` | Unknown hash primitive name |
| 2 | `Itb.Status.Bad_Key_Bits` | ITB key width invalid for the chosen primitive |
| 3 | `Itb.Status.Bad_Handle` | FFI handle invalid or already freed |
| 4 | `Itb.Status.Bad_Input` | Generic shape / range / domain violation on a call argument |
| 5 | `Itb.Status.Buffer_Too_Small` | Output buffer cap below required size; probe-then-allocate idiom |
| 6 | `Itb.Status.Encrypt_Failed` | Encrypt path raised on the Go side (rare; structural / OOM) |
| 7 | `Itb.Status.Decrypt_Failed` | Decrypt path raised on the Go side (corrupt ciphertext shape) |
| 8 | `Itb.Status.Seed_Width_Mix` | Seeds passed to one call do not share the same native hash width |
| 9 | `Itb.Status.Bad_MAC` | Unknown MAC name or key-length violates the primitive's `Min_Key_Bytes` |
| 10 | `Itb.Status.MAC_Failure` | MAC verification failed — tampered ciphertext or wrong MAC key |
| 11 | `Itb.Status.Easy_Closed` | Easy Mode encryptor call after `Close` |
| 12 | `Itb.Status.Easy_Malformed` | Easy Mode `Import_State` blob fails JSON parse / structural check |
| 13 | `Itb.Status.Easy_Version_Too_New` | Easy Mode blob version field higher than this build supports |
| 14 | `Itb.Status.Easy_Unknown_Primitive` | Easy Mode blob references a primitive this build does not know |
| 15 | `Itb.Status.Easy_Unknown_MAC` | Easy Mode blob references a MAC this build does not know |
| 16 | `Itb.Status.Easy_Bad_Key_Bits` | Easy Mode blob's `key_bits` invalid for its primitive |
| 17 | `Itb.Status.Easy_Mismatch` | Easy Mode blob disagrees with the receiver on `primitive` / `key_bits` / `mode` / `mac`; field name reachable via `Itb.Errors.Field` |
| 18 | `Itb.Status.Easy_LockSeed_After_Encrypt` | `Set_Lock_Seed (1)` called after the first encrypt — must precede the first ciphertext |
| 19 | `Itb.Status.Blob_Mode_Mismatch` | Native Blob importer received a Single blob into a Triple receiver (or vice versa) |
| 20 | `Itb.Status.Blob_Malformed` | Native Blob payload fails JSON parse / magic / structural check |
| 21 | `Itb.Status.Blob_Version_Too_New` | Native Blob version field higher than this libitb build supports |
| 22 | `Itb.Status.Blob_Too_Many_Opts` | Native Blob export opts mask carries unsupported bits |
| 23 | `Itb.Status.Stream_Truncated` | Streaming AEAD transcript truncated before the terminator chunk; raised as `Itb_Stream_Truncated_Error` |
| 24 | `Itb.Status.Stream_After_Final` | Streaming AEAD transcript carries chunk bytes after the terminator; raised as `Itb_Stream_After_Final_Error` |
| 99 | `Itb.Status.Internal` | Generic "internal" sentinel for paths the caller cannot recover from at the binding layer |

## Constraints

- **Ada 2022 minimum.** The `itb.gpr` project file passes
  `-gnat2022` to the compiler; the wrapper layer uses
  `Static_Predicate`, expression functions, `'Image` on user-defined
  types, and other Ada 2022 features. Earlier dialects do not compile
  the wrapper.
- **GNAT FSF ≥ 13.** `alire.toml` declares `gnat (>=13)`; older GNAT
  releases lack full Ada 2022 support.
- **Alire toolchain manager.** The recommended build flow uses
  Alire's isolated `gnat_native` + `gprbuild` toolchain (selected via
  `alr toolchain --select`); a system-wide GNAT FSF install also
  works for builds that bypass Alire.
- **Single library project.** All consumer-visible declarations live
  under `src/Itb.*`; the FFI substrate (`Itb.Sys`) is kept separate
  so audits can read it independently.
- **libitb.so required at runtime.** The project links against
  `dist/<os>-<arch>/libitb.<ext>` via the `Linker_Options` declared
  in `itb.gpr` — the shared library must be built first and reachable
  through the loader's search path (compile-time `-L` plus runtime
  `RPATH` or `LD_LIBRARY_PATH`).
- **No external runtime deps.** The wrapper imports only
  `Interfaces.C` and `Ada.Streams` from the standard library; the
  libitb shared library is the only non-stdlib runtime dependency.
- **Frozen C ABI.** The `ITB_*` exports declared in `Itb.Sys` (synced
  from `dist/<os>-<arch>/libitb.h`) are the contract; the binding
  does not extend or reshape them.
- **No `dlopen`.** Symbols are bound at link time via `-litb` plus an
  embedded RPATH. Consumers wanting runtime-resolved FFI loading can
  wrap the binding's shared library list in their own `dlopen` shim.

## API Overview

The package hierarchy below `Itb` partitions the surface by concern.
The root `Itb` package exposes library metadata and process-global
configuration; sibling packages carry the rest.

### Library metadata (root `Itb` package)

| Subprogram | Purpose |
|---|---|
| `function Version return String` | Library version `"<major>.<minor>.<patch>"` |
| `function Max_Key_Bits return Natural` | Max supported ITB key width in bits |
| `function Channels return Natural` | Number of native channel slots |
| `function Header_Size return Natural` | Current chunk header size in bytes |
| `function Parse_Chunk_Len (Header : Byte_Array) return Natural` | Parse chunk header, return total on-wire chunk length |
| `function List_Hashes return Hash_List` / `function List_MACs return MAC_List` | Catalogue accessors |
| `function Hash_Count / Hash_Name / Hash_Width / MAC_Count / MAC_Name / MAC_Key_Size / MAC_Tag_Size / MAC_Min_Key_Bytes` | Indexed catalogue accessors |

### Process-wide configuration (root `Itb` package)

| Subprogram | Purpose |
|---|---|
| `procedure Set_Bit_Soup (Mode : Integer)` / `function Get_Bit_Soup return Integer` | Bit Soup mode toggle |
| `procedure Set_Lock_Soup (Mode : Integer)` / `function Get_Lock_Soup return Integer` | Lock Soup mode toggle |
| `procedure Set_Max_Workers (N : Integer)` / `function Get_Max_Workers return Integer` | Worker pool cap |
| `procedure Set_Nonce_Bits (N : Integer)` / `function Get_Nonce_Bits return Integer` | Nonce width (128 / 256 / 512) |
| `procedure Set_Barrier_Fill (N : Integer)` / `function Get_Barrier_Fill return Integer` | Barrier-fill factor |
| `function Set_Memory_Limit (Limit : Interfaces.Integer_64) return Interfaces.Integer_64` | Go runtime heap soft limit in bytes; pass negative to query only |
| `function Set_GC_Percent (Pct : Interfaces.C.int) return Interfaces.C.int` | Go GC trigger percentage; pass negative to query only |

### Seeds and MAC (`Itb.Seed`, `Itb.MAC`)

| Subprogram | Purpose |
|---|---|
| `function Itb.Seed.Make (Hash_Name : String; Key_Bits : Integer) return Seed` | CSPRNG-fresh seed |
| `function Itb.Seed.From_Components (...)` | Reconstruct from explicit components |
| `function Width / Hash_Name / Hash_Name_Introspect / Hash_Key / Components` | Seed introspection |
| `procedure Attach_Lock_Seed (Self : Seed; Lock : Seed)` | Bind a lock seed onto a noise seed |
| `function Itb.MAC.Make (Mac_Name : String; Key : Byte_Array) return MAC` | Construct MAC handle |

### Low-level cipher (`Itb.Cipher`)

| Subprogram | Purpose |
|---|---|
| `function Encrypt (Noise, Data, Start, Plaintext) return Byte_Array` / `function Decrypt (...)` | Single Message |
| `function Encrypt_Auth (Noise, Data, Start, MAC, Plaintext)` / `function Decrypt_Auth (...)` | MAC-authenticated counterparts |
| `function Encrypt_Triple (Noise, D1, D2, D3, S1, S2, S3, Plaintext)` / `function Decrypt_Triple (...)` | Triple Ouroboros |
| `function Encrypt_Auth_Triple (...)` / `function Decrypt_Auth_Triple (...)` | Triple Ouroboros MAC-authenticated |

### Easy Mode encryptor (`Itb.Encryptor`)

| Subprogram | Purpose |
|---|---|
| `function Make (Primitive : String; Key_Bits : Integer; MAC : String := ""; Mode : String := "single") return Encryptor` | Single-primitive constructor |
| `function Mixed_Single (Primitives, Key_Bits, MAC) return Encryptor` / `function Mixed_Triple (...) return Encryptor` | Mixed-primitive Single / Triple |
| `function Encrypt / Decrypt / Encrypt_Auth / Decrypt_Auth (Self, Buffer) return Byte_Array` | Cipher entry points |
| `procedure Set_Nonce_Bits / Set_Barrier_Fill / Set_Bit_Soup / Set_Lock_Soup / Set_Lock_Seed / Set_Chunk_Size` | Per-instance setters |
| `function Primitive / Primitive_At / Key_Bits / Mode / MAC_Name / Seed_Count / Has_PRF_Keys / Is_Mixed / Nonce_Bits / Header_Size` | Accessors |
| `function Get_Seed_Components / Get_PRF_Key / Get_MAC_Key (Self)` | Key-material accessors |
| `function Parse_Chunk_Len (Self, Header)` | Per-instance chunk-length parser |
| `function Export_State (Self) return Byte_Array` / `procedure Import_State (Self; Blob)` | State-blob persistence |
| `function Peek_Config (Blob : Byte_Array) return Peeked_Config` | Pre-import discriminator |
| `procedure Encrypt_Stream_Auth (...)` / `procedure Decrypt_Stream_Auth (...)` / `procedure Encrypt_Stream (...)` / `procedure Decrypt_Stream (...)` | Easy Mode streaming over Ada.Streams |
| `procedure Close (Self : in out Encryptor)` | Release encryptor (Controlled finaliser also runs on scope exit) |

### Streaming AEAD (`Itb.Streams`)

| Subprogram | Purpose |
|---|---|
| `type Stream_Encryptor / Stream_Decryptor / Stream_Encryptor_Triple / Stream_Decryptor_Triple` | Push-style Low-Level streamers |
| `type Stream_Encryptor_Auth / Stream_Decryptor_Auth / Stream_Encryptor_Auth_3 / Stream_Decryptor_Auth_3` | Push-style Streaming AEAD streamers |
| `function Make / Make_Triple / Make_Auth / Make_Auth_Triple (...)` | Constructors per streamer family |
| `procedure Write_Plaintext / Read_Plaintext / Finish (Self : in out ...)` | Stream loop methods |
| `procedure Encrypt_Stream / Decrypt_Stream / Encrypt_Stream_Triple / Decrypt_Stream_Triple` | Free-function Low-Level bridges |
| `procedure Encrypt_Stream_Auth / Decrypt_Stream_Auth / Encrypt_Stream_Auth_Triple / Decrypt_Stream_Auth_Triple` | Free-function Streaming AEAD bridges |

### Native Blob (`Itb.Blob`)

| Subprogram | Purpose |
|---|---|
| `type Blob128 / Blob256 / Blob512 is tagged limited private` | Width-specific Native Blob handles |
| `function New_Blob128 / New_Blob256 / New_Blob512 return Blob<N>` | Constructors |
| `procedure Set_Key / Set_Components / Set_MAC_Key / Set_MAC_Name (...)` | Field setters |
| `function Get_Key / Get_Components / Get_MAC_Key / Get_MAC_Name (...)` | Field getters |
| `function Export (...) / Export_3 (...) ` and `procedure Import (...) / Import_3 (...)` | Serialisation |
| `type Slot_Type is (Slot_N, Slot_D, ..., Slot_S3, Slot_L)` | Slot enum |
| `type Export_Opts is mod 2 ** 8` (`Opt_LockSeed`, `Opt_MAC`) | Export opt-in flag bits |

### Wrapper (`Itb.Wrapper`)

| Subprogram | Purpose |
|---|---|
| `type Cipher_Type is (Aes_128_Ctr, Cha_Cha_20, Sip_Hash_24)` | Cipher enum |
| `function Ffi_Name (C : Cipher_Type) return String` | Canonical FFI name |
| `function Key_Size (C : Cipher_Type) return Natural` / `function Nonce_Size (C : Cipher_Type) return Natural` | Cipher dimension accessors |
| `function Generate_Key (C : Cipher_Type) return Byte_Array` | CSPRNG-fresh wrapper key |
| `function Wrap (...) return Byte_Array` / `function Unwrap (...) return Byte_Array` | Single Message Wrap / Unwrap |
| `procedure Wrap_In_Place (...) / Unwrap_In_Place (...)` | In-place Wrap / Unwrap |
| `type Wrap_Stream_Writer is tagged limited private` / `type Unwrap_Stream_Reader is tagged limited private` | Streaming wrap writer / unwrap reader |
| `procedure Initialize / Update / Close` per streamer type | Stream loop methods |

### Error model (`Itb.Errors`)

| Subprogram | Purpose |
|---|---|
| `Itb_Error : exception` | Generic exception family (typed subclasses listed below) |
| `Itb_Easy_Mismatch_Error / Itb_Blob_Mode_Mismatch_Error / Itb_Blob_Malformed_Error / Itb_Blob_Version_Too_New_Error` | Typed cold-path discriminators |
| `Itb_Stream_Truncated_Error / Itb_Stream_After_Final_Error` | Streaming AEAD transcript-shape exceptions |
| `function Status_Code (Occurrence) return Integer` / `function Field (Occurrence) return String` / `function Message (Occurrence) return String` | Occurrence accessors |
| `function Last_Error return String` / `function Last_Mismatch_Field return String` | Per-thread last-error helpers |
| `procedure Raise_For (Status : Integer)` | Status → exception bridge |
