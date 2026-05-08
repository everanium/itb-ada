--  Common — shared scaffolding for the Ada Easy Mode benchmark
--  binaries.
--
--  Mirrors bindings/rust/benches/common.rs and
--  bindings/csharp/Itb.Bench/Common.cs file-for-file. Each bench case
--  runs a one-shot warm-up batch to absorb cold-cache transients,
--  then a measured batch whose total wall-clock time is divided by
--  the iteration count to produce the canonical ``ns/op`` throughput
--  line. The output line also carries an MB/s figure derived from
--  the configured payload size, matching the Go reporter's
--  ``-benchmem``-less default.
--
--  Environment variables (mirrored from itb's bitbyte_test.go +
--  extended for Easy Mode):
--
--    * ITB_NONCE_BITS   — process-wide nonce width override; valid
--      values 128 / 256 / 512. Maps to Itb.Set_Nonce_Bits before any
--      Encryptor is constructed. Default 128.
--    * ITB_LOCKSEED     — when set to a non-empty / non-"0" value,
--      every Easy Mode encryptor in this run calls Set_Lock_Seed (1)
--      AND Itb.Set_Lock_Soup (1) is invoked at start. Mixed-primitive
--      cases attach a dedicated lockSeed primitive (via Prim_L) under
--      this flag; otherwise Prim_L is "" so the no-LockSeed bench arm
--      measures the plain mixed-primitive cost. Default off.
--    * ITB_BENCH_FILTER — substring filter on bench-case names; only
--      cases whose name contains the substring run.
--    * ITB_BENCH_MIN_SEC — minimum measured wall-clock seconds per
--      case (default 5.0). The runner doubles iteration count until
--      the measured batch reaches the threshold, mirroring Go's
--      ``-benchtime=Ns``. The 5-second default absorbs the cold-cache
--      / warm-up transient that distorts shorter measurement windows
--      on the 16 MiB encrypt / decrypt path.
--
--  Worker count defaults to Itb.Set_Max_Workers (0) (auto-detect),
--  matching the Go bench default.
--
--  Bench_Case design. Each case is a flat record with the encryptor
--  reference, the payload, the (optional) pre-encrypted ciphertext,
--  and an op tag. The Measure routine inspects the op tag and
--  dispatches directly to the matching cipher method. This avoids
--  having to take 'Access of a deeply-nested subprogram (which Ada's
--  accessibility rules reject) — the Rust / C# / Node.js sources box
--  a closure but Ada's static accessibility model would force every
--  per-case dispatcher to live at library level. The op-tag pattern
--  keeps every cipher call inside a single tight switch in the
--  runner.

with Ada.Streams;

with Itb;
with Itb.Encryptor;

package Common is

   --  Default 16 MiB CSPRNG-flavoured payload, matching the Go bench /
   --  Python bench / Rust bench / C# bench surface. Universal-integer
   --  literal converted explicitly to Stream_Element_Offset to avoid
   --  needing a use-clause for Ada.Streams's operators in the spec.
   Payload_16MB : constant Ada.Streams.Stream_Element_Offset :=
     Ada.Streams.Stream_Element_Offset (16 * 1024 * 1024);

   --  Bench MAC slot. Hard-coded to "hmac-blake3" — never "kmac256".
   --  KMAC-256 adds ~44 % overhead on encrypt_auth via cSHAKE-256 /
   --  Keccak; HMAC-BLAKE3 adds ~9 %. KMAC-256 in benches would shift
   --  the encrypt_auth row 4-5x higher than expected.
   Mac_Name : constant String := "hmac-blake3";

   --  Dedicated lockSeed primitive used by mixed-primitive bench
   --  cases when ITB_LOCKSEED is set. When the env var is unset, the
   --  mixed cases pass "" for Prim_L — DO NOT pass a real primitive
   --  name unconditionally (that would auto-couple Bit Soup +
   --  Lock Soup at the Easy Mode level and the no-LockSeed arm would
   --  mis-measure as ~50 MB/s instead of the real ~110-130 MB/s
   --  plain-Mixed cost).
   Mixed_Lock : constant String := "areion256";

   --  Canonical ITB key width pinned across every bench case
   --  (1024 bits = 128 bytes).
   Key_Bits : constant Integer := 1024;

   --  Dispatch tags. Each Bench_Case stores one of these values; the
   --  runner switches on it to invoke the matching cipher method.
   --
   --    Op_Encrypt       — Itb.Encryptor.Encrypt (Enc, Payload)
   --    Op_Decrypt       — Itb.Encryptor.Decrypt (Enc, Cipher)
   --    Op_Encrypt_Auth  — Itb.Encryptor.Encrypt_Auth (Enc, Payload)
   --    Op_Decrypt_Auth  — Itb.Encryptor.Decrypt_Auth (Enc, Cipher)
   type Bench_Op is
     (Op_Encrypt, Op_Decrypt, Op_Encrypt_Auth, Op_Decrypt_Auth);

   type Encryptor_Access is access all Itb.Encryptor.Encryptor;
   type Byte_Array_Access is access Itb.Byte_Array;
   type String_Access is access constant String;

   --  One bench case. Cipher is null for encrypt / encrypt_auth ops
   --  (no pre-encrypted ciphertext required); non-null for the
   --  decrypt / decrypt_auth ops where the runner invokes the
   --  matching decrypt method on each iteration.
   type Bench_Case is record
      Name          : String_Access      := null;
      Enc           : Encryptor_Access   := null;
      Payload       : Byte_Array_Access  := null;
      Cipher        : Byte_Array_Access  := null;
      Op            : Bench_Op           := Op_Encrypt;
      Payload_Bytes : Ada.Streams.Stream_Element_Offset := 0;
   end record;

   type Bench_Case_Array is array (Positive range <>) of Bench_Case;

   --  Reads ITB_NONCE_BITS from the environment with the same
   --  128 / 256 / 512 validation as bitbyte_test.go's TestMain. Falls
   --  back to Default on missing / invalid input (with a stderr
   --  diagnostic for the invalid case).
   function Env_Nonce_Bits (Default : Integer := 128) return Integer;

   --  True when ITB_LOCKSEED is set to a non-empty / non-"0" value.
   --  Triggers Encryptor.Set_Lock_Seed (1) on every encryptor; Easy
   --  Mode auto-couples Bit Soup + Lock Soup as a side effect.
   function Env_Lock_Seed return Boolean;

   --  Optional substring filter for bench-case names, read from
   --  ITB_BENCH_FILTER. Cases whose name does not contain the filter
   --  substring are skipped; used to scope a run down to a single
   --  primitive or operation during development.
   function Env_Filter return String;

   --  True when ITB_BENCH_FILTER was set non-empty (used to disambiguate
   --  "filter unset" from "filter set to ''").
   function Env_Filter_Set return Boolean;

   --  Minimum wall-clock seconds the measured iter loop should take,
   --  read from ITB_BENCH_MIN_SEC (default 5.0). The runner keeps
   --  doubling iteration count until the measured run reaches this
   --  threshold, mirroring Go's -benchtime=Ns semantics.
   function Env_Min_Seconds return Float;

   --  Returns N non-deterministic test bytes via an Ada.Calendar-mixed
   --  LCG. Mirrors the Token_Bytes helper used by the Phase-5 test
   --  suite — no new dependency is introduced. The bench harness does
   --  not require cryptographic strength here, only that the payload
   --  is non-uniform and changes between runs so a primitive cannot
   --  collapse on a constant input.
   function Random_Bytes
     (N : Ada.Streams.Stream_Element_Offset) return Itb.Byte_Array;

   --  Apply the ITB_LOCKSEED per-encryptor flag. Calling
   --  Encryptor.Set_Lock_Seed with mode 1 auto-couples Bit Soup +
   --  Lock Soup on the Single Ouroboros encryptor; the auto-couple is
   --  intentional behaviour of the underlying easy package, not a
   --  binding-side workaround.
   procedure Apply_Lock_Seed_If_Requested (Enc : Itb.Encryptor.Encryptor);

   --  Run every case in Cases and print one Go-bench-style line per
   --  case to stdout. Honours ITB_BENCH_FILTER for substring scoping
   --  and ITB_BENCH_MIN_SEC for the per-case wall-clock budget.
   procedure Run_All (Cases : Bench_Case_Array);

end Common;
