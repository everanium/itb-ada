--  Common — shared scaffolding for the Ada binding micro-benchmarks.
--
--  Mirrors bindings/c/benches/bench_util.h: each case runs one
--  untimed warm-up, then iterates until the wall-clock budget
--  (ITB_BENCH_MIN_SEC, default 5.0 s) with an iteration floor, and
--  prints one fixed-width table row (bench / size / mb_per_sec).
--
--  Bench-shape env vars (defaults match the root Go BENCH3.md pin so
--  throughput numbers are directly comparable):
--
--    ITB_NONCE_BITS     512
--    ITB_KEY_BITS       1024
--    ITB_WITH_PARALLAX  false
--    ITB_WITH_WRAPPER   false
--    ITB_INNER_HASH     areion512 (via run_bench.sh; empty = profile
--                       default)
--    ITB_PROFILE        overrides the per-shape default profile
--    ITB_BENCH_MIN_SEC  per-case wall-clock budget (default 5.0)

with Itb;
with Itb.Opts;

package Common is

   --  Environment reader; returns Default when the variable is unset
   --  or empty.
   function Env (Name : String; Default : String) return String;

   --  Reads the bench-shape env vars and builds the opts.
   function Build_Opts return Itb.Opts.Opts;

   --  ITB_PROFILE override or Fallback.
   function Profile_Name (Fallback : String) return String;

   --  CSPRNG-fill via getrandom(2) so plaintext content matches the
   --  root Go bench (crypto/rand). Loops until the whole buffer is
   --  filled. Never inside a timing loop.
   procedure Fill_Random (Buffer : in out Itb.Byte_Array);

   --  Prints the table header row.
   procedure Bench_Header;

   --  Runs Proc until the wall-clock budget is spent (one untimed
   --  warm-up + iteration floor), then prints one table row.
   procedure Bench_Case
     (Name       : String;
      Size_Bytes : Positive;
      Proc       : not null access procedure);

end Common;
