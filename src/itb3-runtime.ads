--  The libitb3 version string + process-wide Go runtime
--  knobs. The knobs are readable at libitb3 load time via env vars
--  (ITB_GOMEMLIMIT, ITB_GOGC) and adjustable at any time here;
--  setter calls override the env-var values.

with Interfaces;

package Itb3.Runtime is

   --  The libitb3 library version string ("<major>.<minor>.<patch>").
   function Version return String;

   --  The fill cipher the auto DRBG tier selected on this host
   --  ("aes-256-ctr" or "chacha20"): the tier a Pipeline uses when
   --  its "drbg" option is empty, resolved per host and recorded in
   --  no blob.
   function DRBG_Auto_Tier return String;

   --  Sets the Go runtime's soft heap limit in bytes.
   procedure Set_Memory_Limit (Limit : Interfaces.Integer_64);

   --  Queries the current soft heap limit without changing it.
   function Memory_Limit return Interfaces.Integer_64;

   --  Sets the Go GC trigger percentage (default 100; lower values
   --  trigger GC more aggressively).
   procedure Set_GC_Percent (Pct : Integer);

   --  Queries the current GC trigger percentage without changing it.
   function GC_Percent return Integer;

   --  Sets the Go runtime's GOMAXPROCS. Readable at libitb3 load time
   --  via ITB_GOMAXPROCS; this setter overrides the env-var value.
   procedure Set_GOMAXPROCS (N : Integer);

   --  Queries the current GOMAXPROCS without changing it.
   function GOMAXPROCS return Integer;

   --  Writes a Go runtime heap profile (pprof format) to Path after
   --  one forced collection. An empty Path falls back to the
   --  ITB_MEMPROFILE env var; a path that is still empty, or a
   --  file-system failure, raises Itb_Error with
   --  Itb3.Status.Bad_Input and the diagnostic attached.
   procedure Write_Heap_Profile (Path : String);

   --  Pool hit / miss counters of the libitb3 cipher core. Every
   --  counter is a monotonically increasing total since library load,
   --  so a caller differences two snapshots.
   type Pool_Counters is
     array (Positive range <>) of Interfaces.Integer_64;

   --  Number of counter slots Pool_Stats fills. A destination is
   --  sized from this call, never from a constant: the slot layout
   --  grows with the hash-array pool's tier count, which slot 1
   --  carries.
   function Pool_Stats_Len return Natural;

   --  Copies the counters into Dst and reports how many slots were
   --  written. Slot layout, with T the tier count in Dst (Dst'First):
   --  tier i holds starter width, checkouts, constructor misses,
   --  regrow replacements and bytes allocated at the five slots from
   --  1 + 5*i; the scratch byte pool's get / new / regrow /
   --  regrow-bytes follow at 1 + 5*T, and the parallax chunk pool's
   --  at 1 + 5*T + 4 (zero-based offsets from Dst'First). A Dst
   --  shorter than Pool_Stats_Len raises Itb_Error with
   --  Itb3.Status.Buffer_Too_Small.
   procedure Pool_Stats (Dst : out Pool_Counters; Written : out Natural);

end Itb3.Runtime;
