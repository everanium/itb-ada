--  The final summary in both renderings, and the two measurements it
--  folds in that are not per-worker counters: the process resident
--  set and the shared library's pool counters.

package Harness.Summary is

   --  The process's current resident set and its high-water mark in
   --  bytes, from /proc/self/status (VmRSS and VmHWM, reported in kB).
   --  Both are zero on a platform without that file; the figures are
   --  informational and never enter the verdict.
   procedure Read_RSS (Current : out Count; Peak : out Count);

   --  Allocates one pool-counter snapshot at the length the library
   --  reports.
   function Snapshot_Alloc (Into : out Pool_Snapshot) return Boolean;

   --  Takes one snapshot. A failure leaves it zeroed rather than
   --  stopping the run: the counters are informational and never
   --  enter the verdict.
   procedure Snapshot_Take (Into : Pool_Snapshot);

   --  Output contract. Both renderings are shared with the Go harness
   --  and every other binding's loop utility field for field: the
   --  same lines in the same order, the same keys in the same order,
   --  floats with a fixed number of decimals so the JSON is
   --  byte-identical across implementations. The Go harness alone
   --  adds its runtime-internal lines after rss: and its
   --  runtime-internal keys after parallax_chunk_pool; nothing here
   --  reproduces them because nothing they read is reachable through
   --  the C ABI.
   function Final_Summary (Elapsed_NS : Count) return Integer;

end Harness.Summary;
