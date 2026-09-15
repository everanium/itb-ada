--  Itb3.Runtime — libitb3 version string + process-wide Go runtime
--  knobs. The knobs are readable at libitb3 load time via env vars
--  (ITB_GOMEMLIMIT, ITB_GOGC) and adjustable at any time here;
--  setter calls override the env-var values.

with Interfaces;

package Itb3.Runtime is

   --  The libitb3 library version string ("<major>.<minor>.<patch>").
   function Version return String;

   --  Sets the Go runtime's soft heap limit in bytes.
   procedure Set_Memory_Limit (Limit : Interfaces.Integer_64);

   --  Queries the current soft heap limit without changing it.
   function Memory_Limit return Interfaces.Integer_64;

   --  Sets the Go GC trigger percentage (default 100; lower values
   --  trigger GC more aggressively).
   procedure Set_GC_Percent (Pct : Integer);

   --  Queries the current GC trigger percentage without changing it.
   function GC_Percent return Integer;

end Itb3.Runtime;
