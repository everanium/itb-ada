--  Thin relay onto the libitb3 version string, the Go runtime knobs,
--  the heap-profile writer and the pool counters.

with Interfaces.C;

with Itb3.Error;
with Itb3.Status;

package body Itb3.Runtime is

   use Interfaces.C;
   use type Interfaces.Integer_64;

   -------------
   -- Version --
   -------------

   function Version return String is
      Buf     : aliased char_array (1 .. 64) := [others => nul];
      Out_Len : aliased Size_T := 0;
      St      : constant C_Int :=
        ITB_Version (Buf'Address, Buf'Length, Out_Len'Access);
   begin
      if Integer (St) /= Itb3.Status.OK then
         Itb3.Error.Raise_For (Integer (St));
      end if;
      --  libitb3 counts the trailing NUL terminator in Out_Len.
      if Out_Len <= 1 then
         return "";
      end if;
      return To_Ada (Buf (1 .. Out_Len - 1), Trim_Nul => False);
   end Version;

   --------------------
   -- DRBG_Auto_Tier --
   --------------------

   function DRBG_Auto_Tier return String is
      Buf     : aliased char_array (1 .. 64) := [others => nul];
      Out_Len : aliased Size_T := 0;
      St      : constant C_Int :=
        ITB_DRBGAutoTier (Buf'Address, Buf'Length, Out_Len'Access);
   begin
      if Integer (St) /= Itb3.Status.OK then
         Itb3.Error.Raise_For (Integer (St));
      end if;
      --  libitb3 counts the trailing NUL terminator in Out_Len.
      if Out_Len <= 1 then
         return "";
      end if;
      return To_Ada (Buf (1 .. Out_Len - 1), Trim_Nul => False);
   end DRBG_Auto_Tier;

   ----------------------
   -- Set_Memory_Limit --
   ----------------------

   procedure Set_Memory_Limit (Limit : Interfaces.Integer_64) is
      Previous : constant Interfaces.Integer_64 := ITB_SetMemoryLimit (Limit);
      pragma Unreferenced (Previous);
   begin
      null;
   end Set_Memory_Limit;

   ------------------
   -- Memory_Limit --
   ------------------

   function Memory_Limit return Interfaces.Integer_64 is
   begin
      return ITB_SetMemoryLimit (-1);
   end Memory_Limit;

   --------------------
   -- Set_GC_Percent --
   --------------------

   procedure Set_GC_Percent (Pct : Integer) is
      Previous : constant C_Int := ITB_SetGCPercent (C_Int (Pct));
      pragma Unreferenced (Previous);
   begin
      null;
   end Set_GC_Percent;

   ----------------
   -- GC_Percent --
   ----------------

   function GC_Percent return Integer is
   begin
      return Integer (ITB_SetGCPercent (-1));
   end GC_Percent;

   ---------------------
   -- Set_GOMAXPROCS --
   ---------------------

   procedure Set_GOMAXPROCS (N : Integer) is
      Previous : constant C_Int := ITB_SetGOMAXPROCS (C_Int (N));
      pragma Unreferenced (Previous);
   begin
      null;
   end Set_GOMAXPROCS;

   -----------------
   -- GOMAXPROCS --
   -----------------

   function GOMAXPROCS return Integer is
   begin
      --  Zero or negative queries; the setter takes the positive
      --  values, so zero is the query form here rather than -1.
      return Integer (ITB_SetGOMAXPROCS (0));
   end GOMAXPROCS;

   ------------------------
   -- Write_Heap_Profile --
   ------------------------

   procedure Write_Heap_Profile (Path : String) is
      Path_C : aliased constant char_array := To_C (Path);
      St     : constant C_Int := ITB_WriteHeapProfile (Path_C'Address);
   begin
      if Integer (St) /= Itb3.Status.OK then
         Itb3.Error.Raise_For (Integer (St));
      end if;
   end Write_Heap_Profile;

   --------------------
   -- Pool_Stats_Len --
   --------------------

   function Pool_Stats_Len return Natural is
      N : constant C_Int := ITB_PoolStatsLen;
   begin
      return (if N > 0 then Natural (N) else 0);
   end Pool_Stats_Len;

   ----------------
   -- Pool_Stats --
   ----------------

   procedure Pool_Stats (Dst : out Pool_Counters; Written : out Natural) is
      Len : aliased Size_T := 0;
      St  : C_Int;
   begin
      Dst := [others => 0];
      if Dst'Length = 0 then
         --  An empty destination has no first element to take the
         --  address of, so the probe form goes over as a null pointer
         --  with capacity zero; libitb3 then reports the requirement
         --  through Len without writing anywhere.
         St := ITB_PoolStats (System.Null_Address, 0, Len'Access);
      else
         St := ITB_PoolStats
           (Dst'Address, Size_T (Dst'Length), Len'Access);
      end if;
      Written := Natural (Len);
      if Integer (St) /= Itb3.Status.OK then
         Itb3.Error.Raise_For (Integer (St));
      end if;
   end Pool_Stats;

end Itb3.Runtime;
