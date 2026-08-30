--  Itb.Runtime body.

with Interfaces.C;

with Itb.Error;
with Itb.Status;

package body Itb.Runtime is

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
      if Integer (St) /= Itb.Status.OK then
         Itb.Error.Raise_For (Integer (St));
      end if;
      --  libitb counts the trailing NUL terminator in Out_Len.
      if Out_Len <= 1 then
         return "";
      end if;
      return To_Ada (Buf (1 .. Out_Len - 1), Trim_Nul => False);
   end Version;

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

end Itb.Runtime;
