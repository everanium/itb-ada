--  Common body — env readers, getrandom(2) fill, timing runner.

with Ada.Environment_Variables;
with Ada.Real_Time;
with Ada.Strings.Fixed;
with Ada.Streams;
with Ada.Text_IO;

with Interfaces.C;
with System;
with System.Storage_Elements;

package body Common is

   use type Ada.Real_Time.Time;
   use type Ada.Streams.Stream_Element_Offset;

   ---------
   -- Env --
   ---------

   function Env (Name : String; Default : String) return String is
   begin
      if Ada.Environment_Variables.Exists (Name)
        and then Ada.Environment_Variables.Value (Name) /= ""
      then
         return Ada.Environment_Variables.Value (Name);
      end if;
      return Default;
   end Env;

   function Env_True (Name : String) return Boolean is
      V : constant String := Env (Name, "false");
   begin
      return V = "true" or else V = "1";
   end Env_True;

   ----------------
   -- Build_Opts --
   ----------------

   function Build_Opts return Itb.Opts.Opts is
      O          : Itb.Opts.Opts;
      Inner_Hash : constant String := Env ("ITB_INNER_HASH", "");
      Mac_Name   : constant String := Env ("ITB_MAC_NAME", "");
   begin
      O.Set ("nonceBits", Env ("ITB_NONCE_BITS", "512"));
      O.Set ("keyBits", Env ("ITB_KEY_BITS", "1024"));
      O.Set_With_Parallax (Env_True ("ITB_WITH_PARALLAX"));
      O.Set_With_Wrapper (Env_True ("ITB_WITH_WRAPPER"));
      if Inner_Hash /= "" then
         O.Set_Inner_Hash (Inner_Hash);
      end if;
      if Mac_Name /= "" then
         O.Set ("macName", Mac_Name);
      end if;
      return O;
   end Build_Opts;

   ------------------
   -- Profile_Name --
   ------------------

   function Profile_Name (Fallback : String) return String is
   begin
      return Env ("ITB_PROFILE", Fallback);
   end Profile_Name;

   -----------------
   -- Fill_Random --
   -----------------

   function Getrandom
     (Buf   : System.Address;
      Len   : Interfaces.C.size_t;
      Flags : Interfaces.C.unsigned) return Interfaces.C.long
   with Import => True, Convention => C, External_Name => "getrandom";

   procedure Fill_Random (Buffer : in out Itb.Byte_Array) is
      use System.Storage_Elements;
      use type Interfaces.C.long;
      Done : Ada.Streams.Stream_Element_Offset := 0;
   begin
      --  getrandom returns at most ~33 MiB per call on Linux, so
      --  loop until the whole buffer is filled.
      while Done < Buffer'Length loop
         declare
            Got : constant Interfaces.C.long :=
              Getrandom
                (Buffer'Address + Storage_Offset (Done),
                 Interfaces.C.size_t (Buffer'Length - Done), 0);
         begin
            if Got <= 0 then
               raise Program_Error with "getrandom failed";
            end if;
            Done := Done + Ada.Streams.Stream_Element_Offset (Got);
         end;
      end loop;
   end Fill_Random;

   ------------------
   -- Bench_Header --
   ------------------

   function Pad (S : String; Width : Positive) return String is
   begin
      if S'Length >= Width then
         return S;
      end if;
      return Ada.Strings.Fixed.Head (S, Width);
   end Pad;

   procedure Bench_Header is
   begin
      Ada.Text_IO.Put_Line
        (Pad ("bench", 18) & Pad ("size", 9) & "mb_per_sec");
   end Bench_Header;

   function Size_Label (Size_Bytes : Positive) return String is
   begin
      if Size_Bytes >= 2 ** 20 then
         return Ada.Strings.Fixed.Trim
           (Integer'Image (Size_Bytes / 2 ** 20), Ada.Strings.Left)
           & " MiB";
      end if;
      return Ada.Strings.Fixed.Trim
        (Integer'Image (Size_Bytes / 2 ** 10), Ada.Strings.Left) & " KiB";
   end Size_Label;

   ----------------
   -- Bench_Case --
   ----------------

   Min_Iters : constant := 3;

   function Min_Seconds return Duration is
      V : constant String := Env ("ITB_BENCH_MIN_SEC", "5");
   begin
      return Duration'Value (V);
   exception
      when Constraint_Error =>
         return 5.0;
   end Min_Seconds;

   procedure Bench_Case
     (Name       : String;
      Size_Bytes : Positive;
      Proc       : not null access procedure)
   is
      Budget  : constant Duration := Min_Seconds;
      Start   : Ada.Real_Time.Time;
      Elapsed : Duration := 0.0;
      Iters   : Natural := 0;
   begin
      Proc.all;  --  warm-up, untimed
      Start := Ada.Real_Time.Clock;
      while Elapsed < Budget or else Iters < Min_Iters loop
         Proc.all;
         Iters := Iters + 1;
         Elapsed := Ada.Real_Time.To_Duration (Ada.Real_Time.Clock - Start);
      end loop;
      declare
         MB     : constant Long_Float :=
           Long_Float (Size_Bytes) * Long_Float (Iters) / (1024.0 * 1024.0);
         Rate   : constant Long_Float := MB / Long_Float (Elapsed);
         Tenths : constant Natural := Natural (Rate * 10.0);
         Text   : constant String :=
           Ada.Strings.Fixed.Trim
             (Natural'Image (Tenths / 10), Ada.Strings.Left)
           & "."
           & Ada.Strings.Fixed.Trim
               (Natural'Image (Tenths mod 10), Ada.Strings.Left);
      begin
         Ada.Text_IO.Put_Line
           (Pad (Name, 18) & Pad (Size_Label (Size_Bytes), 9) & Text);
      end;
   end Bench_Case;

end Common;
