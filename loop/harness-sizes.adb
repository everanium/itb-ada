--  The size and duration parsers, the clock_gettime binding behind
--  the monotonic clock, and the fixed-decimal renderings of sizes,
--  rates and durations.

with Ada.Characters.Handling;
with Ada.Long_Float_Text_IO;
with Ada.Strings.Fixed;

with Interfaces.C;
with System;

package body Harness.Sizes is

   use Interfaces;
   use type Interfaces.C.int;

   KiB : constant Count := 1024;
   MiB : constant Count := 1024 * 1024;
   GiB : constant Count := 1024 * 1024 * 1024;

   --  Ada-specific. clock_gettime over CLOCK_MONOTONIC: the Ada
   --  calendar clock is wall time and Ada.Real_Time's epoch is
   --  implementation-defined, while the summary reports nanosecond
   --  windows the other implementations measure the same way.
   type Timespec is record
      Seconds     : Interfaces.C.long := 0;
      Nanoseconds : Interfaces.C.long := 0;
   end record
   with Convention => C;

   CLOCK_MONOTONIC : constant Interfaces.C.int := 1;

   function C_Clock_Gettime
     (Which : Interfaces.C.int; TS : System.Address) return Interfaces.C.int
   with Import => True, Convention => C, External_Name => "clock_gettime";

   ------------------
   -- Parse_U64 --
   ------------------

   function Parse_U64
     (Text : String; Value : out Interfaces.Unsigned_64) return Boolean
   is
      Limit : constant Interfaces.Unsigned_64 := Interfaces.Unsigned_64'Last;
      Acc   : Interfaces.Unsigned_64 := 0;
      Digit : Interfaces.Unsigned_64;
   begin
      Value := 0;
      if Text'Length = 0 then
         return False;
      end if;
      for I in Text'Range loop
         if Text (I) not in '0' .. '9' then
            return False;
         end if;
         Digit := Interfaces.Unsigned_64 (Character'Pos (Text (I)) - 48);
         if Acc > Limit / 10 then
            return False;
         end if;
         if Acc = Limit / 10 and then Digit > Limit mod 10 then
            return False;
         end if;
         Acc := Acc * 10 + Digit;
      end loop;
      Value := Acc;
      return True;
   end Parse_U64;

   ----------------
   -- Parse_Size --
   ----------------

   function Parse_Size (Text : String; Value : out Count) return Boolean is
      Body_Text : constant String :=
        Ada.Strings.Fixed.Trim (Text, Ada.Strings.Both);
      Upper     : constant String :=
        Ada.Characters.Handling.To_Upper (Body_Text);
      Mult      : Count := 1;
      Digits_To : Natural;
      Raw       : Interfaces.Unsigned_64;

      function Ends (Suffix : String) return Boolean is
      begin
         return Upper'Length >= Suffix'Length
           and then Upper (Upper'Last - Suffix'Length + 1 .. Upper'Last)
                    = Suffix;
      end Ends;
   begin
      Value := 0;
      if Upper'Length = 0 then
         return False;
      end if;
      Digits_To := Upper'Last;
      if Ends ("KIB") then
         Mult := KiB;
         Digits_To := Upper'Last - 3;
      elsif Ends ("MIB") then
         Mult := MiB;
         Digits_To := Upper'Last - 3;
      elsif Ends ("GIB") then
         Mult := GiB;
         Digits_To := Upper'Last - 3;
      elsif Ends ("KB") then
         Mult := KiB;
         Digits_To := Upper'Last - 2;
      elsif Ends ("MB") then
         Mult := MiB;
         Digits_To := Upper'Last - 2;
      elsif Ends ("GB") then
         Mult := GiB;
         Digits_To := Upper'Last - 2;
      elsif Ends ("K") then
         Mult := KiB;
         Digits_To := Upper'Last - 1;
      elsif Ends ("M") then
         Mult := MiB;
         Digits_To := Upper'Last - 1;
      elsif Ends ("G") then
         Mult := GiB;
         Digits_To := Upper'Last - 1;
      elsif Ends ("B") then
         Mult := 1;
         Digits_To := Upper'Last - 1;
      end if;
      while Digits_To >= Upper'First and then Upper (Digits_To) = ' ' loop
         Digits_To := Digits_To - 1;
      end loop;
      if Digits_To < Upper'First then
         return False;
      end if;
      if not Parse_U64 (Upper (Upper'First .. Digits_To), Raw) then
         return False;
      end if;
      if Raw > Interfaces.Unsigned_64 (Count'Last) then
         return False;
      end if;
      if Mult > 1 and then Count (Raw) > Count'Last / Mult then
         return False;
      end if;
      Value := Count (Raw) * Mult;
      return True;
   end Parse_Size;

   --------------------
   -- Parse_Duration --
   --------------------

   function Parse_Duration (Text : String; Value : out Count) return Boolean is
      Body_Text : constant String :=
        Ada.Strings.Fixed.Trim (Text, Ada.Strings.Both);
      Total     : Long_Float := 0.0;
      Pos       : Natural;
      Start     : Natural;
      Mult      : Long_Float;
      Matched   : Boolean;
      Number    : Long_Float;

      function Unit_At (Unit : String) return Boolean is
         Last : constant Natural := Pos + Unit'Length - 1;
      begin
         if Last > Body_Text'Last then
            return False;
         end if;
         if Body_Text (Pos .. Last) /= Unit then
            return False;
         end if;
         if Last < Body_Text'Last
           and then Ada.Characters.Handling.Is_Letter
                      (Body_Text (Last + 1))
         then
            return False;
         end if;
         return True;
      end Unit_At;
   begin
      Value := 0;
      if Body_Text'Length = 0 then
         return False;
      end if;
      Pos := Body_Text'First;
      while Pos <= Body_Text'Last loop
         if Body_Text (Pos) not in '0' .. '9'
           and then Body_Text (Pos) /= '.'
         then
            return False;
         end if;
         Start := Pos;
         while Pos <= Body_Text'Last
           and then (Body_Text (Pos) in '0' .. '9'
                     or else Body_Text (Pos) = '.')
         loop
            Pos := Pos + 1;
         end loop;
         begin
            Number := Long_Float'Value (Body_Text (Start .. Pos - 1));
         exception
            when others =>
               return False;
         end;
         if Number < 0.0 then
            return False;
         end if;
         Mult := 0.0;
         Matched := True;
         if Unit_At ("ns") then
            Mult := 1.0;
            Pos := Pos + 2;
         elsif Unit_At ("us") then
            Mult := 1.0E3;
            Pos := Pos + 2;
         elsif Unit_At ("ms") then
            Mult := 1.0E6;
            Pos := Pos + 2;
         elsif Unit_At ("s") then
            Mult := 1.0E9;
            Pos := Pos + 1;
         elsif Unit_At ("m") then
            Mult := 60.0E9;
            Pos := Pos + 1;
         elsif Unit_At ("h") then
            Mult := 3600.0E9;
            Pos := Pos + 1;
         else
            Matched := False;
         end if;
         if not Matched then
            return False;
         end if;
         Total := Total + Number * Mult;
      end loop;
      if Total > 9.2E18 then
         return False;
      end if;
      Value := Count (Long_Float'Truncation (Total));
      return True;
   end Parse_Duration;

   ------------
   -- Now_NS --
   ------------

   function Now_NS return Count is
      TS      : aliased Timespec;
      Ignored : constant Interfaces.C.int :=
        C_Clock_Gettime (CLOCK_MONOTONIC, TS'Address);
   begin
      if Ignored /= 0 then
         return 0;
      end if;
      return Count (TS.Seconds) * 1_000_000_000 + Count (TS.Nanoseconds);
   end Now_NS;

   -----------
   -- Fixed --
   -----------

   function Fixed (X : Long_Float; Aft : Natural) return String is
      Buffer : String (1 .. 64);
   begin
      Ada.Long_Float_Text_IO.Put (To => Buffer, Item => X, Aft => Aft, Exp => 0);
      return Ada.Strings.Fixed.Trim (Buffer, Ada.Strings.Both);
   end Fixed;

   -----------------
   -- Human_Bytes --
   -----------------

   function Human_Bytes (N : Count) return String is
   begin
      if N >= GiB then
         return Fixed (Long_Float (N) / Long_Float (GiB), 1) & "GiB";
      elsif N >= MiB then
         return Fixed (Long_Float (N) / Long_Float (MiB), 1) & "MiB";
      elsif N >= KiB then
         return Fixed (Long_Float (N) / Long_Float (KiB), 1) & "KiB";
      else
         return Img (N) & "B";
      end if;
   end Human_Bytes;

   function Human_Bytes_Signed (N : Count) return String is
   begin
      if N < 0 then
         return "-" & Human_Bytes (-N);
      end if;
      return "+" & Human_Bytes (N);
   end Human_Bytes_Signed;

   ----------------
   -- MB_Per_Sec --
   ----------------

   function MB_Per_Sec (Bytes : Count; NS : Count) return Long_Float is
   begin
      if NS <= 0 then
         return 0.0;
      end if;
      return Long_Float (Bytes) / Long_Float (MiB)
             / (Long_Float (NS) / 1.0E9);
   end MB_Per_Sec;

   function Human_Rate (Bytes : Count; NS : Count) return String is
   begin
      if NS <= 0 then
         return "n/a";
      end if;
      return Fixed (MB_Per_Sec (Bytes, NS), 1) & "MB/s";
   end Human_Rate;

   --------------------
   -- Human_Duration --
   --------------------

   --  The fractional part of a nanosecond remainder (0 .. 1e9) as
   --  ".ddd" with trailing zeros removed; the empty string for zero.
   function Fraction_Of (Frac_NS : Count) return String is
      Raw  : String (1 .. 9);
      Last : Natural := 9;
      V    : Count := Frac_NS;
   begin
      if Frac_NS = 0 then
         return "";
      end if;
      for I in reverse Raw'Range loop
         Raw (I) := Character'Val (48 + Integer (V mod 10));
         V := V / 10;
      end loop;
      while Last > 1 and then Raw (Last) = '0' loop
         Last := Last - 1;
      end loop;
      return "." & Raw (1 .. Last);
   end Fraction_Of;

   function Human_Duration (NS : Count) return String is
      V       : Count := NS;
      Hours   : Count;
      Rem_NS  : Count;
      Minutes : Count;
      Seconds : Count;
      Frac    : Count;
   begin
      if V < 0 then
         V := -V;
      end if;
      if V = 0 then
         return "0s";
      end if;
      if V < 1_000_000_000 then
         return Img (V / 1_000_000)
                & Fraction_Of ((V mod 1_000_000) * 1_000) & "ms";
      end if;
      Hours := V / 3_600_000_000_000;
      Rem_NS := V mod 3_600_000_000_000;
      Minutes := Rem_NS / 60_000_000_000;
      Rem_NS := Rem_NS mod 60_000_000_000;
      Seconds := Rem_NS / 1_000_000_000;
      Frac := Rem_NS mod 1_000_000_000;
      declare
         H : constant String :=
           (if Hours > 0 then Img (Hours) & "h" else "");
         M : constant String :=
           (if Hours > 0 or else Minutes > 0 then Img (Minutes) & "m"
            else "");
      begin
         return H & M & Img (Seconds) & Fraction_Of (Frac) & "s";
      end;
   end Human_Duration;

end Harness.Sizes;
