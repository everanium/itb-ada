--  Test_Support body.

with Ada.Streams;

package body Test_Support is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;
   use type Interfaces.Unsigned_64;

   -----------
   -- Check --
   -----------

   procedure Check (Cond : Boolean; Label : String) is
   begin
      if not Cond then
         raise Test_Failure with Label;
      end if;
   end Check;

   --------------
   -- Check_Eq --
   --------------

   procedure Check_Eq (Got, Want : Itb.Byte_Array; Label : String) is
   begin
      if Got'Length /= Want'Length then
         raise Test_Failure with Label & ": length"
           & Got'Length'Image & " /=" & Want'Length'Image;
      end if;
      for I in 0 .. Got'Length - 1 loop
         if Got (Got'First + Ada.Streams.Stream_Element_Offset (I))
           /= Want (Want'First + Ada.Streams.Stream_Element_Offset (I))
         then
            raise Test_Failure with Label & ": byte mismatch at offset"
              & I'Image;
         end if;
      end loop;
   end Check_Eq;

   -------------
   -- Payload --
   -------------

   function Payload
     (N : Positive; Seed : Interfaces.Unsigned_64) return Itb.Byte_Array
   is
      use Interfaces;
      X      : Unsigned_64 := Seed or 1;
      Result : Itb.Byte_Array (1 .. Ada.Streams.Stream_Element_Offset (N));
   begin
      for I in Result'Range loop
         X := X xor Shift_Left (X, 13);
         X := X xor Shift_Right (X, 7);
         X := X xor Shift_Left (X, 17);
         Result (I) := Ada.Streams.Stream_Element (X mod 256);
      end loop;
      return Result;
   end Payload;

end Test_Support;
