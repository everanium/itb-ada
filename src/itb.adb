--  Itb root body — byte-buffer helpers shared across the binding.

with Ada.Unchecked_Deallocation;

package body Itb is

   use type Ada.Streams.Stream_Element_Offset;

   procedure Deallocate is
     new Ada.Unchecked_Deallocation (Byte_Array, Byte_Array_Access);

   ----------
   -- Free --
   ----------

   procedure Free (Buffer : in out Byte_Array_Access) is
   begin
      if Buffer /= null then
         Deallocate (Buffer);
      end if;
   end Free;

   -------------------
   -- To_Byte_Array --
   -------------------

   function To_Byte_Array (S : String) return Byte_Array is
      Result : Byte_Array (1 .. S'Length);
      J      : Ada.Streams.Stream_Element_Offset := 1;
   begin
      for C of S loop
         Result (J) := Ada.Streams.Stream_Element (Character'Pos (C));
         J := J + 1;
      end loop;
      return Result;
   end To_Byte_Array;

   ---------------
   -- To_String --
   ---------------

   function To_String (B : Byte_Array) return String is
      Result : String (1 .. Natural (B'Length));
      J      : Natural := 1;
   begin
      for E of B loop
         Result (J) := Character'Val (Natural (E));
         J := J + 1;
      end loop;
      return Result;
   end To_String;

end Itb;
