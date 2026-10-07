--  Payload-mode naming and parsing, the per-worker seed derivation,
--  the SplitMix64 generator, and the fill that selects between the
--  operating-system CSPRNG, the seeded generator and the patterns.

with Ada.Streams;

package body Harness.Payload is

   use Interfaces;
   use type Ada.Streams.Stream_Element_Offset;

   subtype Element_Offset is Ada.Streams.Stream_Element_Offset;

   --  Payload mode selector values for the --payload-mode flag.
   --
   --    - fixed: one CSPRNG-generated buffer per worker, held
   --      unchanged for the whole run (the default).
   --    - rotating: the buffer is regenerated before every iteration,
   --      so no two encrypt calls see the same plaintext.
   --    - pattern-zero / pattern-ff: degenerate constant fills (all
   --      16#00# / all 16#FF#) probing minimum-entropy plaintext
   --      handling.
   --    - pattern-ascii: a repeating 'A'..'Z' ramp probing low-entropy
   --      structured text.
   Names : constant array (Payload_Kind) of access constant String :=
     [Payload_Fixed         => new String'("fixed"),
      Payload_Rotating      => new String'("rotating"),
      Payload_Pattern_Zero  => new String'("pattern-zero"),
      Payload_Pattern_FF    => new String'("pattern-ff"),
      Payload_Pattern_ASCII => new String'("pattern-ascii")];

   function Payload_Mode_Name (Mode : Payload_Kind) return String is
   begin
      return Names (Mode).all;
   end Payload_Mode_Name;

   function Parse_Payload_Mode
     (Text : String; Mode : out Payload_Kind) return Boolean is
   begin
      Mode := Payload_Fixed;
      for K in Payload_Kind loop
         if Text = Names (K).all then
            Mode := K;
            return True;
         end if;
      end loop;
      return False;
   end Parse_Payload_Mode;

   function Seed_Worker
     (Seed : Interfaces.Unsigned_64; Worker_Id : Natural)
      return Interfaces.Unsigned_64 is
   begin
      return Seed + Interfaces.Unsigned_64 (Worker_Id) + 1;
   end Seed_Worker;

   Gamma : constant Interfaces.Unsigned_64 := 16#9E37_79B9_7F4A_7C15#;
   Mix_1 : constant Interfaces.Unsigned_64 := 16#BF58_476D_1CE4_E5B9#;
   Mix_2 : constant Interfaces.Unsigned_64 := 16#94D0_49BB_1331_11EB#;

   function Splitmix64
     (State : in out Interfaces.Unsigned_64) return Interfaces.Unsigned_64
   is
      Z : Interfaces.Unsigned_64;
   begin
      State := State + Gamma;
      Z := State;
      Z := (Z xor Interfaces.Shift_Right (Z, 30)) * Mix_1;
      Z := (Z xor Interfaces.Shift_Right (Z, 27)) * Mix_2;
      return Z xor Interfaces.Shift_Right (Z, 31);
   end Splitmix64;

   function Fill_Payload
     (Mode   : Payload_Kind;
      Seeded : Boolean;
      RNG    : in out Interfaces.Unsigned_64;
      Buffer : in out Byte_Array) return Boolean
   is
      Word : Interfaces.Unsigned_64;
      Byte : Interfaces.Unsigned_64;
      I    : Element_Offset;
   begin
      case Mode is
         when Payload_Fixed | Payload_Rotating =>
            if not Seeded then
               return Fill_Random (Buffer);
            end if;
            I := Buffer'First;
            while I <= Buffer'Last loop
               Word := Splitmix64 (RNG);
               for K in 0 .. 7 loop
                  exit when I + Element_Offset (K) > Buffer'Last;
                  Byte := Interfaces.Shift_Right (Word, 8 * K) and 16#FF#;
                  Buffer (I + Element_Offset (K)) :=
                    Ada.Streams.Stream_Element (Byte);
               end loop;
               I := I + 8;
            end loop;
         when Payload_Pattern_Zero =>
            Buffer := [others => 0];
         when Payload_Pattern_FF =>
            Buffer := [others => 16#FF#];
         when Payload_Pattern_ASCII =>
            for J in Buffer'Range loop
               Buffer (J) := Ada.Streams.Stream_Element
                 (Character'Pos ('A') + Integer ((J - Buffer'First) mod 26));
            end loop;
      end case;
      return True;
   end Fill_Payload;

end Harness.Payload;
