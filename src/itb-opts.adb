--  Itb.Opts body — percent-encoding + typed-setter rendering.

with Ada.Strings;
with Ada.Strings.Fixed;

package body Itb.Opts is

   use Ada.Strings.Unbounded;

   Hex_Digits : constant String := "0123456789abcdef";

   --  Minimal percent-encoding: accepted values are ASCII names,
   --  decimal integers, "true" / "false", hex, and comma-separated
   --  lists, so everything outside the URL-safe subset (plus ',') is
   --  escaped byte-wise with uppercase hex.
   function Enc (S : String) return String is
      Upper_Hex : constant String := "0123456789ABCDEF";
      Result    : String (1 .. S'Length * 3);
      J         : Natural := 0;
   begin
      for C of S loop
         case C is
            when 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9'
               | '-' | '.' | '_' | '~' | ',' =>
               J := J + 1;
               Result (J) := C;
            when others =>
               Result (J + 1) := '%';
               Result (J + 2) := Upper_Hex (1 + Character'Pos (C) / 16);
               Result (J + 3) := Upper_Hex (1 + Character'Pos (C) mod 16);
               J := J + 3;
         end case;
      end loop;
      return Result (1 .. J);
   end Enc;

   function Hex (B : Byte_Array) return String is
      Result : String (1 .. Natural (B'Length) * 2);
      J      : Natural := 0;
   begin
      for E of B loop
         Result (J + 1) := Hex_Digits (1 + Natural (E) / 16);
         Result (J + 2) := Hex_Digits (1 + Natural (E) mod 16);
         J := J + 2;
      end loop;
      return Result;
   end Hex;

   function Int_Image (N : Integer) return String is
   begin
      return Ada.Strings.Fixed.Trim (Integer'Image (N), Ada.Strings.Left);
   end Int_Image;

   function Bool_Image (On : Boolean) return String is
   begin
      return (if On then "true" else "false");
   end Bool_Image;

   ---------
   -- Set --
   ---------

   procedure Set (O : in out Opts; Key : String; Value : String) is
   begin
      if Length (O.Query) > 0 then
         Append (O.Query, "&");
      end if;
      Append (O.Query, Enc (Key) & "=" & Enc (Value));
   end Set;

   ---------------------
   -- Set_Perm_Master --
   ---------------------

   procedure Set_Perm_Master (O : in out Opts; Master : Byte_Array) is
   begin
      Set (O, "pm", Hex (Master));
   end Set_Perm_Master;

   ---------------------
   -- Set_Wrap_Master --
   ---------------------

   procedure Set_Wrap_Master (O : in out Opts; Master : Byte_Array) is
   begin
      Set (O, "wm", Hex (Master));
   end Set_Wrap_Master;

   -----------------------
   -- Set_With_Parallax --
   -----------------------

   procedure Set_With_Parallax (O : in out Opts; On : Boolean) is
   begin
      Set (O, "withParallax", Bool_Image (On));
   end Set_With_Parallax;

   ----------------------
   -- Set_With_Wrapper --
   ----------------------

   procedure Set_With_Wrapper (O : in out Opts; On : Boolean) is
   begin
      Set (O, "withWrapper", Bool_Image (On));
   end Set_With_Wrapper;

   ---------------------
   -- Set_Max_Workers --
   ---------------------

   procedure Set_Max_Workers (O : in out Opts; N : Integer) is
   begin
      Set (O, "maxWorkers", Int_Image (N));
   end Set_Max_Workers;

   --------------------
   -- Set_Nonce_Bits --
   --------------------

   procedure Set_Nonce_Bits (O : in out Opts; N : Integer) is
   begin
      Set (O, "nonceBits", Int_Image (N));
   end Set_Nonce_Bits;

   ----------------------
   -- Set_Barrier_Fill --
   ----------------------

   procedure Set_Barrier_Fill (O : in out Opts; N : Integer) is
   begin
      Set (O, "barrierFill", Int_Image (N));
   end Set_Barrier_Fill;

   --------------------
   -- Set_Chunk_Size --
   --------------------

   procedure Set_Chunk_Size (O : in out Opts; N : Integer) is
   begin
      Set (O, "chunkSize", Int_Image (N));
   end Set_Chunk_Size;

   ------------------
   -- Set_Key_Bits --
   ------------------

   procedure Set_Key_Bits (O : in out Opts; N : Integer) is
   begin
      Set (O, "keyBits", Int_Image (N));
   end Set_Key_Bits;

   -------------------------------
   -- Set_Parallax_Segment_Size --
   -------------------------------

   procedure Set_Parallax_Segment_Size (O : in out Opts; N : Integer) is
   begin
      Set (O, "parallaxSegmentSize", Int_Image (N));
   end Set_Parallax_Segment_Size;

   ------------------
   -- Set_MAC_Name --
   ------------------

   procedure Set_MAC_Name (O : in out Opts; Name : String) is
   begin
      Set (O, "macName", Name);
   end Set_MAC_Name;

   --------------------
   -- Set_Inner_Hash --
   --------------------

   procedure Set_Inner_Hash (O : in out Opts; Name : String) is
   begin
      Set (O, "innerHash", Name);
   end Set_Inner_Hash;

   ----------------------
   -- Set_Inner_Hashes --
   ----------------------

   procedure Set_Inner_Hashes (O : in out Opts; Names : String) is
   begin
      Set (O, "innerHashes", Names);
   end Set_Inner_Hashes;

   ----------------------
   -- Set_Outer_Cipher --
   ----------------------

   procedure Set_Outer_Cipher (O : in out Opts; Name : String) is
   begin
      Set (O, "outerCipher", Name);
   end Set_Outer_Cipher;

   --------------------------
   -- Set_Parallax_Palette --
   --------------------------

   procedure Set_Parallax_Palette (O : in out Opts; Names : String) is
   begin
      Set (O, "parallaxPalette", Names);
   end Set_Parallax_Palette;

   -----------
   -- Build --
   -----------

   function Build (O : Opts) return String is
   begin
      return To_String (O.Query);
   end Build;

end Itb.Opts;
