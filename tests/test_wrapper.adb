--  Itb.Wrapper round-trip tests — Ada mirror of
--  bindings/python/tests/test_wrapper.py +
--  bindings/csharp/Itb.Tests/WrapperTests.cs.
--
--  Coverage:
--    * Wrap / Unwrap (allocating)               × 3 ciphers
--    * Wrap_In_Place / Unwrap_In_Place          × 3 ciphers
--    * Wrap_Stream_Writer / Unwrap_Stream_Reader × 3 ciphers
--    * Generate_Key returns a length-correct key
--    * Cross-cipher unwrap (encrypt with AES, decrypt with ChaCha)
--      surfaces a non-equal payload (not necessarily an exception —
--      the wire is XORed under the wrong keystream so decryption is
--      simply garbage; the equality check is the right test).
--    * Bad-input cases: short key, short wire, short nonce buffer.

with Ada.Calendar;
with Ada.Streams;             use Ada.Streams;
with Ada.Text_IO;
with Interfaces;              use Interfaces;

with Itb;                     use Itb;
with Itb.Errors;
with Itb.Status;
with Itb.Wrapper;

procedure Test_Wrapper is

   --  Module-local LCG for non-deterministic test fixtures.
   State : Unsigned_64 :=
     Unsigned_64 (Ada.Calendar.Seconds (Ada.Calendar.Clock) * 1.0E6)
     xor 16#FACE_F00D_DEAD_BEEF#;

   function Token_Bytes (N : Stream_Element_Offset) return Byte_Array is
      Out_Buf : Byte_Array (1 .. N);
   begin
      for I in Out_Buf'Range loop
         State := State * 6364136223846793005 + 1442695040888963407;
         Out_Buf (I) :=
           Stream_Element (Shift_Right (State, 33) and 16#FF#);
      end loop;
      return Out_Buf;
   end Token_Bytes;

   --  Ciphers iterated by every per-cipher test below.
   All_Ciphers : Itb.Wrapper.Cipher_Array renames Itb.Wrapper.All_Ciphers;

   procedure Assert_Equal
     (Got : Byte_Array; Want : Byte_Array; Tag : String) is
   begin
      if Got /= Want then
         raise Program_Error
           with "round-trip mismatch (" & Tag & ")";
      end if;
   end Assert_Equal;

begin

   ------------------------------------------------------------------
   --  Generate_Key returns a length-correct key for each cipher.
   ------------------------------------------------------------------
   for C of All_Ciphers loop
      declare
         Want : constant Natural := Itb.Wrapper.Key_Size (C);
         Key  : constant Byte_Array := Itb.Wrapper.Generate_Key (C);
      begin
         if Key'Length /= Stream_Element_Offset (Want) then
            raise Program_Error
              with "Generate_Key length mismatch for "
                   & Itb.Wrapper.Ffi_Name (C);
         end if;
      end;
   end loop;

   ------------------------------------------------------------------
   --  Derive_Key: deterministic derivation from a 32-byte master
   --  (a stand-in for an ML-KEM shared secret; the binding ships no
   --  KEM). 32 bytes is the wrapper's uniform security floor; the kdf
   --  layer truncates / stretches it to each cipher's key size, so a
   --  single 32-byte master keys every outer cipher. Per cipher the
   --  derived key is length-correct, two derivations from the same
   --  (cipher, master) agree, and the key drives a full Wrap / Unwrap
   --  round-trip.
   ------------------------------------------------------------------
   declare
      Master : constant Byte_Array := Token_Bytes (32);
   begin
      for C of All_Ciphers loop
         declare
            Want  : constant Natural := Itb.Wrapper.Key_Size (C);
            Key1  : constant Byte_Array := Itb.Wrapper.Derive_Key (C, Master);
            Key2  : constant Byte_Array := Itb.Wrapper.Derive_Key (C, Master);
            Plain : constant Byte_Array := Token_Bytes (1024);
            Wire  : constant Byte_Array := Itb.Wrapper.Wrap (C, Key1, Plain);
            Recov : constant Byte_Array := Itb.Wrapper.Unwrap (C, Key1, Wire);
         begin
            if Key1'Length /= Stream_Element_Offset (Want) then
               raise Program_Error
                 with "Derive_Key length mismatch for "
                      & Itb.Wrapper.Ffi_Name (C);
            end if;
            Assert_Equal
              (Key1, Key2,
               "Derive_Key determinism " & Itb.Wrapper.Ffi_Name (C));
            Assert_Equal
              (Recov, Plain,
               "Derive_Key round-trip " & Itb.Wrapper.Ffi_Name (C));
         end;
      end loop;
   end;

   ------------------------------------------------------------------
   --  Derive_Key master floor: the wrapper enforces a uniform 32-byte
   --  master floor for every cipher (not the per-cipher key size). A
   --  31-byte master surfaces as Itb_Error / Bad_Input; a 32-byte
   --  master is accepted and yields a length-correct key.
   ------------------------------------------------------------------
   for C of All_Ciphers loop
      declare
         Short_Master : constant Byte_Array := Token_Bytes (31);
      begin
         declare
            Key : constant Byte_Array := Itb.Wrapper.Derive_Key (C, Short_Master);
            pragma Unreferenced (Key);
         begin
            raise Program_Error
              with "31-byte master did not raise for "
                   & Itb.Wrapper.Ffi_Name (C);
         end;
      exception
         when E : Itb.Errors.Itb_Error =>
            if Itb.Errors.Status_Code (E) /= Itb.Status.Bad_Input then
               raise;
            end if;
      end;
      declare
         Floor_Master : constant Byte_Array := Token_Bytes (32);
         Key          : constant Byte_Array :=
           Itb.Wrapper.Derive_Key (C, Floor_Master);
      begin
         if Key'Length /= Stream_Element_Offset (Itb.Wrapper.Key_Size (C)) then
            raise Program_Error
              with "32-byte master key length mismatch for "
                   & Itb.Wrapper.Ffi_Name (C);
         end if;
      end;
   end loop;

   ------------------------------------------------------------------
   --  Wrap / Unwrap round-trip per cipher across several payload
   --  sizes (empty, single byte, mid-size, larger-than-keystream-
   --  refill-block).
   ------------------------------------------------------------------
   declare
      type Size_Array is array (Positive range <>) of Stream_Element_Offset;
      Sizes : constant Size_Array := [0, 1, 7, 64, 1024, 65535];
   begin
      for C of All_Ciphers loop
         declare
            Key : constant Byte_Array := Itb.Wrapper.Generate_Key (C);
         begin
            for Sz of Sizes loop
               declare
                  Plain : constant Byte_Array := Token_Bytes (Sz);
                  Wire  : constant Byte_Array :=
                    Itb.Wrapper.Wrap (C, Key, Plain);
                  Recov : constant Byte_Array :=
                    Itb.Wrapper.Unwrap (C, Key, Wire);
               begin
                  if Wire'Length /=
                    Plain'Length
                      + Stream_Element_Offset
                          (Itb.Wrapper.Nonce_Size (C))
                  then
                     raise Program_Error
                       with "wire length mismatch for "
                            & Itb.Wrapper.Ffi_Name (C);
                  end if;
                  Assert_Equal
                    (Recov, Plain,
                     "Wrap/Unwrap " & Itb.Wrapper.Ffi_Name (C));
               end;
            end loop;
         end;
      end loop;
   end;

   ------------------------------------------------------------------
   --  Wrap_In_Place / Unwrap_In_Place round-trip per cipher.
   ------------------------------------------------------------------
   for C of All_Ciphers loop
      declare
         Key      : constant Byte_Array := Itb.Wrapper.Generate_Key (C);
         N_Len    : constant Stream_Element_Offset :=
           Stream_Element_Offset (Itb.Wrapper.Nonce_Size (C));
         Plain    : constant Byte_Array := Token_Bytes (4096);
         Mutable  : Byte_Array := Plain;
         Out_Nonce : Byte_Array (1 .. N_Len);
      begin
         Itb.Wrapper.Wrap_In_Place (C, Key, Mutable, Out_Nonce);
         --  Mutable now carries the encrypted body; Plain is preserved.
         if Mutable = Plain then
            raise Program_Error
              with "Wrap_In_Place: blob unchanged for "
                   & Itb.Wrapper.Ffi_Name (C);
         end if;

         declare
            Wire : Byte_Array (1 .. N_Len + Plain'Length);
            Body_First : Stream_Element_Offset;
         begin
            Wire (1 .. N_Len) := Out_Nonce;
            Wire (N_Len + 1 .. Wire'Last) := Mutable;
            Itb.Wrapper.Unwrap_In_Place (C, Key, Wire, Body_First);
            Assert_Equal
              (Wire (Body_First .. Wire'Last), Plain,
               "Wrap_In_Place/Unwrap_In_Place "
               & Itb.Wrapper.Ffi_Name (C));
         end;
      end;
   end loop;

   ------------------------------------------------------------------
   --  Stream writer / reader round-trip per cipher.
   ------------------------------------------------------------------
   for C of All_Ciphers loop
      declare
         Key       : constant Byte_Array := Itb.Wrapper.Generate_Key (C);
         N_Len     : constant Stream_Element_Offset :=
           Stream_Element_Offset (Itb.Wrapper.Nonce_Size (C));
         Plain     : constant Byte_Array := Token_Bytes (8192);
         Out_Nonce : Byte_Array (1 .. N_Len);
         Encrypted : Byte_Array (Plain'Range);
         Last      : Stream_Element_Offset;
         W         : Itb.Wrapper.Wrap_Stream_Writer;
         R         : Itb.Wrapper.Unwrap_Stream_Reader;
      begin
         Itb.Wrapper.Initialize (W, C, Key, Out_Nonce);
         --  Drive the stream in two halves so the keystream-counter
         --  carry across calls is exercised.
         declare
            Mid : constant Stream_Element_Offset :=
              Plain'First + Plain'Length / 2 - 1;
         begin
            Itb.Wrapper.Update
              (W, Plain (Plain'First .. Mid),
               Encrypted (Encrypted'First .. Encrypted'First +
                          (Mid - Plain'First)),
               Last);
            Itb.Wrapper.Update
              (W, Plain (Mid + 1 .. Plain'Last),
               Encrypted (Encrypted'First + (Mid - Plain'First) + 1
                          .. Encrypted'Last),
               Last);
         end;
         Itb.Wrapper.Close (W);

         --  Receiver: feed Out_Nonce once at Initialize, then drive
         --  Update across the encrypted body.
         Itb.Wrapper.Initialize (R, C, Key, Out_Nonce);
         declare
            Decrypted : Byte_Array (Plain'Range);
            R_Last    : Stream_Element_Offset;
         begin
            Itb.Wrapper.Update (R, Encrypted, Decrypted, R_Last);
            Assert_Equal
              (Decrypted, Plain,
               "Stream writer/reader " & Itb.Wrapper.Ffi_Name (C));
         end;
         Itb.Wrapper.Close (R);
      end;
   end loop;

   ------------------------------------------------------------------
   --  Bad-input: short key surfaces as Itb_Error / Bad_Input.
   ------------------------------------------------------------------
   declare
      Plain : constant Byte_Array := Token_Bytes (32);
      Bad_Key : constant Byte_Array (1 .. 4) := [others => 0];
   begin
      declare
         Wire : constant Byte_Array :=
           Itb.Wrapper.Wrap (Itb.Wrapper.Aes_128_Ctr, Bad_Key, Plain);
         pragma Unreferenced (Wire);
      begin
         raise Program_Error with "short key did not raise";
      end;
   exception
      when E : Itb.Errors.Itb_Error =>
         if Itb.Errors.Status_Code (E) /= Itb.Status.Bad_Input then
            raise;
         end if;
   end;

   ------------------------------------------------------------------
   --  Bad-input: short wire surfaces as Itb_Error / Bad_Input.
   ------------------------------------------------------------------
   declare
      Key  : constant Byte_Array :=
        Itb.Wrapper.Generate_Key (Itb.Wrapper.Aes_128_Ctr);
      Wire : constant Byte_Array (1 .. 4) := [others => 0];
   begin
      declare
         Recov : constant Byte_Array :=
           Itb.Wrapper.Unwrap (Itb.Wrapper.Aes_128_Ctr, Key, Wire);
         pragma Unreferenced (Recov);
      begin
         raise Program_Error with "short wire did not raise";
      end;
   exception
      when E : Itb.Errors.Itb_Error =>
         if Itb.Errors.Status_Code (E) /= Itb.Status.Bad_Input then
            raise;
         end if;
   end;

   ------------------------------------------------------------------
   --  Bad-input: short Out_Nonce buffer in Wrap_In_Place.
   ------------------------------------------------------------------
   declare
      Key : constant Byte_Array :=
        Itb.Wrapper.Generate_Key (Itb.Wrapper.Aes_128_Ctr);
      Mutable : Byte_Array (1 .. 100) := [others => 0];
      Bad_Nonce : Byte_Array (1 .. 4) := [others => 0];
   begin
      Itb.Wrapper.Wrap_In_Place
        (Itb.Wrapper.Aes_128_Ctr, Key, Mutable, Bad_Nonce);
      raise Program_Error with "short Out_Nonce did not raise";
   exception
      when E : Itb.Errors.Itb_Error =>
         if Itb.Errors.Status_Code (E) /= Itb.Status.Bad_Input then
            raise;
         end if;
   end;

   ------------------------------------------------------------------
   --  Cross-cipher unwrap: encrypt with AES, decrypt with ChaCha
   --  yields garbage (not the original plaintext). The wire-length
   --  arithmetic also differs (AES nonce is 16 B, ChaCha is 12 B);
   --  ChaCha-Unwrap on an AES-Wrap wire produces a 4-byte longer
   --  recovered "body" prefix than the original. The test reads
   --  whatever bytes come back and asserts they are not equal to
   --  the plaintext — the round-trip is broken on key disagreement,
   --  which is the expected security property.
   ------------------------------------------------------------------
   declare
      Plain   : constant Byte_Array := Token_Bytes (256);
      Aes_Key : constant Byte_Array :=
        Itb.Wrapper.Generate_Key (Itb.Wrapper.Aes_128_Ctr);
      Cha_Key : constant Byte_Array :=
        Itb.Wrapper.Generate_Key (Itb.Wrapper.Cha_Cha_20);
      Wire    : constant Byte_Array :=
        Itb.Wrapper.Wrap (Itb.Wrapper.Aes_128_Ctr, Aes_Key, Plain);
      Recov   : constant Byte_Array :=
        Itb.Wrapper.Unwrap (Itb.Wrapper.Cha_Cha_20, Cha_Key, Wire);
   begin
      if Recov = Plain then
         raise Program_Error
           with "cross-cipher unwrap unexpectedly recovered plaintext";
      end if;
   end;

   Ada.Text_IO.Put_Line ("test_wrapper: PASS");
end Test_Wrapper;
