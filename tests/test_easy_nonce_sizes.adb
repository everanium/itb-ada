--  Round-trip tests across every per-instance nonce-size
--  configuration — Ada mirror of
--  bindings/rust/tests/test_easy_nonce_sizes.rs.
--
--  The Encryptor surface exposes Nonce_Bits as a per-instance setter
--  (Itb.Encryptor.Set_Nonce_Bits) rather than a process-wide config —
--  each encryptor's Header_Size and Parse_Chunk_Len track its own
--  Nonce_Bits state without touching the global Itb.Set_Nonce_Bits /
--  Itb.Get_Nonce_Bits accessors. None of the tests in this file
--  mutate process-global state.

with Ada.Calendar;
with Ada.Streams;  use Ada.Streams;
with Ada.Text_IO;

with Interfaces;   use Interfaces;

with Itb;          use Itb;
with Itb.Encryptor;
with Itb.Errors;
with Itb.Status;

procedure Test_Easy_Nonce_Sizes is

   type Int_Array is array (Positive range <>) of Integer;
   Nonce_Sizes : constant Int_Array := [128, 256, 512];

   type Name_Array is
     array (Positive range <>) of access constant String;

   Hash_Siphash24  : aliased constant String := "siphash24";
   Hash_Blake3     : aliased constant String := "blake3";
   Hash_Blake2b512 : aliased constant String := "blake2b512";
   Hashes : constant Name_Array :=
     [Hash_Siphash24'Access,
      Hash_Blake3'Access,
      Hash_Blake2b512'Access];

   Mac_Kmac256     : aliased constant String := "kmac256";
   Mac_Hmac_Sha256 : aliased constant String := "hmac-sha256";
   Mac_Hmac_Blake3 : aliased constant String := "hmac-blake3";
   Macs : constant Name_Array :=
     [Mac_Kmac256'Access,
      Mac_Hmac_Sha256'Access,
      Mac_Hmac_Blake3'Access];

   State : Unsigned_64 :=
     Unsigned_64 (Ada.Calendar.Seconds (Ada.Calendar.Clock) * 1.0E6)
     xor 16#A5A5A5A5_5A5A5A5A#;

   function Token_Bytes (N : Stream_Element_Offset) return Byte_Array is
      Out_Buf : Byte_Array (1 .. N);
   begin
      for I in Out_Buf'Range loop
         State := State * 6364136223846793005 + 1442695040888963407;
         Out_Buf (I) := Stream_Element (Shift_Right (State, 33) and 16#FF#);
      end loop;
      return Out_Buf;
   end Token_Bytes;

   procedure Tamper (Self : Itb.Encryptor.Encryptor; Buf : in out Byte_Array)
   is
      H_Lo : constant Stream_Element_Offset :=
        Buf'First + Stream_Element_Offset (Itb.Encryptor.Header_Size (Self));
      H_Hi : constant Stream_Element_Offset :=
        Stream_Element_Offset'Min (H_Lo + 256, Buf'Last + 1) - 1;
   begin
      for I in H_Lo .. H_Hi loop
         Buf (I) := Buf (I) xor 1;
      end loop;
   end Tamper;

begin

   ------------------------------------------------------------------
   --  header_size_default_is_20 — fresh encryptor reports the libitb
   --  default of 128 bit nonce / 20 byte header.
   ------------------------------------------------------------------
   declare
      Enc : constant Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
   begin
      if Itb.Encryptor.Header_Size (Enc) /= 20 then
         raise Program_Error
           with "default header_size:"
                & Itb.Encryptor.Header_Size (Enc)'Image;
      end if;
      if Itb.Encryptor.Nonce_Bits (Enc) /= 128 then
         raise Program_Error
           with "default nonce_bits:"
                & Itb.Encryptor.Nonce_Bits (Enc)'Image;
      end if;
   end;

   ------------------------------------------------------------------
   --  header_size_dynamic — Set_Nonce_Bits updates Header_Size to
   --  N / 8 + 4 (nonce bytes + 2-byte width + 2-byte height).
   ------------------------------------------------------------------
   for N of Nonce_Sizes loop
      declare
         Enc : constant Itb.Encryptor.Encryptor :=
           Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
      begin
         Itb.Encryptor.Set_Nonce_Bits (Enc, N);
         if Itb.Encryptor.Nonce_Bits (Enc) /= N then
            raise Program_Error
              with "nonce_bits readback:"
                   & Itb.Encryptor.Nonce_Bits (Enc)'Image
                   & " expected" & N'Image;
         end if;
         if Itb.Encryptor.Header_Size (Enc) /= N / 8 + 4 then
            raise Program_Error
              with "header_size:"
                   & Itb.Encryptor.Header_Size (Enc)'Image
                   & " expected" & Integer'Image (N / 8 + 4);
         end if;
      end;
   end loop;

   ------------------------------------------------------------------
   --  encrypt_decrypt_across_nonce_sizes_single
   ------------------------------------------------------------------
   declare
      Plaintext : constant Byte_Array := Token_Bytes (1024);
   begin
      for N of Nonce_Sizes loop
         for Hash_Ptr of Hashes loop
            declare
               Enc : Itb.Encryptor.Encryptor :=
                 Itb.Encryptor.Make
                   (Hash_Ptr.all, 1024, "kmac256", 1);
            begin
               Itb.Encryptor.Set_Nonce_Bits (Enc, N);
               declare
                  Ct : constant Byte_Array :=
                    Itb.Encryptor.Encrypt (Enc, Plaintext);
                  Pt : constant Byte_Array :=
                    Itb.Encryptor.Decrypt (Enc, Ct);
                  Hdr_Len : constant Stream_Element_Offset :=
                    Stream_Element_Offset
                      (Itb.Encryptor.Header_Size (Enc));
                  Parsed : constant Natural :=
                    Itb.Encryptor.Parse_Chunk_Len
                      (Enc, Ct (Ct'First .. Ct'First + Hdr_Len - 1));
               begin
                  if Pt /= Plaintext then
                     raise Program_Error
                       with "Single mismatch hash="
                            & Hash_Ptr.all & " nonce" & N'Image;
                  end if;
                  if Stream_Element_Offset (Parsed) /= Ct'Length then
                     raise Program_Error
                       with "parse_chunk_len mismatch:"
                            & Parsed'Image & " vs" & Ct'Length'Image;
                  end if;
               end;
            end;
         end loop;
      end loop;
   end;

   ------------------------------------------------------------------
   --  encrypt_decrypt_across_nonce_sizes_triple
   ------------------------------------------------------------------
   declare
      Plaintext : constant Byte_Array := Token_Bytes (1024);
   begin
      for N of Nonce_Sizes loop
         for Hash_Ptr of Hashes loop
            declare
               Enc : Itb.Encryptor.Encryptor :=
                 Itb.Encryptor.Make
                   (Hash_Ptr.all, 1024, "kmac256", 3);
            begin
               Itb.Encryptor.Set_Nonce_Bits (Enc, N);
               declare
                  Ct : constant Byte_Array :=
                    Itb.Encryptor.Encrypt (Enc, Plaintext);
                  Pt : constant Byte_Array :=
                    Itb.Encryptor.Decrypt (Enc, Ct);
                  Hdr_Len : constant Stream_Element_Offset :=
                    Stream_Element_Offset
                      (Itb.Encryptor.Header_Size (Enc));
                  Parsed : constant Natural :=
                    Itb.Encryptor.Parse_Chunk_Len
                      (Enc, Ct (Ct'First .. Ct'First + Hdr_Len - 1));
               begin
                  if Pt /= Plaintext then
                     raise Program_Error
                       with "Triple mismatch hash="
                            & Hash_Ptr.all & " nonce" & N'Image;
                  end if;
                  if Stream_Element_Offset (Parsed) /= Ct'Length then
                     raise Program_Error
                       with "Triple parse_chunk_len mismatch";
                  end if;
               end;
            end;
         end loop;
      end loop;
   end;

   ------------------------------------------------------------------
   --  auth_across_nonce_sizes_single
   ------------------------------------------------------------------
   declare
      Plaintext : constant Byte_Array := Token_Bytes (1024);
   begin
      for N of Nonce_Sizes loop
         for Mac_Ptr of Macs loop
            declare
               Enc : Itb.Encryptor.Encryptor :=
                 Itb.Encryptor.Make ("blake3", 1024, Mac_Ptr.all, 1);
            begin
               Itb.Encryptor.Set_Nonce_Bits (Enc, N);
               declare
                  Ct : constant Byte_Array :=
                    Itb.Encryptor.Encrypt_Auth (Enc, Plaintext);
                  Pt : constant Byte_Array :=
                    Itb.Encryptor.Decrypt_Auth (Enc, Ct);
               begin
                  if Pt /= Plaintext then
                     raise Program_Error
                       with "Single auth mismatch mac="
                            & Mac_Ptr.all & " nonce" & N'Image;
                  end if;
                  declare
                     Tampered : Byte_Array := Ct;
                  begin
                     Tamper (Enc, Tampered);
                     declare
                        Pt2 : constant Byte_Array :=
                          Itb.Encryptor.Decrypt_Auth (Enc, Tampered);
                        pragma Unreferenced (Pt2);
                     begin
                        raise Program_Error
                          with "Single tamper must raise";
                     end;
                  exception
                     when E : Itb.Errors.Itb_Error =>
                        if Itb.Errors.Status_Code (E) /=
                           Itb.Status.MAC_Failure
                        then
                           raise;
                        end if;
                  end;
               end;
            end;
         end loop;
      end loop;
   end;

   ------------------------------------------------------------------
   --  auth_across_nonce_sizes_triple
   ------------------------------------------------------------------
   declare
      Plaintext : constant Byte_Array := Token_Bytes (1024);
   begin
      for N of Nonce_Sizes loop
         for Mac_Ptr of Macs loop
            declare
               Enc : Itb.Encryptor.Encryptor :=
                 Itb.Encryptor.Make ("blake3", 1024, Mac_Ptr.all, 3);
            begin
               Itb.Encryptor.Set_Nonce_Bits (Enc, N);
               declare
                  Ct : constant Byte_Array :=
                    Itb.Encryptor.Encrypt_Auth (Enc, Plaintext);
                  Pt : constant Byte_Array :=
                    Itb.Encryptor.Decrypt_Auth (Enc, Ct);
               begin
                  if Pt /= Plaintext then
                     raise Program_Error
                       with "Triple auth mismatch mac="
                            & Mac_Ptr.all & " nonce" & N'Image;
                  end if;
                  declare
                     Tampered : Byte_Array := Ct;
                  begin
                     Tamper (Enc, Tampered);
                     declare
                        Pt2 : constant Byte_Array :=
                          Itb.Encryptor.Decrypt_Auth (Enc, Tampered);
                        pragma Unreferenced (Pt2);
                     begin
                        raise Program_Error
                          with "Triple tamper must raise";
                     end;
                  exception
                     when E : Itb.Errors.Itb_Error =>
                        if Itb.Errors.Status_Code (E) /=
                           Itb.Status.MAC_Failure
                        then
                           raise;
                        end if;
                  end;
               end;
            end;
         end loop;
      end loop;
   end;

   ------------------------------------------------------------------
   --  two_encryptors_independent_nonce_bits — per-instance Config
   --  snapshot is independent.
   ------------------------------------------------------------------
   declare
      Plaintext : constant Byte_Array :=
        Token_Bytes (Stream_Element_Offset (32));
      A : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
      B : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
   begin
      Itb.Encryptor.Set_Nonce_Bits (A, 512);
      if Itb.Encryptor.Nonce_Bits (A) /= 512 then
         raise Program_Error with "A nonce_bits not 512";
      end if;
      if Itb.Encryptor.Header_Size (A) /= 68 then
         raise Program_Error
           with "A header_size:"
                & Itb.Encryptor.Header_Size (A)'Image;
      end if;
      if Itb.Encryptor.Nonce_Bits (B) /= 128 then
         raise Program_Error
           with "B nonce_bits leaked from A:"
                & Itb.Encryptor.Nonce_Bits (B)'Image;
      end if;
      if Itb.Encryptor.Header_Size (B) /= 20 then
         raise Program_Error
           with "B header_size leaked from A";
      end if;
      declare
         Ct_A : constant Byte_Array :=
           Itb.Encryptor.Encrypt (A, Plaintext);
         Pt_A : constant Byte_Array :=
           Itb.Encryptor.Decrypt (A, Ct_A);
         Ct_B : constant Byte_Array :=
           Itb.Encryptor.Encrypt (B, Plaintext);
         Pt_B : constant Byte_Array :=
           Itb.Encryptor.Decrypt (B, Ct_B);
      begin
         if Pt_A /= Plaintext or else Pt_B /= Plaintext then
            raise Program_Error with "isolated encryptor mismatch";
         end if;
      end;
   end;

   Ada.Text_IO.Put_Line ("test_easy_nonce_sizes: PASS");
end Test_Easy_Nonce_Sizes;
