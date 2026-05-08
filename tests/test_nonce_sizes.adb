--  Round-trip tests across all nonce-size configurations.
--
--  Mirrors bindings/rust/tests/test_nonce_sizes.rs one-to-one. ITB
--  exposes a runtime-configurable nonce size (Set_Nonce_Bits) that
--  takes one of {128, 256, 512}. The on-the-wire chunk header
--  therefore varies between 20, 36, and 68 bytes; consumers must use
--  Header_Size rather than a hardcoded constant.

with Ada.Streams;  use Ada.Streams;
with Ada.Text_IO;

with Itb;          use Itb;
with Itb.Cipher;
with Itb.Errors;
with Itb.MAC;
with Itb.Seed;
with Itb.Status;

procedure Test_Nonce_Sizes is

   type Int_Array is array (Positive range <>) of Integer;
   Nonce_Sizes : constant Int_Array := [128, 256, 512];

   type Name_Array is array (Positive range <>) of access constant String;
   H_Siphash24  : aliased constant String := "siphash24";
   H_Blake3     : aliased constant String := "blake3";
   H_Blake2b512 : aliased constant String := "blake2b512";
   Hashes : constant Name_Array :=
     [H_Siphash24'Access, H_Blake3'Access, H_Blake2b512'Access];

   M_Kmac256     : aliased constant String := "kmac256";
   M_Hmac_Sha256 : aliased constant String := "hmac-sha256";
   M_Hmac_Blake3 : aliased constant String := "hmac-blake3";
   Mac_Names : constant Name_Array :=
     [M_Kmac256'Access, M_Hmac_Sha256'Access, M_Hmac_Blake3'Access];

   Mac_Key : constant Byte_Array := [1 .. 32 => Stream_Element (16#73#)];

   function Pseudo_Plaintext (N : Stream_Element_Offset) return Byte_Array is
      Result : Byte_Array (1 .. N);
   begin
      for I in Result'Range loop
         Result (I) := Stream_Element (((Integer (I - 1) * 31 + 7) mod 256));
      end loop;
      return Result;
   end Pseudo_Plaintext;

   procedure Tamper (Buf : in out Byte_Array) is
      H_Lo : constant Stream_Element_Offset :=
        Buf'First + Stream_Element_Offset (Itb.Header_Size);
      H_Hi : constant Stream_Element_Offset :=
        Stream_Element_Offset'Min (H_Lo + 256, Buf'Last + 1) - 1;
   begin
      for I in H_Lo .. H_Hi loop
         Buf (I) := Buf (I) xor 1;
      end loop;
   end Tamper;

   Saved_Nonce_Bits : constant Integer := Itb.Get_Nonce_Bits;

begin

   ------------------------------------------------------------------
   --  test_default_is_20
   ------------------------------------------------------------------
   Itb.Set_Nonce_Bits (128);
   if Itb.Header_Size /= 20 then
      raise Program_Error
        with "Header_Size at nonce=128 expected 20, got"
             & Itb.Header_Size'Image;
   end if;
   if Itb.Get_Nonce_Bits /= 128 then
      raise Program_Error with "Get_Nonce_Bits expected 128";
   end if;

   ------------------------------------------------------------------
   --  test_header_size_dynamic
   ------------------------------------------------------------------
   for N of Nonce_Sizes loop
      Itb.Set_Nonce_Bits (N);
      if Itb.Header_Size /= N / 8 + 4 then
         raise Program_Error
           with "Header_Size at nonce=" & N'Image
                & " expected " & Integer'Image (N / 8 + 4)
                & ", got" & Itb.Header_Size'Image;
      end if;
   end loop;

   ------------------------------------------------------------------
   --  test_encrypt_decrypt_across_nonce_sizes
   ------------------------------------------------------------------
   declare
      Plain : constant Byte_Array := Pseudo_Plaintext (1024);
   begin
      for N of Nonce_Sizes loop
         for HN of Hashes loop
            Itb.Set_Nonce_Bits (N);
            declare
               Ns : constant Itb.Seed.Seed := Itb.Seed.Make (HN.all, 1024);
               Ds : constant Itb.Seed.Seed := Itb.Seed.Make (HN.all, 1024);
               Ss : constant Itb.Seed.Seed := Itb.Seed.Make (HN.all, 1024);
               Ct : constant Byte_Array :=
                 Itb.Cipher.Encrypt (Ns, Ds, Ss, Plain);
               Decoded : constant Byte_Array :=
                 Itb.Cipher.Decrypt (Ns, Ds, Ss, Ct);
               H : constant Stream_Element_Offset :=
                 Stream_Element_Offset (Itb.Header_Size);
               Chunk_Len : constant Natural :=
                 Itb.Parse_Chunk_Len (Ct (Ct'First .. Ct'First + H - 1));
            begin
               if Decoded /= Plain then
                  raise Program_Error
                    with "single roundtrip mismatch nonce=" & N'Image
                         & " hash=" & HN.all;
               end if;
               if Stream_Element_Offset (Chunk_Len) /= Ct'Length then
                  raise Program_Error
                    with "Parse_Chunk_Len mismatch nonce=" & N'Image;
               end if;
            end;
         end loop;
      end loop;
   end;

   ------------------------------------------------------------------
   --  test_triple_encrypt_decrypt_across_nonce_sizes
   ------------------------------------------------------------------
   declare
      Plain : constant Byte_Array := Pseudo_Plaintext (1024);
   begin
      for N of Nonce_Sizes loop
         for HN of Hashes loop
            Itb.Set_Nonce_Bits (N);
            declare
               S0 : constant Itb.Seed.Seed := Itb.Seed.Make (HN.all, 1024);
               S1 : constant Itb.Seed.Seed := Itb.Seed.Make (HN.all, 1024);
               S2 : constant Itb.Seed.Seed := Itb.Seed.Make (HN.all, 1024);
               S3 : constant Itb.Seed.Seed := Itb.Seed.Make (HN.all, 1024);
               S4 : constant Itb.Seed.Seed := Itb.Seed.Make (HN.all, 1024);
               S5 : constant Itb.Seed.Seed := Itb.Seed.Make (HN.all, 1024);
               S6 : constant Itb.Seed.Seed := Itb.Seed.Make (HN.all, 1024);
               Ct : constant Byte_Array :=
                 Itb.Cipher.Encrypt_Triple
                   (S0, S1, S2, S3, S4, S5, S6, Plain);
               Decoded : constant Byte_Array :=
                 Itb.Cipher.Decrypt_Triple
                   (S0, S1, S2, S3, S4, S5, S6, Ct);
            begin
               if Decoded /= Plain then
                  raise Program_Error
                    with "triple roundtrip mismatch nonce="
                         & N'Image & " hash=" & HN.all;
               end if;
            end;
         end loop;
      end loop;
   end;

   ------------------------------------------------------------------
   --  test_auth_across_nonce_sizes
   ------------------------------------------------------------------
   declare
      Plain : constant Byte_Array := Pseudo_Plaintext (1024);
   begin
      for N of Nonce_Sizes loop
         for MN of Mac_Names loop
            Itb.Set_Nonce_Bits (N);
            declare
               M  : constant Itb.MAC.MAC := Itb.MAC.Make (MN.all, Mac_Key);
               Ns : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
               Ds : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
               Ss : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
               Ct : constant Byte_Array :=
                 Itb.Cipher.Encrypt_Auth (Ns, Ds, Ss, M, Plain);
               Decoded : constant Byte_Array :=
                 Itb.Cipher.Decrypt_Auth (Ns, Ds, Ss, M, Ct);
            begin
               if Decoded /= Plain then
                  raise Program_Error
                    with "auth single mismatch nonce="
                         & N'Image & " mac=" & MN.all;
               end if;
               declare
                  Tampered : Byte_Array := Ct;
               begin
                  Tamper (Tampered);
                  begin
                     declare
                        Pt2 : constant Byte_Array :=
                          Itb.Cipher.Decrypt_Auth (Ns, Ds, Ss, M, Tampered);
                        pragma Unreferenced (Pt2);
                     begin
                        raise Program_Error
                          with "tampered auth must raise nonce="
                               & N'Image;
                     end;
                  exception
                     when E : Itb.Errors.Itb_Error =>
                        if Itb.Errors.Status_Code (E)
                           /= Itb.Status.MAC_Failure
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
   --  test_triple_auth_across_nonce_sizes
   ------------------------------------------------------------------
   declare
      Plain : constant Byte_Array := Pseudo_Plaintext (1024);
   begin
      for N of Nonce_Sizes loop
         for MN of Mac_Names loop
            Itb.Set_Nonce_Bits (N);
            declare
               M  : constant Itb.MAC.MAC := Itb.MAC.Make (MN.all, Mac_Key);
               S0 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
               S1 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
               S2 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
               S3 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
               S4 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
               S5 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
               S6 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
               Ct : constant Byte_Array :=
                 Itb.Cipher.Encrypt_Auth_Triple
                   (S0, S1, S2, S3, S4, S5, S6, M, Plain);
               Decoded : constant Byte_Array :=
                 Itb.Cipher.Decrypt_Auth_Triple
                   (S0, S1, S2, S3, S4, S5, S6, M, Ct);
            begin
               if Decoded /= Plain then
                  raise Program_Error
                    with "auth triple mismatch nonce="
                         & N'Image & " mac=" & MN.all;
               end if;
               declare
                  Tampered : Byte_Array := Ct;
               begin
                  Tamper (Tampered);
                  begin
                     declare
                        Pt2 : constant Byte_Array :=
                          Itb.Cipher.Decrypt_Auth_Triple
                            (S0, S1, S2, S3, S4, S5, S6, M, Tampered);
                        pragma Unreferenced (Pt2);
                     begin
                        raise Program_Error
                          with "tampered triple auth must raise nonce="
                               & N'Image;
                     end;
                  exception
                     when E : Itb.Errors.Itb_Error =>
                        if Itb.Errors.Status_Code (E)
                           /= Itb.Status.MAC_Failure
                        then
                           raise;
                        end if;
                  end;
               end;
            end;
         end loop;
      end loop;
   end;

   Itb.Set_Nonce_Bits (Saved_Nonce_Bits);
   Ada.Text_IO.Put_Line ("test_nonce_sizes: PASS");

exception
   when others =>
      begin
         Itb.Set_Nonce_Bits (Saved_Nonce_Bits);
      exception
         when others =>
            null;
      end;
      raise;
end Test_Nonce_Sizes;
