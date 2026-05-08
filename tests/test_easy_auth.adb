--  End-to-end Encryptor tests for authenticated encryption — Ada
--  mirror of bindings/rust/tests/test_easy_auth.rs.
--
--  Same matrix (3 MACs x 3 hash widths x {Single, Triple} round trip
--  plus tamper rejection) applied to the high-level Itb.Encryptor
--  surface. Cross-MAC structural rejection rides through the
--  Export_State / Import_State path, where a receiver constructed
--  with the wrong MAC primitive surfaces Itb_Easy_Mismatch_Error with
--  Field = "mac". Same-primitive different-key MAC failure verifies
--  that two independently constructed encryptors with their own
--  random MAC material collide on MAC_Failure rather than a corrupted
--  plaintext.

with Ada.Calendar;
with Ada.Streams;  use Ada.Streams;
with Ada.Text_IO;

with Interfaces;   use Interfaces;

with Itb;          use Itb;
with Itb.Encryptor;
with Itb.Errors;
with Itb.Status;

procedure Test_Easy_Auth is

   type Name_Array is
     array (Positive range <>) of access constant String;

   Mac_Kmac256     : aliased constant String := "kmac256";
   Mac_Hmac_Sha256 : aliased constant String := "hmac-sha256";
   Mac_Hmac_Blake3 : aliased constant String := "hmac-blake3";
   Canonical_Macs  : constant Name_Array :=
     [Mac_Kmac256'Access,
      Mac_Hmac_Sha256'Access,
      Mac_Hmac_Blake3'Access];

   Hash_Siphash24  : aliased constant String := "siphash24";
   Hash_Blake3     : aliased constant String := "blake3";
   Hash_Blake2b512 : aliased constant String := "blake2b512";
   Hash_By_Width   : constant Name_Array :=
     [Hash_Siphash24'Access,
      Hash_Blake3'Access,
      Hash_Blake2b512'Access];

   State : Unsigned_64 :=
     Unsigned_64 (Ada.Calendar.Seconds (Ada.Calendar.Clock) * 1.0E6)
     xor 16#CAFEBABE_DEADBEEF#;

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
   --  all_macs_all_widths_single
   ------------------------------------------------------------------
   declare
      Plaintext : constant Byte_Array := Token_Bytes (4096);
   begin
      for Mac_Ptr of Canonical_Macs loop
         for Hash_Ptr of Hash_By_Width loop
            declare
               Enc : Itb.Encryptor.Encryptor :=
                 Itb.Encryptor.Make
                   (Hash_Ptr.all, 1024, Mac_Ptr.all, 1);
               Ct : constant Byte_Array :=
                 Itb.Encryptor.Encrypt_Auth (Enc, Plaintext);
               Pt : constant Byte_Array :=
                 Itb.Encryptor.Decrypt_Auth (Enc, Ct);
            begin
               if Pt /= Plaintext then
                  raise Program_Error
                    with "Single auth roundtrip mismatch at "
                         & Hash_Ptr.all & " / " & Mac_Ptr.all;
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
                       with "Decrypt_Auth tamper must raise at "
                            & Hash_Ptr.all & " / " & Mac_Ptr.all;
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
         end loop;
      end loop;
   end;

   ------------------------------------------------------------------
   --  all_macs_all_widths_triple
   ------------------------------------------------------------------
   declare
      Plaintext : constant Byte_Array := Token_Bytes (4096);
   begin
      for Mac_Ptr of Canonical_Macs loop
         for Hash_Ptr of Hash_By_Width loop
            declare
               Enc : Itb.Encryptor.Encryptor :=
                 Itb.Encryptor.Make
                   (Hash_Ptr.all, 1024, Mac_Ptr.all, 3);
               Ct : constant Byte_Array :=
                 Itb.Encryptor.Encrypt_Auth (Enc, Plaintext);
               Pt : constant Byte_Array :=
                 Itb.Encryptor.Decrypt_Auth (Enc, Ct);
            begin
               if Pt /= Plaintext then
                  raise Program_Error
                    with "Triple auth roundtrip mismatch at "
                         & Hash_Ptr.all & " / " & Mac_Ptr.all;
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
                       with "Triple Decrypt_Auth tamper must raise at "
                            & Hash_Ptr.all & " / " & Mac_Ptr.all;
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
         end loop;
      end loop;
   end;

   ------------------------------------------------------------------
   --  cross_mac_rejection_different_primitive — sender uses kmac256;
   --  receiver uses hmac-sha256, Import must reject on Field = "mac".
   ------------------------------------------------------------------
   declare
      Src : constant Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
      Blob : constant Byte_Array := Itb.Encryptor.Export_State (Src);
   begin
      declare
         Dst : Itb.Encryptor.Encryptor :=
           Itb.Encryptor.Make ("blake3", 1024, "hmac-sha256", 1);
      begin
         Itb.Encryptor.Import_State (Dst, Blob);
         raise Program_Error
           with "cross-MAC Import must raise Itb_Easy_Mismatch_Error";
      exception
         when E : Itb.Errors.Itb_Easy_Mismatch_Error =>
            if Itb.Errors.Field (E) /= "mac" then
               raise Program_Error
                 with "expected Field = mac, got '"
                      & Itb.Errors.Field (E) & "'";
            end if;
      end;
   end;

   ------------------------------------------------------------------
   --  same_primitive_different_key_mac_failure — two encryptors with
   --  identical configuration but independently random MAC keys must
   --  collide on MAC_Failure when Decrypt_Auth-ing each other's
   --  ciphertext.
   ------------------------------------------------------------------
   declare
      Plaintext : constant Byte_Array :=
        Token_Bytes (Stream_Element_Offset (32));
      Enc1 : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "hmac-sha256", 1);
      Enc2 : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "hmac-sha256", 1);
      Ct   : constant Byte_Array :=
        Itb.Encryptor.Encrypt_Auth (Enc1, Plaintext);
   begin
      declare
         Pt : constant Byte_Array :=
           Itb.Encryptor.Decrypt_Auth (Enc2, Ct);
         pragma Unreferenced (Pt);
      begin
         raise Program_Error
           with "different-key Decrypt_Auth must raise MAC_Failure";
      end;
   exception
      when E : Itb.Errors.Itb_Error =>
         if Itb.Errors.Status_Code (E) /= Itb.Status.MAC_Failure then
            raise;
         end if;
   end;

   Ada.Text_IO.Put_Line ("test_easy_auth: PASS");
end Test_Easy_Auth;
