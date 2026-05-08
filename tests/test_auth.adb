--  End-to-end Ada binding tests for Authenticated Encryption.
--
--  Mirrors bindings/rust/tests/test_auth.rs one-to-one. The matrix of
--  3 MACs x 3 hash widths x {Single, Triple} round-trip plus tamper
--  rejection at the dynamic header offset and cross-MAC rejection.

with Ada.Streams;          use Ada.Streams;
with Ada.Strings.Unbounded;
with Ada.Text_IO;

with Itb;          use Itb;
with Itb.Cipher;
with Itb.Errors;
with Itb.MAC;
with Itb.Seed;
with Itb.Status;

procedure Test_Auth is

   --  Canonical MAC catalogue: name, key_size, tag_size, min_key_bytes.
   type MAC_Entry is record
      Name          : access constant String;
      Key_Size      : Integer;
      Tag_Size      : Integer;
      Min_Key_Bytes : Integer;
   end record;
   type MAC_Entry_Array is array (Positive range <>) of MAC_Entry;

   M_Kmac256     : aliased constant String := "kmac256";
   M_Hmac_Sha256 : aliased constant String := "hmac-sha256";
   M_Hmac_Blake3 : aliased constant String := "hmac-blake3";

   Canonical_MACs : constant MAC_Entry_Array :=
     [(M_Kmac256'Access,     32, 32, 16),
      (M_Hmac_Sha256'Access, 32, 32, 16),
      (M_Hmac_Blake3'Access, 32, 32, 32)];

   --  (hash, native width) representatives one per ITB key-width axis.
   type Hash_Entry is record
      Name  : access constant String;
      Width : Integer;
   end record;
   type Hash_Entry_Array is array (Positive range <>) of Hash_Entry;

   H_Siphash24  : aliased constant String := "siphash24";
   H_Blake3     : aliased constant String := "blake3";
   H_Blake2b512 : aliased constant String := "blake2b512";

   Hash_By_Width : constant Hash_Entry_Array :=
     [(H_Siphash24'Access,  128),
      (H_Blake3'Access,     256),
      (H_Blake2b512'Access, 512)];

   Key_Bytes : constant Byte_Array := [1 .. 32 => Stream_Element (16#42#)];

   function Pseudo_Plaintext (N : Stream_Element_Offset) return Byte_Array is
      Result : Byte_Array (1 .. N);
   begin
      for I in Result'Range loop
         Result (I) := Stream_Element ((Integer (I - 1) mod 256));
      end loop;
      return Result;
   end Pseudo_Plaintext;

   --  Strips trailing NUL / spaces so libitb-returned names match
   --  literals.
   function Normalise (S : String) return String is
      Lo : Natural := S'First;
      Hi : Natural := S'Last;
   begin
      while Lo <= Hi
        and then (S (Lo) = ASCII.NUL or else S (Lo) = ' ')
      loop
         Lo := Lo + 1;
      end loop;
      while Hi >= Lo
        and then (S (Hi) = ASCII.NUL or else S (Hi) = ' ')
      loop
         Hi := Hi - 1;
      end loop;
      return S (Lo .. Hi);
   end Normalise;

   procedure Tamper_Header (Buf : in out Byte_Array) is
      H_Lo : constant Stream_Element_Offset :=
        Buf'First + Stream_Element_Offset (Itb.Header_Size);
      H_Hi : constant Stream_Element_Offset :=
        Stream_Element_Offset'Min (H_Lo + 256, Buf'Last + 1) - 1;
   begin
      for I in H_Lo .. H_Hi loop
         Buf (I) := Buf (I) xor 1;
      end loop;
   end Tamper_Header;

begin

   ------------------------------------------------------------------
   --  test_list_macs
   ------------------------------------------------------------------
   declare
      Got : constant MAC_List := Itb.List_MACs;
   begin
      if Got'Length /= Canonical_MACs'Length then
         raise Program_Error
           with "List_MACs length mismatch:" & Got'Length'Image;
      end if;
      for I in Canonical_MACs'Range loop
         declare
            Idx  : constant Positive :=
              Got'First + (I - Canonical_MACs'First);
            Want : constant MAC_Entry := Canonical_MACs (I);
            Got_Name : constant String :=
              Normalise
                (Ada.Strings.Unbounded.To_String (Got (Idx).Name));
         begin
            if Got_Name /= Want.Name.all then
               raise Program_Error
                 with "MAC name mismatch at" & I'Image
                      & ": '" & Got_Name & "' /= '" & Want.Name.all & "'";
            end if;
            if Got (Idx).Key_Size /= Want.Key_Size then
               raise Program_Error
                 with "Key_Size mismatch at " & Want.Name.all;
            end if;
            if Got (Idx).Tag_Size /= Want.Tag_Size then
               raise Program_Error
                 with "Tag_Size mismatch at " & Want.Name.all;
            end if;
            if Got (Idx).Min_Key_Bytes /= Want.Min_Key_Bytes then
               raise Program_Error
                 with "Min_Key_Bytes mismatch at " & Want.Name.all;
            end if;
         end;
      end loop;
   end;

   ------------------------------------------------------------------
   --  test_create_and_free
   ------------------------------------------------------------------
   for ME of Canonical_MACs loop
      declare
         M : constant Itb.MAC.MAC :=
           Itb.MAC.Make (ME.Name.all, Key_Bytes);
      begin
         if Itb.MAC.Name (M) /= ME.Name.all then
            raise Program_Error
              with "MAC.Name mismatch: " & Itb.MAC.Name (M);
         end if;
      end;
   end loop;

   ------------------------------------------------------------------
   --  test_mac_drop_release — equivalent of the Python context-manager
   --  test: the Finalize impl must release the handle when the value
   --  goes out of scope. RAII via Limited_Controlled.
   ------------------------------------------------------------------
   declare
      M : constant Itb.MAC.MAC :=
        Itb.MAC.Make ("hmac-sha256", Key_Bytes);
      pragma Unreferenced (M);
   begin
      null;
   end;

   ------------------------------------------------------------------
   --  test_bad_name
   ------------------------------------------------------------------
   begin
      declare
         M : constant Itb.MAC.MAC :=
           Itb.MAC.Make ("nonsense-mac", Key_Bytes);
         pragma Unreferenced (M);
      begin
         raise Program_Error with "MAC.Make(bad name) must raise";
      end;
   exception
      when E : Itb.Errors.Itb_Error =>
         if Itb.Errors.Status_Code (E) /= Itb.Status.Bad_MAC then
            raise;
         end if;
   end;

   ------------------------------------------------------------------
   --  test_short_key
   ------------------------------------------------------------------
   for ME of Canonical_MACs loop
      declare
         Short : constant Byte_Array
           (1 .. Stream_Element_Offset (ME.Min_Key_Bytes - 1)) :=
             [others => Stream_Element (16#11#)];
      begin
         begin
            declare
               M : constant Itb.MAC.MAC :=
                 Itb.MAC.Make (ME.Name.all, Short);
               pragma Unreferenced (M);
            begin
               raise Program_Error
                 with "MAC.Make short key must raise for " & ME.Name.all;
            end;
         exception
            when E : Itb.Errors.Itb_Error =>
               if Itb.Errors.Status_Code (E) /= Itb.Status.Bad_Input then
                  raise;
               end if;
         end;
      end;
   end loop;

   ------------------------------------------------------------------
   --  test_auth_roundtrip_all_macs_all_widths
   ------------------------------------------------------------------
   declare
      Plain : constant Byte_Array := Pseudo_Plaintext (4096);
   begin
      for ME of Canonical_MACs loop
         for HE of Hash_By_Width loop
            declare
               M  : constant Itb.MAC.MAC :=
                 Itb.MAC.Make (ME.Name.all, Key_Bytes);
               N  : constant Itb.Seed.Seed :=
                 Itb.Seed.Make (HE.Name.all, 1024);
               D  : constant Itb.Seed.Seed :=
                 Itb.Seed.Make (HE.Name.all, 1024);
               S  : constant Itb.Seed.Seed :=
                 Itb.Seed.Make (HE.Name.all, 1024);
               Ct : constant Byte_Array :=
                 Itb.Cipher.Encrypt_Auth (N, D, S, M, Plain);
               Decoded : constant Byte_Array :=
                 Itb.Cipher.Decrypt_Auth (N, D, S, M, Ct);
            begin
               if Decoded /= Plain then
                  raise Program_Error
                    with "auth roundtrip mismatch mac="
                         & ME.Name.all & " hash=" & HE.Name.all;
               end if;
               declare
                  Tampered : Byte_Array := Ct;
               begin
                  Tamper_Header (Tampered);
                  begin
                     declare
                        Pt2 : constant Byte_Array :=
                          Itb.Cipher.Decrypt_Auth (N, D, S, M, Tampered);
                        pragma Unreferenced (Pt2);
                     begin
                        raise Program_Error
                          with "tampered auth must raise mac="
                               & ME.Name.all;
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
   --  test_auth_triple_roundtrip_all_macs_all_widths
   ------------------------------------------------------------------
   declare
      Plain : constant Byte_Array := Pseudo_Plaintext (4096);
   begin
      for ME of Canonical_MACs loop
         for HE of Hash_By_Width loop
            declare
               M  : constant Itb.MAC.MAC :=
                 Itb.MAC.Make (ME.Name.all, Key_Bytes);
               N  : constant Itb.Seed.Seed :=
                 Itb.Seed.Make (HE.Name.all, 1024);
               D1 : constant Itb.Seed.Seed :=
                 Itb.Seed.Make (HE.Name.all, 1024);
               D2 : constant Itb.Seed.Seed :=
                 Itb.Seed.Make (HE.Name.all, 1024);
               D3 : constant Itb.Seed.Seed :=
                 Itb.Seed.Make (HE.Name.all, 1024);
               S1 : constant Itb.Seed.Seed :=
                 Itb.Seed.Make (HE.Name.all, 1024);
               S2 : constant Itb.Seed.Seed :=
                 Itb.Seed.Make (HE.Name.all, 1024);
               S3 : constant Itb.Seed.Seed :=
                 Itb.Seed.Make (HE.Name.all, 1024);
               Ct : constant Byte_Array :=
                 Itb.Cipher.Encrypt_Auth_Triple
                   (N, D1, D2, D3, S1, S2, S3, M, Plain);
               Decoded : constant Byte_Array :=
                 Itb.Cipher.Decrypt_Auth_Triple
                   (N, D1, D2, D3, S1, S2, S3, M, Ct);
            begin
               if Decoded /= Plain then
                  raise Program_Error
                    with "auth triple mismatch mac="
                         & ME.Name.all & " hash=" & HE.Name.all;
               end if;
               declare
                  Tampered : Byte_Array := Ct;
               begin
                  Tamper_Header (Tampered);
                  begin
                     declare
                        Pt2 : constant Byte_Array :=
                          Itb.Cipher.Decrypt_Auth_Triple
                            (N, D1, D2, D3, S1, S2, S3, M, Tampered);
                        pragma Unreferenced (Pt2);
                     begin
                        raise Program_Error
                          with "tampered triple auth must raise mac="
                               & ME.Name.all;
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
   --  test_cross_mac_different_primitive
   ------------------------------------------------------------------
   declare
      N  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      D  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Enc_Mac : constant Itb.MAC.MAC :=
        Itb.MAC.Make ("kmac256", Key_Bytes);
      Dec_Mac : constant Itb.MAC.MAC :=
        Itb.MAC.Make ("hmac-sha256", Key_Bytes);
      Plain : constant String := "authenticated payload";
      Pl_Bytes : Byte_Array (1 .. Stream_Element_Offset (Plain'Length));
   begin
      for I in Plain'Range loop
         Pl_Bytes (Stream_Element_Offset (I - Plain'First + 1)) :=
           Stream_Element (Character'Pos (Plain (I)));
      end loop;
      declare
         Ct : constant Byte_Array :=
           Itb.Cipher.Encrypt_Auth (N, D, S, Enc_Mac, Pl_Bytes);
      begin
         begin
            declare
               Pt2 : constant Byte_Array :=
                 Itb.Cipher.Decrypt_Auth (N, D, S, Dec_Mac, Ct);
               pragma Unreferenced (Pt2);
            begin
               raise Program_Error with "cross-MAC must raise";
            end;
         exception
            when E : Itb.Errors.Itb_Error =>
               if Itb.Errors.Status_Code (E) /= Itb.Status.MAC_Failure then
                  raise;
               end if;
         end;
      end;
   end;

   ------------------------------------------------------------------
   --  test_cross_mac_same_primitive_different_key
   ------------------------------------------------------------------
   declare
      N  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      D  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Key_A : constant Byte_Array := [1 .. 32 => Stream_Element (16#01#)];
      Key_B : constant Byte_Array := [1 .. 32 => Stream_Element (16#02#)];
      Enc_Mac : constant Itb.MAC.MAC :=
        Itb.MAC.Make ("hmac-sha256", Key_A);
      Dec_Mac : constant Itb.MAC.MAC :=
        Itb.MAC.Make ("hmac-sha256", Key_B);
      Plain : constant String := "authenticated payload";
      Pl_Bytes : Byte_Array (1 .. Stream_Element_Offset (Plain'Length));
   begin
      for I in Plain'Range loop
         Pl_Bytes (Stream_Element_Offset (I - Plain'First + 1)) :=
           Stream_Element (Character'Pos (Plain (I)));
      end loop;
      declare
         Ct : constant Byte_Array :=
           Itb.Cipher.Encrypt_Auth (N, D, S, Enc_Mac, Pl_Bytes);
      begin
         begin
            declare
               Pt2 : constant Byte_Array :=
                 Itb.Cipher.Decrypt_Auth (N, D, S, Dec_Mac, Ct);
               pragma Unreferenced (Pt2);
            begin
               raise Program_Error with "cross-key must raise";
            end;
         exception
            when E : Itb.Errors.Itb_Error =>
               if Itb.Errors.Status_Code (E) /= Itb.Status.MAC_Failure then
                  raise;
               end if;
         end;
      end;
   end;

   Ada.Text_IO.Put_Line ("test_auth: PASS");

end Test_Auth;
