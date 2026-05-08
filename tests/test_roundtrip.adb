--  Generic round-trip integration tests.
--
--  Mirrors bindings/rust/tests/test_roundtrip.rs one-to-one. Each Rust
--  #[test] fn becomes a single nested block in the main procedure;
--  the per-test serial_lock is unnecessary because each test_*.adb
--  main procedure compiles into its own executable and runs in its
--  own process with a fresh libitb global state.

with Ada.Streams;          use Ada.Streams;
with Ada.Strings.Unbounded;
with Ada.Text_IO;

with Itb;          use Itb;
with Itb.Cipher;
with Itb.Errors;
with Itb.MAC;
with Itb.Seed;
with Itb.Status;

procedure Test_Roundtrip is

   Plaintext_Default : constant String :=
     "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";

   --  Canonical hash list, mirroring CANONICAL_HASHES in
   --  bindings/rust/tests/test_roundtrip.rs.
   type Hash_Entry is record
      Name  : access constant String;
      Width : Integer;
   end record;
   type Hash_Entry_Array is array (Positive range <>) of Hash_Entry;

   H_Areion256  : aliased constant String := "areion256";
   H_Areion512  : aliased constant String := "areion512";
   H_Siphash24  : aliased constant String := "siphash24";
   H_AESCMAC    : aliased constant String := "aescmac";
   H_Blake2b256 : aliased constant String := "blake2b256";
   H_Blake2b512 : aliased constant String := "blake2b512";
   H_Blake2s    : aliased constant String := "blake2s";
   H_Blake3     : aliased constant String := "blake3";
   H_Chacha20   : aliased constant String := "chacha20";

   Canonical_Hashes : constant Hash_Entry_Array :=
     [(H_Areion256'Access,  256),
      (H_Areion512'Access,  512),
      (H_Siphash24'Access,  128),
      (H_AESCMAC'Access,    128),
      (H_Blake2b256'Access, 256),
      (H_Blake2b512'Access, 512),
      (H_Blake2s'Access,    256),
      (H_Blake3'Access,     256),
      (H_Chacha20'Access,   256)];

   type Int_Array is array (Positive range <>) of Integer;
   Key_Bits_Set : constant Int_Array := [512, 1024, 2048];
   Bad_Bits_Set : constant Int_Array := [0, 256, 511, 2049];

   --  String-to-Byte_Array helper.
   function To_Bytes (S : String) return Byte_Array is
      Result : Byte_Array (1 .. Stream_Element_Offset (S'Length));
   begin
      for I in S'Range loop
         Result (Stream_Element_Offset (I - S'First + 1)) :=
           Stream_Element (Character'Pos (S (I)));
      end loop;
      return Result;
   end To_Bytes;

   --  Pseudo-payload helper (deterministic).
   function Pseudo_Payload (N : Stream_Element_Offset) return Byte_Array is
      Result : Byte_Array (1 .. N);
   begin
      for I in Result'Range loop
         Result (I) := Stream_Element (((Integer (I - 1) * 17 + 5) mod 256));
      end loop;
      return Result;
   end Pseudo_Payload;

   Mac_Key_42 : constant Byte_Array :=
     [1 .. 32 => Stream_Element (16#42#)];
   Mac_Key_21 : constant Byte_Array :=
     [1 .. 32 => Stream_Element (16#21#)];

begin

   ------------------------------------------------------------------
   --  single_roundtrip_blake3
   ------------------------------------------------------------------
   declare
      P  : constant Byte_Array := To_Bytes (Plaintext_Default);
      N  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      D  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Ct : constant Byte_Array := Itb.Cipher.Encrypt (N, D, S, P);
      Decoded : constant Byte_Array := Itb.Cipher.Decrypt (N, D, S, Ct);
   begin
      if Ct = P then
         raise Program_Error with "ciphertext equals plaintext";
      end if;
      if Decoded /= P then
         raise Program_Error with "single_roundtrip_blake3 mismatch";
      end if;
   end;

   ------------------------------------------------------------------
   --  triple_roundtrip_blake3
   ------------------------------------------------------------------
   declare
      P  : constant Byte_Array := To_Bytes (Plaintext_Default);
      N  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      D1 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      D2 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      D3 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S1 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S2 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S3 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Ct : constant Byte_Array :=
        Itb.Cipher.Encrypt_Triple (N, D1, D2, D3, S1, S2, S3, P);
      Decoded : constant Byte_Array :=
        Itb.Cipher.Decrypt_Triple (N, D1, D2, D3, S1, S2, S3, Ct);
   begin
      if Decoded /= P then
         raise Program_Error with "triple_roundtrip_blake3 mismatch";
      end if;
   end;

   ------------------------------------------------------------------
   --  auth_roundtrip_hmac_sha256
   ------------------------------------------------------------------
   declare
      P   : constant Byte_Array := To_Bytes (Plaintext_Default);
      N   : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      D   : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S   : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      M   : constant Itb.MAC.MAC :=
        Itb.MAC.Make ("hmac-sha256", Mac_Key_42);
      Ct  : constant Byte_Array := Itb.Cipher.Encrypt_Auth (N, D, S, M, P);
      Decoded : constant Byte_Array :=
        Itb.Cipher.Decrypt_Auth (N, D, S, M, Ct);
   begin
      if Decoded /= P then
         raise Program_Error with "auth_roundtrip_hmac_sha256 mismatch";
      end if;
   end;

   ------------------------------------------------------------------
   --  auth_triple_roundtrip_kmac256
   ------------------------------------------------------------------
   declare
      P   : constant Byte_Array := To_Bytes (Plaintext_Default);
      N   : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      D1  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      D2  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      D3  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S1  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S2  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S3  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      M   : constant Itb.MAC.MAC :=
        Itb.MAC.Make ("kmac256", Mac_Key_21);
      Ct  : constant Byte_Array :=
        Itb.Cipher.Encrypt_Auth_Triple
          (N, D1, D2, D3, S1, S2, S3, M, P);
      Decoded : constant Byte_Array :=
        Itb.Cipher.Decrypt_Auth_Triple
          (N, D1, D2, D3, S1, S2, S3, M, Ct);
   begin
      if Decoded /= P then
         raise Program_Error with "auth_triple_roundtrip_kmac256 mismatch";
      end if;
   end;

   ------------------------------------------------------------------
   --  seed_components_roundtrip
   ------------------------------------------------------------------
   declare
      S    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Comp : constant Component_Array := Itb.Seed.Get_Components (S);
      Key  : constant Byte_Array := Itb.Seed.Get_Hash_Key (S);
      S2   : constant Itb.Seed.Seed :=
        Itb.Seed.From_Components ("blake3", Comp, Key);
   begin
      if Itb.Seed.Get_Components (S) /= Itb.Seed.Get_Components (S2) then
         raise Program_Error with "components mismatch after rebuild";
      end if;
      if Itb.Seed.Get_Hash_Key (S) /= Itb.Seed.Get_Hash_Key (S2) then
         raise Program_Error with "hash_key mismatch after rebuild";
      end if;
   end;

   ------------------------------------------------------------------
   --  auth_decrypt_tampered_fails_with_mac_failure
   ------------------------------------------------------------------
   declare
      P   : constant Byte_Array := To_Bytes (Plaintext_Default);
      N   : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      D   : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S   : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Zero_Key : constant Byte_Array := [1 .. 32 => 0];
      M   : constant Itb.MAC.MAC :=
        Itb.MAC.Make ("hmac-sha256", Zero_Key);
      Ct  : constant Byte_Array := Itb.Cipher.Encrypt_Auth (N, D, S, M, P);
      Tampered : Byte_Array := Ct;
   begin
      Tampered (Tampered'Last) := Tampered (Tampered'Last) xor 16#FF#;
      declare
         Decoded : constant Byte_Array :=
           Itb.Cipher.Decrypt_Auth (N, D, S, M, Tampered);
         pragma Unreferenced (Decoded);
      begin
         raise Program_Error with "tamper-detected decrypt should raise";
      end;
   exception
      when E : Itb.Errors.Itb_Error =>
         if Itb.Errors.Status_Code (E) /= Itb.Status.MAC_Failure then
            raise;
         end if;
   end;

   ------------------------------------------------------------------
   --  seed_drop_does_not_panic
   ------------------------------------------------------------------
   for I in 1 .. 32 loop
      declare
         S : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 512);
         pragma Unreferenced (S);
      begin
         null;
      end;
   end loop;

   ------------------------------------------------------------------
   --  test_version
   ------------------------------------------------------------------
   declare
      V : constant String := Itb.Version;
      Dot1, Dot2 : Natural := 0;
   begin
      if V'Length = 0 then
         raise Program_Error with "Version returned empty string";
      end if;
      for I in V'Range loop
         if V (I) = '.' then
            if Dot1 = 0 then
               Dot1 := I;
            elsif Dot2 = 0 then
               Dot2 := I;
            end if;
         end if;
      end loop;
      if Dot1 = 0 or else Dot2 = 0 then
         raise Program_Error with "Version not in X.Y.Z form: " & V;
      end if;
      for I in V'First .. Dot1 - 1 loop
         if V (I) not in '0' .. '9' then
            raise Program_Error with "non-digit major in version: " & V;
         end if;
      end loop;
      for I in Dot1 + 1 .. Dot2 - 1 loop
         if V (I) not in '0' .. '9' then
            raise Program_Error with "non-digit minor in version: " & V;
         end if;
      end loop;
      if Dot2 + 1 > V'Last
        or else V (Dot2 + 1) not in '0' .. '9'
      then
         raise Program_Error with "non-digit patch in version: " & V;
      end if;
   end;

   ------------------------------------------------------------------
   --  test_list_hashes — confirm catalogue matches canonical 9 set.
   ------------------------------------------------------------------
   declare
      --  Strips ASCII NUL / spaces from a libitb-returned name so the
      --  catalogue comparison works regardless of whether the FFI
      --  emitted a NUL-padded length. Mirrors what the Rust binding
      --  gets for free via CStr::to_str.
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

      Got : constant Hash_List := Itb.List_Hashes;
   begin
      if Got'Length /= Canonical_Hashes'Length then
         raise Program_Error
           with "List_Hashes length mismatch:" & Got'Length'Image;
      end if;
      for I in Canonical_Hashes'Range loop
         declare
            Idx  : constant Positive :=
              Got'First + (I - Canonical_Hashes'First);
            Want : constant Hash_Entry := Canonical_Hashes (I);
            Got_Name : constant String :=
              Normalise
                (Ada.Strings.Unbounded.To_String (Got (Idx).Name));
         begin
            if Got_Name /= Want.Name.all then
               raise Program_Error
                 with "hash name mismatch at" & I'Image
                      & ": '" & Got_Name & "' /= '" & Want.Name.all & "'";
            end if;
            if Got (Idx).Width /= Want.Width then
               raise Program_Error
                 with "hash width mismatch at " & Want.Name.all;
            end if;
         end;
      end loop;
   end;

   ------------------------------------------------------------------
   --  test_constants
   ------------------------------------------------------------------
   if Itb.Max_Key_Bits /= 2048 then
      raise Program_Error
        with "Max_Key_Bits expected 2048, got" & Itb.Max_Key_Bits'Image;
   end if;
   if Itb.Channels /= 8 then
      raise Program_Error
        with "Channels expected 8, got" & Itb.Channels'Image;
   end if;

   ------------------------------------------------------------------
   --  test_new_and_free
   ------------------------------------------------------------------
   declare
      S : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
   begin
      if Itb.Seed.Hash_Name (S) /= "blake3" then
         raise Program_Error
           with "Hash_Name mismatch: " & Itb.Seed.Hash_Name (S);
      end if;
      if Itb.Seed.Width (S) /= 256 then
         raise Program_Error
           with "Width expected 256, got" & Itb.Seed.Width (S)'Image;
      end if;
   end;

   ------------------------------------------------------------------
   --  test_bad_hash
   --
   --  Per Ada RM 11.2(8), an exception raised during the elaboration
   --  of a block's declarative part propagates OUT of the block — it
   --  is not handled by that block's own exception clause. The inner
   --  declare-begin-end captures the failing constant; the outer
   --  exception clause matches the propagated raise.
   ------------------------------------------------------------------
   begin
      declare
         S : constant Itb.Seed.Seed := Itb.Seed.Make ("nonsense-hash", 1024);
         pragma Unreferenced (S);
      begin
         raise Program_Error with "Make(bad hash) should raise";
      end;
   exception
      when E : Itb.Errors.Itb_Error =>
         if Itb.Errors.Status_Code (E) /= Itb.Status.Bad_Hash then
            raise;
         end if;
   end;

   ------------------------------------------------------------------
   --  test_bad_key_bits
   ------------------------------------------------------------------
   for Bits of Bad_Bits_Set loop
      begin
         declare
            S : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", Bits);
            pragma Unreferenced (S);
         begin
            raise Program_Error
              with "Make(blake3," & Bits'Image & ") should raise";
         end;
      exception
         when E : Itb.Errors.Itb_Error =>
            if Itb.Errors.Status_Code (E) /= Itb.Status.Bad_Key_Bits then
               raise;
            end if;
      end;
   end loop;

   ------------------------------------------------------------------
   --  test_all_hashes_all_widths_single
   ------------------------------------------------------------------
   declare
      P : constant Byte_Array := Pseudo_Payload (4096);
   begin
      for HE of Canonical_Hashes loop
         for KB of Key_Bits_Set loop
            declare
               N : constant Itb.Seed.Seed := Itb.Seed.Make (HE.Name.all, KB);
               D : constant Itb.Seed.Seed := Itb.Seed.Make (HE.Name.all, KB);
               S : constant Itb.Seed.Seed := Itb.Seed.Make (HE.Name.all, KB);
               Ct : constant Byte_Array := Itb.Cipher.Encrypt (N, D, S, P);
               Decoded : constant Byte_Array :=
                 Itb.Cipher.Decrypt (N, D, S, Ct);
            begin
               if Ct'Length <= P'Length then
                  raise Program_Error
                    with "ciphertext not longer than plaintext for "
                       & HE.Name.all;
               end if;
               if Decoded /= P then
                  raise Program_Error
                    with "single roundtrip mismatch hash="
                       & HE.Name.all & " bits=" & KB'Image;
               end if;
            end;
         end loop;
      end loop;
   end;

   ------------------------------------------------------------------
   --  test_seed_width_mismatch
   ------------------------------------------------------------------
   declare
      N : constant Itb.Seed.Seed := Itb.Seed.Make ("siphash24", 1024);
      D : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
   begin
      begin
         declare
            Ct : constant Byte_Array :=
              Itb.Cipher.Encrypt (N, D, S, To_Bytes ("hello"));
            pragma Unreferenced (Ct);
         begin
            raise Program_Error with "Encrypt mixed widths should raise";
         end;
      exception
         when E : Itb.Errors.Itb_Error =>
            if Itb.Errors.Status_Code (E) /= Itb.Status.Seed_Width_Mix then
               raise;
            end if;
      end;
   end;

   ------------------------------------------------------------------
   --  test_all_hashes_all_widths_triple
   ------------------------------------------------------------------
   declare
      P : constant Byte_Array := Pseudo_Payload (4096);
   begin
      for HE of Canonical_Hashes loop
         for KB of Key_Bits_Set loop
            declare
               S0 : constant Itb.Seed.Seed := Itb.Seed.Make (HE.Name.all, KB);
               S1 : constant Itb.Seed.Seed := Itb.Seed.Make (HE.Name.all, KB);
               S2 : constant Itb.Seed.Seed := Itb.Seed.Make (HE.Name.all, KB);
               S3 : constant Itb.Seed.Seed := Itb.Seed.Make (HE.Name.all, KB);
               S4 : constant Itb.Seed.Seed := Itb.Seed.Make (HE.Name.all, KB);
               S5 : constant Itb.Seed.Seed := Itb.Seed.Make (HE.Name.all, KB);
               S6 : constant Itb.Seed.Seed := Itb.Seed.Make (HE.Name.all, KB);
               Ct : constant Byte_Array :=
                 Itb.Cipher.Encrypt_Triple (S0, S1, S2, S3, S4, S5, S6, P);
               Decoded : constant Byte_Array :=
                 Itb.Cipher.Decrypt_Triple (S0, S1, S2, S3, S4, S5, S6, Ct);
            begin
               if Ct'Length <= P'Length then
                  raise Program_Error
                    with "triple ciphertext not longer than plaintext";
               end if;
               if Decoded /= P then
                  raise Program_Error
                    with "triple roundtrip mismatch hash="
                       & HE.Name.all & " bits=" & KB'Image;
               end if;
            end;
         end loop;
      end loop;
   end;

   ------------------------------------------------------------------
   --  test_triple_seed_width_mismatch
   ------------------------------------------------------------------
   declare
      Odd : constant Itb.Seed.Seed := Itb.Seed.Make ("siphash24", 1024);
      R1  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      R2  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      R3  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      R4  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      R5  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      R6  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
   begin
      begin
         declare
            Ct  : constant Byte_Array :=
              Itb.Cipher.Encrypt_Triple
                (Odd, R1, R2, R3, R4, R5, R6, To_Bytes ("hello"));
            pragma Unreferenced (Ct);
         begin
            raise Program_Error
              with "Encrypt_Triple mixed widths should raise";
         end;
      exception
         when E : Itb.Errors.Itb_Error =>
            if Itb.Errors.Status_Code (E) /= Itb.Status.Seed_Width_Mix then
               raise;
            end if;
      end;
   end;

   Ada.Text_IO.Put_Line ("test_roundtrip: PASS");

end Test_Roundtrip;
