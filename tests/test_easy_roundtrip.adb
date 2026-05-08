--  End-to-end Ada binding tests for the high-level Itb.Encryptor
--  surface — Ada mirror of bindings/rust/tests/test_easy_roundtrip.rs.
--
--  Lifecycle tests (close / scope-exit / handle invalidation),
--  structural validation (bad primitive / MAC / key_bits / mode),
--  full-matrix round-trips for both Single and Triple Ouroboros, and
--  per-instance configuration setters that mutate only the local
--  Config copy without touching libitb's process-global state.

with Ada.Calendar;
with Ada.Streams;  use Ada.Streams;
with Ada.Text_IO;

with Interfaces;   use Interfaces;

with Itb;          use Itb;
with Itb.Encryptor;
with Itb.Errors;
with Itb.Status;

procedure Test_Easy_Roundtrip is

   type Width_Pair is record
      Name  : access constant String;
      Width : Integer;
   end record;
   type Width_Pair_Array is array (Positive range <>) of Width_Pair;

   Hash_Areion256  : aliased constant String := "areion256";
   Hash_Areion512  : aliased constant String := "areion512";
   Hash_Siphash24  : aliased constant String := "siphash24";
   Hash_Aescmac    : aliased constant String := "aescmac";
   Hash_Blake2b256 : aliased constant String := "blake2b256";
   Hash_Blake2b512 : aliased constant String := "blake2b512";
   Hash_Blake2s    : aliased constant String := "blake2s";
   Hash_Blake3     : aliased constant String := "blake3";
   Hash_Chacha20   : aliased constant String := "chacha20";

   Canonical_Hashes : constant Width_Pair_Array :=
     [(Hash_Areion256'Access,  256),
      (Hash_Areion512'Access,  512),
      (Hash_Siphash24'Access,  128),
      (Hash_Aescmac'Access,    128),
      (Hash_Blake2b256'Access, 256),
      (Hash_Blake2b512'Access, 512),
      (Hash_Blake2s'Access,    256),
      (Hash_Blake3'Access,     256),
      (Hash_Chacha20'Access,   256)];

   type Int_Array is array (Positive range <>) of Integer;
   All_Key_Bits : constant Int_Array := [512, 1024, 2048];

   State : Unsigned_64 :=
     Unsigned_64 (Ada.Calendar.Seconds (Ada.Calendar.Clock) * 1.0E6)
     xor 16#F00DCAFE_BAADF00D#;

   function Token_Bytes (N : Stream_Element_Offset) return Byte_Array is
      Out_Buf : Byte_Array (1 .. N);
   begin
      for I in Out_Buf'Range loop
         State := State * 6364136223846793005 + 1442695040888963407;
         Out_Buf (I) := Stream_Element (Shift_Right (State, 33) and 16#FF#);
      end loop;
      return Out_Buf;
   end Token_Bytes;

begin

   ------------------------------------------------------------------
   --  new_and_free — accessors return constructor arguments; Close
   --  releases the handle.
   ------------------------------------------------------------------
   declare
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
   begin
      if Itb.Encryptor.Primitive (Enc) /= "blake3" then
         raise Program_Error
           with "primitive: '" & Itb.Encryptor.Primitive (Enc) & "'";
      end if;
      if Itb.Encryptor.Key_Bits (Enc) /= 1024 then
         raise Program_Error
           with "key_bits:" & Itb.Encryptor.Key_Bits (Enc)'Image;
      end if;
      if Itb.Encryptor.Mode (Enc) /= 1 then
         raise Program_Error
           with "mode:" & Itb.Encryptor.Mode (Enc)'Image;
      end if;
      if Itb.Encryptor.MAC_Name (Enc) /= "kmac256" then
         raise Program_Error
           with "mac_name: '" & Itb.Encryptor.MAC_Name (Enc) & "'";
      end if;
      Itb.Encryptor.Close (Enc);
   end;

   ------------------------------------------------------------------
   --  scope_exit_releases_handle — Limited_Controlled finalisation
   --  runs at scope exit.
   ------------------------------------------------------------------
   for I in 1 .. 8 loop
      declare
         Enc : Itb.Encryptor.Encryptor :=
           Itb.Encryptor.Make ("areion256", 1024, "kmac256", 1);
         pragma Unreferenced (Enc);
      begin
         null;
      end;
   end loop;

   ------------------------------------------------------------------
   --  double_close_idempotent
   ------------------------------------------------------------------
   declare
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
   begin
      Itb.Encryptor.Close (Enc);
      Itb.Encryptor.Close (Enc);
   end;

   ------------------------------------------------------------------
   --  close_then_method_raises — Encrypt after Close surfaces
   --  Easy_Closed.
   ------------------------------------------------------------------
   declare
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
      Payload : constant Byte_Array :=
        [Stream_Element (Character'Pos ('a')),
         Stream_Element (Character'Pos ('b')),
         Stream_Element (Character'Pos ('c'))];
   begin
      Itb.Encryptor.Close (Enc);
      declare
         Ct : constant Byte_Array := Itb.Encryptor.Encrypt (Enc, Payload);
         pragma Unreferenced (Ct);
      begin
         raise Program_Error with "Encrypt after Close must raise";
      end;
   exception
      when E : Itb.Errors.Itb_Error =>
         if Itb.Errors.Status_Code (E) /= Itb.Status.Easy_Closed then
            raise;
         end if;
   end;

   ------------------------------------------------------------------
   --  defaults — empty primitive / 1024 / empty MAC pick the package
   --  defaults: areion512 / 1024 / hmac-blake3.
   ------------------------------------------------------------------
   declare
      Enc : constant Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("", 1024, "", 1);
   begin
      if Itb.Encryptor.Primitive (Enc) /= "areion512" then
         raise Program_Error
           with "default primitive: '"
                & Itb.Encryptor.Primitive (Enc) & "'";
      end if;
      if Itb.Encryptor.Key_Bits (Enc) /= 1024 then
         raise Program_Error
           with "default key_bits:"
                & Itb.Encryptor.Key_Bits (Enc)'Image;
      end if;
      if Itb.Encryptor.Mode (Enc) /= 1 then
         raise Program_Error
           with "default mode:" & Itb.Encryptor.Mode (Enc)'Image;
      end if;
      if Itb.Encryptor.MAC_Name (Enc) /= "hmac-blake3" then
         raise Program_Error
           with "default mac: '"
                & Itb.Encryptor.MAC_Name (Enc) & "'";
      end if;
   end;

   ------------------------------------------------------------------
   --  bad_primitive
   ------------------------------------------------------------------
   begin
      declare
         Enc : Itb.Encryptor.Encryptor :=
           Itb.Encryptor.Make ("nonsense-hash", 1024, "kmac256", 1);
         pragma Unreferenced (Enc);
      begin
         raise Program_Error with "bad primitive must raise";
      end;
   exception
      when Itb.Errors.Itb_Error =>
         null;
   end;

   ------------------------------------------------------------------
   --  bad_mac
   ------------------------------------------------------------------
   begin
      declare
         Enc : Itb.Encryptor.Encryptor :=
           Itb.Encryptor.Make ("blake3", 1024, "nonsense-mac", 1);
         pragma Unreferenced (Enc);
      begin
         raise Program_Error with "bad mac must raise";
      end;
   exception
      when Itb.Errors.Itb_Error =>
         null;
   end;

   ------------------------------------------------------------------
   --  bad_key_bits
   ------------------------------------------------------------------
   declare
      Bad_Bits : constant Int_Array := [256, 511, 999, 2049];
   begin
      for KB of Bad_Bits loop
         begin
            declare
               Enc : Itb.Encryptor.Encryptor :=
                 Itb.Encryptor.Make ("blake3", KB, "kmac256", 1);
               pragma Unreferenced (Enc);
            begin
               raise Program_Error
                 with "key_bits=" & KB'Image & " must be rejected";
            end;
         exception
            when Itb.Errors.Itb_Error =>
               null;
         end;
      end loop;
   end;

   ------------------------------------------------------------------
   --  bad_mode — Mode_Type's static predicate carves out 1 | 3, so
   --  any other value is rejected. Under the project's default build
   --  flags (no -gnata) the predicate is not enforced at runtime, so
   --  the offending value reaches libitb and surfaces as Bad_Input.
   ------------------------------------------------------------------
   begin
      declare
         Enc : Itb.Encryptor.Encryptor :=
           Itb.Encryptor.Make ("blake3", 1024, "kmac256", 2);
         pragma Unreferenced (Enc);
      begin
         raise Program_Error with "Mode=2 must be rejected";
      end;
   exception
      when Constraint_Error =>
         null;
      when E : Itb.Errors.Itb_Error =>
         if Itb.Errors.Status_Code (E) /= Itb.Status.Bad_Input then
            raise;
         end if;
   end;

   ------------------------------------------------------------------
   --  all_hashes_all_widths_single — full matrix Encrypt/Decrypt.
   ------------------------------------------------------------------
   declare
      Plaintext : constant Byte_Array := Token_Bytes (4096);
   begin
      for WP of Canonical_Hashes loop
         for KB of All_Key_Bits loop
            if KB mod WP.Width = 0 then
               declare
                  Enc : Itb.Encryptor.Encryptor :=
                    Itb.Encryptor.Make
                      (WP.Name.all, KB, "kmac256", 1);
                  Ct : constant Byte_Array :=
                    Itb.Encryptor.Encrypt (Enc, Plaintext);
                  Pt : constant Byte_Array :=
                    Itb.Encryptor.Decrypt (Enc, Ct);
               begin
                  if Ct'Length <= Plaintext'Length then
                     raise Program_Error
                       with "ciphertext not larger than plaintext";
                  end if;
                  if Pt /= Plaintext then
                     raise Program_Error
                       with "Single mismatch " & WP.Name.all
                            & "/" & KB'Image;
                  end if;
               end;
            end if;
         end loop;
      end loop;
   end;

   ------------------------------------------------------------------
   --  all_hashes_all_widths_single_auth
   ------------------------------------------------------------------
   declare
      Plaintext : constant Byte_Array := Token_Bytes (4096);
   begin
      for WP of Canonical_Hashes loop
         for KB of All_Key_Bits loop
            if KB mod WP.Width = 0 then
               declare
                  Enc : Itb.Encryptor.Encryptor :=
                    Itb.Encryptor.Make
                      (WP.Name.all, KB, "kmac256", 1);
                  Ct : constant Byte_Array :=
                    Itb.Encryptor.Encrypt_Auth (Enc, Plaintext);
                  Pt : constant Byte_Array :=
                    Itb.Encryptor.Decrypt_Auth (Enc, Ct);
               begin
                  if Pt /= Plaintext then
                     raise Program_Error
                       with "Single auth mismatch " & WP.Name.all;
                  end if;
               end;
            end if;
         end loop;
      end loop;
   end;

   ------------------------------------------------------------------
   --  byte_array_input_roundtrip — Byte_Array slicing is the
   --  canonical input shape; any slice survives the round-trip.
   ------------------------------------------------------------------
   declare
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
      Source : constant String := "hello bytearray";
      Payload : Byte_Array (1 .. Stream_Element_Offset (Source'Length));
   begin
      for I in Source'Range loop
         Payload (Stream_Element_Offset (I - Source'First + 1)) :=
           Stream_Element (Character'Pos (Source (I)));
      end loop;
      declare
         Ct : constant Byte_Array := Itb.Encryptor.Encrypt (Enc, Payload);
         Pt : constant Byte_Array := Itb.Encryptor.Decrypt (Enc, Ct);
      begin
         if Pt /= Payload then
            raise Program_Error with "byte-array roundtrip mismatch";
         end if;
      end;
   end;

   ------------------------------------------------------------------
   --  all_hashes_all_widths_triple
   ------------------------------------------------------------------
   declare
      Plaintext : constant Byte_Array := Token_Bytes (4096);
   begin
      for WP of Canonical_Hashes loop
         for KB of All_Key_Bits loop
            if KB mod WP.Width = 0 then
               declare
                  Enc : Itb.Encryptor.Encryptor :=
                    Itb.Encryptor.Make
                      (WP.Name.all, KB, "kmac256", 3);
                  Ct : constant Byte_Array :=
                    Itb.Encryptor.Encrypt (Enc, Plaintext);
                  Pt : constant Byte_Array :=
                    Itb.Encryptor.Decrypt (Enc, Ct);
               begin
                  if Ct'Length <= Plaintext'Length then
                     raise Program_Error
                       with "ciphertext not larger than plaintext";
                  end if;
                  if Pt /= Plaintext then
                     raise Program_Error
                       with "Triple mismatch " & WP.Name.all
                            & "/" & KB'Image;
                  end if;
               end;
            end if;
         end loop;
      end loop;
   end;

   ------------------------------------------------------------------
   --  all_hashes_all_widths_triple_auth
   ------------------------------------------------------------------
   declare
      Plaintext : constant Byte_Array := Token_Bytes (4096);
   begin
      for WP of Canonical_Hashes loop
         for KB of All_Key_Bits loop
            if KB mod WP.Width = 0 then
               declare
                  Enc : Itb.Encryptor.Encryptor :=
                    Itb.Encryptor.Make
                      (WP.Name.all, KB, "kmac256", 3);
                  Ct : constant Byte_Array :=
                    Itb.Encryptor.Encrypt_Auth (Enc, Plaintext);
                  Pt : constant Byte_Array :=
                    Itb.Encryptor.Decrypt_Auth (Enc, Ct);
               begin
                  if Pt /= Plaintext then
                     raise Program_Error
                       with "Triple auth mismatch " & WP.Name.all;
                  end if;
               end;
            end if;
         end loop;
      end loop;
   end;

   ------------------------------------------------------------------
   --  seed_count_reflects_mode — Single = 3 seeds, Triple = 7 seeds.
   ------------------------------------------------------------------
   declare
      Enc1 : constant Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
      Enc3 : constant Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 3);
   begin
      if Itb.Encryptor.Seed_Count (Enc1) /= 3 then
         raise Program_Error
           with "Single seed_count:"
                & Itb.Encryptor.Seed_Count (Enc1)'Image;
      end if;
      if Itb.Encryptor.Seed_Count (Enc3) /= 7 then
         raise Program_Error
           with "Triple seed_count:"
                & Itb.Encryptor.Seed_Count (Enc3)'Image;
      end if;
   end;

   ------------------------------------------------------------------
   --  set_bit_soup
   ------------------------------------------------------------------
   declare
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
      Source : constant String := "bit-soup payload";
      Payload : Byte_Array (1 .. Stream_Element_Offset (Source'Length));
   begin
      for I in Source'Range loop
         Payload (Stream_Element_Offset (I - Source'First + 1)) :=
           Stream_Element (Character'Pos (Source (I)));
      end loop;
      Itb.Encryptor.Set_Bit_Soup (Enc, 1);
      declare
         Ct : constant Byte_Array := Itb.Encryptor.Encrypt (Enc, Payload);
         Pt : constant Byte_Array := Itb.Encryptor.Decrypt (Enc, Ct);
      begin
         if Pt /= Payload then
            raise Program_Error with "bit-soup roundtrip mismatch";
         end if;
      end;
   end;

   ------------------------------------------------------------------
   --  set_lock_soup_couples_bit_soup
   ------------------------------------------------------------------
   declare
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
      Source : constant String := "lock-soup payload";
      Payload : Byte_Array (1 .. Stream_Element_Offset (Source'Length));
   begin
      for I in Source'Range loop
         Payload (Stream_Element_Offset (I - Source'First + 1)) :=
           Stream_Element (Character'Pos (Source (I)));
      end loop;
      Itb.Encryptor.Set_Lock_Soup (Enc, 1);
      declare
         Ct : constant Byte_Array := Itb.Encryptor.Encrypt (Enc, Payload);
         Pt : constant Byte_Array := Itb.Encryptor.Decrypt (Enc, Ct);
      begin
         if Pt /= Payload then
            raise Program_Error with "lock-soup roundtrip mismatch";
         end if;
      end;
   end;

   ------------------------------------------------------------------
   --  set_lock_seed_grows_seed_count
   ------------------------------------------------------------------
   declare
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
      Source : constant String := "lockseed payload";
      Payload : Byte_Array (1 .. Stream_Element_Offset (Source'Length));
   begin
      for I in Source'Range loop
         Payload (Stream_Element_Offset (I - Source'First + 1)) :=
           Stream_Element (Character'Pos (Source (I)));
      end loop;
      if Itb.Encryptor.Seed_Count (Enc) /= 3 then
         raise Program_Error with "pre Seed_Count not 3";
      end if;
      Itb.Encryptor.Set_Lock_Seed (Enc, 1);
      if Itb.Encryptor.Seed_Count (Enc) /= 4 then
         raise Program_Error
           with "post Seed_Count:" & Itb.Encryptor.Seed_Count (Enc)'Image;
      end if;
      declare
         Ct : constant Byte_Array := Itb.Encryptor.Encrypt (Enc, Payload);
         Pt : constant Byte_Array := Itb.Encryptor.Decrypt (Enc, Ct);
      begin
         if Pt /= Payload then
            raise Program_Error with "lockseed roundtrip mismatch";
         end if;
      end;
   end;

   ------------------------------------------------------------------
   --  set_lock_seed_after_encrypt_rejected
   ------------------------------------------------------------------
   declare
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
      Source : constant String := "first";
      Payload : Byte_Array (1 .. Stream_Element_Offset (Source'Length));
   begin
      for I in Source'Range loop
         Payload (Stream_Element_Offset (I - Source'First + 1)) :=
           Stream_Element (Character'Pos (Source (I)));
      end loop;
      declare
         Ct : constant Byte_Array := Itb.Encryptor.Encrypt (Enc, Payload);
         pragma Unreferenced (Ct);
      begin
         null;
      end;
      begin
         Itb.Encryptor.Set_Lock_Seed (Enc, 1);
         raise Program_Error
           with "Set_Lock_Seed after encrypt must raise";
      exception
         when E : Itb.Errors.Itb_Error =>
            if Itb.Errors.Status_Code (E) /=
               Itb.Status.Easy_LockSeed_After_Encrypt
            then
               raise;
            end if;
      end;
   end;

   ------------------------------------------------------------------
   --  set_nonce_bits_validation
   ------------------------------------------------------------------
   declare
      Enc : constant Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
      Valid : constant Int_Array := [128, 256, 512];
      Bad   : constant Int_Array := [0, 1, 192, 1024];
   begin
      for V of Valid loop
         Itb.Encryptor.Set_Nonce_Bits (Enc, V);
      end loop;
      for B of Bad loop
         begin
            Itb.Encryptor.Set_Nonce_Bits (Enc, B);
            raise Program_Error
              with "Set_Nonce_Bits=" & B'Image & " must be rejected";
         exception
            when E : Itb.Errors.Itb_Error =>
               if Itb.Errors.Status_Code (E) /= Itb.Status.Bad_Input then
                  raise;
               end if;
         end;
      end loop;
   end;

   ------------------------------------------------------------------
   --  set_barrier_fill_validation
   ------------------------------------------------------------------
   declare
      Enc : constant Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
      Valid : constant Int_Array := [1, 2, 4, 8, 16, 32];
      Bad   : constant Int_Array := [0, 3, 5, 7, 64];
   begin
      for V of Valid loop
         Itb.Encryptor.Set_Barrier_Fill (Enc, V);
      end loop;
      for B of Bad loop
         begin
            Itb.Encryptor.Set_Barrier_Fill (Enc, B);
            raise Program_Error
              with "Set_Barrier_Fill=" & B'Image & " must be rejected";
         exception
            when E : Itb.Errors.Itb_Error =>
               if Itb.Errors.Status_Code (E) /= Itb.Status.Bad_Input then
                  raise;
               end if;
         end;
      end loop;
   end;

   ------------------------------------------------------------------
   --  set_chunk_size_accepted — Set_Chunk_Size accepts any
   --  non-negative value including 0 (auto-detect via Itb.Chunk_Size).
   ------------------------------------------------------------------
   declare
      Enc : constant Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
   begin
      Itb.Encryptor.Set_Chunk_Size (Enc, 1024);
      Itb.Encryptor.Set_Chunk_Size (Enc, 0);
   end;

   ------------------------------------------------------------------
   --  two_encryptors_isolated — per-instance Config snapshots are
   --  independent.
   ------------------------------------------------------------------
   declare
      A : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
      B : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
      Pa : constant Byte_Array :=
        [Stream_Element (Character'Pos ('a'))];
      Pb : constant Byte_Array :=
        [Stream_Element (Character'Pos ('b'))];
   begin
      Itb.Encryptor.Set_Lock_Soup (A, 1);
      declare
         Ct_A : constant Byte_Array := Itb.Encryptor.Encrypt (A, Pa);
         Pt_A : constant Byte_Array := Itb.Encryptor.Decrypt (A, Ct_A);
         Ct_B : constant Byte_Array := Itb.Encryptor.Encrypt (B, Pb);
         Pt_B : constant Byte_Array := Itb.Encryptor.Decrypt (B, Ct_B);
      begin
         if Pt_A /= Pa or else Pt_B /= Pb then
            raise Program_Error with "isolated encryptors mismatch";
         end if;
      end;
   end;

   Ada.Text_IO.Put_Line ("test_easy_roundtrip: PASS");
end Test_Easy_Roundtrip;
