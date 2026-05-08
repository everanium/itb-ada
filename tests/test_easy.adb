--  Phase-4 smoke for the Itb.Encryptor surface — confirms the
--  high-level Easy Mode wrapper round-trips plaintext under Single +
--  Triple Ouroboros, authenticates on tampered ciphertext, survives
--  Export_State / Import_State on a fresh encryptor, and that the
--  per-instance read-only accessors (Primitive, Key_Bits, Mode,
--  MAC_Name, Is_Mixed, Seed_Count) reflect the constructor arguments.
--
--  Mirrors bindings/rust/tests/test_easy.rs file-for-file. Lock-soup
--  coverage (Set_Lock_Soup / Set_Lock_Seed / Attach_Lock_Seed) lives
--  in Phase-5A's test_attach_lock_seed.adb (low-level) and in the
--  Phase-5D mixed / lock_seed integration tests.
--
--  Each test_easy*.adb main procedure compiles into its own
--  executable and runs in its own process with a fresh libitb global
--  state, so per-test serialisation is unnecessary.

with Ada.Streams;  use Ada.Streams;
with Ada.Strings.Unbounded;
with Ada.Text_IO;

with Itb;          use Itb;
with Itb.Encryptor;
with Itb.Errors;
with Itb.Status;

procedure Test_Easy is

   function To_Bytes (S : String) return Byte_Array is
      Result : Byte_Array (1 .. Stream_Element_Offset (S'Length));
   begin
      for I in S'Range loop
         Result (Stream_Element_Offset (I - S'First + 1)) :=
           Stream_Element (Character'Pos (S (I)));
      end loop;
      return Result;
   end To_Bytes;

   Plaintext : constant Byte_Array :=
     To_Bytes ("Lorem ipsum dolor sit amet, consectetur adipiscing elit.");

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
   --  single_roundtrip_blake3_kmac256 — round-trip + accessor sanity.
   ------------------------------------------------------------------
   declare
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
      Ct : constant Byte_Array := Itb.Encryptor.Encrypt (Enc, Plaintext);
      Pt : constant Byte_Array := Itb.Encryptor.Decrypt (Enc, Ct);
   begin
      if Ct = Plaintext then
         raise Program_Error with "ciphertext equals plaintext";
      end if;
      if Pt /= Plaintext then
         raise Program_Error with "single_roundtrip mismatch";
      end if;
      if Itb.Encryptor.Primitive (Enc) /= "blake3" then
         raise Program_Error with "primitive accessor: '"
                                   & Itb.Encryptor.Primitive (Enc) & "'";
      end if;
      if Itb.Encryptor.Key_Bits (Enc) /= 1024 then
         raise Program_Error with "key_bits accessor:"
                                   & Itb.Encryptor.Key_Bits (Enc)'Image;
      end if;
      if Itb.Encryptor.Mode (Enc) /= 1 then
         raise Program_Error with "mode accessor:"
                                   & Itb.Encryptor.Mode (Enc)'Image;
      end if;
      if Itb.Encryptor.MAC_Name (Enc) /= "kmac256" then
         raise Program_Error with "mac_name accessor: '"
                                   & Itb.Encryptor.MAC_Name (Enc) & "'";
      end if;
      if Itb.Encryptor.Is_Mixed (Enc) then
         raise Program_Error with "Is_Mixed should be False";
      end if;
      if Itb.Encryptor.Seed_Count (Enc) /= 3 then
         raise Program_Error with "seed_count accessor:"
                                   & Itb.Encryptor.Seed_Count (Enc)'Image;
      end if;
   end;

   ------------------------------------------------------------------
   --  triple_roundtrip_areion512_kmac256 — Triple Ouroboros, 7 seeds.
   ------------------------------------------------------------------
   declare
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("areion512", 2048, "kmac256", 3);
      Ct : constant Byte_Array := Itb.Encryptor.Encrypt (Enc, Plaintext);
      Pt : constant Byte_Array := Itb.Encryptor.Decrypt (Enc, Ct);
   begin
      if Pt /= Plaintext then
         raise Program_Error with "triple_roundtrip mismatch";
      end if;
      if Itb.Encryptor.Primitive (Enc) /= "areion512" then
         raise Program_Error with "primitive accessor: '"
                                   & Itb.Encryptor.Primitive (Enc) & "'";
      end if;
      if Itb.Encryptor.Mode (Enc) /= 3 then
         raise Program_Error with "mode accessor:"
                                   & Itb.Encryptor.Mode (Enc)'Image;
      end if;
      if Itb.Encryptor.Seed_Count (Enc) /= 7 then
         raise Program_Error with "seed_count accessor:"
                                   & Itb.Encryptor.Seed_Count (Enc)'Image;
      end if;
   end;

   ------------------------------------------------------------------
   --  auth_roundtrip_single — Encrypt_Auth + Decrypt_Auth.
   ------------------------------------------------------------------
   declare
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
      Ct  : constant Byte_Array :=
        Itb.Encryptor.Encrypt_Auth (Enc, Plaintext);
      Pt  : constant Byte_Array :=
        Itb.Encryptor.Decrypt_Auth (Enc, Ct);
   begin
      if Pt /= Plaintext then
         raise Program_Error with "auth_roundtrip_single mismatch";
      end if;
   end;

   ------------------------------------------------------------------
   --  auth_decrypt_tampered_fails_with_mac_failure — flip 256 bytes
   --  starting at the chunk header boundary; must surface MAC_Failure.
   ------------------------------------------------------------------
   declare
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
      Ct  : constant Byte_Array :=
        Itb.Encryptor.Encrypt_Auth (Enc, Plaintext);
      Tampered : Byte_Array := Ct;
   begin
      Tamper (Enc, Tampered);
      declare
         Pt2 : constant Byte_Array :=
           Itb.Encryptor.Decrypt_Auth (Enc, Tampered);
         pragma Unreferenced (Pt2);
      begin
         raise Program_Error with "Decrypt_Auth on tampered ct must raise";
      end;
   exception
      when E : Itb.Errors.Itb_Error =>
         if Itb.Errors.Status_Code (E) /= Itb.Status.MAC_Failure then
            raise;
         end if;
   end;

   ------------------------------------------------------------------
   --  export_import_roundtrip — Export_State + Peek_Config + fresh
   --  encryptor + Import_State + Decrypt_Auth.
   ------------------------------------------------------------------
   declare
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
      Ct  : constant Byte_Array :=
        Itb.Encryptor.Encrypt_Auth (Enc, Plaintext);
      Blob : constant Byte_Array := Itb.Encryptor.Export_State (Enc);
      PC   : constant Itb.Encryptor.Peeked_Config :=
        Itb.Encryptor.Peek_Config (Blob);
   begin
      if Blob'Length = 0 then
         raise Program_Error with "exported state blob is empty";
      end if;
      if Ada.Strings.Unbounded.To_String (PC.Primitive) /= "blake3" then
         raise Program_Error
           with "peek primitive: '"
                & Ada.Strings.Unbounded.To_String (PC.Primitive) & "'";
      end if;
      if PC.Key_Bits /= 1024 then
         raise Program_Error with "peek key_bits:" & PC.Key_Bits'Image;
      end if;
      if PC.Mode /= 1 then
         raise Program_Error with "peek mode:" & PC.Mode'Image;
      end if;
      if Ada.Strings.Unbounded.To_String (PC.MAC_Name) /= "kmac256" then
         raise Program_Error
           with "peek mac_name: '"
                & Ada.Strings.Unbounded.To_String (PC.MAC_Name) & "'";
      end if;
      declare
         Dec : Itb.Encryptor.Encryptor :=
           Itb.Encryptor.Make
             (Ada.Strings.Unbounded.To_String (PC.Primitive),
              PC.Key_Bits,
              Ada.Strings.Unbounded.To_String (PC.MAC_Name),
              PC.Mode);
      begin
         Itb.Encryptor.Import_State (Dec, Blob);
         declare
            Pt : constant Byte_Array :=
              Itb.Encryptor.Decrypt_Auth (Dec, Ct);
         begin
            if Pt /= Plaintext then
               raise Program_Error with "import_state decrypt mismatch";
            end if;
         end;
      end;
   end;

   ------------------------------------------------------------------
   --  peek_config_returns_correct_tuple — round-trip with hmac-blake3.
   ------------------------------------------------------------------
   declare
      Enc : constant Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("areion512", 2048, "hmac-blake3", 3);
      Blob : constant Byte_Array := Itb.Encryptor.Export_State (Enc);
      PC   : constant Itb.Encryptor.Peeked_Config :=
        Itb.Encryptor.Peek_Config (Blob);
   begin
      if Ada.Strings.Unbounded.To_String (PC.Primitive) /= "areion512" then
         raise Program_Error
           with "peek primitive: '"
                & Ada.Strings.Unbounded.To_String (PC.Primitive) & "'";
      end if;
      if PC.Key_Bits /= 2048 then
         raise Program_Error with "peek key_bits:" & PC.Key_Bits'Image;
      end if;
      if PC.Mode /= 3 then
         raise Program_Error with "peek mode:" & PC.Mode'Image;
      end if;
      if Ada.Strings.Unbounded.To_String (PC.MAC_Name) /= "hmac-blake3" then
         raise Program_Error
           with "peek mac_name: '"
                & Ada.Strings.Unbounded.To_String (PC.MAC_Name) & "'";
      end if;
   end;

   ------------------------------------------------------------------
   --  mixed_single_three_same_width_primitives — three 256-bit
   --  primitives (areion256, blake3, blake2s) share the native hash
   --  width, so Mixed_Single accepts them as a valid (N, D, S) trio
   --  at key_bits = 1024 (a multiple of 256).
   ------------------------------------------------------------------
   declare
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Mixed_Single
          (Prim_N   => "areion256",
           Prim_D   => "blake3",
           Prim_S   => "blake2s",
           Prim_L   => "",
           Key_Bits => 1024,
           Mac_Name => "kmac256");
      Ct : constant Byte_Array :=
        Itb.Encryptor.Encrypt_Auth (Enc, Plaintext);
      Pt : constant Byte_Array :=
        Itb.Encryptor.Decrypt_Auth (Enc, Ct);
   begin
      if not Itb.Encryptor.Is_Mixed (Enc) then
         raise Program_Error with "Mixed_Single Is_Mixed should be True";
      end if;
      if Itb.Encryptor.Primitive_At (Enc, 0) /= "areion256" then
         raise Program_Error
           with "primitive_at(0): '"
                & Itb.Encryptor.Primitive_At (Enc, 0) & "'";
      end if;
      if Itb.Encryptor.Primitive_At (Enc, 1) /= "blake3" then
         raise Program_Error
           with "primitive_at(1): '"
                & Itb.Encryptor.Primitive_At (Enc, 1) & "'";
      end if;
      if Itb.Encryptor.Primitive_At (Enc, 2) /= "blake2s" then
         raise Program_Error
           with "primitive_at(2): '"
                & Itb.Encryptor.Primitive_At (Enc, 2) & "'";
      end if;
      if Pt /= Plaintext then
         raise Program_Error with "Mixed_Single auth round-trip mismatch";
      end if;
   end;

   ------------------------------------------------------------------
   --  invalid_mode_rejected — Mode_Type's Static_Predicate carves
   --  out 1 | 3, so any other value (e.g. 2) is rejected before the
   --  encryptor is constructed. Under the project's default build
   --  flags (no -gnata) the predicate is not enforced at runtime, so
   --  the offending value reaches libitb and surfaces as Itb_Error /
   --  Bad_Input — the same outcome the Rust counterpart asserts via
   --  STATUS_BAD_INPUT. Wrapped as a nested block + outer handler
   --  because an exception raised during declarative-part elaboration
   --  propagates past local handlers into the enclosing scope.
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
   --  close_is_idempotent — multiple Close calls return without
   --  raising.
   ------------------------------------------------------------------
   declare
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
   begin
      Itb.Encryptor.Close (Enc);
      Itb.Encryptor.Close (Enc);
   end;

   ------------------------------------------------------------------
   --  header_size_matches_nonce_bits — header = nonce(N) + width(2)
   --  + height(2).
   ------------------------------------------------------------------
   declare
      Enc : constant Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
      NB : constant Integer := Itb.Encryptor.Nonce_Bits (Enc);
      HS : constant Integer := Itb.Encryptor.Header_Size (Enc);
   begin
      if HS /= NB / 8 + 4 then
         raise Program_Error
           with "header_size mismatch: HS=" & HS'Image
                & " NB=" & NB'Image;
      end if;
   end;

   ------------------------------------------------------------------
   --  parse_chunk_len_matches_chunk_length — feed the encryptor's own
   --  chunk header back through Parse_Chunk_Len; the parsed length
   --  must equal the on-the-wire ciphertext size.
   ------------------------------------------------------------------
   declare
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
      Ct  : constant Byte_Array := Itb.Encryptor.Encrypt (Enc, Plaintext);
      HS  : constant Stream_Element_Offset :=
        Stream_Element_Offset (Itb.Encryptor.Header_Size (Enc));
      Parsed : constant Natural :=
        Itb.Encryptor.Parse_Chunk_Len (Enc, Ct (Ct'First .. Ct'First + HS - 1));
   begin
      if Stream_Element_Offset (Parsed) /= Ct'Length then
         raise Program_Error
           with "parse_chunk_len mismatch:" & Parsed'Image
                & " vs" & Ct'Length'Image;
      end if;
   end;

   ------------------------------------------------------------------
   --  default_mac_override — Make ("blake3", 1024) (no Mac_Name) must
   --  override the empty string to "hmac-blake3" before any FFI call.
   --  This mirrors the documented Easy Mode contract: the binding
   --  substitutes the default MAC name when the caller omits it, so
   --  libitb never sees an empty Mac_Name selector.
   ------------------------------------------------------------------
   declare
      Enc : constant Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024);
   begin
      if Itb.Encryptor.MAC_Name (Enc) /= "hmac-blake3" then
         raise Program_Error
           with "default-MAC override: '"
                & Itb.Encryptor.MAC_Name (Enc) & "'";
      end if;
   end;

   Ada.Text_IO.Put_Line ("test_easy: PASS");
end Test_Easy;
