--  Mixed-mode Encryptor (per-slot PRF primitive selection) tests —
--  Ada mirror of bindings/rust/tests/test_easy_mixed.rs.
--
--  Round-trip on Single + Triple under Itb.Encryptor.Mixed_Single /
--  Itb.Encryptor.Mixed_Triple; optional dedicated lockSeed under its
--  own primitive; state-blob Export_State / Import_State; mixed-width
--  rejection through the cgo boundary; per-slot introspection
--  accessors (Itb.Encryptor.Primitive_At, Itb.Encryptor.Is_Mixed).

with Ada.Calendar;
with Ada.Streams;  use Ada.Streams;
with Ada.Text_IO;

with Interfaces;   use Interfaces;

with Itb;          use Itb;
with Itb.Encryptor;
with Itb.Errors;

procedure Test_Easy_Mixed is

   State : Unsigned_64 :=
     Unsigned_64 (Ada.Calendar.Seconds (Ada.Calendar.Clock) * 1.0E6)
     xor 16#FEEDFACE_DEC0DED0#;

   function Token_Bytes (N : Stream_Element_Offset) return Byte_Array is
      Out_Buf : Byte_Array (1 .. N);
   begin
      for I in Out_Buf'Range loop
         State := State * 6364136223846793005 + 1442695040888963407;
         Out_Buf (I) := Stream_Element (Shift_Right (State, 33) and 16#FF#);
      end loop;
      return Out_Buf;
   end Token_Bytes;

   function To_Bytes (S : String) return Byte_Array is
      Result : Byte_Array (1 .. Stream_Element_Offset (S'Length));
   begin
      for I in S'Range loop
         Result (Stream_Element_Offset (I - S'First + 1)) :=
           Stream_Element (Character'Pos (S (I)));
      end loop;
      return Result;
   end To_Bytes;

begin

   ------------------------------------------------------------------
   --  mixed_single_basic_roundtrip — three 256-bit primitives in the
   --  N / D / S slots, no dedicated lockSeed.
   ------------------------------------------------------------------
   declare
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Mixed_Single
          (Prim_N   => "blake3",
           Prim_D   => "blake2s",
           Prim_S   => "areion256",
           Prim_L   => "",
           Key_Bits => 1024,
           Mac_Name => "kmac256");
      Plaintext : constant Byte_Array :=
        To_Bytes ("ada mixed Single roundtrip payload");
      Ct : constant Byte_Array := Itb.Encryptor.Encrypt (Enc, Plaintext);
      Pt : constant Byte_Array := Itb.Encryptor.Decrypt (Enc, Ct);
   begin
      if not Itb.Encryptor.Is_Mixed (Enc) then
         raise Program_Error with "Is_Mixed should be True";
      end if;
      if Itb.Encryptor.Primitive (Enc) /= "mixed" then
         raise Program_Error
           with "primitive accessor: '"
                & Itb.Encryptor.Primitive (Enc) & "'";
      end if;
      if Itb.Encryptor.Primitive_At (Enc, 0) /= "blake3" then
         raise Program_Error
           with "primitive_at(0): '"
                & Itb.Encryptor.Primitive_At (Enc, 0) & "'";
      end if;
      if Itb.Encryptor.Primitive_At (Enc, 1) /= "blake2s" then
         raise Program_Error
           with "primitive_at(1): '"
                & Itb.Encryptor.Primitive_At (Enc, 1) & "'";
      end if;
      if Itb.Encryptor.Primitive_At (Enc, 2) /= "areion256" then
         raise Program_Error
           with "primitive_at(2): '"
                & Itb.Encryptor.Primitive_At (Enc, 2) & "'";
      end if;
      if Pt /= Plaintext then
         raise Program_Error with "mixed Single round-trip mismatch";
      end if;
   end;

   ------------------------------------------------------------------
   --  mixed_single_with_dedicated_lockseed — Prim_L = "areion256"
   --  allocates a 4th seed slot under its own primitive.
   ------------------------------------------------------------------
   declare
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Mixed_Single
          (Prim_N   => "blake3",
           Prim_D   => "blake2s",
           Prim_S   => "blake3",
           Prim_L   => "areion256",
           Key_Bits => 1024,
           Mac_Name => "kmac256");
      Plaintext : constant Byte_Array :=
        To_Bytes ("ada mixed Single + dedicated lockSeed payload");
      Ct : constant Byte_Array :=
        Itb.Encryptor.Encrypt_Auth (Enc, Plaintext);
      Pt : constant Byte_Array :=
        Itb.Encryptor.Decrypt_Auth (Enc, Ct);
   begin
      if Itb.Encryptor.Primitive_At (Enc, 3) /= "areion256" then
         raise Program_Error
           with "primitive_at(3): '"
                & Itb.Encryptor.Primitive_At (Enc, 3) & "'";
      end if;
      if Pt /= Plaintext then
         raise Program_Error
           with "mixed Single + lockSeed auth mismatch";
      end if;
   end;

   ------------------------------------------------------------------
   --  mixed_single_aescmac_siphash_128bit — SipHash-2-4 in one slot
   --  + AES-CMAC in others — 128-bit width with mixed key shapes
   --  (siphash24 carries no fixed key bytes, aescmac carries 16).
   --  Exercises the per-slot empty / non-empty PRF-key validation
   --  in Export_State / Import_State.
   ------------------------------------------------------------------
   declare
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Mixed_Single
          (Prim_N   => "aescmac",
           Prim_D   => "siphash24",
           Prim_S   => "aescmac",
           Prim_L   => "",
           Key_Bits => 512,
           Mac_Name => "hmac-sha256");
      Plaintext : constant Byte_Array :=
        To_Bytes ("ada mixed 128-bit aescmac+siphash24 mix");
      Ct : constant Byte_Array := Itb.Encryptor.Encrypt (Enc, Plaintext);
      Pt : constant Byte_Array := Itb.Encryptor.Decrypt (Enc, Ct);
   begin
      if Pt /= Plaintext then
         raise Program_Error
           with "mixed 128-bit aescmac+siphash24 mismatch";
      end if;
   end;

   ------------------------------------------------------------------
   --  mixed_triple_basic_roundtrip — seven primitives across the
   --  Triple Ouroboros (N + D1..D3 + S1..S3) slots.
   ------------------------------------------------------------------
   declare
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Mixed_Triple
          (Prim_N   => "areion256",
           Prim_D1  => "blake3",
           Prim_D2  => "blake2s",
           Prim_D3  => "chacha20",
           Prim_S1  => "blake2b256",
           Prim_S2  => "blake3",
           Prim_S3  => "blake2s",
           Prim_L   => "",
           Key_Bits => 1024,
           Mac_Name => "kmac256");
      Plaintext : constant Byte_Array :=
        To_Bytes ("ada mixed Triple roundtrip payload");
      Ct : constant Byte_Array := Itb.Encryptor.Encrypt (Enc, Plaintext);
      Pt : constant Byte_Array := Itb.Encryptor.Decrypt (Enc, Ct);

      type Wants_Array is
        array (Positive range <>) of access constant String;
      Want_Areion256  : aliased constant String := "areion256";
      Want_Blake3     : aliased constant String := "blake3";
      Want_Blake2s    : aliased constant String := "blake2s";
      Want_Chacha20   : aliased constant String := "chacha20";
      Want_Blake2b256 : aliased constant String := "blake2b256";
      Want_Blake3_2   : aliased constant String := "blake3";
      Want_Blake2s_2  : aliased constant String := "blake2s";
      Wants : constant Wants_Array :=
        [Want_Areion256'Access,
         Want_Blake3'Access,
         Want_Blake2s'Access,
         Want_Chacha20'Access,
         Want_Blake2b256'Access,
         Want_Blake3_2'Access,
         Want_Blake2s_2'Access];
   begin
      for I in Wants'Range loop
         declare
            Got : constant String :=
              Itb.Encryptor.Primitive_At (Enc, I - 1);
         begin
            if Got /= Wants (I).all then
               raise Program_Error
                 with "primitive_at(" & Integer'Image (I - 1) & "): '"
                      & Got & "', expected '" & Wants (I).all & "'";
            end if;
         end;
      end loop;
      if Pt /= Plaintext then
         raise Program_Error with "mixed Triple round-trip mismatch";
      end if;
   end;

   ------------------------------------------------------------------
   --  mixed_triple_with_dedicated_lockseed — 8 seed slots; dedicated
   --  lockSeed at index 7.
   ------------------------------------------------------------------
   declare
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Mixed_Triple
          (Prim_N   => "blake3",
           Prim_D1  => "blake2s",
           Prim_D2  => "blake3",
           Prim_D3  => "blake2s",
           Prim_S1  => "blake3",
           Prim_S2  => "blake2s",
           Prim_S3  => "blake3",
           Prim_L   => "areion256",
           Key_Bits => 1024,
           Mac_Name => "kmac256");
      Base : constant Byte_Array :=
        To_Bytes ("ada mixed Triple + lockSeed payload");
      Plaintext : Byte_Array (1 .. Base'Length * 16);
      Ct : Byte_Array (1 .. 0);
      Pt : Byte_Array (1 .. 0);
      pragma Unreferenced (Ct, Pt);
   begin
      for I in 0 .. 15 loop
         Plaintext
           (Stream_Element_Offset (I) * Base'Length + 1
            .. Stream_Element_Offset (I + 1) * Base'Length) :=
           Base;
      end loop;
      if Itb.Encryptor.Primitive_At (Enc, 7) /= "areion256" then
         raise Program_Error
           with "primitive_at(7): '"
                & Itb.Encryptor.Primitive_At (Enc, 7) & "'";
      end if;
      declare
         Ct2 : constant Byte_Array :=
           Itb.Encryptor.Encrypt_Auth (Enc, Plaintext);
         Pt2 : constant Byte_Array :=
           Itb.Encryptor.Decrypt_Auth (Enc, Ct2);
      begin
         if Pt2 /= Plaintext then
            raise Program_Error
              with "mixed Triple + lockSeed auth mismatch";
         end if;
      end;
   end;

   ------------------------------------------------------------------
   --  mixed_single_export_import — round-trip the encryptor state
   --  through Export_State / Import_State.
   ------------------------------------------------------------------
   declare
      Plaintext : constant Byte_Array := Token_Bytes (2048);
      Sender : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Mixed_Single
          (Prim_N   => "blake3",
           Prim_D   => "blake2s",
           Prim_S   => "areion256",
           Prim_L   => "",
           Key_Bits => 1024,
           Mac_Name => "kmac256");
      Ct   : constant Byte_Array :=
        Itb.Encryptor.Encrypt_Auth (Sender, Plaintext);
      Blob : constant Byte_Array :=
        Itb.Encryptor.Export_State (Sender);
   begin
      if Blob'Length = 0 then
         raise Program_Error with "exported blob is empty";
      end if;
      Itb.Encryptor.Close (Sender);
      declare
         Receiver : Itb.Encryptor.Encryptor :=
           Itb.Encryptor.Mixed_Single
             (Prim_N   => "blake3",
              Prim_D   => "blake2s",
              Prim_S   => "areion256",
              Prim_L   => "",
              Key_Bits => 1024,
              Mac_Name => "kmac256");
      begin
         Itb.Encryptor.Import_State (Receiver, Blob);
         declare
            Pt : constant Byte_Array :=
              Itb.Encryptor.Decrypt_Auth (Receiver, Ct);
         begin
            if Pt /= Plaintext then
               raise Program_Error
                 with "mixed Single Export/Import mismatch";
            end if;
         end;
      end;
   end;

   ------------------------------------------------------------------
   --  mixed_triple_export_import_with_lockseed
   ------------------------------------------------------------------
   declare
      Base : constant Byte_Array :=
        To_Bytes ("ada mixed Triple + lockSeed Export/Import");
      Plaintext : Byte_Array (1 .. Base'Length * 16);
      Sender : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Mixed_Triple
          (Prim_N   => "areion256",
           Prim_D1  => "blake3",
           Prim_D2  => "blake2s",
           Prim_D3  => "chacha20",
           Prim_S1  => "blake2b256",
           Prim_S2  => "blake3",
           Prim_S3  => "blake2s",
           Prim_L   => "areion256",
           Key_Bits => 1024,
           Mac_Name => "kmac256");
   begin
      for I in 0 .. 15 loop
         Plaintext
           (Stream_Element_Offset (I) * Base'Length + 1
            .. Stream_Element_Offset (I + 1) * Base'Length) :=
           Base;
      end loop;
      declare
         Ct   : constant Byte_Array :=
           Itb.Encryptor.Encrypt_Auth (Sender, Plaintext);
         Blob : constant Byte_Array :=
           Itb.Encryptor.Export_State (Sender);
      begin
         Itb.Encryptor.Close (Sender);
         declare
            Receiver : Itb.Encryptor.Encryptor :=
              Itb.Encryptor.Mixed_Triple
                (Prim_N   => "areion256",
                 Prim_D1  => "blake3",
                 Prim_D2  => "blake2s",
                 Prim_D3  => "chacha20",
                 Prim_S1  => "blake2b256",
                 Prim_S2  => "blake3",
                 Prim_S3  => "blake2s",
                 Prim_L   => "areion256",
                 Key_Bits => 1024,
                 Mac_Name => "kmac256");
         begin
            Itb.Encryptor.Import_State (Receiver, Blob);
            declare
               Pt : constant Byte_Array :=
                 Itb.Encryptor.Decrypt_Auth (Receiver, Ct);
            begin
               if Pt /= Plaintext then
                  raise Program_Error
                    with "mixed Triple+LS Export/Import mismatch";
               end if;
            end;
         end;
      end;
   end;

   ------------------------------------------------------------------
   --  mixed_shape_mismatch — Mixed blob landing on a single-primitive
   --  receiver must be rejected.
   ------------------------------------------------------------------
   declare
      Mixed_Sender : constant Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Mixed_Single
          (Prim_N   => "blake3",
           Prim_D   => "blake2s",
           Prim_S   => "blake3",
           Prim_L   => "",
           Key_Bits => 1024,
           Mac_Name => "kmac256");
      Mixed_Blob : constant Byte_Array :=
        Itb.Encryptor.Export_State (Mixed_Sender);
   begin
      declare
         Single_Recv : Itb.Encryptor.Encryptor :=
           Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
      begin
         Itb.Encryptor.Import_State (Single_Recv, Mixed_Blob);
         raise Program_Error
           with "Mixed blob into single-primitive receiver must raise";
      exception
         when Itb.Errors.Itb_Error =>
            null;
         when Itb.Errors.Itb_Easy_Mismatch_Error =>
            null;
      end;
   end;

   ------------------------------------------------------------------
   --  reject_mixed_width — mixing a 256-bit primitive with a 512-bit
   --  primitive surfaces as an error from the cgo boundary.
   ------------------------------------------------------------------
   begin
      declare
         Enc : Itb.Encryptor.Encryptor :=
           Itb.Encryptor.Mixed_Single
             (Prim_N   => "blake3",      --  256-bit
              Prim_D   => "areion512",   --  512-bit  <- width mismatch
              Prim_S   => "blake3",
              Prim_L   => "",
              Key_Bits => 1024,
              Mac_Name => "kmac256");
         pragma Unreferenced (Enc);
      begin
         raise Program_Error with "Mixed width must raise";
      end;
   exception
      when Itb.Errors.Itb_Error =>
         null;
   end;

   ------------------------------------------------------------------
   --  reject_unknown_primitive
   ------------------------------------------------------------------
   begin
      declare
         Enc : Itb.Encryptor.Encryptor :=
           Itb.Encryptor.Mixed_Single
             (Prim_N   => "no-such-primitive",
              Prim_D   => "blake3",
              Prim_S   => "blake3",
              Prim_L   => "",
              Key_Bits => 1024,
              Mac_Name => "kmac256");
         pragma Unreferenced (Enc);
      begin
         raise Program_Error with "unknown primitive must raise";
      end;
   exception
      when Itb.Errors.Itb_Error =>
         null;
   end;

   ------------------------------------------------------------------
   --  default_constructor_is_not_mixed — Make-built encryptor reports
   --  Is_Mixed = False and every Primitive_At slot returns the same
   --  primitive name.
   ------------------------------------------------------------------
   declare
      Enc : constant Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
   begin
      if Itb.Encryptor.Is_Mixed (Enc) then
         raise Program_Error
           with "default constructor reports Is_Mixed = True";
      end if;
      for I in 0 .. 2 loop
         if Itb.Encryptor.Primitive_At (Enc, I) /= "blake3" then
            raise Program_Error
              with "primitive_at(" & Integer'Image (I) & "): '"
                   & Itb.Encryptor.Primitive_At (Enc, I) & "'";
         end if;
      end loop;
   end;

   Ada.Text_IO.Put_Line ("test_easy_mixed: PASS");
end Test_Easy_Mixed;
