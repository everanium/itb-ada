--  Cross-process persistence round-trip tests for the high-level
--  Itb.Encryptor surface — Ada mirror of
--  bindings/rust/tests/test_easy_persistence.rs.
--
--  The Export_State / Import_State / Peek_Config triplet is the
--  persistence surface required for any deployment where encrypt and
--  decrypt run in different processes. Without the JSON-encoded blob
--  captured at encrypt-side and re-supplied at decrypt-side, the
--  encryptor state cannot be reconstructed and the ciphertext is
--  unreadable.

with Ada.Streams;             use Ada.Streams;
with Ada.Strings.Unbounded;
with Ada.Text_IO;

with Itb;          use Itb;
with Itb.Encryptor;
with Itb.Errors;
with Itb.Status;

procedure Test_Easy_Persistence is

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

   --  Returns the expected fixed-PRF key length for a primitive.
   function Expected_PRF_Key_Len (Name : String) return Integer is
   begin
      if    Name = "areion256"  then return 32;
      elsif Name = "areion512"  then return 64;
      elsif Name = "siphash24"  then return 0;
      elsif Name = "aescmac"    then return 16;
      elsif Name = "blake2b256" then return 32;
      elsif Name = "blake2b512" then return 64;
      elsif Name = "blake2s"    then return 32;
      elsif Name = "blake3"     then return 32;
      elsif Name = "chacha20"   then return 32;
      else
         raise Program_Error with "unknown hash " & Name;
      end if;
   end Expected_PRF_Key_Len;

   --  Plaintext used for the Single-mode persistence sweep — mirrors
   --  the Rust canonical_plaintext_single helper.
   function Canonical_Plaintext_Single return Byte_Array is
      Prefix : constant String :=
        "any binary data, including 0x00 bytes -- ";
      Total  : constant Stream_Element_Offset :=
        Stream_Element_Offset (Prefix'Length) + 256;
      Result : Byte_Array (1 .. Total);
   begin
      for I in Prefix'Range loop
         Result (Stream_Element_Offset (I - Prefix'First + 1)) :=
           Stream_Element (Character'Pos (Prefix (I)));
      end loop;
      for I in 0 .. 255 loop
         Result (Stream_Element_Offset (Prefix'Length + I + 1)) :=
           Stream_Element (I);
      end loop;
      return Result;
   end Canonical_Plaintext_Single;

   function Canonical_Plaintext_Triple return Byte_Array is
      Prefix : constant String := "triple-mode persistence payload ";
      Total  : constant Stream_Element_Offset :=
        Stream_Element_Offset (Prefix'Length) + 64;
      Result : Byte_Array (1 .. Total);
   begin
      for I in Prefix'Range loop
         Result (Stream_Element_Offset (I - Prefix'First + 1)) :=
           Stream_Element (Character'Pos (Prefix (I)));
      end loop;
      for I in 0 .. 63 loop
         Result (Stream_Element_Offset (Prefix'Length + I + 1)) :=
           Stream_Element (I);
      end loop;
      return Result;
   end Canonical_Plaintext_Triple;

   --  Builds a stable baseline blob for the import-mismatch tests.
   function Make_Baseline_Blob return Byte_Array is
      Src : constant Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
   begin
      return Itb.Encryptor.Export_State (Src);
   end Make_Baseline_Blob;

begin

   ------------------------------------------------------------------
   --  roundtrip_all_hashes_single — every (primitive, key_bits)
   --  combination round-trips through Export_State / Import_State.
   ------------------------------------------------------------------
   declare
      Plaintext : constant Byte_Array := Canonical_Plaintext_Single;
   begin
      for WP of Canonical_Hashes loop
         for KB of All_Key_Bits loop
            if KB mod WP.Width = 0 then
               declare
                  Src : Itb.Encryptor.Encryptor :=
                    Itb.Encryptor.Make
                      (WP.Name.all, KB, "kmac256", 1);
                  Blob : constant Byte_Array :=
                    Itb.Encryptor.Export_State (Src);
                  Ct : constant Byte_Array :=
                    Itb.Encryptor.Encrypt_Auth (Src, Plaintext);
               begin
                  Itb.Encryptor.Close (Src);
                  declare
                     Dst : Itb.Encryptor.Encryptor :=
                       Itb.Encryptor.Make
                         (WP.Name.all, KB, "kmac256", 1);
                  begin
                     Itb.Encryptor.Import_State (Dst, Blob);
                     declare
                        Pt : constant Byte_Array :=
                          Itb.Encryptor.Decrypt_Auth (Dst, Ct);
                     begin
                        if Pt /= Plaintext then
                           raise Program_Error
                             with "Single roundtrip mismatch "
                                  & WP.Name.all & "/" & KB'Image;
                        end if;
                     end;
                     Itb.Encryptor.Close (Dst);
                  end;
               end;
            end if;
         end loop;
      end loop;
   end;

   ------------------------------------------------------------------
   --  roundtrip_all_hashes_triple
   ------------------------------------------------------------------
   declare
      Plaintext : constant Byte_Array := Canonical_Plaintext_Triple;
   begin
      for WP of Canonical_Hashes loop
         for KB of All_Key_Bits loop
            if KB mod WP.Width = 0 then
               declare
                  Src : Itb.Encryptor.Encryptor :=
                    Itb.Encryptor.Make
                      (WP.Name.all, KB, "kmac256", 3);
                  Blob : constant Byte_Array :=
                    Itb.Encryptor.Export_State (Src);
                  Ct : constant Byte_Array :=
                    Itb.Encryptor.Encrypt_Auth (Src, Plaintext);
               begin
                  Itb.Encryptor.Close (Src);
                  declare
                     Dst : Itb.Encryptor.Encryptor :=
                       Itb.Encryptor.Make
                         (WP.Name.all, KB, "kmac256", 3);
                  begin
                     Itb.Encryptor.Import_State (Dst, Blob);
                     declare
                        Pt : constant Byte_Array :=
                          Itb.Encryptor.Decrypt_Auth (Dst, Ct);
                     begin
                        if Pt /= Plaintext then
                           raise Program_Error
                             with "Triple roundtrip mismatch "
                                  & WP.Name.all & "/" & KB'Image;
                        end if;
                     end;
                     Itb.Encryptor.Close (Dst);
                  end;
               end;
            end if;
         end loop;
      end loop;
   end;

   ------------------------------------------------------------------
   --  roundtrip_with_lock_seed — Set_Lock_Seed grows the encryptor
   --  to 4 (Single) or 8 (Triple) seed slots; the exported blob
   --  carries the dedicated lockSeed material via the lock_seed:true
   --  field, and Import_State on a fresh encryptor restores the seed
   --  slot AND auto-couples Lock_Soup + Bit_Soup overlays.
   ------------------------------------------------------------------
   declare
      Prefix : constant String := "lockseed payload ";
      Total  : constant Stream_Element_Offset :=
        Stream_Element_Offset (Prefix'Length) + 32;
      Plaintext : Byte_Array (1 .. Total);
      type Mode_Pair is record
         Mode  : Integer;
         Count : Integer;
      end record;
      type Mode_Pair_Array is array (Positive range <>) of Mode_Pair;
      Cases : constant Mode_Pair_Array := [(1, 4), (3, 8)];
   begin
      for I in Prefix'Range loop
         Plaintext (Stream_Element_Offset (I - Prefix'First + 1)) :=
           Stream_Element (Character'Pos (Prefix (I)));
      end loop;
      for I in 0 .. 31 loop
         Plaintext
           (Stream_Element_Offset (Prefix'Length + I + 1)) :=
           Stream_Element (I);
      end loop;
      for MP of Cases loop
         declare
            Src : Itb.Encryptor.Encryptor :=
              Itb.Encryptor.Make ("blake3", 1024, "kmac256", MP.Mode);
         begin
            Itb.Encryptor.Set_Lock_Seed (Src, 1);
            if Itb.Encryptor.Seed_Count (Src) /= MP.Count then
               raise Program_Error
                 with "lockseed Source seed_count:"
                      & Itb.Encryptor.Seed_Count (Src)'Image
                      & " expected" & MP.Count'Image;
            end if;
            declare
               Blob : constant Byte_Array :=
                 Itb.Encryptor.Export_State (Src);
               Ct : constant Byte_Array :=
                 Itb.Encryptor.Encrypt_Auth (Src, Plaintext);
            begin
               Itb.Encryptor.Close (Src);
               declare
                  Dst : Itb.Encryptor.Encryptor :=
                    Itb.Encryptor.Make
                      ("blake3", 1024, "kmac256", MP.Mode);
               begin
                  if Itb.Encryptor.Seed_Count (Dst) /= MP.Count - 1
                  then
                     raise Program_Error
                       with "Dst pre-import seed_count:"
                            & Itb.Encryptor.Seed_Count (Dst)'Image;
                  end if;
                  Itb.Encryptor.Import_State (Dst, Blob);
                  if Itb.Encryptor.Seed_Count (Dst) /= MP.Count then
                     raise Program_Error
                       with "Dst post-import seed_count:"
                            & Itb.Encryptor.Seed_Count (Dst)'Image;
                  end if;
                  declare
                     Pt : constant Byte_Array :=
                       Itb.Encryptor.Decrypt_Auth (Dst, Ct);
                  begin
                     if Pt /= Plaintext then
                        raise Program_Error
                          with "lockseed roundtrip mismatch mode"
                               & MP.Mode'Image;
                     end if;
                  end;
                  Itb.Encryptor.Close (Dst);
               end;
            end;
         end;
      end loop;
   end;

   ------------------------------------------------------------------
   --  roundtrip_with_full_config — per-instance configuration knobs
   --  (Nonce_Bits, Barrier_Fill, Bit_Soup, Lock_Soup) round-trip
   --  through the state blob along with the seed material — no
   --  manual mirror Set_*() calls required on the receiver.
   ------------------------------------------------------------------
   declare
      Prefix : constant String := "full-config persistence ";
      Total  : constant Stream_Element_Offset :=
        Stream_Element_Offset (Prefix'Length) + 64;
      Plaintext : Byte_Array (1 .. Total);
      Src : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
   begin
      for I in Prefix'Range loop
         Plaintext (Stream_Element_Offset (I - Prefix'First + 1)) :=
           Stream_Element (Character'Pos (Prefix (I)));
      end loop;
      for I in 0 .. 63 loop
         Plaintext
           (Stream_Element_Offset (Prefix'Length + I + 1)) :=
           Stream_Element (I);
      end loop;

      Itb.Encryptor.Set_Nonce_Bits   (Src, 512);
      Itb.Encryptor.Set_Barrier_Fill (Src, 4);
      Itb.Encryptor.Set_Bit_Soup     (Src, 1);
      Itb.Encryptor.Set_Lock_Soup    (Src, 1);
      declare
         Blob : constant Byte_Array :=
           Itb.Encryptor.Export_State (Src);
         Ct : constant Byte_Array :=
           Itb.Encryptor.Encrypt_Auth (Src, Plaintext);
      begin
         Itb.Encryptor.Close (Src);
         declare
            Dst : Itb.Encryptor.Encryptor :=
              Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
         begin
            if Itb.Encryptor.Nonce_Bits (Dst) /= 128 then
               raise Program_Error
                 with "Dst pre-import nonce_bits:"
                      & Itb.Encryptor.Nonce_Bits (Dst)'Image;
            end if;
            Itb.Encryptor.Import_State (Dst, Blob);
            if Itb.Encryptor.Nonce_Bits (Dst) /= 512 then
               raise Program_Error
                 with "Dst post-import nonce_bits:"
                      & Itb.Encryptor.Nonce_Bits (Dst)'Image;
            end if;
            if Itb.Encryptor.Header_Size (Dst) /= 68 then
               raise Program_Error
                 with "Dst post-import header_size:"
                      & Itb.Encryptor.Header_Size (Dst)'Image;
            end if;
            declare
               Pt : constant Byte_Array :=
                 Itb.Encryptor.Decrypt_Auth (Dst, Ct);
            begin
               if Pt /= Plaintext then
                  raise Program_Error
                    with "full-config roundtrip mismatch";
               end if;
            end;
            Itb.Encryptor.Close (Dst);
         end;
      end;
   end;

   ------------------------------------------------------------------
   --  roundtrip_barrier_fill_receiver_priority — Barrier_Fill is
   --  asymmetric. When the receiver explicitly installs a non-default
   --  Barrier_Fill before Import_State, that choice takes priority
   --  over the blob's barrier_fill.
   ------------------------------------------------------------------
   declare
      Plaintext : constant String := "barrier-fill priority";
      Plain_Bytes : Byte_Array (1 .. Stream_Element_Offset (Plaintext'Length));
      Src : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
   begin
      for I in Plaintext'Range loop
         Plain_Bytes (Stream_Element_Offset (I - Plaintext'First + 1)) :=
           Stream_Element (Character'Pos (Plaintext (I)));
      end loop;
      Itb.Encryptor.Set_Barrier_Fill (Src, 4);
      declare
         Blob : constant Byte_Array :=
           Itb.Encryptor.Export_State (Src);
         Ct : constant Byte_Array :=
           Itb.Encryptor.Encrypt_Auth (Src, Plain_Bytes);
      begin
         Itb.Encryptor.Close (Src);
         declare
            Dst : Itb.Encryptor.Encryptor :=
              Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
         begin
            Itb.Encryptor.Set_Barrier_Fill (Dst, 8);
            Itb.Encryptor.Import_State (Dst, Blob);
            declare
               Pt : constant Byte_Array :=
                 Itb.Encryptor.Decrypt_Auth (Dst, Ct);
            begin
               if Pt /= Plain_Bytes then
                  raise Program_Error
                    with "barrier-fill priority mismatch";
               end if;
            end;
            Itb.Encryptor.Close (Dst);
         end;
         declare
            Dst2 : Itb.Encryptor.Encryptor :=
              Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
         begin
            Itb.Encryptor.Import_State (Dst2, Blob);
            declare
               Pt2 : constant Byte_Array :=
                 Itb.Encryptor.Decrypt_Auth (Dst2, Ct);
            begin
               if Pt2 /= Plain_Bytes then
                  raise Program_Error
                    with "barrier-fill (no override) mismatch";
               end if;
            end;
            Itb.Encryptor.Close (Dst2);
         end;
      end;
   end;

   ------------------------------------------------------------------
   --  peek_recovers_metadata — Peek_Config returns the four-tuple
   --  (primitive, key_bits, mode, mac) for every (primitive,
   --  key_bits, mode, mac) combination.
   ------------------------------------------------------------------
   declare
      type Mac_Array is
        array (Positive range <>) of access constant String;
      Mac_Kmac256     : aliased constant String := "kmac256";
      Mac_Hmac_Sha256 : aliased constant String := "hmac-sha256";
      Mac_Hmac_Blake3 : aliased constant String := "hmac-blake3";
      Macs : constant Mac_Array :=
        [Mac_Kmac256'Access,
         Mac_Hmac_Sha256'Access,
         Mac_Hmac_Blake3'Access];
      Modes : constant array (Positive range <>) of Integer := [1, 3];
   begin
      for WP of Canonical_Hashes loop
         for KB of All_Key_Bits loop
            if KB mod WP.Width = 0 then
               for M of Modes loop
                  for Mac_Ptr of Macs loop
                     declare
                        Enc : constant Itb.Encryptor.Encryptor :=
                          Itb.Encryptor.Make
                            (WP.Name.all, KB, Mac_Ptr.all, M);
                        Blob : constant Byte_Array :=
                          Itb.Encryptor.Export_State (Enc);
                        PC : constant Itb.Encryptor.Peeked_Config :=
                          Itb.Encryptor.Peek_Config (Blob);
                     begin
                        if Ada.Strings.Unbounded.To_String
                             (PC.Primitive) /= WP.Name.all
                        then
                           raise Program_Error
                             with "peek primitive mismatch: '"
                                  & Ada.Strings.Unbounded.To_String
                                      (PC.Primitive)
                                  & "', expected '" & WP.Name.all & "'";
                        end if;
                        if PC.Key_Bits /= KB then
                           raise Program_Error
                             with "peek key_bits:" & PC.Key_Bits'Image;
                        end if;
                        if PC.Mode /= M then
                           raise Program_Error
                             with "peek mode:" & PC.Mode'Image;
                        end if;
                        if Ada.Strings.Unbounded.To_String
                             (PC.MAC_Name) /= Mac_Ptr.all
                        then
                           raise Program_Error
                             with "peek mac mismatch: '"
                                  & Ada.Strings.Unbounded.To_String
                                      (PC.MAC_Name) & "'";
                        end if;
                     end;
                  end loop;
               end loop;
            end if;
         end loop;
      end loop;
   end;

   ------------------------------------------------------------------
   --  peek_malformed_blob — every malformed input must raise.
   ------------------------------------------------------------------
   declare
      type Bytes_Access is access constant Byte_Array;
      B0 : aliased constant Byte_Array :=
        [Stream_Element (Character'Pos ('n')),
         Stream_Element (Character'Pos ('o')),
         Stream_Element (Character'Pos ('t')),
         Stream_Element (Character'Pos (' ')),
         Stream_Element (Character'Pos ('j')),
         Stream_Element (Character'Pos ('s')),
         Stream_Element (Character'Pos ('o')),
         Stream_Element (Character'Pos ('n'))];
      B1 : aliased constant Byte_Array := [1 .. 0 => 0];
      B2 : aliased constant Byte_Array :=
        [Stream_Element (Character'Pos ('{')),
         Stream_Element (Character'Pos ('}'))];
      B3_S : constant String := "{""v"":1}";
      B3 : Byte_Array (1 .. Stream_Element_Offset (B3_S'Length));
      Cases : constant array (Positive range <>) of Bytes_Access :=
        [B0'Access, B1'Access, B2'Access, B3'Unrestricted_Access];
   begin
      for I in B3_S'Range loop
         B3 (Stream_Element_Offset (I - B3_S'First + 1)) :=
           Stream_Element (Character'Pos (B3_S (I)));
      end loop;
      for Blob_Ptr of Cases loop
         begin
            declare
               PC : constant Itb.Encryptor.Peeked_Config :=
                 Itb.Encryptor.Peek_Config (Blob_Ptr.all);
               pragma Unreferenced (PC);
            begin
               raise Program_Error
                 with "Peek_Config on malformed blob must raise";
            end;
         exception
            when E : Itb.Errors.Itb_Error =>
               if Itb.Errors.Status_Code (E) /=
                  Itb.Status.Easy_Malformed
               then
                  raise;
               end if;
         end;
      end loop;
   end;

   ------------------------------------------------------------------
   --  peek_too_new_version — peek conflates "too-new version" with
   --  "malformed shape" and surfaces both as Easy_Malformed; only
   --  the Import_State path differentiates them via
   --  Easy_Version_Too_New (covered below).
   ------------------------------------------------------------------
   declare
      Doc : constant String := "{""v"":99,""kind"":""itb-easy""}";
      Blob : Byte_Array (1 .. Stream_Element_Offset (Doc'Length));
   begin
      for I in Doc'Range loop
         Blob (Stream_Element_Offset (I - Doc'First + 1)) :=
           Stream_Element (Character'Pos (Doc (I)));
      end loop;
      begin
         declare
            PC : constant Itb.Encryptor.Peeked_Config :=
              Itb.Encryptor.Peek_Config (Blob);
            pragma Unreferenced (PC);
         begin
            raise Program_Error
              with "v=99 Peek_Config must raise";
         end;
      exception
         when E : Itb.Errors.Itb_Error =>
            if Itb.Errors.Status_Code (E) /= Itb.Status.Easy_Malformed
            then
               raise;
            end if;
      end;
   end;

   ------------------------------------------------------------------
   --  import_mismatch_primitive
   ------------------------------------------------------------------
   declare
      Blob : constant Byte_Array := Make_Baseline_Blob;
      Dst : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake2s", 1024, "kmac256", 1);
   begin
      Itb.Encryptor.Import_State (Dst, Blob);
      raise Program_Error
        with "primitive mismatch must raise Itb_Easy_Mismatch_Error";
   exception
      when E : Itb.Errors.Itb_Easy_Mismatch_Error =>
         if Itb.Errors.Field (E) /= "primitive" then
            raise Program_Error
              with "expected Field=primitive, got '"
                   & Itb.Errors.Field (E) & "'";
         end if;
   end;

   ------------------------------------------------------------------
   --  import_mismatch_key_bits
   ------------------------------------------------------------------
   declare
      Blob : constant Byte_Array := Make_Baseline_Blob;
      Dst : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 2048, "kmac256", 1);
   begin
      Itb.Encryptor.Import_State (Dst, Blob);
      raise Program_Error
        with "key_bits mismatch must raise Itb_Easy_Mismatch_Error";
   exception
      when E : Itb.Errors.Itb_Easy_Mismatch_Error =>
         if Itb.Errors.Field (E) /= "key_bits" then
            raise Program_Error
              with "expected Field=key_bits, got '"
                   & Itb.Errors.Field (E) & "'";
         end if;
   end;

   ------------------------------------------------------------------
   --  import_mismatch_mode
   ------------------------------------------------------------------
   declare
      Blob : constant Byte_Array := Make_Baseline_Blob;
      Dst : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 3);
   begin
      Itb.Encryptor.Import_State (Dst, Blob);
      raise Program_Error
        with "mode mismatch must raise Itb_Easy_Mismatch_Error";
   exception
      when E : Itb.Errors.Itb_Easy_Mismatch_Error =>
         if Itb.Errors.Field (E) /= "mode" then
            raise Program_Error
              with "expected Field=mode, got '"
                   & Itb.Errors.Field (E) & "'";
         end if;
   end;

   ------------------------------------------------------------------
   --  import_mismatch_mac
   ------------------------------------------------------------------
   declare
      Blob : constant Byte_Array := Make_Baseline_Blob;
      Dst : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "hmac-sha256", 1);
   begin
      Itb.Encryptor.Import_State (Dst, Blob);
      raise Program_Error
        with "mac mismatch must raise Itb_Easy_Mismatch_Error";
   exception
      when E : Itb.Errors.Itb_Easy_Mismatch_Error =>
         if Itb.Errors.Field (E) /= "mac" then
            raise Program_Error
              with "expected Field=mac, got '"
                   & Itb.Errors.Field (E) & "'";
         end if;
   end;

   ------------------------------------------------------------------
   --  import_malformed_json
   ------------------------------------------------------------------
   declare
      Doc : constant String := "this is not json";
      Blob : Byte_Array (1 .. Stream_Element_Offset (Doc'Length));
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
   begin
      for I in Doc'Range loop
         Blob (Stream_Element_Offset (I - Doc'First + 1)) :=
           Stream_Element (Character'Pos (Doc (I)));
      end loop;
      Itb.Encryptor.Import_State (Enc, Blob);
      raise Program_Error with "malformed Import must raise";
   exception
      when E : Itb.Errors.Itb_Error =>
         if Itb.Errors.Status_Code (E) /= Itb.Status.Easy_Malformed
         then
            raise;
         end if;
   end;

   ------------------------------------------------------------------
   --  import_too_new_version — Import_State differentiates via the
   --  dedicated Easy_Version_Too_New status code.
   ------------------------------------------------------------------
   declare
      Doc : constant String := "{""v"":99,""kind"":""itb-easy""}";
      Blob : Byte_Array (1 .. Stream_Element_Offset (Doc'Length));
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
   begin
      for I in Doc'Range loop
         Blob (Stream_Element_Offset (I - Doc'First + 1)) :=
           Stream_Element (Character'Pos (Doc (I)));
      end loop;
      Itb.Encryptor.Import_State (Enc, Blob);
      raise Program_Error with "v=99 Import must raise";
   exception
      when E : Itb.Errors.Itb_Error =>
         if Itb.Errors.Status_Code (E) /=
            Itb.Status.Easy_Version_Too_New
         then
            raise;
         end if;
   end;

   ------------------------------------------------------------------
   --  import_wrong_kind
   ------------------------------------------------------------------
   declare
      Doc : constant String :=
        "{""v"":1,""kind"":""not-itb-easy""}";
      Blob : Byte_Array (1 .. Stream_Element_Offset (Doc'Length));
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
   begin
      for I in Doc'Range loop
         Blob (Stream_Element_Offset (I - Doc'First + 1)) :=
           Stream_Element (Character'Pos (Doc (I)));
      end loop;
      Itb.Encryptor.Import_State (Enc, Blob);
      raise Program_Error with "wrong-kind Import must raise";
   exception
      when E : Itb.Errors.Itb_Error =>
         if Itb.Errors.Status_Code (E) /= Itb.Status.Easy_Malformed
         then
            raise;
         end if;
   end;

   ------------------------------------------------------------------
   --  prf_key_lengths_per_primitive — siphash24 has no fixed PRF
   --  keys (Has_PRF_Keys = False, Get_PRF_Key raises). All other
   --  primitives report Has_PRF_Keys = True with the documented
   --  per-primitive key length.
   ------------------------------------------------------------------
   for WP of Canonical_Hashes loop
      for KB of All_Key_Bits loop
         if KB mod WP.Width = 0 then
            declare
               Enc : constant Itb.Encryptor.Encryptor :=
                 Itb.Encryptor.Make
                   (WP.Name.all, KB, "kmac256", 1);
               Want_Len : constant Integer :=
                 Expected_PRF_Key_Len (WP.Name.all);
            begin
               if WP.Name.all = "siphash24" then
                  if Itb.Encryptor.Has_PRF_Keys (Enc) then
                     raise Program_Error
                       with "siphash24 should report Has_PRF_Keys=False";
                  end if;
                  begin
                     declare
                        K : constant Byte_Array :=
                          Itb.Encryptor.Get_PRF_Key (Enc, 0);
                        pragma Unreferenced (K);
                     begin
                        raise Program_Error
                          with "siphash24 Get_PRF_Key(0) must raise";
                     end;
                  exception
                     when Itb.Errors.Itb_Error =>
                        null;
                  end;
               else
                  if not Itb.Encryptor.Has_PRF_Keys (Enc) then
                     raise Program_Error
                       with WP.Name.all & " Has_PRF_Keys = False";
                  end if;
                  declare
                     Count : constant Integer :=
                       Itb.Encryptor.Seed_Count (Enc);
                  begin
                     for Slot in 0 .. Count - 1 loop
                        declare
                           Key : constant Byte_Array :=
                             Itb.Encryptor.Get_PRF_Key (Enc, Slot);
                        begin
                           if Key'Length /=
                              Stream_Element_Offset (Want_Len)
                           then
                              raise Program_Error
                                with "PRF key length mismatch "
                                     & WP.Name.all & " slot"
                                     & Slot'Image & ":"
                                     & Key'Length'Image;
                           end if;
                        end;
                     end loop;
                  end;
               end if;
            end;
         end if;
      end loop;
   end loop;

   ------------------------------------------------------------------
   --  seed_components_lengths_per_key_bits — every slot's component
   --  array satisfies len * 64 == key_bits.
   ------------------------------------------------------------------
   for WP of Canonical_Hashes loop
      for KB of All_Key_Bits loop
         if KB mod WP.Width = 0 then
            declare
               Enc : constant Itb.Encryptor.Encryptor :=
                 Itb.Encryptor.Make
                   (WP.Name.all, KB, "kmac256", 1);
               Count : constant Integer :=
                 Itb.Encryptor.Seed_Count (Enc);
            begin
               for Slot in 0 .. Count - 1 loop
                  declare
                     Comps : constant Component_Array :=
                       Itb.Encryptor.Get_Seed_Components (Enc, Slot);
                  begin
                     if Integer (Comps'Length) * 64 /= KB then
                        raise Program_Error
                          with "components length mismatch "
                               & WP.Name.all & " slot" & Slot'Image
                               & ":" & Comps'Length'Image;
                     end if;
                  end;
               end loop;
            end;
         end if;
      end loop;
   end loop;

   ------------------------------------------------------------------
   --  mac_key_present — every Make-built encryptor exposes a
   --  non-empty MAC fixed key.
   ------------------------------------------------------------------
   declare
      type Mac_Array is
        array (Positive range <>) of access constant String;
      Mac_Kmac256     : aliased constant String := "kmac256";
      Mac_Hmac_Sha256 : aliased constant String := "hmac-sha256";
      Mac_Hmac_Blake3 : aliased constant String := "hmac-blake3";
      Macs : constant Mac_Array :=
        [Mac_Kmac256'Access,
         Mac_Hmac_Sha256'Access,
         Mac_Hmac_Blake3'Access];
   begin
      for Mac_Ptr of Macs loop
         declare
            Enc : constant Itb.Encryptor.Encryptor :=
              Itb.Encryptor.Make
                ("blake3", 1024, Mac_Ptr.all, 1);
            K : constant Byte_Array := Itb.Encryptor.Get_MAC_Key (Enc);
         begin
            if K'Length = 0 then
               raise Program_Error
                 with "MAC key empty for " & Mac_Ptr.all;
            end if;
         end;
      end loop;
   end;

   ------------------------------------------------------------------
   --  seed_components_out_of_range
   ------------------------------------------------------------------
   declare
      Enc : constant Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
   begin
      if Itb.Encryptor.Seed_Count (Enc) /= 3 then
         raise Program_Error
           with "Seed_Count default:"
                & Itb.Encryptor.Seed_Count (Enc)'Image;
      end if;
      begin
         declare
            C : constant Component_Array :=
              Itb.Encryptor.Get_Seed_Components (Enc, 3);
            pragma Unreferenced (C);
         begin
            raise Program_Error
              with "slot=3 must raise";
         end;
      exception
         when E : Itb.Errors.Itb_Error =>
            if Itb.Errors.Status_Code (E) /= Itb.Status.Bad_Input then
               raise;
            end if;
      end;
      begin
         declare
            C : constant Component_Array :=
              Itb.Encryptor.Get_Seed_Components (Enc, -1);
            pragma Unreferenced (C);
         begin
            raise Program_Error
              with "slot=-1 must raise";
         end;
      exception
         when E : Itb.Errors.Itb_Error =>
            if Itb.Errors.Status_Code (E) /= Itb.Status.Bad_Input then
               raise;
            end if;
      end;
   end;

   Ada.Text_IO.Put_Line ("test_easy_persistence: PASS");
end Test_Easy_Persistence;
