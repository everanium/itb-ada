--  AES-CMAC-focused Ada binding coverage.
--
--  W128 counterpart to test_chacha20.adb / test_blake3.adb: the same
--  coverage shape (nonce-size sweep, single and triple roundtrip,
--  single and triple auth with tamper rejection, persistence sweep,
--  plaintext-size sweep) applied to aescmac. AES-CMAC ships at a
--  single width (128 — the AES block size) so this file iterates the
--  single primitive across the same axes test_chacha20.adb covers.
--
--  Mirrors bindings/rust/tests/test_aescmac.rs one-to-one. Each Rust
--  #[test] fn becomes a single nested block in the main procedure;
--  the per-test serial_lock is unnecessary because each test_*.adb
--  main procedure compiles into its own executable and runs in its
--  own process with a fresh libitb global state. Set_Nonce_Bits is
--  saved at the procedure entry and restored on exit anyway, so an
--  exception mid-test still leaves the global at a valid value.

with Ada.Calendar;
with Ada.Streams;  use Ada.Streams;
with Ada.Text_IO;

with Interfaces;   use Interfaces;

with Itb;          use Itb;
with Itb.Cipher;
with Itb.Errors;
with Itb.MAC;
with Itb.Seed;
with Itb.Status;

procedure Test_Aescmac is

   ------------------------------------------------------------------
   --  Per-primitive constants (mirror of AESCMAC_HASHES /
   --  expected_key_len / NONCE_SIZES / MAC_NAMES in the Rust test).
   ------------------------------------------------------------------

   --  AES-CMAC ships only at -128 (the AES block size). Width feeds
   --  into key-bits validation in the persistence test below.
   Hash_Name : constant String := "aescmac";
   Width     : constant Integer := 128;

   --  Hash-key length (bytes) — locks in the FFI-surfaced contract
   --  that AES-CMAC carries a 16-byte AES-128 key.
   Expected_Key_Len : constant Stream_Element_Offset := 16;

   type Nonce_Sizes_Array is array (Positive range <>) of Integer;
   Nonce_Sizes : constant Nonce_Sizes_Array := [128, 256, 512];

   type Mac_Names_Array is
     array (Positive range <>) of access constant String;
   Mac_Kmac256     : aliased constant String := "kmac256";
   Mac_Hmac_Sha256 : aliased constant String := "hmac-sha256";
   Mac_Hmac_Blake3 : aliased constant String := "hmac-blake3";
   Mac_Names       : constant Mac_Names_Array :=
     [Mac_Kmac256'Access, Mac_Hmac_Sha256'Access, Mac_Hmac_Blake3'Access];

   type Size_Array is
     array (Positive range <>) of Stream_Element_Offset;
   Plaintext_Sizes : constant Size_Array :=
     [1, 17, 4096, 65536, 1024 * 1024];

   ------------------------------------------------------------------
   --  Pseudo-random byte buffer (deterministic LCG seeded from the
   --  wall clock). A non-CSPRNG generator is acceptable for this test
   --  fixture because ITB encryption itself is keyed by libitb's
   --  internal CSPRNG via Itb.Seed.Make; the test plaintext / MAC key
   --  only need to be non-trivial, not unpredictable.
   ------------------------------------------------------------------

   State : Unsigned_64 :=
     Unsigned_64 (Ada.Calendar.Seconds (Ada.Calendar.Clock) * 1.0E6)
     xor 16#DEADBEEF_CAFEBABE#;

   function Token_Bytes (N : Stream_Element_Offset) return Byte_Array is
      Out_Buf : Byte_Array (1 .. N);
   begin
      for I in Out_Buf'Range loop
         State := State * 6364136223846793005 + 1442695040888963407;
         Out_Buf (I) := Stream_Element (Shift_Right (State, 33) and 16#FF#);
      end loop;
      return Out_Buf;
   end Token_Bytes;

   ------------------------------------------------------------------
   --  Tamper helper — flips bit 0 of every byte in
   --  ct (Header_Size .. min (Header_Size + 256, ct'Last)),
   --  mirroring the Rust per-test tamper loop.
   ------------------------------------------------------------------

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

   ------------------------------------------------------------------
   --  Saved global state — restored on procedure exit (or on
   --  exception via the outer handler).
   ------------------------------------------------------------------

   Saved_Nonce_Bits : constant Integer := Itb.Get_Nonce_Bits;

begin

   ------------------------------------------------------------------
   --  Round-trip 1: Single Encrypt / Decrypt across nonce sizes.
   ------------------------------------------------------------------

   declare
      Plaintext : constant Byte_Array := Token_Bytes (1024);
   begin
      for N of Nonce_Sizes loop
         Itb.Set_Nonce_Bits (N);
         declare
            S0 : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
            S1 : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
            S2 : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
            Ct : constant Byte_Array :=
              Itb.Cipher.Encrypt (S0, S1, S2, Plaintext);
            Pt : constant Byte_Array :=
              Itb.Cipher.Decrypt (S0, S1, S2, Ct);
            H : constant Stream_Element_Offset :=
              Stream_Element_Offset (Itb.Header_Size);
            Chunk_Len : constant Natural :=
              Itb.Parse_Chunk_Len (Ct (Ct'First .. Ct'First + H - 1));
         begin
            if Pt /= Plaintext then
               raise Program_Error
                 with "Single Encrypt/Decrypt mismatch at nonce" & N'Image;
            end if;
            if Stream_Element_Offset (Chunk_Len) /= Ct'Length then
               raise Program_Error
                 with "Parse_Chunk_Len mismatch:" & Chunk_Len'Image;
            end if;
         end;
      end loop;
   end;

   ------------------------------------------------------------------
   --  Round-trip 2: Triple Encrypt / Decrypt across nonce sizes.
   ------------------------------------------------------------------

   declare
      Plaintext : constant Byte_Array := Token_Bytes (1024);
   begin
      for N of Nonce_Sizes loop
         Itb.Set_Nonce_Bits (N);
         declare
            N_S  : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
            D1   : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
            D2   : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
            D3   : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
            S1   : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
            S2   : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
            S3   : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
            Ct   : constant Byte_Array :=
              Itb.Cipher.Encrypt_Triple (N_S, D1, D2, D3, S1, S2, S3,
                                         Plaintext);
            Pt   : constant Byte_Array :=
              Itb.Cipher.Decrypt_Triple (N_S, D1, D2, D3, S1, S2, S3, Ct);
         begin
            if Pt /= Plaintext then
               raise Program_Error
                 with "Triple Encrypt/Decrypt mismatch at nonce" & N'Image;
            end if;
         end;
      end loop;
   end;

   ------------------------------------------------------------------
   --  Round-trip 3: Auth Single across nonce sizes / MACs, with
   --  tamper-rejection check.
   ------------------------------------------------------------------

   declare
      Plaintext : constant Byte_Array := Token_Bytes (1024);
   begin
      for N of Nonce_Sizes loop
         for M_Ptr of Mac_Names loop
            Itb.Set_Nonce_Bits (N);
            declare
               Key : constant Byte_Array := Token_Bytes (32);
               M   : constant Itb.MAC.MAC := Itb.MAC.Make (M_Ptr.all, Key);
               S0  : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
               S1  : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
               S2  : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
               Ct  : constant Byte_Array :=
                 Itb.Cipher.Encrypt_Auth (S0, S1, S2, M, Plaintext);
               Pt  : constant Byte_Array :=
                 Itb.Cipher.Decrypt_Auth (S0, S1, S2, M, Ct);
            begin
               if Pt /= Plaintext then
                  raise Program_Error
                    with "Auth Single mismatch at " & M_Ptr.all & N'Image;
               end if;

               --  Tamper-rejection.
               declare
                  Tampered : Byte_Array := Ct;
               begin
                  Tamper (Tampered);
                  declare
                     Pt2 : constant Byte_Array :=
                       Itb.Cipher.Decrypt_Auth (S0, S1, S2, M, Tampered);
                     pragma Unreferenced (Pt2);
                  begin
                     raise Program_Error
                       with "Decrypt_Auth on tampered ct should raise";
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
   --  Round-trip 4: Auth Triple across nonce sizes / MACs, with
   --  tamper-rejection check.
   ------------------------------------------------------------------

   declare
      Plaintext : constant Byte_Array := Token_Bytes (1024);
   begin
      for N of Nonce_Sizes loop
         for M_Ptr of Mac_Names loop
            Itb.Set_Nonce_Bits (N);
            declare
               Key : constant Byte_Array := Token_Bytes (32);
               M   : constant Itb.MAC.MAC := Itb.MAC.Make (M_Ptr.all, Key);
               N_S : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
               D1  : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
               D2  : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
               D3  : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
               S1  : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
               S2  : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
               S3  : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
               Ct  : constant Byte_Array :=
                 Itb.Cipher.Encrypt_Auth_Triple
                   (N_S, D1, D2, D3, S1, S2, S3, M, Plaintext);
               Pt  : constant Byte_Array :=
                 Itb.Cipher.Decrypt_Auth_Triple
                   (N_S, D1, D2, D3, S1, S2, S3, M, Ct);
            begin
               if Pt /= Plaintext then
                  raise Program_Error
                    with "Auth Triple mismatch at " & M_Ptr.all & N'Image;
               end if;

               --  Tamper-rejection.
               declare
                  Tampered : Byte_Array := Ct;
               begin
                  Tamper (Tampered);
                  declare
                     Pt2 : constant Byte_Array :=
                       Itb.Cipher.Decrypt_Auth_Triple
                         (N_S, D1, D2, D3, S1, S2, S3, M, Tampered);
                     pragma Unreferenced (Pt2);
                  begin
                     raise Program_Error
                       with "Decrypt_Auth_Triple on tampered ct should raise";
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
   --  Round-trip 5: Persistence — Get_Components / Get_Hash_Key →
   --  From_Components round-trip, decrypts ciphertext from the
   --  original seeds.
   ------------------------------------------------------------------

   declare
      Tag : constant String := "persistence payload ";
      Header     : Byte_Array (1 .. Stream_Element_Offset (Tag'Length));
      Body_Bytes : constant Byte_Array := Token_Bytes (1024);
   begin
      for I in Tag'Range loop
         Header (Stream_Element_Offset (I - Tag'First + 1)) :=
           Stream_Element (Character'Pos (Tag (I)));
      end loop;
      declare
         Plaintext : constant Byte_Array := Header & Body_Bytes;
         --  Valid key-widths whose bit-count is a multiple of the
         --  primitive's native digest width.
         All_Bits  : constant array (Positive range <>) of Integer :=
           [512, 1024, 2048];
      begin
         for KB of All_Bits loop
            if KB mod Width = 0 then
               for N of Nonce_Sizes loop
                  Itb.Set_Nonce_Bits (N);
                  declare
                     --  Day 1 — random seeds; capture every persistable
                     --  bit (components + fixed key) and the ciphertext.
                     Ns      : constant Itb.Seed.Seed :=
                       Itb.Seed.Make (Hash_Name, KB);
                     Ds      : constant Itb.Seed.Seed :=
                       Itb.Seed.Make (Hash_Name, KB);
                     Ss      : constant Itb.Seed.Seed :=
                       Itb.Seed.Make (Hash_Name, KB);
                     Ns_C    : constant Component_Array :=
                       Itb.Seed.Get_Components (Ns);
                     Ns_K    : constant Byte_Array :=
                       Itb.Seed.Get_Hash_Key (Ns);
                     Ds_C    : constant Component_Array :=
                       Itb.Seed.Get_Components (Ds);
                     Ds_K    : constant Byte_Array :=
                       Itb.Seed.Get_Hash_Key (Ds);
                     Ss_C    : constant Component_Array :=
                       Itb.Seed.Get_Components (Ss);
                     Ss_K    : constant Byte_Array :=
                       Itb.Seed.Get_Hash_Key (Ss);
                     Ct      : constant Byte_Array :=
                       Itb.Cipher.Encrypt (Ns, Ds, Ss, Plaintext);
                     --  Day 2 — restore from saved material. Each
                     --  rebuild is a fresh libitb seed handle with
                     --  matching components and key, equivalent to
                     --  the originals on the wire.
                     Ns2     : constant Itb.Seed.Seed :=
                       Itb.Seed.From_Components (Hash_Name, Ns_C, Ns_K);
                     Ds2     : constant Itb.Seed.Seed :=
                       Itb.Seed.From_Components (Hash_Name, Ds_C, Ds_K);
                     Ss2     : constant Itb.Seed.Seed :=
                       Itb.Seed.From_Components (Hash_Name, Ss_C, Ss_K);
                     Pt      : constant Byte_Array :=
                       Itb.Cipher.Decrypt (Ns2, Ds2, Ss2, Ct);
                  begin
                     if Ns_K'Length /= Expected_Key_Len then
                        raise Program_Error
                          with "Hash_Key length mismatch:"
                            & Ns_K'Length'Image;
                     end if;
                     if Ns_C'Length * 64 /= KB then
                        raise Program_Error
                          with "Components length mismatch:"
                            & Ns_C'Length'Image;
                     end if;
                     if Pt /= Plaintext then
                        raise Program_Error
                          with "Persistence rebuild mismatch";
                     end if;
                  end;
               end loop;
            end if;
         end loop;
      end;
   end;

   ------------------------------------------------------------------
   --  Round-trip 6: Plaintext-size sweep — 1, 17, 4096, 65536, 1 MiB.
   ------------------------------------------------------------------

   for N of Nonce_Sizes loop
      Itb.Set_Nonce_Bits (N);
      for Sz of Plaintext_Sizes loop
         declare
            Plaintext : constant Byte_Array := Token_Bytes (Sz);
            Ns : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
            Ds : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
            Ss : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
            Ct : constant Byte_Array :=
              Itb.Cipher.Encrypt (Ns, Ds, Ss, Plaintext);
            Pt : constant Byte_Array :=
              Itb.Cipher.Decrypt (Ns, Ds, Ss, Ct);
         begin
            if Pt /= Plaintext then
               raise Program_Error
                 with "Size sweep mismatch at" & Sz'Image
                      & " nonce" & N'Image;
            end if;
         end;
      end loop;
   end loop;

   --  Restore process-global before normal exit.
   Itb.Set_Nonce_Bits (Saved_Nonce_Bits);

   Ada.Text_IO.Put_Line ("test_aescmac: PASS");

exception
   when others =>
      --  Best-effort restore on the failure path.
      begin
         Itb.Set_Nonce_Bits (Saved_Nonce_Bits);
      exception
         when others =>
            null;
      end;
      raise;
end Test_Aescmac;
