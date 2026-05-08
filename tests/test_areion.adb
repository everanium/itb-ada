--  Areion-SoEM-focused Ada binding coverage.
--
--  Symmetric counterpart to test_blake2b.adb: the same coverage shape
--  (nonce-size sweep, single + triple roundtrip, single + triple
--  auth with tamper rejection, persistence sweep, plaintext-size
--  sweep) applied to areion256 / areion512.
--
--  Mirrors bindings/rust/tests/test_areion.rs one-to-one. Each Rust
--  #[test] fn becomes a single nested block in the main procedure;
--  the per-test serial_lock is unnecessary because each test_*.adb
--  main procedure compiles into its own executable and runs in its
--  own process with a fresh libitb global state. Set_Nonce_Bits is
--  saved at the procedure entry and restored on exit anyway, so an
--  exception mid-test still leaves the global at a valid value.

with Ada.Calendar;
with Ada.Streams;  use Ada.Streams;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO;

with Interfaces;   use Interfaces;

with Itb;          use Itb;
with Itb.Cipher;
with Itb.Errors;
with Itb.MAC;
with Itb.Seed;
with Itb.Status;

procedure Test_Areion is

   ------------------------------------------------------------------
   --  Per-primitive table — both Areion-SoEM widths. Width feeds
   --  into Seed.From_Components key validation in the persistence
   --  test below; Expected_Key_Len locks in the FFI-surfaced
   --  contract that Areion-SoEM-256 carries a 32-byte fixed key and
   --  Areion-SoEM-512 carries a 64-byte fixed key.
   ------------------------------------------------------------------

   type Hash_Spec is record
      Name             : Unbounded_String;
      Width            : Integer;
      Expected_Key_Len : Stream_Element_Offset;
   end record;

   type Hash_Spec_Array is array (Positive range <>) of Hash_Spec;

   Hashes : constant Hash_Spec_Array :=
     [(To_Unbounded_String ("areion256"), 256, 32),
      (To_Unbounded_String ("areion512"), 512, 64)];

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

   --  Round-trip 1: Single Encrypt / Decrypt across nonce sizes.
   declare
      Plaintext : constant Byte_Array := Token_Bytes (1024);
   begin
      for N of Nonce_Sizes loop
         for H of Hashes loop
            Itb.Set_Nonce_Bits (N);
            declare
               H_Name : constant String := To_String (H.Name);
               S0 : constant Itb.Seed.Seed := Itb.Seed.Make (H_Name, 1024);
               S1 : constant Itb.Seed.Seed := Itb.Seed.Make (H_Name, 1024);
               S2 : constant Itb.Seed.Seed := Itb.Seed.Make (H_Name, 1024);
               Ct : constant Byte_Array :=
                 Itb.Cipher.Encrypt (S0, S1, S2, Plaintext);
               Pt : constant Byte_Array :=
                 Itb.Cipher.Decrypt (S0, S1, S2, Ct);
               Hsz : constant Stream_Element_Offset :=
                 Stream_Element_Offset (Itb.Header_Size);
               Chunk_Len : constant Natural :=
                 Itb.Parse_Chunk_Len (Ct (Ct'First .. Ct'First + Hsz - 1));
            begin
               if Pt /= Plaintext then
                  raise Program_Error
                    with "Single mismatch at " & H_Name & N'Image;
               end if;
               if Stream_Element_Offset (Chunk_Len) /= Ct'Length then
                  raise Program_Error
                    with "Parse_Chunk_Len mismatch:" & Chunk_Len'Image;
               end if;
            end;
         end loop;
      end loop;
   end;

   --  Round-trip 2: Triple Encrypt / Decrypt across nonce sizes.
   declare
      Plaintext : constant Byte_Array := Token_Bytes (1024);
   begin
      for N of Nonce_Sizes loop
         for H of Hashes loop
            Itb.Set_Nonce_Bits (N);
            declare
               H_Name : constant String := To_String (H.Name);
               N_S : constant Itb.Seed.Seed := Itb.Seed.Make (H_Name, 1024);
               D1  : constant Itb.Seed.Seed := Itb.Seed.Make (H_Name, 1024);
               D2  : constant Itb.Seed.Seed := Itb.Seed.Make (H_Name, 1024);
               D3  : constant Itb.Seed.Seed := Itb.Seed.Make (H_Name, 1024);
               S1  : constant Itb.Seed.Seed := Itb.Seed.Make (H_Name, 1024);
               S2  : constant Itb.Seed.Seed := Itb.Seed.Make (H_Name, 1024);
               S3  : constant Itb.Seed.Seed := Itb.Seed.Make (H_Name, 1024);
               Ct  : constant Byte_Array :=
                 Itb.Cipher.Encrypt_Triple
                   (N_S, D1, D2, D3, S1, S2, S3, Plaintext);
               Pt  : constant Byte_Array :=
                 Itb.Cipher.Decrypt_Triple
                   (N_S, D1, D2, D3, S1, S2, S3, Ct);
            begin
               if Pt /= Plaintext then
                  raise Program_Error
                    with "Triple mismatch at " & H_Name & N'Image;
               end if;
            end;
         end loop;
      end loop;
   end;

   --  Round-trip 3: Auth Single + tamper-rejection.
   declare
      Plaintext : constant Byte_Array := Token_Bytes (1024);
   begin
      for N of Nonce_Sizes loop
         for M_Ptr of Mac_Names loop
            for H of Hashes loop
               Itb.Set_Nonce_Bits (N);
               declare
                  H_Name : constant String := To_String (H.Name);
                  Key : constant Byte_Array := Token_Bytes (32);
                  M   : constant Itb.MAC.MAC := Itb.MAC.Make (M_Ptr.all, Key);
                  S0  : constant Itb.Seed.Seed :=
                    Itb.Seed.Make (H_Name, 1024);
                  S1  : constant Itb.Seed.Seed :=
                    Itb.Seed.Make (H_Name, 1024);
                  S2  : constant Itb.Seed.Seed :=
                    Itb.Seed.Make (H_Name, 1024);
                  Ct  : constant Byte_Array :=
                    Itb.Cipher.Encrypt_Auth (S0, S1, S2, M, Plaintext);
                  Pt  : constant Byte_Array :=
                    Itb.Cipher.Decrypt_Auth (S0, S1, S2, M, Ct);
               begin
                  if Pt /= Plaintext then
                     raise Program_Error
                       with "Auth Single mismatch at " & H_Name
                            & " " & M_Ptr.all & N'Image;
                  end if;

                  declare
                     Tampered : Byte_Array := Ct;
                  begin
                     Tamper (Tampered);
                     declare
                        Pt2 : constant Byte_Array :=
                          Itb.Cipher.Decrypt_Auth
                            (S0, S1, S2, M, Tampered);
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
      end loop;
   end;

   --  Round-trip 4: Auth Triple + tamper-rejection.
   declare
      Plaintext : constant Byte_Array := Token_Bytes (1024);
   begin
      for N of Nonce_Sizes loop
         for M_Ptr of Mac_Names loop
            for H of Hashes loop
               Itb.Set_Nonce_Bits (N);
               declare
                  H_Name : constant String := To_String (H.Name);
                  Key : constant Byte_Array := Token_Bytes (32);
                  M   : constant Itb.MAC.MAC := Itb.MAC.Make (M_Ptr.all, Key);
                  N_S : constant Itb.Seed.Seed :=
                    Itb.Seed.Make (H_Name, 1024);
                  D1  : constant Itb.Seed.Seed :=
                    Itb.Seed.Make (H_Name, 1024);
                  D2  : constant Itb.Seed.Seed :=
                    Itb.Seed.Make (H_Name, 1024);
                  D3  : constant Itb.Seed.Seed :=
                    Itb.Seed.Make (H_Name, 1024);
                  S1  : constant Itb.Seed.Seed :=
                    Itb.Seed.Make (H_Name, 1024);
                  S2  : constant Itb.Seed.Seed :=
                    Itb.Seed.Make (H_Name, 1024);
                  S3  : constant Itb.Seed.Seed :=
                    Itb.Seed.Make (H_Name, 1024);
                  Ct  : constant Byte_Array :=
                    Itb.Cipher.Encrypt_Auth_Triple
                      (N_S, D1, D2, D3, S1, S2, S3, M, Plaintext);
                  Pt  : constant Byte_Array :=
                    Itb.Cipher.Decrypt_Auth_Triple
                      (N_S, D1, D2, D3, S1, S2, S3, M, Ct);
               begin
                  if Pt /= Plaintext then
                     raise Program_Error
                       with "Auth Triple mismatch at " & H_Name
                            & " " & M_Ptr.all & N'Image;
                  end if;

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
                          with "Decrypt_Auth_Triple on tampered ct"
                               & " should raise";
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
      end loop;
   end;

   --  Round-trip 5: Persistence sweep across (hash, key-bits, nonce).
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
         All_Bits  : constant array (Positive range <>) of Integer :=
           [512, 1024, 2048];
      begin
         for H of Hashes loop
            for KB of All_Bits loop
               if KB mod H.Width = 0 then
                  for N of Nonce_Sizes loop
                     Itb.Set_Nonce_Bits (N);
                     declare
                        H_Name : constant String := To_String (H.Name);
                        Ns : constant Itb.Seed.Seed :=
                          Itb.Seed.Make (H_Name, KB);
                        Ds : constant Itb.Seed.Seed :=
                          Itb.Seed.Make (H_Name, KB);
                        Ss : constant Itb.Seed.Seed :=
                          Itb.Seed.Make (H_Name, KB);
                        Ns_C : constant Component_Array :=
                          Itb.Seed.Get_Components (Ns);
                        Ns_K : constant Byte_Array :=
                          Itb.Seed.Get_Hash_Key (Ns);
                        Ds_C : constant Component_Array :=
                          Itb.Seed.Get_Components (Ds);
                        Ds_K : constant Byte_Array :=
                          Itb.Seed.Get_Hash_Key (Ds);
                        Ss_C : constant Component_Array :=
                          Itb.Seed.Get_Components (Ss);
                        Ss_K : constant Byte_Array :=
                          Itb.Seed.Get_Hash_Key (Ss);
                        Ct  : constant Byte_Array :=
                          Itb.Cipher.Encrypt (Ns, Ds, Ss, Plaintext);
                        Ns2 : constant Itb.Seed.Seed :=
                          Itb.Seed.From_Components (H_Name, Ns_C, Ns_K);
                        Ds2 : constant Itb.Seed.Seed :=
                          Itb.Seed.From_Components (H_Name, Ds_C, Ds_K);
                        Ss2 : constant Itb.Seed.Seed :=
                          Itb.Seed.From_Components (H_Name, Ss_C, Ss_K);
                        Pt  : constant Byte_Array :=
                          Itb.Cipher.Decrypt (Ns2, Ds2, Ss2, Ct);
                     begin
                        if Ns_K'Length /= H.Expected_Key_Len then
                           raise Program_Error
                             with "Hash_Key length mismatch on " & H_Name
                                  & ":" & Ns_K'Length'Image;
                        end if;
                        if Ns_C'Length * 64 /= KB then
                           raise Program_Error
                             with "Components length mismatch:"
                               & Ns_C'Length'Image;
                        end if;
                        if Pt /= Plaintext then
                           raise Program_Error
                             with "Persistence rebuild mismatch on "
                                  & H_Name;
                        end if;
                     end;
                  end loop;
               end if;
            end loop;
         end loop;
      end;
   end;

   --  Round-trip 6: Plaintext-size sweep.
   for H of Hashes loop
      for N of Nonce_Sizes loop
         for Sz of Plaintext_Sizes loop
            Itb.Set_Nonce_Bits (N);
            declare
               H_Name : constant String := To_String (H.Name);
               Plaintext : constant Byte_Array := Token_Bytes (Sz);
               Ns : constant Itb.Seed.Seed := Itb.Seed.Make (H_Name, 1024);
               Ds : constant Itb.Seed.Seed := Itb.Seed.Make (H_Name, 1024);
               Ss : constant Itb.Seed.Seed := Itb.Seed.Make (H_Name, 1024);
               Ct : constant Byte_Array :=
                 Itb.Cipher.Encrypt (Ns, Ds, Ss, Plaintext);
               Pt : constant Byte_Array :=
                 Itb.Cipher.Decrypt (Ns, Ds, Ss, Ct);
            begin
               if Pt /= Plaintext then
                  raise Program_Error
                    with "Size sweep mismatch on " & H_Name
                         & " size" & Sz'Image & " nonce" & N'Image;
               end if;
            end;
         end loop;
      end loop;
   end loop;

   Itb.Set_Nonce_Bits (Saved_Nonce_Bits);
   Ada.Text_IO.Put_Line ("test_areion: PASS");

exception
   when others =>
      begin
         Itb.Set_Nonce_Bits (Saved_Nonce_Bits);
      exception
         when others =>
            null;
      end;
      raise;
end Test_Areion;
