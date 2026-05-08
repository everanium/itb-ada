--  BLAKE2s-focused Easy Mode (Itb.Encryptor) coverage.
--
--  Symmetric counterpart to bindings/rust/tests/test_easy_blake2s.rs
--  applied to the high-level Itb.Encryptor surface. BLAKE2s ships
--  only at -256.
--
--  Each Rust #[test] fn becomes a single nested block in the main
--  procedure; each test_*.adb main procedure compiles into its own
--  executable and runs in its own process with a fresh libitb global
--  state, so per-test serialisation is unnecessary.
--
--  Itb.Encryptor.Set_Nonce_Bits is per-instance and does not touch
--  process-global state, so these tests do not need any process-wide
--  serialisation either.

with Ada.Calendar;
with Ada.Streams;  use Ada.Streams;
with Ada.Text_IO;

with Interfaces;   use Interfaces;

with Itb;          use Itb;
with Itb.Encryptor;
with Itb.Errors;
with Itb.Status;

procedure Test_Easy_Blake2s is

   Hash_Name : constant String := "blake2s";
   Width     : constant Integer := 256;

   --  BLAKE2s carries a 32-byte fixed PRF key.
   Expected_Key_Len : constant Stream_Element_Offset := 32;

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

   Saved_Nonce_Bits : constant Integer := Itb.Get_Nonce_Bits;

begin

   --  Round-trip 1: Single Encrypt / Decrypt across nonce sizes.
   declare
      Plaintext : constant Byte_Array := Token_Bytes (1024);
   begin
      for N of Nonce_Sizes loop
         declare
            Enc : Itb.Encryptor.Encryptor :=
              Itb.Encryptor.Make (Hash_Name, 1024, "kmac256", 1);
         begin
            Itb.Encryptor.Set_Nonce_Bits (Enc, N);
            declare
               Ct : constant Byte_Array :=
                 Itb.Encryptor.Encrypt (Enc, Plaintext);
               Pt : constant Byte_Array :=
                 Itb.Encryptor.Decrypt (Enc, Ct);
            begin
               if Pt /= Plaintext then
                  raise Program_Error
                    with "Single Easy mismatch at nonce" & N'Image;
               end if;
            end;
         end;
      end loop;
   end;

   --  Round-trip 2: Triple Encrypt / Decrypt across nonce sizes.
   declare
      Plaintext : constant Byte_Array := Token_Bytes (1024);
   begin
      for N of Nonce_Sizes loop
         declare
            Enc : Itb.Encryptor.Encryptor :=
              Itb.Encryptor.Make (Hash_Name, 1024, "kmac256", 3);
         begin
            Itb.Encryptor.Set_Nonce_Bits (Enc, N);
            declare
               Ct : constant Byte_Array :=
                 Itb.Encryptor.Encrypt (Enc, Plaintext);
               Pt : constant Byte_Array :=
                 Itb.Encryptor.Decrypt (Enc, Ct);
            begin
               if Pt /= Plaintext then
                  raise Program_Error
                    with "Triple Easy mismatch at nonce" & N'Image;
               end if;
            end;
         end;
      end loop;
   end;

   --  Round-trip 3: Single Auth across nonce sizes + tamper rejection.
   declare
      Plaintext : constant Byte_Array := Token_Bytes (1024);
   begin
      for N of Nonce_Sizes loop
         for M_Ptr of Mac_Names loop
            declare
               Enc : Itb.Encryptor.Encryptor :=
                 Itb.Encryptor.Make (Hash_Name, 1024, M_Ptr.all, 1);
            begin
               Itb.Encryptor.Set_Nonce_Bits (Enc, N);
               declare
                  Ct : constant Byte_Array :=
                    Itb.Encryptor.Encrypt_Auth (Enc, Plaintext);
                  Pt : constant Byte_Array :=
                    Itb.Encryptor.Decrypt_Auth (Enc, Ct);
               begin
                  if Pt /= Plaintext then
                     raise Program_Error
                       with "Single Auth Easy mismatch at "
                            & M_Ptr.all & N'Image;
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
                          with "Single Decrypt_Auth tamper must raise";
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
            end;
         end loop;
      end loop;
   end;

   --  Round-trip 4: Triple Auth across nonce sizes + tamper rejection.
   declare
      Plaintext : constant Byte_Array := Token_Bytes (1024);
   begin
      for N of Nonce_Sizes loop
         for M_Ptr of Mac_Names loop
            declare
               Enc : Itb.Encryptor.Encryptor :=
                 Itb.Encryptor.Make (Hash_Name, 1024, M_Ptr.all, 3);
            begin
               Itb.Encryptor.Set_Nonce_Bits (Enc, N);
               declare
                  Ct : constant Byte_Array :=
                    Itb.Encryptor.Encrypt_Auth (Enc, Plaintext);
                  Pt : constant Byte_Array :=
                    Itb.Encryptor.Decrypt_Auth (Enc, Ct);
               begin
                  if Pt /= Plaintext then
                     raise Program_Error
                       with "Triple Auth Easy mismatch at "
                            & M_Ptr.all & N'Image;
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
                          with "Triple Decrypt_Auth tamper must raise";
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
            end;
         end loop;
      end loop;
   end;

   --  Round-trip 5: Persistence sweep via Export_State / Import_State.
   declare
      Tag        : constant String := "persistence payload ";
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
         for KB of All_Bits loop
            if KB mod Width = 0 then
               for N of Nonce_Sizes loop
                  declare
                     Src : Itb.Encryptor.Encryptor :=
                       Itb.Encryptor.Make (Hash_Name, KB, "kmac256", 1);
                  begin
                     Itb.Encryptor.Set_Nonce_Bits (Src, N);
                     declare
                        Src_Key : constant Byte_Array :=
                          Itb.Encryptor.Get_PRF_Key (Src, 0);
                        Src_C   : constant Component_Array :=
                          Itb.Encryptor.Get_Seed_Components (Src, 0);
                        Blob    : constant Byte_Array :=
                          Itb.Encryptor.Export_State (Src);
                        Ct      : constant Byte_Array :=
                          Itb.Encryptor.Encrypt (Src, Plaintext);
                     begin
                        if Src_Key'Length /= Expected_Key_Len then
                           raise Program_Error
                             with "PRF key length mismatch:"
                                  & Src_Key'Length'Image;
                        end if;
                        if Stream_Element_Offset (Src_C'Length) * 64 /=
                           Stream_Element_Offset (KB)
                        then
                           raise Program_Error
                             with "Components length mismatch:"
                                  & Src_C'Length'Image;
                        end if;
                        Itb.Encryptor.Close (Src);
                        declare
                           Dst : Itb.Encryptor.Encryptor :=
                             Itb.Encryptor.Make (Hash_Name, KB, "kmac256", 1);
                        begin
                           Itb.Encryptor.Set_Nonce_Bits (Dst, N);
                           Itb.Encryptor.Import_State (Dst, Blob);
                           declare
                              Pt : constant Byte_Array :=
                                Itb.Encryptor.Decrypt (Dst, Ct);
                           begin
                              if Pt /= Plaintext then
                                 raise Program_Error
                                   with "Persistence rebuild mismatch";
                              end if;
                           end;
                           Itb.Encryptor.Close (Dst);
                        end;
                     end;
                  end;
               end loop;
            end if;
         end loop;
      end;
   end;

   --  Round-trip 6: Plaintext-size sweep.
   for N of Nonce_Sizes loop
      for Sz of Plaintext_Sizes loop
         declare
            Plaintext : constant Byte_Array := Token_Bytes (Sz);
            Enc : Itb.Encryptor.Encryptor :=
              Itb.Encryptor.Make (Hash_Name, 1024, "kmac256", 1);
         begin
            Itb.Encryptor.Set_Nonce_Bits (Enc, N);
            declare
               Ct : constant Byte_Array :=
                 Itb.Encryptor.Encrypt (Enc, Plaintext);
               Pt : constant Byte_Array :=
                 Itb.Encryptor.Decrypt (Enc, Ct);
            begin
               if Pt /= Plaintext then
                  raise Program_Error
                    with "Size sweep mismatch at" & Sz'Image
                         & " nonce" & N'Image;
               end if;
            end;
         end;
      end loop;
   end loop;

   Itb.Set_Nonce_Bits (Saved_Nonce_Bits);
   Ada.Text_IO.Put_Line ("test_easy_blake2s: PASS");

exception
   when others =>
      begin
         Itb.Set_Nonce_Bits (Saved_Nonce_Bits);
      exception
         when others =>
            null;
      end;
      raise;
end Test_Easy_Blake2s;
