--  Native Blob persistence round-trip tests.
--
--  Mirrors bindings/rust/tests/test_blob.rs one-to-one. Covers the
--  width-typed Blob128 / Blob256 / Blob512 wrappers across Single
--  Ouroboros and Triple Ouroboros export / import flows, MAC + dedicated
--  lockSeed slot opt-ins, captured-globals restoration, and the four
--  malformed-input rejection paths.

with Ada.Streams;          use Ada.Streams;
with Ada.Text_IO;

with Interfaces;

with Itb;          use Itb;
with Itb.Blob;     use type Itb.Blob.Export_Opts;
with Itb.Cipher;
with Itb.Errors;
with Itb.MAC;
with Itb.Seed;

procedure Test_Blob is

   --  Snapshot every global mutated by Blob Import.
   Saved_Nonce_Bits   : constant Integer := Itb.Get_Nonce_Bits;
   Saved_Barrier_Fill : constant Integer := Itb.Get_Barrier_Fill;
   Saved_Bit_Soup     : constant Integer := Itb.Get_Bit_Soup;
   Saved_Lock_Soup    : constant Integer := Itb.Get_Lock_Soup;

   --  Forces non-default globals so an Import-applied snapshot can be
   --  detected via post-Import reads.
   procedure Set_Custom_Globals is
   begin
      Itb.Set_Nonce_Bits   (512);
      Itb.Set_Barrier_Fill (4);
      Itb.Set_Bit_Soup     (1);
      Itb.Set_Lock_Soup    (1);
   end Set_Custom_Globals;

   --  Forces all four globals to their defaults so an Import-applied
   --  snapshot can be detected via post-Import reads.
   procedure Reset_Globals is
   begin
      Itb.Set_Nonce_Bits   (128);
      Itb.Set_Barrier_Fill (1);
      Itb.Set_Bit_Soup     (0);
      Itb.Set_Lock_Soup    (0);
   end Reset_Globals;

   procedure Assert_Globals_Restored is
   begin
      if Itb.Get_Nonce_Bits /= 512 then
         raise Program_Error
           with "Import did not restore Nonce_Bits, got"
                & Itb.Get_Nonce_Bits'Image;
      end if;
      if Itb.Get_Barrier_Fill /= 4 then
         raise Program_Error
           with "Import did not restore Barrier_Fill, got"
                & Itb.Get_Barrier_Fill'Image;
      end if;
      if Itb.Get_Bit_Soup /= 1 then
         raise Program_Error
           with "Import did not restore Bit_Soup";
      end if;
      if Itb.Get_Lock_Soup /= 1 then
         raise Program_Error
           with "Import did not restore Lock_Soup";
      end if;
   end Assert_Globals_Restored;

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
   --  blob256_single_export_import_roundtrip — direct material (no
   --  Seed / Cipher; just slot get/set bytes).
   ------------------------------------------------------------------
   declare
      Sender   : Itb.Blob.Blob256 := Itb.Blob.New_Blob256;
      Receiver : Itb.Blob.Blob256 := Itb.Blob.New_Blob256;
      Key_N    : Byte_Array (1 .. 32);
      Key_D    : Byte_Array (1 .. 32);
      Key_S    : Byte_Array (1 .. 32);
      Mac_Key  : Byte_Array (1 .. 32);
      Comps_N  : Component_Array (1 .. 16);
      Comps_D  : Component_Array (1 .. 16);
      Comps_S  : Component_Array (1 .. 16);
   begin
      for I in 0 .. 31 loop
         Key_N (Stream_Element_Offset (I + 1)) :=
           Stream_Element (16#A0#) xor Stream_Element (I);
         Key_D (Stream_Element_Offset (I + 1)) :=
           Stream_Element (16#B0#) xor Stream_Element (I);
         Key_S (Stream_Element_Offset (I + 1)) :=
           Stream_Element (16#C0#) xor Stream_Element (I);
         Mac_Key (Stream_Element_Offset (I + 1)) :=
           Stream_Element (16#D0#) xor Stream_Element (I);
      end loop;
      for I in 0 .. 15 loop
         Comps_N (I + 1) := Interfaces.Unsigned_64 (16#1000# + I);
         Comps_D (I + 1) := Interfaces.Unsigned_64 (16#2000# + I);
         Comps_S (I + 1) := Interfaces.Unsigned_64 (16#3000# + I);
      end loop;

      Itb.Blob.Set_Key (Sender, Itb.Blob.Slot_N, Key_N);
      Itb.Blob.Set_Components (Sender, Itb.Blob.Slot_N, Comps_N);
      Itb.Blob.Set_Key (Sender, Itb.Blob.Slot_D, Key_D);
      Itb.Blob.Set_Components (Sender, Itb.Blob.Slot_D, Comps_D);
      Itb.Blob.Set_Key (Sender, Itb.Blob.Slot_S, Key_S);
      Itb.Blob.Set_Components (Sender, Itb.Blob.Slot_S, Comps_S);
      Itb.Blob.Set_MAC_Key  (Sender, Mac_Key);
      Itb.Blob.Set_MAC_Name (Sender, "kmac256");

      declare
         Blob_Bytes : constant Byte_Array :=
           Itb.Blob.Export (Sender, Itb.Blob.Opt_Mac);
      begin
         if Blob_Bytes'Length = 0 then
            raise Program_Error with "exported blob is empty";
         end if;
         Itb.Blob.Import (Receiver, Blob_Bytes);
         if Itb.Blob.Width (Receiver) /= 256 then
            raise Program_Error
              with "imported width mismatch:"
                 & Itb.Blob.Width (Receiver)'Image;
         end if;
         if Itb.Blob.Mode (Receiver) /= 1 then
            raise Program_Error
              with "imported mode mismatch:"
                 & Itb.Blob.Mode (Receiver)'Image;
         end if;
         if Itb.Blob.Get_Key (Receiver, Itb.Blob.Slot_N) /= Key_N then
            raise Program_Error with "Key_N mismatch";
         end if;
         if Itb.Blob.Get_Key (Receiver, Itb.Blob.Slot_D) /= Key_D then
            raise Program_Error with "Key_D mismatch";
         end if;
         if Itb.Blob.Get_Key (Receiver, Itb.Blob.Slot_S) /= Key_S then
            raise Program_Error with "Key_S mismatch";
         end if;
         if Itb.Blob.Get_Components (Receiver, Itb.Blob.Slot_N) /= Comps_N
         then
            raise Program_Error with "Comps_N mismatch";
         end if;
         if Itb.Blob.Get_Components (Receiver, Itb.Blob.Slot_D) /= Comps_D
         then
            raise Program_Error with "Comps_D mismatch";
         end if;
         if Itb.Blob.Get_Components (Receiver, Itb.Blob.Slot_S) /= Comps_S
         then
            raise Program_Error with "Comps_S mismatch";
         end if;
         if Itb.Blob.Get_MAC_Key (Receiver) /= Mac_Key then
            raise Program_Error with "MAC key mismatch";
         end if;
         if Itb.Blob.Get_MAC_Name (Receiver) /= "kmac256" then
            raise Program_Error
              with "MAC name mismatch: '"
                 & Itb.Blob.Get_MAC_Name (Receiver) & "'";
         end if;
      end;
   end;

   ------------------------------------------------------------------
   --  blob256_freshly_constructed_has_unset_mode
   ------------------------------------------------------------------
   declare
      B : constant Itb.Blob.Blob256 := Itb.Blob.New_Blob256;
   begin
      if Itb.Blob.Width (B) /= 256 then
         raise Program_Error
           with "fresh Blob256 width:" & Itb.Blob.Width (B)'Image;
      end if;
      if Itb.Blob.Mode (B) /= 0 then
         raise Program_Error
           with "fresh Blob256 mode:" & Itb.Blob.Mode (B)'Image;
      end if;
   end;

   ------------------------------------------------------------------
   --  blob_drop_does_not_panic — RAII via Limited_Controlled.
   ------------------------------------------------------------------
   for I in 1 .. 16 loop
      declare
         B : Itb.Blob.Blob256 := Itb.Blob.New_Blob256;
         pragma Unreferenced (B);
      begin
         null;
      end;
   end loop;

   ------------------------------------------------------------------
   --  test_construct_each_width
   ------------------------------------------------------------------
   declare
      B1 : constant Itb.Blob.Blob128 := Itb.Blob.New_Blob128;
      B2 : constant Itb.Blob.Blob256 := Itb.Blob.New_Blob256;
      B3 : constant Itb.Blob.Blob512 := Itb.Blob.New_Blob512;
   begin
      if Itb.Blob.Width (B1) /= 128 or else Itb.Blob.Mode (B1) /= 0 then
         raise Program_Error with "Blob128 fresh state wrong";
      end if;
      if Itb.Blob.Width (B2) /= 256 or else Itb.Blob.Mode (B2) /= 0 then
         raise Program_Error with "Blob256 fresh state wrong";
      end if;
      if Itb.Blob.Width (B3) /= 512 or else Itb.Blob.Mode (B3) /= 0 then
         raise Program_Error with "Blob512 fresh state wrong";
      end if;
   end;

   ------------------------------------------------------------------
   --  blob512_single_full_matrix — areion512 single, with/without
   --  LockSeed x with/without MAC. Each (LS, Mac) combination drives
   --  through a separate subprogram so the limited Seed types and
   --  conditional Attach_Lock_Seed call don't tangle in one block.
   ------------------------------------------------------------------
   declare
      Plaintext : constant Byte_Array :=
        To_Bytes ("ada blob512 single round-trip payload");

      Mac_Key : constant Byte_Array :=
        [1 .. 32 => Stream_Element (16#55#)];

      procedure Run_Plain is
      begin
         Set_Custom_Globals;
         declare
            Ns : constant Itb.Seed.Seed :=
              Itb.Seed.Make ("areion512", 2048);
            Ds : constant Itb.Seed.Seed :=
              Itb.Seed.Make ("areion512", 2048);
            Ss : constant Itb.Seed.Seed :=
              Itb.Seed.Make ("areion512", 2048);
            Ct : constant Byte_Array :=
              Itb.Cipher.Encrypt (Ns, Ds, Ss, Plaintext);
            Src : Itb.Blob.Blob512 := Itb.Blob.New_Blob512;
         begin
            Itb.Blob.Set_Key
              (Src, Itb.Blob.Slot_N, Itb.Seed.Get_Hash_Key (Ns));
            Itb.Blob.Set_Key
              (Src, Itb.Blob.Slot_D, Itb.Seed.Get_Hash_Key (Ds));
            Itb.Blob.Set_Key
              (Src, Itb.Blob.Slot_S, Itb.Seed.Get_Hash_Key (Ss));
            Itb.Blob.Set_Components
              (Src, Itb.Blob.Slot_N, Itb.Seed.Get_Components (Ns));
            Itb.Blob.Set_Components
              (Src, Itb.Blob.Slot_D, Itb.Seed.Get_Components (Ds));
            Itb.Blob.Set_Components
              (Src, Itb.Blob.Slot_S, Itb.Seed.Get_Components (Ss));
            declare
               Blob_Bytes : constant Byte_Array := Itb.Blob.Export (Src);
               Dst : Itb.Blob.Blob512 := Itb.Blob.New_Blob512;
            begin
               Reset_Globals;
               Itb.Blob.Import (Dst, Blob_Bytes);
               if Itb.Blob.Mode (Dst) /= 1 then
                  raise Program_Error with "single mode mismatch";
               end if;
               Assert_Globals_Restored;
               declare
                  Ns2 : constant Itb.Seed.Seed :=
                    Itb.Seed.From_Components
                      ("areion512",
                       Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_N),
                       Itb.Blob.Get_Key (Dst, Itb.Blob.Slot_N));
                  Ds2 : constant Itb.Seed.Seed :=
                    Itb.Seed.From_Components
                      ("areion512",
                       Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_D),
                       Itb.Blob.Get_Key (Dst, Itb.Blob.Slot_D));
                  Ss2 : constant Itb.Seed.Seed :=
                    Itb.Seed.From_Components
                      ("areion512",
                       Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_S),
                       Itb.Blob.Get_Key (Dst, Itb.Blob.Slot_S));
                  Pt : constant Byte_Array :=
                    Itb.Cipher.Decrypt (Ns2, Ds2, Ss2, Ct);
               begin
                  if Pt /= Plaintext then
                     raise Program_Error with "plain decrypt mismatch";
                  end if;
               end;
            end;
         end;
      end Run_Plain;

      procedure Run_With_Mac is
      begin
         Set_Custom_Globals;
         declare
            Ns : constant Itb.Seed.Seed :=
              Itb.Seed.Make ("areion512", 2048);
            Ds : constant Itb.Seed.Seed :=
              Itb.Seed.Make ("areion512", 2048);
            Ss : constant Itb.Seed.Seed :=
              Itb.Seed.Make ("areion512", 2048);
            M  : constant Itb.MAC.MAC := Itb.MAC.Make ("kmac256", Mac_Key);
            Ct : constant Byte_Array :=
              Itb.Cipher.Encrypt_Auth (Ns, Ds, Ss, M, Plaintext);
            Src : Itb.Blob.Blob512 := Itb.Blob.New_Blob512;
         begin
            Itb.Blob.Set_Key
              (Src, Itb.Blob.Slot_N, Itb.Seed.Get_Hash_Key (Ns));
            Itb.Blob.Set_Key
              (Src, Itb.Blob.Slot_D, Itb.Seed.Get_Hash_Key (Ds));
            Itb.Blob.Set_Key
              (Src, Itb.Blob.Slot_S, Itb.Seed.Get_Hash_Key (Ss));
            Itb.Blob.Set_Components
              (Src, Itb.Blob.Slot_N, Itb.Seed.Get_Components (Ns));
            Itb.Blob.Set_Components
              (Src, Itb.Blob.Slot_D, Itb.Seed.Get_Components (Ds));
            Itb.Blob.Set_Components
              (Src, Itb.Blob.Slot_S, Itb.Seed.Get_Components (Ss));
            Itb.Blob.Set_MAC_Key  (Src, Mac_Key);
            Itb.Blob.Set_MAC_Name (Src, "kmac256");
            declare
               Blob_Bytes : constant Byte_Array :=
                 Itb.Blob.Export (Src, Itb.Blob.Opt_Mac);
               Dst : Itb.Blob.Blob512 := Itb.Blob.New_Blob512;
            begin
               Reset_Globals;
               Itb.Blob.Import (Dst, Blob_Bytes);
               Assert_Globals_Restored;
               declare
                  Ns2 : constant Itb.Seed.Seed :=
                    Itb.Seed.From_Components
                      ("areion512",
                       Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_N),
                       Itb.Blob.Get_Key (Dst, Itb.Blob.Slot_N));
                  Ds2 : constant Itb.Seed.Seed :=
                    Itb.Seed.From_Components
                      ("areion512",
                       Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_D),
                       Itb.Blob.Get_Key (Dst, Itb.Blob.Slot_D));
                  Ss2 : constant Itb.Seed.Seed :=
                    Itb.Seed.From_Components
                      ("areion512",
                       Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_S),
                       Itb.Blob.Get_Key (Dst, Itb.Blob.Slot_S));
                  Mac2 : constant Itb.MAC.MAC :=
                    Itb.MAC.Make ("kmac256", Itb.Blob.Get_MAC_Key (Dst));
                  Pt : constant Byte_Array :=
                    Itb.Cipher.Decrypt_Auth (Ns2, Ds2, Ss2, Mac2, Ct);
               begin
                  if Pt /= Plaintext then
                     raise Program_Error with "+Mac decrypt mismatch";
                  end if;
                  if Itb.Blob.Get_MAC_Name (Dst) /= "kmac256" then
                     raise Program_Error
                       with "MAC name not preserved: '"
                          & Itb.Blob.Get_MAC_Name (Dst) & "'";
                  end if;
               end;
            end;
         end;
      end Run_With_Mac;

      procedure Run_With_LS is
      begin
         Set_Custom_Globals;
         declare
            Ns : constant Itb.Seed.Seed :=
              Itb.Seed.Make ("areion512", 2048);
            Ds : constant Itb.Seed.Seed :=
              Itb.Seed.Make ("areion512", 2048);
            Ss : constant Itb.Seed.Seed :=
              Itb.Seed.Make ("areion512", 2048);
            Ls : constant Itb.Seed.Seed :=
              Itb.Seed.Make ("areion512", 2048);
         begin
            Itb.Seed.Attach_Lock_Seed (Ns, Ls);
            declare
               Ct : constant Byte_Array :=
                 Itb.Cipher.Encrypt (Ns, Ds, Ss, Plaintext);
               Src : Itb.Blob.Blob512 := Itb.Blob.New_Blob512;
            begin
               Itb.Blob.Set_Key
                 (Src, Itb.Blob.Slot_N, Itb.Seed.Get_Hash_Key (Ns));
               Itb.Blob.Set_Key
                 (Src, Itb.Blob.Slot_D, Itb.Seed.Get_Hash_Key (Ds));
               Itb.Blob.Set_Key
                 (Src, Itb.Blob.Slot_S, Itb.Seed.Get_Hash_Key (Ss));
               Itb.Blob.Set_Key
                 (Src, Itb.Blob.Slot_L, Itb.Seed.Get_Hash_Key (Ls));
               Itb.Blob.Set_Components
                 (Src, Itb.Blob.Slot_N, Itb.Seed.Get_Components (Ns));
               Itb.Blob.Set_Components
                 (Src, Itb.Blob.Slot_D, Itb.Seed.Get_Components (Ds));
               Itb.Blob.Set_Components
                 (Src, Itb.Blob.Slot_S, Itb.Seed.Get_Components (Ss));
               Itb.Blob.Set_Components
                 (Src, Itb.Blob.Slot_L, Itb.Seed.Get_Components (Ls));
               declare
                  Blob_Bytes : constant Byte_Array :=
                    Itb.Blob.Export (Src, Itb.Blob.Opt_LockSeed);
                  Dst : Itb.Blob.Blob512 := Itb.Blob.New_Blob512;
               begin
                  Reset_Globals;
                  Itb.Blob.Import (Dst, Blob_Bytes);
                  Assert_Globals_Restored;
                  declare
                     Ns2 : constant Itb.Seed.Seed :=
                       Itb.Seed.From_Components
                         ("areion512",
                          Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_N),
                          Itb.Blob.Get_Key (Dst, Itb.Blob.Slot_N));
                     Ds2 : constant Itb.Seed.Seed :=
                       Itb.Seed.From_Components
                         ("areion512",
                          Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_D),
                          Itb.Blob.Get_Key (Dst, Itb.Blob.Slot_D));
                     Ss2 : constant Itb.Seed.Seed :=
                       Itb.Seed.From_Components
                         ("areion512",
                          Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_S),
                          Itb.Blob.Get_Key (Dst, Itb.Blob.Slot_S));
                     Ls2 : constant Itb.Seed.Seed :=
                       Itb.Seed.From_Components
                         ("areion512",
                          Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_L),
                          Itb.Blob.Get_Key (Dst, Itb.Blob.Slot_L));
                  begin
                     Itb.Seed.Attach_Lock_Seed (Ns2, Ls2);
                     declare
                        Pt : constant Byte_Array :=
                          Itb.Cipher.Decrypt (Ns2, Ds2, Ss2, Ct);
                     begin
                        if Pt /= Plaintext then
                           raise Program_Error
                             with "+LS decrypt mismatch";
                        end if;
                     end;
                  end;
               end;
            end;
         end;
      end Run_With_LS;

      procedure Run_With_LS_And_Mac is
      begin
         Set_Custom_Globals;
         declare
            Ns : constant Itb.Seed.Seed :=
              Itb.Seed.Make ("areion512", 2048);
            Ds : constant Itb.Seed.Seed :=
              Itb.Seed.Make ("areion512", 2048);
            Ss : constant Itb.Seed.Seed :=
              Itb.Seed.Make ("areion512", 2048);
            Ls : constant Itb.Seed.Seed :=
              Itb.Seed.Make ("areion512", 2048);
            M  : constant Itb.MAC.MAC := Itb.MAC.Make ("kmac256", Mac_Key);
         begin
            Itb.Seed.Attach_Lock_Seed (Ns, Ls);
            declare
               Ct : constant Byte_Array :=
                 Itb.Cipher.Encrypt_Auth (Ns, Ds, Ss, M, Plaintext);
               Src : Itb.Blob.Blob512 := Itb.Blob.New_Blob512;
            begin
               Itb.Blob.Set_Key
                 (Src, Itb.Blob.Slot_N, Itb.Seed.Get_Hash_Key (Ns));
               Itb.Blob.Set_Key
                 (Src, Itb.Blob.Slot_D, Itb.Seed.Get_Hash_Key (Ds));
               Itb.Blob.Set_Key
                 (Src, Itb.Blob.Slot_S, Itb.Seed.Get_Hash_Key (Ss));
               Itb.Blob.Set_Key
                 (Src, Itb.Blob.Slot_L, Itb.Seed.Get_Hash_Key (Ls));
               Itb.Blob.Set_Components
                 (Src, Itb.Blob.Slot_N, Itb.Seed.Get_Components (Ns));
               Itb.Blob.Set_Components
                 (Src, Itb.Blob.Slot_D, Itb.Seed.Get_Components (Ds));
               Itb.Blob.Set_Components
                 (Src, Itb.Blob.Slot_S, Itb.Seed.Get_Components (Ss));
               Itb.Blob.Set_Components
                 (Src, Itb.Blob.Slot_L, Itb.Seed.Get_Components (Ls));
               Itb.Blob.Set_MAC_Key  (Src, Mac_Key);
               Itb.Blob.Set_MAC_Name (Src, "kmac256");
               declare
                  Blob_Bytes : constant Byte_Array :=
                    Itb.Blob.Export
                      (Src,
                       Itb.Blob.Opt_LockSeed + Itb.Blob.Opt_Mac);
                  Dst : Itb.Blob.Blob512 := Itb.Blob.New_Blob512;
               begin
                  Reset_Globals;
                  Itb.Blob.Import (Dst, Blob_Bytes);
                  Assert_Globals_Restored;
                  declare
                     Ns2 : constant Itb.Seed.Seed :=
                       Itb.Seed.From_Components
                         ("areion512",
                          Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_N),
                          Itb.Blob.Get_Key (Dst, Itb.Blob.Slot_N));
                     Ds2 : constant Itb.Seed.Seed :=
                       Itb.Seed.From_Components
                         ("areion512",
                          Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_D),
                          Itb.Blob.Get_Key (Dst, Itb.Blob.Slot_D));
                     Ss2 : constant Itb.Seed.Seed :=
                       Itb.Seed.From_Components
                         ("areion512",
                          Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_S),
                          Itb.Blob.Get_Key (Dst, Itb.Blob.Slot_S));
                     Ls2 : constant Itb.Seed.Seed :=
                       Itb.Seed.From_Components
                         ("areion512",
                          Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_L),
                          Itb.Blob.Get_Key (Dst, Itb.Blob.Slot_L));
                     Mac2 : constant Itb.MAC.MAC :=
                       Itb.MAC.Make
                         ("kmac256", Itb.Blob.Get_MAC_Key (Dst));
                  begin
                     Itb.Seed.Attach_Lock_Seed (Ns2, Ls2);
                     declare
                        Pt : constant Byte_Array :=
                          Itb.Cipher.Decrypt_Auth
                            (Ns2, Ds2, Ss2, Mac2, Ct);
                     begin
                        if Pt /= Plaintext then
                           raise Program_Error
                             with "+LS+Mac decrypt mismatch";
                        end if;
                     end;
                  end;
               end;
            end;
         end;
      end Run_With_LS_And_Mac;

   begin
      Run_Plain;
      Run_With_Mac;
      Run_With_LS;
      Run_With_LS_And_Mac;
   end;

   ------------------------------------------------------------------
   --  test_blob256_single (BLAKE3, Set_Custom_Globals + Reset_Globals
   --  + Assert_Globals_Restored).
   ------------------------------------------------------------------
   Set_Custom_Globals;
   declare
      Plaintext : constant Byte_Array :=
        To_Bytes ("ada blob256 single round-trip");
      Ns : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Ds : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Ss : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Ct : constant Byte_Array := Itb.Cipher.Encrypt (Ns, Ds, Ss, Plaintext);
      Src : Itb.Blob.Blob256 := Itb.Blob.New_Blob256;
   begin
      Itb.Blob.Set_Key
        (Src, Itb.Blob.Slot_N, Itb.Seed.Get_Hash_Key (Ns));
      Itb.Blob.Set_Key
        (Src, Itb.Blob.Slot_D, Itb.Seed.Get_Hash_Key (Ds));
      Itb.Blob.Set_Key
        (Src, Itb.Blob.Slot_S, Itb.Seed.Get_Hash_Key (Ss));
      Itb.Blob.Set_Components
        (Src, Itb.Blob.Slot_N, Itb.Seed.Get_Components (Ns));
      Itb.Blob.Set_Components
        (Src, Itb.Blob.Slot_D, Itb.Seed.Get_Components (Ds));
      Itb.Blob.Set_Components
        (Src, Itb.Blob.Slot_S, Itb.Seed.Get_Components (Ss));
      declare
         Blob_Bytes : constant Byte_Array := Itb.Blob.Export (Src);
         Dst        : Itb.Blob.Blob256 := Itb.Blob.New_Blob256;
      begin
         Reset_Globals;
         Itb.Blob.Import (Dst, Blob_Bytes);
         if Itb.Blob.Mode (Dst) /= 1 then
            raise Program_Error with "blob256 single mode";
         end if;
         declare
            Ns2 : constant Itb.Seed.Seed :=
              Itb.Seed.From_Components
                ("blake3",
                 Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_N),
                 Itb.Blob.Get_Key (Dst, Itb.Blob.Slot_N));
            Ds2 : constant Itb.Seed.Seed :=
              Itb.Seed.From_Components
                ("blake3",
                 Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_D),
                 Itb.Blob.Get_Key (Dst, Itb.Blob.Slot_D));
            Ss2 : constant Itb.Seed.Seed :=
              Itb.Seed.From_Components
                ("blake3",
                 Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_S),
                 Itb.Blob.Get_Key (Dst, Itb.Blob.Slot_S));
            Pt : constant Byte_Array :=
              Itb.Cipher.Decrypt (Ns2, Ds2, Ss2, Ct);
         begin
            if Pt /= Plaintext then
               raise Program_Error with "blob256 single round-trip mismatch";
            end if;
         end;
      end;
   end;

   ------------------------------------------------------------------
   --  test_blob256_triple (BLAKE3, 7 seeds).
   ------------------------------------------------------------------
   Set_Custom_Globals;
   declare
      Plaintext : constant Byte_Array :=
        To_Bytes ("ada blob256 triple round-trip");
      S0 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S1 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S2 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S3 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S4 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S5 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S6 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Ct : constant Byte_Array :=
        Itb.Cipher.Encrypt_Triple (S0, S1, S2, S3, S4, S5, S6, Plaintext);
      Src : Itb.Blob.Blob256 := Itb.Blob.New_Blob256;
   begin
      Itb.Blob.Set_Key
        (Src, Itb.Blob.Slot_N, Itb.Seed.Get_Hash_Key (S0));
      Itb.Blob.Set_Key
        (Src, Itb.Blob.Slot_D1, Itb.Seed.Get_Hash_Key (S1));
      Itb.Blob.Set_Key
        (Src, Itb.Blob.Slot_D2, Itb.Seed.Get_Hash_Key (S2));
      Itb.Blob.Set_Key
        (Src, Itb.Blob.Slot_D3, Itb.Seed.Get_Hash_Key (S3));
      Itb.Blob.Set_Key
        (Src, Itb.Blob.Slot_S1, Itb.Seed.Get_Hash_Key (S4));
      Itb.Blob.Set_Key
        (Src, Itb.Blob.Slot_S2, Itb.Seed.Get_Hash_Key (S5));
      Itb.Blob.Set_Key
        (Src, Itb.Blob.Slot_S3, Itb.Seed.Get_Hash_Key (S6));
      Itb.Blob.Set_Components
        (Src, Itb.Blob.Slot_N,  Itb.Seed.Get_Components (S0));
      Itb.Blob.Set_Components
        (Src, Itb.Blob.Slot_D1, Itb.Seed.Get_Components (S1));
      Itb.Blob.Set_Components
        (Src, Itb.Blob.Slot_D2, Itb.Seed.Get_Components (S2));
      Itb.Blob.Set_Components
        (Src, Itb.Blob.Slot_D3, Itb.Seed.Get_Components (S3));
      Itb.Blob.Set_Components
        (Src, Itb.Blob.Slot_S1, Itb.Seed.Get_Components (S4));
      Itb.Blob.Set_Components
        (Src, Itb.Blob.Slot_S2, Itb.Seed.Get_Components (S5));
      Itb.Blob.Set_Components
        (Src, Itb.Blob.Slot_S3, Itb.Seed.Get_Components (S6));
      declare
         Blob_Bytes : constant Byte_Array := Itb.Blob.Export_3 (Src);
         Dst        : Itb.Blob.Blob256 := Itb.Blob.New_Blob256;
      begin
         Reset_Globals;
         Itb.Blob.Import_3 (Dst, Blob_Bytes);
         if Itb.Blob.Mode (Dst) /= 3 then
            raise Program_Error with "blob256 triple mode";
         end if;
         declare
            Ns2 : constant Itb.Seed.Seed :=
              Itb.Seed.From_Components
                ("blake3",
                 Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_N),
                 Itb.Blob.Get_Key (Dst, Itb.Blob.Slot_N));
            D1_2 : constant Itb.Seed.Seed :=
              Itb.Seed.From_Components
                ("blake3",
                 Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_D1),
                 Itb.Blob.Get_Key (Dst, Itb.Blob.Slot_D1));
            D2_2 : constant Itb.Seed.Seed :=
              Itb.Seed.From_Components
                ("blake3",
                 Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_D2),
                 Itb.Blob.Get_Key (Dst, Itb.Blob.Slot_D2));
            D3_2 : constant Itb.Seed.Seed :=
              Itb.Seed.From_Components
                ("blake3",
                 Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_D3),
                 Itb.Blob.Get_Key (Dst, Itb.Blob.Slot_D3));
            S1_2 : constant Itb.Seed.Seed :=
              Itb.Seed.From_Components
                ("blake3",
                 Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_S1),
                 Itb.Blob.Get_Key (Dst, Itb.Blob.Slot_S1));
            S2_2 : constant Itb.Seed.Seed :=
              Itb.Seed.From_Components
                ("blake3",
                 Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_S2),
                 Itb.Blob.Get_Key (Dst, Itb.Blob.Slot_S2));
            S3_2 : constant Itb.Seed.Seed :=
              Itb.Seed.From_Components
                ("blake3",
                 Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_S3),
                 Itb.Blob.Get_Key (Dst, Itb.Blob.Slot_S3));
            Pt : constant Byte_Array :=
              Itb.Cipher.Decrypt_Triple
                (Ns2, D1_2, D2_2, D3_2, S1_2, S2_2, S3_2, Ct);
         begin
            if Pt /= Plaintext then
               raise Program_Error with "blob256 triple round-trip mismatch";
            end if;
         end;
      end;
   end;

   ------------------------------------------------------------------
   --  test_blob128_siphash_single — siphash24 has empty hash key.
   ------------------------------------------------------------------
   Set_Custom_Globals;
   declare
      Plaintext : constant Byte_Array :=
        To_Bytes ("ada blob128 siphash round-trip");
      Ns : constant Itb.Seed.Seed := Itb.Seed.Make ("siphash24", 512);
      Ds : constant Itb.Seed.Seed := Itb.Seed.Make ("siphash24", 512);
      Ss : constant Itb.Seed.Seed := Itb.Seed.Make ("siphash24", 512);
      Ct : constant Byte_Array := Itb.Cipher.Encrypt (Ns, Ds, Ss, Plaintext);
      Src : Itb.Blob.Blob128 := Itb.Blob.New_Blob128;
   begin
      Itb.Blob.Set_Key
        (Src, Itb.Blob.Slot_N, Itb.Seed.Get_Hash_Key (Ns));
      Itb.Blob.Set_Key
        (Src, Itb.Blob.Slot_D, Itb.Seed.Get_Hash_Key (Ds));
      Itb.Blob.Set_Key
        (Src, Itb.Blob.Slot_S, Itb.Seed.Get_Hash_Key (Ss));
      Itb.Blob.Set_Components
        (Src, Itb.Blob.Slot_N, Itb.Seed.Get_Components (Ns));
      Itb.Blob.Set_Components
        (Src, Itb.Blob.Slot_D, Itb.Seed.Get_Components (Ds));
      Itb.Blob.Set_Components
        (Src, Itb.Blob.Slot_S, Itb.Seed.Get_Components (Ss));
      declare
         Blob_Bytes : constant Byte_Array := Itb.Blob.Export (Src);
         Dst        : Itb.Blob.Blob128 := Itb.Blob.New_Blob128;
         Empty      : constant Byte_Array := [1 .. 0 => 0];
      begin
         Reset_Globals;
         Itb.Blob.Import (Dst, Blob_Bytes);
         declare
            Ns2 : constant Itb.Seed.Seed :=
              Itb.Seed.From_Components
                ("siphash24",
                 Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_N),
                 Empty);
            Ds2 : constant Itb.Seed.Seed :=
              Itb.Seed.From_Components
                ("siphash24",
                 Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_D),
                 Empty);
            Ss2 : constant Itb.Seed.Seed :=
              Itb.Seed.From_Components
                ("siphash24",
                 Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_S),
                 Empty);
            Pt : constant Byte_Array :=
              Itb.Cipher.Decrypt (Ns2, Ds2, Ss2, Ct);
         begin
            if Pt /= Plaintext then
               raise Program_Error
                 with "blob128 siphash round-trip mismatch";
            end if;
         end;
      end;
   end;

   ------------------------------------------------------------------
   --  test_blob128_aescmac_single
   ------------------------------------------------------------------
   Set_Custom_Globals;
   declare
      Plaintext : constant Byte_Array :=
        To_Bytes ("ada blob128 aescmac round-trip");
      Ns : constant Itb.Seed.Seed := Itb.Seed.Make ("aescmac", 512);
      Ds : constant Itb.Seed.Seed := Itb.Seed.Make ("aescmac", 512);
      Ss : constant Itb.Seed.Seed := Itb.Seed.Make ("aescmac", 512);
      Ct : constant Byte_Array := Itb.Cipher.Encrypt (Ns, Ds, Ss, Plaintext);
      Src : Itb.Blob.Blob128 := Itb.Blob.New_Blob128;
   begin
      Itb.Blob.Set_Key
        (Src, Itb.Blob.Slot_N, Itb.Seed.Get_Hash_Key (Ns));
      Itb.Blob.Set_Key
        (Src, Itb.Blob.Slot_D, Itb.Seed.Get_Hash_Key (Ds));
      Itb.Blob.Set_Key
        (Src, Itb.Blob.Slot_S, Itb.Seed.Get_Hash_Key (Ss));
      Itb.Blob.Set_Components
        (Src, Itb.Blob.Slot_N, Itb.Seed.Get_Components (Ns));
      Itb.Blob.Set_Components
        (Src, Itb.Blob.Slot_D, Itb.Seed.Get_Components (Ds));
      Itb.Blob.Set_Components
        (Src, Itb.Blob.Slot_S, Itb.Seed.Get_Components (Ss));
      declare
         Blob_Bytes : constant Byte_Array := Itb.Blob.Export (Src);
         Dst        : Itb.Blob.Blob128 := Itb.Blob.New_Blob128;
      begin
         Reset_Globals;
         Itb.Blob.Import (Dst, Blob_Bytes);
         declare
            Ns2 : constant Itb.Seed.Seed :=
              Itb.Seed.From_Components
                ("aescmac",
                 Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_N),
                 Itb.Blob.Get_Key (Dst, Itb.Blob.Slot_N));
            Ds2 : constant Itb.Seed.Seed :=
              Itb.Seed.From_Components
                ("aescmac",
                 Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_D),
                 Itb.Blob.Get_Key (Dst, Itb.Blob.Slot_D));
            Ss2 : constant Itb.Seed.Seed :=
              Itb.Seed.From_Components
                ("aescmac",
                 Itb.Blob.Get_Components (Dst, Itb.Blob.Slot_S),
                 Itb.Blob.Get_Key (Dst, Itb.Blob.Slot_S));
            Pt : constant Byte_Array :=
              Itb.Cipher.Decrypt (Ns2, Ds2, Ss2, Ct);
         begin
            if Pt /= Plaintext then
               raise Program_Error
                 with "blob128 aescmac round-trip mismatch";
            end if;
         end;
      end;
   end;

   ------------------------------------------------------------------
   --  test_mode_mismatch — Single blob fed to Import_3 must raise
   --  Itb_Blob_Mode_Mismatch_Error.
   ------------------------------------------------------------------
   Set_Custom_Globals;
   declare
      Ns : constant Itb.Seed.Seed := Itb.Seed.Make ("areion512", 1024);
      Ds : constant Itb.Seed.Seed := Itb.Seed.Make ("areion512", 1024);
      Ss : constant Itb.Seed.Seed := Itb.Seed.Make ("areion512", 1024);
      Src : Itb.Blob.Blob512 := Itb.Blob.New_Blob512;
   begin
      Itb.Blob.Set_Key
        (Src, Itb.Blob.Slot_N, Itb.Seed.Get_Hash_Key (Ns));
      Itb.Blob.Set_Key
        (Src, Itb.Blob.Slot_D, Itb.Seed.Get_Hash_Key (Ds));
      Itb.Blob.Set_Key
        (Src, Itb.Blob.Slot_S, Itb.Seed.Get_Hash_Key (Ss));
      Itb.Blob.Set_Components
        (Src, Itb.Blob.Slot_N, Itb.Seed.Get_Components (Ns));
      Itb.Blob.Set_Components
        (Src, Itb.Blob.Slot_D, Itb.Seed.Get_Components (Ds));
      Itb.Blob.Set_Components
        (Src, Itb.Blob.Slot_S, Itb.Seed.Get_Components (Ss));
      declare
         Blob_Bytes : constant Byte_Array := Itb.Blob.Export (Src);
         Dst : Itb.Blob.Blob512 := Itb.Blob.New_Blob512;
      begin
         begin
            Itb.Blob.Import_3 (Dst, Blob_Bytes);
            raise Program_Error with "Single-mode blob into Import_3";
         exception
            when Itb.Errors.Itb_Blob_Mode_Mismatch_Error =>
               null;
         end;
      end;
   end;

   ------------------------------------------------------------------
   --  test_malformed
   ------------------------------------------------------------------
   declare
      B : Itb.Blob.Blob512 := Itb.Blob.New_Blob512;
   begin
      begin
         Itb.Blob.Import (B, To_Bytes ("{not json"));
         raise Program_Error with "malformed blob must raise";
      exception
         when Itb.Errors.Itb_Blob_Malformed_Error =>
            null;
      end;
   end;

   ------------------------------------------------------------------
   --  test_version_too_new — hand-built JSON with v=99.
   ------------------------------------------------------------------
   declare
      function Repeat (S : String; N : Natural) return String is
         R : String (1 .. S'Length * N);
      begin
         for I in 0 .. N - 1 loop
            R (I * S'Length + 1 .. (I + 1) * S'Length) := S;
         end loop;
         return R;
      end Repeat;

      Zeros_64 : constant String := Repeat ("00", 64);
      Comp_Block : constant String :=
        """0"",""0"",""0"",""0"",""0"",""0"",""0"",""0""";
      Doc : constant String :=
        "{""v"":99,""mode"":1,""key_bits"":512,"
        & """key_n"":""" & Zeros_64 & ""","
        & """key_d"":""" & Zeros_64 & ""","
        & """key_s"":""" & Zeros_64 & ""","
        & """ns"":[" & Comp_Block & "],"
        & """ds"":[" & Comp_Block & "],"
        & """ss"":[" & Comp_Block & "],"
        & """globals"":{""nonce_bits"":128,""barrier_fill"":1,"
        & """bit_soup"":0,""lock_soup"":0}}";
      B : Itb.Blob.Blob512 := Itb.Blob.New_Blob512;
   begin
      begin
         Itb.Blob.Import (B, To_Bytes (Doc));
         raise Program_Error with "v=99 blob must raise";
      exception
         when Itb.Errors.Itb_Blob_Version_Too_New_Error =>
            null;
      end;
   end;

   --  Restore globals before exit.
   Itb.Set_Nonce_Bits   (Saved_Nonce_Bits);
   Itb.Set_Barrier_Fill (Saved_Barrier_Fill);
   Itb.Set_Bit_Soup     (Saved_Bit_Soup);
   Itb.Set_Lock_Soup    (Saved_Lock_Soup);
   Ada.Text_IO.Put_Line ("test_blob: PASS");

exception
   when others =>
      begin
         Itb.Set_Nonce_Bits   (Saved_Nonce_Bits);
         Itb.Set_Barrier_Fill (Saved_Barrier_Fill);
         Itb.Set_Bit_Soup     (Saved_Bit_Soup);
         Itb.Set_Lock_Soup    (Saved_Lock_Soup);
      exception
         when others =>
            null;
      end;
      raise;
end Test_Blob;
