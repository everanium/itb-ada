--  Integration tests for the low-level Itb.Seed.Attach_Lock_Seed
--  mutator. The dedicated lockSeed routes the bit-permutation
--  derivation through its own state instead of the noiseSeed.
--
--  The bit-permutation overlay must be engaged via Set_Bit_Soup or
--  Set_Lock_Soup before any encrypt call; without the overlay the
--  dedicated lockSeed has no observable effect on the wire output and
--  the Go-side build-PRF guard surfaces as Itb_Error. These tests
--  exercise both the round-trip path with overlay engaged and the
--  attach-time misuse rejections.
--
--  Mirrors bindings/rust/tests/test_attach_lock_seed.rs.

with Ada.Streams;  use Ada.Streams;
with Ada.Text_IO;

with Itb;          use Itb;
with Itb.Cipher;
with Itb.Errors;
with Itb.Seed;
with Itb.Status;

procedure Test_Attach_Lock_Seed is

   --  Snapshot every global mutated.
   Saved_Bit_Soup  : constant Integer := Itb.Get_Bit_Soup;
   Saved_Lock_Soup : constant Integer := Itb.Get_Lock_Soup;

   procedure Engage_Lock_Soup is
   begin
      Itb.Set_Lock_Soup (1);
      --  Set_Lock_Soup auto-couples Bit_Soup=1 inside libitb. The
      --  Easy Mode auto-couple is the documented behaviour: enabling
      --  Lock_Soup implies Bit_Soup, since Lock_Soup operates on the
      --  bit-soup permutation surface.
   end Engage_Lock_Soup;

   procedure Disengage_Lock_Soup is
   begin
      Itb.Set_Bit_Soup (0);
      Itb.Set_Lock_Soup (0);
   end Disengage_Lock_Soup;

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
   --  test_roundtrip
   ------------------------------------------------------------------
   Engage_Lock_Soup;
   declare
      Plain : constant Byte_Array :=
        To_Bytes ("attach_lock_seed roundtrip payload");
      Ns : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Ds : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Ss : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Ls : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
   begin
      Itb.Seed.Attach_Lock_Seed (Ns, Ls);
      declare
         Ct : constant Byte_Array := Itb.Cipher.Encrypt (Ns, Ds, Ss, Plain);
         Decoded : constant Byte_Array :=
           Itb.Cipher.Decrypt (Ns, Ds, Ss, Ct);
      begin
         if Decoded /= Plain then
            raise Program_Error
              with "attach_lock_seed roundtrip mismatch";
         end if;
      end;
   end;
   Disengage_Lock_Soup;

   ------------------------------------------------------------------
   --  test_persistence — Day 1 sender, Day 2 receiver. The lockSeed
   --  must be persisted alongside the noise/data/start seeds.
   ------------------------------------------------------------------
   Engage_Lock_Soup;
   declare
      Plain : constant Byte_Array :=
        To_Bytes ("cross-process attach lockseed roundtrip");
      Ns : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Ds : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Ss : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Ls : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
   begin
      Itb.Seed.Attach_Lock_Seed (Ns, Ls);
      declare
         Ns_C : constant Component_Array := Itb.Seed.Get_Components (Ns);
         Ds_C : constant Component_Array := Itb.Seed.Get_Components (Ds);
         Ss_C : constant Component_Array := Itb.Seed.Get_Components (Ss);
         Ls_C : constant Component_Array := Itb.Seed.Get_Components (Ls);
         Ns_K : constant Byte_Array := Itb.Seed.Get_Hash_Key (Ns);
         Ds_K : constant Byte_Array := Itb.Seed.Get_Hash_Key (Ds);
         Ss_K : constant Byte_Array := Itb.Seed.Get_Hash_Key (Ss);
         Ls_K : constant Byte_Array := Itb.Seed.Get_Hash_Key (Ls);
         Ct   : constant Byte_Array :=
           Itb.Cipher.Encrypt (Ns, Ds, Ss, Plain);
         --  Day 2 — receiver rebuilds.
         Ns2 : constant Itb.Seed.Seed :=
           Itb.Seed.From_Components ("blake3", Ns_C, Ns_K);
         Ds2 : constant Itb.Seed.Seed :=
           Itb.Seed.From_Components ("blake3", Ds_C, Ds_K);
         Ss2 : constant Itb.Seed.Seed :=
           Itb.Seed.From_Components ("blake3", Ss_C, Ss_K);
         Ls2 : constant Itb.Seed.Seed :=
           Itb.Seed.From_Components ("blake3", Ls_C, Ls_K);
      begin
         Itb.Seed.Attach_Lock_Seed (Ns2, Ls2);
         declare
            Decoded : constant Byte_Array :=
              Itb.Cipher.Decrypt (Ns2, Ds2, Ss2, Ct);
         begin
            if Decoded /= Plain then
               raise Program_Error
                 with "attach_lock_seed persistence mismatch";
            end if;
         end;
      end;
   end;
   Disengage_Lock_Soup;

   ------------------------------------------------------------------
   --  test_self_attach_rejected
   ------------------------------------------------------------------
   declare
      Ns : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
   begin
      begin
         Itb.Seed.Attach_Lock_Seed (Ns, Ns);
         raise Program_Error with "self-attach must raise";
      exception
         when E : Itb.Errors.Itb_Error =>
            if Itb.Errors.Status_Code (E) /= Itb.Status.Bad_Input then
               raise;
            end if;
      end;
   end;

   ------------------------------------------------------------------
   --  test_width_mismatch_rejected
   ------------------------------------------------------------------
   declare
      Ns_256 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Ls_128 : constant Itb.Seed.Seed := Itb.Seed.Make ("siphash24", 1024);
   begin
      begin
         Itb.Seed.Attach_Lock_Seed (Ns_256, Ls_128);
         raise Program_Error with "width-mismatch attach must raise";
      exception
         when E : Itb.Errors.Itb_Error =>
            if Itb.Errors.Status_Code (E) /= Itb.Status.Seed_Width_Mix then
               raise;
            end if;
      end;
   end;

   ------------------------------------------------------------------
   --  test_post_encrypt_attach_rejected
   ------------------------------------------------------------------
   Engage_Lock_Soup;
   declare
      Ns  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Ds  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Ss  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Ls  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
   begin
      Itb.Seed.Attach_Lock_Seed (Ns, Ls);
      declare
         Ct : constant Byte_Array :=
           Itb.Cipher.Encrypt (Ns, Ds, Ss, To_Bytes ("pre-switch"));
         pragma Unreferenced (Ct);
      begin
         null;
      end;
      declare
         Ls2 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      begin
         begin
            Itb.Seed.Attach_Lock_Seed (Ns, Ls2);
            raise Program_Error
              with "post-encrypt switching must raise";
         exception
            when E : Itb.Errors.Itb_Error =>
               if Itb.Errors.Status_Code (E) /= Itb.Status.Bad_Input then
                  raise;
               end if;
         end;
      end;
   end;
   Disengage_Lock_Soup;

   ------------------------------------------------------------------
   --  test_overlay_off_panics_on_encrypt
   ------------------------------------------------------------------
   Itb.Set_Bit_Soup (0);
   Itb.Set_Lock_Soup (0);
   declare
      Ns  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Ds  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Ss  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Ls  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
   begin
      Itb.Seed.Attach_Lock_Seed (Ns, Ls);
      begin
         declare
            Ct : constant Byte_Array :=
              Itb.Cipher.Encrypt (Ns, Ds, Ss,
                                   To_Bytes ("overlay off should fail"));
            pragma Unreferenced (Ct);
         begin
            raise Program_Error
              with "encrypt with attach + overlay off must raise";
         end;
      exception
         when Itb.Errors.Itb_Error =>
            null;
      end;
   end;

   --  Restore the originals.
   Itb.Set_Bit_Soup (Saved_Bit_Soup);
   Itb.Set_Lock_Soup (Saved_Lock_Soup);
   Ada.Text_IO.Put_Line ("test_attach_lock_seed: PASS");

exception
   when others =>
      begin
         Itb.Set_Bit_Soup (Saved_Bit_Soup);
         Itb.Set_Lock_Soup (Saved_Lock_Soup);
      exception
         when others =>
            null;
      end;
      raise;
end Test_Attach_Lock_Seed;
