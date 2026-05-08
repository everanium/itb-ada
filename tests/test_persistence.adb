--  Cross-process persistence round-trip tests.
--
--  Mirrors bindings/rust/tests/test_persistence.rs one-to-one. Exercises
--  the Get_Components / Get_Hash_Key / From_Components surface across
--  every primitive in the registry x the three ITB key-bit widths
--  (512 / 1024 / 2048) that are valid for each native hash width.

with Ada.Streams;  use Ada.Streams;
with Ada.Text_IO;

with Itb;          use Itb;
with Itb.Cipher;
with Itb.Errors;
with Itb.Seed;

procedure Test_Persistence is

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

   --  Maps a primitive name to its expected fixed hash-key length in
   --  bytes. SipHash-2-4 has no internal fixed key.
   function Expected_Hash_Key_Len (Name : String) return Stream_Element_Offset
   is
   begin
      if Name = "areion256" then
         return 32;
      elsif Name = "areion512" then
         return 64;
      elsif Name = "siphash24" then
         return 0;
      elsif Name = "aescmac" then
         return 16;
      elsif Name = "blake2b256" then
         return 32;
      elsif Name = "blake2b512" then
         return 64;
      elsif Name = "blake2s" then
         return 32;
      elsif Name = "blake3" then
         return 32;
      elsif Name = "chacha20" then
         return 32;
      else
         raise Program_Error with "unexpected primitive " & Name;
      end if;
   end Expected_Hash_Key_Len;

   --  The three ITB key-bit widths valid for a given native hash width
   --  (key_bits must be a multiple of width).
   type Key_Bit_Set is array (Positive range <>) of Integer;

   function Build_Plaintext return Byte_Array is
      Tag : constant String := "any binary data, including 0x00 bytes -- ";
      Result : Byte_Array
        (1 .. Stream_Element_Offset (Tag'Length) + 256);
   begin
      for I in Tag'Range loop
         Result (Stream_Element_Offset (I - Tag'First + 1)) :=
           Stream_Element (Character'Pos (Tag (I)));
      end loop;
      for I in 0 .. 255 loop
         Result (Stream_Element_Offset (Tag'Length + I + 1)) :=
           Stream_Element (I);
      end loop;
      return Result;
   end Build_Plaintext;

begin

   ------------------------------------------------------------------
   --  test_roundtrip_all_hashes
   ------------------------------------------------------------------
   declare
      Plaintext : constant Byte_Array := Build_Plaintext;
   begin
      for HE of Canonical_Hashes loop
         for KB of Key_Bit_Set'[512, 1024, 2048] loop
            if KB mod HE.Width = 0 then
               declare
                  --  Day 1: random seeds.
                  Ns : constant Itb.Seed.Seed :=
                    Itb.Seed.Make (HE.Name.all, KB);
                  Ds : constant Itb.Seed.Seed :=
                    Itb.Seed.Make (HE.Name.all, KB);
                  Ss : constant Itb.Seed.Seed :=
                    Itb.Seed.Make (HE.Name.all, KB);
                  Ns_C : constant Component_Array :=
                    Itb.Seed.Get_Components (Ns);
                  Ds_C : constant Component_Array :=
                    Itb.Seed.Get_Components (Ds);
                  Ss_C : constant Component_Array :=
                    Itb.Seed.Get_Components (Ss);
                  Ns_K : constant Byte_Array :=
                    Itb.Seed.Get_Hash_Key (Ns);
                  Ds_K : constant Byte_Array :=
                    Itb.Seed.Get_Hash_Key (Ds);
                  Ss_K : constant Byte_Array :=
                    Itb.Seed.Get_Hash_Key (Ss);
                  Ct   : constant Byte_Array :=
                    Itb.Cipher.Encrypt (Ns, Ds, Ss, Plaintext);
                  --  Day 2: rebuild from saved material.
                  Ns2  : constant Itb.Seed.Seed :=
                    Itb.Seed.From_Components (HE.Name.all, Ns_C, Ns_K);
                  Ds2  : constant Itb.Seed.Seed :=
                    Itb.Seed.From_Components (HE.Name.all, Ds_C, Ds_K);
                  Ss2  : constant Itb.Seed.Seed :=
                    Itb.Seed.From_Components (HE.Name.all, Ss_C, Ss_K);
                  Decoded : constant Byte_Array :=
                    Itb.Cipher.Decrypt (Ns2, Ds2, Ss2, Ct);
               begin
                  if Stream_Element_Offset (Ns_C'Length) * 64
                     /= Stream_Element_Offset (KB)
                  then
                     raise Program_Error
                       with "components count mismatch hash="
                         & HE.Name.all & " bits=" & KB'Image;
                  end if;
                  if Ns_K'Length /= Expected_Hash_Key_Len (HE.Name.all) then
                     raise Program_Error
                       with "hash_key length mismatch hash="
                         & HE.Name.all & " got=" & Ns_K'Length'Image;
                  end if;
                  if Decoded /= Plaintext then
                     raise Program_Error
                       with "rebuild round-trip mismatch hash="
                         & HE.Name.all & " bits=" & KB'Image;
                  end if;
                  if Itb.Seed.Get_Components (Ns2) /= Ns_C then
                     raise Program_Error
                       with "rebuilt components mismatch hash="
                         & HE.Name.all;
                  end if;
                  if Itb.Seed.Get_Hash_Key (Ns2) /= Ns_K then
                     raise Program_Error
                       with "rebuilt hash_key mismatch hash="
                         & HE.Name.all;
                  end if;
               end;
            end if;
         end loop;
      end loop;
   end;

   ------------------------------------------------------------------
   --  test_random_key_path — 512-bit zero components are sufficient
   --  for non-SipHash primitives; an empty Hash_Key parameter requests
   --  a CSPRNG-generated internal key.
   ------------------------------------------------------------------
   declare
      Zero_Comps : constant Component_Array := [1 .. 8 => 0];
      Empty_Key  : constant Byte_Array := [1 .. 0 => 0];
   begin
      for HE of Canonical_Hashes loop
         declare
            Seed : constant Itb.Seed.Seed :=
              Itb.Seed.From_Components (HE.Name.all, Zero_Comps, Empty_Key);
            Key  : constant Byte_Array := Itb.Seed.Get_Hash_Key (Seed);
         begin
            if HE.Name.all = "siphash24" then
               if Key'Length /= 0 then
                  raise Program_Error
                    with "siphash24 must report empty key, got"
                       & Key'Length'Image;
               end if;
            else
               if Key'Length /= Expected_Hash_Key_Len (HE.Name.all) then
                  raise Program_Error
                    with "primitive=" & HE.Name.all
                       & " key_len=" & Key'Length'Image;
               end if;
            end if;
         end;
      end loop;
   end;

   ------------------------------------------------------------------
   --  test_explicit_key_preserved — BLAKE3 has a 32-byte symmetric
   --  key.
   ------------------------------------------------------------------
   declare
      Explicit : Byte_Array (1 .. 32);
      Comps    : constant Component_Array :=
        [1 .. 8 => 16#CAFEBABE_DEADBEEF#];
   begin
      for I in Explicit'Range loop
         Explicit (I) := Stream_Element (I - 1);
      end loop;
      declare
         Seed : constant Itb.Seed.Seed :=
           Itb.Seed.From_Components ("blake3", Comps, Explicit);
      begin
         if Itb.Seed.Get_Hash_Key (Seed) /= Explicit then
            raise Program_Error with "BLAKE3 explicit key not preserved";
         end if;
      end;
   end;

   ------------------------------------------------------------------
   --  test_bad_key_size — non-empty hash_key whose length does not
   --  match must raise Itb_Error (no panic across FFI). 7 bytes is
   --  wrong for blake3 (expects 32).
   ------------------------------------------------------------------
   declare
      Comps : constant Component_Array := [1 .. 16 => 0];
      Bad   : constant Byte_Array := [1 .. 7 => 0];
   begin
      begin
         declare
            Seed : constant Itb.Seed.Seed :=
              Itb.Seed.From_Components ("blake3", Comps, Bad);
            pragma Unreferenced (Seed);
         begin
            raise Program_Error
              with "From_Components(blake3, 7-byte key) must raise";
         end;
      exception
         when Itb.Errors.Itb_Error =>
            null;
      end;
   end;

   ------------------------------------------------------------------
   --  test_siphash_rejects_hash_key — siphash24 takes no internal
   --  fixed key; passing a non-empty key must be rejected.
   ------------------------------------------------------------------
   declare
      Comps   : constant Component_Array := [1 .. 8 => 0];
      Nonzero : constant Byte_Array := [1 .. 16 => 0];
   begin
      begin
         declare
            Seed : constant Itb.Seed.Seed :=
              Itb.Seed.From_Components ("siphash24", Comps, Nonzero);
            pragma Unreferenced (Seed);
         begin
            raise Program_Error
              with "From_Components(siphash24, 16-byte key) must raise";
         end;
      exception
         when Itb.Errors.Itb_Error =>
            null;
      end;
   end;

   Ada.Text_IO.Put_Line ("test_persistence: PASS");

end Test_Persistence;
