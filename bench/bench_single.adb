--  Easy Mode Single-Ouroboros benchmarks for the Ada binding.
--
--  Mirrors the BenchmarkSingle* cohort from itb_ext_test.go for the
--  nine PRF-grade primitives, locked at 1024-bit ITB key width and 16
--  MiB CSPRNG-flavoured payload. One mixed-primitive variant
--  (Itb.Encryptor.Mixed_Single with BLAKE3 / BLAKE2s / BLAKE2b-256 +
--  Areion-SoEM-256 dedicated lockSeed) covers the Easy Mode Mixed
--  surface alongside the single-primitive grid.
--
--  Run with::
--
--      gprbuild -P itb_bench.gpr
--      ./obj-bench/bench_single
--      ITB_NONCE_BITS=512 ITB_LOCKSEED=1 ./obj-bench/bench_single
--      ITB_BENCH_FILTER=blake3_encrypt ./obj-bench/bench_single
--
--  The harness emits one Go-bench-style line per case (name, iters,
--  ns/op, MB/s). See bench/common.ads for the supported environment
--  variables and the convergence policy.
--
--  Limited-type design note. Itb.Encryptor.Encryptor is a
--  Limited_Controlled type; Ada cannot copy / aggregate / array-store
--  it. The Rust / C# / Node.js sources keep one freshly-constructed
--  encryptor per (primitive, op) tuple — 40 encryptors total. This
--  Ada port keeps one encryptor per primitive shape (10 total —
--  9 single-primitive + 1 mixed) and reuses it across the four ops
--  (encrypt / decrypt / encrypt_auth / decrypt_auth). The cipher
--  methods are stateless w.r.t. per-call carry on Easy Mode (fresh
--  nonce per encrypt), so reusing one encryptor per primitive
--  measures byte-for-byte the same per-call cost as a
--  fresh-encryptor-per-op design. The 40 case names emitted to
--  stdout still mirror the cross-binding canonical naming.

with Ada.Strings.Fixed;
with Ada.Text_IO;

with Itb;
with Itb.Encryptor;

with Common;

procedure Bench_Single is

   --  Canonical 9-primitive PRF-grade order, mirroring bench_single.rs
   --  / bench_single.cs / bench-single.ts. The three below-spec lab
   --  primitives (CRC128, FNV-1a, MD5) are not exposed through the
   --  libitb registry and are therefore absent here by construction.
   Areion256_Name  : aliased constant String := "areion256";
   Areion512_Name  : aliased constant String := "areion512";
   Blake2b256_Name : aliased constant String := "blake2b256";
   Blake2b512_Name : aliased constant String := "blake2b512";
   Blake2s_Name    : aliased constant String := "blake2s";
   Blake3_Name     : aliased constant String := "blake3";
   Aescmac_Name    : aliased constant String := "aescmac";
   Siphash24_Name  : aliased constant String := "siphash24";
   Chacha20_Name   : aliased constant String := "chacha20";

   type Primitive_Name_Array is
     array (Positive range <>) of access constant String;
   Primitives_Canonical : constant Primitive_Name_Array :=
     [Areion256_Name'Access,
      Areion512_Name'Access,
      Blake2b256_Name'Access,
      Blake2b512_Name'Access,
      Blake2s_Name'Access,
      Blake3_Name'Access,
      Aescmac_Name'Access,
      Siphash24_Name'Access,
      Chacha20_Name'Access];

   --  Mixed-primitive composition used by the bench_single_mixed_*
   --  cases. Noise / data / start cycle through the BLAKE family
   --  while Areion-SoEM-256 takes the dedicated lockSeed slot — every
   --  name resolves to a 256-bit native hash width so the
   --  Itb.Encryptor.Mixed_Single width-check passes.
   Mixed_Noise : constant String := "blake3";
   Mixed_Data  : constant String := "blake2s";
   Mixed_Start : constant String := "blake2b256";

   ---------------------------------------------------------------------
   --  Encryptor pool — 10 encryptors total, one per primitive shape.
   --  Each encryptor's lifetime spans the whole bench run; the
   --  finalizer releases the libitb handle at scope exit when main
   --  returns.
   ---------------------------------------------------------------------

   --  Captured once at elaboration so the Mixed_Single Prim_L slot
   --  resolves consistently with the per-encryptor Set_Lock_Seed
   --  application below.
   Mixed_Lock_Active : constant Boolean := Common.Env_Lock_Seed;

   Enc_Areion256 : aliased Itb.Encryptor.Encryptor :=
     Itb.Encryptor.Make
       (Primitive => Areion256_Name,
        Key_Bits  => Common.Key_Bits,
        Mac_Name  => Common.Mac_Name,
        Mode      => 1);
   Enc_Areion512 : aliased Itb.Encryptor.Encryptor :=
     Itb.Encryptor.Make
       (Primitive => Areion512_Name,
        Key_Bits  => Common.Key_Bits,
        Mac_Name  => Common.Mac_Name,
        Mode      => 1);
   Enc_Blake2b256 : aliased Itb.Encryptor.Encryptor :=
     Itb.Encryptor.Make
       (Primitive => Blake2b256_Name,
        Key_Bits  => Common.Key_Bits,
        Mac_Name  => Common.Mac_Name,
        Mode      => 1);
   Enc_Blake2b512 : aliased Itb.Encryptor.Encryptor :=
     Itb.Encryptor.Make
       (Primitive => Blake2b512_Name,
        Key_Bits  => Common.Key_Bits,
        Mac_Name  => Common.Mac_Name,
        Mode      => 1);
   Enc_Blake2s : aliased Itb.Encryptor.Encryptor :=
     Itb.Encryptor.Make
       (Primitive => Blake2s_Name,
        Key_Bits  => Common.Key_Bits,
        Mac_Name  => Common.Mac_Name,
        Mode      => 1);
   Enc_Blake3 : aliased Itb.Encryptor.Encryptor :=
     Itb.Encryptor.Make
       (Primitive => Blake3_Name,
        Key_Bits  => Common.Key_Bits,
        Mac_Name  => Common.Mac_Name,
        Mode      => 1);
   Enc_Aescmac : aliased Itb.Encryptor.Encryptor :=
     Itb.Encryptor.Make
       (Primitive => Aescmac_Name,
        Key_Bits  => Common.Key_Bits,
        Mac_Name  => Common.Mac_Name,
        Mode      => 1);
   Enc_Siphash24 : aliased Itb.Encryptor.Encryptor :=
     Itb.Encryptor.Make
       (Primitive => Siphash24_Name,
        Key_Bits  => Common.Key_Bits,
        Mac_Name  => Common.Mac_Name,
        Mode      => 1);
   Enc_Chacha20 : aliased Itb.Encryptor.Encryptor :=
     Itb.Encryptor.Make
       (Primitive => Chacha20_Name,
        Key_Bits  => Common.Key_Bits,
        Mac_Name  => Common.Mac_Name,
        Mode      => 1);
   Enc_Mixed : aliased Itb.Encryptor.Encryptor :=
     Itb.Encryptor.Mixed_Single
       (Prim_N   => Mixed_Noise,
        Prim_D   => Mixed_Data,
        Prim_S   => Mixed_Start,
        Prim_L   =>
          (if Mixed_Lock_Active then Common.Mixed_Lock else ""),
        Key_Bits => Common.Key_Bits,
        Mac_Name => Common.Mac_Name);

   --  'Unchecked_Access is used because the encryptors are declared
   --  inside Bench_Single's body (deeper accessibility level than
   --  Common.Encryptor_Access, which is package-level). Per
   --  RM 13.10, 'Unchecked_Access is well-defined here — the
   --  encryptors live as long as Bench_Single's body, which is the
   --  entire process; no dangling-pointer hazard.
   Encryptors : constant array (1 .. 10) of Common.Encryptor_Access :=
     [Enc_Areion256'Unchecked_Access,
      Enc_Areion512'Unchecked_Access,
      Enc_Blake2b256'Unchecked_Access,
      Enc_Blake2b512'Unchecked_Access,
      Enc_Blake2s'Unchecked_Access,
      Enc_Blake3'Unchecked_Access,
      Enc_Aescmac'Unchecked_Access,
      Enc_Siphash24'Unchecked_Access,
      Enc_Chacha20'Unchecked_Access,
      Enc_Mixed'Unchecked_Access];

   Mixed_Name : aliased constant String := "mixed";
   Encryptor_Tags : constant Primitive_Name_Array :=
     [Areion256_Name'Access,
      Areion512_Name'Access,
      Blake2b256_Name'Access,
      Blake2b512_Name'Access,
      Blake2s_Name'Access,
      Blake3_Name'Access,
      Aescmac_Name'Access,
      Siphash24_Name'Access,
      Chacha20_Name'Access,
      Mixed_Name'Access];

   Cases : Common.Bench_Case_Array (1 .. 40);

   Nonce_Bits : constant Integer := Common.Env_Nonce_Bits (128);

   procedure Populate_Cases is
      Kb_Img : constant String :=
        Ada.Strings.Fixed.Trim
          (Integer'Image (Common.Key_Bits), Ada.Strings.Both);
      Slot   : Positive := 1;
   begin
      for I in Encryptors'Range loop
         declare
            Tag  : constant String := Encryptor_Tags (I).all;
            Enc  : constant Common.Encryptor_Access := Encryptors (I);
            Base : constant String :=
              "bench_single_" & Tag & "_" & Kb_Img & "bit";
            P_E : constant Common.Byte_Array_Access :=
              new Itb.Byte_Array'(Common.Random_Bytes (Common.Payload_16MB));
            P_D : constant Common.Byte_Array_Access :=
              new Itb.Byte_Array'(Common.Random_Bytes (Common.Payload_16MB));
            P_A : constant Common.Byte_Array_Access :=
              new Itb.Byte_Array'(Common.Random_Bytes (Common.Payload_16MB));
            P_R : constant Common.Byte_Array_Access :=
              new Itb.Byte_Array'(Common.Random_Bytes (Common.Payload_16MB));
            C_D : constant Common.Byte_Array_Access :=
              new Itb.Byte_Array'(Itb.Encryptor.Encrypt (Enc.all, P_D.all));
            C_R : constant Common.Byte_Array_Access :=
              new Itb.Byte_Array'
                    (Itb.Encryptor.Encrypt_Auth (Enc.all, P_R.all));
         begin
            Cases (Slot) :=
              (Name          => new String'(Base & "_encrypt_16mb"),
               Enc           => Enc,
               Payload       => P_E,
               Cipher        => null,
               Op            => Common.Op_Encrypt,
               Payload_Bytes => Common.Payload_16MB);
            Slot := Slot + 1;
            Cases (Slot) :=
              (Name          => new String'(Base & "_decrypt_16mb"),
               Enc           => Enc,
               Payload       => P_D,
               Cipher        => C_D,
               Op            => Common.Op_Decrypt,
               Payload_Bytes => Common.Payload_16MB);
            Slot := Slot + 1;
            Cases (Slot) :=
              (Name          => new String'(Base & "_encrypt_auth_16mb"),
               Enc           => Enc,
               Payload       => P_A,
               Cipher        => null,
               Op            => Common.Op_Encrypt_Auth,
               Payload_Bytes => Common.Payload_16MB);
            Slot := Slot + 1;
            Cases (Slot) :=
              (Name          => new String'(Base & "_decrypt_auth_16mb"),
               Enc           => Enc,
               Payload       => P_R,
               Cipher        => C_R,
               Op            => Common.Op_Decrypt_Auth,
               Payload_Bytes => Common.Payload_16MB);
            Slot := Slot + 1;
         end;
      end loop;
   end Populate_Cases;

begin
   Itb.Set_Max_Workers (0);
   Itb.Set_Nonce_Bits (Nonce_Bits);
   if Mixed_Lock_Active then
      Itb.Set_Lock_Soup (1);
   end if;

   --  Apply Set_Lock_Seed across every single-primitive encryptor.
   --  Mixed_Single picks Prim_L up at construction so the lockSeed
   --  slot is already active there; an extra Set_Lock_Seed call would
   --  be a redundant no-op.
   if Mixed_Lock_Active then
      Common.Apply_Lock_Seed_If_Requested (Enc_Areion256);
      Common.Apply_Lock_Seed_If_Requested (Enc_Areion512);
      Common.Apply_Lock_Seed_If_Requested (Enc_Blake2b256);
      Common.Apply_Lock_Seed_If_Requested (Enc_Blake2b512);
      Common.Apply_Lock_Seed_If_Requested (Enc_Blake2s);
      Common.Apply_Lock_Seed_If_Requested (Enc_Blake3);
      Common.Apply_Lock_Seed_If_Requested (Enc_Aescmac);
      Common.Apply_Lock_Seed_If_Requested (Enc_Siphash24);
      Common.Apply_Lock_Seed_If_Requested (Enc_Chacha20);
   end if;

   declare
      Lockseed_Img : constant String :=
        (if Mixed_Lock_Active then "on" else "off");
      Prims_Img    : constant String :=
        Ada.Strings.Fixed.Trim
          (Integer'Image (Primitives_Canonical'Length), Ada.Strings.Both);
      Kb_Img       : constant String :=
        Ada.Strings.Fixed.Trim
          (Integer'Image (Common.Key_Bits), Ada.Strings.Both);
      Nb_Img       : constant String :=
        Ada.Strings.Fixed.Trim
          (Integer'Image (Nonce_Bits), Ada.Strings.Both);
   begin
      Ada.Text_IO.Put_Line
        ("# easy_single primitives=" & Prims_Img
         & " key_bits=" & Kb_Img
         & " mac=" & Common.Mac_Name
         & " nonce_bits=" & Nb_Img
         & " lockseed=" & Lockseed_Img
         & " workers=auto");
   end;

   Populate_Cases;
   Common.Run_All (Cases);
end Bench_Single;
