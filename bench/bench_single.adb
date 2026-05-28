--  Easy Mode Single-Ouroboros benchmarks for the Ada binding.
--
--  Mirrors the BenchmarkSingle* cohort from itb_ext_test.go for
--  PRF-grade primitives, locked at 1024-bit ITB key width and 16
--  MiB CSPRNG-flavoured payload. One mixed-primitive variant
--  (Itb.Encryptor.Mixed_Single + dedicated lockSeed) covers the
--  Easy Mode Mixed surface alongside the single-primitive grid.
--
--  Run with::
--
--      gprbuild -P itb_bench.gpr
--      ./obj-bench/bench_single
--      ITB_NONCE_BITS=512 ITB_LOCKSEED=1 ITB_LOCKBATCH=1 ./obj-bench/bench_single
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
--  Ada port keeps one encryptor per primitive shape and reuses it across the four ops
--  (encrypt / decrypt / encrypt_auth / decrypt_auth). The cipher
--  methods are stateless w.r.t. per-call carry on Easy Mode (fresh
--  nonce per encrypt), so reusing one encryptor per primitive
--  measures byte-for-byte the same per-call cost as a
--  fresh-encryptor-per-op design. The 40 case names emitted to
--  stdout still mirror the cross-binding canonical naming.
--
--  Lazy layout. The encryptors are still allocated at elaboration
--  (they are small handles). The payload buffers (16 MiB each) are
--  allocated and freed one primitive-shape at a time — four cases per
--  primitive, four payloads live at once — so peak RSS is bounded to
--  roughly 4 x 16 MiB rather than 40 x 16 MiB.

with Ada.Streams;
with Ada.Strings.Fixed;
with Ada.Text_IO;
with Ada.Unchecked_Deallocation;

with Itb;
with Itb.Encryptor;

with Common;

procedure Bench_Single is

   procedure Free_Bytes is new Ada.Unchecked_Deallocation
     (Object => Itb.Byte_Array, Name => Common.Byte_Array_Access);

   --  Canonical primitive PRF-grade order, mirroring bench_single.rs
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
   --  while Areion takes the dedicated lockSeed slot — every
   --  name resolves to a 256-bit native hash width so the
   --  Itb.Encryptor.Mixed_Single width-check passes.
   Mixed_Noise : constant String := "blake3";
   Mixed_Data  : constant String := "blake2s";
   Mixed_Start : constant String := "blake2b256";

   ---------------------------------------------------------------------
   --  Encryptor pool — one per primitive shape.
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

   --  Case names only (no payloads yet). Indexed parallel to
   --  Encryptors / Encryptor_Tags: row I covers cases (4*I-3) .. 4*I.
   type Op_Name_Quad is array (1 .. 4) of Common.String_Access;
   type Name_Table   is array (1 .. 10) of Op_Name_Quad;

   Nonce_Bits : constant Integer := Common.Env_Nonce_Bits (128);

   --  Build the 40 case names (no allocs beyond the name strings).
   function Build_Name_Table return Name_Table is
      T   : Name_Table;
      Kb  : constant String :=
        Ada.Strings.Fixed.Trim
          (Integer'Image (Common.Key_Bits), Ada.Strings.Both);
   begin
      for I in 1 .. 10 loop
         declare
            Base : constant String :=
              "bench_single_" & Encryptor_Tags (I).all & "_" & Kb & "bit";
         begin
            T (I) (1) := new String'(Base & "_encrypt_16mb");
            T (I) (2) := new String'(Base & "_decrypt_16mb");
            T (I) (3) := new String'(Base & "_encrypt_auth_16mb");
            T (I) (4) := new String'(Base & "_decrypt_auth_16mb");
         end;
      end loop;
      return T;
   end Build_Name_Table;

   Names : constant Name_Table := Build_Name_Table;

   --  True when name passes the optional ITB_BENCH_FILTER substring test.
   function Passes_Filter (Name : String) return Boolean is
      Filter_On : constant Boolean := Common.Env_Filter_Set;
      Filter    : constant String  := Common.Env_Filter;
   begin
      if not Filter_On then
         return True;
      end if;
      --  Substring containment.
      if Filter'Length = 0 then
         return True;
      end if;
      if Name'Length < Filter'Length then
         return False;
      end if;
      for I in Name'First .. Name'Last - Filter'Length + 1 loop
         if Name (I .. I + Filter'Length - 1) = Filter then
            return True;
         end if;
      end loop;
      return False;
   end Passes_Filter;

   --  Count how many of the 40 cases pass the filter.
   function Count_Selected return Natural is
      N : Natural := 0;
   begin
      for I in 1 .. 10 loop
         for J in 1 .. 4 loop
            if Passes_Filter (Names (I) (J).all) then
               N := N + 1;
            end if;
         end loop;
      end loop;
      return N;
   end Count_Selected;

   --  Run one primitive's four cases: allocate payloads, build and
   --  measure each selected case, then free the payloads.
   procedure Run_Primitive_Cases
     (Enc         : Common.Encryptor_Access;
      Case_Names  : Op_Name_Quad;
      Min_Seconds : Float)
   is
      --  Allocate four independent payloads — one per op — so that the
      --  decrypt-side pre-encryption does not share state with the
      --  encrypt-side payload.
      P_E : Common.Byte_Array_Access :=
        new Itb.Byte_Array'(Common.Random_Bytes (Common.Payload_16MB));
      P_D : Common.Byte_Array_Access :=
        new Itb.Byte_Array'(Common.Random_Bytes (Common.Payload_16MB));
      P_A : Common.Byte_Array_Access :=
        new Itb.Byte_Array'(Common.Random_Bytes (Common.Payload_16MB));
      P_R : Common.Byte_Array_Access :=
        new Itb.Byte_Array'(Common.Random_Bytes (Common.Payload_16MB));
      C_D : Common.Byte_Array_Access :=
        new Itb.Byte_Array'(Itb.Encryptor.Encrypt (Enc.all, P_D.all));
      C_R : Common.Byte_Array_Access :=
        new Itb.Byte_Array'
              (Itb.Encryptor.Encrypt_Auth (Enc.all, P_R.all));

      Ops : constant array (1 .. 4) of Common.Bench_Case :=
        [(Name          => Case_Names (1),
          Enc           => Enc,
          Payload       => P_E,
          Cipher        => null,
          Op            => Common.Op_Encrypt,
          Payload_Bytes => Common.Payload_16MB),
         (Name          => Case_Names (2),
          Enc           => Enc,
          Payload       => P_D,
          Cipher        => C_D,
          Op            => Common.Op_Decrypt,
          Payload_Bytes => Common.Payload_16MB),
         (Name          => Case_Names (3),
          Enc           => Enc,
          Payload       => P_A,
          Cipher        => null,
          Op            => Common.Op_Encrypt_Auth,
          Payload_Bytes => Common.Payload_16MB),
         (Name          => Case_Names (4),
          Enc           => Enc,
          Payload       => P_R,
          Cipher        => C_R,
          Op            => Common.Op_Decrypt_Auth,
          Payload_Bytes => Common.Payload_16MB)];
   begin
      for K in Ops'Range loop
         if Passes_Filter (Ops (K).Name.all) then
            Common.Measure_One (Ops (K), Min_Seconds);
         end if;
      end loop;
      --  Free all payload / ciphertext buffers for this primitive
      --  before advancing to the next.
      Free_Bytes (P_E);
      Free_Bytes (P_D);
      Free_Bytes (P_A);
      Free_Bytes (P_R);
      Free_Bytes (C_D);
      Free_Bytes (C_R);
   end Run_Primitive_Cases;

   Selected    : constant Natural := Count_Selected;
   Min_Seconds : constant Float   := Common.Env_Min_Seconds;

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

      --  ITB_LOCKBATCH layers the Lock Batch performance mode on top;
      --  inert unless Lock Soup is engaged via the lockSeed flag above.
      Common.Apply_Lock_Batch_If_Requested (Enc_Areion256);
      Common.Apply_Lock_Batch_If_Requested (Enc_Areion512);
      Common.Apply_Lock_Batch_If_Requested (Enc_Blake2b256);
      Common.Apply_Lock_Batch_If_Requested (Enc_Blake2b512);
      Common.Apply_Lock_Batch_If_Requested (Enc_Blake2s);
      Common.Apply_Lock_Batch_If_Requested (Enc_Blake3);
      Common.Apply_Lock_Batch_If_Requested (Enc_Aescmac);
      Common.Apply_Lock_Batch_If_Requested (Enc_Siphash24);
      Common.Apply_Lock_Batch_If_Requested (Enc_Chacha20);
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

   if Selected = 0 then
      Ada.Text_IO.Put_Line
        (Ada.Text_IO.Standard_Error,
         "no bench cases match filter """ & Common.Env_Filter & """");
      return;
   end if;

   declare
      Min_S_Img : constant String :=
        Ada.Strings.Fixed.Trim
          (Integer'Image (Integer (Min_Seconds)), Ada.Strings.Both);
      Sel_Img   : constant String :=
        Ada.Strings.Fixed.Trim
          (Natural'Image (Selected), Ada.Strings.Both);
      Pay_Img   : constant String :=
        Ada.Strings.Fixed.Trim
          (Ada.Streams.Stream_Element_Offset'Image (Common.Payload_16MB),
           Ada.Strings.Both);
   begin
      Ada.Text_IO.Put_Line
        ("# benchmarks=" & Sel_Img
         & " payload_bytes=" & Pay_Img
         & " min_seconds=" & Min_S_Img);
   end;

   --  Lazy primitive-major loop: allocate / measure / free four payloads
   --  per encryptor rather than 40 upfront.
   for I in Encryptors'Range loop
      Run_Primitive_Cases (Encryptors (I), Names (I), Min_Seconds);
   end loop;
end Bench_Single;
