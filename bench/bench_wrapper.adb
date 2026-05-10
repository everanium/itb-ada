--  Format-deniability wrapper benchmarks for the Ada binding.
--
--  Mirrors bindings/python/itb/wrapper/benchmarks/bench_wrapper.py +
--  bindings/csharp/Itb.Bench/BenchWrapper.cs +
--  bindings/rust/benches/bench_wrapper.rs.
--
--  Sub-bench inventory (102 cases):
--    * 6   wrapper only round-trip   (Wrap / Wrap_In_Place × 3 ciphers)
--    * 24  Message Single Ouroboros  (4 modes × 3 ciphers × 2 dirs)
--    * 24  Message Triple Ouroboros  (4 modes × 3 ciphers × 2 dirs)
--    * 24  Streaming Single Ouroboros (4 modes × 3 ciphers × 2 dirs,
--          excludes noaead-*-io: Ada has no IO-Driven Non-AEAD wrap
--          surface — only User-Driven Loop on the no-MAC arm)
--    * 24  Streaming Triple Ouroboros
--
--  Modes covered (consistent with the eitb 8-example matrix):
--    Single Message: easy-nomac, easy-auth, lowlevel-nomac, lowlevel-auth
--    Streaming     : aead-easy-io, aead-lowlevel-io,
--                    noaead-easy-userloop, noaead-lowlevel-userloop
--
--  Output mirrors Common's Go-bench-style line per case. Run with:
--
--      gprbuild -P itb_bench.gpr
--      ./obj-bench/bench_wrapper
--      ITB_BENCH_MIN_SEC=5 ./obj-bench/bench_wrapper
--
--  Bench harness reuses the small Run_Once_Proc + Measure pattern
--  copied from bench/bench_stream.adb so this case can dispatch
--  directly into the per-case body without going through the
--  Common.Bench_Op enum (which has only the four Single Message ops).

with Ada.Calendar;
with Ada.Environment_Variables;
with Ada.Real_Time;
with Ada.Streams;             use Ada.Streams;
with Ada.Strings.Fixed;
with Ada.Text_IO;
with Ada.Unchecked_Deallocation;

with Interfaces;              use Interfaces;

with Itb;                     use Itb;
with Itb.Cipher;
with Itb.Encryptor;
with Itb.MAC;
with Itb.Seed;
with Itb.Streams;
with Itb.Wrapper;

procedure Bench_Wrapper is

   ---------------------------------------------------------------------
   --  Configuration constants (lock-step with the Go / Python / C# /
   --  Rust / Node bench harnesses).
   ---------------------------------------------------------------------

   Stream_Primitive : constant String := "areion512";
   Mac_Name         : constant String := "hmac-blake3";
   Key_Bits         : constant Integer := 1024;

   Single_Message_Bytes : constant Stream_Element_Offset :=
     Stream_Element_Offset (16 * 1024 * 1024);
   Stream_Payload_Bytes : constant Stream_Element_Offset :=
     Stream_Element_Offset (64 * 1024 * 1024);
   Stream_Chunk_Size    : constant Stream_Element_Offset :=
     Stream_Element_Offset (16 * 1024 * 1024);
   Wrapper_Only_Bytes   : constant Stream_Element_Offset :=
     Stream_Element_Offset (16 * 1024 * 1024);

   --  Ciphers iterated by every per-cipher case below.
   subtype Outer_Cipher is Itb.Wrapper.Cipher_Type;

   ---------------------------------------------------------------------
   --  Heap-resident byte buffer with grow-on-demand, identical to
   --  bench_stream.adb's Memory_Stream — duplicated here so this
   --  bench can stand on its own without modifying Common.
   ---------------------------------------------------------------------

   type Byte_Buf_Access is access Byte_Array;
   procedure Free_Buf is new Ada.Unchecked_Deallocation
     (Object => Byte_Array, Name => Byte_Buf_Access);

   type Memory_Stream is new Root_Stream_Type with record
      Buf  : Byte_Buf_Access := null;
      Used : Stream_Element_Offset := 0;
      Pos  : Stream_Element_Offset := 1;
   end record;

   overriding procedure Read
     (Self : in out Memory_Stream;
      Item : out Stream_Element_Array;
      Last : out Stream_Element_Offset);

   overriding procedure Write
     (Self : in out Memory_Stream;
      Item : Stream_Element_Array);

   procedure Ensure_Cap
     (Self : in out Memory_Stream'Class; Need : Stream_Element_Offset);

   procedure Free (S : in out Memory_Stream'Class);

   procedure Reset_Read (S : in out Memory_Stream'Class);

   overriding procedure Read
     (Self : in out Memory_Stream;
      Item : out Stream_Element_Array;
      Last : out Stream_Element_Offset)
   is
      Avail : Stream_Element_Offset;
   begin
      if Self.Buf = null or else Self.Pos > Self.Used then
         Last := Item'First - 1;
         return;
      end if;
      Avail := Self.Used - Self.Pos + 1;
      if Avail >= Item'Length then
         Item := Self.Buf (Self.Pos .. Self.Pos + Item'Length - 1);
         Self.Pos := Self.Pos + Item'Length;
         Last := Item'Last;
      else
         Item (Item'First .. Item'First + Avail - 1) :=
           Self.Buf (Self.Pos .. Self.Used);
         Self.Pos := Self.Used + 1;
         Last := Item'First + Avail - 1;
      end if;
   end Read;

   procedure Ensure_Cap
     (Self : in out Memory_Stream'Class; Need : Stream_Element_Offset)
   is
      New_Cap : Stream_Element_Offset;
      New_Buf : Byte_Buf_Access;
   begin
      if Self.Buf = null then
         New_Cap := Stream_Element_Offset'Max (Need, 4096);
         Self.Buf := new Byte_Array (1 .. New_Cap);
         return;
      end if;
      if Need <= Self.Buf'Last then
         return;
      end if;
      New_Cap := Self.Buf'Last;
      while New_Cap < Need loop
         New_Cap := New_Cap * 2;
      end loop;
      New_Buf := new Byte_Array (1 .. New_Cap);
      New_Buf (1 .. Self.Used) := Self.Buf (1 .. Self.Used);
      Free_Buf (Self.Buf);
      Self.Buf := New_Buf;
   end Ensure_Cap;

   overriding procedure Write
     (Self : in out Memory_Stream;
      Item : Stream_Element_Array) is
   begin
      Ensure_Cap (Self, Self.Used + Item'Length);
      Self.Buf (Self.Used + 1 .. Self.Used + Item'Length) := Item;
      Self.Used := Self.Used + Item'Length;
   end Write;

   procedure Free (S : in out Memory_Stream'Class) is
   begin
      if S.Buf /= null then
         Free_Buf (S.Buf);
      end if;
      S.Used := 0;
      S.Pos  := 1;
   end Free;

   procedure Reset_Read (S : in out Memory_Stream'Class) is
   begin
      S.Pos := 1;
   end Reset_Read;

   ---------------------------------------------------------------------
   --  CSPRNG-flavoured payload generator (Calendar-mixed LCG).
   ---------------------------------------------------------------------

   State        : Unsigned_64 := 0;
   State_Seeded : Boolean     := False;

   procedure Seed_State is
   begin
      if not State_Seeded then
         State := Unsigned_64
                    (Ada.Calendar.Seconds (Ada.Calendar.Clock) * 1.0E6)
                  xor 16#CAFE_C0DE_DEC0_DED0#;
         if State = 0 then
            State := 16#DEAD_BEEF_CAFE_F00D#;
         end if;
         State_Seeded := True;
      end if;
   end Seed_State;

   function Random_Bytes
     (N : Stream_Element_Offset) return Byte_Buf_Access
   is
      Out_Buf : constant Byte_Buf_Access :=
        new Byte_Array (1 .. N);
   begin
      Seed_State;
      for I in Out_Buf'Range loop
         State := State * 6364136223846793005 + 1442695040888963407;
         Out_Buf (I) :=
           Stream_Element (Shift_Right (State, 33) and 16#FF#);
      end loop;
      return Out_Buf;
   end Random_Bytes;

   ---------------------------------------------------------------------
   --  Go-bench-style timing harness — duplicates the scaffolding from
   --  bench_stream.adb.
   ---------------------------------------------------------------------

   type Run_Once_Proc is access procedure;

   function Env_Min_Seconds return Float is
      function Env_Get (Name : String) return String is
      begin
         if Ada.Environment_Variables.Exists (Name) then
            return Ada.Environment_Variables.Value (Name);
         else
            return "";
         end if;
      end Env_Get;

      V : constant String := Env_Get ("ITB_BENCH_MIN_SEC");
   begin
      if V = "" then
         return 5.0;
      end if;
      begin
         declare
            F : constant Float := Float'Value (V);
         begin
            if F > 0.0 then
               return F;
            end if;
         end;
      exception
         when others => null;
      end;
      Ada.Text_IO.Put_Line
        (Ada.Text_IO.Standard_Error,
         "ITB_BENCH_MIN_SEC=""" & V
         & """ invalid (expected positive float); using 5.0");
      return 5.0;
   end Env_Min_Seconds;

   Iter_Cap : constant Natural := 16#1000000#;

   function Pad_Right (S : String; W : Positive) return String is
   begin
      if S'Length >= W then
         return S;
      else
         return S & (1 .. W - S'Length => ' ');
      end if;
   end Pad_Right;

   function Pad_Left (S : String; W : Positive) return String is
   begin
      if S'Length >= W then
         return S;
      else
         return (1 .. W - S'Length => ' ') & S;
      end if;
   end Pad_Left;

   function Format_Fixed (X : Long_Float; K : Natural) return String is
      Negative : constant Boolean    := X < 0.0;
      Mag      : constant Long_Float := abs X;
      Scale    : Long_Float := 1.0;
   begin
      for I in 1 .. K loop
         pragma Unreferenced (I);
         Scale := Scale * 10.0;
      end loop;
      declare
         Scaled : constant Long_Float := Mag * Scale + 0.5;
         N      : constant Long_Long_Integer := Long_Long_Integer (Scaled);
         N_Adj  : constant Long_Long_Integer :=
           (if Long_Float (N) > Scaled then N - 1 else N);
         Whole  : constant Long_Long_Integer :=
           N_Adj / Long_Long_Integer (Scale);
         Frac   : constant Long_Long_Integer :=
           N_Adj - Whole * Long_Long_Integer (Scale);
         W_Img  : constant String :=
           Ada.Strings.Fixed.Trim
             (Long_Long_Integer'Image (Whole), Ada.Strings.Both);
         F_Raw  : constant String :=
           Ada.Strings.Fixed.Trim
             (Long_Long_Integer'Image (Frac), Ada.Strings.Both);
         F_Img  : constant String :=
           (1 .. K - F_Raw'Length => '0') & F_Raw;
         Sign   : constant String := (if Negative then "-" else "");
      begin
         if K = 0 then
            return Sign & W_Img;
         end if;
         return Sign & W_Img & "." & F_Img;
      end;
   end Format_Fixed;

   procedure Measure
     (Name        : String;
      Run_Once    : Run_Once_Proc;
      Bytes       : Stream_Element_Offset;
      Min_Seconds : Float)
   is
      use Ada.Real_Time;
      Min_Ns      : constant Float := Min_Seconds * 1.0E9;
      Iters       : Natural := 1;
      Elapsed_Ns  : Float := 0.0;
      T0          : Time;
      Span        : Time_Span;
   begin
      Run_Once.all;
      loop
         T0 := Clock;
         for K in 1 .. Iters loop
            pragma Unreferenced (K);
            Run_Once.all;
         end loop;
         Span := Clock - T0;
         Elapsed_Ns := Float (To_Duration (Span)) * 1.0E9;
         exit when Elapsed_Ns >= Min_Ns;
         exit when Iters >= Iter_Cap;
         Iters := Iters * 2;
      end loop;

      declare
         Ns_Per_Op : constant Float := Elapsed_Ns / Float (Iters);
         MB_Per_S  : constant Float :=
           (if Ns_Per_Op > 0.0
            then (Float (Bytes) / (Ns_Per_Op / 1.0E9)) /
                 Float (1024 * 1024)
            else 0.0);
         Iters_S   : constant String :=
           Ada.Strings.Fixed.Trim (Natural'Image (Iters), Ada.Strings.Both);
      begin
         Ada.Text_IO.Put_Line
           (Pad_Right (Name, 70)
            & ASCII.HT & Pad_Left (Iters_S, 10)
            & ASCII.HT & Pad_Left (Format_Fixed (Long_Float (Ns_Per_Op), 1), 14) & " ns/op"
            & ASCII.HT & Pad_Left (Format_Fixed (Long_Float (MB_Per_S), 2), 9) & " MB/s");
      end;
   end Measure;

   ---------------------------------------------------------------------
   --  Per-cipher resources. One outer key per cipher, reused across
   --  every case bound to that cipher.
   ---------------------------------------------------------------------

   type Key_Slot is record
      Key : Byte_Buf_Access := null;
   end record;

   Cipher_Keys : array (Outer_Cipher) of Key_Slot;

   procedure Build_Cipher_Keys is
   begin
      for C in Outer_Cipher loop
         declare
            K : constant Byte_Array := Itb.Wrapper.Generate_Key (C);
         begin
            Cipher_Keys (C).Key := new Byte_Array'(K);
         end;
      end loop;
   end Build_Cipher_Keys;

   ---------------------------------------------------------------------
   --  Encryptors + Seeds + MAC for the Single + Triple cases.
   ---------------------------------------------------------------------

   Enc_Easy_Single : aliased Itb.Encryptor.Encryptor :=
     Itb.Encryptor.Make
       (Primitive => Stream_Primitive,
        Key_Bits  => Key_Bits,
        Mac_Name  => Mac_Name,
        Mode      => 1);
   Enc_Easy_Triple : aliased Itb.Encryptor.Encryptor :=
     Itb.Encryptor.Make
       (Primitive => Stream_Primitive,
        Key_Bits  => Key_Bits,
        Mac_Name  => Mac_Name,
        Mode      => 3);

   Seed_Noise  : aliased constant Itb.Seed.Seed :=
     Itb.Seed.Make (Stream_Primitive, Key_Bits);
   Seed_Data1  : aliased constant Itb.Seed.Seed :=
     Itb.Seed.Make (Stream_Primitive, Key_Bits);
   Seed_Start1 : aliased constant Itb.Seed.Seed :=
     Itb.Seed.Make (Stream_Primitive, Key_Bits);
   Seed_Data2  : aliased constant Itb.Seed.Seed :=
     Itb.Seed.Make (Stream_Primitive, Key_Bits);
   Seed_Data3  : aliased constant Itb.Seed.Seed :=
     Itb.Seed.Make (Stream_Primitive, Key_Bits);
   Seed_Start2 : aliased constant Itb.Seed.Seed :=
     Itb.Seed.Make (Stream_Primitive, Key_Bits);
   Seed_Start3 : aliased constant Itb.Seed.Seed :=
     Itb.Seed.Make (Stream_Primitive, Key_Bits);

   function Make_MAC_Key return Byte_Array is
      Key : Byte_Array (1 .. 32);
   begin
      for I in Key'Range loop
         State := State * 6364136223846793005 + 1442695040888963407;
         Key (I) :=
           Stream_Element (Shift_Right (State, 33) and 16#FF#);
      end loop;
      return Key;
   end Make_MAC_Key;

   Mac_Handle : constant Itb.MAC.MAC := Itb.MAC.Make (Mac_Name, Make_MAC_Key);

   ---------------------------------------------------------------------
   --  Per-case shared buffers (bench-state globals so the per-case
   --  Run_Once procs can address them through nested-procedure
   --  access).
   ---------------------------------------------------------------------

   --  Wrapper Only payloads.
   Wrap_Plain : Byte_Buf_Access := Random_Bytes (Wrapper_Only_Bytes);

   --  Single Message ITB ciphertexts (computed once per case via the
   --  Pre_Compute step) — one for each of the four single-message
   --  modes × Single / Triple.
   Single_Plain         : Byte_Buf_Access :=
     Random_Bytes (Single_Message_Bytes);
   Single_Easy_Nomac    : Byte_Buf_Access := null;
   Single_Easy_Auth     : Byte_Buf_Access := null;
   Single_Low_Nomac     : Byte_Buf_Access := null;
   Single_Low_Auth      : Byte_Buf_Access := null;
   Triple_Easy_Nomac    : Byte_Buf_Access := null;
   Triple_Easy_Auth     : Byte_Buf_Access := null;
   Triple_Low_Nomac     : Byte_Buf_Access := null;
   Triple_Low_Auth      : Byte_Buf_Access := null;

   --  Streaming payload + AEAD transcripts. Triple variants reuse the
   --  same Stream_Primitive so the encryptors have matching widths.
   Stream_Plain : Byte_Buf_Access := Random_Bytes (Stream_Payload_Bytes);

   --  AEAD transcripts pre-encrypted at startup.
   Tx_Easy_AEAD_Single  : aliased Memory_Stream;
   Tx_Easy_AEAD_Triple  : aliased Memory_Stream;
   Tx_Low_AEAD_Single   : aliased Memory_Stream;
   Tx_Low_AEAD_Triple   : aliased Memory_Stream;

   --  No-MAC user-loop transcripts. Each transcript is the
   --  concatenation of u32_LE_len || ITB_chunk_ct, repeated over the
   --  payload sliced into Stream_Chunk_Size pieces. We materialise
   --  the inner transcript (without wrap) so the bench can also
   --  measure the wrap layer's user-loop encrypt cost on top of
   --  pre-built plain ciphertexts.
   Tx_Easy_UL_Single    : Byte_Buf_Access := null;
   Tx_Easy_UL_Triple    : Byte_Buf_Access := null;
   Tx_Low_UL_Single     : Byte_Buf_Access := null;
   Tx_Low_UL_Triple     : Byte_Buf_Access := null;

   --  Wire-shape buffers used by per-case decrypt iters. Each buffer
   --  is reset to its pristine wrap-encrypted shape via copy from
   --  the corresponding _Tx buffer at the start of every iter.
   Source_Stream : aliased Memory_Stream;
   Sink_Stream   : aliased Memory_Stream;

   ---------------------------------------------------------------------
   --  Pre-encrypt every ITB transcript needed for the bench. Runs
   --  outside any timer.
   ---------------------------------------------------------------------

   --  User-Loop transcript builder. Slices Stream_Plain into
   --  Stream_Chunk_Size pieces, emits each as u32_LE_len || ITB_ct,
   --  and concatenates into a fresh Byte_Buf_Access. The result is
   --  the inner ITB transcript that the wrap layer encrypts.
   function Build_UL_Easy
     (Enc : access Itb.Encryptor.Encryptor) return Byte_Buf_Access
   is
      Buf : Byte_Buf_Access := new Byte_Array (1 .. 4);
      Used : Stream_Element_Offset := 0;
      Cur : Stream_Element_Offset := Stream_Plain'First;
   begin
      Free_Buf (Buf);
      Buf := new Byte_Array (1 .. 1 * 1024 * 1024);
      Used := 0;
      Cur := Stream_Plain.all'First;
      while Cur <= Stream_Plain.all'Last loop
         declare
            Take : constant Stream_Element_Offset :=
              Stream_Element_Offset'Min
                (Stream_Chunk_Size,
                 Stream_Plain.all'Last - Cur + 1);
            Ct : constant Byte_Array :=
              Itb.Encryptor.Encrypt
                (Enc.all,
                 Stream_Plain.all (Cur .. Cur + Take - 1));
            Need : constant Stream_Element_Offset :=
              Used + Stream_Element_Offset (4) + Ct'Length;
            CT_Len_LE : Byte_Array (1 .. 4);
            U32 : constant Unsigned_32 := Unsigned_32 (Ct'Length);
         begin
            CT_Len_LE (1) := Stream_Element (U32 and 16#FF#);
            CT_Len_LE (2) :=
              Stream_Element (Shift_Right (U32, 8) and 16#FF#);
            CT_Len_LE (3) :=
              Stream_Element (Shift_Right (U32, 16) and 16#FF#);
            CT_Len_LE (4) :=
              Stream_Element (Shift_Right (U32, 24) and 16#FF#);
            if Need > Buf'Last then
               declare
                  New_Cap : Stream_Element_Offset := Buf'Last;
                  New_Buf : Byte_Buf_Access;
               begin
                  while New_Cap < Need loop
                     New_Cap := New_Cap * 2;
                  end loop;
                  New_Buf := new Byte_Array (1 .. New_Cap);
                  New_Buf (1 .. Used) := Buf (1 .. Used);
                  Free_Buf (Buf);
                  Buf := New_Buf;
               end;
            end if;
            Buf (Used + 1 .. Used + 4) := CT_Len_LE;
            Used := Used + 4;
            Buf (Used + 1 .. Used + Ct'Length) := Ct;
            Used := Used + Ct'Length;
            Cur := Cur + Take;
         end;
      end loop;
      declare
         Final : constant Byte_Buf_Access :=
           new Byte_Array'(Buf (1 .. Used));
      begin
         Free_Buf (Buf);
         return Final;
      end;
   end Build_UL_Easy;

   --  Low-Level (Cipher.Encrypt) variant of the UL transcript builder.
   function Build_UL_Low_Single return Byte_Buf_Access is
      Buf : Byte_Buf_Access := new Byte_Array (1 .. 1 * 1024 * 1024);
      Used : Stream_Element_Offset := 0;
      Cur : Stream_Element_Offset := Stream_Plain.all'First;
   begin
      while Cur <= Stream_Plain.all'Last loop
         declare
            Take : constant Stream_Element_Offset :=
              Stream_Element_Offset'Min
                (Stream_Chunk_Size,
                 Stream_Plain.all'Last - Cur + 1);
            Ct : constant Byte_Array :=
              Itb.Cipher.Encrypt
                (Seed_Noise, Seed_Data1, Seed_Start1,
                 Stream_Plain.all (Cur .. Cur + Take - 1));
            Need : constant Stream_Element_Offset :=
              Used + Stream_Element_Offset (4) + Ct'Length;
            CT_Len_LE : Byte_Array (1 .. 4);
            U32 : constant Unsigned_32 := Unsigned_32 (Ct'Length);
         begin
            CT_Len_LE (1) := Stream_Element (U32 and 16#FF#);
            CT_Len_LE (2) :=
              Stream_Element (Shift_Right (U32, 8) and 16#FF#);
            CT_Len_LE (3) :=
              Stream_Element (Shift_Right (U32, 16) and 16#FF#);
            CT_Len_LE (4) :=
              Stream_Element (Shift_Right (U32, 24) and 16#FF#);
            if Need > Buf'Last then
               declare
                  New_Cap : Stream_Element_Offset := Buf'Last;
                  New_Buf : Byte_Buf_Access;
               begin
                  while New_Cap < Need loop
                     New_Cap := New_Cap * 2;
                  end loop;
                  New_Buf := new Byte_Array (1 .. New_Cap);
                  New_Buf (1 .. Used) := Buf (1 .. Used);
                  Free_Buf (Buf);
                  Buf := New_Buf;
               end;
            end if;
            Buf (Used + 1 .. Used + 4) := CT_Len_LE;
            Used := Used + 4;
            Buf (Used + 1 .. Used + Ct'Length) := Ct;
            Used := Used + Ct'Length;
            Cur := Cur + Take;
         end;
      end loop;
      declare
         Final : constant Byte_Buf_Access :=
           new Byte_Array'(Buf (1 .. Used));
      begin
         Free_Buf (Buf);
         return Final;
      end;
   end Build_UL_Low_Single;

   function Build_UL_Low_Triple return Byte_Buf_Access is
      Buf : Byte_Buf_Access := new Byte_Array (1 .. 1 * 1024 * 1024);
      Used : Stream_Element_Offset := 0;
      Cur : Stream_Element_Offset := Stream_Plain.all'First;
   begin
      while Cur <= Stream_Plain.all'Last loop
         declare
            Take : constant Stream_Element_Offset :=
              Stream_Element_Offset'Min
                (Stream_Chunk_Size,
                 Stream_Plain.all'Last - Cur + 1);
            Ct : constant Byte_Array :=
              Itb.Cipher.Encrypt_Triple
                (Seed_Noise,
                 Seed_Data1, Seed_Data2, Seed_Data3,
                 Seed_Start1, Seed_Start2, Seed_Start3,
                 Stream_Plain.all (Cur .. Cur + Take - 1));
            Need : constant Stream_Element_Offset :=
              Used + Stream_Element_Offset (4) + Ct'Length;
            CT_Len_LE : Byte_Array (1 .. 4);
            U32 : constant Unsigned_32 := Unsigned_32 (Ct'Length);
         begin
            CT_Len_LE (1) := Stream_Element (U32 and 16#FF#);
            CT_Len_LE (2) :=
              Stream_Element (Shift_Right (U32, 8) and 16#FF#);
            CT_Len_LE (3) :=
              Stream_Element (Shift_Right (U32, 16) and 16#FF#);
            CT_Len_LE (4) :=
              Stream_Element (Shift_Right (U32, 24) and 16#FF#);
            if Need > Buf'Last then
               declare
                  New_Cap : Stream_Element_Offset := Buf'Last;
                  New_Buf : Byte_Buf_Access;
               begin
                  while New_Cap < Need loop
                     New_Cap := New_Cap * 2;
                  end loop;
                  New_Buf := new Byte_Array (1 .. New_Cap);
                  New_Buf (1 .. Used) := Buf (1 .. Used);
                  Free_Buf (Buf);
                  Buf := New_Buf;
               end;
            end if;
            Buf (Used + 1 .. Used + 4) := CT_Len_LE;
            Used := Used + 4;
            Buf (Used + 1 .. Used + Ct'Length) := Ct;
            Used := Used + Ct'Length;
            Cur := Cur + Take;
         end;
      end loop;
      declare
         Final : constant Byte_Buf_Access :=
           new Byte_Array'(Buf (1 .. Used));
      begin
         Free_Buf (Buf);
         return Final;
      end;
   end Build_UL_Low_Triple;

   procedure Pre_Compute is
   begin
      --  Single Message — Single Ouroboros.
      Single_Easy_Nomac :=
        new Byte_Array'(Itb.Encryptor.Encrypt
                          (Enc_Easy_Single, Single_Plain.all));
      Single_Easy_Auth :=
        new Byte_Array'(Itb.Encryptor.Encrypt_Auth
                          (Enc_Easy_Single, Single_Plain.all));
      Single_Low_Nomac :=
        new Byte_Array'(Itb.Cipher.Encrypt
                          (Seed_Noise, Seed_Data1, Seed_Start1,
                           Single_Plain.all));
      Single_Low_Auth :=
        new Byte_Array'(Itb.Cipher.Encrypt_Auth
                          (Seed_Noise, Seed_Data1, Seed_Start1,
                           Mac_Handle, Single_Plain.all));

      --  Single Message — Triple Ouroboros.
      Triple_Easy_Nomac :=
        new Byte_Array'(Itb.Encryptor.Encrypt
                          (Enc_Easy_Triple, Single_Plain.all));
      Triple_Easy_Auth :=
        new Byte_Array'(Itb.Encryptor.Encrypt_Auth
                          (Enc_Easy_Triple, Single_Plain.all));
      Triple_Low_Nomac :=
        new Byte_Array'(Itb.Cipher.Encrypt_Triple
                          (Seed_Noise,
                           Seed_Data1, Seed_Data2, Seed_Data3,
                           Seed_Start1, Seed_Start2, Seed_Start3,
                           Single_Plain.all));
      Triple_Low_Auth :=
        new Byte_Array'(Itb.Cipher.Encrypt_Auth_Triple
                          (Seed_Noise,
                           Seed_Data1, Seed_Data2, Seed_Data3,
                           Seed_Start1, Seed_Start2, Seed_Start3,
                           Mac_Handle, Single_Plain.all));

      --  Streaming AEAD transcripts.
      declare
         Src : aliased Memory_Stream;
      begin
         Src.Write (Stream_Plain.all);

         Reset_Read (Src);
         Itb.Encryptor.Encrypt_Stream_Auth
           (Enc_Easy_Single, Src'Access, Tx_Easy_AEAD_Single'Access,
            Stream_Chunk_Size);

         Reset_Read (Src);
         Itb.Encryptor.Encrypt_Stream_Auth
           (Enc_Easy_Triple, Src'Access, Tx_Easy_AEAD_Triple'Access,
            Stream_Chunk_Size);

         Reset_Read (Src);
         Itb.Streams.Encrypt_Stream_Auth
           (Seed_Noise, Seed_Data1, Seed_Start1, Mac_Handle,
            Src'Access, Tx_Low_AEAD_Single'Access,
            Stream_Chunk_Size);

         Reset_Read (Src);
         Itb.Streams.Encrypt_Stream_Auth_Triple
           (Seed_Noise,
            Seed_Data1, Seed_Data2, Seed_Data3,
            Seed_Start1, Seed_Start2, Seed_Start3,
            Mac_Handle,
            Src'Access, Tx_Low_AEAD_Triple'Access,
            Stream_Chunk_Size);

         Free (Src);
      end;

      --  User-Loop transcripts (no-MAC).
      Tx_Easy_UL_Single := Build_UL_Easy (Enc_Easy_Single'Access);
      Tx_Easy_UL_Triple := Build_UL_Easy (Enc_Easy_Triple'Access);
      Tx_Low_UL_Single  := Build_UL_Low_Single;
      Tx_Low_UL_Triple  := Build_UL_Low_Triple;
   end Pre_Compute;

   ---------------------------------------------------------------------
   --  Per-case Run_Once bodies. Each case binds (cipher, mode, op).
   --
   --  Wrapper Only round-trip cases.
   ---------------------------------------------------------------------

   Bench_Cipher : Outer_Cipher := Itb.Wrapper.Aes_128_Ctr;

   --  Wrap_Only allocating roundtrip — Wrap → Unwrap on the same key.
   --  Each iter wraps a fresh CSPRNG payload then unwraps; the output
   --  is discarded. Wraps the call body in heap-allocation scratch so
   --  the 16 MiB Byte_Array result does not blow the primary stack.
   procedure Run_Wrap_Only_Alloc is
      Key : constant Byte_Array := Cipher_Keys (Bench_Cipher).Key.all;
      Wire_Ptr : Byte_Buf_Access :=
        new Byte_Array'(Itb.Wrapper.Wrap
                          (Bench_Cipher, Key, Wrap_Plain.all));
      Pt_Ptr : Byte_Buf_Access :=
        new Byte_Array'(Itb.Wrapper.Unwrap
                          (Bench_Cipher, Key, Wire_Ptr.all));
   begin
      Free_Buf (Wire_Ptr);
      Free_Buf (Pt_Ptr);
   end Run_Wrap_Only_Alloc;

   --  Heap-resident scratch buffer for the in-place wrap-only case
   --  (16 MiB exceeds the default 8 MiB Linux thread stack).
   Wrap_Only_Scratch : Byte_Buf_Access := null;
   Wrap_Only_Wire    : Byte_Buf_Access := null;

   procedure Run_Wrap_Only_In_Place is
      Key : constant Byte_Array := Cipher_Keys (Bench_Cipher).Key.all;
      N_Len : constant Stream_Element_Offset :=
        Stream_Element_Offset (Itb.Wrapper.Nonce_Size (Bench_Cipher));
      Out_Nonce : Byte_Array (1 .. N_Len);
      Wire_Total : constant Stream_Element_Offset :=
        N_Len + Wrap_Plain.all'Length;
      Body_First : Stream_Element_Offset;
   begin
      if Wrap_Only_Scratch = null
        or else Wrap_Only_Scratch'Length < Wrap_Plain.all'Length
      then
         if Wrap_Only_Scratch /= null then
            Free_Buf (Wrap_Only_Scratch);
         end if;
         Wrap_Only_Scratch := new Byte_Array (1 .. Wrap_Plain.all'Length);
      end if;
      if Wrap_Only_Wire = null or else Wrap_Only_Wire'Length < Wire_Total then
         if Wrap_Only_Wire /= null then
            Free_Buf (Wrap_Only_Wire);
         end if;
         Wrap_Only_Wire := new Byte_Array (1 .. Wire_Total);
      end if;
      Wrap_Only_Scratch (1 .. Wrap_Plain.all'Length) := Wrap_Plain.all;
      Itb.Wrapper.Wrap_In_Place
        (Bench_Cipher, Key,
         Wrap_Only_Scratch (1 .. Wrap_Plain.all'Length), Out_Nonce);
      Wrap_Only_Wire (1 .. N_Len) := Out_Nonce;
      Wrap_Only_Wire (N_Len + 1 .. Wire_Total) :=
        Wrap_Only_Scratch (1 .. Wrap_Plain.all'Length);
      Itb.Wrapper.Unwrap_In_Place
        (Bench_Cipher, Key,
         Wrap_Only_Wire (1 .. Wire_Total), Body_First);
   end Run_Wrap_Only_In_Place;

   ---------------------------------------------------------------------
   --  Single Message — Single Ouroboros.
   ---------------------------------------------------------------------

   Bench_Mode_CT : Byte_Buf_Access := null;

   procedure Run_Msg_Single_Encrypt is
      Key : constant Byte_Array := Cipher_Keys (Bench_Cipher).Key.all;
      Wire_Ptr : Byte_Buf_Access :=
        new Byte_Array'(Itb.Wrapper.Wrap
                          (Bench_Cipher, Key, Bench_Mode_CT.all));
   begin
      Free_Buf (Wire_Ptr);
   end Run_Msg_Single_Encrypt;

   procedure Run_Msg_Single_Decrypt is
      Key : constant Byte_Array := Cipher_Keys (Bench_Cipher).Key.all;
      Wire_Ptr : Byte_Buf_Access :=
        new Byte_Array'(Itb.Wrapper.Wrap
                          (Bench_Cipher, Key, Bench_Mode_CT.all));
      Recov_Ptr : Byte_Buf_Access :=
        new Byte_Array'(Itb.Wrapper.Unwrap
                          (Bench_Cipher, Key, Wire_Ptr.all));
   begin
      Free_Buf (Wire_Ptr);
      Free_Buf (Recov_Ptr);
   end Run_Msg_Single_Decrypt;

   ---------------------------------------------------------------------
   --  Streaming UserLoop — wrap pre-built UL transcript through one
   --  WrapStreamWriter session per iter (mirrors AEAD shape — both
   --  measure the wrap layer's per-byte XOR cost on top of the inner
   --  ITB transcript).
   ---------------------------------------------------------------------

   Bench_UL_Tx : Byte_Buf_Access := null;

   --  Heap-resident per-iter scratch buffers shared by every
   --  streaming case. Sized once on first use, reused across iters.
   --  Avoids stack overflow on the ~80 MiB transcripts (Linux default
   --  thread stack is 8 MiB).
   Iter_Encrypted : Byte_Buf_Access := null;
   Iter_Decrypted : Byte_Buf_Access := null;

   procedure Ensure_Iter_Buffers (N : Stream_Element_Offset) is
   begin
      if Iter_Encrypted = null or else Iter_Encrypted'Length < N then
         if Iter_Encrypted /= null then
            Free_Buf (Iter_Encrypted);
         end if;
         Iter_Encrypted := new Byte_Array (1 .. N);
      end if;
      if Iter_Decrypted = null or else Iter_Decrypted'Length < N then
         if Iter_Decrypted /= null then
            Free_Buf (Iter_Decrypted);
         end if;
         Iter_Decrypted := new Byte_Array (1 .. N);
      end if;
   end Ensure_Iter_Buffers;

   procedure Run_Stream_UL_Encrypt is
      Key : constant Byte_Array := Cipher_Keys (Bench_Cipher).Key.all;
      N_Len : constant Stream_Element_Offset :=
        Stream_Element_Offset (Itb.Wrapper.Nonce_Size (Bench_Cipher));
      Out_Nonce : Byte_Array (1 .. N_Len);
      W : Itb.Wrapper.Wrap_Stream_Writer;
      N : constant Stream_Element_Offset := Bench_UL_Tx.all'Length;
      Last : Stream_Element_Offset;
   begin
      Ensure_Iter_Buffers (N);
      Itb.Wrapper.Initialize (W, Bench_Cipher, Key, Out_Nonce);
      Itb.Wrapper.Update
        (W, Bench_UL_Tx.all, Iter_Encrypted (1 .. N), Last);
      Itb.Wrapper.Close (W);
   end Run_Stream_UL_Encrypt;

   procedure Run_Stream_UL_Decrypt is
      Key : constant Byte_Array := Cipher_Keys (Bench_Cipher).Key.all;
      N_Len : constant Stream_Element_Offset :=
        Stream_Element_Offset (Itb.Wrapper.Nonce_Size (Bench_Cipher));
      Out_Nonce : Byte_Array (1 .. N_Len);
      W : Itb.Wrapper.Wrap_Stream_Writer;
      N : constant Stream_Element_Offset := Bench_UL_Tx.all'Length;
      Last : Stream_Element_Offset;
      R : Itb.Wrapper.Unwrap_Stream_Reader;
   begin
      Ensure_Iter_Buffers (N);
      Itb.Wrapper.Initialize (W, Bench_Cipher, Key, Out_Nonce);
      Itb.Wrapper.Update
        (W, Bench_UL_Tx.all, Iter_Encrypted (1 .. N), Last);
      Itb.Wrapper.Close (W);

      Itb.Wrapper.Initialize (R, Bench_Cipher, Key, Out_Nonce);
      Itb.Wrapper.Update
        (R, Iter_Encrypted (1 .. N), Iter_Decrypted (1 .. N), Last);
      Itb.Wrapper.Close (R);
   end Run_Stream_UL_Decrypt;

   ---------------------------------------------------------------------
   --  Bench-case orchestration.
   ---------------------------------------------------------------------

   Min_Seconds : constant Float := Env_Min_Seconds;

   --  Cipher-name slug for case-name composition. Cycle these strings
   --  in canonical order: aes / chacha / siphash.
   function Cipher_Slug (C : Outer_Cipher) return String is
   begin
      case C is
         when Itb.Wrapper.Aes_128_Ctr => return "aes";
         when Itb.Wrapper.Cha_Cha_20  => return "chacha";
         when Itb.Wrapper.Sip_Hash_24 => return "siphash";
      end case;
   end Cipher_Slug;

   procedure Run_Wrapper_Only_Cases is
   begin
      for C in Outer_Cipher loop
         Bench_Cipher := C;
         Measure
           ("bench_wrapper_only_alloc_" & Cipher_Slug (C) & "_16mb",
            Run_Wrap_Only_Alloc'Access,
            Wrapper_Only_Bytes, Min_Seconds);
         Measure
           ("bench_wrapper_only_inplace_" & Cipher_Slug (C) & "_16mb",
            Run_Wrap_Only_In_Place'Access,
            Wrapper_Only_Bytes, Min_Seconds);
      end loop;
   end Run_Wrapper_Only_Cases;

   procedure Run_Single_Message_Cases is
      type Mode_Slug is record
         Tag           : access constant String;
         CT_Single     : Byte_Buf_Access;
         CT_Triple     : Byte_Buf_Access;
      end record;
      Easy_Nomac_Tag    : aliased constant String := "easy_nomac";
      Easy_Auth_Tag     : aliased constant String := "easy_auth";
      Low_Nomac_Tag     : aliased constant String := "lowlevel_nomac";
      Low_Auth_Tag      : aliased constant String := "lowlevel_auth";
   begin
      declare
         Modes : constant array (1 .. 4) of Mode_Slug :=
           [(Easy_Nomac_Tag'Access, Single_Easy_Nomac, Triple_Easy_Nomac),
            (Easy_Auth_Tag'Access,  Single_Easy_Auth,  Triple_Easy_Auth),
            (Low_Nomac_Tag'Access,  Single_Low_Nomac,  Triple_Low_Nomac),
            (Low_Auth_Tag'Access,   Single_Low_Auth,   Triple_Low_Auth)];
      begin
         for C in Outer_Cipher loop
            Bench_Cipher := C;
            for M of Modes loop
               --  Single Ouroboros (encrypt + decrypt)
               Bench_Mode_CT := M.CT_Single;
               Measure
                 ("bench_message_single_" & M.Tag.all & "_"
                  & Cipher_Slug (C) & "_encrypt_16mb",
                  Run_Msg_Single_Encrypt'Access,
                  Single_Message_Bytes, Min_Seconds);
               Measure
                 ("bench_message_single_" & M.Tag.all & "_"
                  & Cipher_Slug (C) & "_decrypt_16mb",
                  Run_Msg_Single_Decrypt'Access,
                  Single_Message_Bytes, Min_Seconds);
               --  Triple Ouroboros (encrypt + decrypt)
               Bench_Mode_CT := M.CT_Triple;
               Measure
                 ("bench_message_triple_" & M.Tag.all & "_"
                  & Cipher_Slug (C) & "_encrypt_16mb",
                  Run_Msg_Single_Encrypt'Access,
                  Single_Message_Bytes, Min_Seconds);
               Measure
                 ("bench_message_triple_" & M.Tag.all & "_"
                  & Cipher_Slug (C) & "_decrypt_16mb",
                  Run_Msg_Single_Decrypt'Access,
                  Single_Message_Bytes, Min_Seconds);
            end loop;
         end loop;
      end;
   end Run_Single_Message_Cases;

   --  Picks the active AEAD transcript from the running Bench_Stream_Tx
   --  selector. Library-level pointer ban (RM 3.10.2 accessibility)
   --  rules out a per-iter access pointer, so a small 1..4 selector
   --  routes the pointer pick at iter time.
   type AEAD_Selector is (Easy_Single, Easy_Triple, Low_Single,
                          Low_Triple);
   Active_AEAD : AEAD_Selector := Easy_Single;

   --  Re-declare Run_Stream_Aead_* as named-by-selector variants so
   --  the Run_Once_Proc takes a parameterless body but the body picks
   --  the right transcript via the global selector.
   procedure Run_Stream_Aead_By_Selector_Encrypt is
      Key : constant Byte_Array := Cipher_Keys (Bench_Cipher).Key.all;
      N_Len : constant Stream_Element_Offset :=
        Stream_Element_Offset (Itb.Wrapper.Nonce_Size (Bench_Cipher));
      Out_Nonce : Byte_Array (1 .. N_Len);
      W : Itb.Wrapper.Wrap_Stream_Writer;
      Tx_Bytes : Stream_Element_Offset := 0;
      Last : Stream_Element_Offset;
   begin
      case Active_AEAD is
         when Easy_Single => Tx_Bytes := Tx_Easy_AEAD_Single.Used;
         when Easy_Triple => Tx_Bytes := Tx_Easy_AEAD_Triple.Used;
         when Low_Single  => Tx_Bytes := Tx_Low_AEAD_Single.Used;
         when Low_Triple  => Tx_Bytes := Tx_Low_AEAD_Triple.Used;
      end case;
      Ensure_Iter_Buffers (Tx_Bytes);
      Itb.Wrapper.Initialize (W, Bench_Cipher, Key, Out_Nonce);
      case Active_AEAD is
         when Easy_Single =>
            Itb.Wrapper.Update
              (W, Tx_Easy_AEAD_Single.Buf (1 .. Tx_Bytes),
               Iter_Encrypted (1 .. Tx_Bytes), Last);
         when Easy_Triple =>
            Itb.Wrapper.Update
              (W, Tx_Easy_AEAD_Triple.Buf (1 .. Tx_Bytes),
               Iter_Encrypted (1 .. Tx_Bytes), Last);
         when Low_Single  =>
            Itb.Wrapper.Update
              (W, Tx_Low_AEAD_Single.Buf (1 .. Tx_Bytes),
               Iter_Encrypted (1 .. Tx_Bytes), Last);
         when Low_Triple  =>
            Itb.Wrapper.Update
              (W, Tx_Low_AEAD_Triple.Buf (1 .. Tx_Bytes),
               Iter_Encrypted (1 .. Tx_Bytes), Last);
      end case;
      Itb.Wrapper.Close (W);
   end Run_Stream_Aead_By_Selector_Encrypt;

   procedure Run_Stream_Aead_By_Selector_Decrypt is
      Key : constant Byte_Array := Cipher_Keys (Bench_Cipher).Key.all;
      N_Len : constant Stream_Element_Offset :=
        Stream_Element_Offset (Itb.Wrapper.Nonce_Size (Bench_Cipher));
      Out_Nonce : Byte_Array (1 .. N_Len);
      W : Itb.Wrapper.Wrap_Stream_Writer;
      Tx_Bytes : Stream_Element_Offset := 0;
      Last : Stream_Element_Offset;
      R : Itb.Wrapper.Unwrap_Stream_Reader;
   begin
      case Active_AEAD is
         when Easy_Single => Tx_Bytes := Tx_Easy_AEAD_Single.Used;
         when Easy_Triple => Tx_Bytes := Tx_Easy_AEAD_Triple.Used;
         when Low_Single  => Tx_Bytes := Tx_Low_AEAD_Single.Used;
         when Low_Triple  => Tx_Bytes := Tx_Low_AEAD_Triple.Used;
      end case;
      Ensure_Iter_Buffers (Tx_Bytes);
      Itb.Wrapper.Initialize (W, Bench_Cipher, Key, Out_Nonce);
      case Active_AEAD is
         when Easy_Single =>
            Itb.Wrapper.Update
              (W, Tx_Easy_AEAD_Single.Buf (1 .. Tx_Bytes),
               Iter_Encrypted (1 .. Tx_Bytes), Last);
         when Easy_Triple =>
            Itb.Wrapper.Update
              (W, Tx_Easy_AEAD_Triple.Buf (1 .. Tx_Bytes),
               Iter_Encrypted (1 .. Tx_Bytes), Last);
         when Low_Single  =>
            Itb.Wrapper.Update
              (W, Tx_Low_AEAD_Single.Buf (1 .. Tx_Bytes),
               Iter_Encrypted (1 .. Tx_Bytes), Last);
         when Low_Triple  =>
            Itb.Wrapper.Update
              (W, Tx_Low_AEAD_Triple.Buf (1 .. Tx_Bytes),
               Iter_Encrypted (1 .. Tx_Bytes), Last);
      end case;
      Itb.Wrapper.Close (W);

      Itb.Wrapper.Initialize (R, Bench_Cipher, Key, Out_Nonce);
      Itb.Wrapper.Update
        (R, Iter_Encrypted (1 .. Tx_Bytes),
         Iter_Decrypted (1 .. Tx_Bytes), Last);
      Itb.Wrapper.Close (R);
   end Run_Stream_Aead_By_Selector_Decrypt;

   procedure Run_Streaming_Cases is
      type Stream_Mode_Tag is
        (AEAD_Easy_IO, AEAD_Low_IO, NoAEAD_Easy_UL, NoAEAD_Low_UL);
      type Mode_Slug_Access is access constant String;
      AEAD_Easy_Tag   : aliased constant String := "aead_easy_io";
      AEAD_Low_Tag    : aliased constant String := "aead_lowlevel_io";
      Noaead_Easy_Tag : aliased constant String :=
        "noaead_easy_userloop";
      Noaead_Low_Tag  : aliased constant String :=
        "noaead_lowlevel_userloop";

      Tags : constant array (Stream_Mode_Tag) of Mode_Slug_Access :=
        [AEAD_Easy_IO   => AEAD_Easy_Tag'Access,
         AEAD_Low_IO    => AEAD_Low_Tag'Access,
         NoAEAD_Easy_UL => Noaead_Easy_Tag'Access,
         NoAEAD_Low_UL  => Noaead_Low_Tag'Access];
   begin
      for C in Outer_Cipher loop
         Bench_Cipher := C;
         for Tag in Stream_Mode_Tag loop
            case Tag is
               when AEAD_Easy_IO =>
                  Active_AEAD := Easy_Single;
                  Measure
                    ("bench_stream_single_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_encrypt_64mb",
                     Run_Stream_Aead_By_Selector_Encrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
                  Measure
                    ("bench_stream_single_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_decrypt_64mb",
                     Run_Stream_Aead_By_Selector_Decrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
                  Active_AEAD := Easy_Triple;
                  Measure
                    ("bench_stream_triple_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_encrypt_64mb",
                     Run_Stream_Aead_By_Selector_Encrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
                  Measure
                    ("bench_stream_triple_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_decrypt_64mb",
                     Run_Stream_Aead_By_Selector_Decrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
               when AEAD_Low_IO =>
                  Active_AEAD := Low_Single;
                  Measure
                    ("bench_stream_single_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_encrypt_64mb",
                     Run_Stream_Aead_By_Selector_Encrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
                  Measure
                    ("bench_stream_single_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_decrypt_64mb",
                     Run_Stream_Aead_By_Selector_Decrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
                  Active_AEAD := Low_Triple;
                  Measure
                    ("bench_stream_triple_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_encrypt_64mb",
                     Run_Stream_Aead_By_Selector_Encrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
                  Measure
                    ("bench_stream_triple_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_decrypt_64mb",
                     Run_Stream_Aead_By_Selector_Decrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
               when NoAEAD_Easy_UL =>
                  Bench_UL_Tx := Tx_Easy_UL_Single;
                  Measure
                    ("bench_stream_single_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_encrypt_64mb",
                     Run_Stream_UL_Encrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
                  Measure
                    ("bench_stream_single_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_decrypt_64mb",
                     Run_Stream_UL_Decrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
                  Bench_UL_Tx := Tx_Easy_UL_Triple;
                  Measure
                    ("bench_stream_triple_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_encrypt_64mb",
                     Run_Stream_UL_Encrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
                  Measure
                    ("bench_stream_triple_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_decrypt_64mb",
                     Run_Stream_UL_Decrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
               when NoAEAD_Low_UL =>
                  Bench_UL_Tx := Tx_Low_UL_Single;
                  Measure
                    ("bench_stream_single_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_encrypt_64mb",
                     Run_Stream_UL_Encrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
                  Measure
                    ("bench_stream_single_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_decrypt_64mb",
                     Run_Stream_UL_Decrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
                  Bench_UL_Tx := Tx_Low_UL_Triple;
                  Measure
                    ("bench_stream_triple_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_encrypt_64mb",
                     Run_Stream_UL_Encrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
                  Measure
                    ("bench_stream_triple_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_decrypt_64mb",
                     Run_Stream_UL_Decrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
            end case;
         end loop;
      end loop;
   end Run_Streaming_Cases;

begin
   Itb.Set_Max_Workers (0);
   Itb.Set_Nonce_Bits (128);

   declare
      Min_S_Img : constant String :=
        Ada.Strings.Fixed.Trim
          (Integer'Image (Integer (Min_Seconds)), Ada.Strings.Both);
   begin
      Ada.Text_IO.Put_Line
        ("# wrapper primitive=" & Stream_Primitive
         & " key_bits=1024 mac=" & Mac_Name
         & " single_message_bytes=16777216"
         & " stream_payload_bytes=67108864"
         & " stream_chunk_size=16777216"
         & " min_seconds=" & Min_S_Img
         & " workers=auto");
      Ada.Text_IO.Put_Line ("# benchmarks=102 min_seconds=" & Min_S_Img);
   end;

   Build_Cipher_Keys;
   Pre_Compute;

   Run_Wrapper_Only_Cases;     --  6 cases
   Run_Single_Message_Cases;   --  48 cases (24 single + 24 triple)
   Run_Streaming_Cases;        --  48 cases (24 single + 24 triple)

   --  Cleanup heap allocations.
   Free_Buf (Wrap_Plain);
   Free_Buf (Single_Plain);
   Free_Buf (Single_Easy_Nomac);
   Free_Buf (Single_Easy_Auth);
   Free_Buf (Single_Low_Nomac);
   Free_Buf (Single_Low_Auth);
   Free_Buf (Triple_Easy_Nomac);
   Free_Buf (Triple_Easy_Auth);
   Free_Buf (Triple_Low_Nomac);
   Free_Buf (Triple_Low_Auth);
   Free_Buf (Stream_Plain);
   Free_Buf (Tx_Easy_UL_Single);
   Free_Buf (Tx_Easy_UL_Triple);
   Free_Buf (Tx_Low_UL_Single);
   Free_Buf (Tx_Low_UL_Triple);
   for C in Outer_Cipher loop
      if Cipher_Keys (C).Key /= null then
         Free_Buf (Cipher_Keys (C).Key);
      end if;
   end loop;
   if Wrap_Only_Scratch /= null then
      Free_Buf (Wrap_Only_Scratch);
   end if;
   if Wrap_Only_Wire /= null then
      Free_Buf (Wrap_Only_Wire);
   end if;
   if Iter_Encrypted /= null then
      Free_Buf (Iter_Encrypted);
   end if;
   if Iter_Decrypted /= null then
      Free_Buf (Iter_Decrypted);
   end if;
   Free (Source_Stream);
   Free (Sink_Stream);
   Free (Tx_Easy_AEAD_Single);
   Free (Tx_Easy_AEAD_Triple);
   Free (Tx_Low_AEAD_Single);
   Free (Tx_Low_AEAD_Triple);
end Bench_Wrapper;
