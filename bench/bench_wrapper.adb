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

   --  Single Message plaintext (re-used across every Single Message
   --  encrypt / decrypt case so the per-iter cost reflects encrypt +
   --  wrap on a stable plaintext).
   Single_Plain         : Byte_Buf_Access :=
     Random_Bytes (Single_Message_Bytes);

   --  Pristine wires for decrypt-direction Single Message cases.
   --  Each wire is computed once at setup as
   --     Wrap_In_Place (cipher_key, ITB_encrypt(plain))
   --  then prefixed with the wrap nonce. The timed decrypt loop
   --  refreshes a working copy from the pristine buffer per iter
   --  (mirrors the wrapper/bench_test.go pristineWire pattern).
   --  Outer key index = Outer_Cipher.
   type Wire_Slot is record
      Wire : Byte_Buf_Access := null;
   end record;
   --  [cipher × mode] (mode encoded in the labelled-array selectors
   --  declared below in Run_Single_Message_Cases).
   Single_Easy_Nomac_Wires : array (Outer_Cipher) of Wire_Slot;
   Single_Easy_Auth_Wires  : array (Outer_Cipher) of Wire_Slot;
   Single_Low_Nomac_Wires  : array (Outer_Cipher) of Wire_Slot;
   Single_Low_Auth_Wires   : array (Outer_Cipher) of Wire_Slot;
   Triple_Easy_Nomac_Wires : array (Outer_Cipher) of Wire_Slot;
   Triple_Easy_Auth_Wires  : array (Outer_Cipher) of Wire_Slot;
   Triple_Low_Nomac_Wires  : array (Outer_Cipher) of Wire_Slot;
   Triple_Low_Auth_Wires   : array (Outer_Cipher) of Wire_Slot;

   --  Streaming payload (64 MiB) reused across every streaming case.
   Stream_Plain : Byte_Buf_Access := Random_Bytes (Stream_Payload_Bytes);

   --  Pristine wires for decrypt-direction Streaming cases. Each
   --  wire is built once at setup as
   --     wrap_stream_writer(stream-encrypt(plain))
   --  with one CSPRNG nonce drawn at setup; the decrypt loop
   --  refreshes a working copy per iter and runs
   --  unwrap-stream-reader → stream-decrypt to recover the
   --  plaintext.
   Stream_Easy_AEAD_Single_Wires : array (Outer_Cipher) of Wire_Slot;
   Stream_Easy_AEAD_Triple_Wires : array (Outer_Cipher) of Wire_Slot;
   Stream_Low_AEAD_Single_Wires  : array (Outer_Cipher) of Wire_Slot;
   Stream_Low_AEAD_Triple_Wires  : array (Outer_Cipher) of Wire_Slot;
   Stream_Easy_UL_Single_Wires   : array (Outer_Cipher) of Wire_Slot;
   Stream_Easy_UL_Triple_Wires   : array (Outer_Cipher) of Wire_Slot;
   Stream_Low_UL_Single_Wires    : array (Outer_Cipher) of Wire_Slot;
   Stream_Low_UL_Triple_Wires    : array (Outer_Cipher) of Wire_Slot;

   --  Reusable Memory_Stream scratch slots for the encrypt-direction
   --  pipeline (inner ITB transcript) and decrypt-direction pipeline
   --  (recovered plaintext sink). Allocated lazily on first use,
   --  Reset (Used := 0) per iter.
   Inner_Stream  : aliased Memory_Stream;
   Plain_Sink    : aliased Memory_Stream;
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

   --  Wraps a plain ITB ciphertext blob into a fresh wrapper wire
   --  (nonce || in-place-XOR(blob)) under the supplied cipher / key.
   --  Returns a freshly-allocated Byte_Buf_Access owning the wire.
   --  Used by the decrypt-direction pre-compute path.
   function Build_Pristine_Wrap
     (C    : Outer_Cipher;
      Key  : Byte_Array;
      Blob : Byte_Array) return Byte_Buf_Access
   is
      N_Len : constant Stream_Element_Offset :=
        Stream_Element_Offset (Itb.Wrapper.Nonce_Size (C));
      Wire_Total : constant Stream_Element_Offset :=
        N_Len + Blob'Length;
      Out_Nonce : Byte_Array (1 .. N_Len);
      Wire : constant Byte_Buf_Access :=
        new Byte_Array (1 .. Wire_Total);
   begin
      Wire (N_Len + 1 .. Wire_Total) := Blob;
      Itb.Wrapper.Wrap_In_Place
        (C, Key, Wire (N_Len + 1 .. Wire_Total), Out_Nonce);
      Wire (1 .. N_Len) := Out_Nonce;
      return Wire;
   end Build_Pristine_Wrap;

   --  Wraps an arbitrary inner streaming transcript bytes (already
   --  produced via stream-encrypt) into a fresh wrapper wire by
   --  driving one Wrap_Stream_Writer over the entire transcript.
   --  Mirrors Build_Pristine_Wrap but for streaming-shaped wires.
   function Build_Pristine_Wrap_Stream
     (C       : Outer_Cipher;
      Key     : Byte_Array;
      Inner   : Byte_Array) return Byte_Buf_Access
   is
      N_Len : constant Stream_Element_Offset :=
        Stream_Element_Offset (Itb.Wrapper.Nonce_Size (C));
      Wire_Total : constant Stream_Element_Offset :=
        N_Len + Inner'Length;
      Out_Nonce : Byte_Array (1 .. N_Len);
      Wire : constant Byte_Buf_Access :=
        new Byte_Array (1 .. Wire_Total);
      W : Itb.Wrapper.Wrap_Stream_Writer;
      Last : Stream_Element_Offset;
   begin
      Itb.Wrapper.Initialize (W, C, Key, Out_Nonce);
      Itb.Wrapper.Update
        (W, Inner, Wire (N_Len + 1 .. Wire_Total), Last);
      Itb.Wrapper.Close (W);
      Wire (1 .. N_Len) := Out_Nonce;
      return Wire;
   end Build_Pristine_Wrap_Stream;

   --  Pre-compute pristine wires for every decrypt-direction case.
   --  Each wire holds wrap_in_place(ITB_encrypt(plain)) (Single
   --  Message) or wrap_stream_writer(stream-encrypt(plain))
   --  (Streaming). The timed decrypt loop refreshes a working copy
   --  from the pristine buffer per iter; encrypt-direction cases do
   --  NOT use these pre-computed buffers — their timed loop runs the
   --  full encrypt + wrap pipeline end-to-end on each iter.
   procedure Pre_Compute is
   begin
      for C in Outer_Cipher loop
         declare
            Key : constant Byte_Array := Cipher_Keys (C).Key.all;
         begin
            --  Single Message — Single Ouroboros wires.
            declare
               CT : constant Byte_Array :=
                 Itb.Encryptor.Encrypt (Enc_Easy_Single, Single_Plain.all);
            begin
               Single_Easy_Nomac_Wires (C).Wire :=
                 Build_Pristine_Wrap (C, Key, CT);
            end;
            declare
               CT : constant Byte_Array :=
                 Itb.Encryptor.Encrypt_Auth
                   (Enc_Easy_Single, Single_Plain.all);
            begin
               Single_Easy_Auth_Wires (C).Wire :=
                 Build_Pristine_Wrap (C, Key, CT);
            end;
            declare
               CT : constant Byte_Array :=
                 Itb.Cipher.Encrypt
                   (Seed_Noise, Seed_Data1, Seed_Start1,
                    Single_Plain.all);
            begin
               Single_Low_Nomac_Wires (C).Wire :=
                 Build_Pristine_Wrap (C, Key, CT);
            end;
            declare
               CT : constant Byte_Array :=
                 Itb.Cipher.Encrypt_Auth
                   (Seed_Noise, Seed_Data1, Seed_Start1,
                    Mac_Handle, Single_Plain.all);
            begin
               Single_Low_Auth_Wires (C).Wire :=
                 Build_Pristine_Wrap (C, Key, CT);
            end;

            --  Single Message — Triple Ouroboros wires.
            declare
               CT : constant Byte_Array :=
                 Itb.Encryptor.Encrypt (Enc_Easy_Triple, Single_Plain.all);
            begin
               Triple_Easy_Nomac_Wires (C).Wire :=
                 Build_Pristine_Wrap (C, Key, CT);
            end;
            declare
               CT : constant Byte_Array :=
                 Itb.Encryptor.Encrypt_Auth
                   (Enc_Easy_Triple, Single_Plain.all);
            begin
               Triple_Easy_Auth_Wires (C).Wire :=
                 Build_Pristine_Wrap (C, Key, CT);
            end;
            declare
               CT : constant Byte_Array :=
                 Itb.Cipher.Encrypt_Triple
                   (Seed_Noise,
                    Seed_Data1, Seed_Data2, Seed_Data3,
                    Seed_Start1, Seed_Start2, Seed_Start3,
                    Single_Plain.all);
            begin
               Triple_Low_Nomac_Wires (C).Wire :=
                 Build_Pristine_Wrap (C, Key, CT);
            end;
            declare
               CT : constant Byte_Array :=
                 Itb.Cipher.Encrypt_Auth_Triple
                   (Seed_Noise,
                    Seed_Data1, Seed_Data2, Seed_Data3,
                    Seed_Start1, Seed_Start2, Seed_Start3,
                    Mac_Handle, Single_Plain.all);
            begin
               Triple_Low_Auth_Wires (C).Wire :=
                 Build_Pristine_Wrap (C, Key, CT);
            end;

            --  Streaming AEAD wires (Easy + Low-Level, Single + Triple).
            declare
               Src : aliased Memory_Stream;
               Sink : aliased Memory_Stream;
            begin
               Src.Write (Stream_Plain.all);

               Reset_Read (Src);
               Itb.Encryptor.Encrypt_Stream_Auth
                 (Enc_Easy_Single, Src'Access, Sink'Access,
                  Stream_Chunk_Size);
               Stream_Easy_AEAD_Single_Wires (C).Wire :=
                 Build_Pristine_Wrap_Stream
                   (C, Key, Sink.Buf (1 .. Sink.Used));
               Sink.Used := 0;

               Reset_Read (Src);
               Itb.Encryptor.Encrypt_Stream_Auth
                 (Enc_Easy_Triple, Src'Access, Sink'Access,
                  Stream_Chunk_Size);
               Stream_Easy_AEAD_Triple_Wires (C).Wire :=
                 Build_Pristine_Wrap_Stream
                   (C, Key, Sink.Buf (1 .. Sink.Used));
               Sink.Used := 0;

               Reset_Read (Src);
               Itb.Streams.Encrypt_Stream_Auth
                 (Seed_Noise, Seed_Data1, Seed_Start1, Mac_Handle,
                  Src'Access, Sink'Access, Stream_Chunk_Size);
               Stream_Low_AEAD_Single_Wires (C).Wire :=
                 Build_Pristine_Wrap_Stream
                   (C, Key, Sink.Buf (1 .. Sink.Used));
               Sink.Used := 0;

               Reset_Read (Src);
               Itb.Streams.Encrypt_Stream_Auth_Triple
                 (Seed_Noise,
                  Seed_Data1, Seed_Data2, Seed_Data3,
                  Seed_Start1, Seed_Start2, Seed_Start3,
                  Mac_Handle, Src'Access, Sink'Access,
                  Stream_Chunk_Size);
               Stream_Low_AEAD_Triple_Wires (C).Wire :=
                 Build_Pristine_Wrap_Stream
                   (C, Key, Sink.Buf (1 .. Sink.Used));
               Sink.Used := 0;

               Free (Src);
               Free (Sink);
            end;

            --  User-Loop wires (no-MAC) — easy + lowlevel × single +
            --  triple. Builds the inner User-Loop transcript then
            --  wraps it.
            declare
               UL : Byte_Buf_Access;
            begin
               UL := Build_UL_Easy (Enc_Easy_Single'Access);
               Stream_Easy_UL_Single_Wires (C).Wire :=
                 Build_Pristine_Wrap_Stream (C, Key, UL.all);
               Free_Buf (UL);

               UL := Build_UL_Easy (Enc_Easy_Triple'Access);
               Stream_Easy_UL_Triple_Wires (C).Wire :=
                 Build_Pristine_Wrap_Stream (C, Key, UL.all);
               Free_Buf (UL);

               UL := Build_UL_Low_Single;
               Stream_Low_UL_Single_Wires (C).Wire :=
                 Build_Pristine_Wrap_Stream (C, Key, UL.all);
               Free_Buf (UL);

               UL := Build_UL_Low_Triple;
               Stream_Low_UL_Triple_Wires (C).Wire :=
                 Build_Pristine_Wrap_Stream (C, Key, UL.all);
               Free_Buf (UL);
            end;
         end;
      end loop;
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
   --  Single Message — encrypt-direction (full pipeline) + decrypt-
   --  direction (pristine wire refresh).
   --
   --  Encrypt cases: each iter builds the inner ITB ciphertext from
   --  Single_Plain via the selected mode (Easy / Low-Level × No-MAC /
   --  MAC × Single / Triple), then wraps the result into a fresh
   --  on-wire buffer. This mirrors the wrapper/bench_test.go
   --  encrypt-side pattern (composeWire over Wrap_In_Place).
   --
   --  Decrypt cases: setup pre-computes a pristine wire (one ITB
   --  encrypt + one Wrap_In_Place); the timed loop refreshes a
   --  working wire from the pristine copy and then runs
   --  Unwrap_In_Place + ITB decrypt.
   ---------------------------------------------------------------------

   --  Per-iter scratch: a single working wire (Body_Cap + Nonce) and
   --  a recovered-plaintext sink (Body_Cap). Sized at first use.
   Msg_Wire_Buf  : Byte_Buf_Access := null;
   Msg_Plain_Buf : Byte_Buf_Access := null;

   procedure Ensure_Msg_Buffers (Wire_Cap, Plain_Cap : Stream_Element_Offset) is
   begin
      if Msg_Wire_Buf = null or else Msg_Wire_Buf'Length < Wire_Cap then
         if Msg_Wire_Buf /= null then
            Free_Buf (Msg_Wire_Buf);
         end if;
         Msg_Wire_Buf := new Byte_Array (1 .. Wire_Cap);
      end if;
      if Msg_Plain_Buf = null or else Msg_Plain_Buf'Length < Plain_Cap then
         if Msg_Plain_Buf /= null then
            Free_Buf (Msg_Plain_Buf);
         end if;
         Msg_Plain_Buf := new Byte_Array (1 .. Plain_Cap);
      end if;
   end Ensure_Msg_Buffers;

   --  Mode selector for encrypt + decrypt run dispatch.
   type Msg_Mode_Tag is
     (Easy_NoMAC_Single,  Easy_Auth_Single,
      Low_NoMAC_Single,   Low_Auth_Single,
      Easy_NoMAC_Triple,  Easy_Auth_Triple,
      Low_NoMAC_Triple,   Low_Auth_Triple);

   Active_Msg_Mode : Msg_Mode_Tag := Easy_NoMAC_Single;

   --  Picks the pristine wire that matches the (cipher, mode)
   --  selector for decrypt-direction iters.
   function Active_Msg_Wire return Byte_Buf_Access is
   begin
      case Active_Msg_Mode is
         when Easy_NoMAC_Single =>
            return Single_Easy_Nomac_Wires (Bench_Cipher).Wire;
         when Easy_Auth_Single =>
            return Single_Easy_Auth_Wires (Bench_Cipher).Wire;
         when Low_NoMAC_Single =>
            return Single_Low_Nomac_Wires (Bench_Cipher).Wire;
         when Low_Auth_Single =>
            return Single_Low_Auth_Wires (Bench_Cipher).Wire;
         when Easy_NoMAC_Triple =>
            return Triple_Easy_Nomac_Wires (Bench_Cipher).Wire;
         when Easy_Auth_Triple =>
            return Triple_Easy_Auth_Wires (Bench_Cipher).Wire;
         when Low_NoMAC_Triple =>
            return Triple_Low_Nomac_Wires (Bench_Cipher).Wire;
         when Low_Auth_Triple =>
            return Triple_Low_Auth_Wires (Bench_Cipher).Wire;
      end case;
   end Active_Msg_Wire;

   --  Encrypt-direction iter — full pipeline. Allocates the inner
   --  ITB ciphertext (per iter), then wraps into a fresh wire buffer.
   --  Mirrors wrapper/bench_test.go's runMessageEasyEncrypt /
   --  runMessageLowLevel*Encrypt shape.
   procedure Run_Msg_Encrypt is
      Key : constant Byte_Array := Cipher_Keys (Bench_Cipher).Key.all;
      N_Len : constant Stream_Element_Offset :=
        Stream_Element_Offset (Itb.Wrapper.Nonce_Size (Bench_Cipher));
      Out_Nonce : Byte_Array (1 .. N_Len);
   begin
      case Active_Msg_Mode is
         when Easy_NoMAC_Single =>
            declare
               CT : constant Byte_Array :=
                 Itb.Encryptor.Encrypt
                   (Enc_Easy_Single, Single_Plain.all);
               Wire_Total : constant Stream_Element_Offset :=
                 N_Len + CT'Length;
            begin
               Ensure_Msg_Buffers (Wire_Total, CT'Length);
               Msg_Wire_Buf (N_Len + 1 .. Wire_Total) := CT;
               Itb.Wrapper.Wrap_In_Place
                 (Bench_Cipher, Key,
                  Msg_Wire_Buf (N_Len + 1 .. Wire_Total), Out_Nonce);
               Msg_Wire_Buf (1 .. N_Len) := Out_Nonce;
            end;
         when Easy_Auth_Single =>
            declare
               CT : constant Byte_Array :=
                 Itb.Encryptor.Encrypt_Auth
                   (Enc_Easy_Single, Single_Plain.all);
               Wire_Total : constant Stream_Element_Offset :=
                 N_Len + CT'Length;
            begin
               Ensure_Msg_Buffers (Wire_Total, CT'Length);
               Msg_Wire_Buf (N_Len + 1 .. Wire_Total) := CT;
               Itb.Wrapper.Wrap_In_Place
                 (Bench_Cipher, Key,
                  Msg_Wire_Buf (N_Len + 1 .. Wire_Total), Out_Nonce);
               Msg_Wire_Buf (1 .. N_Len) := Out_Nonce;
            end;
         when Low_NoMAC_Single =>
            declare
               CT : constant Byte_Array :=
                 Itb.Cipher.Encrypt
                   (Seed_Noise, Seed_Data1, Seed_Start1,
                    Single_Plain.all);
               Wire_Total : constant Stream_Element_Offset :=
                 N_Len + CT'Length;
            begin
               Ensure_Msg_Buffers (Wire_Total, CT'Length);
               Msg_Wire_Buf (N_Len + 1 .. Wire_Total) := CT;
               Itb.Wrapper.Wrap_In_Place
                 (Bench_Cipher, Key,
                  Msg_Wire_Buf (N_Len + 1 .. Wire_Total), Out_Nonce);
               Msg_Wire_Buf (1 .. N_Len) := Out_Nonce;
            end;
         when Low_Auth_Single =>
            declare
               CT : constant Byte_Array :=
                 Itb.Cipher.Encrypt_Auth
                   (Seed_Noise, Seed_Data1, Seed_Start1,
                    Mac_Handle, Single_Plain.all);
               Wire_Total : constant Stream_Element_Offset :=
                 N_Len + CT'Length;
            begin
               Ensure_Msg_Buffers (Wire_Total, CT'Length);
               Msg_Wire_Buf (N_Len + 1 .. Wire_Total) := CT;
               Itb.Wrapper.Wrap_In_Place
                 (Bench_Cipher, Key,
                  Msg_Wire_Buf (N_Len + 1 .. Wire_Total), Out_Nonce);
               Msg_Wire_Buf (1 .. N_Len) := Out_Nonce;
            end;
         when Easy_NoMAC_Triple =>
            declare
               CT : constant Byte_Array :=
                 Itb.Encryptor.Encrypt
                   (Enc_Easy_Triple, Single_Plain.all);
               Wire_Total : constant Stream_Element_Offset :=
                 N_Len + CT'Length;
            begin
               Ensure_Msg_Buffers (Wire_Total, CT'Length);
               Msg_Wire_Buf (N_Len + 1 .. Wire_Total) := CT;
               Itb.Wrapper.Wrap_In_Place
                 (Bench_Cipher, Key,
                  Msg_Wire_Buf (N_Len + 1 .. Wire_Total), Out_Nonce);
               Msg_Wire_Buf (1 .. N_Len) := Out_Nonce;
            end;
         when Easy_Auth_Triple =>
            declare
               CT : constant Byte_Array :=
                 Itb.Encryptor.Encrypt_Auth
                   (Enc_Easy_Triple, Single_Plain.all);
               Wire_Total : constant Stream_Element_Offset :=
                 N_Len + CT'Length;
            begin
               Ensure_Msg_Buffers (Wire_Total, CT'Length);
               Msg_Wire_Buf (N_Len + 1 .. Wire_Total) := CT;
               Itb.Wrapper.Wrap_In_Place
                 (Bench_Cipher, Key,
                  Msg_Wire_Buf (N_Len + 1 .. Wire_Total), Out_Nonce);
               Msg_Wire_Buf (1 .. N_Len) := Out_Nonce;
            end;
         when Low_NoMAC_Triple =>
            declare
               CT : constant Byte_Array :=
                 Itb.Cipher.Encrypt_Triple
                   (Seed_Noise,
                    Seed_Data1, Seed_Data2, Seed_Data3,
                    Seed_Start1, Seed_Start2, Seed_Start3,
                    Single_Plain.all);
               Wire_Total : constant Stream_Element_Offset :=
                 N_Len + CT'Length;
            begin
               Ensure_Msg_Buffers (Wire_Total, CT'Length);
               Msg_Wire_Buf (N_Len + 1 .. Wire_Total) := CT;
               Itb.Wrapper.Wrap_In_Place
                 (Bench_Cipher, Key,
                  Msg_Wire_Buf (N_Len + 1 .. Wire_Total), Out_Nonce);
               Msg_Wire_Buf (1 .. N_Len) := Out_Nonce;
            end;
         when Low_Auth_Triple =>
            declare
               CT : constant Byte_Array :=
                 Itb.Cipher.Encrypt_Auth_Triple
                   (Seed_Noise,
                    Seed_Data1, Seed_Data2, Seed_Data3,
                    Seed_Start1, Seed_Start2, Seed_Start3,
                    Mac_Handle, Single_Plain.all);
               Wire_Total : constant Stream_Element_Offset :=
                 N_Len + CT'Length;
            begin
               Ensure_Msg_Buffers (Wire_Total, CT'Length);
               Msg_Wire_Buf (N_Len + 1 .. Wire_Total) := CT;
               Itb.Wrapper.Wrap_In_Place
                 (Bench_Cipher, Key,
                  Msg_Wire_Buf (N_Len + 1 .. Wire_Total), Out_Nonce);
               Msg_Wire_Buf (1 .. N_Len) := Out_Nonce;
            end;
      end case;
   end Run_Msg_Encrypt;

   --  Decrypt-direction iter. Refreshes a working wire from the
   --  pristine wire (one memcpy), unwraps in place, then runs the
   --  matching ITB decrypt against the recovered inner ciphertext.
   procedure Run_Msg_Decrypt is
      Key : constant Byte_Array := Cipher_Keys (Bench_Cipher).Key.all;
      Pristine : constant Byte_Buf_Access := Active_Msg_Wire;
      Wire_Total : constant Stream_Element_Offset := Pristine'Length;
      N_Len : constant Stream_Element_Offset :=
        Stream_Element_Offset (Itb.Wrapper.Nonce_Size (Bench_Cipher));
      Body_First : Stream_Element_Offset;
   begin
      Ensure_Msg_Buffers (Wire_Total, Wire_Total);
      Msg_Wire_Buf (1 .. Wire_Total) := Pristine.all;
      Itb.Wrapper.Unwrap_In_Place
        (Bench_Cipher, Key,
         Msg_Wire_Buf (1 .. Wire_Total), Body_First);
      case Active_Msg_Mode is
         when Easy_NoMAC_Single =>
            declare
               PT : constant Byte_Array :=
                 Itb.Encryptor.Decrypt
                   (Enc_Easy_Single,
                    Msg_Wire_Buf (Body_First .. Wire_Total));
            begin
               if PT'Length /= Single_Plain.all'Length then
                  raise Program_Error with "decrypt length mismatch";
               end if;
            end;
         when Easy_Auth_Single =>
            declare
               PT : constant Byte_Array :=
                 Itb.Encryptor.Decrypt_Auth
                   (Enc_Easy_Single,
                    Msg_Wire_Buf (Body_First .. Wire_Total));
            begin
               if PT'Length /= Single_Plain.all'Length then
                  raise Program_Error with "decrypt length mismatch";
               end if;
            end;
         when Low_NoMAC_Single =>
            declare
               PT : constant Byte_Array :=
                 Itb.Cipher.Decrypt
                   (Seed_Noise, Seed_Data1, Seed_Start1,
                    Msg_Wire_Buf (Body_First .. Wire_Total));
            begin
               if PT'Length /= Single_Plain.all'Length then
                  raise Program_Error with "decrypt length mismatch";
               end if;
            end;
         when Low_Auth_Single =>
            declare
               PT : constant Byte_Array :=
                 Itb.Cipher.Decrypt_Auth
                   (Seed_Noise, Seed_Data1, Seed_Start1,
                    Mac_Handle,
                    Msg_Wire_Buf (Body_First .. Wire_Total));
            begin
               if PT'Length /= Single_Plain.all'Length then
                  raise Program_Error with "decrypt length mismatch";
               end if;
            end;
         when Easy_NoMAC_Triple =>
            declare
               PT : constant Byte_Array :=
                 Itb.Encryptor.Decrypt
                   (Enc_Easy_Triple,
                    Msg_Wire_Buf (Body_First .. Wire_Total));
            begin
               if PT'Length /= Single_Plain.all'Length then
                  raise Program_Error with "decrypt length mismatch";
               end if;
            end;
         when Easy_Auth_Triple =>
            declare
               PT : constant Byte_Array :=
                 Itb.Encryptor.Decrypt_Auth
                   (Enc_Easy_Triple,
                    Msg_Wire_Buf (Body_First .. Wire_Total));
            begin
               if PT'Length /= Single_Plain.all'Length then
                  raise Program_Error with "decrypt length mismatch";
               end if;
            end;
         when Low_NoMAC_Triple =>
            declare
               PT : constant Byte_Array :=
                 Itb.Cipher.Decrypt_Triple
                   (Seed_Noise,
                    Seed_Data1, Seed_Data2, Seed_Data3,
                    Seed_Start1, Seed_Start2, Seed_Start3,
                    Msg_Wire_Buf (Body_First .. Wire_Total));
            begin
               if PT'Length /= Single_Plain.all'Length then
                  raise Program_Error with "decrypt length mismatch";
               end if;
            end;
         when Low_Auth_Triple =>
            declare
               PT : constant Byte_Array :=
                 Itb.Cipher.Decrypt_Auth_Triple
                   (Seed_Noise,
                    Seed_Data1, Seed_Data2, Seed_Data3,
                    Seed_Start1, Seed_Start2, Seed_Start3,
                    Mac_Handle,
                    Msg_Wire_Buf (Body_First .. Wire_Total));
            begin
               if PT'Length /= Single_Plain.all'Length then
                  raise Program_Error with "decrypt length mismatch";
               end if;
            end;
      end case;
      pragma Unreferenced (N_Len);
   end Run_Msg_Decrypt;

   ---------------------------------------------------------------------
   --  Streaming — encrypt-direction (full pipeline: stream-encrypt +
   --  wrap-stream-writer) + decrypt-direction (pristine wire refresh +
   --  unwrap-stream-reader + stream-decrypt).
   --
   --  Encrypt cases: each iter runs stream-encrypt over Stream_Plain
   --  into a Memory_Stream (inner ITB transcript), then drives
   --  Wrap_Stream_Writer over the inner transcript to produce the
   --  final on-wire bytes. Two-stage internally because Wrap_Stream
   --  is not a Root_Stream_Type'Class — but both stages run within
   --  the timed loop so the measured time covers ITB encrypt + wrap.
   --
   --  Decrypt cases: setup pre-builds one pristine wire (already
   --  wrap-encrypted). Each iter copies the pristine wire bytes,
   --  drives Unwrap_Stream_Reader to recover the inner ITB
   --  transcript, then runs stream-decrypt over the recovered inner
   --  transcript to obtain the plaintext.
   ---------------------------------------------------------------------

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

   --  Frames a single User-Loop chunk (u32_LE_len || ct) into Buf at
   --  position Used + 1; grows Buf if needed; updates Used. Helper
   --  shared by the encrypt-direction UL drivers below.
   procedure Append_UL_Chunk
     (Buf  : in out Byte_Buf_Access;
      Used : in out Stream_Element_Offset;
      CT   : Byte_Array)
   is
      Need : constant Stream_Element_Offset :=
        Used + Stream_Element_Offset (4) + CT'Length;
      CT_Len_LE : Byte_Array (1 .. 4);
      U32 : constant Unsigned_32 := Unsigned_32 (CT'Length);
   begin
      CT_Len_LE (1) := Stream_Element (U32 and 16#FF#);
      CT_Len_LE (2) := Stream_Element (Shift_Right (U32, 8) and 16#FF#);
      CT_Len_LE (3) := Stream_Element (Shift_Right (U32, 16) and 16#FF#);
      CT_Len_LE (4) := Stream_Element (Shift_Right (U32, 24) and 16#FF#);
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
      Buf (Used + 1 .. Used + CT'Length) := CT;
      Used := Used + CT'Length;
   end Append_UL_Chunk;

   --  Streaming mode selector for run dispatch.
   type Stream_Mode_Sel is
     (AEAD_Easy_IO_Single,  AEAD_Easy_IO_Triple,
      AEAD_Low_IO_Single,   AEAD_Low_IO_Triple,
      UL_Easy_Single,       UL_Easy_Triple,
      UL_Low_Single,        UL_Low_Triple);

   Active_Stream : Stream_Mode_Sel := AEAD_Easy_IO_Single;

   --  Picks the pristine wire that matches the (cipher, mode)
   --  selector for decrypt-direction iters.
   function Active_Stream_Wire return Byte_Buf_Access is
   begin
      case Active_Stream is
         when AEAD_Easy_IO_Single =>
            return Stream_Easy_AEAD_Single_Wires (Bench_Cipher).Wire;
         when AEAD_Easy_IO_Triple =>
            return Stream_Easy_AEAD_Triple_Wires (Bench_Cipher).Wire;
         when AEAD_Low_IO_Single =>
            return Stream_Low_AEAD_Single_Wires (Bench_Cipher).Wire;
         when AEAD_Low_IO_Triple =>
            return Stream_Low_AEAD_Triple_Wires (Bench_Cipher).Wire;
         when UL_Easy_Single =>
            return Stream_Easy_UL_Single_Wires (Bench_Cipher).Wire;
         when UL_Easy_Triple =>
            return Stream_Easy_UL_Triple_Wires (Bench_Cipher).Wire;
         when UL_Low_Single =>
            return Stream_Low_UL_Single_Wires (Bench_Cipher).Wire;
         when UL_Low_Triple =>
            return Stream_Low_UL_Triple_Wires (Bench_Cipher).Wire;
      end case;
   end Active_Stream_Wire;

   --  Encrypt-direction iter: full pipeline. Stage 1 produces the
   --  inner ITB transcript into Inner_Stream (Memory_Stream); stage
   --  2 drives Wrap_Stream_Writer over the transcript to produce
   --  the final wire. Both stages live inside the timed loop.
   procedure Run_Stream_Encrypt is
      Key : constant Byte_Array := Cipher_Keys (Bench_Cipher).Key.all;
      N_Len : constant Stream_Element_Offset :=
        Stream_Element_Offset (Itb.Wrapper.Nonce_Size (Bench_Cipher));
      Out_Nonce : Byte_Array (1 .. N_Len);
      W : Itb.Wrapper.Wrap_Stream_Writer;
      Last : Stream_Element_Offset;
   begin
      --  Stage 1 — produce the inner ITB transcript.
      Inner_Stream.Used := 0;
      case Active_Stream is
         when AEAD_Easy_IO_Single =>
            Source_Stream.Used := 0;
            Source_Stream.Pos  := 1;
            Source_Stream.Write (Stream_Plain.all);
            Reset_Read (Source_Stream);
            Itb.Encryptor.Encrypt_Stream_Auth
              (Enc_Easy_Single, Source_Stream'Access,
               Inner_Stream'Access, Stream_Chunk_Size);
         when AEAD_Easy_IO_Triple =>
            Source_Stream.Used := 0;
            Source_Stream.Pos  := 1;
            Source_Stream.Write (Stream_Plain.all);
            Reset_Read (Source_Stream);
            Itb.Encryptor.Encrypt_Stream_Auth
              (Enc_Easy_Triple, Source_Stream'Access,
               Inner_Stream'Access, Stream_Chunk_Size);
         when AEAD_Low_IO_Single =>
            Source_Stream.Used := 0;
            Source_Stream.Pos  := 1;
            Source_Stream.Write (Stream_Plain.all);
            Reset_Read (Source_Stream);
            Itb.Streams.Encrypt_Stream_Auth
              (Seed_Noise, Seed_Data1, Seed_Start1, Mac_Handle,
               Source_Stream'Access, Inner_Stream'Access,
               Stream_Chunk_Size);
         when AEAD_Low_IO_Triple =>
            Source_Stream.Used := 0;
            Source_Stream.Pos  := 1;
            Source_Stream.Write (Stream_Plain.all);
            Reset_Read (Source_Stream);
            Itb.Streams.Encrypt_Stream_Auth_Triple
              (Seed_Noise,
               Seed_Data1, Seed_Data2, Seed_Data3,
               Seed_Start1, Seed_Start2, Seed_Start3,
               Mac_Handle, Source_Stream'Access, Inner_Stream'Access,
               Stream_Chunk_Size);
         when UL_Easy_Single | UL_Easy_Triple |
              UL_Low_Single  | UL_Low_Triple =>
            --  User-Loop transcripts: encrypt each Stream_Chunk_Size
            --  slice through the matching ITB entry point and frame
            --  as u32_LE_len || ct. Inner_Stream is the framed
            --  transcript sink.
            declare
               Cur : Stream_Element_Offset := Stream_Plain.all'First;
               Used : Stream_Element_Offset := 0;
               Buf : Byte_Buf_Access := new Byte_Array (1 .. 1 * 1024 * 1024);
            begin
               while Cur <= Stream_Plain.all'Last loop
                  declare
                     Take : constant Stream_Element_Offset :=
                       Stream_Element_Offset'Min
                         (Stream_Chunk_Size,
                          Stream_Plain.all'Last - Cur + 1);
                  begin
                     case Active_Stream is
                        when UL_Easy_Single =>
                           declare
                              CT : constant Byte_Array :=
                                Itb.Encryptor.Encrypt
                                  (Enc_Easy_Single,
                                   Stream_Plain.all
                                     (Cur .. Cur + Take - 1));
                           begin
                              Append_UL_Chunk (Buf, Used, CT);
                           end;
                        when UL_Easy_Triple =>
                           declare
                              CT : constant Byte_Array :=
                                Itb.Encryptor.Encrypt
                                  (Enc_Easy_Triple,
                                   Stream_Plain.all
                                     (Cur .. Cur + Take - 1));
                           begin
                              Append_UL_Chunk (Buf, Used, CT);
                           end;
                        when UL_Low_Single =>
                           declare
                              CT : constant Byte_Array :=
                                Itb.Cipher.Encrypt
                                  (Seed_Noise, Seed_Data1, Seed_Start1,
                                   Stream_Plain.all
                                     (Cur .. Cur + Take - 1));
                           begin
                              Append_UL_Chunk (Buf, Used, CT);
                           end;
                        when UL_Low_Triple =>
                           declare
                              CT : constant Byte_Array :=
                                Itb.Cipher.Encrypt_Triple
                                  (Seed_Noise,
                                   Seed_Data1, Seed_Data2, Seed_Data3,
                                   Seed_Start1, Seed_Start2, Seed_Start3,
                                   Stream_Plain.all
                                     (Cur .. Cur + Take - 1));
                           begin
                              Append_UL_Chunk (Buf, Used, CT);
                           end;
                        when others =>
                           null;
                     end case;
                     Cur := Cur + Take;
                  end;
               end loop;
               Inner_Stream.Write (Buf (1 .. Used));
               Free_Buf (Buf);
            end;
      end case;

      --  Stage 2 — wrap the inner transcript into the final wire.
      declare
         N_Inner : constant Stream_Element_Offset := Inner_Stream.Used;
      begin
         Ensure_Iter_Buffers (N_Inner);
         Itb.Wrapper.Initialize (W, Bench_Cipher, Key, Out_Nonce);
         Itb.Wrapper.Update
           (W, Inner_Stream.Buf (1 .. N_Inner),
            Iter_Encrypted (1 .. N_Inner), Last);
         Itb.Wrapper.Close (W);
      end;
   end Run_Stream_Encrypt;

   --  Decrypt-direction iter: refresh the working wire from the
   --  pristine pre-built wire, run unwrap-stream-reader to recover
   --  the inner ITB transcript, then run stream-decrypt to recover
   --  the plaintext.
   procedure Run_Stream_Decrypt is
      Key : constant Byte_Array := Cipher_Keys (Bench_Cipher).Key.all;
      N_Len : constant Stream_Element_Offset :=
        Stream_Element_Offset (Itb.Wrapper.Nonce_Size (Bench_Cipher));
      Pristine : constant Byte_Buf_Access := Active_Stream_Wire;
      Wire_Total : constant Stream_Element_Offset := Pristine'Length;
      Inner_Total : constant Stream_Element_Offset := Wire_Total - N_Len;
      Wire_Nonce : Byte_Array (1 .. N_Len);
      R : Itb.Wrapper.Unwrap_Stream_Reader;
      Last : Stream_Element_Offset;
   begin
      Ensure_Iter_Buffers (Inner_Total);
      --  Capture the wire nonce out of the pristine wire (no need
      --  to re-copy the body — Update reads from Pristine and writes
      --  the recovered inner transcript to Iter_Decrypted).
      Wire_Nonce := Pristine (Pristine'First .. Pristine'First + N_Len - 1);

      Itb.Wrapper.Initialize (R, Bench_Cipher, Key, Wire_Nonce);
      Itb.Wrapper.Update
        (R, Pristine (Pristine'First + N_Len .. Pristine'Last),
         Iter_Decrypted (1 .. Inner_Total), Last);
      Itb.Wrapper.Close (R);

      --  Stage 2 — stream-decrypt the recovered inner transcript.
      Source_Stream.Used := 0;
      Source_Stream.Pos  := 1;
      Source_Stream.Write (Iter_Decrypted (1 .. Inner_Total));
      Reset_Read (Source_Stream);
      Plain_Sink.Used := 0;

      case Active_Stream is
         when AEAD_Easy_IO_Single =>
            Itb.Encryptor.Decrypt_Stream_Auth
              (Enc_Easy_Single, Source_Stream'Access,
               Plain_Sink'Access, Stream_Chunk_Size);
         when AEAD_Easy_IO_Triple =>
            Itb.Encryptor.Decrypt_Stream_Auth
              (Enc_Easy_Triple, Source_Stream'Access,
               Plain_Sink'Access, Stream_Chunk_Size);
         when AEAD_Low_IO_Single =>
            Itb.Streams.Decrypt_Stream_Auth
              (Seed_Noise, Seed_Data1, Seed_Start1, Mac_Handle,
               Source_Stream'Access, Plain_Sink'Access,
               Stream_Chunk_Size);
         when AEAD_Low_IO_Triple =>
            Itb.Streams.Decrypt_Stream_Auth_Triple
              (Seed_Noise,
               Seed_Data1, Seed_Data2, Seed_Data3,
               Seed_Start1, Seed_Start2, Seed_Start3,
               Mac_Handle, Source_Stream'Access, Plain_Sink'Access,
               Stream_Chunk_Size);
         when UL_Easy_Single | UL_Easy_Triple |
              UL_Low_Single  | UL_Low_Triple =>
            --  User-Loop decrypt: read u32_LE_len || ct frames out
            --  of Iter_Decrypted, dispatch each chunk through the
            --  matching ITB decrypt entry point.
            declare
               Pos : Stream_Element_Offset := 1;
               Body_End : constant Stream_Element_Offset := Inner_Total;
            begin
               while Pos + 3 <= Body_End loop
                  declare
                     L0 : constant Unsigned_32 :=
                       Unsigned_32 (Iter_Decrypted (Pos));
                     L1 : constant Unsigned_32 :=
                       Unsigned_32 (Iter_Decrypted (Pos + 1));
                     L2 : constant Unsigned_32 :=
                       Unsigned_32 (Iter_Decrypted (Pos + 2));
                     L3 : constant Unsigned_32 :=
                       Unsigned_32 (Iter_Decrypted (Pos + 3));
                     CT_Len : constant Stream_Element_Offset :=
                       Stream_Element_Offset
                         (L0 or Shift_Left (L1, 8)
                            or Shift_Left (L2, 16)
                            or Shift_Left (L3, 24));
                  begin
                     Pos := Pos + 4;
                     case Active_Stream is
                        when UL_Easy_Single =>
                           declare
                              PT : constant Byte_Array :=
                                Itb.Encryptor.Decrypt
                                  (Enc_Easy_Single,
                                   Iter_Decrypted (Pos .. Pos + CT_Len - 1));
                           begin
                              if PT'Length = 0 then
                                 raise Program_Error
                                   with "decrypt empty chunk";
                              end if;
                           end;
                        when UL_Easy_Triple =>
                           declare
                              PT : constant Byte_Array :=
                                Itb.Encryptor.Decrypt
                                  (Enc_Easy_Triple,
                                   Iter_Decrypted (Pos .. Pos + CT_Len - 1));
                           begin
                              if PT'Length = 0 then
                                 raise Program_Error
                                   with "decrypt empty chunk";
                              end if;
                           end;
                        when UL_Low_Single =>
                           declare
                              PT : constant Byte_Array :=
                                Itb.Cipher.Decrypt
                                  (Seed_Noise, Seed_Data1, Seed_Start1,
                                   Iter_Decrypted (Pos .. Pos + CT_Len - 1));
                           begin
                              if PT'Length = 0 then
                                 raise Program_Error
                                   with "decrypt empty chunk";
                              end if;
                           end;
                        when UL_Low_Triple =>
                           declare
                              PT : constant Byte_Array :=
                                Itb.Cipher.Decrypt_Triple
                                  (Seed_Noise,
                                   Seed_Data1, Seed_Data2, Seed_Data3,
                                   Seed_Start1, Seed_Start2, Seed_Start3,
                                   Iter_Decrypted (Pos .. Pos + CT_Len - 1));
                           begin
                              if PT'Length = 0 then
                                 raise Program_Error
                                   with "decrypt empty chunk";
                              end if;
                           end;
                        when others =>
                           null;
                     end case;
                     Pos := Pos + CT_Len;
                  end;
               end loop;
            end;
      end case;
   end Run_Stream_Decrypt;

   ---------------------------------------------------------------------
   --  Bench-case orchestration.
   ---------------------------------------------------------------------

   Min_Seconds : constant Float := Env_Min_Seconds;

   --  Cipher-name slug for case-name composition. Cycle these strings
   --  in canonical order: aes / chacha / siphash.
   function Cipher_Slug (C : Outer_Cipher) return String is
   begin
      case C is
         when Itb.Wrapper.Aes_128_Ctr => return "aescmac";
         when Itb.Wrapper.Cha_Cha_20  => return "chacha20";
         when Itb.Wrapper.Sip_Hash_24 => return "siphash24";
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
      type Msg_Case is record
         Tag    : access constant String;
         Single : Msg_Mode_Tag;
         Triple : Msg_Mode_Tag;
      end record;
      Easy_Nomac_Tag    : aliased constant String := "easy_nomac";
      Easy_Auth_Tag     : aliased constant String := "easy_auth";
      Low_Nomac_Tag     : aliased constant String := "lowlevel_nomac";
      Low_Auth_Tag      : aliased constant String := "lowlevel_auth";
   begin
      declare
         Modes : constant array (1 .. 4) of Msg_Case :=
           [(Easy_Nomac_Tag'Access, Easy_NoMAC_Single, Easy_NoMAC_Triple),
            (Easy_Auth_Tag'Access,  Easy_Auth_Single,  Easy_Auth_Triple),
            (Low_Nomac_Tag'Access,  Low_NoMAC_Single,  Low_NoMAC_Triple),
            (Low_Auth_Tag'Access,   Low_Auth_Single,   Low_Auth_Triple)];
      begin
         for C in Outer_Cipher loop
            Bench_Cipher := C;
            for M of Modes loop
               --  Single Ouroboros (encrypt + decrypt — full pipeline)
               Active_Msg_Mode := M.Single;
               Measure
                 ("bench_message_single_" & M.Tag.all & "_"
                  & Cipher_Slug (C) & "_encrypt_16mb",
                  Run_Msg_Encrypt'Access,
                  Single_Message_Bytes, Min_Seconds);
               Measure
                 ("bench_message_single_" & M.Tag.all & "_"
                  & Cipher_Slug (C) & "_decrypt_16mb",
                  Run_Msg_Decrypt'Access,
                  Single_Message_Bytes, Min_Seconds);
               --  Triple Ouroboros (encrypt + decrypt — full pipeline)
               Active_Msg_Mode := M.Triple;
               Measure
                 ("bench_message_triple_" & M.Tag.all & "_"
                  & Cipher_Slug (C) & "_encrypt_16mb",
                  Run_Msg_Encrypt'Access,
                  Single_Message_Bytes, Min_Seconds);
               Measure
                 ("bench_message_triple_" & M.Tag.all & "_"
                  & Cipher_Slug (C) & "_decrypt_16mb",
                  Run_Msg_Decrypt'Access,
                  Single_Message_Bytes, Min_Seconds);
            end loop;
         end loop;
      end;
   end Run_Single_Message_Cases;

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
                  Active_Stream := AEAD_Easy_IO_Single;
                  Measure
                    ("bench_stream_single_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_encrypt_64mb",
                     Run_Stream_Encrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
                  Measure
                    ("bench_stream_single_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_decrypt_64mb",
                     Run_Stream_Decrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
                  Active_Stream := AEAD_Easy_IO_Triple;
                  Measure
                    ("bench_stream_triple_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_encrypt_64mb",
                     Run_Stream_Encrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
                  Measure
                    ("bench_stream_triple_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_decrypt_64mb",
                     Run_Stream_Decrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
               when AEAD_Low_IO =>
                  Active_Stream := AEAD_Low_IO_Single;
                  Measure
                    ("bench_stream_single_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_encrypt_64mb",
                     Run_Stream_Encrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
                  Measure
                    ("bench_stream_single_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_decrypt_64mb",
                     Run_Stream_Decrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
                  Active_Stream := AEAD_Low_IO_Triple;
                  Measure
                    ("bench_stream_triple_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_encrypt_64mb",
                     Run_Stream_Encrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
                  Measure
                    ("bench_stream_triple_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_decrypt_64mb",
                     Run_Stream_Decrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
               when NoAEAD_Easy_UL =>
                  Active_Stream := UL_Easy_Single;
                  Measure
                    ("bench_stream_single_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_encrypt_64mb",
                     Run_Stream_Encrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
                  Measure
                    ("bench_stream_single_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_decrypt_64mb",
                     Run_Stream_Decrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
                  Active_Stream := UL_Easy_Triple;
                  Measure
                    ("bench_stream_triple_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_encrypt_64mb",
                     Run_Stream_Encrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
                  Measure
                    ("bench_stream_triple_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_decrypt_64mb",
                     Run_Stream_Decrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
               when NoAEAD_Low_UL =>
                  Active_Stream := UL_Low_Single;
                  Measure
                    ("bench_stream_single_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_encrypt_64mb",
                     Run_Stream_Encrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
                  Measure
                    ("bench_stream_single_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_decrypt_64mb",
                     Run_Stream_Decrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
                  Active_Stream := UL_Low_Triple;
                  Measure
                    ("bench_stream_triple_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_encrypt_64mb",
                     Run_Stream_Encrypt'Access,
                     Stream_Payload_Bytes, Min_Seconds);
                  Measure
                    ("bench_stream_triple_" & Tags (Tag).all & "_"
                     & Cipher_Slug (C) & "_decrypt_64mb",
                     Run_Stream_Decrypt'Access,
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
   Free_Buf (Stream_Plain);
   for C in Outer_Cipher loop
      if Cipher_Keys (C).Key /= null then
         Free_Buf (Cipher_Keys (C).Key);
      end if;
      if Single_Easy_Nomac_Wires (C).Wire /= null then
         Free_Buf (Single_Easy_Nomac_Wires (C).Wire);
      end if;
      if Single_Easy_Auth_Wires (C).Wire /= null then
         Free_Buf (Single_Easy_Auth_Wires (C).Wire);
      end if;
      if Single_Low_Nomac_Wires (C).Wire /= null then
         Free_Buf (Single_Low_Nomac_Wires (C).Wire);
      end if;
      if Single_Low_Auth_Wires (C).Wire /= null then
         Free_Buf (Single_Low_Auth_Wires (C).Wire);
      end if;
      if Triple_Easy_Nomac_Wires (C).Wire /= null then
         Free_Buf (Triple_Easy_Nomac_Wires (C).Wire);
      end if;
      if Triple_Easy_Auth_Wires (C).Wire /= null then
         Free_Buf (Triple_Easy_Auth_Wires (C).Wire);
      end if;
      if Triple_Low_Nomac_Wires (C).Wire /= null then
         Free_Buf (Triple_Low_Nomac_Wires (C).Wire);
      end if;
      if Triple_Low_Auth_Wires (C).Wire /= null then
         Free_Buf (Triple_Low_Auth_Wires (C).Wire);
      end if;
      if Stream_Easy_AEAD_Single_Wires (C).Wire /= null then
         Free_Buf (Stream_Easy_AEAD_Single_Wires (C).Wire);
      end if;
      if Stream_Easy_AEAD_Triple_Wires (C).Wire /= null then
         Free_Buf (Stream_Easy_AEAD_Triple_Wires (C).Wire);
      end if;
      if Stream_Low_AEAD_Single_Wires (C).Wire /= null then
         Free_Buf (Stream_Low_AEAD_Single_Wires (C).Wire);
      end if;
      if Stream_Low_AEAD_Triple_Wires (C).Wire /= null then
         Free_Buf (Stream_Low_AEAD_Triple_Wires (C).Wire);
      end if;
      if Stream_Easy_UL_Single_Wires (C).Wire /= null then
         Free_Buf (Stream_Easy_UL_Single_Wires (C).Wire);
      end if;
      if Stream_Easy_UL_Triple_Wires (C).Wire /= null then
         Free_Buf (Stream_Easy_UL_Triple_Wires (C).Wire);
      end if;
      if Stream_Low_UL_Single_Wires (C).Wire /= null then
         Free_Buf (Stream_Low_UL_Single_Wires (C).Wire);
      end if;
      if Stream_Low_UL_Triple_Wires (C).Wire /= null then
         Free_Buf (Stream_Low_UL_Triple_Wires (C).Wire);
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
   if Msg_Wire_Buf /= null then
      Free_Buf (Msg_Wire_Buf);
   end if;
   if Msg_Plain_Buf /= null then
      Free_Buf (Msg_Plain_Buf);
   end if;
   Free (Source_Stream);
   Free (Sink_Stream);
   Free (Inner_Stream);
   Free (Plain_Sink);
end Bench_Wrapper;
