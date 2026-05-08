--  Streaming benchmarks for the Ada binding.
--
--  Sixteen cases covering the (Mode x Width x Op x Variant) matrix:
--    Mode      = Easy / Low-Level
--    Width     = Single / Triple Ouroboros
--    Op        = Encrypt / Decrypt
--    Variant   = AEAD IO / UserLoop
--
--  Every case streams a 64 MiB CSPRNG payload through 16 MiB chunks at
--  the Areion-SoEM-512 / 1024-bit ITB key / HMAC-BLAKE3 MAC config.
--  CSPRNG payload generation, encryptor / Seed / MAC construction, and
--  pre-encryption for the decrypt arms run outside the timer.
--
--  AEAD IO drives the binding's authenticated streaming entry points:
--    - Easy:      Itb.Encryptor.Encrypt_Stream_Auth /
--                 Itb.Encryptor.Decrypt_Stream_Auth
--    - Low-Level: Itb.Streams.Encrypt_Stream_Auth        /
--                 Itb.Streams.Decrypt_Stream_Auth
--                 (Triple counterparts: *_Triple)
--
--  UserLoop drives the plain (no-MAC) chunked stream entry points:
--    - Easy:      Itb.Encryptor.Encrypt_Stream /
--                 Itb.Encryptor.Decrypt_Stream
--    - Low-Level: Itb.Streams.Encrypt_Stream /
--                 Itb.Streams.Decrypt_Stream
--                 (Triple counterparts: *_Triple)
--
--  Output mirrors Common's Go-bench-style line per case.
--
--  Run with::
--
--      gprbuild -P itb_bench.gpr
--      ./obj-bench/bench_stream
--
--  The harness emits one line per case (name, iters, ns/op, MB/s) so
--  the orchestrator can grep / parse the same way it does for
--  bench_single / bench_triple.

with Ada.Calendar;
with Ada.Environment_Variables;
with Ada.Real_Time;
with Ada.Streams;          use Ada.Streams;
with Ada.Strings.Fixed;
with Ada.Text_IO;
with Ada.Unchecked_Deallocation;

with Interfaces;           use Interfaces;

with Itb;                  use Itb;
with Itb.Encryptor;
with Itb.MAC;
with Itb.Seed;
with Itb.Streams;

procedure Bench_Stream is

   ---------------------------------------------------------------------
   --  Configuration constants (lock-step across language bindings).
   ---------------------------------------------------------------------

   Stream_Primitive : constant String := "areion512";
   Mac_Name         : constant String := "hmac-blake3";
   Key_Bits         : constant Integer := 1024;

   Stream_Payload_Bytes : constant Stream_Element_Offset :=
     Stream_Element_Offset (64 * 1024 * 1024);
   Stream_Chunk_Size    : constant Stream_Element_Offset :=
     Stream_Element_Offset (16 * 1024 * 1024);

   ---------------------------------------------------------------------
   --  Ada.Streams-conformant Memory_Stream (heap-backed). Read drains
   --  forward from Pos; Write appends to Used and grows Buf via *2 on
   --  overflow. Used by every bench case as in-memory Source / Sink so
   --  the measured iter loop is bound to the cipher path only.
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

   --  Reset Used + Pos to drop accumulated written data without
   --  reallocating Buf (so iter loops can reuse the same heap buffer
   --  for the per-iter Sink).
   procedure Reset_Write (S : in out Memory_Stream'Class);

   procedure Reset_Write (S : in out Memory_Stream'Class) is
   begin
      S.Used := 0;
      S.Pos  := 1;
   end Reset_Write;

   ---------------------------------------------------------------------
   --  CSPRNG-flavoured payload generator (Calendar-mixed LCG, mirrors
   --  Common.Random_Bytes).
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
   --  Small Go-bench-style timing harness — duplicates Common's
   --  Measure body so this bench can dispatch directly into the
   --  per-case streaming primitives without going through the
   --  Bench_Op enum (which has only Encrypt / Decrypt / Encrypt_Auth /
   --  Decrypt_Auth ops, none of which match the streaming surface).
   ---------------------------------------------------------------------

   --  Shared body type for streaming bench cases. The closure captures
   --  the encryptor / Seeds / MAC / payload / pre-encrypted transcript
   --  and runs the per-iter cipher pass exactly once when called.
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

   --  Iteration cap mirrors Common's, prevents runaway doubling on
   --  pathologically fast operations.
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
      --  Warm-up — one iter to absorb cold-cache transients.
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
           (Pad_Right (Name, 60)
            & ASCII.HT & Pad_Left (Iters_S, 10)
            & ASCII.HT & Pad_Left (Format_Fixed (Long_Float (Ns_Per_Op), 1), 14) & " ns/op"
            & ASCII.HT & Pad_Left (Format_Fixed (Long_Float (MB_Per_S), 2), 9) & " MB/s");
      end;
   end Measure;

   ---------------------------------------------------------------------
   --  Library-wide encryptor / Seed / MAC handles. Constructed once at
   --  elaboration; reused across every iteration of every case.
   ---------------------------------------------------------------------

   --  Easy Mode encryptors (Single + Triple).
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

   --  Low-Level Mode Seeds + MAC. Three Seeds per Single case, seven
   --  Seeds per Triple case (one Noise + three Data + three Start).
   --  Declared as renames of constructed-once limited values; the
   --  underlying Seed handle is mutable inside libitb but the local
   --  binding never reassigns the Ada wrapper.
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

   Mac_Handle : constant Itb.MAC.MAC :=
     Itb.MAC.Make (Mac_Name, Make_MAC_Key);

   ---------------------------------------------------------------------
   --  Shared per-case state (in-memory streams + payload + pre-
   --  encrypted transcripts). Live as library-level globals so the
   --  Run_Once closures can address them through their nested-
   --  procedure access.
   ---------------------------------------------------------------------

   Payload_Bytes : Byte_Buf_Access :=
     Random_Bytes (Stream_Payload_Bytes);

   --  Working in-memory streams. Reused across every iter of every
   --  case (Reset_Write to drop accumulated bytes). Heap-backed so
   --  the 64 MiB payload + ~80 MiB ciphertext fit comfortably.
   Source_Stream : aliased Memory_Stream;
   Sink_Stream   : aliased Memory_Stream;

   --  Pre-encrypted transcripts for the eight decrypt cases, computed
   --  once at elaboration outside every measurement loop.
   Transcript_Easy_AEAD_Single  : aliased Memory_Stream;
   Transcript_Easy_AEAD_Triple  : aliased Memory_Stream;
   Transcript_Easy_Plain_Single : aliased Memory_Stream;
   Transcript_Easy_Plain_Triple : aliased Memory_Stream;
   Transcript_Low_AEAD_Single   : aliased Memory_Stream;
   Transcript_Low_AEAD_Triple   : aliased Memory_Stream;
   Transcript_Low_Plain_Single  : aliased Memory_Stream;
   Transcript_Low_Plain_Triple  : aliased Memory_Stream;

   ---------------------------------------------------------------------
   --  Per-case Run_Once bodies. Each implements one cell of the 4 x 2 x 2
   --  matrix (Mode x Width x Op x Variant). Source / Sink are reset at
   --  the start of each iter so the timed loop measures only the
   --  cipher path.
   ---------------------------------------------------------------------

   procedure Init_Source is
   begin
      Reset_Write (Source_Stream);
      Source_Stream.Write (Payload_Bytes.all);
      Reset_Read (Source_Stream);
   end Init_Source;

   procedure Reset_Sink is
   begin
      Reset_Write (Sink_Stream);
   end Reset_Sink;

   ---------------------------------------------------------------------
   --  Easy Mode -- Streaming AEAD (AEAD IO).
   ---------------------------------------------------------------------

   procedure Run_Easy_Single_AEAD_Encrypt is
   begin
      Init_Source;
      Reset_Sink;
      Itb.Encryptor.Encrypt_Stream_Auth
        (Enc_Easy_Single, Source_Stream'Access, Sink_Stream'Access,
         Stream_Chunk_Size);
   end Run_Easy_Single_AEAD_Encrypt;

   procedure Run_Easy_Single_AEAD_Decrypt is
   begin
      Reset_Read (Transcript_Easy_AEAD_Single);
      Reset_Sink;
      Itb.Encryptor.Decrypt_Stream_Auth
        (Enc_Easy_Single, Transcript_Easy_AEAD_Single'Access,
         Sink_Stream'Access, Stream_Chunk_Size);
   end Run_Easy_Single_AEAD_Decrypt;

   procedure Run_Easy_Triple_AEAD_Encrypt is
   begin
      Init_Source;
      Reset_Sink;
      Itb.Encryptor.Encrypt_Stream_Auth
        (Enc_Easy_Triple, Source_Stream'Access, Sink_Stream'Access,
         Stream_Chunk_Size);
   end Run_Easy_Triple_AEAD_Encrypt;

   procedure Run_Easy_Triple_AEAD_Decrypt is
   begin
      Reset_Read (Transcript_Easy_AEAD_Triple);
      Reset_Sink;
      Itb.Encryptor.Decrypt_Stream_Auth
        (Enc_Easy_Triple, Transcript_Easy_AEAD_Triple'Access,
         Sink_Stream'Access, Stream_Chunk_Size);
   end Run_Easy_Triple_AEAD_Decrypt;

   ---------------------------------------------------------------------
   --  Easy Mode -- plain stream (UserLoop).
   ---------------------------------------------------------------------

   procedure Run_Easy_Single_UserLoop_Encrypt is
   begin
      Init_Source;
      Reset_Sink;
      Itb.Encryptor.Encrypt_Stream
        (Enc_Easy_Single, Source_Stream'Access, Sink_Stream'Access,
         Stream_Chunk_Size);
   end Run_Easy_Single_UserLoop_Encrypt;

   procedure Run_Easy_Single_UserLoop_Decrypt is
   begin
      Reset_Read (Transcript_Easy_Plain_Single);
      Reset_Sink;
      Itb.Encryptor.Decrypt_Stream
        (Enc_Easy_Single, Transcript_Easy_Plain_Single'Access,
         Sink_Stream'Access, Stream_Chunk_Size);
   end Run_Easy_Single_UserLoop_Decrypt;

   procedure Run_Easy_Triple_UserLoop_Encrypt is
   begin
      Init_Source;
      Reset_Sink;
      Itb.Encryptor.Encrypt_Stream
        (Enc_Easy_Triple, Source_Stream'Access, Sink_Stream'Access,
         Stream_Chunk_Size);
   end Run_Easy_Triple_UserLoop_Encrypt;

   procedure Run_Easy_Triple_UserLoop_Decrypt is
   begin
      Reset_Read (Transcript_Easy_Plain_Triple);
      Reset_Sink;
      Itb.Encryptor.Decrypt_Stream
        (Enc_Easy_Triple, Transcript_Easy_Plain_Triple'Access,
         Sink_Stream'Access, Stream_Chunk_Size);
   end Run_Easy_Triple_UserLoop_Decrypt;

   ---------------------------------------------------------------------
   --  Low-Level Mode -- Streaming AEAD (AEAD IO).
   ---------------------------------------------------------------------

   procedure Run_Low_Single_AEAD_Encrypt is
   begin
      Init_Source;
      Reset_Sink;
      Itb.Streams.Encrypt_Stream_Auth
        (Seed_Noise, Seed_Data1, Seed_Start1, Mac_Handle,
         Source_Stream'Access, Sink_Stream'Access,
         Stream_Chunk_Size);
   end Run_Low_Single_AEAD_Encrypt;

   procedure Run_Low_Single_AEAD_Decrypt is
   begin
      Reset_Read (Transcript_Low_AEAD_Single);
      Reset_Sink;
      Itb.Streams.Decrypt_Stream_Auth
        (Seed_Noise, Seed_Data1, Seed_Start1, Mac_Handle,
         Transcript_Low_AEAD_Single'Access,
         Sink_Stream'Access, Stream_Chunk_Size);
   end Run_Low_Single_AEAD_Decrypt;

   procedure Run_Low_Triple_AEAD_Encrypt is
   begin
      Init_Source;
      Reset_Sink;
      Itb.Streams.Encrypt_Stream_Auth_Triple
        (Seed_Noise,
         Seed_Data1, Seed_Data2, Seed_Data3,
         Seed_Start1, Seed_Start2, Seed_Start3,
         Mac_Handle,
         Source_Stream'Access, Sink_Stream'Access,
         Stream_Chunk_Size);
   end Run_Low_Triple_AEAD_Encrypt;

   procedure Run_Low_Triple_AEAD_Decrypt is
   begin
      Reset_Read (Transcript_Low_AEAD_Triple);
      Reset_Sink;
      Itb.Streams.Decrypt_Stream_Auth_Triple
        (Seed_Noise,
         Seed_Data1, Seed_Data2, Seed_Data3,
         Seed_Start1, Seed_Start2, Seed_Start3,
         Mac_Handle,
         Transcript_Low_AEAD_Triple'Access,
         Sink_Stream'Access, Stream_Chunk_Size);
   end Run_Low_Triple_AEAD_Decrypt;

   ---------------------------------------------------------------------
   --  Low-Level Mode -- plain stream (UserLoop).
   ---------------------------------------------------------------------

   procedure Run_Low_Single_UserLoop_Encrypt is
   begin
      Init_Source;
      Reset_Sink;
      Itb.Streams.Encrypt_Stream
        (Seed_Noise, Seed_Data1, Seed_Start1,
         Source_Stream'Access, Sink_Stream'Access,
         Stream_Chunk_Size);
   end Run_Low_Single_UserLoop_Encrypt;

   procedure Run_Low_Single_UserLoop_Decrypt is
   begin
      Reset_Read (Transcript_Low_Plain_Single);
      Reset_Sink;
      Itb.Streams.Decrypt_Stream
        (Seed_Noise, Seed_Data1, Seed_Start1,
         Transcript_Low_Plain_Single'Access,
         Sink_Stream'Access, Stream_Chunk_Size);
   end Run_Low_Single_UserLoop_Decrypt;

   procedure Run_Low_Triple_UserLoop_Encrypt is
   begin
      Init_Source;
      Reset_Sink;
      Itb.Streams.Encrypt_Stream_Triple
        (Seed_Noise,
         Seed_Data1, Seed_Data2, Seed_Data3,
         Seed_Start1, Seed_Start2, Seed_Start3,
         Source_Stream'Access, Sink_Stream'Access,
         Stream_Chunk_Size);
   end Run_Low_Triple_UserLoop_Encrypt;

   procedure Run_Low_Triple_UserLoop_Decrypt is
   begin
      Reset_Read (Transcript_Low_Plain_Triple);
      Reset_Sink;
      Itb.Streams.Decrypt_Stream_Triple
        (Seed_Noise,
         Seed_Data1, Seed_Data2, Seed_Data3,
         Seed_Start1, Seed_Start2, Seed_Start3,
         Transcript_Low_Plain_Triple'Access,
         Sink_Stream'Access, Stream_Chunk_Size);
   end Run_Low_Triple_UserLoop_Decrypt;

   ---------------------------------------------------------------------
   --  Pre-encrypt the eight decrypt-side transcripts at startup.
   ---------------------------------------------------------------------

   procedure Pre_Encrypt_All is
      Src : aliased Memory_Stream;
   begin
      Src.Write (Payload_Bytes.all);

      Reset_Read (Src);
      Itb.Encryptor.Encrypt_Stream_Auth
        (Enc_Easy_Single, Src'Access, Transcript_Easy_AEAD_Single'Access,
         Stream_Chunk_Size);

      Reset_Read (Src);
      Itb.Encryptor.Encrypt_Stream_Auth
        (Enc_Easy_Triple, Src'Access, Transcript_Easy_AEAD_Triple'Access,
         Stream_Chunk_Size);

      Reset_Read (Src);
      Itb.Encryptor.Encrypt_Stream
        (Enc_Easy_Single, Src'Access, Transcript_Easy_Plain_Single'Access,
         Stream_Chunk_Size);

      Reset_Read (Src);
      Itb.Encryptor.Encrypt_Stream
        (Enc_Easy_Triple, Src'Access, Transcript_Easy_Plain_Triple'Access,
         Stream_Chunk_Size);

      Reset_Read (Src);
      Itb.Streams.Encrypt_Stream_Auth
        (Seed_Noise, Seed_Data1, Seed_Start1, Mac_Handle,
         Src'Access, Transcript_Low_AEAD_Single'Access,
         Stream_Chunk_Size);

      Reset_Read (Src);
      Itb.Streams.Encrypt_Stream_Auth_Triple
        (Seed_Noise,
         Seed_Data1, Seed_Data2, Seed_Data3,
         Seed_Start1, Seed_Start2, Seed_Start3,
         Mac_Handle,
         Src'Access, Transcript_Low_AEAD_Triple'Access,
         Stream_Chunk_Size);

      Reset_Read (Src);
      Itb.Streams.Encrypt_Stream
        (Seed_Noise, Seed_Data1, Seed_Start1,
         Src'Access, Transcript_Low_Plain_Single'Access,
         Stream_Chunk_Size);

      Reset_Read (Src);
      Itb.Streams.Encrypt_Stream_Triple
        (Seed_Noise,
         Seed_Data1, Seed_Data2, Seed_Data3,
         Seed_Start1, Seed_Start2, Seed_Start3,
         Src'Access, Transcript_Low_Plain_Triple'Access,
         Stream_Chunk_Size);

      Free (Src);
   end Pre_Encrypt_All;

   Min_Seconds : constant Float := Env_Min_Seconds;

begin
   Itb.Set_Max_Workers (0);
   Itb.Set_Nonce_Bits (128);

   declare
      Kb_Img       : constant String :=
        Ada.Strings.Fixed.Trim
          (Integer'Image (Key_Bits), Ada.Strings.Both);
      Pay_Img      : constant String :=
        Ada.Strings.Fixed.Trim
          (Stream_Element_Offset'Image (Stream_Payload_Bytes),
           Ada.Strings.Both);
      Chunk_Img    : constant String :=
        Ada.Strings.Fixed.Trim
          (Stream_Element_Offset'Image (Stream_Chunk_Size),
           Ada.Strings.Both);
      Min_S_Img    : constant String :=
        Ada.Strings.Fixed.Trim
          (Integer'Image (Integer (Min_Seconds)), Ada.Strings.Both);
   begin
      Ada.Text_IO.Put_Line
        ("# stream primitive=" & Stream_Primitive
         & " key_bits=" & Kb_Img
         & " mac=" & Mac_Name
         & " payload_bytes=" & Pay_Img
         & " chunk_size=" & Chunk_Img
         & " min_seconds=" & Min_S_Img
         & " workers=auto");
      Ada.Text_IO.Put_Line
        ("# benchmarks=16 payload_bytes=" & Pay_Img
         & " min_seconds=" & Min_S_Img);
   end;

   Pre_Encrypt_All;

   --  Run the 16 cases. The naming pattern follows the cross-binding
   --  convention bench_stream_<width>_<key_bits>_<mode>_<op>_<variant>.

   Measure ("bench_stream_single_1024bit_easy_aead_io_encrypt_64mb",
            Run_Easy_Single_AEAD_Encrypt'Access,
            Stream_Payload_Bytes, Min_Seconds);
   Measure ("bench_stream_single_1024bit_easy_user_loop_encrypt_64mb",
            Run_Easy_Single_UserLoop_Encrypt'Access,
            Stream_Payload_Bytes, Min_Seconds);
   Measure ("bench_stream_single_1024bit_easy_aead_io_decrypt_64mb",
            Run_Easy_Single_AEAD_Decrypt'Access,
            Stream_Payload_Bytes, Min_Seconds);
   Measure ("bench_stream_single_1024bit_easy_user_loop_decrypt_64mb",
            Run_Easy_Single_UserLoop_Decrypt'Access,
            Stream_Payload_Bytes, Min_Seconds);

   Measure ("bench_stream_triple_1024bit_easy_aead_io_encrypt_64mb",
            Run_Easy_Triple_AEAD_Encrypt'Access,
            Stream_Payload_Bytes, Min_Seconds);
   Measure ("bench_stream_triple_1024bit_easy_user_loop_encrypt_64mb",
            Run_Easy_Triple_UserLoop_Encrypt'Access,
            Stream_Payload_Bytes, Min_Seconds);
   Measure ("bench_stream_triple_1024bit_easy_aead_io_decrypt_64mb",
            Run_Easy_Triple_AEAD_Decrypt'Access,
            Stream_Payload_Bytes, Min_Seconds);
   Measure ("bench_stream_triple_1024bit_easy_user_loop_decrypt_64mb",
            Run_Easy_Triple_UserLoop_Decrypt'Access,
            Stream_Payload_Bytes, Min_Seconds);

   Measure ("bench_stream_single_1024bit_low_level_aead_io_encrypt_64mb",
            Run_Low_Single_AEAD_Encrypt'Access,
            Stream_Payload_Bytes, Min_Seconds);
   Measure ("bench_stream_single_1024bit_low_level_user_loop_encrypt_64mb",
            Run_Low_Single_UserLoop_Encrypt'Access,
            Stream_Payload_Bytes, Min_Seconds);
   Measure ("bench_stream_single_1024bit_low_level_aead_io_decrypt_64mb",
            Run_Low_Single_AEAD_Decrypt'Access,
            Stream_Payload_Bytes, Min_Seconds);
   Measure ("bench_stream_single_1024bit_low_level_user_loop_decrypt_64mb",
            Run_Low_Single_UserLoop_Decrypt'Access,
            Stream_Payload_Bytes, Min_Seconds);

   Measure ("bench_stream_triple_1024bit_low_level_aead_io_encrypt_64mb",
            Run_Low_Triple_AEAD_Encrypt'Access,
            Stream_Payload_Bytes, Min_Seconds);
   Measure ("bench_stream_triple_1024bit_low_level_user_loop_encrypt_64mb",
            Run_Low_Triple_UserLoop_Encrypt'Access,
            Stream_Payload_Bytes, Min_Seconds);
   Measure ("bench_stream_triple_1024bit_low_level_aead_io_decrypt_64mb",
            Run_Low_Triple_AEAD_Decrypt'Access,
            Stream_Payload_Bytes, Min_Seconds);
   Measure ("bench_stream_triple_1024bit_low_level_user_loop_decrypt_64mb",
            Run_Low_Triple_UserLoop_Decrypt'Access,
            Stream_Payload_Bytes, Min_Seconds);

   --  Final cleanup of allocated buffers.
   if Payload_Bytes /= null then
      Free_Buf (Payload_Bytes);
   end if;
   Free (Source_Stream);
   Free (Sink_Stream);
   Free (Transcript_Easy_AEAD_Single);
   Free (Transcript_Easy_AEAD_Triple);
   Free (Transcript_Easy_Plain_Single);
   Free (Transcript_Easy_Plain_Triple);
   Free (Transcript_Low_AEAD_Single);
   Free (Transcript_Low_AEAD_Triple);
   Free (Transcript_Low_Plain_Single);
   Free (Transcript_Low_Plain_Triple);
end Bench_Stream;
