--  Body of Common — Go-bench-style runner shared between the two
--  bench mains. Mirrors bindings/rust/benches/common.rs and
--  bindings/csharp/Itb.Bench/Common.cs. See the spec for the full
--  contract.

with Ada.Calendar;
with Ada.Environment_Variables;
with Ada.Real_Time;
with Ada.Streams;             use Ada.Streams;
with Ada.Strings.Fixed;
with Ada.Text_IO;

with Interfaces;              use Interfaces;

package body Common is

   --  Module-local mutable LCG state. Seeded from wall-clock micros
   --  on first call so successive bench runs produce different
   --  payloads. The xorshift+LCG mix follows the Phase-5 Token_Bytes
   --  helper byte-for-byte.
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

   ---------------------------------------------------------------------
   --  Environment readers
   ---------------------------------------------------------------------

   function Env_Get (Name : String) return String is
   begin
      if Ada.Environment_Variables.Exists (Name) then
         return Ada.Environment_Variables.Value (Name);
      else
         return "";
      end if;
   end Env_Get;

   function Env_Nonce_Bits (Default : Integer := 128) return Integer is
      V : constant String := Env_Get ("ITB_NONCE_BITS");
   begin
      if V = "" then
         return Default;
      end if;
      if V = "128" then
         return 128;
      elsif V = "256" then
         return 256;
      elsif V = "512" then
         return 512;
      else
         Ada.Text_IO.Put_Line
           (Ada.Text_IO.Standard_Error,
            "ITB_NONCE_BITS=""" & V
            & """ invalid (expected 128/256/512); using"
            & Default'Image);
         return Default;
      end if;
   end Env_Nonce_Bits;

   function Env_Lock_Seed return Boolean is
      V : constant String := Env_Get ("ITB_LOCKSEED");
   begin
      if V = "" then
         return False;
      end if;
      return V /= "0";
   end Env_Lock_Seed;

   function Env_Filter return String is
   begin
      return Env_Get ("ITB_BENCH_FILTER");
   end Env_Filter;

   function Env_Filter_Set return Boolean is
   begin
      return Ada.Environment_Variables.Exists ("ITB_BENCH_FILTER")
        and then Ada.Environment_Variables.Value ("ITB_BENCH_FILTER") /= "";
   end Env_Filter_Set;

   function Env_Min_Seconds return Float is
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

   ---------------------------------------------------------------------
   --  Random byte generator
   ---------------------------------------------------------------------

   function Random_Bytes
     (N : Stream_Element_Offset) return Itb.Byte_Array
   is
      Out_Buf : Itb.Byte_Array (1 .. N);
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
   --  Encryptor helper
   ---------------------------------------------------------------------

   procedure Apply_Lock_Seed_If_Requested
     (Enc : Itb.Encryptor.Encryptor)
   is
   begin
      if Env_Lock_Seed then
         Itb.Encryptor.Set_Lock_Seed (Enc, 1);
      end if;
   end Apply_Lock_Seed_If_Requested;

   ---------------------------------------------------------------------
   --  Convergence loop and reporter
   ---------------------------------------------------------------------

   --  Iteration cap mirroring Rust's `1u64 << 24` ceiling — guards
   --  against runaway doubling on a very fast op.
   Iter_Cap : constant Natural := 16#1000000#;

   --  Right-pad String to width W (truncates if longer). Ada.Text_IO
   --  has no built-in column-aligned formatter for arbitrary-width
   --  String fields, so this small helper covers the
   --  ``%-60s`` Go-print equivalent.
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

   --  Format a Long_Float with K decimal places. Used to produce the
   --  ``ns/op`` (K = 1) and ``MB/s`` (K = 2) columns byte-for-byte
   --  matching the Rust / C# Go-bench-style report. Negative values
   --  are not expected (timing / throughput) but are handled
   --  defensively to avoid exceptions on a degenerate measurement.
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
         --  Round-half-up via +0.5 then truncating cast.
         Scaled : constant Long_Float := Mag * Scale + 0.5;
         N      : constant Long_Long_Integer := Long_Long_Integer (Scaled);
         --  N could be slightly above the rounded value if the cast
         --  performs banker's rounding; correct any over-shoot.
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

   function Format_F1 (X : Float) return String is
   begin
      return Format_Fixed (Long_Float (X), 1);
   end Format_F1;

   function Format_F2 (X : Float) return String is
   begin
      return Format_Fixed (Long_Float (X), 2);
   end Format_F2;

   --  Run the per-iter cipher body once, dispatching on B.Op. Pulled
   --  out of Measure so the warm-up call and the measured loop share
   --  one definition.
   procedure Run_Once (B : Bench_Case) is
   begin
      case B.Op is
         when Op_Encrypt =>
            declare
               Ct : constant Itb.Byte_Array :=
                 Itb.Encryptor.Encrypt (B.Enc.all, B.Payload.all);
               pragma Unreferenced (Ct);
            begin
               null;
            end;
         when Op_Decrypt =>
            declare
               Pt : constant Itb.Byte_Array :=
                 Itb.Encryptor.Decrypt (B.Enc.all, B.Cipher.all);
               pragma Unreferenced (Pt);
            begin
               null;
            end;
         when Op_Encrypt_Auth =>
            declare
               Ct : constant Itb.Byte_Array :=
                 Itb.Encryptor.Encrypt_Auth (B.Enc.all, B.Payload.all);
               pragma Unreferenced (Ct);
            begin
               null;
            end;
         when Op_Decrypt_Auth =>
            declare
               Pt : constant Itb.Byte_Array :=
                 Itb.Encryptor.Decrypt_Auth (B.Enc.all, B.Cipher.all);
               pragma Unreferenced (Pt);
            begin
               null;
            end;
      end case;
   end Run_Once;

   procedure Run_N (B : Bench_Case; N : Natural) is
   begin
      for K in 1 .. N loop
         pragma Unreferenced (K);
         Run_Once (B);
      end loop;
   end Run_N;

   procedure Measure (B : Bench_Case; Min_Seconds : Float) is
      use Ada.Real_Time;
      Min_Ns      : constant Float := Min_Seconds * 1.0E9;
      Iters       : Natural := 1;
      Elapsed_Ns  : Float := 0.0;
      T0          : Time;
      Span        : Time_Span;
   begin
      --  Warm-up — one iteration to hit cache / cold-start transients
      --  before the measured loop.
      Run_Once (B);

      loop
         T0 := Clock;
         Run_N (B, Iters);
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
            then (Float (B.Payload_Bytes) / (Ns_Per_Op / 1.0E9)) /
                 Float (1024 * 1024)
            else 0.0);
         Iters_S   : constant String :=
           Ada.Strings.Fixed.Trim (Natural'Image (Iters), Ada.Strings.Both);
      begin
         --  Mirrors `BenchmarkX-8     N    ns/op    MB/s` Go format,
         --  column-aligned for human reading. The trailing tab + ASCII
         --  whitespace pattern matches Rust / C# output byte-for-byte.
         Ada.Text_IO.Put_Line
           (Pad_Right (B.Name.all, 60)
            & ASCII.HT & Pad_Left (Iters_S, 10)
            & ASCII.HT & Pad_Left (Format_F1 (Ns_Per_Op), 14) & " ns/op"
            & ASCII.HT & Pad_Left (Format_F2 (MB_Per_S), 9) & " MB/s");
      end;
   end Measure;

   --  True when Hay contains Needle as a substring (used by the
   --  ITB_BENCH_FILTER case-name filter). Empty Needle matches every
   --  case — the runner separately gates on Env_Filter_Set so an
   --  unset variable does not fall through to the empty-needle path.
   function Contains (Hay : String; Needle : String) return Boolean is
   begin
      if Needle'Length = 0 then
         return True;
      end if;
      if Hay'Length < Needle'Length then
         return False;
      end if;
      for I in Hay'First .. Hay'Last - Needle'Length + 1 loop
         if Hay (I .. I + Needle'Length - 1) = Needle then
            return True;
         end if;
      end loop;
      return False;
   end Contains;

   procedure Run_All (Cases : Bench_Case_Array) is
      Filter      : constant String  := Env_Filter;
      Filter_On   : constant Boolean := Env_Filter_Set;
      Min_Seconds : constant Float   := Env_Min_Seconds;
      Selected_Ct : Natural := 0;
      Payload_Sz  : Stream_Element_Offset := 0;
   begin
      --  Pre-count selected cases so the harness banner reports the
      --  exact number of cases that will run, not the total count.
      for C of Cases loop
         if not Filter_On or else Contains (C.Name.all, Filter) then
            Selected_Ct := Selected_Ct + 1;
            if Payload_Sz = 0 then
               Payload_Sz := C.Payload_Bytes;
            end if;
         end if;
      end loop;

      if Selected_Ct = 0 then
         Ada.Text_IO.Put_Line
           (Ada.Text_IO.Standard_Error,
            "no bench cases match filter """ & Filter & """");
         return;
      end if;

      declare
         Min_S_Img : constant String :=
           Ada.Strings.Fixed.Trim
             (Integer'Image (Integer (Min_Seconds)), Ada.Strings.Both);
         Sel_Img   : constant String :=
           Ada.Strings.Fixed.Trim
             (Natural'Image (Selected_Ct), Ada.Strings.Both);
         Pay_Img   : constant String :=
           Ada.Strings.Fixed.Trim
             (Stream_Element_Offset'Image (Payload_Sz), Ada.Strings.Both);
      begin
         Ada.Text_IO.Put_Line
           ("# benchmarks=" & Sel_Img
            & " payload_bytes=" & Pay_Img
            & " min_seconds=" & Min_S_Img);
      end;

      for C of Cases loop
         if not Filter_On or else Contains (C.Name.all, Filter) then
            Measure (C, Min_Seconds);
         end if;
      end loop;
   end Run_All;

end Common;
