--  Long-run stress harness. The loop utility holds one Pipeline
--  handle per exercised cipher surface for minutes, hammers it with
--  concurrent encrypt -> decrypt -> compare round-trips from N worker
--  tasks, rotates the outer masters and reopens the handle from its
--  session blob on a schedule, and reports whether the process
--  survived with every byte intact. It is the Ada binding's
--  counterpart of the Go harness under tools/loop: the same flags,
--  the same round structure, the same summary in both renderings.
--
--  The default shape is full production: the Streaming AEAD profile
--  with parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512
--  inner hash, 1024-bit keys, and the compile-in 512-bit nonce width,
--  driven through a stream session by three workers for five minutes
--  on 16 MiB plaintexts. Every worker owns a distinct
--  CSPRNG-generated plaintext held for the whole run, so any
--  cross-call state leakage inside the Pipeline surfaces as a data
--  mismatch between workers rather than cancelling out.
--
--  A failure is one of two things. A cipher, rekey or load call that
--  returns a non-OK status is a worker error: the run stops, the
--  summary lists it, the verdict is FAIL and the exit code 1. A
--  round-trip that returns without error but with different bytes is
--  a data mismatch: the process terminates on the spot with exit
--  code 3, printing the worker, the iteration and the first differing
--  offset, and no summary -- the state that produced the wrong bytes
--  is the evidence. A crash inside the shared library or the host
--  runtime has no exit code of its own here; surfacing it is what the
--  utility is for.
--
--  Usage:
--
--      ./loop --duration 5m --goroutines 3 --shape stream \
--             --hash areion512 --mac hmac-blake3 --payload-size 16MB \
--             --memlimit auto --parallax on --wrapper on
--
--  Ctrl-C triggers a graceful shutdown: in-flight iterations
--  complete, then the partial summary prints.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Streams;

with Interfaces;

with Itb3;
with Itb3.Error;
with Itb3.Opts;
with Itb3.Pipeline;
with Itb3.Runtime;

with Harness;
with Harness.Payload;
with Harness.Sizes;
with Harness.Summary;
with Harness.Worker;

procedure Loop_Main is

   use Harness;
   use Harness.Sizes;
   use type Harness.Worker.Runner_Access;
   use type Interfaces.Integer_64;
   use type Interfaces.Unsigned_64;

   subtype Element_Offset is Ada.Streams.Stream_Element_Offset;

   --  Profiles the shape-based pair is built against when --profile
   --  is empty.
   Default_Stream_Profile  : constant String :=
     "streaming-aead-triple-mac-v1";
   Default_Message_Profile : constant String := "singlemsg-triple-mac-v1";

   --  The primitive supplied for the parallax palette and the outer
   --  cipher when a profile leaves them unnamed. AES-CMAC is
   --  PRF-grade, so it is sound outside the Interlocked Barrier, and
   --  it is the closest relative of the AES-based inner primitive
   --  whose profiles need this fill.
   Keystream_Fill_Cipher : constant String := "aescmac";

   N_Flags : constant := 25;

   type Flag_Kind is (K_Int, K_Int64, K_UInt64, K_String, K_Bool);

   type Flag_Index is range 1 .. N_Flags;

   type Text_Ref is access constant String;

   --  The flag table, in alphabetical order (the order the usage
   --  prints). Names, type labels, help strings and defaults are the
   --  output contract; the default suffix is rendered for the integer
   --  and string kinds only, exactly as the reference composes it.
   Flag_Name : constant array (Flag_Index) of Text_Ref :=
     [new String'("barrier-fill"),
      new String'("blob-cycle-every"),
      new String'("blob-mode"),
      new String'("chunk-size"),
      new String'("drbg"),
      new String'("duration"),
      new String'("gogc"),
      new String'("gomaxprocs"),
      new String'("goroutines"),
      new String'("hash"),
      new String'("iterations"),
      new String'("json-output"),
      new String'("key-bits"),
      new String'("mac"),
      new String'("memlimit"),
      new String'("memprofile"),
      new String'("nonce-bits"),
      new String'("parallax"),
      new String'("payload-mode"),
      new String'("payload-size"),
      new String'("profile"),
      new String'("rekey-every"),
      new String'("seed"),
      new String'("shape"),
      new String'("wrapper")];

   Flag_Type : constant array (Flag_Index) of Text_Ref :=
     [new String'("int"),
      new String'("int"),
      new String'("int"),
      new String'("string"),
      new String'("string"),
      new String'("duration"),
      new String'("int"),
      new String'("int"),
      new String'("int"),
      new String'("string"),
      new String'("int"),
      new String'(""),
      new String'("int"),
      new String'("string"),
      new String'("string"),
      new String'("string"),
      new String'("int"),
      new String'("string"),
      new String'("string"),
      new String'("string"),
      new String'("string"),
      new String'("int"),
      new String'("uint"),
      new String'("string"),
      new String'("string")];

   Flag_Of : constant array (Flag_Index) of Flag_Kind :=
     [K_Int, K_Int64, K_Int, K_String, K_String, K_String, K_Int,
      K_Int, K_Int, K_String, K_Int64, K_Bool,
      K_Int, K_String, K_String, K_String, K_Int,
      K_String, K_String, K_String, K_String, K_Int64,
      K_UInt64, K_String, K_String];

   Flag_Default : constant array (Flag_Index) of Text_Ref :=
     [new String'("0"),
      new String'("0"),
      new String'("1"),
      new String'("0"),
      new String'(""),
      new String'("5m"),
      new String'("0"),
      new String'("0"),
      new String'("3"),
      new String'("areion512"),
      new String'("0"),
      new String'("false"),
      new String'("0"),
      new String'("hmac-blake3"),
      new String'("auto"),
      new String'(""),
      new String'("0"),
      new String'("on"),
      new String'("fixed"),
      new String'("16MB"),
      new String'(""),
      new String'("0"),
      new String'("0"),
      new String'("stream"),
      new String'("on")];

   Flag_Help : constant array (Flag_Index) of Text_Ref :=
     [new String'("DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32;"
                  & " 0 = profile default (1)"),
      new String'("reopen each pipeline from its session blob every N"
                  & " iterations per worker; 0 = never"),
      new String'("container floor sizing mode: 1 (per-region, default)"
                  & " | 2 (per-container)"),
      new String'("streaming chunk-size budget (e.g. 4MB); 0 = profile"
                  & " default; inert for pure message shape"),
      new String'("DRBG fill primitive name (see itb3 drbgs); empty ="
                  & " profile default (auto tier)"),
      new String'("run duration (Go format: 30s / 5m / 1h); ignored when"
                  & " --iterations > 0"),
      new String'("GC trigger percentage; 0 = leave the runtime default"),
      new String'("Go runtime GOMAXPROCS override; 0 = inherit from the"
                  & " environment"),
      new String'("concurrent workers (1..10); on runtimes without"
                  & " parallelism values above 1 are clamped to 1"),
      new String'("inner ITB hash primitive name"),
      new String'("fixed per-worker iteration count; 0 = duration-based"),
      new String'("print the final summary as one compact JSON object"
                  & " instead of log lines"),
      new String'("per-seed key width in bits: 512 | 1024 | 2048;"
                  & " 0 = profile default (1024)"),
      new String'("MAC primitive name"),
      new String'("Go heap soft limit: auto (1GiB when goroutines <= 3,"
                  & " else 256MiB, applied only when the runtime has no"
                  & " limit) or a size (e.g. 512MB)"),
      new String'("write a Go runtime heap profile (pprof) to this path at"
                  & " the end of the run; empty = none"),
      new String'("on-wire nonce width in bits: 128 | 256 | 512;"
                  & " 0 = profile default (512)"),
      new String'("parallax layer: on | off"),
      new String'("plaintext content: fixed | rotating | pattern-zero |"
                  & " pattern-ff | pattern-ascii"),
      new String'("per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)"),
      new String'("exercise this single registered triple profile"
                  & " (overrides --shape with the profile's surface);"
                  & " empty = shape-based profile pair"),
      new String'("rotate the parallax + wrapper masters via Rekey every N"
                  & " iterations per worker; 0 = never"),
      new String'("deterministic plaintext RNG seed for bug reproduction,"
                  & " NOT for security testing (pipeline keys stay"
                  & " CSPRNG-drawn); 0 = crypto/rand plaintexts"),
      new String'("cipher surface to exercise: stream | message |"
                  & " stream_one_shot | both"),
      new String'("wrapper layer: on | off")];

   type Raw_Table is array (Flag_Index) of SU.Unbounded_String;

   Raw : Raw_Table;

   type Parse_Outcome is (Parse_Ok, Parse_Help, Parse_Error);

   --  Prints the usage to stderr, one block per flag in table order.
   procedure Usage is
   begin
      Emit (2, "Usage of loop:");
      for I in Flag_Index loop
         Emit (2, "  -" & Flag_Name (I).all
               & (if Flag_Type (I).all = "" then ""
                  else " " & Flag_Type (I).all));
         --  Ada-specific. The default-value suffix is composed by
         --  hand; a flag library that appends its own renders it
         --  itself.
         declare
            Head : constant String :=
              "    " & ASCII.HT & Flag_Help (I).all;
         begin
            if Flag_Of (I) = K_Int and then Flag_Default (I).all /= "0" then
               Emit (2, Head & " (default " & Flag_Default (I).all & ")");
            elsif Flag_Of (I) = K_String and then Flag_Default (I).all /= ""
            then
               Emit (2, Head & " (default """ & Flag_Default (I).all & """)");
            else
               Emit (2, Head);
            end if;
         end;
      end loop;
   end Usage;

   --  Whether Text is a well-formed value for the flag's kind. The
   --  lexical check happens as the value is assigned, so a malformed
   --  value is reported against the flag that carried it.
   function Value_Ok (Kind : Flag_Kind; Text : String) return Boolean is
      Magnitude : Interfaces.Unsigned_64;
      First     : Natural;
   begin
      case Kind is
         when K_String =>
            return True;
         when K_Bool =>
            return Text = "true" or else Text = "false";
         when K_UInt64 =>
            return Parse_U64 (Text, Magnitude);
         when K_Int | K_Int64 =>
            if Text'Length = 0 then
               return False;
            end if;
            First := Text'First;
            if Text (First) = '-' or else Text (First) = '+' then
               First := First + 1;
            end if;
            if First > Text'Last then
               return False;
            end if;
            if not Parse_U64 (Text (First .. Text'Last), Magnitude) then
               return False;
            end if;
            if Kind = K_Int and then Magnitude > 2_147_483_647 then
               return False;
            end if;
            if Kind = K_Int64
              and then Magnitude > Interfaces.Unsigned_64 (Count'Last)
            then
               return False;
            end if;
            return True;
      end case;
   end Value_Ok;

   function As_Count (Text : String) return Count is
      Magnitude : Interfaces.Unsigned_64 := 0;
      First     : Natural := Text'First;
      Ignored   : Boolean;
   begin
      if Text'Length = 0 then
         return 0;
      end if;
      if Text (First) = '-' or else Text (First) = '+' then
         First := First + 1;
      end if;
      Ignored := Parse_U64 (Text (First .. Text'Last), Magnitude);
      if not Ignored then
         return 0;
      end if;
      if Text (Text'First) = '-' then
         return -Count (Magnitude);
      end if;
      return Count (Magnitude);
   end As_Count;

   function As_Integer (Text : String) return Integer is
   begin
      return Integer (As_Count (Text));
   end As_Integer;

   function Parse_On_Off (Text : String; Flag : out Boolean) return Boolean is
   begin
      Flag := False;
      if Text = "on" then
         Flag := True;
         return True;
      elsif Text = "off" then
         Flag := False;
         return True;
      end if;
      return False;
   end Parse_On_Off;

   --  Whether Name is in the JSON array of strings the binding
   --  returns for the shipped hash registry. Names are restricted to
   --  [a-z0-9-], so a quoted run is one complete name.
   function Hash_Registered (Name : String) return Boolean is
      Quoted : constant String := """" & Name & """";
   begin
      declare
         JSON : constant String := Itb3.Pipeline.Hash_Names;
      begin
         for I in JSON'First .. JSON'Last - Quoted'Length + 1 loop
            if JSON (I .. I + Quoted'Length - 1) = Quoted then
               return True;
            end if;
         end loop;
      end;
      return False;
   exception
      when Itb3.Error.Itb_Error =>
         return False;
   end Hash_Registered;

   --  Index of Needle in Haystack, or 0 when absent.
   function Find (Haystack : String; Needle : String) return Natural is
   begin
      if Needle'Length = 0 or else Haystack'Length < Needle'Length then
         return 0;
      end if;
      for I in Haystack'First .. Haystack'Last - Needle'Length + 1 loop
         if Haystack (I .. I + Needle'Length - 1) = Needle then
            return I;
         end if;
      end loop;
      return 0;
   end Find;

   --  Resolves a registered profile to the shape family its record's
   --  mode exposes by reading the record through the binding's
   --  lookup: a mode beginning with "streaming" exposes the stream
   --  surfaces, one beginning with "singlemsg" the message surface,
   --  "blob-only" none.
   function Profile_Surface
     (Name : String; Surface : out Shape_Kind) return Boolean
   is
      Needle : constant String := """mode"":""";
      At_Pos : Natural;
   begin
      Surface := Shape_Stream;
      declare
         JSON : constant String := Itb3.Pipeline.Lookup (Name);
      begin
         At_Pos := Find (JSON, Needle);
         if At_Pos /= 0 then
            At_Pos := At_Pos + Needle'Length;
            if At_Pos + 8 <= JSON'Last then
               if JSON (At_Pos .. At_Pos + 8) = "streaming" then
                  Surface := Shape_Stream;
                  return True;
               elsif JSON (At_Pos .. At_Pos + 8) = "singlemsg" then
                  Surface := Shape_Message;
                  return True;
               end if;
            end if;
         end if;
      end;
      Err_Line ("--profile """ & Name
                & """ carries no cipher surface (blob-only mode)");
      return False;
   exception
      when Itb3.Error.Itb_Error =>
         Err_Line ("--profile """ & Name
                   & """ is not a registered triple profile");
         return False;
   end Profile_Surface;

   --  Applies a --profile's surface to the requested shape: a
   --  message-surface profile forces message; a stream-surface
   --  profile keeps stream or stream_one_shot as requested and turns
   --  message or both into stream.
   function Narrow_Shape
     (Requested : Shape_Kind; Surface : Shape_Kind) return Shape_Kind is
   begin
      if Surface = Shape_Message then
         return Shape_Message;
      end if;
      if Requested = Shape_Stream_One_Shot then
         return Shape_Stream_One_Shot;
      end if;
      return Shape_Stream;
   end Narrow_Shape;

   function Text_Of (I : Flag_Index) return String is
   begin
      return SU.To_String (Raw (I));
   end Text_Of;

   --  Values are validated after the whole command line is parsed;
   --  the first failing rule prints its message and stops the run.
   function Validate return Parse_Outcome is
      Surface : Shape_Kind;
   begin
      if not Parse_Duration (Text_Of (6), Cfg.Duration_NS)
        or else Cfg.Duration_NS <= 0
      then
         Err_Line ("--duration must be positive, got " & Text_Of (6));
         return Parse_Error;
      end if;
      Cfg.Iterations := As_Count (Text_Of (11));
      if Cfg.Iterations < 0 then
         Err_Line ("--iterations must be >= 0, got " & Img (Cfg.Iterations));
         return Parse_Error;
      end if;
      declare
         Asked : constant Integer := As_Integer (Text_Of (9));
      begin
         if Asked < 1 or else Asked > Max_Workers then
            Err_Line ("--goroutines must be in 1.."
                      & Img (Integer (Max_Workers)) & ", got " & Img (Asked));
            return Parse_Error;
         end if;
         --  Concurrency mode. This binding runs shared-handle: Ada
         --  tasks call into one Pipeline handle concurrently, which
         --  the shared library permits after construction, so
         --  --goroutines is the task count verbatim, never clamped.
         Cfg.Workers_Asked := Asked;
         Cfg.Workers := Asked;
      end;
      if not Harness.Worker.Parse_Shape (Text_Of (24), Cfg.Shape) then
         Err_Line ("--shape must be stream | message | stream_one_shot "
                   & "| both, got """ & Text_Of (24) & """");
         return Parse_Error;
      end if;
      if not Hash_Registered (Text_Of (10)) then
         Err_Line ("--hash """ & Text_Of (10)
                   & """ is not a registered hash primitive");
         return Parse_Error;
      end if;
      Cfg.Hash := Raw (10);
      --  Validated by Init: the C ABI enumerates no MAC names.
      Cfg.MAC := Raw (14);
      if not Parse_Size (Text_Of (20), Cfg.Payload) then
         Err_Line ("--payload-size: invalid size """ & Text_Of (20) & """");
         return Parse_Error;
      end if;
      if Cfg.Payload < 1 then
         Err_Line ("--payload-size must be at least 1 byte");
         return Parse_Error;
      end if;
      if Text_Of (15) = "auto" then
         Cfg.Memlimit_Auto := True;
         Cfg.Memlimit :=
           (if Cfg.Workers <= 3 then 1024 * 1024 * 1024
            else 256 * 1024 * 1024);
      elsif not Parse_Size (Text_Of (15), Cfg.Memlimit) then
         Err_Line ("--memlimit: invalid size """ & Text_Of (15) & """");
         return Parse_Error;
      end if;
      Cfg.GoGC := As_Integer (Text_Of (7));
      if Cfg.GoGC < 0 then
         Err_Line ("--gogc must be >= 0, got " & Img (Cfg.GoGC));
         return Parse_Error;
      end if;
      if not Parse_On_Off (Text_Of (18), Cfg.Parallax) then
         Err_Line ("--parallax must be on | off, got """ & Text_Of (18)
                   & """");
         return Parse_Error;
      end if;
      if not Parse_On_Off (Text_Of (25), Cfg.Wrapper) then
         Err_Line ("--wrapper must be on | off, got """ & Text_Of (25)
                   & """");
         return Parse_Error;
      end if;
      Cfg.Profile := Raw (21);
      if SU.Length (Cfg.Profile) > 0 then
         if not Profile_Surface (SU.To_String (Cfg.Profile), Surface) then
            return Parse_Error;
         end if;
         Cfg.Shape := Narrow_Shape (Cfg.Shape, Surface);
      end if;
      Cfg.Key_Bits := As_Integer (Text_Of (13));
      case Cfg.Key_Bits is
         when 0 | 512 | 1024 | 2048 =>
            null;
         when others =>
            Err_Line ("--key-bits must be 512 | 1024 | 2048 "
                      & "(or 0 = profile default), got " & Img (Cfg.Key_Bits));
            return Parse_Error;
      end case;
      Cfg.Nonce_Bits := As_Integer (Text_Of (17));
      case Cfg.Nonce_Bits is
         when 0 | 128 | 256 | 512 =>
            null;
         when others =>
            Err_Line ("--nonce-bits must be 128 | 256 | 512 "
                      & "(or 0 = profile default), got "
                      & Img (Cfg.Nonce_Bits));
            return Parse_Error;
      end case;
      Cfg.Blob_Mode := As_Integer (Text_Of (3));
      case Cfg.Blob_Mode is
         when 1 | 2 =>
            null;
         when others =>
            Err_Line ("--blob-mode must be 1 (per-region) | 2 "
                      & "(per-container), got " & Img (Cfg.Blob_Mode));
            return Parse_Error;
      end case;
      Cfg.Barrier_Fill := As_Integer (Text_Of (1));
      case Cfg.Barrier_Fill is
         when 0 | 1 | 2 | 4 | 8 | 16 | 32 =>
            null;
         when others =>
            Err_Line ("--barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 "
                      & "(or 0 = profile default), got "
                      & Img (Cfg.Barrier_Fill));
            return Parse_Error;
      end case;
      --  Validated by Init: the C ABI enumerates no DRBG names.
      Cfg.DRBG := Raw (5);
      if not Parse_Size (Text_Of (4), Cfg.Chunk_Size) then
         Err_Line ("--chunk-size: invalid size """ & Text_Of (4) & """");
         return Parse_Error;
      end if;
      Cfg.GOMAXPROCS := As_Integer (Text_Of (8));
      if Cfg.GOMAXPROCS < 0 then
         Err_Line ("--gomaxprocs must be > 0 when specified, got "
                   & Img (Cfg.GOMAXPROCS));
         return Parse_Error;
      end if;
      Cfg.Rekey_Every := As_Count (Text_Of (22));
      if Cfg.Rekey_Every < 0 then
         Err_Line ("--rekey-every must be >= 0, got "
                   & Img (Cfg.Rekey_Every));
         return Parse_Error;
      end if;
      Cfg.Blob_Cycle_Every := As_Count (Text_Of (2));
      if Cfg.Blob_Cycle_Every < 0 then
         Err_Line ("--blob-cycle-every must be >= 0, got "
                   & Img (Cfg.Blob_Cycle_Every));
         return Parse_Error;
      end if;
      if not Harness.Payload.Parse_Payload_Mode
               (Text_Of (19), Cfg.Payload_Mode)
      then
         Err_Line ("--payload-mode must be fixed | rotating | "
                   & "pattern-zero | pattern-ff | pattern-ascii, got """
                   & Text_Of (19) & """");
         return Parse_Error;
      end if;
      if not Parse_U64 (Text_Of (23), Cfg.Seed) then
         Cfg.Seed := 0;
      end if;
      Cfg.JSON_Output := Text_Of (12) = "true";
      Cfg.Memprofile := Raw (16);
      return Parse_Ok;
   end Validate;

   --  Parses argv into the raw flag values, then validates them.
   --  Accepts -name value, --name value, -name=value and
   --  --name=value; a boolean flag takes no value unless given as
   --  -name=true / -name=false.
   function Parse_Flags return Parse_Outcome is
      I     : Natural := 1;
      Argc  : constant Natural := Ada.Command_Line.Argument_Count;
      Found : Natural;
   begin
      for F in Flag_Index loop
         Raw (F) := SU.To_Unbounded_String (Flag_Default (F).all);
      end loop;

      while I <= Argc loop
         declare
            Arg   : constant String := Ada.Command_Line.Argument (I);
            Name  : SU.Unbounded_String;
            Value : SU.Unbounded_String;
            Eq    : Natural := 0;
            Has   : Boolean := False;
         begin
            if Arg'Length < 2 or else Arg (Arg'First) /= '-' then
               Err_Line ("unexpected positional arguments: [" & Arg & "]");
               return Parse_Error;
            end if;
            if Arg (Arg'First + 1) = '-' then
               Name := SU.To_Unbounded_String
                 (Arg (Arg'First + 2 .. Arg'Last));
            else
               Name := SU.To_Unbounded_String
                 (Arg (Arg'First + 1 .. Arg'Last));
            end if;
            if SU.To_String (Name) = "h"
              or else SU.To_String (Name) = "help"
            then
               Usage;
               return Parse_Help;
            end if;
            Eq := SU.Index (Name, "=");
            if Eq /= 0 then
               Value := SU.To_Unbounded_String
                 (SU.Slice (Name, Eq + 1, SU.Length (Name)));
               Has := True;
               Name := SU.To_Unbounded_String (SU.Slice (Name, 1, Eq - 1));
            end if;
            Found := 0;
            for F in Flag_Index loop
               if SU.To_String (Name) = Flag_Name (F).all then
                  Found := Natural (F);
                  exit;
               end if;
            end loop;
            if Found = 0 then
               Err_Line ("flag provided but not defined: -"
                         & SU.To_String (Name));
               Usage;
               return Parse_Error;
            end if;
            if not Has then
               if Flag_Of (Flag_Index (Found)) = K_Bool then
                  Value := SU.To_Unbounded_String ("true");
               elsif I < Argc then
                  I := I + 1;
                  Value := SU.To_Unbounded_String
                    (Ada.Command_Line.Argument (I));
               else
                  Err_Line ("flag needs an argument: -"
                            & Flag_Name (Flag_Index (Found)).all);
                  return Parse_Error;
               end if;
            end if;
            if not Value_Ok (Flag_Of (Flag_Index (Found)),
                             SU.To_String (Value))
            then
               Err_Line ("invalid value """ & SU.To_String (Value)
                         & """ for flag -"
                         & Flag_Name (Flag_Index (Found)).all);
               return Parse_Error;
            end if;
            Raw (Flag_Index (Found)) := Value;
         end;
         I := I + 1;
      end loop;

      return Validate;
   end Parse_Flags;

   -----------------------
   -- Profile record IO --
   -----------------------

   --  Integer value of Key in a profile JSON record; zero when
   --  absent.
   function Record_Int (JSON : String; Key : String) return Count is
      Needle : constant String := """" & Key & """:";
      At_Pos : Natural := Find (JSON, Needle);
      Last   : Natural;
   begin
      if At_Pos = 0 then
         return 0;
      end if;
      At_Pos := At_Pos + Needle'Length;
      Last := At_Pos;
      while Last <= JSON'Last and then JSON (Last) in '0' .. '9' loop
         Last := Last + 1;
      end loop;
      if Last = At_Pos then
         return 0;
      end if;
      return Count'Value (JSON (At_Pos .. Last - 1));
   end Record_Int;

   --  String value of Key in a profile JSON record, or "-" when
   --  absent or empty. Profile record strings are restricted to
   --  [a-z0-9-], so a quoted run is one complete value.
   function Record_Str (JSON : String; Key : String) return String is
      Needle : constant String := """" & Key & """:""";
      At_Pos : Natural := Find (JSON, Needle);
      Last   : Natural;
   begin
      if At_Pos = 0 then
         return "-";
      end if;
      At_Pos := At_Pos + Needle'Length;
      Last := At_Pos;
      while Last <= JSON'Last and then JSON (Last) /= '"' loop
         Last := Last + 1;
      end loop;
      if Last = At_Pos then
         return "-";
      end if;
      return JSON (At_Pos .. Last - 1);
   end Record_Str;

   --  Boolean value of Key in a profile JSON record; False when
   --  absent.
   function Record_Bool (JSON : String; Key : String) return Boolean is
   begin
      return Find (JSON, """" & Key & """:true") /= 0;
   end Record_Bool;

   --  Prints the construction line with the recipe read back from the
   --  blob the Pipeline handed out, not echoed from the flags: every
   --  construction override is proven to have reached the library by
   --  the value the receiver would see. Record values that are empty
   --  (a No MAC profile's MAC, a mixed profile's single hash) print
   --  as "-".
   procedure Log_Pipeline_Initialised
     (Profile : String; Blob : Byte_Array)
   is
      Head : constant String :=
        "pipeline initialised: profile=" & Profile & " blob="
        & Img (Count (Blob'Length)) & " bytes";
   begin
      declare
         JSON : constant String := Itb3.Pipeline.Inspect (Blob);
         Line : SU.Unbounded_String;
         DRBG : constant String := Record_Str (JSON, "drbg");
         Container_Mode : constant Count :=
           Record_Int (JSON, "container_mode");
      begin
         Line := SU.To_Unbounded_String
                  (Head
                   & " hash=" & Record_Str (JSON, "hash")
                   & " key-bits=" & Img (Record_Int (JSON, "keybits"))
                   & " nonce-bits=" & Img (Record_Int (JSON, "nonce_bits"))
                   & " barrier-fill=" & Img (Record_Int (JSON, "barrier_fill"))
                   & " chunk-size=" & Img (Record_Int (JSON, "chunk"))
                   & " mac=" & Record_Str (JSON, "mac")
                   & " parallax=" & On_Off (Record_Bool (JSON, "parallax"))
                   & " wrapper=" & On_Off (Record_Bool (JSON, "wrapper")));
         if Container_Mode = 2 then
            SU.Append (Line, " container-mode=" & Img (Container_Mode));
         end if;
         if DRBG /= "-" then
            SU.Append (Line, " drbg=" & DRBG);
         end if;
         Log_Line (SU.To_String (Line));
      end;
   exception
      when E : Itb3.Error.Itb_Error =>
         Log_Line (Head & " (inspect: " & Detail (E) & ")");
   end Log_Pipeline_Initialised;

   --  Sets the inner blob's "mode" field of a wrap-layer session blob
   --  to Target (1 = per-region, 2 = per-container) in place. The wrap
   --  layer's profile record carries its own "mode" (a string), so the
   --  search starts at the inner blob ("ib"); both shipped modes are
   --  one digit wide, so the blob length does not change and the key
   --  material in Blob is never copied. Returns False when the inner
   --  blob or its mode field is not found.
   function Edit_Inner_Blob_Mode
     (Blob : in out Byte_Array; Target : Integer) return Boolean
   is
      use type Ada.Streams.Stream_Element;
      use type Ada.Streams.Stream_Element_Offset;

      --  Offset of the first occurrence of Needle in Blob at or after
      --  From, or Blob'Last + 1 when absent.
      function Find_Bytes
        (From : Element_Offset; Needle : String) return Element_Offset is
      begin
         for I in From .. Blob'Last - Element_Offset (Needle'Length) + 1 loop
            declare
               Hit : Boolean := True;
            begin
               for J in Needle'Range loop
                  if Blob (I + Element_Offset (J - Needle'First))
                    /= Character'Pos (Needle (J))
                  then
                     Hit := False;
                     exit;
                  end if;
               end loop;
               if Hit then
                  return I;
               end if;
            end;
         end loop;
         return Blob'Last + 1;
      end Find_Bytes;

      IB_Key   : constant String := """ib"":{";
      Mode_Key : constant String := """mode"":";
      IB       : Element_Offset;
      Mode     : Element_Offset;
      At_Pos   : Element_Offset;
   begin
      IB := Find_Bytes (Blob'First, IB_Key);
      if IB > Blob'Last then
         return False;
      end if;
      Mode := Find_Bytes (IB + IB_Key'Length, Mode_Key);
      if Mode > Blob'Last then
         return False;
      end if;
      At_Pos := Mode + Mode_Key'Length;
      if At_Pos + 1 > Blob'Last
        or else Blob (At_Pos) < Character'Pos ('1')
        or else Blob (At_Pos) > Character'Pos ('2')
        or else (Blob (At_Pos + 1) >= Character'Pos ('0')
                 and then Blob (At_Pos + 1) <= Character'Pos ('9'))
      then
         return False;
      end if;
      Blob (At_Pos) :=
        Ada.Streams.Stream_Element (Character'Pos ('0') + Target);
      return True;
   end Edit_Inner_Blob_Mode;

   --  Folds a keystream primitive into opts for any layer the named
   --  profile leaves unfilled but the operator asked for.
   --
   --  A profile built around a primitive that is safe only inside the
   --  Interlocked Barrier ships with no parallax palette and no outer
   --  cipher: both layers run outside the barrier, where that
   --  primitive would stand bare, so the recipe leaves them unnamed
   --  rather than naming a primitive that must not key them. Engaging
   --  either layer therefore needs a keystream-capable primitive
   --  supplied from outside the recipe; without it construction fails
   --  on a palette below its minimum or an unnamed outer cipher, and
   --  the primitive that most deserves stressing becomes the one that
   --  cannot be stressed with those layers engaged.
   --
   --  Overrides fold into the resolved record the blob carries, so the
   --  receiver rebuilds the same shape from the blob alone.
   --
   --  Ada-specific. The record is read as JSON text and the two keys
   --  are probed by substring: an absent "palette" or "outer" key is
   --  the unfilled state, since the encoder omits both when unset.
   function Fill_Keystream_Layers
     (Name : String; Options : in out Itb3.Opts.Opts) return Integer
   is
      Filled : Integer := 0;
   begin
      declare
         JSON : constant String := Itb3.Pipeline.Lookup (Name);
      begin
         if Cfg.Parallax and then Find (JSON, """palette"":") = 0 then
            Itb3.Opts.Set
              (Options, "parallaxPalette",
               Keystream_Fill_Cipher & "," & Keystream_Fill_Cipher & ","
               & Keystream_Fill_Cipher);
            if Find (JSON, """segment"":") = 0 then
               --  A recipe that never carried a palette never carried
               --  a segment size either, and the schedule rejects
               --  zero.
               Itb3.Opts.Set (Options, "parallaxSegmentSize", "4093");
            end if;
            Filled := 1;
         end if;
         if Cfg.Wrapper and then Find (JSON, """outer"":") = 0 then
            Itb3.Opts.Set (Options, "outerCipher", Keystream_Fill_Cipher);
            Filled := 1;
         end if;
      end;
      return Filled;
   exception
      when Itb3.Error.Itb_Error =>
         Err_Line ("--profile """ & Name
                   & """ is not a registered triple profile");
         return -1;
   end Fill_Keystream_Layers;

   --  Constructs one Pipeline against Profile with every flag-carried
   --  override in the opts string (zero values included -- the shared
   --  library treats zero as "profile default"), then obtains the
   --  Init blob once through Save: the binding's init entry does not
   --  hand the blob back, and the bytes are the ones Init produced.
   --  Later blob reopens use the retained blob; Save is never called
   --  again.
   function Build_Pipeline
     (Profile : String;
      Pipe    : out Pipeline_Access;
      Blob    : out Itb3.Byte_Array_Access) return Boolean
   is
      Options : Itb3.Opts.Opts;
      Filled  : Integer;
   begin
      Pipe := null;
      Blob := null;
      Itb3.Opts.Set (Options, "innerHash", SU.To_String (Cfg.Hash));
      Itb3.Opts.Set (Options, "macName", SU.To_String (Cfg.MAC));
      Itb3.Opts.Set (Options, "withParallax", Truth (Cfg.Parallax));
      Itb3.Opts.Set (Options, "withWrapper", Truth (Cfg.Wrapper));
      Itb3.Opts.Set (Options, "keyBits", Img (Cfg.Key_Bits));
      Itb3.Opts.Set (Options, "nonceBits", Img (Cfg.Nonce_Bits));
      Itb3.Opts.Set (Options, "barrierFill", Img (Cfg.Barrier_Fill));
      Itb3.Opts.Set (Options, "drbg", SU.To_String (Cfg.DRBG));
      Itb3.Opts.Set (Options, "chunkSize", Img (Cfg.Chunk_Size));
      if SU.Length (Cfg.Profile) > 0 then
         Filled := Fill_Keystream_Layers
           (SU.To_String (Cfg.Profile), Options);
         if Filled < 0 then
            return False;
         end if;
         if Filled > 0 then
            Err_Line (SU.To_String (Cfg.Profile)
                      & " leaves the requested keystream layers unnamed; "
                      & Keystream_Fill_Cipher & " supplied for them");
         end if;
      end if;

      Pipe := new Itb3.Pipeline.Pipeline;
      begin
         Itb3.Pipeline.Init (Pipe.all, Profile, Options);
      exception
         when E : Itb3.Error.Itb_Error =>
            Err_Line ("Init(" & Profile & "): " & Detail (E));
            return False;
      end;
      begin
         Blob := new Byte_Array'(Itb3.Pipeline.Save (Pipe.all));
      exception
         when E : Itb3.Error.Itb_Error =>
            Err_Line ("Save(" & Profile & "): " & Detail (E));
            return False;
      end;
      if Cfg.Blob_Mode = 2 then
         --  The sizing mode is not an Opts knob: the Init blob is
         --  edited and the Pipeline reopened from it (Load releases
         --  the Init handle first), so the retained blob (the one
         --  blob-cycle reopens from) carries the edited mode.
         if not Edit_Inner_Blob_Mode (Blob.all, 2) then
            Err_Line ("rewrite blob mode: inner blob mode field not found");
            return False;
         end if;
         begin
            Itb3.Pipeline.Load (Pipe.all, Blob.all);
         exception
            when E : Itb3.Error.Itb_Error =>
               Err_Line ("reload Mode 2 blob: " & Detail (E));
               return False;
         end;
      end if;
      Log_Pipeline_Initialised (Profile, Blob.all);
      return True;
   end Build_Pipeline;

   Outcome      : Parse_Outcome;
   Warmup_Start : Count;
   Elapsed_NS   : Count;
   Previous     : Count;
   Code         : Integer;
   Runners      : Harness.Worker.Runner_Array := [others => null];

begin
   --  The signal dispositions go in before the first byte of output:
   --  a consumer that stops reading can end the run at any line,
   --  including the first, so the restoration cannot wait until the
   --  workers are about to start.
   Install_Signals;

   Outcome := Parse_Flags;
   if Outcome = Parse_Help then
      Die (0);
   elsif Outcome /= Parse_Ok then
      Die (2);
   end if;

   --  Runtime shaping. A long run under allocation churn grows the Go
   --  heap inside the shared library without bound unless a soft
   --  limit paces the collector, so a limit is always in force: an
   --  explicit --memlimit is set as given, and auto caps the heap
   --  only when the runtime reports no limit at all (a limit already
   --  installed from the environment is left standing). The GC
   --  percentage and GOMAXPROCS are set only when their flag is
   --  non-zero -- a zero flag skips the setter rather than calling it
   --  with zero, because zero is a real value to the GC-percent
   --  setter, and a call would clobber whatever the environment
   --  installed. All of it lands before any Pipeline exists so the
   --  baselines are taken under the shaped runtime.
   if Cfg.Memlimit_Auto then
      Previous := Itb3.Runtime.Memory_Limit;
      if Previous = Interfaces.Integer_64'Last then
         Itb3.Runtime.Set_Memory_Limit (Cfg.Memlimit);
      end if;
   else
      Itb3.Runtime.Set_Memory_Limit (Cfg.Memlimit);
   end if;
   Cfg.Memlimit := Itb3.Runtime.Memory_Limit;
   if Cfg.GoGC > 0 then
      Itb3.Runtime.Set_GC_Percent (Cfg.GoGC);
   end if;
   if Cfg.GOMAXPROCS > 0 then
      Itb3.Runtime.Set_GOMAXPROCS (Cfg.GOMAXPROCS);
   end if;

   Log_Line ("start: duration=" & Human_Duration (Cfg.Duration_NS)
             & " iterations=" & Img (Cfg.Iterations)
             & " goroutines=" & Img (Cfg.Workers_Asked)
             & " workers=" & Img (Cfg.Workers)
             & " concurrency=" & Concurrency
             & " shape=" & Harness.Worker.Shape_Name (Cfg.Shape)
             & " hash=" & SU.To_String (Cfg.Hash)
             & " mac=" & SU.To_String (Cfg.MAC)
             & " payload=" & Human_Bytes (Cfg.Payload)
             & " memlimit=" & Human_Bytes (Cfg.Memlimit)
             & " parallax=" & On_Off (Cfg.Parallax)
             & " wrapper=" & On_Off (Cfg.Wrapper));
   Log_Line ("overrides: profile=""" & SU.To_String (Cfg.Profile)
             & """ key-bits=" & Img (Cfg.Key_Bits)
             & " nonce-bits=" & Img (Cfg.Nonce_Bits)
             & " chunk-size=" & Human_Bytes (Cfg.Chunk_Size)
             & " barrier-fill=" & Img (Cfg.Barrier_Fill)
             & " gomaxprocs=" & Img (Cfg.GOMAXPROCS)
             & " rekey-every=" & Img (Cfg.Rekey_Every)
             & " blob-cycle-every=" & Img (Cfg.Blob_Cycle_Every)
             & " payload-mode="
             & Harness.Payload.Payload_Mode_Name (Cfg.Payload_Mode)
             & " seed=" & Img (Cfg.Seed)
             & " json-output=" & Truth (Cfg.JSON_Output)
             & (if Cfg.Blob_Mode /= 1
                then " blob-mode=" & Img (Cfg.Blob_Mode) else "")
             & (if SU.Length (Cfg.DRBG) > 0
                then " drbg=" & SU.To_String (Cfg.DRBG) else ""));
   Log_Line ("policy: microbatch-tiers="
             & Policy_Label ("ITB_MICROBATCH_TIERS")
             & " hashpool-starters="
             & Policy_Label ("ITB_HASHPOOL_STARTERS"));

   --  Pipeline construction -- one shared handle per exercised shape.
   --  stream and stream_one_shot share the streaming handle.
   if SU.Length (Cfg.Profile) > 0 then
      Stream_Profile := Cfg.Profile;
      Msg_Profile := Cfg.Profile;
   else
      Stream_Profile := SU.To_Unbounded_String (Default_Stream_Profile);
      Msg_Profile := SU.To_Unbounded_String (Default_Message_Profile);
   end if;
   if Cfg.Shape in Shape_Stream | Shape_Stream_One_Shot | Shape_Both then
      if not Build_Pipeline (SU.To_String (Stream_Profile),
                             Stream_Pipe, Stream_Blob)
      then
         Die (1);
      end if;
   end if;
   if Cfg.Shape in Shape_Message | Shape_Both then
      if not Build_Pipeline (SU.To_String (Msg_Profile),
                             Msg_Pipe, Msg_Blob)
      then
         Die (1);
      end if;
   end if;

   --  Allocation posture. Per-worker plaintexts are allocated once
   --  and held for the whole run (rotating mode refills them in place
   --  per iteration); the pump accumulators live inside each worker
   --  and are reused across iterations; the message and one-shot
   --  outputs are returned by value and reclaimed per iteration.
   --  Under the default fixed CSPRNG mode every worker's buffer is
   --  distinct, so cross-worker data crossover is detectable; pattern
   --  modes trade that property for content edge-case coverage.
   for I in 0 .. Cfg.Workers - 1 loop
      Workers (I).Id := I;
      Workers (I).Plaintext :=
        new Byte_Array (1 .. Element_Offset (Cfg.Payload));
      Workers (I).Wire.Data :=
        new Byte_Array (1 .. Element_Offset (Pump_Slice));
      Workers (I).Plain.Data :=
        new Byte_Array (1 .. Element_Offset (Pump_Slice));
      Workers (I).Seeded := Cfg.Seed /= 0;
      Workers (I).RNG := Harness.Payload.Seed_Worker (Cfg.Seed, I);
      if not Harness.Payload.Fill_Payload
               (Cfg.Payload_Mode, Workers (I).Seeded, Workers (I).RNG,
                Workers (I).Plaintext.all)
      then
         Err_Line ("payload fill: csprng");
         Die (1);
      end if;
   end loop;

   if not Harness.Summary.Snapshot_Alloc (Pool_Warmup) then
      Err_Line ("pool snapshot alloc failed");
      Die (1);
   end if;
   if not Harness.Summary.Snapshot_Alloc (Pool_Steady) then
      Err_Line ("pool snapshot alloc failed");
      Die (1);
   end if;

   Rendezvous.Set_Parties (Cfg.Workers);

   --  Warmup barrier. Every worker runs one iteration and waits; the
   --  clock starts only once all of them have paid their first-call
   --  costs (pool warm-up, lazy kernel dispatch, page faults on the
   --  payload buffers), and the RSS and pool baselines taken here
   --  describe a process that has already run the whole cipher path
   --  once per worker.
   Warmup_Start := Now_NS;
   for I in 0 .. Cfg.Workers - 1 loop
      Runners (I) := new Harness.Worker.Runner (Id => I);
   end loop;
   if Runners (0) = null then
      Err_Line ("worker launch failed");
      Die (1);
   end if;
   Rendezvous.Wait_Warmup;
   Harness.Summary.Read_RSS (RSS_Warmup, RSS_Peak);
   Harness.Summary.Snapshot_Take (Pool_Warmup);
   Log_Line ("warmup: " & Img (Cfg.Workers) & " workers x 1 iter completed in "
             & Human_Duration ((Now_NS - Warmup_Start + 50_000_000)
                               / 100_000_000 * 100_000_000)
             & " (baseline rss=" & Human_Bytes (RSS_Warmup) & ")");

   --  Open the gate; the deadline is enforced by every worker before
   --  it starts an iteration.
   Run_Start := Now_NS;
   Run_Finish := Run_Start;
   Rendezvous.Open;

   Rendezvous.Wait_All;
   Run_Finish := Rendezvous.Finish;
   Elapsed_NS := Run_Finish - Run_Start;
   Harness.Summary.Read_RSS (RSS_Final, RSS_Peak);
   Harness.Summary.Snapshot_Take (Pool_Steady);

   if SU.Length (Cfg.Memprofile) > 0 then
      begin
         Itb3.Runtime.Write_Heap_Profile (SU.To_String (Cfg.Memprofile));
         Log_Line ("memprofile: heap profile written to "
                   & SU.To_String (Cfg.Memprofile));
      exception
         when E : Itb3.Error.Itb_Error =>
            Err_Line ("memprofile: " & Detail (E));
      end;
   end if;

   Code := Harness.Summary.Final_Summary (Elapsed_NS);
   Die (Code);

exception
   when E : others =>
      Err_Line (Ada.Exceptions.Exception_Name (E) & ": "
                & Ada.Exceptions.Exception_Message (E));
      Die (1);
end Loop_Main;
