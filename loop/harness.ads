--  Shared declarations of the loop stress harness: the resolved
--  configuration, the per-worker state, the run state every worker
--  shares, the reader / writer lock that keeps iterations clear of
--  handle mutation, the warmup and completion rendezvous, and the
--  line-at-a-time output primitives.
--
--  Ada-specific. A root package is how the Ada unit system shares
--  declarations with its children without a mutual-reference cycle:
--  the worker, ops and summary units all reach the state here, and
--  the two routines they all call back into (Log_Line, Worker_Fail)
--  sit here for the same reason. A language whose modules may refer
--  to one another folds these into the units that own them.

with Ada.Exceptions;
with Ada.Strings.Unbounded;

with Interfaces;

private with Interfaces.C;
private with System;

with Itb3;
with Itb3.Pipeline;
with Itb3.Runtime;

package Harness is

   package SU renames Ada.Strings.Unbounded;

   --  --goroutines ceiling; the harness targets modest hosts and each
   --  worker pins payload-sized buffers for the whole run.
   Max_Workers : constant := 10;

   --  Largest slice fed to a stream session per write; the drain
   --  after every write uses the same bound.
   Pump_Slice : constant := 1024 * 1024;

   --  The concurrency mode this binding implements, as the summary
   --  reports it (shared-handle / independent-handles / single).
   Concurrency : constant String := "shared-handle";

   subtype Byte_Array is Itb3.Byte_Array;
   subtype Count is Interfaces.Integer_64;

   --  Cipher surfaces the --shape flag selects.
   type Shape_Kind is
     (Shape_Stream,          --  session pump: begin / write / read / end
      Shape_Message,         --  Single Message: one whole-buffer call
      Shape_Stream_One_Shot, --  stream surface, one whole-buffer call
      Shape_Both);           --  all three, rotating by iteration number

   --  Plaintext content policies the --payload-mode flag selects.
   type Payload_Kind is
     (Payload_Fixed,
      Payload_Rotating,
      Payload_Pattern_Zero,
      Payload_Pattern_FF,
      Payload_Pattern_ASCII);

   --  The resolved command line.
   type Config is record
      Duration_NS      : Count := 0;   --  ignored when Iterations > 0
      Iterations       : Count := 0;   --  per worker incl. warmup; 0 = by duration
      Workers_Asked    : Natural := 0; --  the --goroutines value as given
      Workers          : Natural := 0; --  the effective worker count
      Shape            : Shape_Kind := Shape_Stream;
      Hash             : SU.Unbounded_String;
      MAC              : SU.Unbounded_String;
      Payload          : Count := 0;   --  bytes per iteration
      Memlimit         : Count := 0;   --  the effective limit once shaped
      Memlimit_Auto    : Boolean := False;
      GoGC             : Integer := 0; --  0 = leave the runtime default
      Parallax         : Boolean := True;
      Wrapper          : Boolean := True;
      Profile          : SU.Unbounded_String;
      Key_Bits         : Integer := 0; --  0 = profile default
      Nonce_Bits       : Integer := 0;
      Blob_Mode        : Integer := 1; --  1 = per-region, 2 = per-container
      Chunk_Size       : Count := 0;
      Barrier_Fill     : Integer := 0;
      DRBG             : SU.Unbounded_String; --  empty = profile default
      GOMAXPROCS       : Integer := 0; --  0 = inherit from the environment
      Rekey_Every      : Count := 0;   --  0 = never
      Blob_Cycle_Every : Count := 0;   --  0 = never
      Payload_Mode     : Payload_Kind := Payload_Fixed;
      Seed             : Interfaces.Unsigned_64 := 0;
      JSON_Output      : Boolean := False;
      Memprofile       : SU.Unbounded_String;
   end record;

   --  Growable byte accumulator for the pump loop, reused across
   --  iterations so the steady-state allocation profile stays flat.
   type Accumulator is record
      Data : Itb3.Byte_Array_Access := null;
      Len  : Count := 0;
   end record;

   procedure Append
     (Buffer : in out Accumulator;
      Src    : Byte_Array;
      Taken  : Count);

   procedure Release (Buffer : in out Accumulator);

   --  One worker's private state: its plaintext, its reusable pump
   --  accumulators, its generator, its counters, and the error it
   --  stopped on.
   type Worker_State is record
      Id        : Natural := 0;
      Plaintext : Itb3.Byte_Array_Access := null;
      Seeded    : Boolean := False;
      RNG       : Interfaces.Unsigned_64 := 0;
      Wire      : Accumulator;
      Plain     : Accumulator;
      Iters     : Count := 0;
      Bytes_Enc : Count := 0;
      Bytes_Dec : Count := 0;
      Nanos_Enc : Count := 0;
      Nanos_Dec : Count := 0;
      Failed    : Boolean := False;
      Error     : SU.Unbounded_String;
   end record;

   type Worker_Array is array (0 .. Max_Workers - 1) of Worker_State;

   type Pipeline_Access is access Itb3.Pipeline.Pipeline;

   --  Handle mutation. Iterations hold the read side for their whole
   --  encrypt -> decrypt -> compare; rekey and blob reopen take the
   --  write side, so no cipher call is in flight while a handle's
   --  keying changes or the handle itself is swapped, and no encrypt
   --  is separated from its decrypt by either. A raised writer flag
   --  bars arriving readers, so a waiting writer is never starved by
   --  a stream of iterations.
   protected Lock is
      entry Read_Lock;
      procedure Read_Unlock;
      entry Write_Lock;
      procedure Write_Unlock;
   private
      Readers : Natural := 0;
      Writer  : Boolean := False;
   end Lock;

   --  Warmup barrier and completion rendezvous. Workers report in
   --  after iteration 0 and wait for the gate; the launcher takes the
   --  baselines in between and opens it. The last worker to return
   --  stamps the finish instant, so the elapsed window excludes the
   --  launcher's wake-up latency.
   protected Rendezvous is
      procedure Set_Parties (N : Natural);
      procedure Arrive_Warmup;
      entry Wait_Warmup;
      procedure Open;
      entry Wait_Open;
      procedure Done (Now : Count);
      entry Wait_All;
      function Finish return Count;
   private
      Parties  : Natural := 0;
      Arrived  : Natural := 0;
      Opened   : Boolean := False;
      Left     : Natural := 0;
      Finished : Count := 0;
   end Rendezvous;

   --  The state every worker shares. Ada-specific: a package-level
   --  singleton rather than a record threaded through every task,
   --  because a task body reaches its enclosing library unit's
   --  variables directly and the alternative is a discriminant on
   --  every type.
   Cfg            : Config;
   Workers        : Worker_Array;
   Stream_Pipe    : Pipeline_Access := null;
   Msg_Pipe       : Pipeline_Access := null;
   Stream_Profile : SU.Unbounded_String;
   Msg_Profile    : SU.Unbounded_String;

   --  The blob Init handed out, replaced by every rekey; the input of
   --  the next blob reopen. Guarded by Lock.
   Stream_Blob : Itb3.Byte_Array_Access := null;
   Msg_Blob    : Itb3.Byte_Array_Access := null;

   Rekeys      : Count := 0;
   Blob_Cycles : Count := 0;

   Run_Start  : Count := 0;
   Run_Finish : Count := 0;

   --  Baselines taken after the warmup barrier and at shutdown.
   type Pool_Snapshot is access Itb3.Runtime.Pool_Counters;
   RSS_Warmup  : Count := 0;
   RSS_Peak    : Count := 0;
   RSS_Final   : Count := 0;
   Pool_Warmup : Pool_Snapshot := null;
   Pool_Steady : Pool_Snapshot := null;

   --  Set by the deadline check, by a signal, or by a failing worker;
   --  read by every worker before it starts an iteration.
   function Stop_Requested return Boolean;
   procedure Request_Stop;

   --  A line and its newline leave in one write. Workers log
   --  concurrently during maintenance, so the text and the
   --  terminator are assembled first and handed to a single write
   --  call; a split pair would let another worker's line land
   --  between them.
   procedure Log_Line (Text : String);
   procedure Err_Line (Text : String);
   procedure Emit (Fd : Integer; Text : String);

   --  Ada-specific. Returning from the main unit runs finalisation of
   --  every library-level controlled object, which closes handles the
   --  data-mismatch path must leave untouched; every exit leaves
   --  through the C library instead, so one mechanism covers all four
   --  codes.
   procedure Die (Code : Integer) with No_Return;

   --  Records the worker's error text (first error wins) and requests
   --  a stop of the whole run.
   procedure Worker_Fail (W : in out Worker_State; Text : String);

   --  "status <n>: <sentence>" -- the sentence libitb3 left behind,
   --  never a wording table of the utility's own.
   --
   --  Ada-specific. The text is read from the binding's own
   --  Last_Error accessor rather than from the occurrence's message,
   --  because GNAT bounds an exception message at 200 characters and
   --  the longest sentences are the caller's own data echoed back --
   --  an options key quoted in full runs past a thousand. The
   --  accessor is process-global last-write-wins, so under two
   --  simultaneous failures the text may belong to the other one;
   --  the status code, which comes from the occurrence, is always
   --  attributable, and the run stops on the first error either way.
   function Detail (E : Ada.Exceptions.Exception_Occurrence) return String;

   function On_Off (Flag : Boolean) return String;
   function Truth (Flag : Boolean) return String;

   --  Renders an encoder policy env value for the summary: the raw
   --  string when set, "default" when the shipped ladder applies.
   function Policy_Label (Name : String) return String;
   function Env_Value (Name : String) return String;

   --  Decimal renderings with no leading blank (the 'Image attribute
   --  keeps one for the sign position).
   function Img (N : Count) return String;
   function Img (N : Integer) return String;
   function Img (N : Interfaces.Unsigned_64) return String;

   --  "g<id> iter <n>" -- the prefix every worker-error text opens
   --  with.
   function Worker_Tag (Id : Natural; Iter : Count) return String;

   --  Fills Buffer from the operating-system CSPRNG; False on a
   --  failure. It sits here because both the payload unit and the
   --  master rotation draw through it.
   function Fill_Random (Buffer : in out Byte_Array) return Boolean;

   --  Graceful stop. SIGINT / SIGTERM set the stop flag every worker
   --  checks before it starts an iteration, and SIGPIPE is restored
   --  to its default disposition in the same place.
   procedure Install_Signals;

private

   function C_Write
     (Fd : Interfaces.C.int; Buf : System.Address; N : Interfaces.C.size_t)
      return Interfaces.C.long
   with Import => True, Convention => C, External_Name => "write";

   function C_Signal
     (Sig : Interfaces.C.int; Handler : System.Address) return System.Address
   with Import => True, Convention => C, External_Name => "signal";

   function C_Getrandom
     (Buf   : System.Address;
      N     : Interfaces.C.size_t;
      Flags : Interfaces.C.unsigned) return Interfaces.C.long
   with Import => True, Convention => C, External_Name => "getrandom";

   procedure C_Exit (Code : Interfaces.C.int)
   with Import => True, Convention => C, External_Name => "exit",
        No_Return => True;

end Harness;
