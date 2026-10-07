--  The worker task body and one iteration: the session pump written
--  once as a generic and instantiated per direction, the round-trip
--  comparison, and the failure model that separates a worker error
--  from a data mismatch.

with Ada.Exceptions;
with Ada.Streams;

with Itb3.Error;
with Itb3.Pipeline;
with Itb3.Stream;

with Harness.Ops;
with Harness.Payload;
with Harness.Sizes;

package body Harness.Worker is

   use type Ada.Streams.Stream_Element;
   use type Interfaces.Integer_64;
   use type Ada.Streams.Stream_Element_Offset;

   subtype Element_Offset is Ada.Streams.Stream_Element_Offset;

   Shape_Names : constant array (Shape_Kind) of access constant String :=
     [Shape_Stream          => new String'("stream"),
      Shape_Message         => new String'("message"),
      Shape_Stream_One_Shot => new String'("stream_one_shot"),
      Shape_Both            => new String'("both")];

   function Shape_Name (Shape : Shape_Kind) return String is
   begin
      return Shape_Names (Shape).all;
   end Shape_Name;

   function Parse_Shape
     (Text : String; Shape : out Shape_Kind) return Boolean is
   begin
      Shape := Shape_Stream;
      for K in Shape_Kind loop
         if Text = Shape_Names (K).all then
            Shape := K;
            return True;
         end if;
      end loop;
      return False;
   end Parse_Shape;

   --  Records a worker error for a failed cipher call.
   procedure Cipher_Fail
     (W         : in out Worker_State;
      Iter      : Count;
      Shape     : Shape_Kind;
      Direction : String;
      What      : String;
      Text      : String)
   is
      Head : constant String :=
        Worker_Tag (W.Id, Iter) & " shape=" & Shape_Name (Shape) & ": "
        & Direction;
   begin
      if What = "" or else What = Direction then
         Worker_Fail (W, Head & ": " & Text);
      else
         Worker_Fail (W, Head & ": " & What & ": " & Text);
      end if;
   end Cipher_Fail;

   --  Pump loop. The Go harness hands ITB an io.Reader / io.Writer
   --  pair and ITB drives the chunk loop internally; the C ABI has no
   --  reader / writer entry, so the caller drives it: open a session,
   --  feed slices of at most 1 MiB, drain whatever the session has
   --  produced after every write (a read before end never blocks),
   --  end, then drain until the session reports finished (after end,
   --  a read on an empty spool blocks until the terminal bytes
   --  arrive). The whole produced output lands in the worker's
   --  reusable accumulator. The loop is written here rather than
   --  delegated to the binding's pump convenience so it stands in the
   --  utility, at the same place, in every language.
   --
   --  Ada-specific. The encrypt and decrypt sessions are distinct
   --  types with distinct Write / Finish / Read operations rather than
   --  one type with a direction flag, so the loop is written once as
   --  a generic and instantiated for each direction instead of
   --  branching on the direction inside it.
   generic
      type Session is limited private;
      with procedure Begin_Session
        (S : in out Session; P : Itb3.Pipeline.Pipeline);
      with procedure Write (S : in out Session; Src : Byte_Array);
      with procedure Finish (S : in out Session);
      with procedure Read
        (S        : in out Session;
         Dst      : in out Byte_Array;
         Last     : out Element_Offset;
         Finished : out Boolean);
   procedure Generic_Pump
     (Pipe    : Itb3.Pipeline.Pipeline;
      Src     : Byte_Array;
      Src_Len : Count;
      Dst     : in out Accumulator;
      Scratch : in out Byte_Array;
      What    : out SU.Unbounded_String;
      Text    : out SU.Unbounded_String;
      Ok      : out Boolean);

   procedure Generic_Pump
     (Pipe    : Itb3.Pipeline.Pipeline;
      Src     : Byte_Array;
      Src_Len : Count;
      Dst     : in out Accumulator;
      Scratch : in out Byte_Array;
      What    : out SU.Unbounded_String;
      Text    : out SU.Unbounded_String;
      Ok      : out Boolean)
   is
      Sess     : Session;
      Off      : Count := 0;
      Slice    : Count;
      Last     : Element_Offset;
      Finished : Boolean;
   begin
      Ok := False;
      What := SU.Null_Unbounded_String;
      Text := SU.Null_Unbounded_String;
      Dst.Len := 0;
      begin
         Begin_Session (Sess, Pipe);
      exception
         when E : Itb3.Error.Itb_Error =>
            What := SU.To_Unbounded_String ("StreamBegin");
            Text := SU.To_Unbounded_String (Detail (E));
            return;
      end;
      begin
         while Off < Src_Len loop
            Slice := Count'Min (Count (Pump_Slice), Src_Len - Off);
            Write (Sess,
                   Src (Src'First + Element_Offset (Off)
                        .. Src'First + Element_Offset (Off + Slice) - 1));
            Off := Off + Slice;
            loop
               Read (Sess, Scratch, Last, Finished);
               exit when Last < Scratch'First;
               Append (Dst, Scratch, Count (Last - Scratch'First + 1));
            end loop;
         end loop;
      exception
         when E : Itb3.Error.Itb_Error =>
            What := SU.To_Unbounded_String ("StreamWrite");
            Text := SU.To_Unbounded_String (Detail (E));
            return;
      end;
      begin
         Finish (Sess);
      exception
         when E : Itb3.Error.Itb_Error =>
            What := SU.To_Unbounded_String ("StreamEnd");
            Text := SU.To_Unbounded_String (Detail (E));
            return;
      end;
      begin
         loop
            Read (Sess, Scratch, Last, Finished);
            if Last >= Scratch'First then
               Append (Dst, Scratch, Count (Last - Scratch'First + 1));
            end if;
            exit when Finished;
         end loop;
      exception
         when E : Itb3.Error.Itb_Error =>
            What := SU.To_Unbounded_String ("StreamRead");
            Text := SU.To_Unbounded_String (Detail (E));
            return;
      end;
      Ok := True;
   end Generic_Pump;

   procedure Pump_Enc is new Generic_Pump
     (Session       => Itb3.Stream.Encrypt_Stream,
      Begin_Session => Itb3.Stream.Begin_Encrypt,
      Write         => Itb3.Stream.Write,
      Finish        => Itb3.Stream.Finish,
      Read          => Itb3.Stream.Read);

   procedure Pump_Dec is new Generic_Pump
     (Session       => Itb3.Stream.Decrypt_Stream,
      Begin_Session => Itb3.Stream.Begin_Decrypt,
      Write         => Itb3.Stream.Write,
      Finish        => Itb3.Stream.Finish,
      Read          => Itb3.Stream.Read);

   --  First offset at which A and B differ, counted from zero; the
   --  shorter length when one is a prefix of the other.
   function First_Difference
     (A : Byte_Array; A_Len : Count; B : Byte_Array; B_Len : Count)
      return Count
   is
      N : constant Count := Count'Min (A_Len, B_Len);
   begin
      for I in 0 .. N - 1 loop
         if A (A'First + Element_Offset (I))
            /= B (B'First + Element_Offset (I))
         then
            return I;
         end if;
      end loop;
      return N;
   end First_Difference;

   --  Up to 16 bytes of Buf from Off (zero-based) as lowercase hex,
   --  or "-" when Buf has no bytes there.
   function Hex_Window (Buf : Byte_Array; B_Len : Count; Off : Count)
     return String
   is
      Nibbles : constant String := "0123456789abcdef";
      Last    : Count;
      Result  : String (1 .. 32);
      Used    : Natural := 0;
      V       : Natural;
   begin
      if Off >= B_Len then
         return "-";
      end if;
      Last := Count'Min (Off + 16, B_Len);
      for I in Off .. Last - 1 loop
         V := Natural (Buf (Buf'First + Element_Offset (I)));
         Result (Used + 1) := Nibbles (V / 16 + 1);
         Result (Used + 2) := Nibbles (V mod 16 + 1);
         Used := Used + 2;
      end loop;
      return Result (1 .. Used);
   end Hex_Window;

   --  Failure model. A cipher call that returns a non-OK status is a
   --  worker error: it is recorded, the run is asked to stop, the
   --  other workers finish their in-flight iteration, and the error
   --  is listed in the summary with the FAIL verdict. A round-trip
   --  that returns OK with different bytes is a data mismatch: the
   --  process terminates here, without summary or cleanup, because
   --  the Pipeline state that produced the wrong bytes is the
   --  evidence and nothing that runs afterwards may touch it.
   procedure Check_Round_Trip
     (W       : Worker_State;
      Iter    : Count;
      Shape   : Shape_Kind;
      Got     : Byte_Array;
      Got_Len : Count)
   is
      Want_Len : constant Count := Count (W.Plaintext.all'Length);
      Off      : constant Count :=
        First_Difference (W.Plaintext.all, Want_Len, Got, Got_Len);
   begin
      if Got_Len = Want_Len and then Off = Want_Len then
         return;
      end if;
      Err_Line ("DATA MISMATCH " & Worker_Tag (W.Id, Iter) & " shape="
                & Shape_Name (Shape) & ": want " & Img (Want_Len)
                & " bytes, got " & Img (Got_Len)
                & " bytes, first difference at offset " & Img (Off)
                & ": want " & Hex_Window (W.Plaintext.all, Want_Len, Off)
                & " got " & Hex_Window (Got, Got_Len, Off));
      Die (3);
   end Check_Round_Trip;

   --  One iteration. In order: refill the plaintext under rotating
   --  mode; take the read lock; pick the surface; encrypt (timed);
   --  decrypt (timed); compare the round-trip with the plaintext;
   --  bump the counters; release the lock. The whole round-trip runs
   --  under the read lock so handle-mutating maintenance (rekey, blob
   --  reopen) never lands between an encrypt and its matching decrypt
   --  -- maintenance runs after this returns, from the worker loop.
   function Iterate
     (W : in out Worker_State; Scratch : in out Byte_Array; Iter : Count)
      return Boolean
   is
      Plain_Len : constant Count := Count (W.Plaintext.all'Length);
      Shape     : Shape_Kind := Cfg.Shape;
      T0        : Count;
      What      : SU.Unbounded_String;
      Text      : SU.Unbounded_String;
      Ok        : Boolean;
   begin
      if Cfg.Payload_Mode = Payload_Rotating then
         if not Harness.Payload.Fill_Payload
                  (Payload_Rotating, W.Seeded, W.RNG, W.Plaintext.all)
         then
            Worker_Fail (W, Worker_Tag (W.Id, Iter)
                         & ": payload refill: csprng");
            return False;
         end if;
      end if;

      Lock.Read_Lock;

      --  Shape dispatch. message is one whole-buffer call on the
      --  Single Message Pipeline; stream_one_shot is one whole-buffer
      --  call on the streaming Pipeline (the C ABI's
      --  ITB_Triple_EncryptStream, which routes to the same
      --  one-shot stream entry the Go harness calls by name);
      --  stream opens a session on the same streaming Pipeline and
      --  drives the chunk loop from here. Under both the three rotate
      --  by iteration number so the session path and the whole-buffer
      --  path alternate on one handle inside every worker -- the
      --  cross-path state-reuse hazard this harness exists to catch.
      if Shape = Shape_Both then
         case Integer (Iter mod 3) is
            when 0      => Shape := Shape_Stream;
            when 1      => Shape := Shape_Message;
            when others => Shape := Shape_Stream_One_Shot;
         end case;
      end if;

      case Shape is
         when Shape_Stream =>
            T0 := Harness.Sizes.Now_NS;
            Pump_Enc (Stream_Pipe.all, W.Plaintext.all, Plain_Len,
                      W.Wire, Scratch, What, Text, Ok);
            if not Ok then
               Cipher_Fail (W, Iter, Shape, "encrypt",
                            SU.To_String (What), SU.To_String (Text));
               Lock.Read_Unlock;
               return False;
            end if;
            W.Nanos_Enc := W.Nanos_Enc + (Harness.Sizes.Now_NS - T0);
            T0 := Harness.Sizes.Now_NS;
            Pump_Dec (Stream_Pipe.all, W.Wire.Data.all, W.Wire.Len,
                      W.Plain, Scratch, What, Text, Ok);
            if not Ok then
               Cipher_Fail (W, Iter, Shape, "decrypt",
                            SU.To_String (What), SU.To_String (Text));
               Lock.Read_Unlock;
               return False;
            end if;
            W.Nanos_Dec := W.Nanos_Dec + (Harness.Sizes.Now_NS - T0);
            Check_Round_Trip
              (W, Iter, Shape,
               W.Plain.Data.all (1 .. Element_Offset (W.Plain.Len)),
               W.Plain.Len);
            W.Bytes_Dec := W.Bytes_Dec + W.Plain.Len;

         when Shape_Stream_One_Shot | Shape_Message =>
            --  Ada-specific. The whole-buffer entries return their
            --  output by value, so each result lives for the length
            --  of the block that declares it and is reclaimed at its
            --  end, while the pump accumulators are the worker's own
            --  and are reused. The two nested blocks also separate
            --  the two failure reports: an exception from a block's
            --  declarative part is handled by the enclosing block, so
            --  the encrypt and the decrypt land in different handlers
            --  without a direction flag.
            T0 := Harness.Sizes.Now_NS;
            begin
               declare
                  Wire : constant Byte_Array :=
                    (if Shape = Shape_Message
                     then Itb3.Pipeline.Encrypt_Message
                            (Msg_Pipe.all, W.Plaintext.all)
                     else Itb3.Pipeline.Encrypt_Stream_One_Shot
                            (Stream_Pipe.all, W.Plaintext.all));
               begin
                  W.Nanos_Enc := W.Nanos_Enc + (Harness.Sizes.Now_NS - T0);
                  T0 := Harness.Sizes.Now_NS;
                  declare
                     Got : constant Byte_Array :=
                       (if Shape = Shape_Message
                        then Itb3.Pipeline.Decrypt_Message
                               (Msg_Pipe.all, Wire)
                        else Itb3.Pipeline.Decrypt_Stream_One_Shot
                               (Stream_Pipe.all, Wire));
                  begin
                     W.Nanos_Dec := W.Nanos_Dec
                                    + (Harness.Sizes.Now_NS - T0);
                     Check_Round_Trip
                       (W, Iter, Shape, Got, Count (Got'Length));
                     W.Bytes_Dec := W.Bytes_Dec + Count (Got'Length);
                  end;
               exception
                  when E : Itb3.Error.Itb_Error =>
                     Cipher_Fail (W, Iter, Shape, "decrypt", "decrypt",
                                  Detail (E));
                     Lock.Read_Unlock;
                     return False;
               end;
            exception
               when E : Itb3.Error.Itb_Error =>
                  Cipher_Fail (W, Iter, Shape, "encrypt", "encrypt",
                               Detail (E));
                  Lock.Read_Unlock;
                  return False;
            end;

         when Shape_Both =>
            null;  --  resolved above
      end case;

      W.Iters := W.Iters + 1;
      W.Bytes_Enc := W.Bytes_Enc + Plain_Len;
      Lock.Read_Unlock;
      return True;
   end Iterate;

   ------------
   -- Runner --
   ------------

   --  Ada-specific. An unhandled exception inside a task body
   --  terminates that task silently, which would leave the completion
   --  rendezvous waiting forever, so the whole body sits inside
   --  handlers that record the failure and still report in.
   task body Runner is
      W       : Worker_State renames Workers (Id);
      Scratch : Itb3.Byte_Array_Access :=
        new Byte_Array (1 .. Element_Offset (Pump_Slice));
      Warmed  : Boolean := False;
      Iter    : Count := 1;
   begin
      --  Iteration 0, counted in the totals; its completion feeds the
      --  post-warmup baselines. A failing warmup still reports in and
      --  still waits for the gate, so the launcher never waits on a
      --  worker that has already given up.
      begin
         Warmed := Iterate (W, Scratch.all, 0);
      exception
         when E : others =>
            Worker_Fail (W, Worker_Tag (Id, 0) & ": "
                         & Ada.Exceptions.Exception_Name (E) & ": "
                         & Ada.Exceptions.Exception_Message (E));
            Warmed := False;
      end;
      Rendezvous.Arrive_Warmup;
      Rendezvous.Wait_Open;

      if Warmed then
         begin
            loop
               exit when Cfg.Iterations > 0 and then Iter >= Cfg.Iterations;
               exit when Stop_Requested;
               if Cfg.Iterations = 0
                 and then Harness.Sizes.Now_NS - Run_Start >= Cfg.Duration_NS
               then
                  Request_Stop;
                  exit;
               end if;
               exit when not Iterate (W, Scratch.all, Iter);
               exit when not Harness.Ops.Maintenance (W, Iter);
               Iter := Iter + 1;
            end loop;
         exception
            when E : others =>
               Worker_Fail (W, Worker_Tag (Id, Iter) & ": "
                            & Ada.Exceptions.Exception_Name (E) & ": "
                            & Ada.Exceptions.Exception_Message (E));
         end;
      end if;
      Itb3.Free (Scratch);
      Rendezvous.Done (Harness.Sizes.Now_NS);
   end Runner;

end Harness.Worker;
