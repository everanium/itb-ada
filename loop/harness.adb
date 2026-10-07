--  The shared primitives the whole utility calls into.

with Ada.Environment_Variables;
with Ada.Streams;

with Itb3.Error;

package body Harness is

   use Interfaces;
   use Interfaces.C;
   use type Ada.Streams.Stream_Element_Offset;
   use type Itb3.Byte_Array_Access;

   subtype Element_Offset is Ada.Streams.Stream_Element_Offset;

   --  Set by the signal handler, by the deadline check, and by a
   --  failing worker. Atomic rather than protected: every reader
   --  polls it between iterations and the handler must be able to
   --  write it from whatever thread the signal lands on.
   Stop_Flag : Boolean := False with Atomic;

   SIG_INT  : constant Interfaces.C.int := 2;
   SIG_PIPE : constant Interfaces.C.int := 13;
   SIG_TERM : constant Interfaces.C.int := 15;

   ---------------
   -- Pipe_Lock --
   ---------------

   protected body Lock is

      entry Read_Lock when not Writer is
      begin
         Readers := Readers + 1;
      end Read_Lock;

      procedure Read_Unlock is
      begin
         Readers := Readers - 1;
      end Read_Unlock;

      entry Write_Lock when not Writer and then Readers = 0 is
      begin
         Writer := True;
      end Write_Lock;

      procedure Write_Unlock is
      begin
         Writer := False;
      end Write_Unlock;

   end Lock;

   ----------------
   -- Rendezvous --
   ----------------

   protected body Rendezvous is

      procedure Set_Parties (N : Natural) is
      begin
         Parties := N;
         Arrived := 0;
         Opened := False;
         Left := N;
         Finished := 0;
      end Set_Parties;

      procedure Arrive_Warmup is
      begin
         Arrived := Arrived + 1;
      end Arrive_Warmup;

      entry Wait_Warmup when Arrived >= Parties is
      begin
         null;
      end Wait_Warmup;

      procedure Open is
      begin
         Opened := True;
      end Open;

      entry Wait_Open when Opened is
      begin
         null;
      end Wait_Open;

      procedure Done (Now : Count) is
      begin
         if Left > 0 then
            Left := Left - 1;
         end if;
         if Left = 0 and then Finished = 0 then
            Finished := Now;
         end if;
      end Done;

      entry Wait_All when Left = 0 is
      begin
         null;
      end Wait_All;

      function Finish return Count is
      begin
         return Finished;
      end Finish;

   end Rendezvous;

   -----------------
   -- Accumulator --
   -----------------

   procedure Append
     (Buffer : in out Accumulator;
      Src    : Byte_Array;
      Taken  : Count)
   is
      Need : Count;
      Cap  : Count;
   begin
      if Taken <= 0 then
         return;
      end if;
      Need := Buffer.Len + Taken;
      if Buffer.Data = null then
         Buffer.Data := new Byte_Array (1 .. Element_Offset (Pump_Slice));
      end if;
      Cap := Count (Buffer.Data.all'Length);
      if Need > Cap then
         while Cap < Need loop
            Cap := Cap * 2;
         end loop;
         declare
            Grown : constant Itb3.Byte_Array_Access :=
              new Byte_Array (1 .. Element_Offset (Cap));
         begin
            if Buffer.Len > 0 then
               Grown.all (1 .. Element_Offset (Buffer.Len)) :=
                 Buffer.Data.all (1 .. Element_Offset (Buffer.Len));
            end if;
            Itb3.Free (Buffer.Data);
            Buffer.Data := Grown;
         end;
      end if;
      Buffer.Data.all
        (Element_Offset (Buffer.Len) + 1 .. Element_Offset (Need)) :=
        Src (Src'First .. Src'First + Element_Offset (Taken) - 1);
      Buffer.Len := Need;
   end Append;

   procedure Release (Buffer : in out Accumulator) is
   begin
      Itb3.Free (Buffer.Data);
      Buffer.Len := 0;
   end Release;

   ----------
   -- Stop --
   ----------

   function Stop_Requested return Boolean is
   begin
      return Stop_Flag;
   end Stop_Requested;

   procedure Request_Stop is
   begin
      Stop_Flag := True;
   end Request_Stop;

   ------------
   -- Output --
   ------------

   --  Ada-specific. Ada.Text_IO writes the text and the line
   --  terminator through separate calls on a buffered file, which
   --  neither keeps a line whole under concurrent logging nor fails
   --  promptly when the consumer goes away, so every byte this
   --  utility emits goes through the raw descriptor instead.
   procedure Emit (Fd : Integer; Text : String) is
      Line  : constant String := Text & ASCII.LF;
      Off   : Natural := 0;
      Moved : Interfaces.C.long;
   begin
      while Off < Line'Length loop
         Moved := C_Write
           (Interfaces.C.int (Fd),
            Line (Line'First + Off)'Address,
            Interfaces.C.size_t (Line'Length - Off));
         exit when Moved <= 0;
         Off := Off + Natural (Moved);
      end loop;
   end Emit;

   procedure Log_Line (Text : String) is
   begin
      Emit (1, "[loop] " & Text);
   end Log_Line;

   procedure Err_Line (Text : String) is
   begin
      Emit (2, "loop: " & Text);
   end Err_Line;

   procedure Die (Code : Integer) is
   begin
      C_Exit (Interfaces.C.int (Code));
   end Die;

   -----------------
   -- Worker_Fail --
   -----------------

   procedure Worker_Fail (W : in out Worker_State; Text : String) is
   begin
      if not W.Failed then
         W.Error := SU.To_Unbounded_String (Text);
         W.Failed := True;
      end if;
      Request_Stop;
   end Worker_Fail;

   ------------------
   -- Small pieces --
   ------------------

   function Detail (E : Ada.Exceptions.Exception_Occurrence) return String is
   begin
      return "status " & Img (Itb3.Error.Status_Code (E)) & ": "
             & Itb3.Error.Last_Error;
   end Detail;

   function On_Off (Flag : Boolean) return String is
   begin
      return (if Flag then "on" else "off");
   end On_Off;

   function Truth (Flag : Boolean) return String is
   begin
      return (if Flag then "true" else "false");
   end Truth;

   function Env_Value (Name : String) return String is
   begin
      if not Ada.Environment_Variables.Exists (Name) then
         return "";
      end if;
      return Ada.Environment_Variables.Value (Name);
   end Env_Value;

   function Policy_Label (Name : String) return String is
      Raw : constant String := Env_Value (Name);
      I   : Natural := Raw'First;
   begin
      while I <= Raw'Last and then (Raw (I) = ' ' or else Raw (I) = ASCII.HT)
      loop
         I := I + 1;
      end loop;
      if I > Raw'Last then
         return "default";
      end if;
      return Raw (I .. Raw'Last);
   end Policy_Label;

   function Img (N : Count) return String is
      Raw : constant String := Count'Image (N);
   begin
      return (if Raw (Raw'First) = ' ' then Raw (Raw'First + 1 .. Raw'Last)
              else Raw);
   end Img;

   function Img (N : Integer) return String is
      Raw : constant String := Integer'Image (N);
   begin
      return (if Raw (Raw'First) = ' ' then Raw (Raw'First + 1 .. Raw'Last)
              else Raw);
   end Img;

   function Img (N : Interfaces.Unsigned_64) return String is
      Raw : constant String := Interfaces.Unsigned_64'Image (N);
   begin
      return (if Raw (Raw'First) = ' ' then Raw (Raw'First + 1 .. Raw'Last)
              else Raw);
   end Img;

   function Worker_Tag (Id : Natural; Iter : Count) return String is
   begin
      return "g" & Img (Id) & " iter " & Img (Iter);
   end Worker_Tag;

   -----------------
   -- Fill_Random --
   -----------------

   --  Ada-specific. getrandom returns at most ~33 MiB per call and
   --  may return short on a signal, so the fill loops until every
   --  byte is in place.
   function Fill_Random (Buffer : in out Byte_Array) return Boolean is
      Off  : Element_Offset := 0;
      Got  : Interfaces.C.long;
      Last : constant Element_Offset := Buffer'Length;
   begin
      if Last = 0 then
         return True;
      end if;
      while Off < Last loop
         Got := C_Getrandom
           (Buffer (Buffer'First + Off)'Address,
            Interfaces.C.size_t (Last - Off), 0);
         if Got <= 0 then
            return False;
         end if;
         Off := Off + Element_Offset (Got);
      end loop;
      return True;
   end Fill_Random;

   -------------
   -- Signals --
   -------------

   procedure On_Signal (Sig : Interfaces.C.int) with Convention => C;

   procedure On_Signal (Sig : Interfaces.C.int) is
   begin
      if Sig /= 0 then
         Stop_Flag := True;
      end if;
   end On_Signal;

   --  SIGPIPE is restored to its default disposition here as well. A
   --  consumer that stops reading ends the run: the utility dies from
   --  the signal with exit 141 and prints nothing further, which is
   --  what anyone piping into head or less expects. The libitb3 load
   --  has installed a handler of its own by the time this runs, so
   --  the restoration is an explicit step rather than something
   --  inherited.
   --  The previous disposition each call reports is of no use here:
   --  the run installs its own and never restores them.
   procedure Set_Disposition (Sig : Interfaces.C.int; Handler : System.Address)
   is
      Previous : constant System.Address := C_Signal (Sig, Handler);
      pragma Unreferenced (Previous);
   begin
      null;
   end Set_Disposition;

   procedure Install_Signals is
   begin
      Set_Disposition (SIG_INT, On_Signal'Address);
      Set_Disposition (SIG_TERM, On_Signal'Address);
      Set_Disposition (SIG_PIPE, System.Null_Address);
   end Install_Signals;

end Harness;
