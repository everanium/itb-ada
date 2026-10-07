--  Master rotation and blob reopen across every active Pipeline under
--  the write lock, and the per-iteration scheduling that triggers
--  them.

with Ada.Streams;
with Ada.Unchecked_Deallocation;

with Itb3.Error;
with Itb3.Pipeline;

package body Harness.Ops is

   use type Ada.Streams.Stream_Element_Offset;
   use type Interfaces.Integer_64;

   subtype Element_Offset is Ada.Streams.Stream_Element_Offset;

   --  Byte length of each fresh master drawn for a rotation. Matches
   --  the size Init auto-generates for both the parallax and the
   --  wrapper master.
   Master_Size : constant Element_Offset := 32;

   Empty : constant Byte_Array (1 .. 0) := [];

   --  Finalizing the controlled Pipeline releases the libitb3 handle;
   --  the storage goes with it.
   procedure Free_Pipe is new Ada.Unchecked_Deallocation
     (Itb3.Pipeline.Pipeline, Pipeline_Access);

   --  Master rotation. Rotates the parallax + wrapper masters on
   --  every active Pipeline under the write lock and retains the
   --  refreshed blob for subsequent blob reopens. Masters are drawn
   --  fresh from the OS CSPRNG on every rotation regardless of --seed
   --  (master rotation is pipeline keying, not plaintext content); a
   --  disabled layer passes no bytes, which Rekey ignores. The eight
   --  inner seeds and the MAC key are untouched by design -- Rekey
   --  targets only the two outer-layer master secrets.
   function Rekey_Pipes
     (W : in out Worker_State; Iter : Count) return Boolean
   is
      Perm : Byte_Array (1 .. Master_Size);
      Wrap : Byte_Array (1 .. Master_Size);
      Perm_Len : Element_Offset := 0;
      Wrap_Len : Element_Offset := 0;
   begin
      if Cfg.Parallax then
         if not Fill_Random (Perm) then
            Worker_Fail (W, Worker_Tag (W.Id, Iter)
                         & ": csprng: parallax master");
            return False;
         end if;
         Perm_Len := Master_Size;
      end if;
      if Cfg.Wrapper then
         if not Fill_Random (Wrap) then
            Worker_Fail (W, Worker_Tag (W.Id, Iter)
                         & ": csprng: wrapper master");
            return False;
         end if;
         Wrap_Len := Master_Size;
      end if;

      Lock.Write_Lock;
      if Stream_Pipe /= null then
         begin
            declare
               Fresh : constant Byte_Array := Itb3.Pipeline.Rekey
                 (Stream_Pipe.all,
                  (if Perm_Len = 0 then Empty else Perm (1 .. Perm_Len)),
                  (if Wrap_Len = 0 then Empty else Wrap (1 .. Wrap_Len)));
            begin
               Itb3.Free (Stream_Blob);
               Stream_Blob := new Byte_Array'(Fresh);
            end;
         exception
            when E : Itb3.Error.Itb_Error =>
               Worker_Fail (W, Worker_Tag (W.Id, Iter) & ": Rekey("
                            & SU.To_String (Stream_Profile) & "): "
                            & Detail (E));
               Lock.Write_Unlock;
               return False;
         end;
      end if;
      if Msg_Pipe /= null then
         begin
            declare
               Fresh : constant Byte_Array := Itb3.Pipeline.Rekey
                 (Msg_Pipe.all,
                  (if Perm_Len = 0 then Empty else Perm (1 .. Perm_Len)),
                  (if Wrap_Len = 0 then Empty else Wrap (1 .. Wrap_Len)));
            begin
               Itb3.Free (Msg_Blob);
               Msg_Blob := new Byte_Array'(Fresh);
            end;
         exception
            when E : Itb3.Error.Itb_Error =>
               Worker_Fail (W, Worker_Tag (W.Id, Iter) & ": Rekey("
                            & SU.To_String (Msg_Profile) & "): "
                            & Detail (E));
               Lock.Write_Unlock;
               return False;
         end;
      end if;
      Rekeys := Rekeys + 1;
      Log_Line ("rekey: " & Worker_Tag (W.Id, Iter)
                & " rotated parallax + wrapper masters (rekey #"
                & Img (Rekeys) & ")");
      Lock.Write_Unlock;
      return True;
   end Rekey_Pipes;

   --  Blob reopen. Reopens every active Pipeline from its retained
   --  blob under the write lock: a fresh handle is loaded from the
   --  blob, the running handle is freed, and the fresh one is swapped
   --  in, so every later iteration round-trips through seeds and
   --  masters that survived a blob crossing. The input is the blob
   --  Init or the latest Rekey handed out, not a fresh Save: that is
   --  what a receiver holds, and reopening from it proves the
   --  handed-out bytes rather than the live state. The blob carries
   --  the Pipeline's full shape, so no override reaches the reopen.
   --  On a Load failure the running handle stays and the failure
   --  aborts the run.
   function Blob_Cycle_Pipes
     (W : in out Worker_State; Iter : Count) return Boolean
   is
      Fresh : Pipeline_Access;
   begin
      Lock.Write_Lock;
      if Stream_Pipe /= null then
         Fresh := new Itb3.Pipeline.Pipeline;
         begin
            Itb3.Pipeline.Load (Fresh.all, Stream_Blob.all);
         exception
            when E : Itb3.Error.Itb_Error =>
               Free_Pipe (Fresh);
               Worker_Fail (W, Worker_Tag (W.Id, Iter) & ": Load("
                            & SU.To_String (Stream_Profile) & "): "
                            & Detail (E));
               Lock.Write_Unlock;
               return False;
         end;
         Free_Pipe (Stream_Pipe);
         Stream_Pipe := Fresh;
         Fresh := null;
      end if;
      if Msg_Pipe /= null then
         Fresh := new Itb3.Pipeline.Pipeline;
         begin
            Itb3.Pipeline.Load (Fresh.all, Msg_Blob.all);
         exception
            when E : Itb3.Error.Itb_Error =>
               Free_Pipe (Fresh);
               Worker_Fail (W, Worker_Tag (W.Id, Iter) & ": Load("
                            & SU.To_String (Msg_Profile) & "): "
                            & Detail (E));
               Lock.Write_Unlock;
               return False;
         end;
         Free_Pipe (Msg_Pipe);
         Msg_Pipe := Fresh;
         Fresh := null;
      end if;
      Blob_Cycles := Blob_Cycles + 1;
      Log_Line ("blob-cycle: " & Worker_Tag (W.Id, Iter)
                & " reopened from session blob (cycle #"
                & Img (Blob_Cycles) & ")");
      Lock.Write_Unlock;
      return True;
   end Blob_Cycle_Pipes;

   function Maintenance
     (W : in out Worker_State; Iter : Count) return Boolean is
   begin
      if Cfg.Rekey_Every > 0 and then Iter mod Cfg.Rekey_Every = 0 then
         if not Rekey_Pipes (W, Iter) then
            return False;
         end if;
      end if;
      if Cfg.Blob_Cycle_Every > 0
        and then Iter mod Cfg.Blob_Cycle_Every = 0
      then
         if not Blob_Cycle_Pipes (W, Iter) then
            return False;
         end if;
      end if;
      return True;
   end Maintenance;

end Harness.Ops;
