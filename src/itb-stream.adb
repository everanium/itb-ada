--  Itb.Stream body — thin relay onto the six session entry points.

with Interfaces.C;

with Itb.Error;
with Itb.Status;

package body Itb.Stream is

   use type Ada.Streams.Stream_Element_Offset;

   subtype Offset is Ada.Streams.Stream_Element_Offset;

   procedure Check (St : C_Int) is
   begin
      if Integer (St) /= Itb.Status.OK then
         Itb.Error.Raise_For (Integer (St));
      end if;
   end Check;

   procedure Do_Begin
     (S : in out Session'Class; P : Itb.Pipeline.Pipeline; Encrypt : Boolean)
   is
      H : aliased Handle := Null_Handle;
   begin
      if S.H /= Null_Handle then
         --  Re-Begin on a live session: cancel the old one first.
         Finalize (Session (S));
      end if;
      if Encrypt then
         Check (ITB_Triple_EncryptStreamBegin (Itb.Pipeline.Raw (P), H'Access));
      else
         Check (ITB_Triple_DecryptStreamBegin (Itb.Pipeline.Raw (P), H'Access));
      end if;
      S.H := H;
   end Do_Begin;

   procedure Do_Write (S : in out Session'Class; Src : Byte_Array) is
   begin
      Check (ITB_Triple_StreamWrite
               (S.H, Src'Address, Interfaces.C.size_t (Src'Length)));
   end Do_Write;

   procedure Do_Finish (S : in out Session'Class) is
   begin
      Check (ITB_Triple_StreamEnd (S.H));
   end Do_Finish;

   procedure Do_Read
     (S        : in out Session'Class;
      Dst      : in out Byte_Array;
      Last     : out Offset;
      Finished : out Boolean)
   is
      Len : aliased Size_T := 0;
      Fin : aliased C_Int := 0;
   begin
      Check (ITB_Triple_StreamRead
               (S.H, Dst'Address, Interfaces.C.size_t (Dst'Length),
                Len'Access, Fin'Access));
      Last := Dst'First + Offset (Len) - 1;
      Finished := Integer (Fin) /= 0;
   end Do_Read;

   -------------------
   -- Begin_Encrypt --
   -------------------

   procedure Begin_Encrypt
     (S : in out Encrypt_Stream; P : Itb.Pipeline.Pipeline) is
   begin
      Do_Begin (S, P, Encrypt => True);
   end Begin_Encrypt;

   -------------------
   -- Begin_Decrypt --
   -------------------

   procedure Begin_Decrypt
     (S : in out Decrypt_Stream; P : Itb.Pipeline.Pipeline) is
   begin
      Do_Begin (S, P, Encrypt => False);
   end Begin_Decrypt;

   -----------
   -- Write --
   -----------

   procedure Write (S : in out Encrypt_Stream; Src : Byte_Array) is
   begin
      Do_Write (S, Src);
   end Write;

   procedure Write (S : in out Decrypt_Stream; Src : Byte_Array) is
   begin
      Do_Write (S, Src);
   end Write;

   ------------
   -- Finish --
   ------------

   procedure Finish (S : in out Encrypt_Stream) is
   begin
      Do_Finish (S);
   end Finish;

   procedure Finish (S : in out Decrypt_Stream) is
   begin
      Do_Finish (S);
   end Finish;

   ----------
   -- Read --
   ----------

   procedure Read
     (S        : in out Encrypt_Stream;
      Dst      : in out Byte_Array;
      Last     : out Ada.Streams.Stream_Element_Offset;
      Finished : out Boolean) is
   begin
      Do_Read (S, Dst, Last, Finished);
   end Read;

   procedure Read
     (S        : in out Decrypt_Stream;
      Dst      : in out Byte_Array;
      Last     : out Ada.Streams.Stream_Element_Offset;
      Finished : out Boolean) is
   begin
      Do_Read (S, Dst, Last, Finished);
   end Read;

   --------------
   -- Finalize --
   --------------

   overriding procedure Finalize (S : in out Session) is
   begin
      if S.H /= Null_Handle then
         --  StreamFree cancels and releases the session from any
         --  state; the status is deliberately ignored on this path.
         declare
            Ignored : constant C_Int := ITB_Triple_StreamFree (S.H);
            pragma Unreferenced (Ignored);
         begin
            null;
         end;
         S.H := Null_Handle;
      end if;
   end Finalize;

end Itb.Stream;
