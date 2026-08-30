--  Itb.Pipeline body — handle lifecycle + buffer-in / buffer-out
--  relay with the retry-once convention: pre-allocate, and on
--  Buffer_Too_Small retry once with the exact size libitb reported
--  through the length out-parameter.

with Interfaces.C;
with System;

with Itb.Error;
with Itb.Status;

package body Itb.Pipeline is

   use Interfaces.C;
   use type Ada.Streams.Stream_Element_Offset;

   subtype Offset is Ada.Streams.Stream_Element_Offset;

   --  Floor capacity for blob output buffers (Init / Rekey).
   Blob_Floor : constant Offset := 64 * 1024;

   Empty : constant Byte_Array (1 .. 0) := [];

   --  Pre-allocation formula for Message / one-shot stream outputs:
   --  max (131072, payload * 5/4 + 131072).
   function Result_Cap (N : Offset) return Offset is
     (Offset'Max (131_072, N + N / 4 + 131_072));

   --  Frees the Go-side handle (ignoring status — safe from any
   --  state) and drops the cached blob. Idempotent.
   procedure Release (P : in out Pipeline) is
   begin
      if P.H /= Null_Handle then
         declare
            Ignored : constant C_Int := ITB_Triple_Free (P.H);
            pragma Unreferenced (Ignored);
         begin
            null;
         end;
         P.H := Null_Handle;
      end if;
      Free (P.Blob_Bytes);
   end Release;

   ----------
   -- Init --
   ----------

   procedure Init
     (P       : in out Pipeline;
      Profile : String;
      Options : Itb.Opts.Opts)
   is
      Profile_C : aliased constant char_array := To_C (Profile);
      Opts_C    : aliased constant char_array :=
        To_C (Itb.Opts.Build (Options));
      Buf       : Byte_Array_Access := new Byte_Array (1 .. Blob_Floor);
      Len       : aliased Size_T := 0;
      H         : aliased Handle := Null_Handle;
      St        : C_Int;
   begin
      Release (P);
      St := ITB_Triple_Init
        (Profile_C'Address, Opts_C'Address,
         Buf.all'Address, Size_T (Buf.all'Length), Len'Access, H'Access);
      if Integer (St) = Itb.Status.Buffer_Too_Small
         and then Len > Size_T (Buf.all'Length)
      then
         --  On a blob-buffer retry the Init re-runs and yields a
         --  fresh session (the undersized attempt is closed by
         --  libitb before returning).
         Free (Buf);
         Buf := new Byte_Array (1 .. Offset (Len));
         St := ITB_Triple_Init
           (Profile_C'Address, Opts_C'Address,
            Buf.all'Address, Len, Len'Access, H'Access);
      end if;
      if Integer (St) /= Itb.Status.OK then
         Free (Buf);
         Itb.Error.Raise_For (Integer (St));
      end if;
      P.Blob_Bytes := new Byte_Array'(Buf.all (1 .. Offset (Len)));
      Free (Buf);
      P.H := H;
   end Init;

   --  Shared body for both Open variants.
   procedure Open_Internal
     (P           : in out Pipeline;
      Profile     : String;
      Blob        : Byte_Array;
      Options     : Itb.Opts.Opts;
      Perm_Master : Byte_Array;
      Wrap_Master : Byte_Array;
      Count       : Size_T)
   is
      Profile_C : aliased constant char_array := To_C (Profile);
      Opts_C    : aliased constant char_array :=
        To_C (Itb.Opts.Build (Options));
      H         : aliased Handle := Null_Handle;
      St        : C_Int;
   begin
      Release (P);
      St := ITB_Triple_Open
        (Profile_C'Address,
         Blob'Address, Size_T (Blob'Length),
         Opts_C'Address,
         Perm_Master'Address, Size_T (Perm_Master'Length),
         Wrap_Master'Address, Size_T (Wrap_Master'Length),
         Count, H'Access);
      if Integer (St) /= Itb.Status.OK then
         Itb.Error.Raise_For (Integer (St));
      end if;
      P.Blob_Bytes := new Byte_Array'(Blob);
      P.H := H;
   end Open_Internal;

   ----------
   -- Open --
   ----------

   procedure Open
     (P       : in out Pipeline;
      Profile : String;
      Blob    : Byte_Array;
      Options : Itb.Opts.Opts) is
   begin
      Open_Internal (P, Profile, Blob, Options, Empty, Empty, 0);
   end Open;

   procedure Open
     (P           : in out Pipeline;
      Profile     : String;
      Blob        : Byte_Array;
      Options     : Itb.Opts.Opts;
      Perm_Master : Byte_Array;
      Wrap_Master : Byte_Array) is
   begin
      if Perm_Master'Length = 0 or else Wrap_Master'Length = 0 then
         raise Itb.Error.Itb_Error
           with "4|master override buffers must be non-empty";
      end if;
      Open_Internal
        (P, Profile, Blob, Options, Perm_Master, Wrap_Master, 2);
   end Open;

   ----------
   -- Blob --
   ----------

   function Blob (P : Pipeline) return Byte_Array is
   begin
      if P.Blob_Bytes = null then
         return Empty;
      end if;
      return P.Blob_Bytes.all;
   end Blob;

   -----------
   -- Rekey --
   -----------

   procedure Rekey
     (P           : in out Pipeline;
      Perm_Master : Byte_Array;
      Wrap_Master : Byte_Array)
   is
      Cap : constant Offset :=
        Offset'Max
          (Blob_Floor,
           (if P.Blob_Bytes = null then 0 else P.Blob_Bytes.all'Length));
      Buf : Byte_Array_Access := new Byte_Array (1 .. Cap);
      Len : aliased Size_T := 0;
      St  : C_Int;
   begin
      St := ITB_Triple_Rekey
        (P.H,
         Perm_Master'Address, Size_T (Perm_Master'Length),
         Wrap_Master'Address, Size_T (Wrap_Master'Length),
         Buf.all'Address, Size_T (Buf.all'Length), Len'Access);
      if Integer (St) = Itb.Status.Buffer_Too_Small
         and then Len > Size_T (Buf.all'Length)
      then
         Free (Buf);
         Buf := new Byte_Array (1 .. Offset (Len));
         St := ITB_Triple_Rekey
           (P.H,
            Perm_Master'Address, Size_T (Perm_Master'Length),
            Wrap_Master'Address, Size_T (Wrap_Master'Length),
            Buf.all'Address, Len, Len'Access);
      end if;
      if Integer (St) /= Itb.Status.OK then
         Free (Buf);
         Itb.Error.Raise_For (Integer (St));
      end if;
      Free (P.Blob_Bytes);
      P.Blob_Bytes := new Byte_Array'(Buf.all (1 .. Offset (Len)));
      Free (Buf);
   end Rekey;

   -----------
   -- Close --
   -----------

   procedure Close (P : in out Pipeline) is
      St : constant C_Int := ITB_Triple_Close (P.H);
   begin
      if Integer (St) /= Itb.Status.OK then
         Itb.Error.Raise_For (Integer (St));
      end if;
   end Close;

   --  Shared body for the four buffer-in / buffer-out cipher entries.
   type Cipher_Kind is (Enc_Msg, Dec_Msg, Enc_Stream, Dec_Stream);

   function Cipher
     (Kind : Cipher_Kind;
      H    : Handle;
      Src  : Byte_Array) return Byte_Array
   is
      function Call
        (Out_Buf : System.Address;
         Out_Cap : Size_T;
         Out_Len : access Size_T) return C_Int
      is
         A : constant System.Address := Src'Address;
         L : constant Size_T := Size_T (Src'Length);
      begin
         case Kind is
            when Enc_Msg =>
               return ITB_Triple_EncryptMessage
                 (H, A, L, Out_Buf, Out_Cap, Out_Len);
            when Dec_Msg =>
               return ITB_Triple_DecryptMessage
                 (H, A, L, Out_Buf, Out_Cap, Out_Len);
            when Enc_Stream =>
               return ITB_Triple_EncryptStream
                 (H, A, L, Out_Buf, Out_Cap, Out_Len);
            when Dec_Stream =>
               return ITB_Triple_DecryptStream
                 (H, A, L, Out_Buf, Out_Cap, Out_Len);
         end case;
      end Call;

      Buf : Byte_Array_Access :=
        new Byte_Array (1 .. Result_Cap (Src'Length));
      Len : aliased Size_T := 0;
      St  : C_Int;
   begin
      St := Call (Buf.all'Address, Size_T (Buf.all'Length), Len'Access);
      if Integer (St) = Itb.Status.Buffer_Too_Small
         and then Len > Size_T (Buf.all'Length)
      then
         Free (Buf);
         Buf := new Byte_Array (1 .. Offset (Len));
         St := Call (Buf.all'Address, Len, Len'Access);
      end if;
      if Integer (St) /= Itb.Status.OK then
         Free (Buf);
         Itb.Error.Raise_For (Integer (St));
      end if;
      declare
         Result : constant Byte_Array := Buf.all (1 .. Offset (Len));
      begin
         Free (Buf);
         return Result;
      end;
   end Cipher;

   ---------------------
   -- Encrypt_Message --
   ---------------------

   function Encrypt_Message
     (P : Pipeline; Plain : Byte_Array) return Byte_Array is
   begin
      return Cipher (Enc_Msg, P.H, Plain);
   end Encrypt_Message;

   ---------------------
   -- Decrypt_Message --
   ---------------------

   function Decrypt_Message
     (P : Pipeline; Wire : Byte_Array) return Byte_Array is
   begin
      return Cipher (Dec_Msg, P.H, Wire);
   end Decrypt_Message;

   -----------------------------
   -- Encrypt_Stream_One_Shot --
   -----------------------------

   function Encrypt_Stream_One_Shot
     (P : Pipeline; Plain : Byte_Array) return Byte_Array is
   begin
      return Cipher (Enc_Stream, P.H, Plain);
   end Encrypt_Stream_One_Shot;

   -----------------------------
   -- Decrypt_Stream_One_Shot --
   -----------------------------

   function Decrypt_Stream_One_Shot
     (P : Pipeline; Wire : Byte_Array) return Byte_Array is
   begin
      return Cipher (Dec_Stream, P.H, Wire);
   end Decrypt_Stream_One_Shot;

   ----------------------
   -- Register_Profile --
   ----------------------

   procedure Register_Profile (Name : String; Options : Itb.Opts.Opts) is
      Name_C : aliased constant char_array := To_C (Name);
      Opts_C : aliased constant char_array :=
        To_C (Itb.Opts.Build (Options));
      St     : constant C_Int :=
        ITB_Triple_RegisterProfile (Name_C'Address, Opts_C'Address);
   begin
      if Integer (St) /= Itb.Status.OK then
         Itb.Error.Raise_For (Integer (St));
      end if;
   end Register_Profile;

   ---------
   -- Raw --
   ---------

   function Raw (P : Pipeline) return Handle is
   begin
      return P.H;
   end Raw;

   --------------
   -- Finalize --
   --------------

   overriding procedure Finalize (P : in out Pipeline) is
   begin
      Release (P);
   end Finalize;

end Itb.Pipeline;
