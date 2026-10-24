--  Handle lifecycle + buffer-in / buffer-out
--  relay with the retry-once convention: pre-allocate, and on
--  Buffer_Too_Small retry once with the exact size libitb3 reported
--  through the length out-parameter.

with Interfaces.C;
with System;

with Itb3.Error;
with Itb3.Status;

package body Itb3.Pipeline is

   use Interfaces.C;
   use type Ada.Streams.Stream_Element_Offset;

   subtype Offset is Ada.Streams.Stream_Element_Offset;

   --  Floor capacity for blob / JSON output buffers (Init / Rekey /
   --  Save / Inspect / Lookup / Profiles).
   Blob_Floor : constant Offset := 64 * 1024;

   Empty : constant Byte_Array (1 .. 0) := [];

   --  Pre-allocation formula for Message / one-shot stream outputs:
   --  max (131072, payload * 5/4 + 131072).
   function Result_Cap (N : Offset) return Offset is
     (Offset'Max (131_072, N + N / 4 + 131_072));

   --  Frees the Go-side handle (ignoring status — safe from any
   --  state). Idempotent.
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
   end Release;

   --  Single retry-once dispatch site for every variable-size output
   --  buffer: pre-allocate Blob_Floor, and on Buffer_Too_Small retry
   --  once with the exact size libitb3 reported through the length
   --  out-parameter. Raises Itb_Error on any other non-OK status.
   generic
      with function Call
        (Out_Buf : System.Address;
         Out_Cap : Size_T;
         Out_Len : access Size_T) return C_Int;
   function Buffer_Call return Byte_Array;

   function Buffer_Call return Byte_Array is
      Buf : Byte_Array_Access := new Byte_Array (1 .. Blob_Floor);
      Len : aliased Size_T := 0;
      St  : C_Int;
   begin
      St := Call (Buf.all'Address, Size_T (Buf.all'Length), Len'Access);
      if Integer (St) = Itb3.Status.Buffer_Too_Small
         and then Len > Size_T (Buf.all'Length)
      then
         Buf.all := [others => 0];
         pragma Inspection_Point (Buf);
         Free (Buf);
         Buf := new Byte_Array (1 .. Offset (Len));
         St := Call (Buf.all'Address, Len, Len'Access);
      end if;
      if Integer (St) /= Itb3.Status.OK then
         Buf.all := [others => 0];
         pragma Inspection_Point (Buf);
         Free (Buf);
         Itb3.Error.Raise_For (Integer (St));
      end if;
      declare
         Result : constant Byte_Array := Buf.all (1 .. Offset (Len));
      begin
         if Len > 0 then
            Buf.all (1 .. Offset (Len)) := [others => 0];
            pragma Inspection_Point (Buf);
         end if;
         Free (Buf);
         return Result;
      end;
   end Buffer_Call;

   ----------
   -- Init --
   ----------

   procedure Init
     (P       : in out Pipeline;
      Profile : String;
      Options : Itb3.Opts.Opts)
   is
      Profile_C : aliased constant char_array := To_C (Profile);
      Opts_C    : aliased char_array :=
        To_C (Itb3.Opts.Build (Options));
      H         : aliased Handle := Null_Handle;

      --  On a blob-buffer retry the Init re-runs and yields a fresh
      --  session (the undersized attempt is closed by libitb3 before
      --  returning). The Init blob is not retained binding-side;
      --  Save reads the current bytes from libitb3.
      function Call
        (Out_Buf : System.Address;
         Out_Cap : Size_T;
         Out_Len : access Size_T) return C_Int is
      begin
         H := Null_Handle;
         return ITB_Triple_Init
           (Profile_C'Address, Opts_C'Address,
            Out_Buf, Out_Cap, Out_Len, H'Access);
      end Call;

      function Run is new Buffer_Call (Call);
   begin
      Release (P);
      declare
         Blob : Byte_Array := Run;
      begin
         Opts_C := [others => nul];
         pragma Inspection_Point (Opts_C);
         Blob := [others => 0];
         pragma Inspection_Point (Blob);
         P.H := H;
      exception
         when others =>
            Opts_C := [others => nul];
            pragma Inspection_Point (Opts_C);
            raise;
      end;
   end Init;

   ---------------
   -- Init_Keys --
   ---------------

   procedure Init_Keys
     (P            : in out Pipeline;
      Profile      : String;
      Masters_Flat : Byte_Array;
      Master_Lens  : Size_Array;
      Options      : Itb3.Opts.Opts := Itb3.Opts.Empty)
   is
      Profile_C : aliased constant char_array := To_C (Profile);
      Opts_C    : aliased char_array :=
        To_C (Itb3.Opts.Build (Options));
      Lens_C    : array (1 .. Master_Lens'Length) of aliased Size_T
        with Convention => C;
      Flat_Addr : constant System.Address :=
        (if Masters_Flat'Length = 0 then System.Null_Address
         else Masters_Flat (Masters_Flat'First)'Address);
      Lens_Addr : System.Address;
      H         : aliased Handle := Null_Handle;

      function Call
        (Out_Buf : System.Address;
         Out_Cap : Size_T;
         Out_Len : access Size_T) return C_Int is
      begin
         H := Null_Handle;
         return ITB_Triple_InitKeys
           (Profile_C'Address, Opts_C'Address,
            Flat_Addr, Size_T (Masters_Flat'Length),
            Lens_Addr, Size_T (Lens_C'Length),
            Out_Buf, Out_Cap, Out_Len, H'Access);
      end Call;

      function Run is new Buffer_Call (Call);
   begin
      for I in Master_Lens'Range loop
         Lens_C (I - Master_Lens'First + 1) := Size_T (Master_Lens (I));
      end loop;
      Lens_Addr :=
        (if Lens_C'Length = 0 then System.Null_Address
         else Lens_C (1)'Address);
      Release (P);
      declare
         Blob : Byte_Array := Run;
      begin
         Opts_C := [others => nul];
         pragma Inspection_Point (Opts_C);
         Blob := [others => 0];
         pragma Inspection_Point (Blob);
         P.H := H;
      exception
         when others =>
            Opts_C := [others => nul];
            pragma Inspection_Point (Opts_C);
            raise;
      end;
   end Init_Keys;

   procedure Init_Keys
     (P            : in out Pipeline;
      Profile      : String;
      Options      : Itb3.Opts.Opts;
      Masters_Flat : Byte_Array;
      Master_Lens  : Size_Array) is
   begin
      Init_Keys (P, Profile, Masters_Flat, Master_Lens, Options);
   end Init_Keys;

   ----------
   -- Load --
   ----------

   --  The masters pair crosses as (perm, wrap, count): both absent
   --  yields 0, otherwise 2 — libitb3 validates the pair.
   procedure Load_Internal
     (P           : in out Pipeline;
      Blob        : Byte_Array;
      Perm_Master : Byte_Array;
      Wrap_Master : Byte_Array;
      Count       : Size_T)
   is
      H  : aliased Handle := Null_Handle;
      St : C_Int;
   begin
      Release (P);
      St := ITB_Triple_Load
        (Blob'Address, Size_T (Blob'Length),
         Perm_Master'Address, Size_T (Perm_Master'Length),
         Wrap_Master'Address, Size_T (Wrap_Master'Length),
         Count, H'Access);
      if Integer (St) /= Itb3.Status.OK then
         Itb3.Error.Raise_For (Integer (St));
      end if;
      P.H := H;
   end Load_Internal;

   procedure Load
     (P    : in out Pipeline;
      Blob : Byte_Array) is
   begin
      Load_Internal (P, Blob, Empty, Empty, 0);
   end Load;

   procedure Load
     (P           : in out Pipeline;
      Blob        : Byte_Array;
      Perm_Master : Byte_Array;
      Wrap_Master : Byte_Array) is
   begin
      Load_Internal (P, Blob, Perm_Master, Wrap_Master, 2);
   end Load;

   ------------
   -- Load_F --
   ------------

   procedure Load_F_Internal
     (P           : in out Pipeline;
      Path        : String;
      Perm_Master : Byte_Array;
      Wrap_Master : Byte_Array;
      Count       : Size_T)
   is
      Path_C : aliased constant char_array := To_C (Path);
      H      : aliased Handle := Null_Handle;
      St     : C_Int;
   begin
      Release (P);
      St := ITB_Triple_LoadF
        (Path_C'Address,
         Perm_Master'Address, Size_T (Perm_Master'Length),
         Wrap_Master'Address, Size_T (Wrap_Master'Length),
         Count, H'Access);
      if Integer (St) /= Itb3.Status.OK then
         Itb3.Error.Raise_For (Integer (St));
      end if;
      P.H := H;
   end Load_F_Internal;

   procedure Load_F
     (P    : in out Pipeline;
      Path : String) is
   begin
      Load_F_Internal (P, Path, Empty, Empty, 0);
   end Load_F;

   procedure Load_F
     (P           : in out Pipeline;
      Path        : String;
      Perm_Master : Byte_Array;
      Wrap_Master : Byte_Array) is
   begin
      Load_F_Internal (P, Path, Perm_Master, Wrap_Master, 2);
   end Load_F;

   ----------
   -- Save --
   ----------

   function Save (P : Pipeline) return Byte_Array is
      function Call
        (Out_Buf : System.Address;
         Out_Cap : Size_T;
         Out_Len : access Size_T) return C_Int is
      begin
         return ITB_Triple_Save (P.H, Out_Buf, Out_Cap, Out_Len);
      end Call;

      function Run is new Buffer_Call (Call);
   begin
      return Run;
   end Save;

   ------------
   -- Save_F --
   ------------

   procedure Save_F (P : Pipeline; Path : String) is
      Path_C : aliased constant char_array := To_C (Path);
      St     : constant C_Int := ITB_Triple_SaveF (P.H, Path_C'Address);
   begin
      if Integer (St) /= Itb3.Status.OK then
         Itb3.Error.Raise_For (Integer (St));
      end if;
   end Save_F;

   -----------------
   -- Max_Workers --
   -----------------

   procedure Max_Workers (P : Pipeline; N : Integer) is
      St : constant C_Int := ITB_Triple_MaxWorkers (P.H, C_Int (N));
   begin
      if Integer (St) /= Itb3.Status.OK then
         Itb3.Error.Raise_For (Integer (St));
      end if;
   end Max_Workers;

   -----------
   -- Rekey --
   -----------

   function Rekey
     (P           : in out Pipeline;
      Perm_Master : Byte_Array;
      Wrap_Master : Byte_Array) return Byte_Array
   is
      function Call
        (Out_Buf : System.Address;
         Out_Cap : Size_T;
         Out_Len : access Size_T) return C_Int is
      begin
         return ITB_Triple_Rekey
           (P.H,
            Perm_Master'Address, Size_T (Perm_Master'Length),
            Wrap_Master'Address, Size_T (Wrap_Master'Length),
            Out_Buf, Out_Cap, Out_Len);
      end Call;

      function Run is new Buffer_Call (Call);
   begin
      return Run;
   end Rekey;

   procedure Rekey
     (P           : in out Pipeline;
      Perm_Master : Byte_Array;
      Wrap_Master : Byte_Array)
   is
      Blob : Byte_Array := Rekey (P, Perm_Master, Wrap_Master);
   begin
      Blob := [others => 0];
      pragma Inspection_Point (Blob);
   end Rekey;

   -----------
   -- Close --
   -----------

   procedure Close (P : in out Pipeline) is
      St : constant C_Int := ITB_Triple_Close (P.H);
   begin
      if Integer (St) /= Itb3.Status.OK then
         Itb3.Error.Raise_For (Integer (St));
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
      if Integer (St) = Itb3.Status.Buffer_Too_Small
         and then Len > Size_T (Buf.all'Length)
      then
         Free (Buf);
         Buf := new Byte_Array (1 .. Offset (Len));
         St := Call (Buf.all'Address, Len, Len'Access);
      end if;
      if Integer (St) /= Itb3.Status.OK then
         Free (Buf);
         Itb3.Error.Raise_For (Integer (St));
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

   --  JSON string out of a caller-allocated-buffer libitb3 call.
   function To_JSON (B : Byte_Array) return String is
      S : String (1 .. B'Length);
   begin
      for I in S'Range loop
         S (I) := Character'Val (B (B'First + Offset (I) - 1));
      end loop;
      return S;
   end To_JSON;

   -------------
   -- Inspect --
   -------------

   function Inspect (Blob : Byte_Array) return String is
      function Call
        (Out_Buf : System.Address;
         Out_Cap : Size_T;
         Out_Len : access Size_T) return C_Int is
      begin
         return ITB_Triple_Inspect
           (Blob'Address, Size_T (Blob'Length), Out_Buf, Out_Cap, Out_Len);
      end Call;

      function Run is new Buffer_Call (Call);
   begin
      return To_JSON (Run);
   end Inspect;

   --------------
   -- Register --
   --------------

   procedure Register (Name : String; Profile_JSON : String) is
      Name_C : aliased constant char_array := To_C (Name);
      JSON_C : aliased constant char_array := To_C (Profile_JSON);
      St     : constant C_Int :=
        ITB_Triple_Register (Name_C'Address, JSON_C'Address);
   begin
      if Integer (St) /= Itb3.Status.OK then
         Itb3.Error.Raise_For (Integer (St));
      end if;
   end Register;

   ------------
   -- Lookup --
   ------------

   function Lookup (Name : String) return String is
      Name_C : aliased constant char_array := To_C (Name);

      function Call
        (Out_Buf : System.Address;
         Out_Cap : Size_T;
         Out_Len : access Size_T) return C_Int is
      begin
         return ITB_Triple_Lookup (Name_C'Address, Out_Buf, Out_Cap, Out_Len);
      end Call;

      function Run is new Buffer_Call (Call);
   begin
      return To_JSON (Run);
   end Lookup;

   --------------
   -- Profiles --
   --------------

   function Profiles return String is
      function Call
        (Out_Buf : System.Address;
         Out_Cap : Size_T;
         Out_Len : access Size_T) return C_Int is
      begin
         return ITB_Triple_Profiles (Out_Buf, Out_Cap, Out_Len);
      end Call;

      function Run is new Buffer_Call (Call);
   begin
      return To_JSON (Run);
   end Profiles;

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

   ----------------
   -- Hash_Names --
   ----------------

   function Hash_Names return String is
      function Call
        (Out_Buf : System.Address;
         Out_Cap : Size_T;
         Out_Len : access Size_T) return C_Int is
      begin
         return ITB_Triple_HashNames (Out_Buf, Out_Cap, Out_Len);
      end Call;

      function Run is new Buffer_Call (Call);
   begin
      return To_JSON (Run);
   end Hash_Names;

end Itb3.Pipeline;
