--  Itb.Wrapper body — format-deniability wrapper implementation.

with Ada.Calendar;
with Ada.Streams;             use Ada.Streams;
with Interfaces;              use Interfaces;
with Interfaces.C;
with Interfaces.C.Strings;
with System;

with GNAT.Random_Numbers;

with Itb.Errors;
with Itb.Status;

package body Itb.Wrapper is

   use type Itb.Sys.Handle;

   ---------------------------------------------------------------------
   --  Internal helpers
   ---------------------------------------------------------------------

   --  Module-local CSPRNG-flavoured generator. GNAT.Random_Numbers
   --  exposes a Mersenne Twister suitable for non-cryptographic test
   --  fixtures and key-distribution helpers; the wrapper key is
   --  delivered to the caller as opaque bytes for use against the
   --  libitb-side AES / ChaCha / SipHash keystream — the per-stream
   --  CSPRNG nonce that closes the security argument is drawn on the
   --  Go side at every Wrap / WrapInPlace / WrapStreamWriter_Init
   --  call from crypto/rand. Production deployments are expected to
   --  derive the wrapper key out-of-band (KDF, KEM, etc.); this
   --  helper exists for self-test convenience.
   Rng        : GNAT.Random_Numbers.Generator;
   Rng_Seeded : Boolean := False;

   procedure Seed_Rng is
      Now    : constant Long_Long_Integer :=
        Long_Long_Integer
          (Ada.Calendar.Seconds (Ada.Calendar.Clock) * 1.0E6);
      Folded : constant Long_Long_Integer :=
        Now mod Long_Long_Integer (Integer'Last);
   begin
      if not Rng_Seeded then
         GNAT.Random_Numbers.Reset (Rng, Integer (Folded));
         Rng_Seeded := True;
      end if;
   end Seed_Rng;

   --  Returns the canonical FFI cipher-name string. Ada-side enum
   --  → libitb-side const-char* roundtrip. These three literal
   --  constants must remain bit-identical to the Go-side
   --  wrapper.CipherAES128CTR / wrapper.CipherChaCha20 /
   --  wrapper.CipherSipHash24 string values.
   function Ffi_Name (C : Cipher_Type) return String is
   begin
      case C is
         when Aes_128_Ctr => return "aes";
         when Cha_Cha_20  => return "chacha";
         when Sip_Hash_24 => return "siphash";
      end case;
   end Ffi_Name;

   --  Three NUL-terminated cipher-name strings preallocated at
   --  package elaboration. These persist for the program lifetime
   --  and avoid the per-call Strings.New_String / Strings.Free
   --  bracket — leaks across an exception-raising path are then
   --  structurally impossible.
   Cipher_Names_Aes  : aliased Interfaces.C.char_array := Interfaces.C.To_C ("aes", True);
   Cipher_Names_Cha  : aliased Interfaces.C.char_array := Interfaces.C.To_C ("chacha", True);
   Cipher_Names_Sip  : aliased Interfaces.C.char_array := Interfaces.C.To_C ("siphash", True);

   function Cipher_Name_Ptr
     (C : Cipher_Type) return Interfaces.C.Strings.chars_ptr is
   begin
      case C is
         when Aes_128_Ctr =>
            return Interfaces.C.Strings.To_Chars_Ptr
                     (Cipher_Names_Aes'Unchecked_Access);
         when Cha_Cha_20 =>
            return Interfaces.C.Strings.To_Chars_Ptr
                     (Cipher_Names_Cha'Unchecked_Access);
         when Sip_Hash_24 =>
            return Interfaces.C.Strings.To_Chars_Ptr
                     (Cipher_Names_Sip'Unchecked_Access);
      end case;
   end Cipher_Name_Ptr;

   --  Translates an FFI return code to an Ada exception. OK is a
   --  no-op; every other code routes through the existing
   --  Itb.Errors.Raise_For pipeline so the wrapper exceptions sit in
   --  the same hierarchy as every other binding-level exception.
   procedure Check (Status : Interfaces.C.int) is
      use Interfaces.C;
   begin
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end Check;

   --  Probes Key_Size / Nonce_Size via the FFI. The bare-FFI route
   --  is used here rather than caching at elaboration so a future
   --  libitb update that adds a fourth outer cipher is detected as
   --  an Itb_Error rather than silently reading a stale cached
   --  value.
   function Probe_Key_Size (C : Cipher_Type) return Natural is
      use Interfaces.C;
      Out_Sz : aliased size_t := 0;
      Status : int;
   begin
      Status := Itb.Sys.ITB_WrapperKeySize
                  (Cipher_Name_Ptr (C), Out_Sz'Access);
      Check (Status);
      return Natural (Out_Sz);
   end Probe_Key_Size;

   function Probe_Nonce_Size (C : Cipher_Type) return Natural is
      use Interfaces.C;
      Out_Sz : aliased size_t := 0;
      Status : int;
   begin
      Status := Itb.Sys.ITB_WrapperNonceSize
                  (Cipher_Name_Ptr (C), Out_Sz'Access);
      Check (Status);
      return Natural (Out_Sz);
   end Probe_Nonce_Size;

   ---------------------------------------------------------------------
   --  Public metadata + key-generation accessors
   ---------------------------------------------------------------------

   function Key_Size (C : Cipher_Type) return Natural is
   begin
      return Probe_Key_Size (C);
   end Key_Size;

   function Nonce_Size (C : Cipher_Type) return Natural is
   begin
      return Probe_Nonce_Size (C);
   end Nonce_Size;

   function Generate_Key (C : Cipher_Type) return Byte_Array is
      N : constant Natural := Probe_Key_Size (C);
      Out_Buf : Byte_Array (1 .. Stream_Element_Offset (N));
      Word    : Unsigned_32;
   begin
      Seed_Rng;
      --  Fill the buffer four bytes at a time from the MT generator.
      --  The trailing-byte branch covers nonce-size lengths that are
      --  not multiples of 4 (no shipped cipher hits this — 16 / 32 /
      --  16 are all multiples of 4 — but defensive in case a future
      --  cipher does).
      declare
         I : Stream_Element_Offset := Out_Buf'First;
      begin
         while I + 3 <= Out_Buf'Last loop
            Word := GNAT.Random_Numbers.Random (Rng);
            Out_Buf (I)     := Stream_Element (Word and 16#FF#);
            Out_Buf (I + 1) :=
              Stream_Element (Shift_Right (Word, 8) and 16#FF#);
            Out_Buf (I + 2) :=
              Stream_Element (Shift_Right (Word, 16) and 16#FF#);
            Out_Buf (I + 3) :=
              Stream_Element (Shift_Right (Word, 24) and 16#FF#);
            I := I + 4;
         end loop;
         while I <= Out_Buf'Last loop
            Word := GNAT.Random_Numbers.Random (Rng);
            Out_Buf (I) := Stream_Element (Word and 16#FF#);
            I := I + 1;
         end loop;
      end;
      return Out_Buf;
   end Generate_Key;

   ---------------------------------------------------------------------
   --  Internal: bound-check helpers
   ---------------------------------------------------------------------

   --  Validates that the caller-supplied key length matches the
   --  cipher's expected key size. Routes a mismatch through the
   --  existing Itb.Errors.Raise_For pipeline as Bad_Input so the
   --  caller catches one canonical exception family.
   procedure Check_Key_Length
     (Cipher : Cipher_Type; Key : Byte_Array)
   is
      Want : constant Natural := Probe_Key_Size (Cipher);
   begin
      if Key'Length /= Stream_Element_Offset (Want) then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
   end Check_Key_Length;

   --  Validates that an out-nonce / wire-nonce buffer length matches
   --  the cipher's expected nonce size.
   procedure Check_Nonce_Length
     (Cipher : Cipher_Type; Nonce : Byte_Array)
   is
      Want : constant Natural := Probe_Nonce_Size (Cipher);
   begin
      if Nonce'Length /= Stream_Element_Offset (Want) then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
   end Check_Nonce_Length;

   ---------------------------------------------------------------------
   --  Single Message Wrap / Unwrap (allocating)
   ---------------------------------------------------------------------

   function Wrap
     (Cipher : Cipher_Type;
      Key    : Byte_Array;
      Blob   : Byte_Array) return Byte_Array
   is
      use Interfaces.C;
      N_Len     : constant Natural := Probe_Nonce_Size (Cipher);
      Cap       : constant Stream_Element_Offset :=
        Stream_Element_Offset (N_Len) + Blob'Length;
      Out_Buf   : Byte_Array (1 .. Cap);
      Out_Len   : aliased size_t := 0;
      Status    : int;
      Key_Addr  : constant System.Address :=
        (if Key'Length > 0 then Key'Address else System.Null_Address);
      Blob_Addr : constant System.Address :=
        (if Blob'Length > 0 then Blob'Address else System.Null_Address);
      Out_Addr  : constant System.Address :=
        (if Cap > 0 then Out_Buf'Address else System.Null_Address);
   begin
      Check_Key_Length (Cipher, Key);
      Status := Itb.Sys.ITB_Wrap
                  (Cipher_Name => Cipher_Name_Ptr (Cipher),
                   Key         => Key_Addr,
                   Key_Len     => size_t (Key'Length),
                   Blob        => Blob_Addr,
                   Blob_Len    => size_t (Blob'Length),
                   Out_Buf     => Out_Addr,
                   Out_Cap     => size_t (Cap),
                   Out_Len     => Out_Len'Access);
      Check (Status);
      return Out_Buf (1 .. Stream_Element_Offset (Out_Len));
   end Wrap;

   function Unwrap
     (Cipher : Cipher_Type;
      Key    : Byte_Array;
      Wire   : Byte_Array) return Byte_Array
   is
      use Interfaces.C;
      N_Len     : constant Natural := Probe_Nonce_Size (Cipher);
      Body_Len  : Stream_Element_Offset;
      Out_Len   : aliased size_t := 0;
      Status    : int;
      Key_Addr  : constant System.Address :=
        (if Key'Length > 0 then Key'Address else System.Null_Address);
      Wire_Addr : constant System.Address :=
        (if Wire'Length > 0 then Wire'Address else System.Null_Address);
   begin
      Check_Key_Length (Cipher, Key);
      if Wire'Length < Stream_Element_Offset (N_Len) then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      Body_Len := Wire'Length - Stream_Element_Offset (N_Len);
      declare
         --  Pre-size to at least 1 byte so the FFI receives a
         --  non-null pointer even when the body is empty (the libitb
         --  validation accepts a NULL pointer paired with cap=0 but
         --  the explicit-non-null branch is the documented hot path).
         Out_Cap : constant Stream_Element_Offset :=
           Stream_Element_Offset'Max (Body_Len, 1);
         Out_Buf : Byte_Array (1 .. Out_Cap);
      begin
         Status := Itb.Sys.ITB_Unwrap
                     (Cipher_Name => Cipher_Name_Ptr (Cipher),
                      Key         => Key_Addr,
                      Key_Len     => size_t (Key'Length),
                      Wire        => Wire_Addr,
                      Wire_Len    => size_t (Wire'Length),
                      Out_Buf     => Out_Buf'Address,
                      Out_Cap     => size_t (Body_Len),
                      Out_Len     => Out_Len'Access);
         Check (Status);
         return Out_Buf (1 .. Stream_Element_Offset (Out_Len));
      end;
   end Unwrap;

   ---------------------------------------------------------------------
   --  Single Message Wrap / Unwrap (in-place mutation)
   ---------------------------------------------------------------------

   procedure Wrap_In_Place
     (Cipher    : Cipher_Type;
      Key       : Byte_Array;
      Blob      : in out Byte_Array;
      Out_Nonce : out Byte_Array)
   is
      use Interfaces.C;
      Status    : int;
      Want_N    : constant Natural := Probe_Nonce_Size (Cipher);
      Nonce_Len : constant Stream_Element_Offset := Out_Nonce'Length;
      Nonce_Addr : constant System.Address := Out_Nonce'Address;
      Key_Addr  : constant System.Address :=
        (if Key'Length > 0 then Key'Address else System.Null_Address);
      Blob_Addr : constant System.Address :=
        (if Blob'Length > 0 then Blob'Address else System.Null_Address);
   begin
      Check_Key_Length (Cipher, Key);
      if Nonce_Len /= Stream_Element_Offset (Want_N) then
         --  Initialise the output array before propagating the
         --  exception so the compiler sees it written along the
         --  raise-and-return path.
         Out_Nonce := [others => 0];
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      Status := Itb.Sys.ITB_WrapInPlace
                  (Cipher_Name => Cipher_Name_Ptr (Cipher),
                   Key         => Key_Addr,
                   Key_Len     => size_t (Key'Length),
                   Blob        => Blob_Addr,
                   Blob_Len    => size_t (Blob'Length),
                   Out_Nonce   => Nonce_Addr,
                   Nonce_Cap   => size_t (Nonce_Len));
      Check (Status);
   end Wrap_In_Place;

   procedure Unwrap_In_Place
     (Cipher     : Cipher_Type;
      Key        : Byte_Array;
      Wire       : in out Byte_Array;
      Body_First : out Stream_Element_Offset)
   is
      use Interfaces.C;
      N_Len     : constant Natural := Probe_Nonce_Size (Cipher);
      Status    : int;
      Key_Addr  : constant System.Address :=
        (if Key'Length > 0 then Key'Address else System.Null_Address);
      Wire_Addr : constant System.Address :=
        (if Wire'Length > 0 then Wire'Address else System.Null_Address);
   begin
      Check_Key_Length (Cipher, Key);
      if Wire'Length < Stream_Element_Offset (N_Len) then
         Body_First := Wire'First;
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      Status := Itb.Sys.ITB_UnwrapInPlace
                  (Cipher_Name => Cipher_Name_Ptr (Cipher),
                   Key         => Key_Addr,
                   Key_Len     => size_t (Key'Length),
                   Wire        => Wire_Addr,
                   Wire_Len    => size_t (Wire'Length));
      Check (Status);
      Body_First := Wire'First + Stream_Element_Offset (N_Len);
   end Unwrap_In_Place;

   ---------------------------------------------------------------------
   --  Streaming wrap-encrypt handle
   ---------------------------------------------------------------------

   procedure Initialize
     (Self      : in out Wrap_Stream_Writer;
      Cipher    : Cipher_Type;
      Key       : Byte_Array;
      Out_Nonce : out Byte_Array)
   is
      use Interfaces.C;
      Handle     : aliased Itb.Sys.Handle := 0;
      Status     : int;
      Want_N     : constant Natural := Probe_Nonce_Size (Cipher);
      Nonce_Len  : constant Stream_Element_Offset := Out_Nonce'Length;
      Nonce_Addr : constant System.Address := Out_Nonce'Address;
      Key_Addr   : constant System.Address :=
        (if Key'Length > 0 then Key'Address else System.Null_Address);
   begin
      Check_Key_Length (Cipher, Key);
      if Nonce_Len /= Stream_Element_Offset (Want_N) then
         Out_Nonce := [others => 0];
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;

      --  Release any prior handle bound to this writer so a
      --  re-Initialize call does not leak (RAII would catch this on
      --  scope exit, but explicit re-binding may happen during a
      --  long-running session that resets per stream).
      if not Self.Closed and then Self.Handle /= 0 then
         declare
            Free_Status : int := Itb.Sys.ITB_WrapStreamWriter_Free (Self.Handle);
            pragma Unreferenced (Free_Status);
         begin
            Self.Handle := 0;
         end;
      end if;

      Status := Itb.Sys.ITB_WrapStreamWriter_Init
                  (Cipher_Name => Cipher_Name_Ptr (Cipher),
                   Key         => Key_Addr,
                   Key_Len     => size_t (Key'Length),
                   Out_Nonce   => Nonce_Addr,
                   Nonce_Cap   => size_t (Nonce_Len),
                   Out_Handle  => Handle'Access);
      Check (Status);
      Self.Handle := Handle;
      Self.Bound  := Cipher;
      Self.Closed := False;
   end Initialize;

   procedure Update
     (Self : in out Wrap_Stream_Writer;
      Src  : Byte_Array;
      Dst  : out Byte_Array;
      Last : out Stream_Element_Offset)
   is
      use Interfaces.C;
      Status   : int;
      Src_Addr : constant System.Address :=
        (if Src'Length > 0 then Src'Address else System.Null_Address);
      Dst_Addr : constant System.Address :=
        (if Dst'Length > 0 then Dst'Address else System.Null_Address);
   begin
      if Self.Closed or else Self.Handle = 0 then
         Itb.Errors.Raise_For (Itb.Status.Bad_Handle);
      end if;
      if Dst'Length < Src'Length then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      if Src'Length = 0 then
         Last := Dst'First - 1;
         return;
      end if;
      Status := Itb.Sys.ITB_WrapStreamWriter_Update
                  (H       => Self.Handle,
                   Src     => Src_Addr,
                   Src_Len => size_t (Src'Length),
                   Dst     => Dst_Addr,
                   Dst_Cap => size_t (Dst'Length));
      Check (Status);
      Last := Dst'First + Src'Length - 1;
   end Update;

   function Cipher (Self : Wrap_Stream_Writer) return Cipher_Type is
   begin
      return Self.Bound;
   end Cipher;

   procedure Close (Self : in out Wrap_Stream_Writer) is
      use Interfaces.C;
      Status : int;
      pragma Unreferenced (Status);
   begin
      if Self.Closed or else Self.Handle = 0 then
         Self.Closed := True;
         Self.Handle := 0;
         return;
      end if;
      Status := Itb.Sys.ITB_WrapStreamWriter_Free (Self.Handle);
      Self.Handle := 0;
      Self.Closed := True;
   end Close;

   overriding procedure Finalize (Self : in out Wrap_Stream_Writer) is
   begin
      Close (Self);
   end Finalize;

   ---------------------------------------------------------------------
   --  Streaming wrap-decrypt handle
   ---------------------------------------------------------------------

   procedure Initialize
     (Self       : in out Unwrap_Stream_Reader;
      Cipher     : Cipher_Type;
      Key        : Byte_Array;
      Wire_Nonce : Byte_Array)
   is
      use Interfaces.C;
      Handle     : aliased Itb.Sys.Handle := 0;
      Status     : int;
      Key_Addr   : constant System.Address :=
        (if Key'Length > 0 then Key'Address else System.Null_Address);
      Nonce_Addr : constant System.Address :=
        (if Wire_Nonce'Length > 0 then Wire_Nonce'Address
         else System.Null_Address);
   begin
      Check_Key_Length (Cipher, Key);
      Check_Nonce_Length (Cipher, Wire_Nonce);

      if not Self.Closed and then Self.Handle /= 0 then
         declare
            Free_Status : int :=
              Itb.Sys.ITB_UnwrapStreamReader_Free (Self.Handle);
            pragma Unreferenced (Free_Status);
         begin
            Self.Handle := 0;
         end;
      end if;

      Status := Itb.Sys.ITB_UnwrapStreamReader_Init
                  (Cipher_Name => Cipher_Name_Ptr (Cipher),
                   Key         => Key_Addr,
                   Key_Len     => size_t (Key'Length),
                   Wire_Nonce  => Nonce_Addr,
                   Nonce_Len   => size_t (Wire_Nonce'Length),
                   Out_Handle  => Handle'Access);
      Check (Status);
      Self.Handle := Handle;
      Self.Bound  := Cipher;
      Self.Closed := False;
   end Initialize;

   procedure Update
     (Self : in out Unwrap_Stream_Reader;
      Src  : Byte_Array;
      Dst  : out Byte_Array;
      Last : out Stream_Element_Offset)
   is
      use Interfaces.C;
      Status   : int;
      Src_Addr : constant System.Address :=
        (if Src'Length > 0 then Src'Address else System.Null_Address);
      Dst_Addr : constant System.Address :=
        (if Dst'Length > 0 then Dst'Address else System.Null_Address);
   begin
      if Self.Closed or else Self.Handle = 0 then
         Itb.Errors.Raise_For (Itb.Status.Bad_Handle);
      end if;
      if Dst'Length < Src'Length then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      if Src'Length = 0 then
         Last := Dst'First - 1;
         return;
      end if;
      Status := Itb.Sys.ITB_UnwrapStreamReader_Update
                  (H       => Self.Handle,
                   Src     => Src_Addr,
                   Src_Len => size_t (Src'Length),
                   Dst     => Dst_Addr,
                   Dst_Cap => size_t (Dst'Length));
      Check (Status);
      Last := Dst'First + Src'Length - 1;
   end Update;

   function Cipher (Self : Unwrap_Stream_Reader) return Cipher_Type is
   begin
      return Self.Bound;
   end Cipher;

   procedure Close (Self : in out Unwrap_Stream_Reader) is
      use Interfaces.C;
      Status : int;
      pragma Unreferenced (Status);
   begin
      if Self.Closed or else Self.Handle = 0 then
         Self.Closed := True;
         Self.Handle := 0;
         return;
      end if;
      Status := Itb.Sys.ITB_UnwrapStreamReader_Free (Self.Handle);
      Self.Handle := 0;
      Self.Closed := True;
   end Close;

   overriding procedure Finalize (Self : in out Unwrap_Stream_Reader) is
   begin
      Close (Self);
   end Finalize;

end Itb.Wrapper;
