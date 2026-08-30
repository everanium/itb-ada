--  Itb — root of the Ada thin-proxy binding over the libitb shared
--  library's Triple Pipeline C ABI surface (cmd/cshared).
--
--  The binding carries no ITB construction logic of its own: every
--  hash-name / MAC-name / cipher-name / profile-name is an opaque
--  String passed through to Go for validation, and every chunking /
--  MAC / envelope / wire-format decision stays inside libitb. The
--  wrapper surface is split across child packages:
--
--    Itb.Status    Numeric status codes mirrored from the C ABI
--                  (cmd/cshared/internal/capi/errors.go).
--    Itb.Error     Itb_Error exception + structured-payload accessors.
--    Itb.Opts      URL-query builder for the opts pass-through string.
--    Itb.Pipeline  Triple Pipeline session — Init / Open / Rekey /
--                  Close, Single Message encrypt / decrypt, one-shot
--                  stream ciphers, profile registration.
--    Itb.Stream    Incremental stream sessions over an open Pipeline.
--    Itb.Runtime   Library version string + Go runtime knobs.
--
--  C ABI source-of-truth: dist/<os>-<arch>/libitb.h. The raw FFI
--  declarations live in this package's private part so every child
--  body shares them without exposing an unsafe public layer.

with Ada.Streams;

private with Interfaces.C;
private with System;

package Itb is
   pragma Preelaborate;

   --  Byte buffer type used at every binding boundary that takes
   --  arbitrary plaintext / wire / session-blob bytes.
   subtype Byte_Array is Ada.Streams.Stream_Element_Array;

   type Byte_Array_Access is access Byte_Array;

   --  Releases a heap-allocated byte buffer. Null-safe.
   procedure Free (Buffer : in out Byte_Array_Access);

   --  Opaque libitb object handle. Internal to the binding — exposed
   --  as a type name only so child packages can share it across
   --  package boundaries; user code has no operations on it.
   type Handle is private;

   --  Latin-1 String <-> byte-buffer conversions for callers moving
   --  textual payloads across the binding boundary.
   function To_Byte_Array (S : String) return Byte_Array;
   function To_String (B : Byte_Array) return String;

private

   type Handle is mod 2 ** Standard'Address_Size;
   for Handle'Size use Standard'Address_Size;

   Null_Handle : constant Handle := 0;

   subtype C_Int  is Interfaces.C.int;
   subtype Size_T is Interfaces.C.size_t;

   ---------------------------------------------------------------------
   --  Raw FFI imports. Every signature mirrors the corresponding
   --  `extern int ITB_*` prototype in libitb.h; C `size_t` maps to
   --  Interfaces.C.size_t, C `uintptr_t` to Handle, buffer pointers
   --  to System.Address. `char*` inputs cross as the address of a
   --  NUL-terminated Interfaces.C.char_array held by the caller.
   ---------------------------------------------------------------------

   function ITB_Version
     (Out_Buf : System.Address;
      Cap     : Size_T;
      Out_Len : access Size_T) return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Version";

   function ITB_LastError
     (Out_Buf : System.Address;
      Cap     : Size_T;
      Out_Len : access Size_T) return C_Int
   with Import => True, Convention => C, External_Name => "ITB_LastError";

   function ITB_SetMemoryLimit
     (Limit : Interfaces.Integer_64) return Interfaces.Integer_64
   with Import => True, Convention => C,
        External_Name => "ITB_SetMemoryLimit";

   function ITB_SetGCPercent (Pct : C_Int) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_SetGCPercent";

   function ITB_Triple_Init
     (Profile    : System.Address;
      Opts       : System.Address;
      Blob_Out   : System.Address;
      Blob_Cap   : Size_T;
      Blob_Len   : access Size_T;
      Out_Handle : access Handle) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Triple_Init";

   function ITB_Triple_Open
     (Profile         : System.Address;
      Blob            : System.Address;
      Blob_Len        : Size_T;
      Opts            : System.Address;
      Perm_Master     : System.Address;
      Perm_Master_Len : Size_T;
      Wrap_Master     : System.Address;
      Wrap_Master_Len : Size_T;
      Masters_Count   : Size_T;
      Out_Handle      : access Handle) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Triple_Open";

   function ITB_Triple_Rekey
     (H               : Handle;
      Perm_Master     : System.Address;
      Perm_Master_Len : Size_T;
      Wrap_Master     : System.Address;
      Wrap_Master_Len : Size_T;
      Blob_Out        : System.Address;
      Blob_Cap        : Size_T;
      Blob_Len        : access Size_T) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Triple_Rekey";

   function ITB_Triple_Close (H : Handle) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Triple_Close";

   function ITB_Triple_Free (H : Handle) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Triple_Free";

   function ITB_Triple_EncryptStream
     (H       : Handle;
      Src     : System.Address;
      Src_Len : Size_T;
      Out_Buf : System.Address;
      Out_Cap : Size_T;
      Out_Len : access Size_T) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Triple_EncryptStream";

   function ITB_Triple_DecryptStream
     (H       : Handle;
      Src     : System.Address;
      Src_Len : Size_T;
      Out_Buf : System.Address;
      Out_Cap : Size_T;
      Out_Len : access Size_T) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Triple_DecryptStream";

   function ITB_Triple_EncryptMessage
     (H       : Handle;
      Src     : System.Address;
      Src_Len : Size_T;
      Out_Buf : System.Address;
      Out_Cap : Size_T;
      Out_Len : access Size_T) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Triple_EncryptMessage";

   function ITB_Triple_DecryptMessage
     (H       : Handle;
      Src     : System.Address;
      Src_Len : Size_T;
      Out_Buf : System.Address;
      Out_Cap : Size_T;
      Out_Len : access Size_T) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Triple_DecryptMessage";

   function ITB_Triple_RegisterProfile
     (Name : System.Address;
      Opts : System.Address) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Triple_RegisterProfile";

   function ITB_Triple_EncryptStreamBegin
     (Pipe       : Handle;
      Out_Stream : access Handle) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Triple_EncryptStreamBegin";

   function ITB_Triple_DecryptStreamBegin
     (Pipe       : Handle;
      Out_Stream : access Handle) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Triple_DecryptStreamBegin";

   function ITB_Triple_StreamWrite
     (Stream  : Handle;
      Src     : System.Address;
      Src_Len : Size_T) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Triple_StreamWrite";

   function ITB_Triple_StreamEnd (Stream : Handle) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Triple_StreamEnd";

   function ITB_Triple_StreamRead
     (Stream   : Handle;
      Out_Buf  : System.Address;
      Out_Cap  : Size_T;
      Out_Len  : access Size_T;
      Finished : access C_Int) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Triple_StreamRead";

   function ITB_Triple_StreamFree (Stream : Handle) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Triple_StreamFree";

end Itb;
