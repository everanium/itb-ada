--  Itb.Sys — raw FFI declarations over libitb's C ABI.
--
--  Every public subprogram in this package is a `pragma Import (C,
--  Convention => C, External_Name => "ITB_*")` over a C function
--  exported by libitb. This is the unsafe layer of the binding: no
--  range checks, no exception translation, no handle lifecycle
--  management. The corresponding safe Ada wrappers in Itb.Seed /
--  Itb.MAC / Itb.Encryptor / Itb.Cipher / Itb.Blob / Itb.Streams cover
--  the typical use cases; reach into Itb.Sys directly only when the
--  safe wrappers do not surface a needed capability.
--
--  C ABI source-of-truth: dist/<os>-<arch>/libitb.h. Every signature
--  here mirrors the corresponding `extern int ITB_*` declaration in
--  that header file.
--
--  Type mapping:
--    C `int`         → Itb.Sys.C_Int        (= Interfaces.C.int)
--    C `size_t`      → Itb.Sys.Size_T       (= Interfaces.C.size_t)
--    C `uintptr_t`   → Itb.Sys.Handle       (modular, host-word-sized)
--    C `uint64_t`    → Itb.Sys.U64          (= Interfaces.Unsigned_64)
--    C `uint8_t`     → Itb.Sys.U8           (= Interfaces.Unsigned_8)
--    C `void*`       → System.Address
--    C `uint8_t*`    → System.Address
--    C `uint64_t*`   → System.Address
--    C `char*` (in)  → Itb.Sys.C_String     (= Interfaces.C.Strings.chars_ptr)
--    C `char*` (out) → System.Address       (caller-owned buffer)
--    C `int*`        → access C_Int
--    C `size_t*`     → access Size_T
--
--  Threading note. ITB_LastError and ITB_Easy_LastMismatchField read
--  process-global state that follows the C `errno` discipline: the
--  most recent non-OK status across the whole process wins, and a
--  sibling task that calls into libitb between the failing call and
--  the diagnostic read overwrites the message. Multi-tasking Ada
--  applications that need reliable diagnostic attribution should
--  serialise FFI calls under a protected object or accept that the
--  textual message returned via the diagnostic accessor may belong
--  to a different call. The structural status code on the failing
--  call's return value is unaffected — only the textual diagnostic
--  is racy.
--
--  SPARK formal verification is intentionally Off in this package
--  because every entry point is an external C import. The safe
--  wrappers above this layer are SPARK-eligible at the maintainer's
--  discretion (decided post-Phase-8 audit).

with Interfaces;
with Interfaces.C;
with Interfaces.C.Strings;
with System;

package Itb.Sys is
   pragma Preelaborate;

   ---------------------------------------------------------------------
   --  Type aliases
   ---------------------------------------------------------------------

   --  Pointer-width unsigned integer matching `uintptr_t`. libitb
   --  returns these as Seed / MAC / Encryptor / Blob handles. The
   --  size constraint pins the binary representation to the host
   --  word size so the C ABI roundtrip is exact.
   type Handle is mod 2 ** Standard'Address_Size;
   for Handle'Size use Standard'Address_Size;

   subtype C_Int    is Interfaces.C.int;
   subtype Size_T   is Interfaces.C.size_t;
   subtype U64      is Interfaces.Unsigned_64;
   subtype U8       is Interfaces.Unsigned_8;
   subtype C_String is Interfaces.C.Strings.chars_ptr;

   --  Convenience constant for a NULL `chars_ptr` — used for optional
   --  input strings (e.g. macName=nullptr → "use the binding default").
   Null_String : C_String renames Interfaces.C.Strings.Null_Ptr;

   ---------------------------------------------------------------------
   --  Library metadata + globals
   ---------------------------------------------------------------------

   function ITB_Version
     (Out_Buf : System.Address;
      Cap     : Size_T;
      Out_Len : access Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Version";

   function ITB_HashCount return C_Int
   with Import => True, Convention => C, External_Name => "ITB_HashCount";

   function ITB_HashName
     (I       : C_Int;
      Out_Buf : System.Address;
      Cap     : Size_T;
      Out_Len : access Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_HashName";

   function ITB_HashWidth (I : C_Int) return C_Int
   with Import => True, Convention => C, External_Name => "ITB_HashWidth";

   function ITB_LastError
     (Out_Buf : System.Address;
      Cap     : Size_T;
      Out_Len : access Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_LastError";

   ---------------------------------------------------------------------
   --  Seed (low-level)
   ---------------------------------------------------------------------

   function ITB_NewSeed
     (Hash_Name  : C_String;
      Key_Bits   : C_Int;
      Out_Handle : access Handle)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_NewSeed";

   function ITB_FreeSeed (H : Handle) return C_Int
   with Import => True, Convention => C, External_Name => "ITB_FreeSeed";

   function ITB_SeedWidth
     (H          : Handle;
      Out_Status : access C_Int)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_SeedWidth";

   function ITB_SeedHashName
     (H       : Handle;
      Out_Buf : System.Address;
      Cap     : Size_T;
      Out_Len : access Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_SeedHashName";

   function ITB_NewSeedFromComponents
     (Hash_Name       : C_String;
      Components      : System.Address;  --  uint64_t*
      Components_Len  : C_Int;
      Hash_Key        : System.Address;  --  uint8_t*
      Hash_Key_Len    : C_Int;
      Out_Handle      : access Handle)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_NewSeedFromComponents";

   function ITB_GetSeedHashKey
     (H       : Handle;
      Out_Buf : System.Address;  --  uint8_t*
      Cap     : Size_T;
      Out_Len : access Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_GetSeedHashKey";

   function ITB_GetSeedComponents
     (H       : Handle;
      Out_Buf : System.Address;  --  uint64_t*
      Cap     : C_Int;
      Out_Len : access C_Int)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_GetSeedComponents";

   ---------------------------------------------------------------------
   --  Encrypt / Decrypt — Single Ouroboros (3-seed)
   ---------------------------------------------------------------------

   function ITB_Encrypt
     (Noise_Handle : Handle;
      Data_Handle  : Handle;
      Start_Handle : Handle;
      Plaintext    : System.Address;
      Pt_Len       : Size_T;
      Out_Buf      : System.Address;
      Out_Cap      : Size_T;
      Out_Len      : access Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Encrypt";

   function ITB_Decrypt
     (Noise_Handle : Handle;
      Data_Handle  : Handle;
      Start_Handle : Handle;
      Ciphertext   : System.Address;
      Ct_Len       : Size_T;
      Out_Buf      : System.Address;
      Out_Cap      : Size_T;
      Out_Len      : access Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Decrypt";

   ---------------------------------------------------------------------
   --  Encrypt / Decrypt — Triple Ouroboros (7-seed)
   ---------------------------------------------------------------------

   function ITB_Encrypt3
     (Noise_Handle  : Handle;
      Data_Handle1  : Handle;
      Data_Handle2  : Handle;
      Data_Handle3  : Handle;
      Start_Handle1 : Handle;
      Start_Handle2 : Handle;
      Start_Handle3 : Handle;
      Plaintext     : System.Address;
      Pt_Len        : Size_T;
      Out_Buf       : System.Address;
      Out_Cap       : Size_T;
      Out_Len       : access Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Encrypt3";

   function ITB_Decrypt3
     (Noise_Handle  : Handle;
      Data_Handle1  : Handle;
      Data_Handle2  : Handle;
      Data_Handle3  : Handle;
      Start_Handle1 : Handle;
      Start_Handle2 : Handle;
      Start_Handle3 : Handle;
      Ciphertext    : System.Address;
      Ct_Len        : Size_T;
      Out_Buf       : System.Address;
      Out_Cap       : Size_T;
      Out_Len       : access Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Decrypt3";

   ---------------------------------------------------------------------
   --  MAC
   ---------------------------------------------------------------------

   function ITB_MACCount return C_Int
   with Import => True, Convention => C, External_Name => "ITB_MACCount";

   function ITB_MACName
     (I       : C_Int;
      Out_Buf : System.Address;
      Cap     : Size_T;
      Out_Len : access Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_MACName";

   function ITB_MACKeySize (I : C_Int) return C_Int
   with Import => True, Convention => C, External_Name => "ITB_MACKeySize";

   function ITB_MACTagSize (I : C_Int) return C_Int
   with Import => True, Convention => C, External_Name => "ITB_MACTagSize";

   function ITB_MACMinKeyBytes (I : C_Int) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_MACMinKeyBytes";

   function ITB_NewMAC
     (Mac_Name   : C_String;
      Key        : System.Address;
      Key_Len    : Size_T;
      Out_Handle : access Handle)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_NewMAC";

   function ITB_FreeMAC (H : Handle) return C_Int
   with Import => True, Convention => C, External_Name => "ITB_FreeMAC";

   ---------------------------------------------------------------------
   --  EncryptAuth / DecryptAuth — authenticated cipher (Single + Triple)
   ---------------------------------------------------------------------

   function ITB_EncryptAuth
     (Noise_Handle : Handle;
      Data_Handle  : Handle;
      Start_Handle : Handle;
      MAC_Handle   : Handle;
      Plaintext    : System.Address;
      Pt_Len       : Size_T;
      Out_Buf      : System.Address;
      Out_Cap      : Size_T;
      Out_Len      : access Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_EncryptAuth";

   function ITB_DecryptAuth
     (Noise_Handle : Handle;
      Data_Handle  : Handle;
      Start_Handle : Handle;
      MAC_Handle   : Handle;
      Ciphertext   : System.Address;
      Ct_Len       : Size_T;
      Out_Buf      : System.Address;
      Out_Cap      : Size_T;
      Out_Len      : access Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_DecryptAuth";

   function ITB_EncryptAuth3
     (Noise_Handle  : Handle;
      Data_Handle1  : Handle;
      Data_Handle2  : Handle;
      Data_Handle3  : Handle;
      Start_Handle1 : Handle;
      Start_Handle2 : Handle;
      Start_Handle3 : Handle;
      MAC_Handle    : Handle;
      Plaintext     : System.Address;
      Pt_Len        : Size_T;
      Out_Buf       : System.Address;
      Out_Cap       : Size_T;
      Out_Len       : access Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_EncryptAuth3";

   function ITB_DecryptAuth3
     (Noise_Handle  : Handle;
      Data_Handle1  : Handle;
      Data_Handle2  : Handle;
      Data_Handle3  : Handle;
      Start_Handle1 : Handle;
      Start_Handle2 : Handle;
      Start_Handle3 : Handle;
      MAC_Handle    : Handle;
      Ciphertext    : System.Address;
      Ct_Len        : Size_T;
      Out_Buf       : System.Address;
      Out_Cap       : Size_T;
      Out_Len       : access Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_DecryptAuth3";

   ---------------------------------------------------------------------
   --  Library-level configuration (process-global)
   ---------------------------------------------------------------------

   function ITB_SetBitSoup (Mode : C_Int) return C_Int
   with Import => True, Convention => C, External_Name => "ITB_SetBitSoup";

   function ITB_GetBitSoup return C_Int
   with Import => True, Convention => C, External_Name => "ITB_GetBitSoup";

   function ITB_SetLockSoup (Mode : C_Int) return C_Int
   with Import => True, Convention => C, External_Name => "ITB_SetLockSoup";

   function ITB_GetLockSoup return C_Int
   with Import => True, Convention => C, External_Name => "ITB_GetLockSoup";

   function ITB_SetMaxWorkers (N : C_Int) return C_Int
   with Import => True, Convention => C, External_Name => "ITB_SetMaxWorkers";

   function ITB_GetMaxWorkers return C_Int
   with Import => True, Convention => C, External_Name => "ITB_GetMaxWorkers";

   function ITB_SetNonceBits (N : C_Int) return C_Int
   with Import => True, Convention => C, External_Name => "ITB_SetNonceBits";

   function ITB_GetNonceBits return C_Int
   with Import => True, Convention => C, External_Name => "ITB_GetNonceBits";

   function ITB_SetBarrierFill (N : C_Int) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_SetBarrierFill";

   function ITB_GetBarrierFill return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_GetBarrierFill";

   function ITB_SetMemoryLimit
     (Limit : Interfaces.Integer_64) return Interfaces.Integer_64
   with Import => True, Convention => C,
        External_Name => "ITB_SetMemoryLimit";

   function ITB_SetGCPercent (Pct : C_Int) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_SetGCPercent";

   ---------------------------------------------------------------------
   --  Header / chunk-len / max-key-bits utilities
   ---------------------------------------------------------------------

   function ITB_ParseChunkLen
     (Header     : System.Address;
      Header_Len : Size_T;
      Out_Chunk  : access Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_ParseChunkLen";

   function ITB_MaxKeyBits return C_Int
   with Import => True, Convention => C, External_Name => "ITB_MaxKeyBits";

   function ITB_Channels return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Channels";

   function ITB_HeaderSize return C_Int
   with Import => True, Convention => C, External_Name => "ITB_HeaderSize";

   ---------------------------------------------------------------------
   --  AttachLockSeed
   ---------------------------------------------------------------------

   function ITB_AttachLockSeed
     (Noise_Handle : Handle;
      Lock_Handle  : Handle)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_AttachLockSeed";

   ---------------------------------------------------------------------
   --  Easy Mode encryptor
   ---------------------------------------------------------------------

   function ITB_Easy_New
     (Primitive  : C_String;
      Key_Bits   : C_Int;
      Mac_Name   : C_String;
      Mode       : C_Int;
      Out_Handle : access Handle)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Easy_New";

   function ITB_Easy_NewMixed
     (Prim_N     : C_String;
      Prim_D     : C_String;
      Prim_S     : C_String;
      Prim_L     : C_String;
      Key_Bits   : C_Int;
      Mac_Name   : C_String;
      Out_Handle : access Handle)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Easy_NewMixed";

   function ITB_Easy_NewMixed3
     (Prim_N     : C_String;
      Prim_D1    : C_String;
      Prim_D2    : C_String;
      Prim_D3    : C_String;
      Prim_S1    : C_String;
      Prim_S2    : C_String;
      Prim_S3    : C_String;
      Prim_L     : C_String;
      Key_Bits   : C_Int;
      Mac_Name   : C_String;
      Out_Handle : access Handle)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Easy_NewMixed3";

   function ITB_Easy_Free (H : Handle) return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Easy_Free";

   function ITB_Easy_PrimitiveAt
     (H       : Handle;
      Slot    : C_Int;
      Out_Buf : System.Address;
      Cap     : Size_T;
      Out_Len : access Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Easy_PrimitiveAt";

   function ITB_Easy_IsMixed
     (H          : Handle;
      Out_Status : access C_Int)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Easy_IsMixed";

   function ITB_Easy_Encrypt
     (H         : Handle;
      Plaintext : System.Address;
      Pt_Len    : Size_T;
      Out_Buf   : System.Address;
      Out_Cap   : Size_T;
      Out_Len   : access Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Easy_Encrypt";

   function ITB_Easy_Decrypt
     (H          : Handle;
      Ciphertext : System.Address;
      Ct_Len     : Size_T;
      Out_Buf    : System.Address;
      Out_Cap    : Size_T;
      Out_Len    : access Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Easy_Decrypt";

   function ITB_Easy_EncryptAuth
     (H         : Handle;
      Plaintext : System.Address;
      Pt_Len    : Size_T;
      Out_Buf   : System.Address;
      Out_Cap   : Size_T;
      Out_Len   : access Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Easy_EncryptAuth";

   function ITB_Easy_DecryptAuth
     (H          : Handle;
      Ciphertext : System.Address;
      Ct_Len     : Size_T;
      Out_Buf    : System.Address;
      Out_Cap    : Size_T;
      Out_Len    : access Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Easy_DecryptAuth";

   function ITB_Easy_SetNonceBits (H : Handle; N : C_Int) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Easy_SetNonceBits";

   function ITB_Easy_SetBarrierFill (H : Handle; N : C_Int) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Easy_SetBarrierFill";

   function ITB_Easy_SetBitSoup (H : Handle; Mode : C_Int) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Easy_SetBitSoup";

   function ITB_Easy_SetLockSoup (H : Handle; Mode : C_Int) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Easy_SetLockSoup";

   function ITB_Easy_SetLockSeed (H : Handle; Mode : C_Int) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Easy_SetLockSeed";

   function ITB_Easy_SetChunkSize (H : Handle; N : C_Int) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Easy_SetChunkSize";

   function ITB_Easy_Primitive
     (H       : Handle;
      Out_Buf : System.Address;
      Cap     : Size_T;
      Out_Len : access Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Easy_Primitive";

   function ITB_Easy_KeyBits
     (H          : Handle;
      Out_Status : access C_Int)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Easy_KeyBits";

   function ITB_Easy_Mode
     (H          : Handle;
      Out_Status : access C_Int)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Easy_Mode";

   function ITB_Easy_MACName
     (H       : Handle;
      Out_Buf : System.Address;
      Cap     : Size_T;
      Out_Len : access Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Easy_MACName";

   function ITB_Easy_SeedCount
     (H          : Handle;
      Out_Status : access C_Int)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Easy_SeedCount";

   function ITB_Easy_SeedComponents
     (H       : Handle;
      Slot    : C_Int;
      Out_Buf : System.Address;  --  uint64_t*
      Cap     : C_Int;
      Out_Len : access C_Int)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Easy_SeedComponents";

   function ITB_Easy_HasPRFKeys
     (H          : Handle;
      Out_Status : access C_Int)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Easy_HasPRFKeys";

   function ITB_Easy_PRFKey
     (H       : Handle;
      Slot    : C_Int;
      Out_Buf : System.Address;  --  uint8_t*
      Cap     : Size_T;
      Out_Len : access Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Easy_PRFKey";

   function ITB_Easy_MACKey
     (H       : Handle;
      Out_Buf : System.Address;  --  uint8_t*
      Cap     : Size_T;
      Out_Len : access Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Easy_MACKey";

   function ITB_Easy_Close (H : Handle) return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Easy_Close";

   function ITB_Easy_Export
     (H       : Handle;
      Out_Buf : System.Address;
      Out_Cap : Size_T;
      Out_Len : access Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Easy_Export";

   function ITB_Easy_Import
     (H        : Handle;
      Blob     : System.Address;
      Blob_Len : Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Easy_Import";

   function ITB_Easy_PeekConfig
     (Blob       : System.Address;
      Blob_Len   : Size_T;
      Prim_Out   : System.Address;  --  char*
      Prim_Cap   : Size_T;
      Prim_Len   : access Size_T;
      Key_Bits   : access C_Int;
      Mode_Out   : access C_Int;
      Mac_Out    : System.Address;  --  char*
      Mac_Cap    : Size_T;
      Mac_Len    : access Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Easy_PeekConfig";

   function ITB_Easy_LastMismatchField
     (Out_Buf : System.Address;
      Cap     : Size_T;
      Out_Len : access Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Easy_LastMismatchField";

   function ITB_Easy_NonceBits
     (H          : Handle;
      Out_Status : access C_Int)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Easy_NonceBits";

   function ITB_Easy_HeaderSize
     (H          : Handle;
      Out_Status : access C_Int)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Easy_HeaderSize";

   function ITB_Easy_ParseChunkLen
     (H          : Handle;
      Header     : System.Address;
      Header_Len : Size_T;
      Out_Chunk  : access Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Easy_ParseChunkLen";

   ---------------------------------------------------------------------
   --  Native Blob — low-level state persistence
   ---------------------------------------------------------------------

   function ITB_Blob128_New (Out_Handle : access Handle) return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Blob128_New";

   function ITB_Blob256_New (Out_Handle : access Handle) return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Blob256_New";

   function ITB_Blob512_New (Out_Handle : access Handle) return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Blob512_New";

   function ITB_Blob_Free (H : Handle) return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Blob_Free";

   function ITB_Blob_Width
     (H          : Handle;
      Out_Status : access C_Int)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Blob_Width";

   function ITB_Blob_Mode
     (H          : Handle;
      Out_Status : access C_Int)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Blob_Mode";

   function ITB_Blob_SetKey
     (H       : Handle;
      Slot    : C_Int;
      Key     : System.Address;
      Key_Len : Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Blob_SetKey";

   function ITB_Blob_GetKey
     (H       : Handle;
      Slot    : C_Int;
      Out_Buf : System.Address;
      Out_Cap : Size_T;
      Out_Len : access Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Blob_GetKey";

   function ITB_Blob_SetComponents
     (H     : Handle;
      Slot  : C_Int;
      Comps : System.Address;  --  uint64_t*
      Count : Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Blob_SetComponents";

   function ITB_Blob_GetComponents
     (H         : Handle;
      Slot      : C_Int;
      Out_Buf   : System.Address;  --  uint64_t*
      Out_Cap   : Size_T;
      Out_Count : access Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Blob_GetComponents";

   function ITB_Blob_SetMACKey
     (H       : Handle;
      Key     : System.Address;
      Key_Len : Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Blob_SetMACKey";

   function ITB_Blob_GetMACKey
     (H       : Handle;
      Out_Buf : System.Address;
      Out_Cap : Size_T;
      Out_Len : access Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Blob_GetMACKey";

   function ITB_Blob_SetMACName
     (H        : Handle;
      Name     : System.Address;  --  char*
      Name_Len : Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Blob_SetMACName";

   function ITB_Blob_GetMACName
     (H       : Handle;
      Out_Buf : System.Address;  --  char*
      Out_Cap : Size_T;
      Out_Len : access Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Blob_GetMACName";

   function ITB_Blob_Export
     (H            : Handle;
      Opts_Bitmask : C_Int;
      Out_Buf      : System.Address;
      Out_Cap      : Size_T;
      Out_Len      : access Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Blob_Export";

   function ITB_Blob_Export3
     (H            : Handle;
      Opts_Bitmask : C_Int;
      Out_Buf      : System.Address;
      Out_Cap      : Size_T;
      Out_Len      : access Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Blob_Export3";

   function ITB_Blob_Import
     (H        : Handle;
      Blob     : System.Address;
      Blob_Len : Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Blob_Import";

   function ITB_Blob_Import3
     (H        : Handle;
      Blob     : System.Address;
      Blob_Len : Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Blob_Import3";

   ---------------------------------------------------------------------
   --  Streaming AEAD per-chunk ABI surface
   ---------------------------------------------------------------------
   --
   --  One ABI export per (Single / Triple) × (Encrypt / Decrypt) ×
   --  (128 / 256 / 512). The encrypt path takes Stream_ID +
   --  Cumulative_Pixel_Offset + Final_Flag in; the decrypt path
   --  takes Stream_ID + Cumulative_Pixel_Offset in and writes
   --  Final_Flag_Out. Easy Mode counterparts route per-chunk
   --  dispatch through the encryptor's bound config + MAC closure.

   function ITB_EncryptStreamAuthenticated128
     (Noise_Handle              : Handle;
      Data_Handle               : Handle;
      Start_Handle              : Handle;
      MAC_Handle                : Handle;
      Plaintext                 : System.Address;
      Pt_Len                    : Size_T;
      Stream_ID                 : System.Address;
      Cumulative_Pixel_Offset   : U64;
      Final_Flag                : C_Int;
      Out_Buf                   : System.Address;
      Out_Cap                   : Size_T;
      Out_Len                   : access Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_EncryptStreamAuthenticated128";

   function ITB_EncryptStreamAuthenticated256
     (Noise_Handle              : Handle;
      Data_Handle               : Handle;
      Start_Handle              : Handle;
      MAC_Handle                : Handle;
      Plaintext                 : System.Address;
      Pt_Len                    : Size_T;
      Stream_ID                 : System.Address;
      Cumulative_Pixel_Offset   : U64;
      Final_Flag                : C_Int;
      Out_Buf                   : System.Address;
      Out_Cap                   : Size_T;
      Out_Len                   : access Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_EncryptStreamAuthenticated256";

   function ITB_EncryptStreamAuthenticated512
     (Noise_Handle              : Handle;
      Data_Handle               : Handle;
      Start_Handle              : Handle;
      MAC_Handle                : Handle;
      Plaintext                 : System.Address;
      Pt_Len                    : Size_T;
      Stream_ID                 : System.Address;
      Cumulative_Pixel_Offset   : U64;
      Final_Flag                : C_Int;
      Out_Buf                   : System.Address;
      Out_Cap                   : Size_T;
      Out_Len                   : access Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_EncryptStreamAuthenticated512";

   function ITB_DecryptStreamAuthenticated128
     (Noise_Handle              : Handle;
      Data_Handle               : Handle;
      Start_Handle              : Handle;
      MAC_Handle                : Handle;
      Ciphertext                : System.Address;
      Ct_Len                    : Size_T;
      Stream_ID                 : System.Address;
      Cumulative_Pixel_Offset   : U64;
      Out_Buf                   : System.Address;
      Out_Cap                   : Size_T;
      Out_Len                   : access Size_T;
      Final_Flag_Out            : access C_Int)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_DecryptStreamAuthenticated128";

   function ITB_DecryptStreamAuthenticated256
     (Noise_Handle              : Handle;
      Data_Handle               : Handle;
      Start_Handle              : Handle;
      MAC_Handle                : Handle;
      Ciphertext                : System.Address;
      Ct_Len                    : Size_T;
      Stream_ID                 : System.Address;
      Cumulative_Pixel_Offset   : U64;
      Out_Buf                   : System.Address;
      Out_Cap                   : Size_T;
      Out_Len                   : access Size_T;
      Final_Flag_Out            : access C_Int)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_DecryptStreamAuthenticated256";

   function ITB_DecryptStreamAuthenticated512
     (Noise_Handle              : Handle;
      Data_Handle               : Handle;
      Start_Handle              : Handle;
      MAC_Handle                : Handle;
      Ciphertext                : System.Address;
      Ct_Len                    : Size_T;
      Stream_ID                 : System.Address;
      Cumulative_Pixel_Offset   : U64;
      Out_Buf                   : System.Address;
      Out_Cap                   : Size_T;
      Out_Len                   : access Size_T;
      Final_Flag_Out            : access C_Int)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_DecryptStreamAuthenticated512";

   function ITB_EncryptStreamAuthenticated3x128
     (Noise_Handle              : Handle;
      Data_Handle1              : Handle;
      Data_Handle2              : Handle;
      Data_Handle3              : Handle;
      Start_Handle1             : Handle;
      Start_Handle2             : Handle;
      Start_Handle3             : Handle;
      MAC_Handle                : Handle;
      Plaintext                 : System.Address;
      Pt_Len                    : Size_T;
      Stream_ID                 : System.Address;
      Cumulative_Pixel_Offset   : U64;
      Final_Flag                : C_Int;
      Out_Buf                   : System.Address;
      Out_Cap                   : Size_T;
      Out_Len                   : access Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_EncryptStreamAuthenticated3x128";

   function ITB_EncryptStreamAuthenticated3x256
     (Noise_Handle              : Handle;
      Data_Handle1              : Handle;
      Data_Handle2              : Handle;
      Data_Handle3              : Handle;
      Start_Handle1             : Handle;
      Start_Handle2             : Handle;
      Start_Handle3             : Handle;
      MAC_Handle                : Handle;
      Plaintext                 : System.Address;
      Pt_Len                    : Size_T;
      Stream_ID                 : System.Address;
      Cumulative_Pixel_Offset   : U64;
      Final_Flag                : C_Int;
      Out_Buf                   : System.Address;
      Out_Cap                   : Size_T;
      Out_Len                   : access Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_EncryptStreamAuthenticated3x256";

   function ITB_EncryptStreamAuthenticated3x512
     (Noise_Handle              : Handle;
      Data_Handle1              : Handle;
      Data_Handle2              : Handle;
      Data_Handle3              : Handle;
      Start_Handle1             : Handle;
      Start_Handle2             : Handle;
      Start_Handle3             : Handle;
      MAC_Handle                : Handle;
      Plaintext                 : System.Address;
      Pt_Len                    : Size_T;
      Stream_ID                 : System.Address;
      Cumulative_Pixel_Offset   : U64;
      Final_Flag                : C_Int;
      Out_Buf                   : System.Address;
      Out_Cap                   : Size_T;
      Out_Len                   : access Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_EncryptStreamAuthenticated3x512";

   function ITB_DecryptStreamAuthenticated3x128
     (Noise_Handle              : Handle;
      Data_Handle1              : Handle;
      Data_Handle2              : Handle;
      Data_Handle3              : Handle;
      Start_Handle1             : Handle;
      Start_Handle2             : Handle;
      Start_Handle3             : Handle;
      MAC_Handle                : Handle;
      Ciphertext                : System.Address;
      Ct_Len                    : Size_T;
      Stream_ID                 : System.Address;
      Cumulative_Pixel_Offset   : U64;
      Out_Buf                   : System.Address;
      Out_Cap                   : Size_T;
      Out_Len                   : access Size_T;
      Final_Flag_Out            : access C_Int)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_DecryptStreamAuthenticated3x128";

   function ITB_DecryptStreamAuthenticated3x256
     (Noise_Handle              : Handle;
      Data_Handle1              : Handle;
      Data_Handle2              : Handle;
      Data_Handle3              : Handle;
      Start_Handle1             : Handle;
      Start_Handle2             : Handle;
      Start_Handle3             : Handle;
      MAC_Handle                : Handle;
      Ciphertext                : System.Address;
      Ct_Len                    : Size_T;
      Stream_ID                 : System.Address;
      Cumulative_Pixel_Offset   : U64;
      Out_Buf                   : System.Address;
      Out_Cap                   : Size_T;
      Out_Len                   : access Size_T;
      Final_Flag_Out            : access C_Int)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_DecryptStreamAuthenticated3x256";

   function ITB_DecryptStreamAuthenticated3x512
     (Noise_Handle              : Handle;
      Data_Handle1              : Handle;
      Data_Handle2              : Handle;
      Data_Handle3              : Handle;
      Start_Handle1             : Handle;
      Start_Handle2             : Handle;
      Start_Handle3             : Handle;
      MAC_Handle                : Handle;
      Ciphertext                : System.Address;
      Ct_Len                    : Size_T;
      Stream_ID                 : System.Address;
      Cumulative_Pixel_Offset   : U64;
      Out_Buf                   : System.Address;
      Out_Cap                   : Size_T;
      Out_Len                   : access Size_T;
      Final_Flag_Out            : access C_Int)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_DecryptStreamAuthenticated3x512";

   function ITB_Easy_EncryptStreamAuth
     (H                       : Handle;
      Plaintext               : System.Address;
      Pt_Len                  : Size_T;
      Stream_ID               : System.Address;
      Cumulative_Pixel_Offset : U64;
      Final_Flag              : C_Int;
      Out_Buf                 : System.Address;
      Out_Cap                 : Size_T;
      Out_Len                 : access Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Easy_EncryptStreamAuth";

   function ITB_Easy_DecryptStreamAuth
     (H                       : Handle;
      Ciphertext              : System.Address;
      Ct_Len                  : Size_T;
      Stream_ID               : System.Address;
      Cumulative_Pixel_Offset : U64;
      Out_Buf                 : System.Address;
      Out_Cap                 : Size_T;
      Out_Len                 : access Size_T;
      Final_Flag_Out          : access C_Int)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_Easy_DecryptStreamAuth";

   ---------------------------------------------------------------------
   --  Format-deniability wrapper.
   ---------------------------------------------------------------------
   --
   --  Twelve entry points covering the wrapper surface:
   --    * Two metadata getters (KeySize / NonceSize)
   --    * Four Single Message calls (Wrap / Unwrap + WrapInPlace /
   --      UnwrapInPlace)
   --    * Six streaming-handle calls
   --      (WrapStreamWriter_Init/_Update/_Free +
   --       UnwrapStreamReader_Init/_Update/_Free)
   --
   --  The cipher_name argument selects the outer keystream cipher:
   --  "aescmac" (AES-128-CTR — 16-byte key + 16-byte nonce), "chacha20"
   --  (ChaCha20 (RFC8439) — 32-byte key + 12-byte nonce), or "siphash24"
   --  (SipHash-2-4 in CTR mode — 16-byte key + 16-byte nonce). All
   --  three FFI strings are NUL-terminated.

   function ITB_WrapperKeySize
     (Cipher_Name : C_String;
      Out_Size    : access Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_WrapperKeySize";

   function ITB_WrapperNonceSize
     (Cipher_Name : C_String;
      Out_Size    : access Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_WrapperNonceSize";

   function ITB_WrapperDeriveKey
     (Cipher_Name : C_String;
      Master      : System.Address;
      Master_Len  : Size_T;
      Out_Buf     : System.Address;
      Out_Cap     : Size_T;
      Out_Len     : access Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_WrapperDeriveKey";

   function ITB_Wrap
     (Cipher_Name : C_String;
      Key         : System.Address;
      Key_Len     : Size_T;
      Blob        : System.Address;
      Blob_Len    : Size_T;
      Out_Buf     : System.Address;
      Out_Cap     : Size_T;
      Out_Len     : access Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Wrap";

   function ITB_Unwrap
     (Cipher_Name : C_String;
      Key         : System.Address;
      Key_Len     : Size_T;
      Wire        : System.Address;
      Wire_Len    : Size_T;
      Out_Buf     : System.Address;
      Out_Cap     : Size_T;
      Out_Len     : access Size_T)
      return C_Int
   with Import => True, Convention => C, External_Name => "ITB_Unwrap";

   function ITB_WrapInPlace
     (Cipher_Name : C_String;
      Key         : System.Address;
      Key_Len     : Size_T;
      Blob        : System.Address;
      Blob_Len    : Size_T;
      Out_Nonce   : System.Address;
      Nonce_Cap   : Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_WrapInPlace";

   function ITB_UnwrapInPlace
     (Cipher_Name : C_String;
      Key         : System.Address;
      Key_Len     : Size_T;
      Wire        : System.Address;
      Wire_Len    : Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_UnwrapInPlace";

   function ITB_WrapStreamWriter_Init
     (Cipher_Name : C_String;
      Key         : System.Address;
      Key_Len     : Size_T;
      Out_Nonce   : System.Address;
      Nonce_Cap   : Size_T;
      Out_Handle  : access Handle)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_WrapStreamWriter_Init";

   function ITB_WrapStreamWriter_Update
     (H        : Handle;
      Src      : System.Address;
      Src_Len  : Size_T;
      Dst      : System.Address;
      Dst_Cap  : Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_WrapStreamWriter_Update";

   function ITB_WrapStreamWriter_Free (H : Handle) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_WrapStreamWriter_Free";

   function ITB_UnwrapStreamReader_Init
     (Cipher_Name : C_String;
      Key         : System.Address;
      Key_Len     : Size_T;
      Wire_Nonce  : System.Address;
      Nonce_Len   : Size_T;
      Out_Handle  : access Handle)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_UnwrapStreamReader_Init";

   function ITB_UnwrapStreamReader_Update
     (H        : Handle;
      Src      : System.Address;
      Src_Len  : Size_T;
      Dst      : System.Address;
      Dst_Cap  : Size_T)
      return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_UnwrapStreamReader_Update";

   function ITB_UnwrapStreamReader_Free (H : Handle) return C_Int
   with Import => True, Convention => C,
        External_Name => "ITB_UnwrapStreamReader_Free";

end Itb.Sys;
