--  Itb.Encryptor body — Easy Mode encryptor implementation.

with Ada.Streams; use Ada.Streams;
with Ada.Unchecked_Deallocation;
with Interfaces;
with Interfaces.C;
with Interfaces.C.Strings;
with System;

with Itb.Errors;
with Itb.Status;

package body Itb.Encryptor is

   use type Itb.Sys.Handle;

   ---------------------------------------------------------------------
   --  Internal helpers
   ---------------------------------------------------------------------

   procedure Free_Cache is
     new Ada.Unchecked_Deallocation
       (Object => Byte_Array, Name => Byte_Array_Access);

   --  Empty-Byte_Array helper. Stream_Element_Array indexing starts at
   --  any base; the canonical "no data" form across the binding is
   --  (1 .. 0).
   function Empty return Byte_Array is
   begin
      return Byte_Array'(1 .. 0 => 0);
   end Empty;

   --  Constructs the C-string handle to pass for an optional input
   --  string: Ada empty "" maps to libitb's Null_String sentinel
   --  (meaning "no value / use default" semantics on the FFI side);
   --  any non-empty string is allocated via Strings.New_String and
   --  must be paired with Strings.Free by the caller.
   function To_C_String_Or_Null
     (S : String) return Interfaces.C.Strings.chars_ptr is
   begin
      if S = "" then
         return Itb.Sys.Null_String;
      else
         return Interfaces.C.Strings.New_String (S);
      end if;
   end To_C_String_Or_Null;

   procedure Free_If_Allocated
     (Ptr : in out Interfaces.C.Strings.chars_ptr) is
      use type Interfaces.C.Strings.chars_ptr;
   begin
      if Ptr /= Itb.Sys.Null_String then
         Interfaces.C.Strings.Free (Ptr);
      end if;
   end Free_If_Allocated;

   --  Default MAC override: an empty Mac_Name from the Ada side maps
   --  to the binding's "hmac-blake3" default before any FFI call.
   --  Mirrors every other binding's default-MAC override.
   function Resolved_Mac_Name (Mac_Name : String) return String is
   begin
      if Mac_Name = "" then
         return "hmac-blake3";
      else
         return Mac_Name;
      end if;
   end Resolved_Mac_Name;

   --  Wipes the cache buffer in place (zero out every byte) without
   --  releasing the heap allocation. Used before grow + on Close /
   --  Finalize so the most recent ciphertext / plaintext does not
   --  linger in heap memory.
   procedure Wipe_Cache (Self : in out Encryptor) is
   begin
      if Self.Cache /= null then
         for I in Self.Cache'Range loop
            Self.Cache (I) := 0;
         end loop;
      end if;
   end Wipe_Cache;

   --  Preflight rejection for closed / freed encryptors. Routes
   --  through Itb.Errors.Raise_For with Itb.Status.Easy_Closed so
   --  callers see the canonical "encryptor has been closed" code
   --  regardless of whether the underlying handle slot has merely
   --  been zeroed (post-Close) or has been released back to libitb
   --  (post-Finalize).
   procedure Check_Open (Self : Encryptor) is
   begin
      if Self.Closed or else Self.Handle = 0 then
         Itb.Errors.Raise_For (Itb.Status.Easy_Closed);
      end if;
   end Check_Open;

   --  Grows the cache buffer to at least Need bytes. Wipes the
   --  previous buffer (if any) before deallocating it so a previous-
   --  call ciphertext / plaintext does not linger in heap garbage
   --  between cipher calls.
   procedure Ensure_Capacity
     (Self : in out Encryptor;
      Need : Stream_Element_Offset)
   is
   begin
      if Self.Cache /= null and then Self.Cache'Length >= Need then
         return;
      end if;
      if Self.Cache /= null then
         Wipe_Cache (Self);
         Free_Cache (Self.Cache);
      end if;
      Self.Cache := new Byte_Array (1 .. Need);
   end Ensure_Capacity;

   --  C-convention access type for the four ITB_Easy_{Encrypt,Decrypt,
   --  EncryptAuth,DecryptAuth} entry points. Identical signature
   --  across all four; only the function pointer differs.
   type Easy_Cipher_Fn is access function
     (H       : Itb.Sys.Handle;
      In_Buf  : System.Address;
      In_Len  : Interfaces.C.size_t;
      Out_Buf : System.Address;
      Out_Cap : Interfaces.C.size_t;
      Out_Len : access Interfaces.C.size_t) return Interfaces.C.int
   with Convention => C;

   --  Direct-call buffer-convention dispatcher with a per-encryptor
   --  output cache. Skips the size-probe round-trip the lower-level
   --  FFI helpers use: pre-allocates output capacity from a 1.25x
   --  upper bound (the empirical ITB ciphertext-expansion factor
   --  measured at <= 1.155 across every primitive / mode / nonce /
   --  payload-size combination) and falls through to an explicit
   --  grow-and-retry only on the rare under-shoot. Reuses the cache
   --  across calls.
   function Cipher_Call
     (Self    : in out Encryptor;
      Fn      : Easy_Cipher_Fn;
      Payload : Byte_Array) return Byte_Array
   is
      use Interfaces.C;
      Payload_Len : constant Stream_Element_Offset := Payload'Length;
      In_Addr     : constant System.Address :=
        (if Payload_Len > 0 then Payload'Address else System.Null_Address);

      --  1.25x + 128 KiB headroom comfortably exceeds the worst-case
      --  expansion observed across the primitive / mode / nonce-bits
      --  / barrier-fill matrix; bf=32 with payloads near 1 MiB pushes
      --  the absolute ratio to ~1.346, leaving roughly 100 KiB of
      --  residual margin over the 1.25x term that the constant pad
      --  must absorb. The 128 KiB pad covers that worst case (and
      --  the ratio tapers below 1.25x + small-K beyond a few MiB as
      --  the bf-induced sqrt-shaped border overhead becomes
      --  asymptotically negligible). Floor at 128 KiB so the very-
      --  small payload case still gets a usable buffer that handles
      --  the Triple + auth-MAC + bf=32 short-payload expansion
      --  (~35 KiB at ptlen=1). The explicit Long_Long_Integer
      --  intermediate guards against Stream_Element_Offset overflow
      --  at very large payload sizes — under wrap the grow-and-retry
      --  path would still recover, but the saturated initial
      --  allocation avoids the extra round-trip.
      Cap_LL : constant Long_Long_Integer :=
        Long_Long_Integer'Max
          (131072,
           Long_Long_Integer (Payload_Len) * 5 / 4 + 131072);
      Cap     : constant Stream_Element_Offset :=
        Stream_Element_Offset (Cap_LL);
      Pt_Len_C : constant size_t := size_t (Payload_Len);
      Out_Len  : aliased size_t := 0;
      Status   : int;
   begin
      Check_Open (Self);
      Ensure_Capacity (Self, Cap);

      Status := Fn
                  (H       => Self.Handle,
                   In_Buf  => In_Addr,
                   In_Len  => Pt_Len_C,
                   Out_Buf => Self.Cache.all'Address,
                   Out_Cap => size_t (Self.Cache.all'Length),
                   Out_Len => Out_Len'Access);

      if Status = Itb.Status.Buffer_Too_Small then
         --  Pre-allocation was too tight (extremely rare given the
         --  1.25x safety margin) — grow exactly to the required size
         --  and retry. The first call already paid for the underlying
         --  crypto via the current C ABI's full-encrypt-on-every-call
         --  contract, so the retry runs the work again; this is
         --  strictly the fallback path and not the hot loop.
         Ensure_Capacity (Self, Stream_Element_Offset (Out_Len));
         Status := Fn
                     (H       => Self.Handle,
                      In_Buf  => In_Addr,
                      In_Len  => Pt_Len_C,
                      Out_Buf => Self.Cache.all'Address,
                      Out_Cap => size_t (Self.Cache.all'Length),
                      Out_Len => Out_Len'Access);
      end if;

      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      if Out_Len = 0 then
         return Empty;
      end if;
      return Self.Cache (1 .. Stream_Element_Offset (Out_Len));
   end Cipher_Call;

   --  Probe / allocate / write helper for the Easy Mode string
   --  getters of shape
   --      int FFI (uintptr_t h, char* out, size_t cap, size_t* outLen)
   --  Routes every non-OK return code through the Easy Mode error
   --  translation so the offending JSON field name is folded into the
   --  raised exception when the rc is Status.Easy_Mismatch.
   type Easy_String_Getter is access function
     (H       : Itb.Sys.Handle;
      Out_Buf : System.Address;
      Cap     : Interfaces.C.size_t;
      Out_Len : access Interfaces.C.size_t) return Interfaces.C.int
   with Convention => C;

   function Read_Easy_String
     (H : Itb.Sys.Handle; Get : Easy_String_Getter) return String
   is
      use Interfaces.C;
      Probe  : aliased size_t := 0;
      Status : int;
   begin
      Status := Get
                  (H       => H,
                   Out_Buf => System.Null_Address,
                   Cap     => 0,
                   Out_Len => Probe'Access);
      if Status = Itb.Status.OK and then Probe = 0 then
         return "";
      end if;
      if Status /= Itb.Status.Buffer_Too_Small then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      declare
         Buf     : aliased char_array (1 .. Probe) := [others => nul];
         Out_Len : aliased size_t := 0;
      begin
         Status := Get
                     (H       => H,
                      Out_Buf => Buf'Address,
                      Cap     => Probe,
                      Out_Len => Out_Len'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         if Out_Len = 0 then
            return "";
         end if;
         --  libitb returns C strings with a trailing NUL counted in
         --  Out_Len; strip it before handing back to Ada.
         declare
            N : constant size_t :=
              (if Out_Len > 0 then Out_Len - 1 else 0);
         begin
            if N = 0 then
               return "";
            end if;
            return To_Ada (Buf (1 .. N), Trim_Nul => False);
         end;
      end;
   end Read_Easy_String;

   ---------------------------------------------------------------------
   --  Constructors
   ---------------------------------------------------------------------

   function Make
     (Primitive : String;
      Key_Bits  : Integer;
      Mac_Name  : String    := "";
      Mode      : Mode_Type := 1) return Encryptor
   is
      use Interfaces.C;
      C_Prim : Strings.chars_ptr := To_C_String_Or_Null (Primitive);
      C_Mac  : Strings.chars_ptr :=
        Strings.New_String (Resolved_Mac_Name (Mac_Name));
      Handle : aliased Itb.Sys.Handle := 0;
      Status : int;
   begin
      --  Mode_Type's Static_Predicate (1 | 3) catches literal mis-use
      --  at compile time, but the predicate is only enforced at run
      --  time when the project is built with -gnata (assertion checks
      --  enabled). Make is the entry point that decides what mode
      --  reaches libitb, so the runtime guard belongs here regardless
      --  of the build configuration. Surface as Itb_Error / Bad_Input
      --  for cross-binding parity with Python / C# / Rust / D / Node.js
      --  where invalid mode flows through the libitb status-translation
      --  pipeline instead of a language-builtin exception.
      if Mode /= 1 and then Mode /= 3 then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;

      Status := Itb.Sys.ITB_Easy_New
                  (Primitive  => C_Prim,
                   Key_Bits   => int (Key_Bits),
                   Mac_Name   => C_Mac,
                   Mode       => int (Mode),
                   Out_Handle => Handle'Access);
      Free_If_Allocated (C_Prim);
      Strings.Free (C_Mac);
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      return E : Encryptor do
         E.Handle := Handle;
         E.Cache  := null;
      end return;
   end Make;

   function Mixed_Single
     (Prim_N   : String;
      Prim_D   : String;
      Prim_S   : String;
      Prim_L   : String;
      Key_Bits : Integer;
      Mac_Name : String := "") return Encryptor
   is
      use Interfaces.C;
      C_N    : Strings.chars_ptr := Strings.New_String (Prim_N);
      C_D    : Strings.chars_ptr := Strings.New_String (Prim_D);
      C_S    : Strings.chars_ptr := Strings.New_String (Prim_S);
      C_L    : Strings.chars_ptr := To_C_String_Or_Null (Prim_L);
      C_Mac  : Strings.chars_ptr :=
        Strings.New_String (Resolved_Mac_Name (Mac_Name));
      Handle : aliased Itb.Sys.Handle := 0;
      Status : int;
   begin
      Status := Itb.Sys.ITB_Easy_NewMixed
                  (Prim_N     => C_N,
                   Prim_D     => C_D,
                   Prim_S     => C_S,
                   Prim_L     => C_L,
                   Key_Bits   => int (Key_Bits),
                   Mac_Name   => C_Mac,
                   Out_Handle => Handle'Access);
      Strings.Free (C_N);
      Strings.Free (C_D);
      Strings.Free (C_S);
      Free_If_Allocated (C_L);
      Strings.Free (C_Mac);
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      return E : Encryptor do
         E.Handle := Handle;
         E.Cache  := null;
      end return;
   end Mixed_Single;

   function Mixed_Triple
     (Prim_N   : String;
      Prim_D1  : String;
      Prim_D2  : String;
      Prim_D3  : String;
      Prim_S1  : String;
      Prim_S2  : String;
      Prim_S3  : String;
      Prim_L   : String;
      Key_Bits : Integer;
      Mac_Name : String := "") return Encryptor
   is
      use Interfaces.C;
      C_N    : Strings.chars_ptr := Strings.New_String (Prim_N);
      C_D1   : Strings.chars_ptr := Strings.New_String (Prim_D1);
      C_D2   : Strings.chars_ptr := Strings.New_String (Prim_D2);
      C_D3   : Strings.chars_ptr := Strings.New_String (Prim_D3);
      C_S1   : Strings.chars_ptr := Strings.New_String (Prim_S1);
      C_S2   : Strings.chars_ptr := Strings.New_String (Prim_S2);
      C_S3   : Strings.chars_ptr := Strings.New_String (Prim_S3);
      C_L    : Strings.chars_ptr := To_C_String_Or_Null (Prim_L);
      C_Mac  : Strings.chars_ptr :=
        Strings.New_String (Resolved_Mac_Name (Mac_Name));
      Handle : aliased Itb.Sys.Handle := 0;
      Status : int;
   begin
      Status := Itb.Sys.ITB_Easy_NewMixed3
                  (Prim_N     => C_N,
                   Prim_D1    => C_D1,
                   Prim_D2    => C_D2,
                   Prim_D3    => C_D3,
                   Prim_S1    => C_S1,
                   Prim_S2    => C_S2,
                   Prim_S3    => C_S3,
                   Prim_L     => C_L,
                   Key_Bits   => int (Key_Bits),
                   Mac_Name   => C_Mac,
                   Out_Handle => Handle'Access);
      Strings.Free (C_N);
      Strings.Free (C_D1);
      Strings.Free (C_D2);
      Strings.Free (C_D3);
      Strings.Free (C_S1);
      Strings.Free (C_S2);
      Strings.Free (C_S3);
      Free_If_Allocated (C_L);
      Strings.Free (C_Mac);
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      return E : Encryptor do
         E.Handle := Handle;
         E.Cache  := null;
      end return;
   end Mixed_Triple;

   ---------------------------------------------------------------------
   --  Cipher entry points
   ---------------------------------------------------------------------

   function Encrypt
     (Self      : in out Encryptor;
      Plaintext : Byte_Array) return Byte_Array is
   begin
      return Cipher_Call
        (Self, Itb.Sys.ITB_Easy_Encrypt'Access, Plaintext);
   end Encrypt;

   function Decrypt
     (Self       : in out Encryptor;
      Ciphertext : Byte_Array) return Byte_Array is
   begin
      return Cipher_Call
        (Self, Itb.Sys.ITB_Easy_Decrypt'Access, Ciphertext);
   end Decrypt;

   function Encrypt_Auth
     (Self      : in out Encryptor;
      Plaintext : Byte_Array) return Byte_Array is
   begin
      return Cipher_Call
        (Self, Itb.Sys.ITB_Easy_EncryptAuth'Access, Plaintext);
   end Encrypt_Auth;

   function Decrypt_Auth
     (Self       : in out Encryptor;
      Ciphertext : Byte_Array) return Byte_Array is
   begin
      return Cipher_Call
        (Self, Itb.Sys.ITB_Easy_DecryptAuth'Access, Ciphertext);
   end Decrypt_Auth;

   ---------------------------------------------------------------------
   --  Per-instance configuration setters
   ---------------------------------------------------------------------

   procedure Set_Nonce_Bits (Self : Encryptor; N : Integer) is
      use Interfaces.C;
      Status : int;
   begin
      Check_Open (Self);
      Status := Itb.Sys.ITB_Easy_SetNonceBits (Self.Handle, int (N));
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end Set_Nonce_Bits;

   procedure Set_Barrier_Fill (Self : Encryptor; N : Integer) is
      use Interfaces.C;
      Status : int;
   begin
      Check_Open (Self);
      Status := Itb.Sys.ITB_Easy_SetBarrierFill (Self.Handle, int (N));
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end Set_Barrier_Fill;

   procedure Set_Bit_Soup (Self : Encryptor; Mode : Integer) is
      use Interfaces.C;
      Status : int;
   begin
      Check_Open (Self);
      Status := Itb.Sys.ITB_Easy_SetBitSoup (Self.Handle, int (Mode));
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end Set_Bit_Soup;

   procedure Set_Lock_Soup (Self : Encryptor; Mode : Integer) is
      use Interfaces.C;
      Status : int;
   begin
      Check_Open (Self);
      Status := Itb.Sys.ITB_Easy_SetLockSoup (Self.Handle, int (Mode));
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end Set_Lock_Soup;

   procedure Set_Lock_Batch (Self : Encryptor; Mode : Integer) is
      use Interfaces.C;
      Status : int;
   begin
      Check_Open (Self);
      Status := Itb.Sys.ITB_Easy_SetLockBatch (Self.Handle, int (Mode));
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end Set_Lock_Batch;

   procedure Set_Lock_Seed (Self : Encryptor; Mode : Integer) is
      use Interfaces.C;
      Status : int;
   begin
      Check_Open (Self);
      Status := Itb.Sys.ITB_Easy_SetLockSeed (Self.Handle, int (Mode));
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end Set_Lock_Seed;

   procedure Set_Chunk_Size (Self : Encryptor; N : Integer) is
      use Interfaces.C;
      Status : int;
   begin
      Check_Open (Self);
      Status := Itb.Sys.ITB_Easy_SetChunkSize (Self.Handle, int (N));
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end Set_Chunk_Size;

   ---------------------------------------------------------------------
   --  Read-only accessors
   ---------------------------------------------------------------------

   function Primitive (Self : Encryptor) return String is
   begin
      Check_Open (Self);
      return Read_Easy_String
        (Self.Handle, Itb.Sys.ITB_Easy_Primitive'Access);
   end Primitive;

   function Primitive_At (Self : Encryptor; Slot : Integer) return String is
      use Interfaces.C;
      H      : constant Itb.Sys.Handle := Self.Handle;
      Slot_C : constant int := int (Slot);
      Probe  : aliased size_t := 0;
      Status : int;
   begin
      Check_Open (Self);
      Status := Itb.Sys.ITB_Easy_PrimitiveAt
                  (H       => H,
                   Slot    => Slot_C,
                   Out_Buf => System.Null_Address,
                   Cap     => 0,
                   Out_Len => Probe'Access);
      if Status = Itb.Status.OK and then Probe = 0 then
         return "";
      end if;
      if Status /= Itb.Status.Buffer_Too_Small then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      declare
         Buf     : aliased char_array (1 .. Probe) := [others => nul];
         Out_Len : aliased size_t := 0;
      begin
         Status := Itb.Sys.ITB_Easy_PrimitiveAt
                     (H       => H,
                      Slot    => Slot_C,
                      Out_Buf => Buf'Address,
                      Cap     => Probe,
                      Out_Len => Out_Len'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         if Out_Len = 0 then
            return "";
         end if;
         declare
            N : constant size_t :=
              (if Out_Len > 0 then Out_Len - 1 else 0);
         begin
            if N = 0 then
               return "";
            end if;
            return To_Ada (Buf (1 .. N), Trim_Nul => False);
         end;
      end;
   end Primitive_At;

   function Key_Bits (Self : Encryptor) return Integer is
      use Interfaces.C;
      Out_Status : aliased int := 0;
      V          : int;
   begin
      Check_Open (Self);
      V := Itb.Sys.ITB_Easy_KeyBits (Self.Handle, Out_Status'Access);
      if Out_Status /= 0 then
         Itb.Errors.Raise_For (Integer (Out_Status));
      end if;
      return Integer (V);
   end Key_Bits;

   function Mode (Self : Encryptor) return Integer is
      use Interfaces.C;
      Out_Status : aliased int := 0;
      V          : int;
   begin
      Check_Open (Self);
      V := Itb.Sys.ITB_Easy_Mode (Self.Handle, Out_Status'Access);
      if Out_Status /= 0 then
         Itb.Errors.Raise_For (Integer (Out_Status));
      end if;
      return Integer (V);
   end Mode;

   function MAC_Name (Self : Encryptor) return String is
   begin
      Check_Open (Self);
      return Read_Easy_String
        (Self.Handle, Itb.Sys.ITB_Easy_MACName'Access);
   end MAC_Name;

   function Seed_Count (Self : Encryptor) return Integer is
      use Interfaces.C;
      Out_Status : aliased int := 0;
      V          : int;
   begin
      Check_Open (Self);
      V := Itb.Sys.ITB_Easy_SeedCount (Self.Handle, Out_Status'Access);
      if Out_Status /= 0 then
         Itb.Errors.Raise_For (Integer (Out_Status));
      end if;
      return Integer (V);
   end Seed_Count;

   function Has_PRF_Keys (Self : Encryptor) return Boolean is
      use Interfaces.C;
      Out_Status : aliased int := 0;
      V          : int;
   begin
      Check_Open (Self);
      V := Itb.Sys.ITB_Easy_HasPRFKeys (Self.Handle, Out_Status'Access);
      if Out_Status /= 0 then
         Itb.Errors.Raise_For (Integer (Out_Status));
      end if;
      return V /= 0;
   end Has_PRF_Keys;

   function Is_Mixed (Self : Encryptor) return Boolean is
      use Interfaces.C;
      Out_Status : aliased int := 0;
      V          : int;
   begin
      Check_Open (Self);
      V := Itb.Sys.ITB_Easy_IsMixed (Self.Handle, Out_Status'Access);
      if Out_Status /= 0 then
         Itb.Errors.Raise_For (Integer (Out_Status));
      end if;
      return V /= 0;
   end Is_Mixed;

   function Nonce_Bits (Self : Encryptor) return Integer is
      use Interfaces.C;
      Out_Status : aliased int := 0;
      V          : int;
   begin
      Check_Open (Self);
      V := Itb.Sys.ITB_Easy_NonceBits (Self.Handle, Out_Status'Access);
      if Out_Status /= 0 then
         Itb.Errors.Raise_For (Integer (Out_Status));
      end if;
      return Integer (V);
   end Nonce_Bits;

   function Header_Size (Self : Encryptor) return Integer is
      use Interfaces.C;
      Out_Status : aliased int := 0;
      V          : int;
   begin
      Check_Open (Self);
      V := Itb.Sys.ITB_Easy_HeaderSize (Self.Handle, Out_Status'Access);
      if Out_Status /= 0 then
         Itb.Errors.Raise_For (Integer (Out_Status));
      end if;
      return Integer (V);
   end Header_Size;

   ---------------------------------------------------------------------
   --  Component / key extractors
   ---------------------------------------------------------------------

   function Get_Seed_Components
     (Self : Encryptor;
      Slot : Integer) return Component_Array
   is
      use Interfaces.C;
      Probe  : aliased int := 0;
      Status : int;
   begin
      Check_Open (Self);
      --  Probe required count.
      Status := Itb.Sys.ITB_Easy_SeedComponents
                  (H       => Self.Handle,
                   Slot    => int (Slot),
                   Out_Buf => System.Null_Address,
                   Cap     => 0,
                   Out_Len => Probe'Access);
      if Status = Itb.Status.OK then
         return Component_Array'(1 .. 0 => 0);
      end if;
      if Status /= Itb.Status.Buffer_Too_Small then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      declare
         N       : constant Natural := Natural (Probe);
         Buf     : Component_Array (1 .. N);
         Out_Len : aliased int := 0;
      begin
         Status := Itb.Sys.ITB_Easy_SeedComponents
                     (H       => Self.Handle,
                      Slot    => int (Slot),
                      Out_Buf => Buf'Address,
                      Cap     => int (N),
                      Out_Len => Out_Len'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         return Buf (1 .. Natural (Out_Len));
      end;
   end Get_Seed_Components;

   function Get_PRF_Key
     (Self : Encryptor;
      Slot : Integer) return Byte_Array
   is
      use Interfaces.C;
      Probe  : aliased size_t := 0;
      Status : int;
   begin
      Check_Open (Self);
      Status := Itb.Sys.ITB_Easy_PRFKey
                  (H       => Self.Handle,
                   Slot    => int (Slot),
                   Out_Buf => System.Null_Address,
                   Cap     => 0,
                   Out_Len => Probe'Access);
      --  Probe pattern: zero-length key (siphash24) -> OK with
      --  Probe = 0; non-zero length -> Buffer_Too_Small with Probe
      --  carrying the required size. Bad_Input is reserved for
      --  out-of-range slot or no-fixed-key primitive (raised below).
      if Status = Itb.Status.OK and then Probe = 0 then
         return Empty;
      end if;
      if Status /= Itb.Status.Buffer_Too_Small then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      declare
         Buf     : Byte_Array (1 .. Stream_Element_Offset (Probe));
         Out_Len : aliased size_t := 0;
      begin
         Status := Itb.Sys.ITB_Easy_PRFKey
                     (H       => Self.Handle,
                      Slot    => int (Slot),
                      Out_Buf => Buf'Address,
                      Cap     => Probe,
                      Out_Len => Out_Len'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         return Buf (1 .. Stream_Element_Offset (Out_Len));
      end;
   end Get_PRF_Key;

   function Get_MAC_Key (Self : Encryptor) return Byte_Array is
      use Interfaces.C;
      Probe  : aliased size_t := 0;
      Status : int;
   begin
      Check_Open (Self);
      Status := Itb.Sys.ITB_Easy_MACKey
                  (H       => Self.Handle,
                   Out_Buf => System.Null_Address,
                   Cap     => 0,
                   Out_Len => Probe'Access);
      if Status = Itb.Status.OK and then Probe = 0 then
         return Empty;
      end if;
      if Status /= Itb.Status.Buffer_Too_Small then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      declare
         Buf     : Byte_Array (1 .. Stream_Element_Offset (Probe));
         Out_Len : aliased size_t := 0;
      begin
         Status := Itb.Sys.ITB_Easy_MACKey
                     (H       => Self.Handle,
                      Out_Buf => Buf'Address,
                      Cap     => Probe,
                      Out_Len => Out_Len'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         return Buf (1 .. Stream_Element_Offset (Out_Len));
      end;
   end Get_MAC_Key;

   ---------------------------------------------------------------------
   --  Streaming helpers
   ---------------------------------------------------------------------

   function Parse_Chunk_Len
     (Self   : Encryptor;
      Header : Byte_Array) return Natural
   is
      use Interfaces.C;
      Hdr_Addr : constant System.Address :=
        (if Header'Length > 0 then Header'Address else System.Null_Address);
      Out_Chunk : aliased size_t := 0;
      Status    : int;
   begin
      Check_Open (Self);
      Status := Itb.Sys.ITB_Easy_ParseChunkLen
                  (H          => Self.Handle,
                   Header     => Hdr_Addr,
                   Header_Len => Header'Length,
                   Out_Chunk  => Out_Chunk'Access);
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      return Natural (Out_Chunk);
   end Parse_Chunk_Len;

   ---------------------------------------------------------------------
   --  Lifecycle
   ---------------------------------------------------------------------

   procedure Close (Self : in out Encryptor) is
      use Interfaces.C;
      Status : int;
   begin
      --  Wipe + free the cached output buffer regardless of close
      --  state — repeated close calls keep the cache wiped without
      --  racing the Go-side close.
      if Self.Cache /= null then
         Wipe_Cache (Self);
         Free_Cache (Self.Cache);
      end if;
      if Self.Closed or else Self.Handle = 0 then
         --  Idempotent — already closed.
         Self.Closed := True;
         return;
      end if;
      Status := Itb.Sys.ITB_Easy_Close (Self.Handle);
      Self.Closed := True;
      --  Close is documented as idempotent on the Go side; any
      --  non-OK return after close is a bug.
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end Close;

   ---------------------------------------------------------------------
   --  State persistence
   ---------------------------------------------------------------------

   function Export_State (Self : Encryptor) return Byte_Array is
      use Interfaces.C;
      Probe  : aliased size_t := 0;
      Status : int;
   begin
      Check_Open (Self);
      Status := Itb.Sys.ITB_Easy_Export
                  (H       => Self.Handle,
                   Out_Buf => System.Null_Address,
                   Out_Cap => 0,
                   Out_Len => Probe'Access);
      if Status = Itb.Status.OK and then Probe = 0 then
         return Empty;
      end if;
      if Status /= Itb.Status.Buffer_Too_Small then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      declare
         Buf     : Byte_Array (1 .. Stream_Element_Offset (Probe));
         Out_Len : aliased size_t := 0;
      begin
         Status := Itb.Sys.ITB_Easy_Export
                     (H       => Self.Handle,
                      Out_Buf => Buf'Address,
                      Out_Cap => Probe,
                      Out_Len => Out_Len'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         return Buf (1 .. Stream_Element_Offset (Out_Len));
      end;
   end Export_State;

   procedure Import_State
     (Self : in out Encryptor; Blob : Byte_Array)
   is
      use Interfaces.C;
      Blob_Addr : constant System.Address :=
        (if Blob'Length > 0 then Blob'Address else System.Null_Address);
      Status    : int;
   begin
      Check_Open (Self);
      Status := Itb.Sys.ITB_Easy_Import
                  (H        => Self.Handle,
                   Blob     => Blob_Addr,
                   Blob_Len => Blob'Length);
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end Import_State;

   function Peek_Config (Blob : Byte_Array) return Peeked_Config is
      use Interfaces.C;
      Blob_Addr : constant System.Address :=
        (if Blob'Length > 0 then Blob'Address else System.Null_Address);
      Prim_Probe : aliased size_t := 0;
      Mac_Probe  : aliased size_t := 0;
      KB_Out     : aliased int := 0;
      Mode_Out   : aliased int := 0;
      Status     : int;
   begin
      --  Probe both string sizes first.
      Status := Itb.Sys.ITB_Easy_PeekConfig
                  (Blob       => Blob_Addr,
                   Blob_Len   => Blob'Length,
                   Prim_Out   => System.Null_Address,
                   Prim_Cap   => 0,
                   Prim_Len   => Prim_Probe'Access,
                   Key_Bits   => KB_Out'Access,
                   Mode_Out   => Mode_Out'Access,
                   Mac_Out    => System.Null_Address,
                   Mac_Cap    => 0,
                   Mac_Len    => Mac_Probe'Access);
      if Status /= Itb.Status.OK and then Status /= Itb.Status.Buffer_Too_Small
      then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      declare
         Prim_Buf : aliased char_array (1 .. Prim_Probe) := [others => nul];
         Mac_Buf  : aliased char_array (1 .. Mac_Probe)  := [others => nul];
         Prim_Len : aliased size_t := 0;
         Mac_Len  : aliased size_t := 0;
         Result   : Peeked_Config;
      begin
         Status := Itb.Sys.ITB_Easy_PeekConfig
                     (Blob       => Blob_Addr,
                      Blob_Len   => Blob'Length,
                      Prim_Out   => Prim_Buf'Address,
                      Prim_Cap   => Prim_Probe,
                      Prim_Len   => Prim_Len'Access,
                      Key_Bits   => KB_Out'Access,
                      Mode_Out   => Mode_Out'Access,
                      Mac_Out    => Mac_Buf'Address,
                      Mac_Cap    => Mac_Probe,
                      Mac_Len    => Mac_Len'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;

         declare
            Prim_N : constant size_t :=
              (if Prim_Len > 0 then Prim_Len - 1 else 0);
            Mac_N  : constant size_t :=
              (if Mac_Len > 0 then Mac_Len - 1 else 0);
         begin
            if Prim_N > 0 then
               Result.Primitive :=
                 Ada.Strings.Unbounded.To_Unbounded_String
                   (To_Ada (Prim_Buf (1 .. Prim_N), Trim_Nul => False));
            end if;
            if Mac_N > 0 then
               Result.MAC_Name :=
                 Ada.Strings.Unbounded.To_Unbounded_String
                   (To_Ada (Mac_Buf (1 .. Mac_N), Trim_Nul => False));
            end if;
         end;
         Result.Key_Bits := Integer (KB_Out);
         Result.Mode     := Integer (Mode_Out);
         return Result;
      end;
   end Peek_Config;

   ---------------------------------------------------------------------
   --  Finalize — deterministic release at scope exit.
   ---------------------------------------------------------------------

   overriding procedure Finalize (Self : in out Encryptor) is
      use Interfaces.C;
      Discard : int;
      pragma Unreferenced (Discard);
   begin
      if Self.Handle /= 0 then
         Discard := Itb.Sys.ITB_Easy_Free (Self.Handle);
         Self.Handle := 0;
      end if;
      Self.Closed := True;
      if Self.Cache /= null then
         Wipe_Cache (Self);
         Free_Cache (Self.Cache);
      end if;
   end Finalize;

   ---------------------------------------------------------------------
   --  Streaming AEAD Easy methods.
   ---------------------------------------------------------------------

   use type Interfaces.Unsigned_64;

   Stream_Auth_ID_Length : constant Stream_Element_Offset := 32;
   subtype Easy_Stream_ID is Byte_Array (1 .. 32);

   procedure Easy_Generate_Stream_ID (Out_Bytes : out Easy_Stream_ID) is
      use Interfaces.C;
      Comps   : aliased constant array (1 .. 8) of Itb.Sys.U64 :=
                  [1, 2, 3, 4, 5, 6, 7, 8];
      Cname   : Interfaces.C.Strings.chars_ptr :=
                  Interfaces.C.Strings.New_String ("blake3");
      H       : aliased Itb.Sys.Handle := 0;
      Got     : aliased size_t := 0;
      Status  : int;
   begin
      Out_Bytes := [others => 0];
      Status := Itb.Sys.ITB_NewSeedFromComponents
                  (Hash_Name      => Cname,
                   Components     => Comps'Address,
                   Components_Len => Comps'Length,
                   Hash_Key       => System.Null_Address,
                   Hash_Key_Len   => 0,
                   Out_Handle     => H'Access);
      Interfaces.C.Strings.Free (Cname);
      if Status /= Itb.Status.OK then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      Status := Itb.Sys.ITB_GetSeedHashKey
                  (H       => H,
                   Out_Buf => Out_Bytes'Address,
                   Cap     => size_t (Stream_Auth_ID_Length),
                   Out_Len => Got'Access);
      declare
         Free_Status : constant int := Itb.Sys.ITB_FreeSeed (H);
      begin
         if Status /= Itb.Status.OK then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         if Free_Status /= Itb.Status.OK then
            Itb.Errors.Raise_For (Integer (Free_Status));
         end if;
      end;
      if Got /= size_t (Stream_Auth_ID_Length) then
         Itb.Errors.Raise_For (Itb.Status.Internal);
      end if;
   end Easy_Generate_Stream_ID;

   --  Per-chunk encrypt dispatch through ITB_Easy_EncryptStreamAuth.
   --  Routes the FFI write target through the per-encryptor output
   --  cache (Self.Cache) via Ensure_Capacity + retry-once on
   --  Buffer_Too_Small, mirroring Cipher_Call's reference shape — the
   --  hot loop amortises the allocation across every chunk just like
   --  the Single Message Easy Mode path does. Returning the ciphertext
   --  through the sink keeps the per-chunk output buffer entirely on
   --  the heap; with a 16 MiB Chunk_Size the ciphertext is ~20 MiB,
   --  which would burst the default 8 MiB thread stack as a returned
   --  Byte_Array. The Out_Pixels parameter hands the caller back the
   --  (W,H)-derived pixel count parsed from the cipher header so
   --  cumulative-pixel tracking continues to work without re-parsing.
   procedure Easy_Emit_Chunk_Auth
     (Self       : in out Encryptor;
      Plaintext  : Byte_Array;
      Stream_ID  : Easy_Stream_ID;
      Cum_Pixels : Itb.Sys.U64;
      Final_Flag : Boolean;
      Hsz        : Stream_Element_Offset;
      Sink       : not null access Ada.Streams.Root_Stream_Type'Class;
      Out_Pixels : out Itb.Sys.U64)
   is
      use Interfaces.C;
      In_Addr : constant System.Address :=
        (if Plaintext'Length > 0 then Plaintext'Address
         else System.Null_Address);
      FF      : constant int := (if Final_Flag then 1 else 0);
      --  See Cipher_Call for the formula+retry-once rationale. Pre-
      --  allocate at 1.25x + 128 KiB so the per-chunk encrypt reaches
      --  libitb in one FFI call instead of probe-then-retry, which
      --  doubles the cipher work.
      Cap_LL  : constant Long_Long_Integer :=
        Long_Long_Integer'Max
          (131072,
           Long_Long_Integer (Plaintext'Length) * 5 / 4 + 131072);
      Cap     : constant Stream_Element_Offset :=
        Stream_Element_Offset (Cap_LL);
      Out_Len : aliased size_t := 0;
      Status  : int;
   begin
      Out_Pixels := 0;
      Ensure_Capacity (Self, Cap);
      Status := Itb.Sys.ITB_Easy_EncryptStreamAuth
                  (H                       => Self.Handle,
                   Plaintext               => In_Addr,
                   Pt_Len                  => Plaintext'Length,
                   Stream_ID               => Stream_ID'Address,
                   Cumulative_Pixel_Offset => Cum_Pixels,
                   Final_Flag              => FF,
                   Out_Buf                 => Self.Cache.all'Address,
                   Out_Cap                 => size_t (Self.Cache.all'Length),
                   Out_Len                 => Out_Len'Access);

      if Status = Itb.Status.Buffer_Too_Small then
         Ensure_Capacity (Self, Stream_Element_Offset (Out_Len));
         Out_Len := 0;
         Status := Itb.Sys.ITB_Easy_EncryptStreamAuth
                     (H                       => Self.Handle,
                      Plaintext               => In_Addr,
                      Pt_Len                  => Plaintext'Length,
                      Stream_ID               => Stream_ID'Address,
                      Cumulative_Pixel_Offset => Cum_Pixels,
                      Final_Flag              => FF,
                      Out_Buf                 => Self.Cache.all'Address,
                      Out_Cap                 =>
                        size_t (Self.Cache.all'Length),
                      Out_Len                 => Out_Len'Access);
      end if;

      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      if Stream_Element_Offset (Out_Len) >= Hsz then
         declare
            First_Idx : constant Stream_Element_Offset :=
              Self.Cache.all'First;
            W : constant Natural :=
              Natural (Self.Cache (First_Idx + Hsz - 4)) * 256
              + Natural (Self.Cache (First_Idx + Hsz - 3));
            H : constant Natural :=
              Natural (Self.Cache (First_Idx + Hsz - 2)) * 256
              + Natural (Self.Cache (First_Idx + Hsz - 1));
         begin
            Out_Pixels := Itb.Sys.U64 (W) * Itb.Sys.U64 (H);
         end;
      end if;
      if Out_Len > 0 then
         Sink.all.Write
           (Self.Cache (1 .. Stream_Element_Offset (Out_Len)));
      end if;
   end Easy_Emit_Chunk_Auth;

   --  Per-chunk decrypt dispatch through ITB_Easy_DecryptStreamAuth.
   --  Routes the FFI write target through the per-encryptor output
   --  cache (Self.Cache); the recovered plaintext lives in
   --  Self.Cache (1 .. PT_Len) on return. The caller writes the slice
   --  to its sink and is responsible for wiping the consumed prefix
   --  (Self.Cache (1 .. PT_Len) := [others => 0]) before the next
   --  cipher call overwrites those bytes. Wipe-on-grow + wipe-on-Close
   --  + wipe-on-Finalize discipline of the cache is preserved by the
   --  Ensure_Capacity / Wipe_Cache / Finalize trio.
   procedure Easy_Consume_Chunk_Auth
     (Self       : in out Encryptor;
      Cipher     : Byte_Array;
      Stream_ID  : Easy_Stream_ID;
      Cum_Pixels : Itb.Sys.U64;
      PT_Len     : out Stream_Element_Offset;
      Final_Flag : out Boolean)
   is
      use Interfaces.C;
      In_Addr : constant System.Address :=
        (if Cipher'Length > 0 then Cipher'Address else System.Null_Address);
      FF      : aliased int := 0;
      --  See Cipher_Call / Easy_Emit_Chunk_Auth for the rationale.
      Cap_LL  : constant Long_Long_Integer :=
        Long_Long_Integer'Max
          (131072,
           Long_Long_Integer (Cipher'Length) * 5 / 4 + 131072);
      Cap     : constant Stream_Element_Offset :=
        Stream_Element_Offset (Cap_LL);
      Out_Len : aliased size_t := 0;
      Status  : int;
   begin
      Ensure_Capacity (Self, Cap);
      Status := Itb.Sys.ITB_Easy_DecryptStreamAuth
                  (H                       => Self.Handle,
                   Ciphertext              => In_Addr,
                   Ct_Len                  => Cipher'Length,
                   Stream_ID               => Stream_ID'Address,
                   Cumulative_Pixel_Offset => Cum_Pixels,
                   Out_Buf                 => Self.Cache.all'Address,
                   Out_Cap                 => size_t (Self.Cache.all'Length),
                   Out_Len                 => Out_Len'Access,
                   Final_Flag_Out          => FF'Access);

      if Status = Itb.Status.Buffer_Too_Small then
         Ensure_Capacity (Self, Stream_Element_Offset (Out_Len));
         Out_Len := 0;
         Status := Itb.Sys.ITB_Easy_DecryptStreamAuth
                     (H                       => Self.Handle,
                      Ciphertext              => In_Addr,
                      Ct_Len                  => Cipher'Length,
                      Stream_ID               => Stream_ID'Address,
                      Cumulative_Pixel_Offset => Cum_Pixels,
                      Out_Buf                 => Self.Cache.all'Address,
                      Out_Cap                 =>
                        size_t (Self.Cache.all'Length),
                      Out_Len                 => Out_Len'Access,
                      Final_Flag_Out          => FF'Access);
      end if;

      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      PT_Len := Stream_Element_Offset (Out_Len);
      Final_Flag := FF /= 0;
   end Easy_Consume_Chunk_Auth;

   procedure Encrypt_Stream_Auth
     (Self       : in out Encryptor;
      Source     : not null access Ada.Streams.Root_Stream_Type'Class;
      Sink       : not null access Ada.Streams.Root_Stream_Type'Class;
      Chunk_Size : Stream_Element_Offset)
   is
   begin
      Check_Open (Self);
      if Chunk_Size <= 0 then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      declare
         Stream_ID  : Easy_Stream_ID;
         Hsz        : constant Stream_Element_Offset :=
                        Stream_Element_Offset (Header_Size (Self));
         Cum        : Itb.Sys.U64 := 0;
         --  Both buffers live on the heap so user-supplied chunk sizes
         --  exceeding the default 8 MiB Linux thread stack (a typical
         --  16 MiB Streaming AEAD chunk overflows it) do not blow the
         --  Ada stack. Released at scope exit and on any propagated
         --  exception via the handler below.
         Buf        : Byte_Array_Access :=
                        new Byte_Array (1 .. Chunk_Size + 1);
         Buf_Used   : Stream_Element_Offset := 0;
         Read_Buf   : Byte_Array_Access :=
                        new Byte_Array (1 .. Chunk_Size);
         Got        : Stream_Element_Offset;
         EOF_Hit    : Boolean := False;
      begin
         Easy_Generate_Stream_ID (Stream_ID);
         Sink.all.Write (Stream_ID);

         while not EOF_Hit loop
            --  Fill until buf is full (Chunk_Size + 1 bytes — one
            --  byte of look-ahead beyond the chunk boundary) or EOF.
            while Buf_Used < Buf'Length and then not EOF_Hit loop
               declare
                  Slice_End : constant Stream_Element_Offset :=
                    Stream_Element_Offset'Min
                      (Read_Buf'Last,
                       Read_Buf'First + (Buf'Length - Buf_Used) - 1);
                  Slice     : Stream_Element_Array
                              renames Read_Buf (Read_Buf'First .. Slice_End);
               begin
                  Got := Slice'First - 1;
                  Source.all.Read (Slice, Got);
                  if Got < Slice'First then
                     EOF_Hit := True;
                  else
                     declare
                        N : constant Stream_Element_Offset :=
                          Got - Slice'First + 1;
                     begin
                        Buf (Buf_Used + 1 .. Buf_Used + N) :=
                          Slice (Slice'First .. Got);
                        Buf_Used := Buf_Used + N;
                     end;
                  end if;
               end;
            end loop;
            if Buf_Used > Chunk_Size then
               --  Emit one full chunk as non-terminal. Pass the slice
               --  directly to Easy_Emit_Chunk_Auth so the per-chunk
               --  ciphertext never materialises as a stack-resident
               --  Byte_Array result; the helper writes it straight to
               --  Sink from the per-encryptor cache.
               declare
                  Pixels : Itb.Sys.U64 := 0;
               begin
                  Easy_Emit_Chunk_Auth
                    (Self,
                     Buf (1 .. Chunk_Size),
                     Stream_ID, Cum, False, Hsz,
                     Sink, Pixels);
                  Cum := Cum + Pixels;
                  Buf (1 .. Buf_Used - Chunk_Size) :=
                    Buf (Chunk_Size + 1 .. Buf_Used);
                  Buf_Used := Buf_Used - Chunk_Size;
                  Buf (Buf_Used + 1 .. Buf'Last) := [others => 0];
               end;
            end if;
         end loop;
         --  Residual (possibly empty) as terminating chunk.
         declare
            Tail_Pixels : Itb.Sys.U64 := 0;
         begin
            Easy_Emit_Chunk_Auth
              (Self,
               Buf (1 .. Buf_Used),
               Stream_ID, Cum, True, Hsz,
               Sink, Tail_Pixels);
         end;
         Buf.all := [others => 0];
         Free_Cache (Buf);
         Read_Buf.all := [others => 0];
         Free_Cache (Read_Buf);
      exception
         when others =>
            if Buf /= null then
               Buf.all := [others => 0];
               Free_Cache (Buf);
            end if;
            if Read_Buf /= null then
               Read_Buf.all := [others => 0];
               Free_Cache (Read_Buf);
            end if;
            raise;
      end;
   end Encrypt_Stream_Auth;

   procedure Decrypt_Stream_Auth
     (Self      : in out Encryptor;
      Source    : not null access Ada.Streams.Root_Stream_Type'Class;
      Sink      : not null access Ada.Streams.Root_Stream_Type'Class;
      Read_Size : Stream_Element_Offset)
   is
   begin
      Check_Open (Self);
      if Read_Size <= 0 then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      declare
         Stream_ID    : Easy_Stream_ID := [others => 0];
         Sid_Have     : Stream_Element_Offset := 0;
         Hsz          : constant Stream_Element_Offset :=
                          Stream_Element_Offset (Header_Size (Self));
         Cum          : Itb.Sys.U64 := 0;
         Seen_Final   : Boolean := False;
         Accum        : Byte_Array_Access :=
                          new Byte_Array (1 .. 64 * 1024);
         Accum_Used   : Stream_Element_Offset := 0;
         --  Read_Buf lives on the heap so user-supplied Read_Size
         --  exceeding the default 8 MiB Linux thread stack does not
         --  blow the Ada stack. Released at scope exit and on any
         --  propagated exception via the handler below.
         Read_Buf     : Byte_Array_Access :=
                          new Byte_Array (1 .. Read_Size);
         Got          : Stream_Element_Offset;
         EOF_Hit      : Boolean := False;

         procedure Drain is
         begin
            loop
               if Seen_Final then
                  if Accum_Used > 0 then
                     Itb.Errors.Raise_For (Itb.Status.Stream_After_Final);
                  end if;
                  return;
               end if;
               if Accum_Used < Hsz then
                  return;
               end if;
               declare
                  Want : constant Natural := Itb.Encryptor.Parse_Chunk_Len
                    (Self, Accum (1 .. Hsz));
                  WL   : constant Stream_Element_Offset :=
                    Stream_Element_Offset (Want);
               begin
                  if Accum_Used < WL then
                     return;
                  end if;
                  declare
                     W : constant Natural :=
                       Natural (Accum (Hsz - 3)) * 256
                       + Natural (Accum (Hsz - 2));
                     H : constant Natural :=
                       Natural (Accum (Hsz - 1)) * 256
                       + Natural (Accum (Hsz));
                     Pixels : constant Itb.Sys.U64 :=
                       Itb.Sys.U64 (W) * Itb.Sys.U64 (H);
                     PT_Len : Stream_Element_Offset := 0;
                     FF     : Boolean;
                     Tail   : constant Stream_Element_Offset :=
                       Accum_Used - WL;
                  begin
                     --  Pass the slice directly to the consumer rather
                     --  than materialising a constant Byte_Array copy
                     --  on the stack: at chunk sizes near 16 MiB the
                     --  per-chunk ciphertext is ~20 MiB and a stack
                     --  copy would burst the default 8 MiB thread
                     --  stack. The recovered plaintext lives in
                     --  Self.Cache (1 .. PT_Len); wipe the consumed
                     --  prefix after Sink.write so the next chunk's
                     --  Ensure_Capacity does not have to wipe-on-grow
                     --  for an unchanged-capacity case.
                     Easy_Consume_Chunk_Auth
                       (Self, Accum (1 .. WL),
                        Stream_ID, Cum, PT_Len, FF);
                     if PT_Len > 0 then
                        Sink.all.Write (Self.Cache (1 .. PT_Len));
                        Self.Cache (1 .. PT_Len) := [others => 0];
                     end if;
                     if Tail > 0 then
                        Accum (1 .. Tail) := Accum (WL + 1 .. Accum_Used);
                     end if;
                     Accum_Used := Tail;
                     Cum := Cum + Pixels;
                     if FF then
                        Seen_Final := True;
                     end if;
                  end;
               end;
            end loop;
         end Drain;
      begin
         while not EOF_Hit loop
            Got := Read_Buf.all'First - 1;
            Source.all.Read (Read_Buf.all, Got);
            if Got < Read_Buf.all'First then
               EOF_Hit := True;
            else
               declare
                  Off : Stream_Element_Offset := Read_Buf.all'First;
               begin
                  if Sid_Have < Stream_Auth_ID_Length then
                     declare
                        Need : constant Stream_Element_Offset :=
                          Stream_Auth_ID_Length - Sid_Have;
                        Avail : constant Stream_Element_Offset :=
                          Got - Read_Buf.all'First + 1;
                        Take : constant Stream_Element_Offset :=
                          Stream_Element_Offset'Min (Need, Avail);
                     begin
                        Stream_ID
                          (Sid_Have + 1 .. Sid_Have + Take) :=
                          Read_Buf (Off .. Off + Take - 1);
                        Sid_Have := Sid_Have + Take;
                        Off := Off + Take;
                     end;
                  end if;
                  if Off <= Got then
                     declare
                        Append_N : constant Stream_Element_Offset :=
                          Got - Off + 1;
                     begin
                        if Accum_Used + Append_N > Accum'Length then
                           declare
                              New_Cap : Stream_Element_Offset :=
                                Accum'Length * 2;
                              New_Buf : Byte_Array_Access;
                           begin
                              while New_Cap < Accum_Used + Append_N loop
                                 New_Cap := New_Cap * 2;
                              end loop;
                              New_Buf := new Byte_Array (1 .. New_Cap);
                              New_Buf (1 .. Accum_Used) :=
                                Accum (1 .. Accum_Used);
                              Free_Cache (Accum);
                              Accum := New_Buf;
                           end;
                        end if;
                        Accum (Accum_Used + 1 .. Accum_Used + Append_N)
                          := Read_Buf (Off .. Got);
                        Accum_Used := Accum_Used + Append_N;
                     end;
                  end if;
                  if Sid_Have = Stream_Auth_ID_Length then
                     Drain;
                  end if;
               end;
            end if;
         end loop;
         if Sid_Have < Stream_Auth_ID_Length then
            Free_Cache (Accum);
            Read_Buf.all := [others => 0];
            Free_Cache (Read_Buf);
            Itb.Errors.Raise_For (Itb.Status.Bad_Input);
         end if;
         Drain;
         Free_Cache (Accum);
         Read_Buf.all := [others => 0];
         Free_Cache (Read_Buf);
         if not Seen_Final then
            Itb.Errors.Raise_For (Itb.Status.Stream_Truncated);
         end if;
      exception
         when others =>
            if Accum /= null then
               Free_Cache (Accum);
            end if;
            if Read_Buf /= null then
               Read_Buf.all := [others => 0];
               Free_Cache (Read_Buf);
            end if;
            raise;
      end;
   end Decrypt_Stream_Auth;

   ---------------------------------------------------------------------
   --  Plain stream helpers — Single Message Easy_Encrypt / Easy_Decrypt
   --  per chunk, with chunk boundaries carried in ITB's own per-chunk
   --  header (nonce + W + H) parsed via Parse_Chunk_Len.
   ---------------------------------------------------------------------

   --  Emit one plain ciphertext chunk straight to Sink. Mirrors the
   --  shape of Easy_Emit_Chunk_Auth but routes through ITB_Easy_Encrypt
   --  (no Streaming AEAD parameters) and keeps the per-chunk output on
   --  the heap so the per-chunk ciphertext never materialises as a
   --  stack-resident Byte_Array.
   procedure Easy_Emit_Chunk_Plain
     (Handle    : Itb.Sys.Handle;
      Plaintext : Byte_Array;
      Sink      : not null access Ada.Streams.Root_Stream_Type'Class)
   is
      use Interfaces.C;
      In_Addr : constant System.Address :=
        (if Plaintext'Length > 0 then Plaintext'Address
         else System.Null_Address);
      --  See Cipher_Call for the formula+retry-once rationale.
      Cap_LL  : constant Long_Long_Integer :=
        Long_Long_Integer'Max
          (131072,
           Long_Long_Integer (Plaintext'Length) * 5 / 4 + 131072);
      Cap     : constant size_t := size_t (Cap_LL);
      Result  : Byte_Array_Access :=
                  new Byte_Array (1 .. Stream_Element_Offset (Cap));
      Out_Len : aliased size_t := 0;
      Status  : int;
   begin
      Status := Itb.Sys.ITB_Easy_Encrypt
                  (H         => Handle,
                   Plaintext => In_Addr,
                   Pt_Len    => size_t (Plaintext'Length),
                   Out_Buf   => Result.all'Address,
                   Out_Cap   => Cap,
                   Out_Len   => Out_Len'Access);

      if Status = Itb.Status.Buffer_Too_Small then
         declare
            Need : constant size_t := Out_Len;
         begin
            Result.all := [others => 0];
            Free_Cache (Result);
            Result := new Byte_Array (1 .. Stream_Element_Offset (Need));
            Out_Len := 0;
            Status := Itb.Sys.ITB_Easy_Encrypt
                        (H         => Handle,
                         Plaintext => In_Addr,
                         Pt_Len    => size_t (Plaintext'Length),
                         Out_Buf   => Result.all'Address,
                         Out_Cap   => Need,
                         Out_Len   => Out_Len'Access);
         end;
      end if;

      if Status /= 0 then
         Result.all := [others => 0];
         Free_Cache (Result);
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      if Out_Len > 0 then
         Sink.all.Write (Result (1 .. Stream_Element_Offset (Out_Len)));
      end if;
      Result.all := [others => 0];
      Free_Cache (Result);
   exception
      when others =>
         if Result /= null then
            Result.all := [others => 0];
            Free_Cache (Result);
         end if;
         raise;
   end Easy_Emit_Chunk_Plain;

   --  Decrypt one plain ciphertext chunk and return the recovered
   --  plaintext on the heap. Mirrors Easy_Consume_Chunk_Auth shape
   --  minus the Streaming AEAD parameters and final-flag output.
   procedure Easy_Consume_Chunk_Plain
     (Handle : Itb.Sys.Handle;
      Cipher : Byte_Array;
      PT_Out : out Byte_Array_Access)
   is
      use Interfaces.C;
      In_Addr : constant System.Address :=
        (if Cipher'Length > 0 then Cipher'Address else System.Null_Address);
      --  See Cipher_Call / Easy_Emit_Chunk_Plain for the rationale.
      Cap_LL  : constant Long_Long_Integer :=
        Long_Long_Integer'Max
          (131072,
           Long_Long_Integer (Cipher'Length) * 5 / 4 + 131072);
      Cap     : constant size_t := size_t (Cap_LL);
      Buf     : Byte_Array_Access :=
                  new Byte_Array (1 .. Stream_Element_Offset (Cap));
      Out_Len : aliased size_t := 0;
      Status  : int;
   begin
      PT_Out := null;
      Status := Itb.Sys.ITB_Easy_Decrypt
                  (H          => Handle,
                   Ciphertext => In_Addr,
                   Ct_Len     => size_t (Cipher'Length),
                   Out_Buf    => Buf.all'Address,
                   Out_Cap    => Cap,
                   Out_Len    => Out_Len'Access);

      if Status = Itb.Status.Buffer_Too_Small then
         declare
            Need : constant size_t := Out_Len;
         begin
            Buf.all := [others => 0];
            Free_Cache (Buf);
            Buf := new Byte_Array (1 .. Stream_Element_Offset (Need));
            Out_Len := 0;
            Status := Itb.Sys.ITB_Easy_Decrypt
                        (H          => Handle,
                         Ciphertext => In_Addr,
                         Ct_Len     => size_t (Cipher'Length),
                         Out_Buf    => Buf.all'Address,
                         Out_Cap    => Need,
                         Out_Len    => Out_Len'Access);
         end;
      end if;

      if Status /= 0 then
         Buf.all := [others => 0];
         Free_Cache (Buf);
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      declare
         Real : constant Byte_Array_Access :=
           new Byte_Array (1 .. Stream_Element_Offset (Out_Len));
      begin
         if Out_Len > 0 then
            Real (1 .. Stream_Element_Offset (Out_Len)) :=
              Buf (1 .. Stream_Element_Offset (Out_Len));
         end if;
         Buf.all := [others => 0];
         Free_Cache (Buf);
         PT_Out := Real;
      end;
   exception
      when others =>
         if Buf /= null then
            Buf.all := [others => 0];
            Free_Cache (Buf);
         end if;
         raise;
   end Easy_Consume_Chunk_Plain;

   procedure Encrypt_Stream
     (Self       : in out Encryptor;
      Source     : not null access Ada.Streams.Root_Stream_Type'Class;
      Sink       : not null access Ada.Streams.Root_Stream_Type'Class;
      Chunk_Size : Stream_Element_Offset)
   is
   begin
      Check_Open (Self);
      if Chunk_Size <= 0 then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      declare
         --  Heap-resident plaintext staging buffer — sized to the
         --  caller's chunk so a 16 MiB chunk does not burst the
         --  default 8 MiB Linux thread stack. Released at scope exit
         --  and on any propagated exception via the handler below.
         Buf      : Byte_Array_Access :=
                      new Byte_Array (1 .. Chunk_Size);
         Buf_Used : Stream_Element_Offset := 0;
         Got      : Stream_Element_Offset;
         EOF_Hit  : Boolean := False;
      begin
         while not EOF_Hit loop
            --  Fill Buf to Chunk_Size bytes or hit EOF.
            while Buf_Used < Chunk_Size and then not EOF_Hit loop
               declare
                  Slice : Stream_Element_Array
                            renames Buf (Buf_Used + 1 .. Chunk_Size);
               begin
                  Got := Slice'First - 1;
                  Source.all.Read (Slice, Got);
                  if Got < Slice'First then
                     EOF_Hit := True;
                  else
                     Buf_Used := Got;
                  end if;
               end;
            end loop;
            if Buf_Used = Chunk_Size then
               Easy_Emit_Chunk_Plain
                 (Self.Handle, Buf (1 .. Chunk_Size), Sink);
               Buf_Used := 0;
               Buf.all  := [others => 0];
            end if;
         end loop;
         --  Residual short chunk, if any. ITB rejects empty plaintext
         --  with STATUS_ENCRYPT_FAILED, so emit only when at least
         --  one byte remains.
         if Buf_Used > 0 then
            Easy_Emit_Chunk_Plain
              (Self.Handle, Buf (1 .. Buf_Used), Sink);
         end if;
         Buf.all := [others => 0];
         Free_Cache (Buf);
      exception
         when others =>
            if Buf /= null then
               Buf.all := [others => 0];
               Free_Cache (Buf);
            end if;
            raise;
      end;
   end Encrypt_Stream;

   procedure Decrypt_Stream
     (Self      : in out Encryptor;
      Source    : not null access Ada.Streams.Root_Stream_Type'Class;
      Sink      : not null access Ada.Streams.Root_Stream_Type'Class;
      Read_Size : Stream_Element_Offset)
   is
   begin
      Check_Open (Self);
      if Read_Size <= 0 then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      declare
         Hsz        : constant Stream_Element_Offset :=
                        Stream_Element_Offset (Header_Size (Self));
         --  Read_Buf lives on the heap so user-supplied Read_Size
         --  exceeding the default 8 MiB Linux thread stack does not
         --  blow the Ada stack.
         Read_Buf   : Byte_Array_Access :=
                        new Byte_Array (1 .. Read_Size);
         Accum      : Byte_Array_Access :=
                        new Byte_Array (1 .. 64 * 1024);
         Accum_Used : Stream_Element_Offset := 0;
         Got        : Stream_Element_Offset;
         EOF_Hit    : Boolean := False;

         procedure Drain is
         begin
            loop
               if Accum_Used < Hsz then
                  return;
               end if;
               declare
                  Want : constant Natural := Itb.Encryptor.Parse_Chunk_Len
                    (Self, Accum (1 .. Hsz));
                  WL   : constant Stream_Element_Offset :=
                    Stream_Element_Offset (Want);
               begin
                  if Accum_Used < WL then
                     return;
                  end if;
                  declare
                     PT   : Byte_Array_Access;
                     Tail : constant Stream_Element_Offset :=
                       Accum_Used - WL;
                  begin
                     Easy_Consume_Chunk_Plain
                       (Self.Handle, Accum (1 .. WL), PT);
                     if PT'Length > 0 then
                        Sink.all.Write (PT.all);
                     end if;
                     PT.all := [others => 0];
                     Free_Cache (PT);
                     if Tail > 0 then
                        Accum (1 .. Tail) := Accum (WL + 1 .. Accum_Used);
                     end if;
                     Accum_Used := Tail;
                  end;
               end;
            end loop;
         end Drain;
      begin
         while not EOF_Hit loop
            Got := Read_Buf.all'First - 1;
            Source.all.Read (Read_Buf.all, Got);
            if Got < Read_Buf.all'First then
               EOF_Hit := True;
            else
               declare
                  Append_N : constant Stream_Element_Offset :=
                    Got - Read_Buf.all'First + 1;
               begin
                  if Accum_Used + Append_N > Accum'Length then
                     declare
                        New_Cap : Stream_Element_Offset :=
                          Accum'Length * 2;
                        New_Buf : Byte_Array_Access;
                     begin
                        while New_Cap < Accum_Used + Append_N loop
                           New_Cap := New_Cap * 2;
                        end loop;
                        New_Buf := new Byte_Array (1 .. New_Cap);
                        New_Buf (1 .. Accum_Used) :=
                          Accum (1 .. Accum_Used);
                        Free_Cache (Accum);
                        Accum := New_Buf;
                     end;
                  end if;
                  Accum (Accum_Used + 1 .. Accum_Used + Append_N) :=
                    Read_Buf (Read_Buf.all'First .. Got);
                  Accum_Used := Accum_Used + Append_N;
                  Drain;
               end;
            end if;
         end loop;
         if Accum_Used > 0 then
            --  Trailing bytes that do not form a complete chunk —
            --  surface as Bad_Input so the caller learns the
            --  ciphertext stream was truncated mid-chunk.
            Free_Cache (Accum);
            Read_Buf.all := [others => 0];
            Free_Cache (Read_Buf);
            Itb.Errors.Raise_For (Itb.Status.Bad_Input);
         end if;
         Free_Cache (Accum);
         Read_Buf.all := [others => 0];
         Free_Cache (Read_Buf);
      exception
         when others =>
            if Accum /= null then
               Free_Cache (Accum);
            end if;
            if Read_Buf /= null then
               Read_Buf.all := [others => 0];
               Free_Cache (Read_Buf);
            end if;
            raise;
      end;
   end Decrypt_Stream;

end Itb.Encryptor;
