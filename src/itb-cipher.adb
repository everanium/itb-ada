--  Itb.Cipher body — probe / allocate / write idiom over libitb's
--  ITB_Encrypt* / ITB_Decrypt* family.

with Ada.Streams; use Ada.Streams;
with Interfaces.C;
with System;

with Itb.Errors;
with Itb.Status;
with Itb.Sys;

package body Itb.Cipher is

   ---------------------------------------------------------------------
   --  Internal helpers
   ---------------------------------------------------------------------

   --  Single Ouroboros (Encrypt / Decrypt) — shared formula+retry-once
   --  output-buffer pattern. The fn-pointer choice (Encrypt vs Decrypt)
   --  is passed by the caller; both signatures are identical.
   type Single_Cipher_Fn is access function
     (Noise_Handle : Itb.Sys.Handle;
      Data_Handle  : Itb.Sys.Handle;
      Start_Handle : Itb.Sys.Handle;
      Plaintext    : System.Address;
      Pt_Len       : Interfaces.C.size_t;
      Out_Buf      : System.Address;
      Out_Cap      : Interfaces.C.size_t;
      Out_Len      : access Interfaces.C.size_t)
      return Interfaces.C.int
   with Convention => C;

   function Run_Single
     (Fn      : Single_Cipher_Fn;
      Noise   : Itb.Seed.Seed;
      Data    : Itb.Seed.Seed;
      Start   : Itb.Seed.Seed;
      Payload : Byte_Array) return Byte_Array
   is
      use Interfaces.C;
      In_Addr : constant System.Address :=
        (if Payload'Length > 0 then Payload'Address else System.Null_Address);
      --  Pre-allocate from the canonical 1.25x + 128 KiB formula.
      --  See Itb.Encryptor.Cipher_Call for the rationale: the underlying
      --  C ABI runs the full encrypt / decrypt on every call regardless
      --  of the supplied out-buffer capacity, so a probe-then-retry
      --  pattern doubles the work per chunk. Allocate once at a size
      --  that comfortably exceeds the worst-case ITB ciphertext
      --  expansion observed across the primitive / mode / nonce-bits /
      --  barrier-fill matrix; retry once on the rare under-shoot using
      --  the returned out_len.
      Cap_LL  : constant Long_Long_Integer :=
        Long_Long_Integer'Max
          (131072,
           Long_Long_Integer (Payload'Length) * 5 / 4 + 131072);
      Cap     : constant size_t := size_t (Cap_LL);
      Result  : Byte_Array (1 .. Stream_Element_Offset (Cap));
      Out_Len : aliased size_t := 0;
      Status  : int;
   begin
      Status := Fn (Itb.Seed.Raw_Handle (Noise),
                    Itb.Seed.Raw_Handle (Data),
                    Itb.Seed.Raw_Handle (Start),
                    In_Addr,
                    Payload'Length,
                    Result'Address,
                    Cap,
                    Out_Len'Access);

      if Status = Itb.Status.Buffer_Too_Small then
         --  Pre-allocation was too tight (extremely rare given the
         --  1.25x + 128 KiB safety margin). Retry exactly to the size
         --  libitb just reported. The first call already paid for the
         --  cipher work; this is the fallback path, not the hot loop.
         declare
            Need     : constant size_t := Out_Len;
            Result2  : Byte_Array (1 .. Stream_Element_Offset (Need));
            Out_Len2 : aliased size_t := 0;
         begin
            Status := Fn (Itb.Seed.Raw_Handle (Noise),
                          Itb.Seed.Raw_Handle (Data),
                          Itb.Seed.Raw_Handle (Start),
                          In_Addr,
                          Payload'Length,
                          Result2'Address,
                          Need,
                          Out_Len2'Access);
            if Status /= 0 then
               Itb.Errors.Raise_For (Integer (Status));
            end if;
            return Result2 (1 .. Stream_Element_Offset (Out_Len2));
         end;
      end if;

      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      return Result (1 .. Stream_Element_Offset (Out_Len));
   end Run_Single;

   type Triple_Cipher_Fn is access function
     (Noise_Handle  : Itb.Sys.Handle;
      Data_Handle1  : Itb.Sys.Handle;
      Data_Handle2  : Itb.Sys.Handle;
      Data_Handle3  : Itb.Sys.Handle;
      Start_Handle1 : Itb.Sys.Handle;
      Start_Handle2 : Itb.Sys.Handle;
      Start_Handle3 : Itb.Sys.Handle;
      Plaintext     : System.Address;
      Pt_Len        : Interfaces.C.size_t;
      Out_Buf       : System.Address;
      Out_Cap       : Interfaces.C.size_t;
      Out_Len       : access Interfaces.C.size_t)
      return Interfaces.C.int
   with Convention => C;

   function Run_Triple
     (Fn      : Triple_Cipher_Fn;
      Noise   : Itb.Seed.Seed;
      Data1   : Itb.Seed.Seed;
      Data2   : Itb.Seed.Seed;
      Data3   : Itb.Seed.Seed;
      Start1  : Itb.Seed.Seed;
      Start2  : Itb.Seed.Seed;
      Start3  : Itb.Seed.Seed;
      Payload : Byte_Array) return Byte_Array
   is
      use Interfaces.C;
      In_Addr : constant System.Address :=
        (if Payload'Length > 0 then Payload'Address else System.Null_Address);
      --  See Run_Single for the formula+retry-once rationale.
      Cap_LL  : constant Long_Long_Integer :=
        Long_Long_Integer'Max
          (131072,
           Long_Long_Integer (Payload'Length) * 5 / 4 + 131072);
      Cap     : constant size_t := size_t (Cap_LL);
      Result  : Byte_Array (1 .. Stream_Element_Offset (Cap));
      Out_Len : aliased size_t := 0;
      Status  : int;
   begin
      Status := Fn (Itb.Seed.Raw_Handle (Noise),
                    Itb.Seed.Raw_Handle (Data1),
                    Itb.Seed.Raw_Handle (Data2),
                    Itb.Seed.Raw_Handle (Data3),
                    Itb.Seed.Raw_Handle (Start1),
                    Itb.Seed.Raw_Handle (Start2),
                    Itb.Seed.Raw_Handle (Start3),
                    In_Addr,
                    Payload'Length,
                    Result'Address,
                    Cap,
                    Out_Len'Access);

      if Status = Itb.Status.Buffer_Too_Small then
         declare
            Need     : constant size_t := Out_Len;
            Result2  : Byte_Array (1 .. Stream_Element_Offset (Need));
            Out_Len2 : aliased size_t := 0;
         begin
            Status := Fn (Itb.Seed.Raw_Handle (Noise),
                          Itb.Seed.Raw_Handle (Data1),
                          Itb.Seed.Raw_Handle (Data2),
                          Itb.Seed.Raw_Handle (Data3),
                          Itb.Seed.Raw_Handle (Start1),
                          Itb.Seed.Raw_Handle (Start2),
                          Itb.Seed.Raw_Handle (Start3),
                          In_Addr,
                          Payload'Length,
                          Result2'Address,
                          Need,
                          Out_Len2'Access);
            if Status /= 0 then
               Itb.Errors.Raise_For (Integer (Status));
            end if;
            return Result2 (1 .. Stream_Element_Offset (Out_Len2));
         end;
      end if;

      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      return Result (1 .. Stream_Element_Offset (Out_Len));
   end Run_Triple;

   type Auth_Cipher_Fn is access function
     (Noise_Handle : Itb.Sys.Handle;
      Data_Handle  : Itb.Sys.Handle;
      Start_Handle : Itb.Sys.Handle;
      MAC_Handle   : Itb.Sys.Handle;
      Plaintext    : System.Address;
      Pt_Len       : Interfaces.C.size_t;
      Out_Buf      : System.Address;
      Out_Cap      : Interfaces.C.size_t;
      Out_Len      : access Interfaces.C.size_t)
      return Interfaces.C.int
   with Convention => C;

   function Run_Auth
     (Fn      : Auth_Cipher_Fn;
      Noise   : Itb.Seed.Seed;
      Data    : Itb.Seed.Seed;
      Start   : Itb.Seed.Seed;
      Mac     : Itb.MAC.MAC;
      Payload : Byte_Array) return Byte_Array
   is
      use Interfaces.C;
      In_Addr : constant System.Address :=
        (if Payload'Length > 0 then Payload'Address else System.Null_Address);
      --  See Run_Single for the formula+retry-once rationale.
      Cap_LL  : constant Long_Long_Integer :=
        Long_Long_Integer'Max
          (131072,
           Long_Long_Integer (Payload'Length) * 5 / 4 + 131072);
      Cap     : constant size_t := size_t (Cap_LL);
      Result  : Byte_Array (1 .. Stream_Element_Offset (Cap));
      Out_Len : aliased size_t := 0;
      Status  : int;
   begin
      Status := Fn (Itb.Seed.Raw_Handle (Noise),
                    Itb.Seed.Raw_Handle (Data),
                    Itb.Seed.Raw_Handle (Start),
                    Itb.MAC.Raw_Handle (Mac),
                    In_Addr,
                    Payload'Length,
                    Result'Address,
                    Cap,
                    Out_Len'Access);

      if Status = Itb.Status.Buffer_Too_Small then
         declare
            Need     : constant size_t := Out_Len;
            Result2  : Byte_Array (1 .. Stream_Element_Offset (Need));
            Out_Len2 : aliased size_t := 0;
         begin
            Status := Fn (Itb.Seed.Raw_Handle (Noise),
                          Itb.Seed.Raw_Handle (Data),
                          Itb.Seed.Raw_Handle (Start),
                          Itb.MAC.Raw_Handle (Mac),
                          In_Addr,
                          Payload'Length,
                          Result2'Address,
                          Need,
                          Out_Len2'Access);
            if Status /= 0 then
               Itb.Errors.Raise_For (Integer (Status));
            end if;
            return Result2 (1 .. Stream_Element_Offset (Out_Len2));
         end;
      end if;

      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      return Result (1 .. Stream_Element_Offset (Out_Len));
   end Run_Auth;

   type Auth_Triple_Cipher_Fn is access function
     (Noise_Handle  : Itb.Sys.Handle;
      Data_Handle1  : Itb.Sys.Handle;
      Data_Handle2  : Itb.Sys.Handle;
      Data_Handle3  : Itb.Sys.Handle;
      Start_Handle1 : Itb.Sys.Handle;
      Start_Handle2 : Itb.Sys.Handle;
      Start_Handle3 : Itb.Sys.Handle;
      MAC_Handle    : Itb.Sys.Handle;
      Plaintext     : System.Address;
      Pt_Len        : Interfaces.C.size_t;
      Out_Buf       : System.Address;
      Out_Cap       : Interfaces.C.size_t;
      Out_Len       : access Interfaces.C.size_t)
      return Interfaces.C.int
   with Convention => C;

   function Run_Auth_Triple
     (Fn      : Auth_Triple_Cipher_Fn;
      Noise   : Itb.Seed.Seed;
      Data1   : Itb.Seed.Seed;
      Data2   : Itb.Seed.Seed;
      Data3   : Itb.Seed.Seed;
      Start1  : Itb.Seed.Seed;
      Start2  : Itb.Seed.Seed;
      Start3  : Itb.Seed.Seed;
      Mac     : Itb.MAC.MAC;
      Payload : Byte_Array) return Byte_Array
   is
      use Interfaces.C;
      In_Addr : constant System.Address :=
        (if Payload'Length > 0 then Payload'Address else System.Null_Address);
      --  See Run_Single for the formula+retry-once rationale.
      Cap_LL  : constant Long_Long_Integer :=
        Long_Long_Integer'Max
          (131072,
           Long_Long_Integer (Payload'Length) * 5 / 4 + 131072);
      Cap     : constant size_t := size_t (Cap_LL);
      Result  : Byte_Array (1 .. Stream_Element_Offset (Cap));
      Out_Len : aliased size_t := 0;
      Status  : int;
   begin
      Status := Fn (Itb.Seed.Raw_Handle (Noise),
                    Itb.Seed.Raw_Handle (Data1),
                    Itb.Seed.Raw_Handle (Data2),
                    Itb.Seed.Raw_Handle (Data3),
                    Itb.Seed.Raw_Handle (Start1),
                    Itb.Seed.Raw_Handle (Start2),
                    Itb.Seed.Raw_Handle (Start3),
                    Itb.MAC.Raw_Handle (Mac),
                    In_Addr,
                    Payload'Length,
                    Result'Address,
                    Cap,
                    Out_Len'Access);

      if Status = Itb.Status.Buffer_Too_Small then
         declare
            Need     : constant size_t := Out_Len;
            Result2  : Byte_Array (1 .. Stream_Element_Offset (Need));
            Out_Len2 : aliased size_t := 0;
         begin
            Status := Fn (Itb.Seed.Raw_Handle (Noise),
                          Itb.Seed.Raw_Handle (Data1),
                          Itb.Seed.Raw_Handle (Data2),
                          Itb.Seed.Raw_Handle (Data3),
                          Itb.Seed.Raw_Handle (Start1),
                          Itb.Seed.Raw_Handle (Start2),
                          Itb.Seed.Raw_Handle (Start3),
                          Itb.MAC.Raw_Handle (Mac),
                          In_Addr,
                          Payload'Length,
                          Result2'Address,
                          Need,
                          Out_Len2'Access);
            if Status /= 0 then
               Itb.Errors.Raise_For (Integer (Status));
            end if;
            return Result2 (1 .. Stream_Element_Offset (Out_Len2));
         end;
      end if;

      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      return Result (1 .. Stream_Element_Offset (Out_Len));
   end Run_Auth_Triple;

   ---------------------------------------------------------------------
   --  Public API — thin shells around the helpers.
   ---------------------------------------------------------------------

   function Encrypt
     (Noise     : Itb.Seed.Seed;
      Data      : Itb.Seed.Seed;
      Start     : Itb.Seed.Seed;
      Plaintext : Byte_Array) return Byte_Array is
   begin
      return Run_Single
        (Itb.Sys.ITB_Encrypt'Access, Noise, Data, Start, Plaintext);
   end Encrypt;

   function Decrypt
     (Noise      : Itb.Seed.Seed;
      Data       : Itb.Seed.Seed;
      Start      : Itb.Seed.Seed;
      Ciphertext : Byte_Array) return Byte_Array is
   begin
      return Run_Single
        (Itb.Sys.ITB_Decrypt'Access, Noise, Data, Start, Ciphertext);
   end Decrypt;

   function Encrypt_Triple
     (Noise     : Itb.Seed.Seed;
      Data1     : Itb.Seed.Seed;
      Data2     : Itb.Seed.Seed;
      Data3     : Itb.Seed.Seed;
      Start1    : Itb.Seed.Seed;
      Start2    : Itb.Seed.Seed;
      Start3    : Itb.Seed.Seed;
      Plaintext : Byte_Array) return Byte_Array is
   begin
      return Run_Triple
        (Itb.Sys.ITB_Encrypt3'Access,
         Noise, Data1, Data2, Data3, Start1, Start2, Start3, Plaintext);
   end Encrypt_Triple;

   function Decrypt_Triple
     (Noise      : Itb.Seed.Seed;
      Data1      : Itb.Seed.Seed;
      Data2      : Itb.Seed.Seed;
      Data3      : Itb.Seed.Seed;
      Start1     : Itb.Seed.Seed;
      Start2     : Itb.Seed.Seed;
      Start3     : Itb.Seed.Seed;
      Ciphertext : Byte_Array) return Byte_Array is
   begin
      return Run_Triple
        (Itb.Sys.ITB_Decrypt3'Access,
         Noise, Data1, Data2, Data3, Start1, Start2, Start3, Ciphertext);
   end Decrypt_Triple;

   function Encrypt_Auth
     (Noise     : Itb.Seed.Seed;
      Data      : Itb.Seed.Seed;
      Start     : Itb.Seed.Seed;
      Mac       : Itb.MAC.MAC;
      Plaintext : Byte_Array) return Byte_Array is
   begin
      return Run_Auth
        (Itb.Sys.ITB_EncryptAuth'Access,
         Noise, Data, Start, Mac, Plaintext);
   end Encrypt_Auth;

   function Decrypt_Auth
     (Noise      : Itb.Seed.Seed;
      Data       : Itb.Seed.Seed;
      Start      : Itb.Seed.Seed;
      Mac        : Itb.MAC.MAC;
      Ciphertext : Byte_Array) return Byte_Array is
   begin
      return Run_Auth
        (Itb.Sys.ITB_DecryptAuth'Access,
         Noise, Data, Start, Mac, Ciphertext);
   end Decrypt_Auth;

   function Encrypt_Auth_Triple
     (Noise     : Itb.Seed.Seed;
      Data1     : Itb.Seed.Seed;
      Data2     : Itb.Seed.Seed;
      Data3     : Itb.Seed.Seed;
      Start1    : Itb.Seed.Seed;
      Start2    : Itb.Seed.Seed;
      Start3    : Itb.Seed.Seed;
      Mac       : Itb.MAC.MAC;
      Plaintext : Byte_Array) return Byte_Array is
   begin
      return Run_Auth_Triple
        (Itb.Sys.ITB_EncryptAuth3'Access,
         Noise, Data1, Data2, Data3, Start1, Start2, Start3, Mac, Plaintext);
   end Encrypt_Auth_Triple;

   function Decrypt_Auth_Triple
     (Noise      : Itb.Seed.Seed;
      Data1      : Itb.Seed.Seed;
      Data2      : Itb.Seed.Seed;
      Data3      : Itb.Seed.Seed;
      Start1     : Itb.Seed.Seed;
      Start2     : Itb.Seed.Seed;
      Start3     : Itb.Seed.Seed;
      Mac        : Itb.MAC.MAC;
      Ciphertext : Byte_Array) return Byte_Array is
   begin
      return Run_Auth_Triple
        (Itb.Sys.ITB_DecryptAuth3'Access,
         Noise, Data1, Data2, Data3, Start1, Start2, Start3, Mac, Ciphertext);
   end Decrypt_Auth_Triple;

end Itb.Cipher;
