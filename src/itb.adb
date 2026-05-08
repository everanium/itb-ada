--  Itb body — implementations of the library-wide free subprograms.

with Interfaces.C;
with System;

with Itb.Errors;
with Itb.Status;
with Itb.Sys;

package body Itb is

   ---------------------------------------------------------------------
   --  Local helpers
   ---------------------------------------------------------------------

   --  Reads a libitb-owned variable-length string into a fresh Ada
   --  String. Caller passes the FFI status, the buffer it filled, and
   --  the libitb-reported length. libitb counts the trailing NUL
   --  terminator in Out_Len; strip it before returning the Ada String.
   --  Raises an Itb_Error on non-OK.
   function Decode_String
     (Status  : Interfaces.C.int;
      Buf     : Interfaces.C.char_array;
      Out_Len : Interfaces.C.size_t) return String
   is
      use Interfaces.C;
   begin
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      if Out_Len <= 1 then
         return "";
      end if;
      return To_Ada
        (Buf (Buf'First .. Buf'First + Out_Len - 2), Trim_Nul => False);
   end Decode_String;

   --  C-convention access types so that 'Access on a pragma-imported
   --  C function (Convention => C) is layout-compatible with the
   --  helper-subprogram parameter type.
   type C_String_Getter is access function
     (Out_Buf : System.Address;
      Cap     : Interfaces.C.size_t;
      Out_Len : access Interfaces.C.size_t)
      return Interfaces.C.int
   with Convention => C;

   type C_Indexed_String_Getter is access function
     (I       : Interfaces.C.int;
      Out_Buf : System.Address;
      Cap     : Interfaces.C.size_t;
      Out_Len : access Interfaces.C.size_t)
      return Interfaces.C.int
   with Convention => C;

   --  Wraps an FFI string-getter of shape
   --      int FFI (char* out, size_t cap, size_t* outLen)
   --  into a plain Ada String.
   function Read_FFI_String (Get : C_String_Getter) return String is
      use Interfaces.C;
      Buf     : aliased char_array (1 .. 256) := [others => nul];
      Out_Len : aliased size_t := 0;
      Status  : int;
   begin
      Status := Get (Buf'Address, Buf'Length, Out_Len'Access);
      return Decode_String (Status, Buf, Out_Len);
   end Read_FFI_String;

   --  Wraps an FFI string-getter of shape
   --      int FFI (int i, char* out, size_t cap, size_t* outLen)
   --  into a plain Ada String, indexed by i.
   function Read_FFI_Indexed_String
     (Get : C_Indexed_String_Getter;
      I   : Natural)
      return String
   is
      use Interfaces.C;
      Buf     : aliased char_array (1 .. 256) := [others => nul];
      Out_Len : aliased size_t := 0;
      Status  : int;
   begin
      Status := Get (int (I), Buf'Address, Buf'Length, Out_Len'Access);
      return Decode_String (Status, Buf, Out_Len);
   end Read_FFI_Indexed_String;

   ---------------------------------------------------------------------
   --  Library metadata implementations
   ---------------------------------------------------------------------

   function Version return String is
   begin
      return Read_FFI_String (Itb.Sys.ITB_Version'Access);
   end Version;

   function Hash_Count return Natural is
      N : constant Interfaces.C.int := Itb.Sys.ITB_HashCount;
   begin
      return Natural (N);
   end Hash_Count;

   function Hash_Name (I : Natural) return String is
   begin
      return Read_FFI_Indexed_String (Itb.Sys.ITB_HashName'Access, I);
   end Hash_Name;

   function Hash_Width (I : Natural) return Natural is
      use Interfaces.C;
      W : constant int := Itb.Sys.ITB_HashWidth (int (I));
   begin
      if W < 0 then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      return Natural (W);
   end Hash_Width;

   function List_Hashes return Hash_List is
      N      : constant Natural := Hash_Count;
      Result : Hash_List (1 .. N);
   begin
      for I in 1 .. N loop
         Result (I).Name :=
           Ada.Strings.Unbounded.To_Unbounded_String (Hash_Name (I - 1));
         Result (I).Width := Hash_Width (I - 1);
      end loop;
      return Result;
   end List_Hashes;

   function MAC_Count return Natural is
      N : constant Interfaces.C.int := Itb.Sys.ITB_MACCount;
   begin
      return Natural (N);
   end MAC_Count;

   function MAC_Name (I : Natural) return String is
   begin
      return Read_FFI_Indexed_String (Itb.Sys.ITB_MACName'Access, I);
   end MAC_Name;

   function MAC_Key_Size (I : Natural) return Natural is
      use Interfaces.C;
      W : constant int := Itb.Sys.ITB_MACKeySize (int (I));
   begin
      if W < 0 then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      return Natural (W);
   end MAC_Key_Size;

   function MAC_Tag_Size (I : Natural) return Natural is
      use Interfaces.C;
      W : constant int := Itb.Sys.ITB_MACTagSize (int (I));
   begin
      if W < 0 then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      return Natural (W);
   end MAC_Tag_Size;

   function MAC_Min_Key_Bytes (I : Natural) return Natural is
      use Interfaces.C;
      W : constant int := Itb.Sys.ITB_MACMinKeyBytes (int (I));
   begin
      if W < 0 then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      return Natural (W);
   end MAC_Min_Key_Bytes;

   function List_MACs return MAC_List is
      N      : constant Natural := MAC_Count;
      Result : MAC_List (1 .. N);
   begin
      for I in 1 .. N loop
         Result (I).Name :=
           Ada.Strings.Unbounded.To_Unbounded_String (MAC_Name (I - 1));
         Result (I).Key_Size      := MAC_Key_Size (I - 1);
         Result (I).Tag_Size      := MAC_Tag_Size (I - 1);
         Result (I).Min_Key_Bytes := MAC_Min_Key_Bytes (I - 1);
      end loop;
      return Result;
   end List_MACs;

   function Channels return Natural is
   begin
      return Natural (Itb.Sys.ITB_Channels);
   end Channels;

   function Max_Key_Bits return Natural is
   begin
      return Natural (Itb.Sys.ITB_MaxKeyBits);
   end Max_Key_Bits;

   function Header_Size return Natural is
   begin
      return Natural (Itb.Sys.ITB_HeaderSize);
   end Header_Size;

   function Parse_Chunk_Len (Header : Byte_Array) return Natural is
      use Interfaces.C;
      Out_Chunk : aliased size_t := 0;
      Status    : int;
      Header_Addr : constant System.Address :=
        (if Header'Length > 0 then Header'Address else System.Null_Address);
   begin
      Status := Itb.Sys.ITB_ParseChunkLen
                  (Header     => Header_Addr,
                   Header_Len => Header'Length,
                   Out_Chunk  => Out_Chunk'Access);
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      return Natural (Out_Chunk);
   end Parse_Chunk_Len;

   ---------------------------------------------------------------------
   --  Process-global configuration implementations
   ---------------------------------------------------------------------

   procedure Set_Bit_Soup (Mode : Integer) is
      use Interfaces.C;
      Status : constant int := Itb.Sys.ITB_SetBitSoup (int (Mode));
   begin
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end Set_Bit_Soup;

   function Get_Bit_Soup return Integer is
   begin
      return Integer (Itb.Sys.ITB_GetBitSoup);
   end Get_Bit_Soup;

   procedure Set_Lock_Soup (Mode : Integer) is
      use Interfaces.C;
      Status : constant int := Itb.Sys.ITB_SetLockSoup (int (Mode));
   begin
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end Set_Lock_Soup;

   function Get_Lock_Soup return Integer is
   begin
      return Integer (Itb.Sys.ITB_GetLockSoup);
   end Get_Lock_Soup;

   procedure Set_Max_Workers (N : Integer) is
      use Interfaces.C;
      Status : constant int := Itb.Sys.ITB_SetMaxWorkers (int (N));
   begin
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end Set_Max_Workers;

   function Get_Max_Workers return Integer is
   begin
      return Integer (Itb.Sys.ITB_GetMaxWorkers);
   end Get_Max_Workers;

   procedure Set_Nonce_Bits (N : Integer) is
      use Interfaces.C;
      Status : constant int := Itb.Sys.ITB_SetNonceBits (int (N));
   begin
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end Set_Nonce_Bits;

   function Get_Nonce_Bits return Integer is
   begin
      return Integer (Itb.Sys.ITB_GetNonceBits);
   end Get_Nonce_Bits;

   procedure Set_Barrier_Fill (N : Integer) is
      use Interfaces.C;
      Status : constant int := Itb.Sys.ITB_SetBarrierFill (int (N));
   begin
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end Set_Barrier_Fill;

   function Get_Barrier_Fill return Integer is
   begin
      return Integer (Itb.Sys.ITB_GetBarrierFill);
   end Get_Barrier_Fill;

end Itb;
