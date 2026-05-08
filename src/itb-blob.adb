--  Itb.Blob body — three width-typed wrappers sharing a single set of
--  raw-handle helpers. The helpers accept an Itb.Sys.Handle directly
--  so each wrapper struct's body stays a thin shell that extracts
--  Self.Handle and delegates.

with Ada.Streams; use Ada.Streams;
with Interfaces.C;
with System;

with Itb.Errors;
with Itb.Status;

package body Itb.Blob is

   use type Itb.Sys.Handle;

   ---------------------------------------------------------------------
   --  Internal helpers operating on a raw Itb.Sys.Handle.
   ---------------------------------------------------------------------

   function Empty_Bytes return Byte_Array is
   begin
      return Byte_Array'(1 .. 0 => 0);
   end Empty_Bytes;

   function Empty_Components return Component_Array is
   begin
      return Component_Array'(1 .. 0 => 0);
   end Empty_Components;

   function H_Width (H : Itb.Sys.Handle) return Integer is
      use Interfaces.C;
      Out_Status : aliased int := 0;
      W          : constant int :=
        Itb.Sys.ITB_Blob_Width (H, Out_Status'Access);
   begin
      if Out_Status /= 0 then
         Itb.Errors.Raise_For (Integer (Out_Status));
      end if;
      return Integer (W);
   end H_Width;

   function H_Mode (H : Itb.Sys.Handle) return Integer is
      use Interfaces.C;
      Out_Status : aliased int := 0;
      M          : constant int :=
        Itb.Sys.ITB_Blob_Mode (H, Out_Status'Access);
   begin
      if Out_Status /= 0 then
         Itb.Errors.Raise_For (Integer (Out_Status));
      end if;
      return Integer (M);
   end H_Mode;

   procedure H_Set_Key
     (H    : Itb.Sys.Handle;
      Slot : Slot_Type;
      Key  : Byte_Array)
   is
      use Interfaces.C;
      Key_Addr : constant System.Address :=
        (if Key'Length > 0 then Key'Address else System.Null_Address);
      Status   : constant int :=
        Itb.Sys.ITB_Blob_SetKey
          (H       => H,
           Slot    => int (Slot),
           Key     => Key_Addr,
           Key_Len => Key'Length);
   begin
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end H_Set_Key;

   function H_Get_Key
     (H    : Itb.Sys.Handle;
      Slot : Slot_Type) return Byte_Array
   is
      use Interfaces.C;
      Probe_Len : aliased size_t := 0;
      Status    : int;
   begin
      Status := Itb.Sys.ITB_Blob_GetKey
                  (H       => H,
                   Slot    => int (Slot),
                   Out_Buf => System.Null_Address,
                   Out_Cap => 0,
                   Out_Len => Probe_Len'Access);
      if Status = Itb.Status.OK and then Probe_Len = 0 then
         return Empty_Bytes;
      end if;
      if Status /= Itb.Status.Buffer_Too_Small then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      declare
         Buf     : Byte_Array
                     (1 .. Stream_Element_Offset (Probe_Len));
         Out_Len : aliased size_t := 0;
      begin
         Status := Itb.Sys.ITB_Blob_GetKey
                     (H       => H,
                      Slot    => int (Slot),
                      Out_Buf => Buf'Address,
                      Out_Cap => Probe_Len,
                      Out_Len => Out_Len'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         return Buf (1 .. Stream_Element_Offset (Out_Len));
      end;
   end H_Get_Key;

   procedure H_Set_Components
     (H     : Itb.Sys.Handle;
      Slot  : Slot_Type;
      Comps : Component_Array)
   is
      use Interfaces.C;
      Comps_Addr : constant System.Address :=
        (if Comps'Length > 0 then Comps'Address else System.Null_Address);
      Status     : constant int :=
        Itb.Sys.ITB_Blob_SetComponents
          (H     => H,
           Slot  => int (Slot),
           Comps => Comps_Addr,
           Count => Comps'Length);
   begin
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end H_Set_Components;

   function H_Get_Components
     (H    : Itb.Sys.Handle;
      Slot : Slot_Type) return Component_Array
   is
      use Interfaces.C;
      Probe_Count : aliased size_t := 0;
      Status      : int;
   begin
      Status := Itb.Sys.ITB_Blob_GetComponents
                  (H         => H,
                   Slot      => int (Slot),
                   Out_Buf   => System.Null_Address,
                   Out_Cap   => 0,
                   Out_Count => Probe_Count'Access);
      if Status = Itb.Status.OK and then Probe_Count = 0 then
         return Empty_Components;
      end if;
      if Status /= Itb.Status.Buffer_Too_Small then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      declare
         N         : constant Natural := Natural (Probe_Count);
         Buf       : Component_Array (1 .. N);
         Out_Count : aliased size_t := 0;
      begin
         Status := Itb.Sys.ITB_Blob_GetComponents
                     (H         => H,
                      Slot      => int (Slot),
                      Out_Buf   => Buf'Address,
                      Out_Cap   => Probe_Count,
                      Out_Count => Out_Count'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         return Buf (1 .. Natural (Out_Count));
      end;
   end H_Get_Components;

   procedure H_Set_MAC_Key
     (H   : Itb.Sys.Handle;
      Key : Byte_Array)
   is
      use Interfaces.C;
      Key_Addr : constant System.Address :=
        (if Key'Length > 0 then Key'Address else System.Null_Address);
      Status   : constant int :=
        Itb.Sys.ITB_Blob_SetMACKey
          (H       => H,
           Key     => Key_Addr,
           Key_Len => Key'Length);
   begin
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end H_Set_MAC_Key;

   function H_Get_MAC_Key (H : Itb.Sys.Handle) return Byte_Array is
      use Interfaces.C;
      Probe_Len : aliased size_t := 0;
      Status    : int;
   begin
      Status := Itb.Sys.ITB_Blob_GetMACKey
                  (H       => H,
                   Out_Buf => System.Null_Address,
                   Out_Cap => 0,
                   Out_Len => Probe_Len'Access);
      if Status = Itb.Status.OK and then Probe_Len = 0 then
         return Empty_Bytes;
      end if;
      if Status /= Itb.Status.Buffer_Too_Small then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      declare
         Buf     : Byte_Array
                     (1 .. Stream_Element_Offset (Probe_Len));
         Out_Len : aliased size_t := 0;
      begin
         Status := Itb.Sys.ITB_Blob_GetMACKey
                     (H       => H,
                      Out_Buf => Buf'Address,
                      Out_Cap => Probe_Len,
                      Out_Len => Out_Len'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         return Buf (1 .. Stream_Element_Offset (Out_Len));
      end;
   end H_Get_MAC_Key;

   procedure H_Set_MAC_Name
     (H    : Itb.Sys.Handle;
      Name : String)
   is
      use Interfaces.C;
      Name_Addr : constant System.Address :=
        (if Name'Length > 0 then Name'Address else System.Null_Address);
      Status    : constant int :=
        Itb.Sys.ITB_Blob_SetMACName
          (H        => H,
           Name     => Name_Addr,
           Name_Len => Name'Length);
   begin
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end H_Set_MAC_Name;

   function H_Get_MAC_Name (H : Itb.Sys.Handle) return String is
      use Interfaces.C;
      Probe_Len : aliased size_t := 0;
      Status    : int;
   begin
      Status := Itb.Sys.ITB_Blob_GetMACName
                  (H       => H,
                   Out_Buf => System.Null_Address,
                   Out_Cap => 0,
                   Out_Len => Probe_Len'Access);
      if Status = Itb.Status.OK and then Probe_Len <= 1 then
         --  Out_Len of 0 or 1 includes only the trailing NUL — empty
         --  name on the handle.
         return "";
      end if;
      if Status /= Itb.Status.Buffer_Too_Small then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      declare
         Buf     : aliased char_array (1 .. Probe_Len) := [others => nul];
         Out_Len : aliased size_t := 0;
      begin
         Status := Itb.Sys.ITB_Blob_GetMACName
                     (H       => H,
                      Out_Buf => Buf'Address,
                      Out_Cap => Probe_Len,
                      Out_Len => Out_Len'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         if Out_Len <= 1 then
            return "";
         end if;
         --  ITB_Blob_GetMACName reports Out_Len including the trailing
         --  NUL; trim it before returning the Ada String.
         return To_Ada (Buf (1 .. Out_Len - 1), Trim_Nul => False);
      end;
   end H_Get_MAC_Name;

   --  Two-call probe-then-allocate over ITB_Blob_Export /
   --  ITB_Blob_Export3. The Triple flag selects which entry point
   --  runs.
   function H_Export
     (H      : Itb.Sys.Handle;
      Opts   : Export_Opts;
      Triple : Boolean) return Byte_Array
   is
      use Interfaces.C;
      Probe_Len : aliased size_t := 0;
      Status    : int;
   begin
      if Triple then
         Status := Itb.Sys.ITB_Blob_Export3
                     (H            => H,
                      Opts_Bitmask => int (Opts),
                      Out_Buf      => System.Null_Address,
                      Out_Cap      => 0,
                      Out_Len      => Probe_Len'Access);
      else
         Status := Itb.Sys.ITB_Blob_Export
                     (H            => H,
                      Opts_Bitmask => int (Opts),
                      Out_Buf      => System.Null_Address,
                      Out_Cap      => 0,
                      Out_Len      => Probe_Len'Access);
      end if;
      if Status = Itb.Status.OK and then Probe_Len = 0 then
         return Empty_Bytes;
      end if;
      if Status /= Itb.Status.Buffer_Too_Small then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      declare
         Buf     : Byte_Array
                     (1 .. Stream_Element_Offset (Probe_Len));
         Out_Len : aliased size_t := 0;
      begin
         if Triple then
            Status := Itb.Sys.ITB_Blob_Export3
                        (H            => H,
                         Opts_Bitmask => int (Opts),
                         Out_Buf      => Buf'Address,
                         Out_Cap      => Probe_Len,
                         Out_Len      => Out_Len'Access);
         else
            Status := Itb.Sys.ITB_Blob_Export
                        (H            => H,
                         Opts_Bitmask => int (Opts),
                         Out_Buf      => Buf'Address,
                         Out_Cap      => Probe_Len,
                         Out_Len      => Out_Len'Access);
         end if;
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         return Buf (1 .. Stream_Element_Offset (Out_Len));
      end;
   end H_Export;

   procedure H_Import
     (H      : Itb.Sys.Handle;
      Blob   : Byte_Array;
      Triple : Boolean)
   is
      use Interfaces.C;
      Blob_Addr : constant System.Address :=
        (if Blob'Length > 0 then Blob'Address else System.Null_Address);
      Status    : int;
   begin
      if Triple then
         Status := Itb.Sys.ITB_Blob_Import3
                     (H        => H,
                      Blob     => Blob_Addr,
                      Blob_Len => Blob'Length);
      else
         Status := Itb.Sys.ITB_Blob_Import
                     (H        => H,
                      Blob     => Blob_Addr,
                      Blob_Len => Blob'Length);
      end if;
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end H_Import;

   ---------------------------------------------------------------------
   --  Blob128 — constructor + thin delegating shells.
   ---------------------------------------------------------------------

   function New_Blob128 return Blob128 is
      use Interfaces.C;
      Handle : aliased Itb.Sys.Handle := 0;
      Status : constant int := Itb.Sys.ITB_Blob128_New (Handle'Access);
   begin
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      return B : Blob128 do
         B.Handle := Handle;
      end return;
   end New_Blob128;

   function Width (Self : Blob128) return Integer is
   begin
      return H_Width (Self.Handle);
   end Width;

   function Mode (Self : Blob128) return Integer is
   begin
      return H_Mode (Self.Handle);
   end Mode;

   procedure Set_Key
     (Self : in out Blob128;
      Slot : Slot_Type;
      Key  : Byte_Array) is
   begin
      H_Set_Key (Self.Handle, Slot, Key);
   end Set_Key;

   function Get_Key
     (Self : Blob128;
      Slot : Slot_Type) return Byte_Array is
   begin
      return H_Get_Key (Self.Handle, Slot);
   end Get_Key;

   procedure Set_Components
     (Self  : in out Blob128;
      Slot  : Slot_Type;
      Comps : Component_Array) is
   begin
      H_Set_Components (Self.Handle, Slot, Comps);
   end Set_Components;

   function Get_Components
     (Self : Blob128;
      Slot : Slot_Type) return Component_Array is
   begin
      return H_Get_Components (Self.Handle, Slot);
   end Get_Components;

   procedure Set_MAC_Key
     (Self : in out Blob128;
      Key  : Byte_Array) is
   begin
      H_Set_MAC_Key (Self.Handle, Key);
   end Set_MAC_Key;

   function Get_MAC_Key (Self : Blob128) return Byte_Array is
   begin
      return H_Get_MAC_Key (Self.Handle);
   end Get_MAC_Key;

   procedure Set_MAC_Name
     (Self : in out Blob128;
      Name : String) is
   begin
      H_Set_MAC_Name (Self.Handle, Name);
   end Set_MAC_Name;

   function Get_MAC_Name (Self : Blob128) return String is
   begin
      return H_Get_MAC_Name (Self.Handle);
   end Get_MAC_Name;

   function Export
     (Self : Blob128;
      Opts : Export_Opts := Opt_None) return Byte_Array is
   begin
      return H_Export (Self.Handle, Opts, Triple => False);
   end Export;

   procedure Import
     (Self : in out Blob128;
      Blob : Byte_Array) is
   begin
      H_Import (Self.Handle, Blob, Triple => False);
   end Import;

   function Export_3
     (Self : Blob128;
      Opts : Export_Opts := Opt_None) return Byte_Array is
   begin
      return H_Export (Self.Handle, Opts, Triple => True);
   end Export_3;

   procedure Import_3
     (Self : in out Blob128;
      Blob : Byte_Array) is
   begin
      H_Import (Self.Handle, Blob, Triple => True);
   end Import_3;

   overriding procedure Finalize (Self : in out Blob128) is
      use Interfaces.C;
      Discard : int;
      pragma Unreferenced (Discard);
   begin
      if Self.Handle /= 0 then
         Discard := Itb.Sys.ITB_Blob_Free (Self.Handle);
         Self.Handle := 0;
      end if;
   end Finalize;

   ---------------------------------------------------------------------
   --  Blob256 — constructor + thin delegating shells.
   ---------------------------------------------------------------------

   function New_Blob256 return Blob256 is
      use Interfaces.C;
      Handle : aliased Itb.Sys.Handle := 0;
      Status : constant int := Itb.Sys.ITB_Blob256_New (Handle'Access);
   begin
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      return B : Blob256 do
         B.Handle := Handle;
      end return;
   end New_Blob256;

   function Width (Self : Blob256) return Integer is
   begin
      return H_Width (Self.Handle);
   end Width;

   function Mode (Self : Blob256) return Integer is
   begin
      return H_Mode (Self.Handle);
   end Mode;

   procedure Set_Key
     (Self : in out Blob256;
      Slot : Slot_Type;
      Key  : Byte_Array) is
   begin
      H_Set_Key (Self.Handle, Slot, Key);
   end Set_Key;

   function Get_Key
     (Self : Blob256;
      Slot : Slot_Type) return Byte_Array is
   begin
      return H_Get_Key (Self.Handle, Slot);
   end Get_Key;

   procedure Set_Components
     (Self  : in out Blob256;
      Slot  : Slot_Type;
      Comps : Component_Array) is
   begin
      H_Set_Components (Self.Handle, Slot, Comps);
   end Set_Components;

   function Get_Components
     (Self : Blob256;
      Slot : Slot_Type) return Component_Array is
   begin
      return H_Get_Components (Self.Handle, Slot);
   end Get_Components;

   procedure Set_MAC_Key
     (Self : in out Blob256;
      Key  : Byte_Array) is
   begin
      H_Set_MAC_Key (Self.Handle, Key);
   end Set_MAC_Key;

   function Get_MAC_Key (Self : Blob256) return Byte_Array is
   begin
      return H_Get_MAC_Key (Self.Handle);
   end Get_MAC_Key;

   procedure Set_MAC_Name
     (Self : in out Blob256;
      Name : String) is
   begin
      H_Set_MAC_Name (Self.Handle, Name);
   end Set_MAC_Name;

   function Get_MAC_Name (Self : Blob256) return String is
   begin
      return H_Get_MAC_Name (Self.Handle);
   end Get_MAC_Name;

   function Export
     (Self : Blob256;
      Opts : Export_Opts := Opt_None) return Byte_Array is
   begin
      return H_Export (Self.Handle, Opts, Triple => False);
   end Export;

   procedure Import
     (Self : in out Blob256;
      Blob : Byte_Array) is
   begin
      H_Import (Self.Handle, Blob, Triple => False);
   end Import;

   function Export_3
     (Self : Blob256;
      Opts : Export_Opts := Opt_None) return Byte_Array is
   begin
      return H_Export (Self.Handle, Opts, Triple => True);
   end Export_3;

   procedure Import_3
     (Self : in out Blob256;
      Blob : Byte_Array) is
   begin
      H_Import (Self.Handle, Blob, Triple => True);
   end Import_3;

   overriding procedure Finalize (Self : in out Blob256) is
      use Interfaces.C;
      Discard : int;
      pragma Unreferenced (Discard);
   begin
      if Self.Handle /= 0 then
         Discard := Itb.Sys.ITB_Blob_Free (Self.Handle);
         Self.Handle := 0;
      end if;
   end Finalize;

   ---------------------------------------------------------------------
   --  Blob512 — constructor + thin delegating shells.
   ---------------------------------------------------------------------

   function New_Blob512 return Blob512 is
      use Interfaces.C;
      Handle : aliased Itb.Sys.Handle := 0;
      Status : constant int := Itb.Sys.ITB_Blob512_New (Handle'Access);
   begin
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      return B : Blob512 do
         B.Handle := Handle;
      end return;
   end New_Blob512;

   function Width (Self : Blob512) return Integer is
   begin
      return H_Width (Self.Handle);
   end Width;

   function Mode (Self : Blob512) return Integer is
   begin
      return H_Mode (Self.Handle);
   end Mode;

   procedure Set_Key
     (Self : in out Blob512;
      Slot : Slot_Type;
      Key  : Byte_Array) is
   begin
      H_Set_Key (Self.Handle, Slot, Key);
   end Set_Key;

   function Get_Key
     (Self : Blob512;
      Slot : Slot_Type) return Byte_Array is
   begin
      return H_Get_Key (Self.Handle, Slot);
   end Get_Key;

   procedure Set_Components
     (Self  : in out Blob512;
      Slot  : Slot_Type;
      Comps : Component_Array) is
   begin
      H_Set_Components (Self.Handle, Slot, Comps);
   end Set_Components;

   function Get_Components
     (Self : Blob512;
      Slot : Slot_Type) return Component_Array is
   begin
      return H_Get_Components (Self.Handle, Slot);
   end Get_Components;

   procedure Set_MAC_Key
     (Self : in out Blob512;
      Key  : Byte_Array) is
   begin
      H_Set_MAC_Key (Self.Handle, Key);
   end Set_MAC_Key;

   function Get_MAC_Key (Self : Blob512) return Byte_Array is
   begin
      return H_Get_MAC_Key (Self.Handle);
   end Get_MAC_Key;

   procedure Set_MAC_Name
     (Self : in out Blob512;
      Name : String) is
   begin
      H_Set_MAC_Name (Self.Handle, Name);
   end Set_MAC_Name;

   function Get_MAC_Name (Self : Blob512) return String is
   begin
      return H_Get_MAC_Name (Self.Handle);
   end Get_MAC_Name;

   function Export
     (Self : Blob512;
      Opts : Export_Opts := Opt_None) return Byte_Array is
   begin
      return H_Export (Self.Handle, Opts, Triple => False);
   end Export;

   procedure Import
     (Self : in out Blob512;
      Blob : Byte_Array) is
   begin
      H_Import (Self.Handle, Blob, Triple => False);
   end Import;

   function Export_3
     (Self : Blob512;
      Opts : Export_Opts := Opt_None) return Byte_Array is
   begin
      return H_Export (Self.Handle, Opts, Triple => True);
   end Export_3;

   procedure Import_3
     (Self : in out Blob512;
      Blob : Byte_Array) is
   begin
      H_Import (Self.Handle, Blob, Triple => True);
   end Import_3;

   overriding procedure Finalize (Self : in out Blob512) is
      use Interfaces.C;
      Discard : int;
      pragma Unreferenced (Discard);
   begin
      if Self.Handle /= 0 then
         Discard := Itb.Sys.ITB_Blob_Free (Self.Handle);
         Self.Handle := 0;
      end if;
   end Finalize;

end Itb.Blob;
