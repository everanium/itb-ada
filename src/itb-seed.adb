--  Itb.Seed body.

with Interfaces.C;
with Interfaces.C.Strings;
with System;

with Itb.Errors;
with Itb.Status;

package body Itb.Seed is

   use type Itb.Sys.Handle;

   ---------------------------------------------------------------------
   --  Constructor — CSPRNG-keyed Seed.
   ---------------------------------------------------------------------

   function Make
     (Hash_Name : String;
      Key_Bits  : Integer) return Seed
   is
      use Interfaces.C;
      C_Name : Strings.chars_ptr := Strings.New_String (Hash_Name);
      Handle : aliased Itb.Sys.Handle := 0;
      Status : int;
   begin
      Status := Itb.Sys.ITB_NewSeed
                  (Hash_Name  => C_Name,
                   Key_Bits   => int (Key_Bits),
                   Out_Handle => Handle'Access);
      Strings.Free (C_Name);
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      return S : Seed do
         S.Handle    := Handle;
         S.Hash_Name :=
           Ada.Strings.Unbounded.To_Unbounded_String (Hash_Name);
      end return;
   end Make;

   ---------------------------------------------------------------------
   --  Constructor — deterministic rebuild from components.
   ---------------------------------------------------------------------

   function From_Components
     (Hash_Name  : String;
      Components : Component_Array;
      Hash_Key   : Byte_Array) return Seed
   is
      use Interfaces.C;
      C_Name : Strings.chars_ptr := Strings.New_String (Hash_Name);
      Handle : aliased Itb.Sys.Handle := 0;
      Status : int;

      Comps_Addr : constant System.Address :=
        (if Components'Length > 0 then Components'Address
         else System.Null_Address);
      Key_Addr   : constant System.Address :=
        (if Hash_Key'Length > 0 then Hash_Key'Address
         else System.Null_Address);
   begin
      Status := Itb.Sys.ITB_NewSeedFromComponents
                  (Hash_Name      => C_Name,
                   Components     => Comps_Addr,
                   Components_Len => int (Components'Length),
                   Hash_Key       => Key_Addr,
                   Hash_Key_Len   => int (Hash_Key'Length),
                   Out_Handle     => Handle'Access);
      Strings.Free (C_Name);
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      return S : Seed do
         S.Handle    := Handle;
         S.Hash_Name :=
           Ada.Strings.Unbounded.To_Unbounded_String (Hash_Name);
      end return;
   end From_Components;

   ---------------------------------------------------------------------
   --  Accessors
   ---------------------------------------------------------------------

   function Width (Self : Seed) return Integer is
      use Interfaces.C;
      Out_Status : aliased int := 0;
      W          : constant int :=
        Itb.Sys.ITB_SeedWidth (Self.Handle, Out_Status'Access);
   begin
      if Out_Status /= 0 then
         Itb.Errors.Raise_For (Integer (Out_Status));
      end if;
      return Integer (W);
   end Width;

   function Hash_Name (Self : Seed) return String is
   begin
      return Ada.Strings.Unbounded.To_String (Self.Hash_Name);
   end Hash_Name;

   function Hash_Name_Introspect (Self : Seed) return String is
      use Interfaces.C;
      Buf     : aliased char_array (1 .. 64) := [others => nul];
      Out_Len : aliased size_t := 0;
      Status  : int;
   begin
      Status := Itb.Sys.ITB_SeedHashName
                  (H       => Self.Handle,
                   Out_Buf => Buf'Address,
                   Cap     => Buf'Length,
                   Out_Len => Out_Len'Access);
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      --  libitb counts the trailing NUL terminator in Out_Len; strip
      --  it before returning the Ada String.
      if Out_Len <= 1 then
         return "";
      end if;
      return To_Ada (Buf (1 .. Out_Len - 1), Trim_Nul => False);
   end Hash_Name_Introspect;

   function Get_Hash_Key (Self : Seed) return Byte_Array is
      use Interfaces.C;
      Probe_Len : aliased size_t := 0;
      Status    : int;
   begin
      --  Two-call pattern: probe length first.
      Status := Itb.Sys.ITB_GetSeedHashKey
                  (H       => Self.Handle,
                   Out_Buf => System.Null_Address,
                   Cap     => 0,
                   Out_Len => Probe_Len'Access);
      if Status = Itb.Status.OK and then Probe_Len = 0 then
         --  siphash24 has no internal fixed key.
         return Byte_Array'(1 .. 0 => 0);
      end if;
      if Status /= Itb.Status.Buffer_Too_Small then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      declare
         Buf     : Byte_Array
                     (1 .. Ada.Streams.Stream_Element_Offset (Probe_Len));
         Out_Len : aliased size_t := 0;
      begin
         Status := Itb.Sys.ITB_GetSeedHashKey
                     (H       => Self.Handle,
                      Out_Buf => Buf'Address,
                      Cap     => Probe_Len,
                      Out_Len => Out_Len'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         return Buf
           (1 .. Ada.Streams.Stream_Element_Offset (Out_Len));
      end;
   end Get_Hash_Key;

   function Get_Components (Self : Seed) return Component_Array is
      use Interfaces.C;
      Probe_Len : aliased int := 0;
      Status    : int;
   begin
      --  Probe count first.
      Status := Itb.Sys.ITB_GetSeedComponents
                  (H       => Self.Handle,
                   Out_Buf => System.Null_Address,
                   Cap     => 0,
                   Out_Len => Probe_Len'Access);
      --  Mirror the OK-with-zero-count branch every other probe site
      --  in the binding handles (e.g. ITB_Easy_PRFKey returning empty
      --  for primitives without per-slot PRF keys). A practical Seed
      --  always carries 8 .. 32 components, so the path is unreachable
      --  on shipped libitb, but keeping the asymmetry would be a
      --  maintainability hazard.
      if Status = Itb.Status.OK and then Probe_Len = 0 then
         return Component_Array'(1 .. 0 => 0);
      end if;
      if Status /= Itb.Status.Buffer_Too_Small then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      declare
         N       : constant Natural := Natural (Probe_Len);
         Buf     : Component_Array (1 .. N);
         Out_Len : aliased int := 0;
      begin
         Status := Itb.Sys.ITB_GetSeedComponents
                     (H       => Self.Handle,
                      Out_Buf => Buf'Address,
                      Cap     => int (N),
                      Out_Len => Out_Len'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         return Buf (1 .. Natural (Out_Len));
      end;
   end Get_Components;

   procedure Attach_Lock_Seed (Self : Seed; Lock : Seed) is
      use Interfaces.C;
      Status : constant int :=
        Itb.Sys.ITB_AttachLockSeed (Self.Handle, Lock.Handle);
   begin
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end Attach_Lock_Seed;

   function Raw_Handle (Self : Seed) return Itb.Sys.Handle is
   begin
      return Self.Handle;
   end Raw_Handle;

   ---------------------------------------------------------------------
   --  Finalize — deterministic release at scope exit.
   ---------------------------------------------------------------------

   overriding procedure Finalize (Self : in out Seed) is
      use Interfaces.C;
      Discard : int;
      pragma Unreferenced (Discard);
   begin
      if Self.Handle /= 0 then
         Discard := Itb.Sys.ITB_FreeSeed (Self.Handle);
         Self.Handle := 0;
      end if;
   end Finalize;

end Itb.Seed;
