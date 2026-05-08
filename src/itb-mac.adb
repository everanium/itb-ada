--  Itb.MAC body.

with Interfaces.C;
with Interfaces.C.Strings;
with System;

with Itb.Errors;

package body Itb.MAC is

   use type Itb.Sys.Handle;

   function Make (Mac_Name : String; Key : Byte_Array) return MAC is
      use Interfaces.C;
      C_Name : Strings.chars_ptr := Strings.New_String (Mac_Name);
      Handle : aliased Itb.Sys.Handle := 0;
      Status : int;

      Key_Addr : constant System.Address :=
        (if Key'Length > 0 then Key'Address else System.Null_Address);
   begin
      Status := Itb.Sys.ITB_NewMAC
                  (Mac_Name   => C_Name,
                   Key        => Key_Addr,
                   Key_Len    => Key'Length,
                   Out_Handle => Handle'Access);
      Strings.Free (C_Name);
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      return M : MAC do
         M.Handle := Handle;
         M.Name   := Ada.Strings.Unbounded.To_Unbounded_String (Mac_Name);
      end return;
   end Make;

   function Name (Self : MAC) return String is
   begin
      return Ada.Strings.Unbounded.To_String (Self.Name);
   end Name;

   function Raw_Handle (Self : MAC) return Itb.Sys.Handle is
   begin
      return Self.Handle;
   end Raw_Handle;

   overriding procedure Finalize (Self : in out MAC) is
      use Interfaces.C;
      Discard : int;
      pragma Unreferenced (Discard);
   begin
      if Self.Handle /= 0 then
         Discard := Itb.Sys.ITB_FreeMAC (Self.Handle);
         Self.Handle := 0;
      end if;
   end Finalize;

end Itb.MAC;
