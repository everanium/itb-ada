--  Itb.Error body — payload encoding / decoding + ITB_LastError read.

with Ada.Strings;
with Ada.Strings.Fixed;

with Interfaces.C;

package body Itb.Error is

   -----------------
   -- Status_Code --
   -----------------

   function Status_Code
     (E : Ada.Exceptions.Exception_Occurrence) return Itb.Status.Code
   is
      Msg  : constant String := Ada.Exceptions.Exception_Message (E);
      Pipe : Natural;
   begin
      if Msg'Length = 0 then
         return Itb.Status.Internal_Error;
      end if;
      Pipe := Ada.Strings.Fixed.Index (Msg, "|");
      if Pipe = 0 then
         return Itb.Status.Internal_Error;
      end if;
      begin
         return Itb.Status.Code'Value (Msg (Msg'First .. Pipe - 1));
      exception
         when Constraint_Error =>
            return Itb.Status.Internal_Error;
      end;
   end Status_Code;

   -------------
   -- Message --
   -------------

   function Message
     (E : Ada.Exceptions.Exception_Occurrence) return String
   is
      Msg  : constant String := Ada.Exceptions.Exception_Message (E);
      Pipe : Natural;
   begin
      if Msg'Length = 0 then
         return "";
      end if;
      Pipe := Ada.Strings.Fixed.Index (Msg, "|");
      if Pipe = 0 then
         return Msg;
      end if;
      return Msg (Pipe + 1 .. Msg'Last);
   end Message;

   ----------------
   -- Last_Error --
   ----------------

   function Last_Error return String is
      use Interfaces.C;
      Buf     : aliased char_array (1 .. 512) := [others => nul];
      Out_Len : aliased Size_T := 0;
      St      : constant C_Int :=
        ITB_LastError (Buf'Address, Buf'Length, Out_Len'Access);
   begin
      --  libitb counts the trailing NUL terminator in Out_Len; strip
      --  it before handing back to Ada. A non-OK probe (message wider
      --  than the buffer) degrades to the empty string — the status
      --  label alone still identifies the failure.
      if St /= C_Int (Itb.Status.OK) or else Out_Len <= 1 then
         return "";
      end if;
      return To_Ada (Buf (1 .. Out_Len - 1), Trim_Nul => False);
   end Last_Error;

   ---------------
   -- Raise_For --
   ---------------

   procedure Raise_For (Status : Itb.Status.Code) is
      Img  : constant String :=
        Ada.Strings.Fixed.Trim
          (Itb.Status.Code'Image (Status), Ada.Strings.Left);
      Base : constant String := Itb.Status.Label (Status);
      Diag : constant String := Last_Error;
   begin
      if Diag = "" then
         raise Itb_Error with Img & "|" & Base;
      else
         raise Itb_Error with Img & "|" & Base & ": " & Diag;
      end if;
   end Raise_For;

end Itb.Error;
