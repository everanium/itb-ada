--  Itb.Errors body — Raise_For implementation + accessor decoders.

with Ada.Strings.Fixed;
with Interfaces.C;

with Itb.Status;
with Itb.Sys;

package body Itb.Errors is

   ---------------------------------------------------------------------
   --  Local helpers
   ---------------------------------------------------------------------

   --  Wraps ITB_LastError into a plain Ada String. Returns the empty
   --  string when libitb has no diagnostic to report or the buffer
   --  size probe ever fails. 512 bytes is wider than any libitb error
   --  message produced by cmd/cshared/internal/capi.
   function Get_Last_Error return String is
      pragma SPARK_Mode (Off);
      use Interfaces.C;
      Buf     : aliased char_array (1 .. 512) := [others => nul];
      Out_Len : aliased size_t := 0;
      St      : int;
      pragma Unreferenced (St);
   begin
      St := Itb.Sys.ITB_LastError
              (Out_Buf => Buf'Address,
               Cap     => Buf'Length,
               Out_Len => Out_Len'Access);
      --  libitb counts the trailing NUL terminator in Out_Len; strip
      --  it before handing back to Ada.
      if Out_Len <= 1 then
         return "";
      end if;
      return To_Ada (Buf (1 .. Out_Len - 1), Trim_Nul => False);
   end Get_Last_Error;

   --  Wraps ITB_Easy_LastMismatchField. Returns the empty string when
   --  no mismatch has been recorded since the most recent
   --  encryptor-config error.
   function Get_Last_Mismatch_Field return String is
      pragma SPARK_Mode (Off);
      use Interfaces.C;
      Buf     : aliased char_array (1 .. 64) := [others => nul];
      Out_Len : aliased size_t := 0;
      St      : int;
      pragma Unreferenced (St);
   begin
      St := Itb.Sys.ITB_Easy_LastMismatchField
              (Out_Buf => Buf'Address,
               Cap     => Buf'Length,
               Out_Len => Out_Len'Access);
      --  libitb counts the trailing NUL terminator in Out_Len; strip
      --  it so callers compare against plain Ada string literals.
      if Out_Len <= 1 then
         return "";
      end if;
      return To_Ada (Buf (1 .. Out_Len - 1), Trim_Nul => False);
   end Get_Last_Mismatch_Field;

   ---------------------------------------------------------------------
   --  Public accessor over ITB_Easy_LastMismatchField. Delegates to the
   --  package-body-private Get_Last_Mismatch_Field helper above.
   ---------------------------------------------------------------------
   function Last_Mismatch_Field return String is
   begin
      return Get_Last_Mismatch_Field;
   end Last_Mismatch_Field;

   --  Pack <status>|<field>|<message> into a single Ada string.
   function Encode_Payload
     (Status_Code : Natural;
      Field       : String;
      Message     : String) return String is
      pragma SPARK_Mode (Off);
   begin
      return Natural'Image (Status_Code) (2 .. Natural'Image (Status_Code)'Last)
             & '|' & Field & '|' & Message;
   end Encode_Payload;

   ---------------------------------------------------------------------
   --  Status_Code accessor
   ---------------------------------------------------------------------

   function Status_Code
     (E : Ada.Exceptions.Exception_Occurrence) return Natural
   is
      --  SPARK_Mode Off: the body catches Constraint_Error from
      --  Natural'Value on a malformed payload. SPARK silver requires
      --  the value be provably overflow-free *before* the call rather
      --  than handling the overflow after; adding such a precondition
      --  would constrain the function's domain to "well-formed payload
      --  only" and break the defensive contract callers rely on.
      --  The defence stays at runtime; the body is opaque to SPARK.
      pragma SPARK_Mode (Off);
      Msg  : constant String := Ada.Exceptions.Exception_Message (E);
      Pipe : Natural;
   begin
      if Msg'Length = 0 then
         return 0;
      end if;
      Pipe := Ada.Strings.Fixed.Index (Msg, "|");
      if Pipe = 0 then
         return 0;
      end if;
      begin
         return Natural'Value (Msg (Msg'First .. Pipe - 1));
      exception
         when Constraint_Error =>
            return 0;
      end;
   end Status_Code;

   ---------------------------------------------------------------------
   --  Field accessor
   ---------------------------------------------------------------------

   function Field
     (E : Ada.Exceptions.Exception_Occurrence) return String
   is
      --  SPARK_Mode Off: GNATprove silver flags `First_Pipe + 1` as a
      --  potential 32-bit overflow when `First_Pipe = Natural'Last`.
      --  The precondition that closes the warning (`Msg'Length <
      --  Natural'Last`) is true for every Exception_Message libitb
      --  produces but adding the contract is out-of-selective-scope.
      pragma SPARK_Mode (Off);
      Msg          : constant String := Ada.Exceptions.Exception_Message (E);
      First_Pipe   : Natural;
      Second_Pipe  : Natural;
   begin
      if Msg'Length = 0 then
         return "";
      end if;
      First_Pipe := Ada.Strings.Fixed.Index (Msg, "|");
      if First_Pipe = 0 then
         return "";
      end if;
      Second_Pipe :=
        Ada.Strings.Fixed.Index (Msg, "|", First_Pipe + 1);
      if Second_Pipe = 0 then
         return "";
      end if;
      return Msg (First_Pipe + 1 .. Second_Pipe - 1);
   end Field;

   ---------------------------------------------------------------------
   --  Message accessor
   ---------------------------------------------------------------------

   function Message
     (E : Ada.Exceptions.Exception_Occurrence) return String
   is
      --  SPARK_Mode Off: same overflow guard as Field, plus a second
      --  one on `Second_Pipe + 1`. Same out-of-scope rationale.
      pragma SPARK_Mode (Off);
      Msg          : constant String := Ada.Exceptions.Exception_Message (E);
      First_Pipe   : Natural;
      Second_Pipe  : Natural;
   begin
      if Msg'Length = 0 then
         return "";
      end if;
      First_Pipe := Ada.Strings.Fixed.Index (Msg, "|");
      if First_Pipe = 0 then
         return Msg;
      end if;
      Second_Pipe :=
        Ada.Strings.Fixed.Index (Msg, "|", First_Pipe + 1);
      if Second_Pipe = 0 then
         return "";
      end if;
      return Msg (Second_Pipe + 1 .. Msg'Last);
   end Message;

   ---------------------------------------------------------------------
   --  Raise_For — pick the right exception, attach the structured
   --  payload, and raise. Never returns.
   ---------------------------------------------------------------------

   procedure Raise_For (Status : Integer) is
      pragma SPARK_Mode (Off);
      Last_Msg : constant String := Get_Last_Error;
      Field    : constant String :=
        (if Status = Itb.Status.Easy_Mismatch
         then Get_Last_Mismatch_Field else "");
      Payload  : constant String :=
        Encode_Payload (Natural (Status), Field, Last_Msg);
   begin
      if Status = Itb.Status.OK then
         --  Caller bug: Raise_For invoked on an OK status. Surface as
         --  Program_Error so the bug is visible during debugging
         --  rather than silently swallowed by a no-op exception.
         raise Program_Error
           with "Itb.Errors.Raise_For called with Status = OK";
      end if;

      case Status is
         when Itb.Status.Easy_Mismatch =>
            Ada.Exceptions.Raise_Exception
              (Itb_Easy_Mismatch_Error'Identity, Payload);

         when Itb.Status.Blob_Mode_Mismatch =>
            Ada.Exceptions.Raise_Exception
              (Itb_Blob_Mode_Mismatch_Error'Identity, Payload);

         when Itb.Status.Blob_Malformed =>
            Ada.Exceptions.Raise_Exception
              (Itb_Blob_Malformed_Error'Identity, Payload);

         when Itb.Status.Blob_Version_Too_New =>
            Ada.Exceptions.Raise_Exception
              (Itb_Blob_Version_Too_New_Error'Identity, Payload);

         when Itb.Status.Stream_Truncated =>
            Ada.Exceptions.Raise_Exception
              (Itb_Stream_Truncated_Error'Identity, Payload);

         when Itb.Status.Stream_After_Final =>
            Ada.Exceptions.Raise_Exception
              (Itb_Stream_After_Final_Error'Identity, Payload);

         when others =>
            Ada.Exceptions.Raise_Exception
              (Itb_Error'Identity, Payload);
      end case;
   end Raise_For;

   ---------------------------------------------------------------------
   --  Public accessor over ITB_LastError. Delegates to the
   --  package-body-private Get_Last_Error helper above.
   ---------------------------------------------------------------------
   function Last_Error return String is
   begin
      return Get_Last_Error;
   end Last_Error;

end Itb.Errors;
