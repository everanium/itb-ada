--  Itb.Error — the exception raised by every binding subprogram on a
--  non-OK libitb status, plus accessors over its structured payload.
--
--  The Exception_Message attached to every raise carries a
--  "<status>|<text>" payload, e.g.
--
--      "4|invalid input: unknown profile "no-such-profile""
--      "25|Triple Pipeline is closed"
--
--  decoded by the Status_Code and Message accessors below. The text
--  half combines the status label with the ITB_LastError diagnostic
--  captured immediately after the failing call.

with Ada.Exceptions;

with Itb.Status;

package Itb.Error is

   --  Raised by every Itb.* subprogram on a non-OK libitb status.
   Itb_Error : exception;

   --  Numeric status code encoded in the occurrence's payload.
   --  Returns Itb.Status.Internal_Error when the payload is not in
   --  the canonical "<status>|<text>" form (e.g. a re-raise with a
   --  free-form message).
   function Status_Code
     (E : Ada.Exceptions.Exception_Occurrence) return Itb.Status.Code;

   --  Diagnostic text encoded in the occurrence's payload. Returns
   --  the raw Exception_Message when the payload is non-canonical.
   function Message
     (E : Ada.Exceptions.Exception_Occurrence) return String;

   --  Reads the ITB_LastError diagnostic for the most recent non-OK
   --  status. Process-global last-write-wins: under concurrent FFI
   --  use the text may belong to a different call; the status code on
   --  the failing call is always attributable. Returns the empty
   --  string when no diagnostic is recorded.
   function Last_Error return String;

   --  Raises Itb_Error carrying the structured payload for Status.
   --  Used by every binding call site that observes a non-OK return.
   procedure Raise_For (Status : Itb.Status.Code)
   with No_Return;

end Itb.Error;
