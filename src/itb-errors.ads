--  Itb.Errors — exception types raised by every Itb.* safe wrapper on
--  a non-OK libitb status, plus the Raise_For helper that maps a
--  numeric status code to the right exception with the right
--  structured payload attached.
--
--  The 5-exception layout lets callers catch the structurally-distinct
--  failure modes selectively while still falling through to the base
--  exception for generic handling:
--    base                   ← Itb_Error
--    EasyMismatch (.field)  ← Itb_Easy_Mismatch_Error
--    BlobModeMismatch       ← Itb_Blob_Mode_Mismatch_Error
--    BlobMalformed          ← Itb_Blob_Malformed_Error
--    BlobVersionTooNew      ← Itb_Blob_Version_Too_New_Error
--  The Status_Code accessor below preserves the "match by code" idiom
--  alongside the type-based exception hierarchy.
--
--  Structured payload format. The Exception_Message attached to every
--  raise carries three pipe-separated fields, e.g.
--      "12||malformed Easy Mode state blob"
--      "17|primitive|expected blake3, got chacha20"
--      "0||generic libitb error"
--  decoded by the Status_Code, Field, and Message accessor functions
--  in this package.

with Ada.Exceptions;

package Itb.Errors is
   pragma Preelaborate;
   pragma SPARK_Mode (Off);

   --  Base exception raised by every Itb.* subprogram on a non-OK
   --  status that does not have a more specific typed exception below.
   Itb_Error                      : exception;

   --  Easy Mode encryptor: persisted-config field disagrees with the
   --  receiving encryptor (peek / import / chunk-len boundary). The
   --  mismatched field name is attached via the structured payload
   --  and accessible through Field.
   Itb_Easy_Mismatch_Error        : exception;

   --  Native Blob: persisted mode (Single / Triple) or width does not
   --  match the receiving Blob.
   Itb_Blob_Mode_Mismatch_Error   : exception;

   --  Native Blob: payload fails internal sanity checks (magic / CRC
   --  / structural).
   Itb_Blob_Malformed_Error       : exception;

   --  Native Blob: persisted format version is newer than this build
   --  of libitb knows how to parse.
   Itb_Blob_Version_Too_New_Error : exception;

   --  Streaming AEAD: input exhausted without observing a chunk whose
   --  recovered final_flag is set. Surfaced by the auth-stream decrypt
   --  loop on truncate-tail.
   Itb_Stream_Truncated_Error     : exception;

   --  Streaming AEAD: extra chunk bytes followed the terminating
   --  chunk. Surfaced by the auth-stream decrypt loop when a
   --  transcript carries data past the terminator.
   Itb_Stream_After_Final_Error   : exception;

   --  Accessors over the structured Exception_Message format. Return
   --  zero / empty when the payload is malformed (e.g. an Itb_Error
   --  re-raised with a non-canonical message).

   function Status_Code
     (E : Ada.Exceptions.Exception_Occurrence) return Natural;

   function Field
     (E : Ada.Exceptions.Exception_Occurrence) return String;

   function Message
     (E : Ada.Exceptions.Exception_Occurrence) return String;

   --  Reads the offending JSON field name from the most recent
   --  ITB_Easy_Import call that returned STATUS_EASY_MISMATCH on this
   --  thread. Returns the empty string when the most recent failure was
   --  not a mismatch. Itb.Encryptor.Import already attaches this name
   --  to the Field accessor on the raised Itb_Easy_Mismatch_Error
   --  occurrence; this free function is exposed for callers that need
   --  to read the field independently of the error path.
   function Last_Mismatch_Field return String;

   --  Reads ITB_LastError for the most recent non-OK status returned
   --  on this thread. Returns the empty string when no error has been
   --  recorded. The textual message follows C errno discipline: it is
   --  published through a process-wide atomic, so a sibling thread
   --  that calls into libitb between the failing call and this read
   --  can overwrite the message. The structural status code on the
   --  failing call is unaffected — only the textual message is racy.
   --  Itb.Errors.Raise_For already attaches this string to the raised
   --  exception's Message accessor at construction time; this free
   --  function is exposed for callers that want to read the
   --  diagnostic independently of the exception path.
   function Last_Error return String;

   --  Internal helper used by every safe wrapper: takes the libitb
   --  status code, looks up the corresponding diagnostic message via
   --  ITB_LastError and (for Easy_Mismatch) ITB_Easy_LastMismatchField,
   --  picks the right typed exception, and raises with the structured
   --  payload assembled. Never returns when Status /= 0; raises
   --  Program_Error when called with Status = 0 (defensive guard).
   procedure Raise_For (Status : Integer)
   with No_Return,
        SPARK_Mode => Off;

end Itb.Errors;
