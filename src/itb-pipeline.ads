--  Itb.Pipeline — Triple Pipeline session over a libitb handle.
--
--  A Pipeline is Init'ed fresh against a named profile (producing the
--  session-bundle blob for the receiver) or Open'ed from a blob. All
--  cipher entry points relay buffer-in / buffer-out to libitb; the
--  controlled wrapper frees the Go-side handle at Finalize (libitb
--  zeroes key material internally).
--
--  Streaming-decrypt caveat: chunked Streaming AEAD verifies per
--  chunk, so plaintext of verified chunks is released before a later
--  chunk can fail authentication.

with Itb.Opts;

private with Ada.Finalization;

package Itb.Pipeline is

   type Pipeline is tagged limited private;

   --  Constructs a fresh Pipeline against the named profile and
   --  captures the exported session-bundle blob (see Blob below).
   procedure Init
     (P       : in out Pipeline;
      Profile : String;
      Options : Itb.Opts.Opts);

   --  Reconstructs a Pipeline from a blob produced by Init or Rekey,
   --  using the blob-embedded masters.
   procedure Open
     (P       : in out Pipeline;
      Profile : String;
      Blob    : Byte_Array;
      Options : Itb.Opts.Opts);

   --  Open variant overriding the blob-embedded parallax + wrapper
   --  masters. Both override buffers must be non-empty.
   procedure Open
     (P           : in out Pipeline;
      Profile     : String;
      Blob        : Byte_Array;
      Options     : Itb.Opts.Opts;
      Perm_Master : Byte_Array;
      Wrap_Master : Byte_Array);

   --  The exported session-bundle bytes for the receiver side.
   --  Refreshed by Rekey. Empty before Init / Open.
   function Blob (P : Pipeline) return Byte_Array;

   --  Rotates the parallax + wrapper masters and refreshes Blob.
   --  Must not run concurrently with cipher calls or open stream
   --  sessions on the same Pipeline.
   procedure Rekey
     (P           : in out Pipeline;
      Perm_Master : Byte_Array;
      Wrap_Master : Byte_Array);

   --  Zeroes the Pipeline's key material and marks it closed.
   --  Idempotent; subsequent cipher calls raise Itb_Error with
   --  Itb.Status.Triple_Closed.
   procedure Close (P : in out Pipeline);

   --  Single Message encrypt: one call, one self-contained wire.
   function Encrypt_Message
     (P : Pipeline; Plain : Byte_Array) return Byte_Array;

   --  Receive-side counterpart of Encrypt_Message.
   function Decrypt_Message
     (P : Pipeline; Wire : Byte_Array) return Byte_Array;

   --  One-shot stream encrypt for callers holding the whole
   --  plaintext in memory. For bounded-memory streaming use the
   --  incremental sessions in Itb.Stream.
   function Encrypt_Stream_One_Shot
     (P : Pipeline; Plain : Byte_Array) return Byte_Array;

   --  Receive-side counterpart of Encrypt_Stream_One_Shot.
   function Decrypt_Stream_One_Shot
     (P : Pipeline; Wire : Byte_Array) return Byte_Array;

   --  Registers a user-defined Triple profile under Name so
   --  subsequent Init / Open calls resolve it. The opts follow the
   --  register-profile grammar validated by Go. A duplicate name
   --  raises Itb_Error with Itb.Status.Profile_Exists.
   procedure Register_Profile (Name : String; Options : Itb.Opts.Opts);

   --  The raw libitb handle — internal, used by Itb.Stream to open
   --  sessions against this Pipeline.
   function Raw (P : Pipeline) return Handle;

private

   type Pipeline is new Ada.Finalization.Limited_Controlled with record
      H          : Handle := Null_Handle;
      Blob_Bytes : Byte_Array_Access := null;
   end record;

   overriding procedure Finalize (P : in out Pipeline);

end Itb.Pipeline;
