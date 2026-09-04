--  Itb.Pipeline — Triple Pipeline session over a libitb handle.
--
--  A Pipeline is Init'ed fresh against a named profile or Load'ed
--  from a session-bundle blob produced by Save / Rekey. All cipher
--  entry points relay buffer-in / buffer-out to libitb; the
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

   --  Constructs a fresh Pipeline against the named profile. The
   --  session-bundle blob for the receiver is available through Save.
   procedure Init
     (P       : in out Pipeline;
      Profile : String;
      Options : Itb.Opts.Opts);

   --  Reconstructs a Pipeline from a blob produced by Save or Rekey,
   --  using the blob-embedded masters. The profile shape travels
   --  inside the blob — no profile name, no options. A blob whose
   --  record names a primitive absent from the local build raises
   --  Itb_Error with Itb.Status.Recipe_Primitive_Unknown; a record
   --  failing the profile field rules with
   --  Itb.Status.Blob_Malformed_Recipe.
   procedure Load
     (P    : in out Pipeline;
      Blob : Byte_Array);

   --  Load variant overriding the blob-embedded parallax + wrapper
   --  masters (the pair is validated by libitb).
   procedure Load
     (P           : in out Pipeline;
      Blob        : Byte_Array;
      Perm_Master : Byte_Array;
      Wrap_Master : Byte_Array);

   --  Load for a blob stored at Path; the file is read inside libitb
   --  (a missing or unreadable file raises Itb_Error with
   --  Itb.Status.Bad_Input and the diagnostic attached).
   procedure Load_F
     (P    : in out Pipeline;
      Path : String);

   --  Load_F variant overriding the blob-embedded masters.
   procedure Load_F
     (P           : in out Pipeline;
      Path        : String;
      Perm_Master : Byte_Array;
      Wrap_Master : Byte_Array);

   --  The current session-bundle bytes for the receiver side (the
   --  Init blob, or the bytes of the latest Rekey). A closed Pipeline
   --  raises Itb_Error with Itb.Status.Triple_Closed.
   function Save (P : Pipeline) return Byte_Array;

   --  Writes the current blob to Path inside libitb (mode 0600; the
   --  containing directory must exist).
   procedure Save_F (P : Pipeline; Path : String);

   --  Sets the worker cap for every subsequent cipher call. N is
   --  clamped by libitb (<= 0 selects auto, > 256 becomes 256); only
   --  the handle state is reported. The cap is per-machine and never
   --  travels in the blob.
   procedure Max_Workers (P : Pipeline; N : Integer);

   --  Rotates the parallax + wrapper masters; the fresh blob is
   --  available through Save. Must not run concurrently with cipher
   --  calls or open stream sessions on the same Pipeline.
   procedure Rekey
     (P           : in out Pipeline;
      Perm_Master : Byte_Array;
      Wrap_Master : Byte_Array);

   --  Rekey variant returning the fresh blob bytes.
   function Rekey
     (P           : in out Pipeline;
      Perm_Master : Byte_Array;
      Wrap_Master : Byte_Array) return Byte_Array;

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

   --  Profile records. A profile record is the JSON object libitb
   --  accepts in Register, returns from Lookup / Inspect, and embeds
   --  in every blob: keys name / mode / width / hash / hashes /
   --  keybits / mac / tagstub / chunk / wrapper / outer / parallax /
   --  palette / segment. Optional keys are omitted when empty / zero.
   --  The binding treats the record as an opaque String; every field
   --  rule is enforced by libitb.

   --  Decodes the profile record embedded in Blob without
   --  constructing a Pipeline. No registry read, no primitive probe.
   function Inspect (Blob : Byte_Array) return String;

   --  Registers a user-defined Triple profile under Name from a
   --  profile JSON record (a non-empty "name" key inside the record
   --  must equal Name) so subsequent Init calls resolve it. A
   --  duplicate name raises Itb_Error with Itb.Status.Profile_Exists.
   procedure Register (Name : String; Profile_JSON : String);

   --  The profile registered under Name — a shipped catalogue entry
   --  or a prior Register — as its JSON record. An unregistered name
   --  raises Itb_Error with Itb.Status.Unknown_Profile.
   function Lookup (Name : String) return String;

   --  The sorted list of every registered profile name as a JSON
   --  array of strings.
   function Profiles return String;

   --  The raw libitb handle — internal, used by Itb.Stream to open
   --  sessions against this Pipeline.
   function Raw (P : Pipeline) return Handle;

private

   type Pipeline is new Ada.Finalization.Limited_Controlled with record
      H : Handle := Null_Handle;
   end record;

   overriding procedure Finalize (P : in out Pipeline);

end Itb.Pipeline;
