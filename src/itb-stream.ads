--  Itb.Stream — incremental stream sessions over an open Pipeline.
--
--  A session is a dumb byte pump: an Encrypt_Stream takes plaintext
--  in through Write and yields wire through Read; a Decrypt_Stream
--  is the mirror (wire in, plaintext out). All chunking, MAC,
--  envelope, and wire-format decisions stay inside libitb. Finalize
--  cancels the session and frees the Go-side state. A session must
--  not outlive the Pipeline it was begun on.

with Itb.Pipeline;

private with Ada.Finalization;

package Itb.Stream is

   type Encrypt_Stream is tagged limited private;
   type Decrypt_Stream is tagged limited private;

   --  Opens an incremental session against P. Only Streaming
   --  profiles are accepted — a Single Message profile makes the
   --  session error out on the first Write.
   procedure Begin_Encrypt
     (S : in out Encrypt_Stream; P : Itb.Pipeline.Pipeline);
   procedure Begin_Decrypt
     (S : in out Decrypt_Stream; P : Itb.Pipeline.Pipeline);

   --  Feeds Src into the session. Blocks until the cipher chain
   --  accepts the bytes; errors are sticky.
   procedure Write (S : in out Encrypt_Stream; Src : Byte_Array);
   procedure Write (S : in out Decrypt_Stream; Src : Byte_Array);

   --  Signals end-of-input. Idempotent; Write after Finish raises
   --  Itb_Error with Itb.Status.Bad_Input.
   procedure Finish (S : in out Encrypt_Stream);
   procedure Finish (S : in out Decrypt_Stream);

   --  Drains up to Dst'Length produced bytes into Dst. Last receives
   --  the index of the last written element (Dst'First - 1 when
   --  nothing was available); Finished becomes True once the session
   --  has ended and its output is fully drained. Partial drains are
   --  normal. After Finish, an empty-spool Read blocks until the
   --  terminal bytes arrive or the session errors.
   procedure Read
     (S        : in out Encrypt_Stream;
      Dst      : in out Byte_Array;
      Last     : out Ada.Streams.Stream_Element_Offset;
      Finished : out Boolean);
   procedure Read
     (S        : in out Decrypt_Stream;
      Dst      : in out Byte_Array;
      Last     : out Ada.Streams.Stream_Element_Offset;
      Finished : out Boolean);

private

   type Session is new Ada.Finalization.Limited_Controlled with record
      H : Handle := Null_Handle;
   end record;

   overriding procedure Finalize (S : in out Session);

   type Encrypt_Stream is new Session with null record;
   type Decrypt_Stream is new Session with null record;

end Itb.Stream;
