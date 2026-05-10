--  Itb.Streams — file-like streaming wrappers over the Single Message
--  Itb.Cipher Encrypt / Decrypt entry points.
--
--  ITB ciphertexts cap at ~64 MB plaintext per chunk (the underlying
--  container size limit). Streaming larger payloads slices the input
--  into chunks at the binding layer, encrypts each chunk through the
--  Itb.Cipher path, and concatenates the results. The reverse
--  operation walks a concatenated chunk stream by reading the chunk
--  header, calling Itb.Parse_Chunk_Len to learn the chunk's body
--  length, reading that many bytes, and decrypting the single chunk.
--
--  Ada idiom note. The wrappers do NOT derive from
--  Ada.Streams.Root_Stream_Type — that would overload the standard
--  Stream_IO Read / Write semantics ambiguously with the ITB
--  encrypt / decrypt pipeline. Instead they accept a caller-owned
--  Ada.Streams.Root_Stream_Type'Class access (the underlying writable
--  / readable byte sink / source) at construction and expose explicit
--  Write_Plaintext / Read_Plaintext primitives that flow plaintext
--  through the (encrypt → underlying stream) or (underlying stream →
--  decrypt) pipeline.
--
--  Both struct-based wrappers (Stream_Encryptor / Stream_Decryptor and
--  their Triple counterparts) and free-subprogram convenience drivers
--  (Encrypt_Stream / Decrypt_Stream / Triple variants) are provided.
--  Memory peak is bounded by Chunk_Size (default 16 MB) regardless of
--  the total payload length.
--
--  The Triple Ouroboros (7-seed) variants share the same I/O contract
--  and only differ in the seed list passed to the constructor.
--
--  Warning. Do not call Itb.Set_Nonce_Bits between writes on the same
--  stream. Each chunk is encrypted under the active nonce-size at the
--  moment it is flushed; switching nonce-bits mid-stream produces a
--  chunk header layout the paired decryptor (which snapshots
--  Itb.Header_Size at construction) cannot parse.
--
--  Seed lifetime contract. Every Seed passed to Make / Make_Triple
--  (and to the convenience drivers Encrypt_Stream / Decrypt_Stream /
--  the Triple variants) MUST remain in scope, un-finalized, for the
--  whole lifetime of the resulting stream wrapper. The wrappers
--  cache the raw libitb handles internally; finalising the originating
--  Seed before the stream finishes its work would free the handle
--  while the stream is still using it (a stochastic use-after-free).
--  Rust enforces the parallel constraint via &'a Seed lifetime
--  borrows; Ada relies on caller discipline. The same caller-owns
--  rule already applies to Itb.Seed.Attach_Lock_Seed for the
--  dedicated lockSeed channel.

private with Ada.Finalization;
private with Itb.Sys;

with Ada.Streams;
with Itb.MAC;
with Itb.Seed;

package Itb.Streams is
   pragma Preelaborate;

   --  Default chunk size — matches itb.DefaultChunkSize on the Go side
   --  (16 MB), the size at which ITB's barrier-encoded container layout
   --  stays well within the per-chunk pixel cap.
   Default_Chunk_Size : constant Ada.Streams.Stream_Element_Offset :=
     Ada.Streams.Stream_Element_Offset (16 * 1024 * 1024);

   ---------------------------------------------------------------------
   --  Single Ouroboros — chunked writer.
   ---------------------------------------------------------------------

   --  Buffers plaintext until at least Chunk_Size bytes are available,
   --  then encrypts and emits one chunk to the underlying Sink. The
   --  trailing partial buffer is flushed as a final chunk on Finish
   --  (so the on-the-wire chunk count is ceil(total / Chunk_Size)).
   type Stream_Encryptor is tagged limited private;

   --  Constructs a fresh stream encryptor wrapping the given Sink.
   --  Chunk_Size must be positive; the default matches the Go-side
   --  itb.DefaultChunkSize.
   function Make
     (Noise      : Itb.Seed.Seed;
      Data       : Itb.Seed.Seed;
      Start      : Itb.Seed.Seed;
      Sink       : not null access Ada.Streams.Root_Stream_Type'Class;
      Chunk_Size : Ada.Streams.Stream_Element_Offset :=
                     Default_Chunk_Size) return Stream_Encryptor;

   --  Appends Data to the internal buffer, encrypting and emitting
   --  every full Chunk_Size-sized slice that becomes available.
   procedure Write_Plaintext
     (Self : in out Stream_Encryptor;
      Data : Byte_Array);

   --  Encrypts and emits any remaining buffered bytes as the final
   --  chunk. Idempotent — a second call is a no-op.
   procedure Finish (Self : in out Stream_Encryptor);

   ---------------------------------------------------------------------
   --  Single Ouroboros — chunked reader.
   ---------------------------------------------------------------------

   --  Pulls ciphertext bytes from the underlying Source on demand, one
   --  full chunk at a time, decrypts it, and refills the caller's
   --  Buffer with the recovered plaintext. Returns Buffer'First - 1 in
   --  Last on EOF.
   type Stream_Decryptor is tagged limited private;

   --  Constructs a fresh stream decryptor wrapping the given Source.
   --  The chunk-header size is snapshotted at construction so the
   --  decryptor uses the same header layout the matching encryptor
   --  saw — changing Itb.Set_Nonce_Bits mid-stream would break decoding
   --  anyway.
   function Make
     (Noise  : Itb.Seed.Seed;
      Data   : Itb.Seed.Seed;
      Start  : Itb.Seed.Seed;
      Source : not null access Ada.Streams.Root_Stream_Type'Class)
      return Stream_Decryptor;

   --  Reads enough ciphertext from Source to decrypt at least one
   --  chunk, then copies recovered plaintext into Buffer. Last is set
   --  to the index of the last byte filled (Buffer'First - 1 if EOF
   --  was reached before any plaintext could be produced). Returns
   --  fewer than Buffer'Length bytes when a chunk boundary or EOF is
   --  hit; callers that need exactly Buffer'Length bytes loop until
   --  Last < Buffer'Last or EOF.
   procedure Read_Plaintext
     (Self   : in out Stream_Decryptor;
      Buffer : out Byte_Array;
      Last   : out Ada.Streams.Stream_Element_Offset);

   --  Finalises the decryptor. Raises Itb_Error / Bad_Input when
   --  leftover bytes do not form a complete chunk — streaming ITB
   --  ciphertext cannot have a half-chunk tail.
   procedure Finish (Self : in out Stream_Decryptor);

   ---------------------------------------------------------------------
   --  Triple Ouroboros — chunked writer.
   ---------------------------------------------------------------------

   --  Triple-Ouroboros (7-seed) counterpart of Stream_Encryptor.
   type Stream_Encryptor_Triple is tagged limited private;

   function Make_Triple
     (Noise      : Itb.Seed.Seed;
      Data1      : Itb.Seed.Seed;
      Data2      : Itb.Seed.Seed;
      Data3      : Itb.Seed.Seed;
      Start1     : Itb.Seed.Seed;
      Start2     : Itb.Seed.Seed;
      Start3     : Itb.Seed.Seed;
      Sink       : not null access Ada.Streams.Root_Stream_Type'Class;
      Chunk_Size : Ada.Streams.Stream_Element_Offset :=
                     Default_Chunk_Size)
      return Stream_Encryptor_Triple;

   procedure Write_Plaintext
     (Self : in out Stream_Encryptor_Triple;
      Data : Byte_Array);

   procedure Finish (Self : in out Stream_Encryptor_Triple);

   ---------------------------------------------------------------------
   --  Triple Ouroboros — chunked reader.
   ---------------------------------------------------------------------

   --  Triple-Ouroboros (7-seed) counterpart of Stream_Decryptor.
   type Stream_Decryptor_Triple is tagged limited private;

   function Make_Triple
     (Noise  : Itb.Seed.Seed;
      Data1  : Itb.Seed.Seed;
      Data2  : Itb.Seed.Seed;
      Data3  : Itb.Seed.Seed;
      Start1 : Itb.Seed.Seed;
      Start2 : Itb.Seed.Seed;
      Start3 : Itb.Seed.Seed;
      Source : not null access Ada.Streams.Root_Stream_Type'Class)
      return Stream_Decryptor_Triple;

   procedure Read_Plaintext
     (Self   : in out Stream_Decryptor_Triple;
      Buffer : out Byte_Array;
      Last   : out Ada.Streams.Stream_Element_Offset);

   procedure Finish (Self : in out Stream_Decryptor_Triple);

   ---------------------------------------------------------------------
   --  Free-subprogram convenience drivers — read entire Source until
   --  EOF, encrypt / decrypt in chunks, and write to Sink.
   ---------------------------------------------------------------------

   procedure Encrypt_Stream
     (Noise      : Itb.Seed.Seed;
      Data       : Itb.Seed.Seed;
      Start      : Itb.Seed.Seed;
      Source     : not null access Ada.Streams.Root_Stream_Type'Class;
      Sink       : not null access Ada.Streams.Root_Stream_Type'Class;
      Chunk_Size : Ada.Streams.Stream_Element_Offset :=
                     Default_Chunk_Size);

   procedure Decrypt_Stream
     (Noise     : Itb.Seed.Seed;
      Data      : Itb.Seed.Seed;
      Start     : Itb.Seed.Seed;
      Source    : not null access Ada.Streams.Root_Stream_Type'Class;
      Sink      : not null access Ada.Streams.Root_Stream_Type'Class;
      Read_Size : Ada.Streams.Stream_Element_Offset :=
                    Default_Chunk_Size);

   procedure Encrypt_Stream_Triple
     (Noise      : Itb.Seed.Seed;
      Data1      : Itb.Seed.Seed;
      Data2      : Itb.Seed.Seed;
      Data3      : Itb.Seed.Seed;
      Start1     : Itb.Seed.Seed;
      Start2     : Itb.Seed.Seed;
      Start3     : Itb.Seed.Seed;
      Source     : not null access Ada.Streams.Root_Stream_Type'Class;
      Sink       : not null access Ada.Streams.Root_Stream_Type'Class;
      Chunk_Size : Ada.Streams.Stream_Element_Offset :=
                     Default_Chunk_Size);

   procedure Decrypt_Stream_Triple
     (Noise     : Itb.Seed.Seed;
      Data1     : Itb.Seed.Seed;
      Data2     : Itb.Seed.Seed;
      Data3     : Itb.Seed.Seed;
      Start1    : Itb.Seed.Seed;
      Start2    : Itb.Seed.Seed;
      Start3    : Itb.Seed.Seed;
      Source    : not null access Ada.Streams.Root_Stream_Type'Class;
      Sink      : not null access Ada.Streams.Root_Stream_Type'Class;
      Read_Size : Ada.Streams.Stream_Element_Offset :=
                    Default_Chunk_Size);

   ---------------------------------------------------------------------
   --  Streaming AEAD: 32-byte stream prefix + per-chunk MAC under
   --  (stream_id, cumulative_pixel_offset, final_flag) binding.
   ---------------------------------------------------------------------
   --
   --  The Streaming AEAD wrappers extend the plain streaming surface
   --  with an authentication binding tuple that closes chunk reorder,
   --  replay within stream, cross-stream replay, truncate-tail, and
   --  after-final attack vectors. On wire: a 32-byte CSPRNG stream_id
   --  prefix is written once at stream start, followed by a sequence
   --  of standard ITB chunks. The final_flag byte is appended to the
   --  encrypted body inside the container (deniable layout, not
   --  externally visible). The cumulative_pixel_offset is recomputed
   --  by both sides from each chunk's on-wire W * H header, so it
   --  never appears as a wire field. Tampered transcript surfaces as
   --  Itb_Error / MAC_Failure on the affected chunk; missing
   --  terminator surfaces as Itb_Stream_Truncated_Error; trailing
   --  bytes after the terminator surface as
   --  Itb_Stream_After_Final_Error.

   ---------------------------------------------------------------------
   --  Single Ouroboros + MAC — chunked writer.
   ---------------------------------------------------------------------

   --  Authenticated chunked encrypt writer (Single Ouroboros + MAC).
   --  Buffers plaintext until at least Chunk_Size bytes are
   --  available, then drains one full chunk per FFI call. Each chunk
   --  is bound to the running (stream_id, cumulative_pixel_offset,
   --  final_flag) tuple inside the MAC closure. The 32-byte
   --  stream_id prefix is generated by Make_Auth and emitted to the
   --  Sink on the first Write_Plaintext / Finish call.
   --
   --  Closed-state preflight is enforced: any Write_Plaintext /
   --  Finish after Finish (or after Finalize) raises
   --  Itb_Error / Easy_Closed.
   type Stream_Encryptor_Auth is tagged limited private;

   function Make_Auth
     (Noise      : Itb.Seed.Seed;
      Data       : Itb.Seed.Seed;
      Start      : Itb.Seed.Seed;
      Mac        : Itb.MAC.MAC;
      Sink       : not null access Ada.Streams.Root_Stream_Type'Class;
      Chunk_Size : Ada.Streams.Stream_Element_Offset :=
                     Default_Chunk_Size) return Stream_Encryptor_Auth;

   procedure Write_Plaintext
     (Self : in out Stream_Encryptor_Auth;
      Data : Byte_Array);

   procedure Finish (Self : in out Stream_Encryptor_Auth);

   ---------------------------------------------------------------------
   --  Single Ouroboros + MAC — chunked reader.
   ---------------------------------------------------------------------

   --  Authenticated chunked decrypt reader (Single Ouroboros + MAC).
   --  Reads the 32-byte stream_id prefix once, then drains every
   --  complete chunk available in the internal buffer. Each chunk is
   --  verified under the running cumulative pixel offset and
   --  recovered final_flag; missing terminator surfaces as
   --  Itb_Stream_Truncated_Error from Finish, trailing bytes after
   --  the terminator surface as Itb_Stream_After_Final_Error on the
   --  next Read_Plaintext / Finish call.
   type Stream_Decryptor_Auth is tagged limited private;

   function Make_Auth
     (Noise  : Itb.Seed.Seed;
      Data   : Itb.Seed.Seed;
      Start  : Itb.Seed.Seed;
      Mac    : Itb.MAC.MAC;
      Source : not null access Ada.Streams.Root_Stream_Type'Class)
      return Stream_Decryptor_Auth;

   procedure Read_Plaintext
     (Self   : in out Stream_Decryptor_Auth;
      Buffer : out Byte_Array;
      Last   : out Ada.Streams.Stream_Element_Offset);

   procedure Finish (Self : in out Stream_Decryptor_Auth);

   ---------------------------------------------------------------------
   --  Triple Ouroboros + MAC — chunked writer.
   ---------------------------------------------------------------------

   --  Triple-Ouroboros (7-seed) authenticated counterpart of
   --  Stream_Encryptor_Auth.
   type Stream_Encryptor_Auth_3 is tagged limited private;

   function Make_Auth_Triple
     (Noise      : Itb.Seed.Seed;
      Data1      : Itb.Seed.Seed;
      Data2      : Itb.Seed.Seed;
      Data3      : Itb.Seed.Seed;
      Start1     : Itb.Seed.Seed;
      Start2     : Itb.Seed.Seed;
      Start3     : Itb.Seed.Seed;
      Mac        : Itb.MAC.MAC;
      Sink       : not null access Ada.Streams.Root_Stream_Type'Class;
      Chunk_Size : Ada.Streams.Stream_Element_Offset :=
                     Default_Chunk_Size) return Stream_Encryptor_Auth_3;

   procedure Write_Plaintext
     (Self : in out Stream_Encryptor_Auth_3;
      Data : Byte_Array);

   procedure Finish (Self : in out Stream_Encryptor_Auth_3);

   ---------------------------------------------------------------------
   --  Triple Ouroboros + MAC — chunked reader.
   ---------------------------------------------------------------------

   --  Triple-Ouroboros (7-seed) authenticated counterpart of
   --  Stream_Decryptor_Auth.
   type Stream_Decryptor_Auth_3 is tagged limited private;

   function Make_Auth_Triple
     (Noise  : Itb.Seed.Seed;
      Data1  : Itb.Seed.Seed;
      Data2  : Itb.Seed.Seed;
      Data3  : Itb.Seed.Seed;
      Start1 : Itb.Seed.Seed;
      Start2 : Itb.Seed.Seed;
      Start3 : Itb.Seed.Seed;
      Mac    : Itb.MAC.MAC;
      Source : not null access Ada.Streams.Root_Stream_Type'Class)
      return Stream_Decryptor_Auth_3;

   procedure Read_Plaintext
     (Self   : in out Stream_Decryptor_Auth_3;
      Buffer : out Byte_Array;
      Last   : out Ada.Streams.Stream_Element_Offset);

   procedure Finish (Self : in out Stream_Decryptor_Auth_3);

   ---------------------------------------------------------------------
   --  Free-subprogram convenience drivers (authenticated).
   ---------------------------------------------------------------------

   procedure Encrypt_Stream_Auth
     (Noise      : Itb.Seed.Seed;
      Data       : Itb.Seed.Seed;
      Start      : Itb.Seed.Seed;
      Mac        : Itb.MAC.MAC;
      Source     : not null access Ada.Streams.Root_Stream_Type'Class;
      Sink       : not null access Ada.Streams.Root_Stream_Type'Class;
      Chunk_Size : Ada.Streams.Stream_Element_Offset :=
                     Default_Chunk_Size);

   procedure Decrypt_Stream_Auth
     (Noise     : Itb.Seed.Seed;
      Data      : Itb.Seed.Seed;
      Start     : Itb.Seed.Seed;
      Mac       : Itb.MAC.MAC;
      Source    : not null access Ada.Streams.Root_Stream_Type'Class;
      Sink      : not null access Ada.Streams.Root_Stream_Type'Class;
      Read_Size : Ada.Streams.Stream_Element_Offset :=
                    Default_Chunk_Size);

   procedure Encrypt_Stream_Auth_Triple
     (Noise      : Itb.Seed.Seed;
      Data1      : Itb.Seed.Seed;
      Data2      : Itb.Seed.Seed;
      Data3      : Itb.Seed.Seed;
      Start1     : Itb.Seed.Seed;
      Start2     : Itb.Seed.Seed;
      Start3     : Itb.Seed.Seed;
      Mac        : Itb.MAC.MAC;
      Source     : not null access Ada.Streams.Root_Stream_Type'Class;
      Sink       : not null access Ada.Streams.Root_Stream_Type'Class;
      Chunk_Size : Ada.Streams.Stream_Element_Offset :=
                     Default_Chunk_Size);

   procedure Decrypt_Stream_Auth_Triple
     (Noise     : Itb.Seed.Seed;
      Data1     : Itb.Seed.Seed;
      Data2     : Itb.Seed.Seed;
      Data3     : Itb.Seed.Seed;
      Start1    : Itb.Seed.Seed;
      Start2    : Itb.Seed.Seed;
      Start3    : Itb.Seed.Seed;
      Mac       : Itb.MAC.MAC;
      Source    : not null access Ada.Streams.Root_Stream_Type'Class;
      Sink      : not null access Ada.Streams.Root_Stream_Type'Class;
      Read_Size : Ada.Streams.Stream_Element_Offset :=
                    Default_Chunk_Size);

private

   --  Indefinite holder for the per-instance chunk / buffer queue.
   --  Pre-sized to Chunk_Size on construction; trimmed in place as
   --  chunks drain. Stored as Byte_Array on the heap because the
   --  buffer length grows / shrinks at runtime independently of the
   --  controlled type's discriminant constraints.
   type Byte_Buffer_Access is access Byte_Array;

   --  Common Single-Ouroboros encryptor state.
   type Stream_Encryptor is new Ada.Finalization.Limited_Controlled with
      record
         Noise_H    : Itb.Sys.Handle := 0;
         Data_H     : Itb.Sys.Handle := 0;
         Start_H    : Itb.Sys.Handle := 0;
         Sink       : access Ada.Streams.Root_Stream_Type'Class := null;
         Chunk_Size : Ada.Streams.Stream_Element_Offset := 0;
         Buf        : Byte_Buffer_Access := null;
         Buf_Used   : Ada.Streams.Stream_Element_Offset := 0;
         Closed     : Boolean := False;
      end record;

   overriding procedure Finalize (Self : in out Stream_Encryptor);

   type Stream_Decryptor is new Ada.Finalization.Limited_Controlled with
      record
         Noise_H     : Itb.Sys.Handle := 0;
         Data_H      : Itb.Sys.Handle := 0;
         Start_H     : Itb.Sys.Handle := 0;
         Source      : access Ada.Streams.Root_Stream_Type'Class := null;
         Buf         : Byte_Buffer_Access := null;
         Buf_Used    : Ada.Streams.Stream_Element_Offset := 0;
         Plain       : Byte_Buffer_Access := null;
         Plain_Pos   : Ada.Streams.Stream_Element_Offset := 0;
         Plain_Last  : Ada.Streams.Stream_Element_Offset := 0;
         Header_Size : Ada.Streams.Stream_Element_Offset := 0;
         At_EOF      : Boolean := False;
         Closed      : Boolean := False;
      end record;

   overriding procedure Finalize (Self : in out Stream_Decryptor);

   type Stream_Encryptor_Triple is new
     Ada.Finalization.Limited_Controlled with
      record
         Noise_H    : Itb.Sys.Handle := 0;
         Data1_H    : Itb.Sys.Handle := 0;
         Data2_H    : Itb.Sys.Handle := 0;
         Data3_H    : Itb.Sys.Handle := 0;
         Start1_H   : Itb.Sys.Handle := 0;
         Start2_H   : Itb.Sys.Handle := 0;
         Start3_H   : Itb.Sys.Handle := 0;
         Sink       : access Ada.Streams.Root_Stream_Type'Class := null;
         Chunk_Size : Ada.Streams.Stream_Element_Offset := 0;
         Buf        : Byte_Buffer_Access := null;
         Buf_Used   : Ada.Streams.Stream_Element_Offset := 0;
         Closed     : Boolean := False;
      end record;

   overriding procedure Finalize (Self : in out Stream_Encryptor_Triple);

   type Stream_Decryptor_Triple is new
     Ada.Finalization.Limited_Controlled with
      record
         Noise_H     : Itb.Sys.Handle := 0;
         Data1_H     : Itb.Sys.Handle := 0;
         Data2_H     : Itb.Sys.Handle := 0;
         Data3_H     : Itb.Sys.Handle := 0;
         Start1_H    : Itb.Sys.Handle := 0;
         Start2_H    : Itb.Sys.Handle := 0;
         Start3_H    : Itb.Sys.Handle := 0;
         Source      : access Ada.Streams.Root_Stream_Type'Class := null;
         Buf         : Byte_Buffer_Access := null;
         Buf_Used    : Ada.Streams.Stream_Element_Offset := 0;
         Plain       : Byte_Buffer_Access := null;
         Plain_Pos   : Ada.Streams.Stream_Element_Offset := 0;
         Plain_Last  : Ada.Streams.Stream_Element_Offset := 0;
         Header_Size : Ada.Streams.Stream_Element_Offset := 0;
         At_EOF      : Boolean := False;
         Closed      : Boolean := False;
      end record;

   overriding procedure Finalize (Self : in out Stream_Decryptor_Triple);

   ---------------------------------------------------------------------
   --  Streaming AEAD private record types.
   ---------------------------------------------------------------------

   subtype Stream_ID_Bytes is Byte_Array (1 .. 32);

   type Stream_Encryptor_Auth is new
     Ada.Finalization.Limited_Controlled with
      record
         Noise_H        : Itb.Sys.Handle := 0;
         Data_H         : Itb.Sys.Handle := 0;
         Start_H        : Itb.Sys.Handle := 0;
         MAC_H          : Itb.Sys.Handle := 0;
         Width          : Integer := 0;
         Header_Size    : Ada.Streams.Stream_Element_Offset := 0;
         Sink           : access Ada.Streams.Root_Stream_Type'Class :=
                            null;
         Chunk_Size     : Ada.Streams.Stream_Element_Offset := 0;
         Buf            : Byte_Buffer_Access := null;
         Buf_Used       : Ada.Streams.Stream_Element_Offset := 0;
         Stream_ID      : Stream_ID_Bytes := [others => 0];
         Cum_Pixels     : Itb.Sys.U64 := 0;
         Prefix_Emitted : Boolean := False;
         Closed         : Boolean := False;
         --  Per-stream output buffer cache. Reused across every chunk's
         --  FFI dispatch instead of a fresh heap allocation per chunk.
         --  Wiped on grow + on Finalize, mirroring Encryptor.Cache.
         Cache          : Byte_Buffer_Access := null;
      end record;

   overriding procedure Finalize (Self : in out Stream_Encryptor_Auth);

   type Stream_Decryptor_Auth is new
     Ada.Finalization.Limited_Controlled with
      record
         Noise_H        : Itb.Sys.Handle := 0;
         Data_H         : Itb.Sys.Handle := 0;
         Start_H        : Itb.Sys.Handle := 0;
         MAC_H          : Itb.Sys.Handle := 0;
         Width          : Integer := 0;
         Header_Size    : Ada.Streams.Stream_Element_Offset := 0;
         Source         : access Ada.Streams.Root_Stream_Type'Class :=
                            null;
         Buf            : Byte_Buffer_Access := null;
         Buf_Used       : Ada.Streams.Stream_Element_Offset := 0;
         Plain          : Byte_Buffer_Access := null;
         Plain_Pos      : Ada.Streams.Stream_Element_Offset := 0;
         Plain_Last     : Ada.Streams.Stream_Element_Offset := 0;
         Stream_ID      : Stream_ID_Bytes := [others => 0];
         Sid_Have       : Ada.Streams.Stream_Element_Offset := 0;
         Cum_Pixels     : Itb.Sys.U64 := 0;
         Seen_Final     : Boolean := False;
         At_EOF         : Boolean := False;
         Closed         : Boolean := False;
         --  Per-stream output buffer cache (decrypt-side counterpart);
         --  same wipe-on-grow + wipe-on-Finalize discipline.
         Cache          : Byte_Buffer_Access := null;
      end record;

   overriding procedure Finalize (Self : in out Stream_Decryptor_Auth);

   type Stream_Encryptor_Auth_3 is new
     Ada.Finalization.Limited_Controlled with
      record
         Noise_H        : Itb.Sys.Handle := 0;
         Data1_H        : Itb.Sys.Handle := 0;
         Data2_H        : Itb.Sys.Handle := 0;
         Data3_H        : Itb.Sys.Handle := 0;
         Start1_H       : Itb.Sys.Handle := 0;
         Start2_H       : Itb.Sys.Handle := 0;
         Start3_H       : Itb.Sys.Handle := 0;
         MAC_H          : Itb.Sys.Handle := 0;
         Width          : Integer := 0;
         Header_Size    : Ada.Streams.Stream_Element_Offset := 0;
         Sink           : access Ada.Streams.Root_Stream_Type'Class :=
                            null;
         Chunk_Size     : Ada.Streams.Stream_Element_Offset := 0;
         Buf            : Byte_Buffer_Access := null;
         Buf_Used       : Ada.Streams.Stream_Element_Offset := 0;
         Stream_ID      : Stream_ID_Bytes := [others => 0];
         Cum_Pixels     : Itb.Sys.U64 := 0;
         Prefix_Emitted : Boolean := False;
         Closed         : Boolean := False;
         --  Per-stream output buffer cache (Triple variant).
         Cache          : Byte_Buffer_Access := null;
      end record;

   overriding procedure Finalize (Self : in out Stream_Encryptor_Auth_3);

   type Stream_Decryptor_Auth_3 is new
     Ada.Finalization.Limited_Controlled with
      record
         Noise_H        : Itb.Sys.Handle := 0;
         Data1_H        : Itb.Sys.Handle := 0;
         Data2_H        : Itb.Sys.Handle := 0;
         Data3_H        : Itb.Sys.Handle := 0;
         Start1_H       : Itb.Sys.Handle := 0;
         Start2_H       : Itb.Sys.Handle := 0;
         Start3_H       : Itb.Sys.Handle := 0;
         MAC_H          : Itb.Sys.Handle := 0;
         Width          : Integer := 0;
         Header_Size    : Ada.Streams.Stream_Element_Offset := 0;
         Source         : access Ada.Streams.Root_Stream_Type'Class :=
                            null;
         Buf            : Byte_Buffer_Access := null;
         Buf_Used       : Ada.Streams.Stream_Element_Offset := 0;
         Plain          : Byte_Buffer_Access := null;
         Plain_Pos      : Ada.Streams.Stream_Element_Offset := 0;
         Plain_Last     : Ada.Streams.Stream_Element_Offset := 0;
         Stream_ID      : Stream_ID_Bytes := [others => 0];
         Sid_Have       : Ada.Streams.Stream_Element_Offset := 0;
         Cum_Pixels     : Itb.Sys.U64 := 0;
         Seen_Final     : Boolean := False;
         At_EOF         : Boolean := False;
         Closed         : Boolean := False;
         --  Per-stream output buffer cache (decrypt-side Triple
         --  variant).
         Cache          : Byte_Buffer_Access := null;
      end record;

   overriding procedure Finalize (Self : in out Stream_Decryptor_Auth_3);

end Itb.Streams;
