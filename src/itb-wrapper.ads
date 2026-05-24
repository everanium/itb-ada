--  Itb.Wrapper — format-deniability wrapper over the libitb wrap
--  surface.
--
--  Wraps an ITB ciphertext under one of three outer keystream ciphers
--  (AES-128-CTR / ChaCha20 (RFC8439) / SipHash-2-4 in CTR mode) so the
--  on-wire bytes carry no ITB-specific format pattern (W / H /
--  container layout for Non-AEAD; 32-byte streamID prefix +
--  per-chunk metadata for Streaming AEAD). The wrap exists for
--  format-deniability ONLY — ITB already provides
--  content-deniability and the AEAD path already provides integrity.
--
--  Quick start (Single Message Wrap / Unwrap, immutable inputs):
--
--     declare
--        Key  : constant Itb.Byte_Array :=
--          Itb.Wrapper.Generate_Key (Itb.Wrapper.Aes_128_Ctr);
--        Wire : constant Itb.Byte_Array :=
--          Itb.Wrapper.Wrap (Itb.Wrapper.Aes_128_Ctr, Key, Blob);
--        Recovered : constant Itb.Byte_Array :=
--          Itb.Wrapper.Unwrap (Itb.Wrapper.Aes_128_Ctr, Key, Wire);
--     begin
--        pragma Assert (Recovered = Blob);
--     end;
--
--  Single Message in-place mutation (zero-allocation steady state):
--
--     declare
--        N_Len     : constant Natural :=
--          Itb.Wrapper.Nonce_Size (Itb.Wrapper.Cha_Cha_20);
--        Out_Nonce : Itb.Byte_Array
--                       (1 .. Stream_Element_Offset (N_Len));
--        Mutable   : Itb.Byte_Array := Blob;
--     begin
--        Itb.Wrapper.Wrap_In_Place
--          (Itb.Wrapper.Cha_Cha_20, Key, Mutable, Out_Nonce);
--        --  Wire = Out_Nonce & Mutable
--     end;
--
--  Streaming wrap (caller-side framing through one keystream so
--  length prefixes also XOR through):
--
--     declare
--        Writer : Itb.Wrapper.Wrap_Stream_Writer;
--        Out_Nonce : Itb.Byte_Array
--                       (1 .. Stream_Element_Offset
--                               (Itb.Wrapper.Nonce_Size
--                                  (Itb.Wrapper.Sip_Hash_24)));
--     begin
--        Itb.Wrapper.Initialize
--          (Writer, Itb.Wrapper.Sip_Hash_24, Key, Out_Nonce);
--        --  Emit Out_Nonce once at stream start, then drive Update
--        --  per chunk.
--     end;  --  Writer.Finalize releases the libitb handle.
--
--  Threading. Each Wrap_Stream_Writer / Unwrap_Stream_Reader value
--  owns one libitb wrap-stream handle and is single-feeder by
--  construction; do not invoke Update from multiple Ada tasks
--  concurrently against the same handle. Distinct values run
--  independently. The free subprograms (Wrap / Unwrap /
--  Wrap_In_Place / Unwrap_In_Place) are thread-safe — each call
--  allocates its own outer cipher state internally and the
--  underlying libitb keystream constructor draws a fresh CSPRNG
--  nonce per call.

private with Ada.Finalization;

with Ada.Streams;

with Itb.Sys;

package Itb.Wrapper is

   ---------------------------------------------------------------------
   --  Outer keystream cipher selector
   ---------------------------------------------------------------------

   --  Outer cipher selected per wrap session. Each variant maps to
   --  one of the nine cipher-name strings the libitb FFI accepts:
   --  "aescmac" / "chacha20" / "siphash24" / "areion256" / "areion512"
   --  / "blake2b256" / "blake2b512" / "blake2s" / "blake3". The Go-side
   --  constants are wrapper.CipherAES128CTR / wrapper.CipherChaCha20 /
   --  wrapper.CipherSipHash24 and the matching wrapper.Cipher* values
   --  for the remaining six.
   type Cipher_Type is
     (Aes_128_Ctr, Cha_Cha_20, Sip_Hash_24,
      Areion_256, Areion_512,
      Blake_2b_256, Blake_2b_512, Blake_2s, Blake_3);

   --  Iteration order over every supported outer cipher.
   type Cipher_Array is array (Positive range <>) of Cipher_Type;
   All_Ciphers : constant Cipher_Array :=
     [Areion_256, Areion_512, Sip_Hash_24, Aes_128_Ctr,
      Blake_2b_256, Blake_2b_512, Blake_2s, Blake_3, Cha_Cha_20];

   --  Returns the canonical FFI cipher-name string ("aescmac" / "chacha20"
   --  / "siphash24" / "areion256" / "areion512" / "blake2b256" /
   --  "blake2b512" / "blake2s" / "blake3") for the given Cipher_Type.
   --  Used at every libitb call site that takes a const char* cipherName
   --  argument.
   function Ffi_Name (C : Cipher_Type) return String;

   ---------------------------------------------------------------------
   --  Metadata + key generation
   ---------------------------------------------------------------------

   --  Returns the byte length of the keystream-cipher key for the
   --  named outer cipher (16 / 32 / 16 for AES / ChaCha / SipHash).
   function Key_Size (C : Cipher_Type) return Natural;

   --  Returns the on-wire nonce length the named outer cipher emits
   --  per stream (16 / 12 / 16 for AES / ChaCha / SipHash).
   function Nonce_Size (C : Cipher_Type) return Natural;

   --  Returns a fresh CSPRNG key sized for the named outer cipher.
   --  Uses GNAT.Random_Numbers for the underlying PRNG seeded once at
   --  package elaboration; mixed with a fresh Ada.Calendar.Clock
   --  reading per call so successive program runs draw distinct keys.
   --  The wrapper key MAY be reused across many streams — the per-
   --  stream nonce drawn internally by Wrap / Wrap_In_Place /
   --  Initialize is the safety boundary.
   function Generate_Key (C : Cipher_Type) return Byte_Array;

   --  Deterministically derives the outer cipher key for C from a
   --  caller-supplied Master secret (e.g. an ML-KEM shared secret).
   --  The result is a deterministic function of (C, Master), so both
   --  endpoints derive the same key from a shared master. Master must
   --  be at least 32 bytes (the wrapper's uniform security floor — a
   --  256-bit master matching an ML-KEM shared secret). The kdf layer
   --  truncates / stretches that master to the per-cipher key length
   --  internally, so a single 32-byte master keys every outer cipher.
   --  Returns the derived key of length Key_Size(C) (16 / 32 / 16 for
   --  AES / ChaCha / SipHash); raises an Itb_Error for a master
   --  shorter than 32 bytes.
   function Derive_Key
     (C      : Cipher_Type;
      Master : Byte_Array) return Byte_Array;

   ---------------------------------------------------------------------
   --  Single Message Wrap / Unwrap (allocating)
   ---------------------------------------------------------------------

   --  Seals one ITB ciphertext blob under C with a fresh CSPRNG
   --  nonce; returns the wire bytes nonce || keystream-XOR(blob).
   --  Allocates a fresh output buffer of size
   --  Nonce_Size(C) + Blob'Length per call. For zero-allocation steady
   --  state on the hot path use Wrap_In_Place.
   function Wrap
     (Cipher : Cipher_Type;
      Key    : Byte_Array;
      Blob   : Byte_Array) return Byte_Array;

   --  Reverses Wrap. Reads the leading Nonce_Size(C) bytes of Wire as
   --  the per-stream nonce, XOR-decrypts the remainder under
   --  (Key, nonce), returns the recovered blob. Allocates a fresh
   --  output buffer of size Wire'Length - Nonce_Size(C) per call.
   --  For zero-allocation steady state use Unwrap_In_Place.
   function Unwrap
     (Cipher : Cipher_Type;
      Key    : Byte_Array;
      Wire   : Byte_Array) return Byte_Array;

   ---------------------------------------------------------------------
   --  Single Message Wrap / Unwrap (in-place mutation)
   ---------------------------------------------------------------------

   --  XORs Blob in place under a fresh CSPRNG outer cipher keystream
   --  and writes the per-stream nonce into Out_Nonce. The caller is
   --  expected to emit Out_Nonce followed by Blob to the wire (or
   --  compose a single buffer themselves).
   --
   --  Blob is MUTATED. Do not pass plaintext that must be preserved
   --  beyond the call. Suitable for hot paths where the caller has
   --  just produced an ITB ciphertext and will not re-read it (the
   --  typical case for buffered write-to-wire). Out_Nonce'Length must
   --  equal Nonce_Size(Cipher); otherwise an Itb_Error /
   --  Itb.Status.Bad_Input is raised.
   procedure Wrap_In_Place
     (Cipher    : Cipher_Type;
      Key       : Byte_Array;
      Blob      : in out Byte_Array;
      Out_Nonce : out Byte_Array);

   --  Strips the leading Nonce_Size(Cipher) bytes from Wire and
   --  XOR-decrypts the remainder in place. Returns Body_First — the
   --  index of the first decrypted byte inside Wire (i.e.
   --  Wire'First + Nonce_Size(Cipher)) so the caller can address the
   --  recovered body via Wire (Body_First .. Wire'Last). Wire is
   --  MUTATED. Wire'Length must be at least Nonce_Size(Cipher);
   --  otherwise an Itb_Error / Itb.Status.Bad_Input is raised.
   procedure Unwrap_In_Place
     (Cipher     : Cipher_Type;
      Key        : Byte_Array;
      Wire       : in out Byte_Array;
      Body_First : out Ada.Streams.Stream_Element_Offset);

   ---------------------------------------------------------------------
   --  Streaming wrap-encrypt handle
   ---------------------------------------------------------------------

   --  Owns one libitb wrap-stream handle keyed by (cipher, key,
   --  nonce) where nonce is a fresh CSPRNG draw made at Initialize.
   --  Initialize emits the per-stream nonce into Out_Nonce so the
   --  caller can prepend it to the wire once at stream start;
   --  subsequent Update calls XOR caller plaintext through the
   --  keystream and the keystream counter advances monotonically
   --  across calls.
   --
   --  Lifecycle is RAII via Ada.Finalization.Limited_Controlled —
   --  leaving the value's scope releases the underlying libitb
   --  handle deterministically.
   type Wrap_Stream_Writer is tagged limited private;

   --  Allocates a fresh wrap-stream handle and writes the per-stream
   --  CSPRNG nonce into Out_Nonce. Out_Nonce'Length must equal
   --  Nonce_Size(Cipher); otherwise an Itb_Error /
   --  Itb.Status.Bad_Input is raised. Calling Initialize on a writer
   --  that already owns a handle releases the previous handle first.
   procedure Initialize
     (Self      : in out Wrap_Stream_Writer;
      Cipher    : Cipher_Type;
      Key       : Byte_Array;
      Out_Nonce : out Byte_Array);

   --  XOR-encrypts Src through the keystream and writes the result
   --  into Dst. Dst MAY equal Src for in-place mutation; Dst'Length
   --  must be at least Src'Length. Last is set to the offset of the
   --  last byte written (Dst'First + Src'Length - 1, or
   --  Dst'First - 1 when Src is empty). The keystream counter
   --  advances by Src'Length bytes regardless.
   procedure Update
     (Self : in out Wrap_Stream_Writer;
      Src  : Byte_Array;
      Dst  : out Byte_Array;
      Last : out Ada.Streams.Stream_Element_Offset);

   --  Returns the cipher selected at Initialize.
   function Cipher (Self : Wrap_Stream_Writer) return Cipher_Type;

   --  Releases the underlying libitb handle. Idempotent — a second
   --  call is a no-op. Finalize is invoked automatically at scope
   --  exit; explicit Close is the path for ASAP release.
   procedure Close (Self : in out Wrap_Stream_Writer);

   ---------------------------------------------------------------------
   --  Streaming wrap-decrypt handle
   ---------------------------------------------------------------------

   --  Counterpart of Wrap_Stream_Writer. Initialize takes the
   --  per-stream nonce read off the wire and binds the libitb
   --  unwrap-stream handle to it; Update XOR-decrypts caller-supplied
   --  ciphertext bytes through the keystream.
   type Unwrap_Stream_Reader is tagged limited private;

   --  Allocates a fresh unwrap-stream handle keyed by
   --  (Cipher, Key, Wire_Nonce). Wire_Nonce'Length must equal
   --  Nonce_Size(Cipher); otherwise an Itb_Error /
   --  Itb.Status.Bad_Input is raised.
   procedure Initialize
     (Self       : in out Unwrap_Stream_Reader;
      Cipher     : Cipher_Type;
      Key        : Byte_Array;
      Wire_Nonce : Byte_Array);

   --  XOR-decrypts Src through the keystream and writes the recovered
   --  plaintext into Dst. Dst MAY equal Src for in-place mutation;
   --  Dst'Length must be at least Src'Length. Last is set to the
   --  offset of the last byte written (Dst'First + Src'Length - 1,
   --  or Dst'First - 1 when Src is empty). The keystream counter
   --  advances by Src'Length bytes regardless.
   procedure Update
     (Self : in out Unwrap_Stream_Reader;
      Src  : Byte_Array;
      Dst  : out Byte_Array;
      Last : out Ada.Streams.Stream_Element_Offset);

   --  Returns the cipher selected at Initialize.
   function Cipher (Self : Unwrap_Stream_Reader) return Cipher_Type;

   --  Releases the underlying libitb handle. Idempotent.
   procedure Close (Self : in out Unwrap_Stream_Reader);

private

   type Wrap_Stream_Writer is new Ada.Finalization.Limited_Controlled with
      record
         Handle : Itb.Sys.Handle := 0;
         Bound  : Cipher_Type    := Aes_128_Ctr;
         Closed : Boolean        := False;
      end record;

   overriding procedure Finalize (Self : in out Wrap_Stream_Writer);

   type Unwrap_Stream_Reader is new
     Ada.Finalization.Limited_Controlled with
      record
         Handle : Itb.Sys.Handle := 0;
         Bound  : Cipher_Type    := Aes_128_Ctr;
         Closed : Boolean        := False;
      end record;

   overriding procedure Finalize (Self : in out Unwrap_Stream_Reader);

end Itb.Wrapper;
