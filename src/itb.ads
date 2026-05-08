--  Itb — Ada binding to libitb, the ITB cryptographic library.
--
--  This is the root of the binding hierarchy. The wrapper surface is
--  split across child packages:
--
--    Itb.Sys       Raw FFI declarations over libitb's C ABI. Every
--                  ITB_* C function is exposed via pragma Import.
--                  Internal / unsafe; consumers should prefer the
--                  safe wrappers in the sibling packages.
--    Itb.Status    Named numeric status codes (OK = 0, BAD_HASH = 1,
--                  ... MAC_FAILURE = 10, EASY_MISMATCH = 17,
--                  BLOB_MALFORMED = 20, INTERNAL = 99). 24 codes
--                  total.
--    Itb.Errors    Itb_Error exception family + Raise_For helper +
--                  Status_Code / Field / Message accessors.
--    Itb.Seed      Seed type (Ada.Finalization.Controlled wrapper).
--    Itb.MAC       MAC type (Controlled wrapper).
--    Itb.Cipher    Free subprograms — Encrypt / Decrypt /
--                  Encrypt_Triple / Decrypt_Triple plus the four
--                  authenticated variants.
--    Itb.Encryptor Easy Mode wrapper — Encryptor type with output
--                  buffer cache, default-MAC override, mixed-primitive
--                  constructors, state-blob export / import.
--    Itb.Blob      Blob128 / Blob256 / Blob512 — low-level state
--                  persistence types.
--    Itb.Streams   Stream_Encryptor / Stream_Decryptor + Triple
--                  variants over Ada.Streams.
--
--  This root package also exposes the library-wide configuration
--  globals — version, hash / MAC catalogue, channel count, max key
--  width, header size, and the Set_* / Get_* knobs over the
--  process-global libitb state (Bit_Soup, Lock_Soup, Max_Workers,
--  Nonce_Bits, Barrier_Fill). All of these wrap the corresponding
--  ITB_* free function in libitb and raise from Itb.Errors on a
--  non-OK status.

with Ada.Streams;
with Ada.Strings.Unbounded;
with Interfaces;

package Itb is
   pragma Preelaborate;

   ---------------------------------------------------------------------
   --  Cross-cutting types
   ---------------------------------------------------------------------

   --  Byte buffer type used at every binding boundary that takes
   --  arbitrary plaintext / ciphertext / state-blob bytes. Aliased to
   --  Ada.Streams.Stream_Element_Array so the same buffer type works
   --  uniformly with Ada.Streams readers / writers for streaming use.
   subtype Byte_Array is Ada.Streams.Stream_Element_Array;

   --  Seed components — the 8 .. 32 (multiple-of-8) uint64 entries
   --  that fully reconstruct a Seed via Itb.Seed.From_Components.
   --  Used by Itb.Seed and Itb.Blob for state-persistence round-trips.
   type Component_Array is
     array (Positive range <>) of Interfaces.Unsigned_64;

   --  Catalogue entry returned by List_Hashes — the hash primitive's
   --  name and the native digest width in bits.
   type Hash_Info is record
      Name  : Ada.Strings.Unbounded.Unbounded_String;
      Width : Natural := 0;
   end record;

   type Hash_List is array (Positive range <>) of Hash_Info;

   --  Catalogue entry returned by List_MACs — name + key / tag /
   --  minimum-key sizes in bytes.
   type MAC_Info is record
      Name          : Ada.Strings.Unbounded.Unbounded_String;
      Key_Size      : Natural := 0;
      Tag_Size      : Natural := 0;
      Min_Key_Bytes : Natural := 0;
   end record;

   type MAC_List is array (Positive range <>) of MAC_Info;

   ---------------------------------------------------------------------
   --  Library metadata
   ---------------------------------------------------------------------

   --  Returns the libitb library version string in
   --  "<major>.<minor>.<patch>" form.
   function Version return String;

   --  Number of registered hash primitives (typically 9 for the
   --  shipping PRF-grade catalogue: Areion-SoEM-256, Areion-SoEM-512,
   --  BLAKE2b-256, BLAKE2b-512, BLAKE2s, BLAKE3, AES-CMAC,
   --  SipHash-2-4, ChaCha20).
   function Hash_Count return Natural;

   --  Returns the canonical name of the I'th hash primitive.
   --  Constraint_Error raised on out-of-range index.
   function Hash_Name (I : Natural) return String;

   --  Native digest width in bits of the I'th hash primitive
   --  (128 / 256 / 512). Constraint_Error raised on out-of-range
   --  index.
   function Hash_Width (I : Natural) return Natural;

   --  Snapshot of the full hash catalogue.
   function List_Hashes return Hash_List;

   --  Number of registered MAC primitives.
   function MAC_Count return Natural;

   --  Returns the canonical name of the I'th MAC.
   function MAC_Name (I : Natural) return String;

   --  Key size in bytes for the I'th MAC.
   function MAC_Key_Size (I : Natural) return Natural;

   --  Tag size in bytes for the I'th MAC.
   function MAC_Tag_Size (I : Natural) return Natural;

   --  Minimum key size in bytes accepted by the I'th MAC.
   function MAC_Min_Key_Bytes (I : Natural) return Natural;

   --  Snapshot of the full MAC catalogue.
   function List_MACs return MAC_List;

   --  Number of native-channel slots (typically 7 for the shipping
   --  primitives).
   function Channels return Natural;

   --  Maximum supported ITB key width in bits.
   function Max_Key_Bits return Natural;

   --  Current ciphertext-chunk header size in bytes
   --  (nonce + width(2) + height(2)). Tracks Set_Nonce_Bits — 20 by
   --  default, 36 under Set_Nonce_Bits (256), 68 under
   --  Set_Nonce_Bits (512). Streaming consumers read this many bytes
   --  before calling Parse_Chunk_Len on each chunk.
   function Header_Size return Natural;

   --  Inspects the fixed-size header of a ciphertext chunk and
   --  returns the total on-the-wire chunk length. Buffer must
   --  contain at least Header_Size bytes; body bytes are not
   --  consulted. Raises an Itb_Error on too-short buffer, zero
   --  dimensions, or overflow.
   function Parse_Chunk_Len (Header : Byte_Array) return Natural;

   ---------------------------------------------------------------------
   --  Process-global configuration
   ---------------------------------------------------------------------

   --  Process-wide Bit Soup mode (0 = byte-level split, non-zero =
   --  bit-level Bit Soup split). Independent of Set_Lock_Soup at the
   --  setter level — there is no BitSoup -> LockSoup cascade. In
   --  Single Ouroboros, either flag alone activates the dispatcher's
   --  keyed bit-permutation overlay (Single OR-gates the two flags).
   procedure Set_Bit_Soup (Mode : Integer);
   function  Get_Bit_Soup return Integer;

   --  Process-wide Lock Soup mode (0 = off, non-zero = on). A
   --  non-zero value auto-couples Set_Bit_Soup (1) (Lock Soup overlay
   --  layers on top of bit soup; one-direction cascade). The
   --  off-direction does not auto-disable bit soup.
   procedure Set_Lock_Soup (Mode : Integer);
   function  Get_Lock_Soup return Integer;

   procedure Set_Max_Workers (N : Integer);
   function  Get_Max_Workers return Integer;

   --  Accepts 128, 256, or 512. Other values raise an Itb_Error with
   --  Status_Code = Bad_Input.
   procedure Set_Nonce_Bits (N : Integer);
   function  Get_Nonce_Bits return Integer;

   --  Accepts 1, 2, 4, 8, 16, 32. Other values raise an Itb_Error
   --  with Status_Code = Bad_Input.
   procedure Set_Barrier_Fill (N : Integer);
   function  Get_Barrier_Fill return Integer;

end Itb;
