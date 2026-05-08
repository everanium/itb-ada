--  Itb.Seed — RAII wrapper over an ITB_NewSeed handle.
--
--  The Seed type is a limited controlled type; its Finalize
--  procedure releases the underlying libitb handle deterministically
--  when the Seed goes out of scope.
--
--  Constructors:
--    Make             — CSPRNG-keyed seed with the named hash and
--                       width.
--    From_Components  — Deterministic rebuild from saved components
--                       and an optional fixed hash key. Use this on
--                       the persistence-restore path.
--
--  Three Seeds with matching native hash widths are passed to
--  Itb.Cipher.Encrypt / .Decrypt / their Triple variants. Mixing
--  widths surfaces as Itb_Error with Status_Code = Seed_Width_Mix.

private with Ada.Finalization;
private with Ada.Strings.Unbounded;

with Itb.Sys;

package Itb.Seed is
   pragma Preelaborate;

   --  Opaque handle on a libitb seed. Limited type — passed by
   --  reference, never copied; release deterministic at scope exit.
   type Seed is tagged limited private;

   --  CSPRNG-keyed constructor. Hash_Name is one of the canonical
   --  names returned by Itb.List_Hashes. Key_Bits is the ITB key
   --  width in bits — 512, 1024, or 2048 (multiple of 64).
   function Make
     (Hash_Name : String;
      Key_Bits  : Integer) return Seed;

   --  Deterministic-rebuild constructor. Components length must be
   --  8..32 (multiple of 8). Hash_Key length, when non-empty, must
   --  match the primitive's native fixed-key size: 16 (aescmac), 32
   --  (areion256 / blake2{s,b256} / blake3 / chacha20), 64
   --  (areion512 / blake2b512). Pass an empty Byte_Array for
   --  siphash24 (no internal fixed key) or to request a CSPRNG-
   --  generated key (still useful when only the components need to
   --  be deterministic).
   function From_Components
     (Hash_Name  : String;
      Components : Component_Array;
      Hash_Key   : Byte_Array) return Seed;

   --  Native hash width in bits (128 / 256 / 512).
   function Width (Self : Seed) return Integer;

   --  Canonical hash name this Seed was constructed with (round-trip
   --  of the Make / From_Components Hash_Name argument).
   function Hash_Name (Self : Seed) return String;

   --  Re-reads the canonical hash name from libitb; returns the same
   --  value as Hash_Name in the absence of corruption.
   function Hash_Name_Introspect (Self : Seed) return String;

   --  Returns the fixed key the underlying hash closure is bound to
   --  (16 / 32 / 64 bytes). Save these bytes alongside Get_Components
   --  for cross-process persistence; the pair fully reconstructs the
   --  Seed via From_Components. siphash24 returns an empty
   --  Byte_Array (SipHash-2-4 has no internal fixed key — its keying
   --  material is the seed components themselves).
   function Get_Hash_Key (Self : Seed) return Byte_Array;

   --  Returns the seed's underlying uint64 components.
   function Get_Components (Self : Seed) return Component_Array;

   --  Wires a dedicated lockSeed onto this noise seed. Both seeds
   --  must share the same native hash width. Has no observable wire
   --  effect unless Itb.Set_Bit_Soup (1) or Itb.Set_Lock_Soup (1) is
   --  called before the first encrypt / decrypt invocation.
   --
   --  Misuse paths surface as:
   --    Itb_Error / Bad_Input        — self-attach, post-encrypt
   --                                   switching, component-array
   --                                   aliasing.
   --    Itb_Error / Seed_Width_Mix   — width mismatch.
   --
   --  The dedicated lockSeed remains owned by the caller — Attach
   --  only records a pointer on the noise seed, so keep the lockSeed
   --  alive (in scope) for the lifetime of the noise seed.
   procedure Attach_Lock_Seed (Self : Seed; Lock : Seed);

   --  Internal-use accessor over the raw libitb handle. Used by
   --  Itb.Cipher / Itb.Streams to build their FFI calls. External
   --  consumers should not need this — prefer the higher-level
   --  Encryptor / Cipher interfaces.
   function Raw_Handle (Self : Seed) return Itb.Sys.Handle;

private

   type Seed is new Ada.Finalization.Limited_Controlled with record
      Handle    : Itb.Sys.Handle := 0;
      Hash_Name : Ada.Strings.Unbounded.Unbounded_String;
   end record;

   overriding procedure Finalize (Self : in out Seed);

end Itb.Seed;
