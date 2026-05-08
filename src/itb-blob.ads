--  Itb.Blob — width-typed RAII wrappers over the libitb native-Blob
--  surface (low-level state persistence).
--
--  The Blob128 / Blob256 / Blob512 types are limited controlled
--  wrappers; their Finalize procedures release the underlying
--  libitb handle deterministically when the Blob goes out of scope.
--
--  The native-Blob layer packs the low-level Encryptor material — the
--  per-seed hash key + components, the optional dedicated lockSeed,
--  and the optional MAC key + name — plus the captured process-wide
--  configuration into one self-describing JSON blob. Intended for the
--  low-level Itb.Cipher path where each seed slot may carry a
--  different primitive; Itb.Encryptor wraps a narrower
--  one-primitive-per-encryptor surface over the same libitb state-
--  persistence primitives.
--
--  The blob is mode-discriminated: Export packs Single Ouroboros
--  material into the N / D / S (and optionally L) slots, Export_3
--  packs Triple Ouroboros material into D1..D3 / S1..S3. A blob built
--  under one mode rejects the wrong importer with Itb_Error /
--  Blob_Mode_Mismatch.
--
--  Globals (Nonce_Bits / Barrier_Fill / Bit_Soup / Lock_Soup) are
--  captured into the blob at export time and applied process-wide on
--  import via the Itb.Set_* setters. The worker count and the global
--  LockSeed flag are not serialised — the former is a deployment knob,
--  the latter is irrelevant on the native path which consults
--  Itb.Seed.Attach_Lock_Seed directly.

private with Ada.Finalization;

with Itb.Sys;

package Itb.Blob is
   pragma Preelaborate;

   ---------------------------------------------------------------------
   --  Slot identifiers — must mirror the BlobSlot* constants in
   --  cmd/cshared/internal/capi/blob_handles.go.
   ---------------------------------------------------------------------

   subtype Slot_Type is Integer range 0 .. 9;

   Slot_N  : constant Slot_Type := 0;  --  Noise seed (Single Ouroboros).
   Slot_D  : constant Slot_Type := 1;  --  Data seed (Single Ouroboros).
   Slot_S  : constant Slot_Type := 2;  --  Start seed (Single Ouroboros).
   Slot_L  : constant Slot_Type := 3;  --  Dedicated lockSeed.
   Slot_D1 : constant Slot_Type := 4;  --  Triple Ouroboros — data 1.
   Slot_D2 : constant Slot_Type := 5;  --  Triple Ouroboros — data 2.
   Slot_D3 : constant Slot_Type := 6;  --  Triple Ouroboros — data 3.
   Slot_S1 : constant Slot_Type := 7;  --  Triple Ouroboros — start 1.
   Slot_S2 : constant Slot_Type := 8;  --  Triple Ouroboros — start 2.
   Slot_S3 : constant Slot_Type := 9;  --  Triple Ouroboros — start 3.

   ---------------------------------------------------------------------
   --  Export option bitmask — must mirror BlobOpt* in blob_handles.go.
   --  Modular type so the `or` and `+` operators are both visible
   --  (the constants are disjoint single-bit values; either works).
   ---------------------------------------------------------------------

   type Export_Opts is mod 2 ** 8;

   --  No optional sections — emit only the minimal Single / Triple
   --  state shape.
   Opt_None     : constant Export_Opts := 0;

   --  Emit the `l` slot's lockSeed material (KeyL + components) into
   --  the blob.
   Opt_LockSeed : constant Export_Opts := 1;

   --  Emit the MAC key + name into the blob. Both must be non-empty
   --  on the handle.
   Opt_Mac      : constant Export_Opts := 2;

   ---------------------------------------------------------------------
   --  128-bit width Blob — covers `siphash24` and `aescmac` primitives.
   --  Hash key length is variable: empty for siphash24 (no internal
   --  fixed key), 16 bytes for aescmac.
   ---------------------------------------------------------------------

   type Blob128 is tagged limited private;

   --  Constructs a fresh 128-bit width Blob handle.
   function New_Blob128 return Blob128;

   --  Native hash width in bits (always 128). Pinned at construction.
   function Width (Self : Blob128) return Integer;

   --  Blob mode field — 0 = unset (freshly constructed handle), 1 =
   --  Single Ouroboros, 3 = Triple Ouroboros. Updated by Import /
   --  Import_3 from the parsed blob's mode discriminator.
   function Mode (Self : Blob128) return Integer;

   --  Stores the hash key bytes for the given slot. The 128 width
   --  accepts variable lengths (empty for siphash24, 16 bytes for
   --  aescmac).
   procedure Set_Key
     (Self : in out Blob128;
      Slot : Slot_Type;
      Key  : Byte_Array);

   --  Returns a fresh copy of the hash key bytes from the given slot.
   --  Returns an empty Byte_Array for an unset slot or siphash24's
   --  no-internal-key path.
   function Get_Key
     (Self : Blob128;
      Slot : Slot_Type) return Byte_Array;

   --  Stores the seed components (uint64 entries) for the given slot.
   --  Component count must satisfy the 8 .. Max_Key_Bits/64
   --  multiple-of-8 invariants — same rules as
   --  Itb.Seed.From_Components. Validation is deferred to Export /
   --  Import time.
   procedure Set_Components
     (Self  : in out Blob128;
      Slot  : Slot_Type;
      Comps : Component_Array);

   --  Returns the seed components stored at the given slot. Returns
   --  an empty Component_Array for an unset slot.
   function Get_Components
     (Self : Blob128;
      Slot : Slot_Type) return Component_Array;

   --  Stores the optional MAC key bytes. Pass an empty Byte_Array to
   --  clear a previously-set key. The MAC section is only emitted by
   --  Export / Export_3 when Opt_Mac is set AND the MAC key on the
   --  handle is non-empty.
   procedure Set_MAC_Key
     (Self : in out Blob128;
      Key  : Byte_Array);

   --  Returns a fresh copy of the MAC key bytes from the handle, or
   --  an empty Byte_Array if no MAC is associated.
   function Get_MAC_Key (Self : Blob128) return Byte_Array;

   --  Stores the optional MAC name on the handle (e.g. "kmac256",
   --  "hmac-blake3"). Pass an empty string to clear a previously-set
   --  name.
   procedure Set_MAC_Name
     (Self : in out Blob128;
      Name : String);

   --  Returns the MAC name from the handle, or an empty string if no
   --  MAC is associated.
   function Get_MAC_Name (Self : Blob128) return String;

   --  Serialises the handle's Single Ouroboros state into a JSON blob.
   --  Opts is a bitmask combining Opt_LockSeed and / or Opt_Mac via
   --  the modular Export_Opts type's `or` (or `+`) operator; bring
   --  the operators into scope at the call site with
   --  `use type Itb.Blob.Export_Opts;`. Default Opt_None emits only
   --  the mandatory N / D / S material.
   function Export
     (Self : Blob128;
      Opts : Export_Opts := Opt_None) return Byte_Array;

   --  Parses a Single Ouroboros JSON blob, populates the handle's
   --  slots, and applies the captured globals via the process-wide
   --  setters. Raises Itb_Blob_Mode_Mismatch_Error when the blob is
   --  Triple-mode, Itb_Blob_Malformed_Error on parse / shape failure,
   --  Itb_Blob_Version_Too_New_Error on a version field higher than
   --  this build supports.
   procedure Import
     (Self : in out Blob128;
      Blob : Byte_Array);

   --  Serialises the handle's Triple Ouroboros state into a JSON
   --  blob. See Export for the Opts bitmask.
   function Export_3
     (Self : Blob128;
      Opts : Export_Opts := Opt_None) return Byte_Array;

   --  Triple-Ouroboros counterpart of Import. Same error contract.
   procedure Import_3
     (Self : in out Blob128;
      Blob : Byte_Array);

   ---------------------------------------------------------------------
   --  256-bit width Blob — covers `areion256`, `blake2s`, `blake2b256`,
   --  `blake3`, `chacha20`. Hash key length is fixed at 32 bytes.
   ---------------------------------------------------------------------

   type Blob256 is tagged limited private;

   function New_Blob256 return Blob256;

   function Width (Self : Blob256) return Integer;
   function Mode  (Self : Blob256) return Integer;

   procedure Set_Key
     (Self : in out Blob256;
      Slot : Slot_Type;
      Key  : Byte_Array);
   function Get_Key
     (Self : Blob256;
      Slot : Slot_Type) return Byte_Array;

   procedure Set_Components
     (Self  : in out Blob256;
      Slot  : Slot_Type;
      Comps : Component_Array);
   function Get_Components
     (Self : Blob256;
      Slot : Slot_Type) return Component_Array;

   procedure Set_MAC_Key
     (Self : in out Blob256;
      Key  : Byte_Array);
   function Get_MAC_Key (Self : Blob256) return Byte_Array;

   procedure Set_MAC_Name
     (Self : in out Blob256;
      Name : String);
   function Get_MAC_Name (Self : Blob256) return String;

   function Export
     (Self : Blob256;
      Opts : Export_Opts := Opt_None) return Byte_Array;
   procedure Import
     (Self : in out Blob256;
      Blob : Byte_Array);

   function Export_3
     (Self : Blob256;
      Opts : Export_Opts := Opt_None) return Byte_Array;
   procedure Import_3
     (Self : in out Blob256;
      Blob : Byte_Array);

   ---------------------------------------------------------------------
   --  512-bit width Blob — covers `areion512` (via the SoEM-512
   --  construction) and `blake2b512`. Hash key length is fixed at 64
   --  bytes.
   ---------------------------------------------------------------------

   type Blob512 is tagged limited private;

   function New_Blob512 return Blob512;

   function Width (Self : Blob512) return Integer;
   function Mode  (Self : Blob512) return Integer;

   procedure Set_Key
     (Self : in out Blob512;
      Slot : Slot_Type;
      Key  : Byte_Array);
   function Get_Key
     (Self : Blob512;
      Slot : Slot_Type) return Byte_Array;

   procedure Set_Components
     (Self  : in out Blob512;
      Slot  : Slot_Type;
      Comps : Component_Array);
   function Get_Components
     (Self : Blob512;
      Slot : Slot_Type) return Component_Array;

   procedure Set_MAC_Key
     (Self : in out Blob512;
      Key  : Byte_Array);
   function Get_MAC_Key (Self : Blob512) return Byte_Array;

   procedure Set_MAC_Name
     (Self : in out Blob512;
      Name : String);
   function Get_MAC_Name (Self : Blob512) return String;

   function Export
     (Self : Blob512;
      Opts : Export_Opts := Opt_None) return Byte_Array;
   procedure Import
     (Self : in out Blob512;
      Blob : Byte_Array);

   function Export_3
     (Self : Blob512;
      Opts : Export_Opts := Opt_None) return Byte_Array;
   procedure Import_3
     (Self : in out Blob512;
      Blob : Byte_Array);

private

   type Blob128 is new Ada.Finalization.Limited_Controlled with record
      Handle : Itb.Sys.Handle := 0;
   end record;

   overriding procedure Finalize (Self : in out Blob128);

   type Blob256 is new Ada.Finalization.Limited_Controlled with record
      Handle : Itb.Sys.Handle := 0;
   end record;

   overriding procedure Finalize (Self : in out Blob256);

   type Blob512 is new Ada.Finalization.Limited_Controlled with record
      Handle : Itb.Sys.Handle := 0;
   end record;

   overriding procedure Finalize (Self : in out Blob512);

end Itb.Blob;
