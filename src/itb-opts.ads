--  Itb.Opts — URL-query builder for the opts pass-through string.
--
--  The builder performs no validation: every key and value is
--  rendered into a percent-encoded query string and passed through
--  to Go verbatim; libitb rejects unknown keys or bad values with a
--  diagnostic surfaced via Itb.Error. Primitive / MAC / cipher /
--  palette names are opaque strings.

private with Ada.Strings.Unbounded;

package Itb.Opts is

   --  Accumulates key=value pairs in call order. The default value
   --  renders as the empty query (profile defaults apply).
   type Opts is tagged private;

   --  Escape hatch appending a raw key=value pair. Covers every key
   --  the Go side accepts for Init overrides. Profile registration
   --  takes a profile JSON record instead (see Itb.Pipeline.Register).
   procedure Set (O : in out Opts; Key : String; Value : String);

   --  Typed setters over the common keys. Each renders onto the same
   --  pass-through query string as Set.
   procedure Set_Perm_Master (O : in out Opts; Master : Byte_Array);
   procedure Set_Wrap_Master (O : in out Opts; Master : Byte_Array);
   procedure Set_With_Parallax (O : in out Opts; On : Boolean);
   procedure Set_With_Wrapper (O : in out Opts; On : Boolean);
   procedure Set_Max_Workers (O : in out Opts; N : Integer);
   procedure Set_Nonce_Bits (O : in out Opts; N : Integer);
   procedure Set_Barrier_Fill (O : in out Opts; N : Integer);
   procedure Set_Chunk_Size (O : in out Opts; N : Integer);
   procedure Set_Key_Bits (O : in out Opts; N : Integer);
   procedure Set_Parallax_Segment_Size (O : in out Opts; N : Integer);
   procedure Set_MAC_Name (O : in out Opts; Name : String);
   procedure Set_Inner_Hash (O : in out Opts; Name : String);

   --  Per-call constellation override mirroring the Go-side
   --  Opts.MixedHashes [8]string field: the 8 slot names are joined
   --  into the "innerHashes" pass-through key in the slot order
   --  [noise, lock, data1, data2, data3, start1, start2, start3]
   --  and re-parsed by Go into the per-call MixedHashes vector.
   --  Fail-fast validation surfaces at Init on the Go side; a typo'd
   --  slot or width mismatch surfaces with an error naming the
   --  offending slot. When both this and Set_Inner_Hash are set,
   --  the mixed override wins on the Go side.
   procedure Set_Inner_Hashes (O : in out Opts; Names : String);

   procedure Set_Outer_Cipher (O : in out Opts; Name : String);

   --  Comma-separated palette names, passed through opaquely
   --  ("parallaxPalette").
   procedure Set_Parallax_Palette (O : in out Opts; Names : String);

   --  Renders the accumulated pairs as a query string
   --  ("k1=v1&k2=v2&...", percent-encoded).
   function Build (O : Opts) return String;

private

   type Opts is tagged record
      Query : Ada.Strings.Unbounded.Unbounded_String;
   end record;

end Itb.Opts;
