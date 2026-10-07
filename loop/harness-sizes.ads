--  Size and duration parsing, the monotonic clock, and the human
--  renderings of sizes, rates and durations. Every rendering here is
--  part of the output contract shared with the Go harness and the
--  other bindings' loop utilities, so the formats are fixed to the
--  character, not to taste.

with Interfaces;

package Harness.Sizes is

   --  Parses a human byte-size string ("16MB", "1MiB", "512K",
   --  "1073741824") into a byte count. Every suffix is a binary
   --  multiple: K/KB/KiB = 1024, M/MB/MiB = 1024**2, G/GB/GiB =
   --  1024**3, B or none = bytes; matching is case-insensitive and
   --  surrounding whitespace is trimmed.
   function Parse_Size (Text : String; Value : out Count) return Boolean;

   --  Parses the Go duration grammar -- a sequence of decimal numbers
   --  each followed by a unit (h, m, s, ms, us, ns), such as "30s",
   --  "5m", "1h30m", "3s500ms", "1.5s" -- into nanoseconds.
   function Parse_Duration (Text : String; Value : out Count) return Boolean;

   --  Parses an unsigned decimal integer. Rejects an empty string, a
   --  non-digit, and a value above 2**64 - 1.
   function Parse_U64
     (Text : String; Value : out Interfaces.Unsigned_64) return Boolean;

   --  Monotonic wall clock in nanoseconds.
   function Now_NS return Count;

   --  Renders a byte count with a binary-unit suffix: "1.0GiB",
   --  "16.0MiB", "4.0KiB", "512B".
   function Human_Bytes (N : Count) return String;

   --  Renders a possibly-negative byte delta with an explicit sign.
   function Human_Bytes_Signed (N : Count) return String;

   --  Renders a throughput as "123.4MB/s" (binary MiB per second) or
   --  "n/a" for an unmeasured window.
   function Human_Rate (Bytes : Count; NS : Count) return String;

   --  Renders a duration the way Go's time.Duration prints: below one
   --  second as milliseconds ("900ms", "1.5ms"); otherwise
   --  "[Hh][Mm]Ss" where the hour part appears when non-zero, the
   --  minute part when the hour part appears or the minutes are
   --  non-zero, and the seconds carry their fraction with trailing
   --  zeros removed ("5s", "5.003s", "1m0s", "1m5.25s", "1h0m0s").
   --  The caller rounds first.
   function Human_Duration (NS : Count) return String;

   --  Binary MiB per second over a nanosecond window; zero when the
   --  window is unmeasured.
   function MB_Per_Sec (Bytes : Count; NS : Count) return Long_Float;

   --  Fixed-point rendering with Aft decimals and no exponent.
   function Fixed (X : Long_Float; Aft : Natural) return String;

end Harness.Sizes;
