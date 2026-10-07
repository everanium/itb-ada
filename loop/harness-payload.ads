--  Plaintext content: the payload modes, the seeded per-worker
--  generator, and the buffer fill from the operating-system CSPRNG.

with Interfaces;

package Harness.Payload is

   function Payload_Mode_Name (Mode : Payload_Kind) return String;

   function Parse_Payload_Mode
     (Text : String; Mode : out Payload_Kind) return Boolean;

   --  Seeded plaintext. The seed makes plaintext content reproducible
   --  so a failing iteration can be replayed with the same bytes; it
   --  governs nothing else -- pipeline keys, nonces and masters stay
   --  CSPRNG-drawn, so a seeded run is a reproduction aid and never a
   --  security test. Each worker's stream is domain-separated by its
   --  id so seeded workers still hold pairwise-distinct buffers under
   --  the fixed and rotating modes. The generator is splitmix64: a
   --  few lines in any language, which is why it is the one every
   --  binding uses.
   function Seed_Worker
     (Seed : Interfaces.Unsigned_64; Worker_Id : Natural)
      return Interfaces.Unsigned_64;

   --  Writes one plaintext buffer according to the payload mode. The
   --  fixed and rotating modes draw from the seeded generator when
   --  the run is seeded and from the OS CSPRNG otherwise; the pattern
   --  modes are deterministic regardless of the seed.
   function Fill_Payload
     (Mode   : Payload_Kind;
      Seeded : Boolean;
      RNG    : in out Interfaces.Unsigned_64;
      Buffer : in out Byte_Array) return Boolean;

end Harness.Payload;
