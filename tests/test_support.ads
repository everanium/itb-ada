--  Test_Support — shared assertion helper + payload generator for
--  the Itb binding test suite.

with Interfaces;

with Itb;

package Test_Support is

   --  Raised by every failed check; the driver catches it per test
   --  and reports FAIL with the attached label.
   Test_Failure : exception;

   --  Raises Test_Failure with Label unless Cond holds.
   procedure Check (Cond : Boolean; Label : String);

   --  Byte-wise equality check between two buffers.
   procedure Check_Eq (Got, Want : Itb.Byte_Array; Label : String);

   --  Deterministic non-trivial payload (xorshift fill), 1-based.
   function Payload
     (N : Positive; Seed : Interfaces.Unsigned_64) return Itb.Byte_Array;

end Test_Support;
