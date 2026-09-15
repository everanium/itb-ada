--  bench_message — Encrypt_Message throughput vs plaintext size
--  (Single Message profile) at 1 MiB / 16 MiB / 64 MiB.

with Ada.Streams;

with Common;
with Itb3;
with Itb3.Pipeline;
with Itb3.Runtime;

procedure Bench_Message is

   Sizes : constant array (1 .. 3) of Positive :=
     [1 * 2 ** 20, 16 * 2 ** 20, 64 * 2 ** 20];

   Pipe : Itb3.Pipeline.Pipeline;

begin
   --  Bench-scale allocation churn leaks Go scratch heap unboundedly
   --  without a soft memory cap + aggressive GC.
   Itb3.Runtime.Set_Memory_Limit (4_294_967_296);  --  4 GiB soft cap
   Itb3.Runtime.Set_GC_Percent (100);

   Pipe.Init
     (Common.Profile_Name ("singlemsg-triple-nomac-v1"),
      Common.Build_Opts);
   Common.Bench_Header;

   for Size of Sizes loop
      declare
         Plain : Itb3.Byte_Array_Access :=
           new Itb3.Byte_Array
             (1 .. Ada.Streams.Stream_Element_Offset (Size));

         Dec_Wire : Itb3.Byte_Array_Access;

         procedure Run is
            --  Build-in-place into a heap object — a stack-declared
            --  result would overflow the primary stack at 64 MiB.
            Wire : Itb3.Byte_Array_Access :=
              new Itb3.Byte_Array'(Pipe.Encrypt_Message (Plain.all));
         begin
            Itb3.Free (Wire);
         end Run;

         procedure Run_Dec is
            Plain_Out : Itb3.Byte_Array_Access :=
              new Itb3.Byte_Array'(Pipe.Decrypt_Message (Dec_Wire.all));
         begin
            Itb3.Free (Plain_Out);
         end Run_Dec;
      begin
         Common.Fill_Random (Plain.all);
         Common.Bench_Case ("message", Size, Run'Access);
         --  Pre-encrypt one wire outside the decrypt timing loop.
         Dec_Wire :=
           new Itb3.Byte_Array'(Pipe.Encrypt_Message (Plain.all));
         Common.Bench_Case ("message-dec", Size, Run_Dec'Access);
         Itb3.Free (Dec_Wire);
         Itb3.Free (Plain);
      end;
   end loop;
end Bench_Message;
