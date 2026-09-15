--  bench_stream_one_shot — Encrypt_Stream_One_Shot throughput vs
--  plaintext size (Streaming Non-AEAD profile by default) at
--  1 MiB / 16 MiB / 64 MiB. Times the whole-buffer path (a single
--  FFI round trip through the Pipeline's stream chain).

with Ada.Streams;

with Common;
with Itb3;
with Itb3.Pipeline;
with Itb3.Runtime;

procedure Bench_Stream_One_Shot is

   Sizes : constant array (1 .. 3) of Positive :=
     [1 * 2 ** 20, 16 * 2 ** 20, 64 * 2 ** 20];

   Pipe : Itb3.Pipeline.Pipeline;

begin
   --  Bench-scale allocation churn leaks Go scratch heap unboundedly
   --  without a soft memory cap + aggressive GC.
   Itb3.Runtime.Set_Memory_Limit (4_294_967_296);  --  4 GiB soft cap
   Itb3.Runtime.Set_GC_Percent (100);

   Pipe.Init
     (Common.Profile_Name ("streaming-noaead-triple-v1"),
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
              new Itb3.Byte_Array'(Pipe.Encrypt_Stream_One_Shot (Plain.all));
         begin
            Itb3.Free (Wire);
         end Run;

         procedure Run_Dec is
            Plain_Out : Itb3.Byte_Array_Access :=
              new Itb3.Byte_Array'(Pipe.Decrypt_Stream_One_Shot (Dec_Wire.all));
         begin
            Itb3.Free (Plain_Out);
         end Run_Dec;
      begin
         Common.Fill_Random (Plain.all);
         Common.Bench_Case ("stream_one_shot", Size, Run'Access);
         --  Pre-encrypt one wire outside the decrypt timing loop.
         Dec_Wire :=
           new Itb3.Byte_Array'(Pipe.Encrypt_Stream_One_Shot (Plain.all));
         Common.Bench_Case ("stream_one_shot-dec", Size, Run_Dec'Access);
         Itb3.Free (Dec_Wire);
         Itb3.Free (Plain);
      end;
   end loop;
end Bench_Stream_One_Shot;
