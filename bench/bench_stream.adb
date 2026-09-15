--  bench_stream — incremental stream-pump encrypt throughput vs
--  plaintext size (Streaming Non-AEAD profile by default) at
--  1 MiB / 16 MiB / 64 MiB. Each iteration opens a session, feeds
--  the plaintext in 1 MiB slices, drains produced wire into an
--  accumulation buffer, and finishes the session — mirroring the
--  reference pump loops.

with Ada.Streams;

with Common;
with Itb3;
with Itb3.Pipeline;
with Itb3.Runtime;
with Itb3.Stream;

procedure Bench_Stream is

   use type Ada.Streams.Stream_Element_Offset;

   subtype Offset is Ada.Streams.Stream_Element_Offset;

   Slice : constant Offset := 2 ** 20;

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
         N        : constant Offset := Offset (Size);
         Plain    : Itb3.Byte_Array_Access := new Itb3.Byte_Array (1 .. N);
         Scratch  : Itb3.Byte_Array_Access :=
           new Itb3.Byte_Array (1 .. Slice);
         Dec_Wire : Itb3.Byte_Array_Access;
         Dec_Len  : Offset := 0;

         procedure Run is
            Sess : Itb3.Stream.Encrypt_Stream;
            Wire : Itb3.Byte_Array_Access :=
              new Itb3.Byte_Array (1 .. N + N / 4 + 131_072);
            Wpos : Offset := 0;
            Pos  : Offset := 1;
            Last : Offset;
            Fin  : Boolean;
         begin
            Sess.Begin_Encrypt (Pipe);
            while Pos <= N loop
               declare
                  Hi : constant Offset := Offset'Min (Pos + Slice - 1, N);
               begin
                  Sess.Write (Plain.all (Pos .. Hi));
                  Pos := Hi + 1;
               end;
               loop
                  Sess.Read (Scratch.all, Last, Fin);
                  exit when Last < Scratch.all'First;
                  Wire.all (Wpos + 1 .. Wpos + Last) :=
                    Scratch.all (1 .. Last);
                  Wpos := Wpos + Last;
               end loop;
            end loop;
            Sess.Finish;
            loop
               Sess.Read (Scratch.all, Last, Fin);
               if Last >= Scratch.all'First then
                  Wire.all (Wpos + 1 .. Wpos + Last) :=
                    Scratch.all (1 .. Last);
                  Wpos := Wpos + Last;
               end if;
               exit when Fin;
            end loop;
            Itb3.Free (Wire);
         end Run;

         procedure Run_Dec is
            Sess : Itb3.Stream.Decrypt_Stream;
            Out_Buf : Itb3.Byte_Array_Access :=
              new Itb3.Byte_Array (1 .. N + 131_072);
            Wpos : Offset := 0;
            Pos  : Offset := 1;
            Last : Offset;
            Fin  : Boolean;
         begin
            Sess.Begin_Decrypt (Pipe);
            while Pos <= Dec_Len loop
               declare
                  Hi : constant Offset :=
                    Offset'Min (Pos + Slice - 1, Dec_Len);
               begin
                  Sess.Write (Dec_Wire.all (Pos .. Hi));
                  Pos := Hi + 1;
               end;
               loop
                  Sess.Read (Scratch.all, Last, Fin);
                  exit when Last < Scratch.all'First;
                  Out_Buf.all (Wpos + 1 .. Wpos + Last) :=
                    Scratch.all (1 .. Last);
                  Wpos := Wpos + Last;
               end loop;
            end loop;
            Sess.Finish;
            loop
               Sess.Read (Scratch.all, Last, Fin);
               if Last >= Scratch.all'First then
                  Out_Buf.all (Wpos + 1 .. Wpos + Last) :=
                    Scratch.all (1 .. Last);
                  Wpos := Wpos + Last;
               end if;
               exit when Fin;
            end loop;
            Itb3.Free (Out_Buf);
         end Run_Dec;

         --  Pre-encrypt once outside the decrypt timing loop; the
         --  same block is Written back for every decrypt iteration.
         procedure Setup_Dec_Wire is
            Sess : Itb3.Stream.Encrypt_Stream;
            Buf  : Itb3.Byte_Array_Access :=
              new Itb3.Byte_Array (1 .. N + N / 4 + 131_072);
            Wpos : Offset := 0;
            Pos  : Offset := 1;
            Last : Offset;
            Fin  : Boolean;
         begin
            Sess.Begin_Encrypt (Pipe);
            while Pos <= N loop
               declare
                  Hi : constant Offset := Offset'Min (Pos + Slice - 1, N);
               begin
                  Sess.Write (Plain.all (Pos .. Hi));
                  Pos := Hi + 1;
               end;
               loop
                  Sess.Read (Scratch.all, Last, Fin);
                  exit when Last < Scratch.all'First;
                  Buf.all (Wpos + 1 .. Wpos + Last) :=
                    Scratch.all (1 .. Last);
                  Wpos := Wpos + Last;
               end loop;
            end loop;
            Sess.Finish;
            loop
               Sess.Read (Scratch.all, Last, Fin);
               if Last >= Scratch.all'First then
                  Buf.all (Wpos + 1 .. Wpos + Last) :=
                    Scratch.all (1 .. Last);
                  Wpos := Wpos + Last;
               end if;
               exit when Fin;
            end loop;
            --  Trim to actual length via a copy.
            Dec_Wire := new Itb3.Byte_Array'(Buf.all (1 .. Wpos));
            Dec_Len  := Wpos;
            Itb3.Free (Buf);
         end Setup_Dec_Wire;
      begin
         Common.Fill_Random (Plain.all);
         Common.Bench_Case ("stream_pump", Size, Run'Access);
         Setup_Dec_Wire;
         Common.Bench_Case ("stream_pump-dec", Size, Run_Dec'Access);
         Itb3.Free (Dec_Wire);
         Itb3.Free (Plain);
         Itb3.Free (Scratch);
      end;
   end loop;
end Bench_Stream;
