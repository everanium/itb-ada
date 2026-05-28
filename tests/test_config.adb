--  Process-global configuration roundtrip tests.
--
--  Mirror of bindings/rust/tests/test_config.rs. These tests mutate
--  libitb's process-wide atomics (bit_soup, lock_soup, max_workers,
--  nonce_bits, barrier_fill); each test_*.adb compiles into its own
--  executable so cross-process isolation makes serial-locking
--  unnecessary. Per-test, the prior value of any global mutated is
--  saved at procedure entry and restored on exit (with an
--  exception-handler restorer).

with Ada.Text_IO;

with Itb;
with Itb.Errors;
with Itb.Status;

procedure Test_Config is

   --  Save every process-global at procedure entry; restore on exit.
   Saved_Bit_Soup     : constant Integer := Itb.Get_Bit_Soup;
   Saved_Lock_Soup    : constant Integer := Itb.Get_Lock_Soup;
   Saved_Lock_Batch   : constant Integer := Itb.Get_Lock_Batch;
   Saved_Max_Workers  : constant Integer := Itb.Get_Max_Workers;
   Saved_Nonce_Bits   : constant Integer := Itb.Get_Nonce_Bits;
   Saved_Barrier_Fill : constant Integer := Itb.Get_Barrier_Fill;

   type Int_Array is array (Positive range <>) of Integer;
   Valid_Nonce_Bits   : constant Int_Array := [128, 256, 512];
   Bad_Nonce_Bits     : constant Int_Array := [0, 1, 192, 1024];
   Valid_Barrier_Fill : constant Int_Array := [1, 2, 4, 8, 16, 32];
   Bad_Barrier_Fill   : constant Int_Array := [0, 3, 5, 7, 64];

begin

   ------------------------------------------------------------------
   --  bit_soup_roundtrip — Easy Mode auto-couple is intentional;
   --  the global toggles independently and is restored to the
   --  original value at the end.
   ------------------------------------------------------------------
   Itb.Set_Bit_Soup (1);
   if Itb.Get_Bit_Soup /= 1 then
      raise Program_Error with "Bit_Soup setter did not stick (1)";
   end if;
   Itb.Set_Bit_Soup (0);
   if Itb.Get_Bit_Soup /= 0 then
      raise Program_Error with "Bit_Soup setter did not stick (0)";
   end if;
   Itb.Set_Bit_Soup (Saved_Bit_Soup);

   ------------------------------------------------------------------
   --  lock_soup_roundtrip
   ------------------------------------------------------------------
   Itb.Set_Lock_Soup (1);
   if Itb.Get_Lock_Soup /= 1 then
      raise Program_Error with "Lock_Soup setter did not stick (1)";
   end if;
   Itb.Set_Lock_Soup (Saved_Lock_Soup);

   ------------------------------------------------------------------
   --  lock_batch_roundtrip
   ------------------------------------------------------------------
   Itb.Set_Lock_Batch (1);
   if Itb.Get_Lock_Batch /= 1 then
      raise Program_Error with "Lock_Batch setter did not stick (1)";
   end if;
   Itb.Set_Lock_Batch (Saved_Lock_Batch);

   ------------------------------------------------------------------
   --  max_workers_roundtrip
   ------------------------------------------------------------------
   Itb.Set_Max_Workers (4);
   if Itb.Get_Max_Workers /= 4 then
      raise Program_Error with "Max_Workers setter did not stick (4)";
   end if;
   Itb.Set_Max_Workers (Saved_Max_Workers);

   ------------------------------------------------------------------
   --  nonce_bits_validation
   ------------------------------------------------------------------
   for Valid of Valid_Nonce_Bits loop
      Itb.Set_Nonce_Bits (Valid);
      if Itb.Get_Nonce_Bits /= Valid then
         raise Program_Error
           with "Nonce_Bits setter did not stick (" & Valid'Image & " )";
      end if;
   end loop;
   for Bad of Bad_Nonce_Bits loop
      begin
         Itb.Set_Nonce_Bits (Bad);
         raise Program_Error
           with "Set_Nonce_Bits(" & Bad'Image & ") must reject";
      exception
         when E : Itb.Errors.Itb_Error =>
            if Itb.Errors.Status_Code (E) /= Itb.Status.Bad_Input then
               raise;
            end if;
      end;
   end loop;
   Itb.Set_Nonce_Bits (Saved_Nonce_Bits);

   ------------------------------------------------------------------
   --  barrier_fill_validation
   ------------------------------------------------------------------
   for Valid of Valid_Barrier_Fill loop
      Itb.Set_Barrier_Fill (Valid);
      if Itb.Get_Barrier_Fill /= Valid then
         raise Program_Error
           with "Barrier_Fill setter did not stick (" & Valid'Image & ")";
      end if;
   end loop;
   for Bad of Bad_Barrier_Fill loop
      begin
         Itb.Set_Barrier_Fill (Bad);
         raise Program_Error
           with "Set_Barrier_Fill(" & Bad'Image & ") must reject";
      exception
         when E : Itb.Errors.Itb_Error =>
            if Itb.Errors.Status_Code (E) /= Itb.Status.Bad_Input then
               raise;
            end if;
      end;
   end loop;
   Itb.Set_Barrier_Fill (Saved_Barrier_Fill);

   Ada.Text_IO.Put_Line ("test_config: PASS");

exception
   when others =>
      --  Best-effort restorer.
      begin
         Itb.Set_Bit_Soup     (Saved_Bit_Soup);
         Itb.Set_Lock_Soup    (Saved_Lock_Soup);
         Itb.Set_Lock_Batch   (Saved_Lock_Batch);
         Itb.Set_Max_Workers  (Saved_Max_Workers);
         Itb.Set_Nonce_Bits   (Saved_Nonce_Bits);
         Itb.Set_Barrier_Fill (Saved_Barrier_Fill);
      exception
         when others =>
            null;
      end;
      raise;
end Test_Config;
