--  test_driver — runs the binding test roster and reports PASS /
--  FAIL per test in Go-test style. Optional positional argument
--  filters by exact test name (e.g. `test_driver smoke`).
--  Exits 0 when every executed test passed, 1 otherwise.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Strings.Fixed;
with Ada.Text_IO;

with Test_Cases;

procedure Test_Driver is

   Ran      : Natural := 0;
   Failures : Natural := 0;

   function Filter return String is
   begin
      if Ada.Command_Line.Argument_Count >= 1 then
         return Ada.Command_Line.Argument (1);
      end if;
      return "";
   end Filter;

   procedure Run (Name : String; Proc : not null access procedure) is
      Tag : constant String :=
        Ada.Strings.Fixed.Head (Name, 24);
   begin
      if Filter /= "" and then Name /= Filter then
         return;
      end if;
      Ran := Ran + 1;
      begin
         Proc.all;
         Ada.Text_IO.Put_Line (Tag & " PASS");
      exception
         when E : others =>
            Failures := Failures + 1;
            Ada.Text_IO.Put_Line
              (Tag & " FAIL: " & Ada.Exceptions.Exception_Message (E));
      end;
   end Run;

begin
   Run ("smoke", Test_Cases.Smoke'Access);
   Run ("message", Test_Cases.Message'Access);
   Run ("stream_pump", Test_Cases.Stream_Pump'Access);
   Run ("stream_incremental", Test_Cases.Stream_Incremental'Access);
   Run ("stream_sticky", Test_Cases.Stream_Sticky'Access);
   Run ("stream_cancel", Test_Cases.Stream_Cancel'Access);
   Run ("rekey", Test_Cases.Rekey'Access);
   Run ("errors", Test_Cases.Errors'Access);
   Run ("opts", Test_Cases.Opts_Render'Access);

   Ada.Text_IO.Put_Line
     ("ran" & Ran'Image & " tests --"
      & Natural'Image (Ran - Failures) & " PASS,"
      & Failures'Image & " FAIL");
   if Failures > 0 or else Ran = 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_Driver;
