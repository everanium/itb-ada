--  eitb — command-line demonstrator for the ITB Ada binding.
--
--  Subcommands:
--
--    eitb version                                   library + binding versions
--    eitb hashes                                    shipped hash primitive roster
--    eitb encrypt <profile> <in-file> <out-file>    Single Message encrypt
--    eitb decrypt <profile> <blob-hex> <in-file> <out-file>
--
--  `encrypt` prints the session blob to stderr as hex; feed that hex
--  back to `decrypt` on the receiving side.

with Ada.Command_Line;
with Ada.Directories;
with Ada.Exceptions;
with Ada.Streams.Stream_IO;
with Ada.Text_IO;

with Interfaces.C;
with System;

with Itb;
with Itb.Opts;
with Itb.Pipeline;
with Itb.Runtime;

procedure Eitb is

   use Ada.Command_Line;
   use Ada.Text_IO;

   use type Ada.Streams.Stream_Element_Offset;

   Binding_Version : constant String := "0.3.3";

   Hex_Digits : constant String := "0123456789abcdef";

   procedure Usage is
   begin
      Put_Line (Standard_Error, "usage: eitb version");
      Put_Line (Standard_Error, "       eitb hashes");
      Put_Line (Standard_Error,
                "       eitb encrypt <profile> <in-file> <out-file>");
      Put_Line (Standard_Error,
                "       eitb decrypt <profile> <blob-hex> <in-file>"
                & " <out-file>");
      Set_Exit_Status (2);
   end Usage;

   --  Go-runtime pacing caps for the cipher subcommands (matches the
   --  canonical bench configuration).
   procedure Apply_Runtime_Caps is
   begin
      Itb.Runtime.Set_Memory_Limit (536_870_912);  --  512 MiB soft cap
      Itb.Runtime.Set_GC_Percent (20);
   end Apply_Runtime_Caps;

   function Read_File (Name : String) return Itb.Byte_Array_Access is
      use Ada.Streams.Stream_IO;
      F : Ada.Streams.Stream_IO.File_Type;
   begin
      Open (F, In_File, Name);
      declare
         N      : constant Ada.Streams.Stream_Element_Offset :=
           Ada.Streams.Stream_Element_Offset (Size (F));
         Result : constant Itb.Byte_Array_Access :=
           new Itb.Byte_Array (1 .. N);
         Last   : Ada.Streams.Stream_Element_Offset := 0;
      begin
         if N > 0 then
            Read (F, Result.all, Last);
         end if;
         Close (F);
         if Last /= N then
            raise Program_Error with "short read from " & Name;
         end if;
         return Result;
      end;
   end Read_File;

   --  Profiles whose canonical name begins with "streaming-" route
   --  through the one-shot streaming buffered pair instead of the
   --  Single Message pair.
   function Is_Streaming_Profile (Profile : String) return Boolean is
      Prefix : constant String := "streaming-";
   begin
      return Profile'Length >= Prefix'Length
        and then Profile
                   (Profile'First .. Profile'First + Prefix'Length - 1) =
                 Prefix;
   end Is_Streaming_Profile;

   --  Recursively creates the parent directory of Name (analogue of
   --  `mkdir -p $(dirname Name)`). Silent when the directory already
   --  exists.
   procedure Ensure_Parent_Dir (Name : String) is
      Dir : constant String := Ada.Directories.Containing_Directory (Name);
   begin
      if Dir'Length > 0
        and then not Ada.Directories.Exists (Dir)
      then
         Ada.Directories.Create_Path (Dir);
      end if;
   exception
      when Ada.Directories.Name_Error =>
         null;
   end Ensure_Parent_Dir;

   procedure Write_File (Name : String; Content : Itb.Byte_Array) is
      use Ada.Streams.Stream_IO;
      F : Ada.Streams.Stream_IO.File_Type;
   begin
      Ensure_Parent_Dir (Name);
      Create (F, Out_File, Name);
      Write (F, Content);
      Close (F);
   end Write_File;

   function Hex_Encode (B : Itb.Byte_Array) return String is
      Result : String (1 .. Natural (B'Length) * 2);
      J      : Natural := 0;
   begin
      for E of B loop
         Result (J + 1) := Hex_Digits (1 + Natural (E) / 16);
         Result (J + 2) := Hex_Digits (1 + Natural (E) mod 16);
         J := J + 2;
      end loop;
      return Result;
   end Hex_Encode;

   function Nibble (C : Character) return Natural is
   begin
      case C is
         when '0' .. '9' =>
            return Character'Pos (C) - Character'Pos ('0');
         when 'a' .. 'f' =>
            return Character'Pos (C) - Character'Pos ('a') + 10;
         when 'A' .. 'F' =>
            return Character'Pos (C) - Character'Pos ('A') + 10;
         when others =>
            raise Program_Error with "blob hex: invalid digit '" & C & "'";
      end case;
   end Nibble;

   function Hex_Decode (S : String) return Itb.Byte_Array_Access is
   begin
      if S'Length mod 2 /= 0 then
         raise Program_Error with "blob hex has odd length";
      end if;
      declare
         Result : constant Itb.Byte_Array_Access :=
           new Itb.Byte_Array
             (1 .. Ada.Streams.Stream_Element_Offset (S'Length / 2));
         J      : Natural := S'First;
      begin
         for I in Result'Range loop
            Result (I) :=
              Ada.Streams.Stream_Element
                (Nibble (S (J)) * 16 + Nibble (S (J + 1)));
            J := J + 2;
         end loop;
         return Result;
      end;
   end Hex_Decode;

   -----------------
   -- cmd_version --
   -----------------

   procedure Cmd_Version is
   begin
      Put_Line ("libitb " & Itb.Runtime.Version);
      Put_Line ("itb-ada " & Binding_Version);
   end Cmd_Version;

   ----------------
   -- cmd_hashes --
   ----------------

   --  Diagnostic registry iteration. The binding library deliberately
   --  exposes no primitive enumeration; this CLI diagnostic imports
   --  the three iteration symbols itself so the shipped roster can be
   --  inspected from the shell.

   function ITB_HashCount return Interfaces.C.int
   with Import => True, Convention => C, External_Name => "ITB_HashCount";

   function ITB_HashName
     (I       : Interfaces.C.int;
      Out_Buf : System.Address;
      Cap     : Interfaces.C.size_t;
      Out_Len : access Interfaces.C.size_t) return Interfaces.C.int
   with Import => True, Convention => C, External_Name => "ITB_HashName";

   function ITB_HashWidth (I : Interfaces.C.int) return Interfaces.C.int
   with Import => True, Convention => C, External_Name => "ITB_HashWidth";

   procedure Cmd_Hashes is
      use Interfaces.C;
      Count : constant int := ITB_HashCount;
   begin
      for I in 0 .. Integer (Count) - 1 loop
         declare
            Buf     : aliased char_array (1 .. 128) := [others => nul];
            Out_Len : aliased size_t := 0;
            St      : constant int :=
              ITB_HashName (int (I), Buf'Address, Buf'Length,
                            Out_Len'Access);
            Width   : constant int := ITB_HashWidth (int (I));
         begin
            if St /= 0 then
               raise Program_Error
                 with "ITB_HashName (" & I'Image & ") failed with status"
                      & St'Image;
            end if;
            declare
               Name : constant String :=
                 To_Ada (Buf (1 .. Out_Len - 1), Trim_Nul => False);
               Tag  : String (1 .. 12) := [others => ' '];
            begin
               Tag (1 .. Natural'Min (12, Name'Length)) :=
                 Name (Name'First
                       .. Name'First + Natural'Min (12, Name'Length) - 1);
               Put_Line (I'Image & "  " & Tag & Width'Image & " bits");
            end;
         end;
      end loop;
   end Cmd_Hashes;

   -----------------
   -- cmd_encrypt --
   -----------------

   procedure Cmd_Encrypt (Profile, In_File, Out_File : String) is
      O     : Itb.Opts.Opts;
      Pipe  : Itb.Pipeline.Pipeline;
      Plain : Itb.Byte_Array_Access := Read_File (In_File);
   begin
      Apply_Runtime_Caps;
      Pipe.Init (Profile, O);
      declare
         Wire : Itb.Byte_Array_Access :=
           (if Is_Streaming_Profile (Profile) then
               new Itb.Byte_Array'(Pipe.Encrypt_Stream_One_Shot (Plain.all))
            else
               new Itb.Byte_Array'(Pipe.Encrypt_Message (Plain.all)));
      begin
         Write_File (Out_File, Wire.all);
         Put_Line (Standard_Error, Hex_Encode (Pipe.Blob));
         Put_Line
           ("encrypted " & In_File & " -> " & Out_File & " ("
            & Ada.Streams.Stream_Element_Offset'Image (Plain.all'Length)
            & " ->"
            & Ada.Streams.Stream_Element_Offset'Image (Wire.all'Length)
            & " bytes)");
         Itb.Free (Wire);
      end;
      Itb.Free (Plain);
   end Cmd_Encrypt;

   -----------------
   -- cmd_decrypt --
   -----------------

   procedure Cmd_Decrypt (Profile, Blob_Hex, In_File, Out_File : String) is
      O    : Itb.Opts.Opts;
      Pipe : Itb.Pipeline.Pipeline;
      Blob : Itb.Byte_Array_Access := Hex_Decode (Blob_Hex);
      Wire : Itb.Byte_Array_Access := Read_File (In_File);
   begin
      Apply_Runtime_Caps;
      Pipe.Open (Profile, Blob.all, O);
      declare
         Plain : Itb.Byte_Array_Access :=
           (if Is_Streaming_Profile (Profile) then
               new Itb.Byte_Array'(Pipe.Decrypt_Stream_One_Shot (Wire.all))
            else
               new Itb.Byte_Array'(Pipe.Decrypt_Message (Wire.all)));
      begin
         Write_File (Out_File, Plain.all);
         Put_Line
           ("decrypted " & In_File & " -> " & Out_File & " ("
            & Ada.Streams.Stream_Element_Offset'Image (Wire.all'Length)
            & " ->"
            & Ada.Streams.Stream_Element_Offset'Image (Plain.all'Length)
            & " bytes)");
         Itb.Free (Plain);
      end;
      Itb.Free (Blob);
      Itb.Free (Wire);
   end Cmd_Decrypt;

begin
   if Argument_Count = 1 and then Argument (1) = "version" then
      Cmd_Version;
   elsif Argument_Count = 1 and then Argument (1) = "hashes" then
      Cmd_Hashes;
   elsif Argument_Count = 4 and then Argument (1) = "encrypt" then
      Cmd_Encrypt (Argument (2), Argument (3), Argument (4));
   elsif Argument_Count = 5 and then Argument (1) = "decrypt" then
      Cmd_Decrypt (Argument (2), Argument (3), Argument (4), Argument (5));
   else
      Usage;
   end if;
exception
   when E : others =>
      Put_Line
        (Standard_Error,
         "eitb: " & Ada.Exceptions.Exception_Message (E));
      Set_Exit_Status (1);
end Eitb;
