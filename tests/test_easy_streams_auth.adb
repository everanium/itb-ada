--  Authenticated Streaming AEAD tests for the Easy Mode Encryptor
--  (Encryptor.Encrypt_Stream_Auth / Decrypt_Stream_Auth). Mirrors
--  the seed-based suite in test_streams_auth.adb at the Encryptor
--  abstraction level.

with Ada.Streams;  use Ada.Streams;
with Ada.Text_IO;
with Ada.Unchecked_Deallocation;

with Itb;          use Itb;
with Itb.Encryptor;
with Itb.Errors;
with Itb.Status;

procedure Test_Easy_Streams_Auth is

   ------------------------------------------------------------------
   --  Memory_Stream — same shape as test_streams_auth.adb.
   ------------------------------------------------------------------

   type Byte_Buf_Access is access Byte_Array;
   procedure Free_Buf is new Ada.Unchecked_Deallocation
     (Object => Byte_Array, Name => Byte_Buf_Access);

   type Memory_Stream is new Root_Stream_Type with record
      Buf  : Byte_Buf_Access := null;
      Used : Stream_Element_Offset := 0;
      Pos  : Stream_Element_Offset := 1;
   end record;

   overriding procedure Read
     (Self : in out Memory_Stream;
      Item : out Stream_Element_Array;
      Last : out Stream_Element_Offset);

   overriding procedure Write
     (Self : in out Memory_Stream;
      Item : Stream_Element_Array);

   procedure Free (S : in out Memory_Stream'Class);

   procedure Ensure_Cap
     (Self : in out Memory_Stream'Class; Need : Stream_Element_Offset);

   overriding procedure Read
     (Self : in out Memory_Stream;
      Item : out Stream_Element_Array;
      Last : out Stream_Element_Offset)
   is
      Avail : Stream_Element_Offset;
   begin
      if Self.Buf = null or else Self.Pos > Self.Used then
         Last := Item'First - 1;
         return;
      end if;
      Avail := Self.Used - Self.Pos + 1;
      if Avail >= Item'Length then
         Item := Self.Buf (Self.Pos .. Self.Pos + Item'Length - 1);
         Self.Pos := Self.Pos + Item'Length;
         Last := Item'Last;
      else
         Item (Item'First .. Item'First + Avail - 1) :=
           Self.Buf (Self.Pos .. Self.Used);
         Self.Pos := Self.Used + 1;
         Last := Item'First + Avail - 1;
      end if;
   end Read;

   procedure Ensure_Cap
     (Self : in out Memory_Stream'Class; Need : Stream_Element_Offset)
   is
      New_Cap : Stream_Element_Offset;
      New_Buf : Byte_Buf_Access;
   begin
      if Self.Buf = null then
         New_Cap := Stream_Element_Offset'Max (Need, 4096);
         Self.Buf := new Byte_Array (1 .. New_Cap);
         return;
      end if;
      if Need <= Self.Buf'Last then
         return;
      end if;
      New_Cap := Self.Buf'Last;
      while New_Cap < Need loop
         New_Cap := New_Cap * 2;
      end loop;
      New_Buf := new Byte_Array (1 .. New_Cap);
      New_Buf (1 .. Self.Used) := Self.Buf (1 .. Self.Used);
      Free_Buf (Self.Buf);
      Self.Buf := New_Buf;
   end Ensure_Cap;

   overriding procedure Write
     (Self : in out Memory_Stream;
      Item : Stream_Element_Array) is
   begin
      Ensure_Cap (Self, Self.Used + Item'Length);
      Self.Buf (Self.Used + 1 .. Self.Used + Item'Length) := Item;
      Self.Used := Self.Used + Item'Length;
   end Write;

   procedure Free (S : in out Memory_Stream'Class) is
   begin
      if S.Buf /= null then
         Free_Buf (S.Buf);
      end if;
      S.Used := 0;
      S.Pos  := 1;
   end Free;

   function Snapshot (S : Memory_Stream'Class) return Byte_Array is
   begin
      if S.Buf = null or else S.Used = 0 then
         return [1 .. 0 => 0];
      end if;
      return S.Buf (1 .. S.Used);
   end Snapshot;

   ------------------------------------------------------------------
   --  Helpers
   ------------------------------------------------------------------

   Small_Chunk : constant Stream_Element_Offset := 4096;

   function Pseudo_Plaintext (N : Stream_Element_Offset) return Byte_Array is
      Result : Byte_Array (1 .. N);
   begin
      for I in Result'Range loop
         Result (I) := Stream_Element (((Integer (I - 1) * 17 + 3) mod 256));
      end loop;
      return Result;
   end Pseudo_Plaintext;

   ------------------------------------------------------------------
   --  Easy round-trip across (hash × MAC) matrix, Single mode.
   ------------------------------------------------------------------
   procedure Test_Easy_Roundtrip_Single is
      Hashes : constant array (1 .. 3) of String (1 .. 9) :=
        ["siphash24", "blake3   ", "areion512"];
      Hash_Lens : constant array (1 .. 3) of Positive := [9, 6, 9];
      Macs : constant array (1 .. 3) of String (1 .. 11) :=
        ["kmac256    ", "hmac-sha256", "hmac-blake3"];
      Mac_Lens : constant array (1 .. 3) of Positive := [7, 11, 11];
      Plain : constant Byte_Array :=
        Pseudo_Plaintext (Small_Chunk * 2 + 11);
   begin
      for HI in 1 .. 3 loop
         for MI in 1 .. 3 loop
            declare
               Hash_Name : constant String :=
                 Hashes (HI) (1 .. Hash_Lens (HI));
               Mac_Name  : constant String :=
                 Macs (MI) (1 .. Mac_Lens (MI));
               Enc       : Itb.Encryptor.Encryptor :=
                 Itb.Encryptor.Make
                   (Hash_Name, 1024, Mac_Name, 1);
               Source    : aliased Memory_Stream;
               CMem      : aliased Memory_Stream;
               PMem      : aliased Memory_Stream;
            begin
               Source.Write (Plain);
               Source.Pos := 1;
               Itb.Encryptor.Encrypt_Stream_Auth
                 (Enc, Source'Access, CMem'Access, Small_Chunk);
               Itb.Encryptor.Decrypt_Stream_Auth
                 (Enc, CMem'Access, PMem'Access, 4096);
               if Snapshot (PMem) /= Plain then
                  raise Program_Error
                    with "Easy single auth roundtrip mismatch: "
                         & Hash_Name & "/" & Mac_Name;
               end if;
               Free (Source);
               Free (CMem);
               Free (PMem);
            end;
         end loop;
      end loop;
   end Test_Easy_Roundtrip_Single;

   ------------------------------------------------------------------
   --  Easy round-trip across MACs, Triple mode.
   ------------------------------------------------------------------
   procedure Test_Easy_Roundtrip_Triple is
      Macs : constant array (1 .. 3) of String (1 .. 11) :=
        ["kmac256    ", "hmac-sha256", "hmac-blake3"];
      Mac_Lens : constant array (1 .. 3) of Positive := [7, 11, 11];
      Plain : constant Byte_Array :=
        Pseudo_Plaintext (Small_Chunk * 2 + 7);
   begin
      for MI in 1 .. 3 loop
         declare
            MN     : constant String := Macs (MI) (1 .. Mac_Lens (MI));
            Enc    : Itb.Encryptor.Encryptor :=
              Itb.Encryptor.Make ("blake3", 1024, MN, 3);
            Source : aliased Memory_Stream;
            CMem   : aliased Memory_Stream;
            PMem   : aliased Memory_Stream;
         begin
            Source.Write (Plain);
            Source.Pos := 1;
            Itb.Encryptor.Encrypt_Stream_Auth
              (Enc, Source'Access, CMem'Access, Small_Chunk);
            Itb.Encryptor.Decrypt_Stream_Auth
              (Enc, CMem'Access, PMem'Access, 4096);
            if Snapshot (PMem) /= Plain then
               raise Program_Error
                 with "Easy triple auth roundtrip mismatch: " & MN;
            end if;
            Free (Source);
            Free (CMem);
            Free (PMem);
         end;
      end loop;
   end Test_Easy_Roundtrip_Triple;

   ------------------------------------------------------------------
   --  Empty stream.
   ------------------------------------------------------------------
   procedure Test_Easy_Empty is
      Enc    : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "hmac-blake3", 1);
      Source : aliased Memory_Stream;
      CMem   : aliased Memory_Stream;
      PMem   : aliased Memory_Stream;
   begin
      Itb.Encryptor.Encrypt_Stream_Auth
        (Enc, Source'Access, CMem'Access, Small_Chunk);
      if Snapshot (CMem)'Length <= 32 then
         raise Program_Error with "empty stream lacks prefix + 1 chunk";
      end if;
      Itb.Encryptor.Decrypt_Stream_Auth
        (Enc, CMem'Access, PMem'Access, 4096);
      if Snapshot (PMem)'Length /= 0 then
         raise Program_Error with "empty stream recovered non-zero bytes";
      end if;
      Free (Source);
      Free (CMem);
      Free (PMem);
   end Test_Easy_Empty;

   ------------------------------------------------------------------
   --  Closed-state preflight: encrypt / decrypt after Close raises.
   ------------------------------------------------------------------
   procedure Test_Easy_Closed_Preflight is
      Enc    : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "hmac-blake3", 1);
      Source : aliased Memory_Stream;
      Sink   : aliased Memory_Stream;
   begin
      Itb.Encryptor.Close (Enc);
      declare
         Got_Expected : Boolean := False;
      begin
         begin
            Itb.Encryptor.Encrypt_Stream_Auth
              (Enc, Source'Access, Sink'Access, Small_Chunk);
         exception
            when E : Itb.Errors.Itb_Error =>
               if Itb.Errors.Status_Code (E) =
                    Itb.Status.Easy_Closed
               then
                  Got_Expected := True;
               end if;
         end;
         if not Got_Expected then
            raise Program_Error with "encrypt after close did not raise";
         end if;
      end;
      declare
         Got_Expected : Boolean := False;
      begin
         begin
            Itb.Encryptor.Decrypt_Stream_Auth
              (Enc, Source'Access, Sink'Access, 4096);
         exception
            when E : Itb.Errors.Itb_Error =>
               if Itb.Errors.Status_Code (E) =
                    Itb.Status.Easy_Closed
               then
                  Got_Expected := True;
               end if;
         end;
         if not Got_Expected then
            raise Program_Error with "decrypt after close did not raise";
         end if;
      end;
      Free (Source);
      Free (Sink);
   end Test_Easy_Closed_Preflight;

   ------------------------------------------------------------------
   --  Truncate-tail (drop everything past the partial prefix).
   ------------------------------------------------------------------
   procedure Test_Easy_Truncate_Below_Prefix is
      Enc    : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "hmac-blake3", 1);
      Plain  : constant Byte_Array := Pseudo_Plaintext (64);
      Source : aliased Memory_Stream;
      CMem   : aliased Memory_Stream;
      Trunc  : aliased Memory_Stream;
      PMem   : aliased Memory_Stream;
   begin
      Source.Write (Plain);
      Source.Pos := 1;
      Itb.Encryptor.Encrypt_Stream_Auth
        (Enc, Source'Access, CMem'Access, Small_Chunk);
      Trunc.Write (Snapshot (CMem) (1 .. 16));  --  Less than 32 bytes.
      declare
         Got_Expected : Boolean := False;
      begin
         begin
            Itb.Encryptor.Decrypt_Stream_Auth
              (Enc, Trunc'Access, PMem'Access, 4096);
         exception
            when E : Itb.Errors.Itb_Error =>
               if Itb.Errors.Status_Code (E) = Itb.Status.Bad_Input
               then
                  Got_Expected := True;
               end if;
         end;
         if not Got_Expected then
            raise Program_Error
              with "partial-prefix did not raise Bad_Input";
         end if;
      end;
      Free (Source);
      Free (CMem);
      Free (Trunc);
      Free (PMem);
   end Test_Easy_Truncate_Below_Prefix;

begin
   Test_Easy_Roundtrip_Single;
   Test_Easy_Roundtrip_Triple;
   Test_Easy_Empty;
   Test_Easy_Closed_Preflight;
   Test_Easy_Truncate_Below_Prefix;
   Ada.Text_IO.Put_Line ("test_easy_streams_auth: PASS");
end Test_Easy_Streams_Auth;
