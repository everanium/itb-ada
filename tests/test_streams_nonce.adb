--  Streaming roundtrips across non-default nonce sizes.
--
--  Mirrors bindings/rust/tests/test_streams_nonce.rs one-to-one. Each
--  test snapshots the original nonce setting on entry and restores it
--  on exit. Each test_*.adb compiles into its own executable and runs
--  in its own process, so cross-test serial-locking is unnecessary.

with Ada.Streams;  use Ada.Streams;
with Ada.Text_IO;
with Ada.Unchecked_Deallocation;

with Itb;          use Itb;
with Itb.Seed;
with Itb.Streams;

procedure Test_Streams_Nonce is

   ------------------------------------------------------------------
   --  In-memory byte stream — same shape as test_streams.adb.
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

   procedure Rewind (S : in out Memory_Stream'Class) is
   begin
      S.Pos := 1;
   end Rewind;

   procedure Drain_Decryptor
     (Dec  : in out Itb.Streams.Stream_Decryptor;
      Sink : in out Memory_Stream)
   is
      Buf  : Byte_Array (1 .. 4096);
      Last : Stream_Element_Offset;
   begin
      loop
         Itb.Streams.Read_Plaintext (Dec, Buf, Last);
         exit when Last < Buf'First;
         Sink.Write (Buf (Buf'First .. Last));
      end loop;
   end Drain_Decryptor;

   procedure Drain_Decryptor_Triple
     (Dec  : in out Itb.Streams.Stream_Decryptor_Triple;
      Sink : in out Memory_Stream)
   is
      Buf  : Byte_Array (1 .. 4096);
      Last : Stream_Element_Offset;
   begin
      loop
         Itb.Streams.Read_Plaintext (Dec, Buf, Last);
         exit when Last < Buf'First;
         Sink.Write (Buf (Buf'First .. Last));
      end loop;
   end Drain_Decryptor_Triple;

   ------------------------------------------------------------------
   --  Helpers
   ------------------------------------------------------------------

   Small_Chunk : constant Stream_Element_Offset := 4096;

   type Int_Array is array (Positive range <>) of Integer;
   Two_Sizes  : constant Int_Array := [256, 512];
   All_Sizes  : constant Int_Array := [128, 256, 512];

   function Pseudo_Payload (N : Stream_Element_Offset) return Byte_Array is
      Result : Byte_Array (1 .. N);
   begin
      for I in Result'Range loop
         Result (I) := Stream_Element (((Integer (I - 1) * 31 + 11) mod 256));
      end loop;
      return Result;
   end Pseudo_Payload;

   Saved_Nonce_Bits : constant Integer := Itb.Get_Nonce_Bits;

begin

   ------------------------------------------------------------------
   --  class_roundtrip_non_default_nonce_single — nonces 256, 512.
   ------------------------------------------------------------------
   declare
      Plain : constant Byte_Array := Pseudo_Payload (Small_Chunk * 3 + 100);
   begin
      for N of Two_Sizes loop
         Itb.Set_Nonce_Bits (N);
         declare
            Noise : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
            Data  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
            Start : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
            Cipher_Mem : aliased Memory_Stream;
            Plain_Mem  : aliased Memory_Stream;
         begin
            declare
               Enc : Itb.Streams.Stream_Encryptor :=
                 Itb.Streams.Make
                   (Noise, Data, Start,
                    Cipher_Mem'Access, Small_Chunk);
            begin
               Itb.Streams.Write_Plaintext (Enc, Plain);
               Itb.Streams.Finish (Enc);
            end;
            Rewind (Cipher_Mem);
            declare
               Dec : Itb.Streams.Stream_Decryptor :=
                 Itb.Streams.Make
                   (Noise, Data, Start, Cipher_Mem'Access);
            begin
               Drain_Decryptor (Dec, Plain_Mem);
               Itb.Streams.Finish (Dec);
            end;
            if Snapshot (Plain_Mem) /= Plain then
               raise Program_Error
                 with "single class roundtrip mismatch nonce=" & N'Image;
            end if;
            Free (Cipher_Mem);
            Free (Plain_Mem);
         end;
      end loop;
   end;

   ------------------------------------------------------------------
   --  encrypt_stream_across_nonce_sizes_single — nonces 128, 256, 512.
   ------------------------------------------------------------------
   declare
      Plain : constant Byte_Array := Pseudo_Payload (Small_Chunk * 3 + 256);
   begin
      for N of All_Sizes loop
         Itb.Set_Nonce_Bits (N);
         declare
            Noise : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
            Data  : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
            Start : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
            Cipher_Mem : aliased Memory_Stream;
            Plain_Mem  : aliased Memory_Stream;
         begin
            declare
               Src : aliased Memory_Stream;
            begin
               Src.Write (Plain);
               Itb.Streams.Encrypt_Stream
                 (Noise, Data, Start, Src'Access,
                  Cipher_Mem'Access, Small_Chunk);
               Free (Src);
            end;
            Rewind (Cipher_Mem);
            Itb.Streams.Decrypt_Stream
              (Noise, Data, Start,
               Cipher_Mem'Access, Plain_Mem'Access, Small_Chunk);
            if Snapshot (Plain_Mem) /= Plain then
               raise Program_Error
                 with "encrypt_stream nonce=" & N'Image & " mismatch";
            end if;
            Free (Cipher_Mem);
            Free (Plain_Mem);
         end;
      end loop;
   end;

   ------------------------------------------------------------------
   --  class_roundtrip_non_default_nonce_triple — nonces 256, 512.
   ------------------------------------------------------------------
   declare
      Plain : constant Byte_Array := Pseudo_Payload (Small_Chunk * 3);
   begin
      for N of Two_Sizes loop
         Itb.Set_Nonce_Bits (N);
         declare
            Noise : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
            D1    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
            D2    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
            D3    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
            S1    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
            S2    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
            S3    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
            Cipher_Mem : aliased Memory_Stream;
            Plain_Mem  : aliased Memory_Stream;
         begin
            declare
               Enc : Itb.Streams.Stream_Encryptor_Triple :=
                 Itb.Streams.Make_Triple
                   (Noise, D1, D2, D3, S1, S2, S3,
                    Cipher_Mem'Access, Small_Chunk);
            begin
               Itb.Streams.Write_Plaintext (Enc, Plain);
               Itb.Streams.Finish (Enc);
            end;
            Rewind (Cipher_Mem);
            declare
               Dec : Itb.Streams.Stream_Decryptor_Triple :=
                 Itb.Streams.Make_Triple
                   (Noise, D1, D2, D3, S1, S2, S3,
                    Cipher_Mem'Access);
            begin
               Drain_Decryptor_Triple (Dec, Plain_Mem);
               Itb.Streams.Finish (Dec);
            end;
            if Snapshot (Plain_Mem) /= Plain then
               raise Program_Error
                 with "triple class roundtrip mismatch nonce=" & N'Image;
            end if;
            Free (Cipher_Mem);
            Free (Plain_Mem);
         end;
      end loop;
   end;

   ------------------------------------------------------------------
   --  encrypt_stream_triple_across_nonce_sizes — nonces 128, 256, 512.
   ------------------------------------------------------------------
   declare
      Plain : constant Byte_Array := Pseudo_Payload (Small_Chunk * 3 + 100);
   begin
      for N of All_Sizes loop
         Itb.Set_Nonce_Bits (N);
         declare
            Noise : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
            D1    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
            D2    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
            D3    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
            S1    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
            S2    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
            S3    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
            Cipher_Mem : aliased Memory_Stream;
            Plain_Mem  : aliased Memory_Stream;
         begin
            declare
               Src : aliased Memory_Stream;
            begin
               Src.Write (Plain);
               Itb.Streams.Encrypt_Stream_Triple
                 (Noise, D1, D2, D3, S1, S2, S3,
                  Src'Access, Cipher_Mem'Access, Small_Chunk);
               Free (Src);
            end;
            Rewind (Cipher_Mem);
            Itb.Streams.Decrypt_Stream_Triple
              (Noise, D1, D2, D3, S1, S2, S3,
               Cipher_Mem'Access, Plain_Mem'Access, Small_Chunk);
            if Snapshot (Plain_Mem) /= Plain then
               raise Program_Error
                 with "encrypt_stream_triple nonce=" & N'Image
                      & " mismatch";
            end if;
            Free (Cipher_Mem);
            Free (Plain_Mem);
         end;
      end loop;
   end;

   Itb.Set_Nonce_Bits (Saved_Nonce_Bits);
   Ada.Text_IO.Put_Line ("test_streams_nonce: PASS");

exception
   when others =>
      begin
         Itb.Set_Nonce_Bits (Saved_Nonce_Bits);
      exception
         when others =>
            null;
      end;
      raise;
end Test_Streams_Nonce;
