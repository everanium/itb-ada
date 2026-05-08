--  Streaming wrapper tests under the default-nonce configuration.
--
--  Mirrors bindings/rust/tests/test_streams.rs one-to-one. Exercises
--  Stream_Encryptor / Stream_Decryptor (Single + Triple) plus the
--  free-subprogram convenience drivers Encrypt_Stream / Decrypt_Stream
--  via in-memory Ada.Streams.Root_Stream_Type subclasses so no file
--  I/O is needed.

with Ada.Streams;  use Ada.Streams;
with Ada.Text_IO;
with Ada.Unchecked_Deallocation;

with Itb;          use Itb;
with Itb.Errors;
with Itb.Seed;
with Itb.Status;
with Itb.Streams;

procedure Test_Streams is

   ------------------------------------------------------------------
   --  In-memory byte stream — supports Read (advancing a cursor) and
   --  Write (appending to a heap buffer). Used to replace Cursor /
   --  Vec<u8> from the Rust source.
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

   --  Returns a fresh copy of the stream's accumulated bytes.
   function Snapshot (S : Memory_Stream'Class) return Byte_Array is
   begin
      if S.Buf = null or else S.Used = 0 then
         return [1 .. 0 => 0];
      end if;
      return S.Buf (1 .. S.Used);
   end Snapshot;

   --  Resets the read cursor so the same buffer can be replayed by a
   --  decryptor; bytes already in the buffer are kept.
   procedure Rewind (S : in out Memory_Stream'Class) is
   begin
      S.Pos := 1;
   end Rewind;

   ------------------------------------------------------------------
   --  Helpers
   ------------------------------------------------------------------

   Small_Chunk : constant Stream_Element_Offset := 4096;

   function Pseudo_Plaintext (N : Stream_Element_Offset) return Byte_Array is
      Result : Byte_Array (1 .. N);
   begin
      for I in Result'Range loop
         Result (I) := Stream_Element ((Integer (I - 1) mod 256));
      end loop;
      return Result;
   end Pseudo_Plaintext;

   function Pseudo_Payload (N : Stream_Element_Offset) return Byte_Array is
      Result : Byte_Array (1 .. N);
   begin
      for I in Result'Range loop
         Result (I) := Stream_Element (((Integer (I - 1) * 13 + 11) mod 256));
      end loop;
      return Result;
   end Pseudo_Payload;

   --  Drains a Stream_Decryptor / Stream_Decryptor_Triple into a
   --  Memory_Stream sink one buffer at a time. Each call returns the
   --  total decoded plaintext.
   procedure Drain_Decryptor
     (Dec  : in out Itb.Streams.Stream_Decryptor;
      Sink : in out Memory_Stream)
   is
      Buf  : Byte_Array (1 .. Small_Chunk);
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
      Buf  : Byte_Array (1 .. Small_Chunk);
      Last : Stream_Element_Offset;
   begin
      loop
         Itb.Streams.Read_Plaintext (Dec, Buf, Last);
         exit when Last < Buf'First;
         Sink.Write (Buf (Buf'First .. Last));
      end loop;
   end Drain_Decryptor_Triple;

begin

   ------------------------------------------------------------------
   --  stream_single_roundtrip_200kb
   ------------------------------------------------------------------
   declare
      Plain : constant Byte_Array := Pseudo_Plaintext (200 * 1024);
      N : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      D : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Cipher_Mem : aliased Memory_Stream;
      Plain_Mem  : aliased Memory_Stream;
   begin
      declare
         Src : aliased Memory_Stream;
      begin
         Src.Write (Plain);
         Itb.Streams.Encrypt_Stream
           (N, D, S, Src'Access, Cipher_Mem'Access, 64 * 1024);
         Free (Src);
      end;
      if Cipher_Mem.Used = 0 then
         raise Program_Error with "Encrypt_Stream produced zero bytes";
      end if;
      if Snapshot (Cipher_Mem) = Plain then
         raise Program_Error with "ciphertext equals plaintext";
      end if;

      Rewind (Cipher_Mem);
      Itb.Streams.Decrypt_Stream
        (N, D, S, Cipher_Mem'Access, Plain_Mem'Access, 4096);
      if Snapshot (Plain_Mem) /= Plain then
         raise Program_Error with "200kb single roundtrip mismatch";
      end if;
      Free (Cipher_Mem);
      Free (Plain_Mem);
   end;

   ------------------------------------------------------------------
   --  stream_single_roundtrip_short_payload — payload smaller than
   --  chunk size exercises the close-flush path.
   ------------------------------------------------------------------
   declare
      Plain : constant String :=
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
      Plain_Bytes : Byte_Array (1 .. Stream_Element_Offset (Plain'Length));
      N : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      D : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Cipher_Mem : aliased Memory_Stream;
      Plain_Mem  : aliased Memory_Stream;
   begin
      for I in Plain'Range loop
         Plain_Bytes (Stream_Element_Offset (I - Plain'First + 1)) :=
           Stream_Element (Character'Pos (Plain (I)));
      end loop;
      declare
         Src : aliased Memory_Stream;
      begin
         Src.Write (Plain_Bytes);
         Itb.Streams.Encrypt_Stream
           (N, D, S, Src'Access, Cipher_Mem'Access, 64 * 1024);
         Free (Src);
      end;
      Rewind (Cipher_Mem);
      Itb.Streams.Decrypt_Stream
        (N, D, S, Cipher_Mem'Access, Plain_Mem'Access, 64 * 1024);
      if Snapshot (Plain_Mem) /= Plain_Bytes then
         raise Program_Error with "short payload roundtrip mismatch";
      end if;
      Free (Cipher_Mem);
      Free (Plain_Mem);
   end;

   ------------------------------------------------------------------
   --  stream_encryptor_struct_api — chunked Write / Finish on the
   --  encryptor; feed-and-Finish on the decryptor.
   ------------------------------------------------------------------
   declare
      Part1 : constant String := "first chunk ";
      Part2 : constant String := "second chunk ";
      Part3 : constant String := "third chunk";
      P1, P2, P3 : Byte_Array (1 .. 64);
      Last1 : constant Stream_Element_Offset :=
        Stream_Element_Offset (Part1'Length);
      Last2 : constant Stream_Element_Offset :=
        Stream_Element_Offset (Part2'Length);
      Last3 : constant Stream_Element_Offset :=
        Stream_Element_Offset (Part3'Length);
      N : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      D : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Cipher_Mem : aliased Memory_Stream;
      Plain_Mem  : aliased Memory_Stream;
      Expected   : Byte_Array (1 .. Last1 + Last2 + Last3);
   begin
      for I in Part1'Range loop
         P1 (Stream_Element_Offset (I - Part1'First + 1)) :=
           Stream_Element (Character'Pos (Part1 (I)));
      end loop;
      for I in Part2'Range loop
         P2 (Stream_Element_Offset (I - Part2'First + 1)) :=
           Stream_Element (Character'Pos (Part2 (I)));
      end loop;
      for I in Part3'Range loop
         P3 (Stream_Element_Offset (I - Part3'First + 1)) :=
           Stream_Element (Character'Pos (Part3 (I)));
      end loop;
      Expected (1 .. Last1) := P1 (1 .. Last1);
      Expected (Last1 + 1 .. Last1 + Last2) := P2 (1 .. Last2);
      Expected (Last1 + Last2 + 1 .. Expected'Last) := P3 (1 .. Last3);

      declare
         Enc : Itb.Streams.Stream_Encryptor :=
           Itb.Streams.Make (N, D, S, Cipher_Mem'Access, 64 * 1024);
      begin
         Itb.Streams.Write_Plaintext (Enc, P1 (1 .. Last1));
         Itb.Streams.Write_Plaintext (Enc, P2 (1 .. Last2));
         Itb.Streams.Write_Plaintext (Enc, P3 (1 .. Last3));
         Itb.Streams.Finish (Enc);
      end;

      Rewind (Cipher_Mem);
      declare
         Dec : Itb.Streams.Stream_Decryptor :=
           Itb.Streams.Make (N, D, S, Cipher_Mem'Access);
      begin
         Drain_Decryptor (Dec, Plain_Mem);
         Itb.Streams.Finish (Dec);
      end;
      if Snapshot (Plain_Mem) /= Expected then
         raise Program_Error with "encryptor struct API mismatch";
      end if;
      Free (Cipher_Mem);
      Free (Plain_Mem);
   end;

   ------------------------------------------------------------------
   --  test_class_roundtrip_default_nonce — three irregular slices.
   ------------------------------------------------------------------
   declare
      Plain : constant Byte_Array :=
        Pseudo_Payload (Small_Chunk * 5 + 17);
      N : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      D : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Cipher_Mem : aliased Memory_Stream;
      Plain_Mem  : aliased Memory_Stream;
   begin
      declare
         Enc : Itb.Streams.Stream_Encryptor :=
           Itb.Streams.Make (N, D, S, Cipher_Mem'Access, Small_Chunk);
      begin
         Itb.Streams.Write_Plaintext (Enc, Plain (1 .. 1000));
         Itb.Streams.Write_Plaintext (Enc, Plain (1001 .. 5000));
         Itb.Streams.Write_Plaintext (Enc, Plain (5001 .. Plain'Last));
         Itb.Streams.Finish (Enc);
      end;
      Rewind (Cipher_Mem);
      declare
         Dec : Itb.Streams.Stream_Decryptor :=
           Itb.Streams.Make (N, D, S, Cipher_Mem'Access);
      begin
         Drain_Decryptor (Dec, Plain_Mem);
         Itb.Streams.Finish (Dec);
      end;
      if Snapshot (Plain_Mem) /= Plain then
         raise Program_Error
           with "irregular-slice roundtrip mismatch";
      end if;
      Free (Cipher_Mem);
      Free (Plain_Mem);
   end;

   ------------------------------------------------------------------
   --  test_encrypt_stream_decrypt_stream
   ------------------------------------------------------------------
   declare
      Plain : constant Byte_Array := Pseudo_Payload (Small_Chunk * 4);
      N : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      D : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Cipher_Mem : aliased Memory_Stream;
      Plain_Mem  : aliased Memory_Stream;
   begin
      declare
         Src : aliased Memory_Stream;
      begin
         Src.Write (Plain);
         Itb.Streams.Encrypt_Stream
           (N, D, S, Src'Access, Cipher_Mem'Access, Small_Chunk);
         Free (Src);
      end;
      Rewind (Cipher_Mem);
      Itb.Streams.Decrypt_Stream
        (N, D, S, Cipher_Mem'Access, Plain_Mem'Access, Small_Chunk);
      if Snapshot (Plain_Mem) /= Plain then
         raise Program_Error
           with "encrypt_stream/decrypt_stream mismatch";
      end if;
      Free (Cipher_Mem);
      Free (Plain_Mem);
   end;

   ------------------------------------------------------------------
   --  test_class_roundtrip_default_nonce_triple
   ------------------------------------------------------------------
   declare
      Plain : constant Byte_Array :=
        Pseudo_Payload (Small_Chunk * 4 + 33);
      S0 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S1 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S2 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S3 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S4 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S5 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S6 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Cipher_Mem : aliased Memory_Stream;
      Plain_Mem  : aliased Memory_Stream;
   begin
      declare
         Enc : Itb.Streams.Stream_Encryptor_Triple :=
           Itb.Streams.Make_Triple
             (S0, S1, S2, S3, S4, S5, S6,
              Cipher_Mem'Access, Small_Chunk);
      begin
         Itb.Streams.Write_Plaintext (Enc, Plain (1 .. Small_Chunk));
         Itb.Streams.Write_Plaintext
           (Enc, Plain (Small_Chunk + 1 .. 3 * Small_Chunk));
         Itb.Streams.Write_Plaintext
           (Enc, Plain (3 * Small_Chunk + 1 .. Plain'Last));
         Itb.Streams.Finish (Enc);
      end;
      Rewind (Cipher_Mem);
      declare
         Dec : Itb.Streams.Stream_Decryptor_Triple :=
           Itb.Streams.Make_Triple
             (S0, S1, S2, S3, S4, S5, S6, Cipher_Mem'Access);
      begin
         Drain_Decryptor_Triple (Dec, Plain_Mem);
         Itb.Streams.Finish (Dec);
      end;
      if Snapshot (Plain_Mem) /= Plain then
         raise Program_Error with "triple roundtrip mismatch";
      end if;
      Free (Cipher_Mem);
      Free (Plain_Mem);
   end;

   ------------------------------------------------------------------
   --  test_encrypt_stream_triple_decrypt_stream_triple
   ------------------------------------------------------------------
   declare
      Plain : constant Byte_Array := Pseudo_Payload (Small_Chunk * 5 + 7);
      S0 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S1 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S2 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S3 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S4 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S5 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S6 : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Cipher_Mem : aliased Memory_Stream;
      Plain_Mem  : aliased Memory_Stream;
   begin
      declare
         Src : aliased Memory_Stream;
      begin
         Src.Write (Plain);
         Itb.Streams.Encrypt_Stream_Triple
           (S0, S1, S2, S3, S4, S5, S6,
            Src'Access, Cipher_Mem'Access, Small_Chunk);
         Free (Src);
      end;
      Rewind (Cipher_Mem);
      Itb.Streams.Decrypt_Stream_Triple
        (S0, S1, S2, S3, S4, S5, S6,
         Cipher_Mem'Access, Plain_Mem'Access, Small_Chunk);
      if Snapshot (Plain_Mem) /= Plain then
         raise Program_Error with "triple stream driver mismatch";
      end if;
      Free (Cipher_Mem);
      Free (Plain_Mem);
   end;

   ------------------------------------------------------------------
   --  test_write_after_close_raises
   ------------------------------------------------------------------
   declare
      N : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      D : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Cipher_Mem : aliased Memory_Stream;
   begin
      declare
         Enc : Itb.Streams.Stream_Encryptor :=
           Itb.Streams.Make (N, D, S, Cipher_Mem'Access, Small_Chunk);
         Hello : constant Byte_Array :=
           [Stream_Element (Character'Pos ('h')),
            Stream_Element (Character'Pos ('e')),
            Stream_Element (Character'Pos ('l')),
            Stream_Element (Character'Pos ('l')),
            Stream_Element (Character'Pos ('o'))];
         World : constant Byte_Array :=
           [Stream_Element (Character'Pos ('w')),
            Stream_Element (Character'Pos ('o')),
            Stream_Element (Character'Pos ('r')),
            Stream_Element (Character'Pos ('l')),
            Stream_Element (Character'Pos ('d'))];
      begin
         Itb.Streams.Write_Plaintext (Enc, Hello);
         Itb.Streams.Finish (Enc);
         begin
            Itb.Streams.Write_Plaintext (Enc, World);
            raise Program_Error with "write after Finish must raise";
         exception
            when E : Itb.Errors.Itb_Error =>
               if Itb.Errors.Status_Code (E) /= Itb.Status.Easy_Closed then
                  raise;
               end if;
         end;
      end;
      Free (Cipher_Mem);
   end;

   ------------------------------------------------------------------
   --  test_partial_chunk_at_close_raises — feed only the header but
   --  truncate body, then Finish must raise.
   ------------------------------------------------------------------
   declare
      N : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      D : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Cipher_Mem : aliased Memory_Stream;
      Trunc_Mem  : aliased Memory_Stream;
      Plain_Mem  : aliased Memory_Stream;
   begin
      declare
         Enc : Itb.Streams.Stream_Encryptor :=
           Itb.Streams.Make (N, D, S, Cipher_Mem'Access, Small_Chunk);
         Filler : constant Byte_Array :=
           [1 .. 100 => Stream_Element (Character'Pos ('x'))];
      begin
         Itb.Streams.Write_Plaintext (Enc, Filler);
         Itb.Streams.Finish (Enc);
      end;
      --  Feed only the first 30 bytes.
      Trunc_Mem.Write (Snapshot (Cipher_Mem) (1 .. 30));
      declare
         Dec : Itb.Streams.Stream_Decryptor :=
           Itb.Streams.Make (N, D, S, Trunc_Mem'Access);
      begin
         Drain_Decryptor (Dec, Plain_Mem);
         begin
            Itb.Streams.Finish (Dec);
            raise Program_Error
              with "Finish on truncated tail must raise";
         exception
            when E : Itb.Errors.Itb_Error =>
               if Itb.Errors.Status_Code (E) /= Itb.Status.Bad_Input then
                  raise;
               end if;
         end;
      end;
      Free (Cipher_Mem);
      Free (Trunc_Mem);
      Free (Plain_Mem);
   end;

   Ada.Text_IO.Put_Line ("test_streams: PASS");

end Test_Streams;
