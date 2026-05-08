--  Streaming-style use of the high-level Itb.Encryptor surface — Ada
--  mirror of bindings/rust/tests/test_easy_streams.rs.
--
--  Streaming over the Encryptor surface lives entirely on the binding
--  side (no separate Stream_Encryptor / Stream_Decryptor classes for
--  the Easy API): the consumer slices the plaintext into chunks of
--  the desired size and calls Itb.Encryptor.Encrypt per chunk; the
--  decrypt side walks the concatenated chunk stream by reading
--  Header_Size bytes, calling Parse_Chunk_Len, reading the remaining
--  body, and feeding the full chunk to Itb.Encryptor.Decrypt.
--
--  Triple-Ouroboros (Mode = 3) and non-default nonce-bits
--  configurations are covered explicitly so a regression in the
--  per-instance Header_Size / Parse_Chunk_Len path or in the seed
--  plumbing surfaces here.

with Ada.Calendar;
with Ada.Streams;             use Ada.Streams;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with Ada.Unchecked_Deallocation;

with Interfaces;   use Interfaces;

with Itb;          use Itb;
with Itb.Encryptor;
with Itb.Errors;
with Itb.Status;

procedure Test_Easy_Streams is

   Small_Chunk : constant Stream_Element_Offset := 4096;

   State : Unsigned_64 :=
     Unsigned_64 (Ada.Calendar.Seconds (Ada.Calendar.Clock) * 1.0E6)
     xor 16#12345678_9ABCDEF0#;

   function Token_Bytes (N : Stream_Element_Offset) return Byte_Array is
      Out_Buf : Byte_Array (1 .. N);
   begin
      for I in Out_Buf'Range loop
         State := State * 6364136223846793005 + 1442695040888963407;
         Out_Buf (I) := Stream_Element (Shift_Right (State, 33) and 16#FF#);
      end loop;
      return Out_Buf;
   end Token_Bytes;

   --  Heap-resident byte buffer with grow-on-demand. Mirrors the Rust
   --  Vec<u8> the helper functions return.
   type Byte_Buf_Access is access Byte_Array;
   procedure Free_Buf is new Ada.Unchecked_Deallocation
     (Object => Byte_Array, Name => Byte_Buf_Access);

   type Byte_Buf is record
      Buf  : Byte_Buf_Access := null;
      Used : Stream_Element_Offset := 0;
   end record;

   procedure Free (B : in out Byte_Buf) is
   begin
      if B.Buf /= null then
         Free_Buf (B.Buf);
      end if;
      B.Used := 0;
   end Free;

   procedure Ensure_Cap (B : in out Byte_Buf; Need : Stream_Element_Offset)
   is
      New_Cap : Stream_Element_Offset;
      New_Buf : Byte_Buf_Access;
   begin
      if B.Buf = null then
         New_Cap := Stream_Element_Offset'Max (Need, 4096);
         B.Buf := new Byte_Array (1 .. New_Cap);
         return;
      end if;
      if Need <= B.Buf'Last then
         return;
      end if;
      New_Cap := B.Buf'Last;
      while New_Cap < Need loop
         New_Cap := New_Cap * 2;
      end loop;
      New_Buf := new Byte_Array (1 .. New_Cap);
      New_Buf (1 .. B.Used) := B.Buf (1 .. B.Used);
      Free_Buf (B.Buf);
      B.Buf := New_Buf;
   end Ensure_Cap;

   procedure Append (B : in out Byte_Buf; Data : Byte_Array) is
   begin
      Ensure_Cap (B, B.Used + Data'Length);
      B.Buf (B.Used + 1 .. B.Used + Data'Length) := Data;
      B.Used := B.Used + Data'Length;
   end Append;

   --  Returns a fresh copy of the live bytes.
   function Snapshot (B : Byte_Buf) return Byte_Array is
   begin
      if B.Buf = null or else B.Used = 0 then
         return [1 .. 0 => 0];
      end if;
      return B.Buf (1 .. B.Used);
   end Snapshot;

   --  Drains the front N bytes of B (shifts the tail down).
   procedure Drain_Front (B : in out Byte_Buf; N : Stream_Element_Offset) is
      Remaining : constant Stream_Element_Offset := B.Used - N;
   begin
      if N >= B.Used then
         B.Used := 0;
         return;
      end if;
      B.Buf (1 .. Remaining) := B.Buf (N + 1 .. B.Used);
      B.Used := Remaining;
   end Drain_Front;

   --  Encrypts plaintext chunk-by-chunk through Itb.Encryptor.Encrypt
   --  and returns the concatenated ciphertext stream. Mirrors the
   --  Rust stream_encrypt helper.
   function Stream_Encrypt
     (Enc       : in out Itb.Encryptor.Encryptor;
      Plaintext : Byte_Array;
      Chunk     : Stream_Element_Offset) return Byte_Array
   is
      Out_Buf : Byte_Buf;
      I : Stream_Element_Offset := Plaintext'First;
   begin
      while I <= Plaintext'Last loop
         declare
            Last : constant Stream_Element_Offset :=
              Stream_Element_Offset'Min (I + Chunk - 1, Plaintext'Last);
            Ct : constant Byte_Array :=
              Itb.Encryptor.Encrypt (Enc, Plaintext (I .. Last));
         begin
            Append (Out_Buf, Ct);
            I := Last + 1;
         end;
      end loop;
      declare
         Result : constant Byte_Array := Snapshot (Out_Buf);
      begin
         Free (Out_Buf);
         return Result;
      end;
   end Stream_Encrypt;

   --  Reason returned by Stream_Decrypt's failure path. Mirrors the
   --  Rust Err(String) signal that the trailing accumulator did not
   --  resolve to a complete chunk.
   type Stream_Result is record
      Ok      : Boolean := False;
      Plain   : Byte_Buf;
      Failure : Ada.Strings.Unbounded.Unbounded_String;
   end record;

   procedure Stream_Decrypt
     (Enc        : in out Itb.Encryptor.Encryptor;
      Ciphertext : Byte_Array;
      Result     : in out Stream_Result)
   is
      Header_Size : constant Stream_Element_Offset :=
        Stream_Element_Offset (Itb.Encryptor.Header_Size (Enc));
      Accum   : Byte_Buf;
      Feed_Off : Stream_Element_Offset := Ciphertext'First;
   begin
      while Feed_Off <= Ciphertext'Last loop
         declare
            Last : constant Stream_Element_Offset :=
              Stream_Element_Offset'Min
                (Feed_Off + Small_Chunk - 1, Ciphertext'Last);
         begin
            Append (Accum, Ciphertext (Feed_Off .. Last));
            Feed_Off := Last + 1;
         end;
         loop
            if Accum.Used < Header_Size then
               exit;
            end if;
            declare
               Chunk_Len : constant Natural :=
                 Itb.Encryptor.Parse_Chunk_Len
                   (Enc, Accum.Buf (1 .. Header_Size));
               Need : constant Stream_Element_Offset :=
                 Stream_Element_Offset (Chunk_Len);
            begin
               if Accum.Used < Need then
                  exit;
               end if;
               declare
                  Pt : constant Byte_Array :=
                    Itb.Encryptor.Decrypt (Enc, Accum.Buf (1 .. Need));
               begin
                  Append (Result.Plain, Pt);
                  Drain_Front (Accum, Need);
               end;
            end;
         end loop;
      end loop;
      if Accum.Used /= 0 then
         Result.Ok := False;
         Result.Failure :=
           Ada.Strings.Unbounded.To_Unbounded_String
             ("trailing"
              & Stream_Element_Offset'Image (Accum.Used)
              & " bytes do not form a complete chunk");
      else
         Result.Ok := True;
      end if;
      Free (Accum);
   end Stream_Decrypt;

begin

   ------------------------------------------------------------------
   --  stream_roundtrip_default_nonce_single
   ------------------------------------------------------------------
   declare
      Plaintext : constant Byte_Array :=
        Token_Bytes (Small_Chunk * 5 + 17);
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
      Ct : constant Byte_Array := Stream_Encrypt (Enc, Plaintext, Small_Chunk);
      Result : Stream_Result;
   begin
      Stream_Decrypt (Enc, Ct, Result);
      if not Result.Ok then
         raise Program_Error
           with "Single default-nonce stream decode failed: "
                & Ada.Strings.Unbounded.To_String (Result.Failure);
      end if;
      if Snapshot (Result.Plain) /= Plaintext then
         raise Program_Error with "Single default-nonce roundtrip mismatch";
      end if;
      Free (Result.Plain);
   end;

   ------------------------------------------------------------------
   --  stream_roundtrip_non_default_nonce_single
   ------------------------------------------------------------------
   declare
      type Int_Array is array (Positive range <>) of Integer;
      Sizes : constant Int_Array := [256, 512];
      Plaintext : constant Byte_Array :=
        Token_Bytes (Small_Chunk * 3 + 100);
   begin
      for N of Sizes loop
         declare
            Enc : Itb.Encryptor.Encryptor :=
              Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
         begin
            Itb.Encryptor.Set_Nonce_Bits (Enc, N);
            declare
               Ct : constant Byte_Array :=
                 Stream_Encrypt (Enc, Plaintext, Small_Chunk);
               Result : Stream_Result;
            begin
               Stream_Decrypt (Enc, Ct, Result);
               if not Result.Ok then
                  raise Program_Error
                    with "Single nonce" & N'Image & " stream failed: "
                         & Ada.Strings.Unbounded.To_String
                             (Result.Failure);
               end if;
               if Snapshot (Result.Plain) /= Plaintext then
                  raise Program_Error
                    with "Single nonce" & N'Image & " mismatch";
               end if;
               Free (Result.Plain);
            end;
         end;
      end loop;
   end;

   ------------------------------------------------------------------
   --  stream_triple_roundtrip_default_nonce
   ------------------------------------------------------------------
   declare
      Plaintext : constant Byte_Array :=
        Token_Bytes (Small_Chunk * 4 + 33);
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 3);
      Ct : constant Byte_Array := Stream_Encrypt (Enc, Plaintext, Small_Chunk);
      Result : Stream_Result;
   begin
      Stream_Decrypt (Enc, Ct, Result);
      if not Result.Ok then
         raise Program_Error
           with "Triple default-nonce stream decode failed: "
                & Ada.Strings.Unbounded.To_String (Result.Failure);
      end if;
      if Snapshot (Result.Plain) /= Plaintext then
         raise Program_Error
           with "Triple default-nonce roundtrip mismatch";
      end if;
      Free (Result.Plain);
   end;

   ------------------------------------------------------------------
   --  stream_triple_roundtrip_non_default_nonce
   ------------------------------------------------------------------
   declare
      type Int_Array is array (Positive range <>) of Integer;
      Sizes : constant Int_Array := [256, 512];
      Plaintext : constant Byte_Array := Token_Bytes (Small_Chunk * 3);
   begin
      for N of Sizes loop
         declare
            Enc : Itb.Encryptor.Encryptor :=
              Itb.Encryptor.Make ("blake3", 1024, "kmac256", 3);
         begin
            Itb.Encryptor.Set_Nonce_Bits (Enc, N);
            declare
               Ct : constant Byte_Array :=
                 Stream_Encrypt (Enc, Plaintext, Small_Chunk);
               Result : Stream_Result;
            begin
               Stream_Decrypt (Enc, Ct, Result);
               if not Result.Ok then
                  raise Program_Error
                    with "Triple nonce" & N'Image & " stream failed: "
                         & Ada.Strings.Unbounded.To_String
                             (Result.Failure);
               end if;
               if Snapshot (Result.Plain) /= Plaintext then
                  raise Program_Error
                    with "Triple nonce" & N'Image & " mismatch";
               end if;
               Free (Result.Plain);
            end;
         end;
      end loop;
   end;

   ------------------------------------------------------------------
   --  stream_partial_chunk_raises — feeding only a partial chunk to
   --  the streaming decoder reports a trailing-bytes failure.
   ------------------------------------------------------------------
   declare
      Plaintext : constant Byte_Array :=
        [1 .. 100 => Stream_Element (Character'Pos ('x'))];
      Enc : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
      Ct : constant Byte_Array := Stream_Encrypt (Enc, Plaintext, Small_Chunk);
      Result : Stream_Result;
      Truncated : constant Byte_Array := Ct (Ct'First .. Ct'First + 29);
   begin
      Stream_Decrypt (Enc, Truncated, Result);
      if Result.Ok then
         raise Program_Error
           with "truncated stream must report failure";
      end if;
      declare
         Msg : constant String :=
           Ada.Strings.Unbounded.To_String (Result.Failure);
      begin
         if Msg'Length < 8
           or else Msg (Msg'First .. Msg'First + 7) /= "trailing"
         then
            raise Program_Error
              with "expected 'trailing' prefix, got '" & Msg & "'";
         end if;
      end;
      Free (Result.Plain);
   end;

   ------------------------------------------------------------------
   --  parse_chunk_len_short_buffer — Parse_Chunk_Len on fewer than
   --  Header_Size bytes raises Bad_Input.
   ------------------------------------------------------------------
   declare
      Enc : constant Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
      H : constant Stream_Element_Offset :=
        Stream_Element_Offset (Itb.Encryptor.Header_Size (Enc));
      Buf : constant Byte_Array := [1 .. H - 1 => 0];
   begin
      declare
         Parsed : constant Natural :=
           Itb.Encryptor.Parse_Chunk_Len (Enc, Buf);
         pragma Unreferenced (Parsed);
      begin
         raise Program_Error with "short buffer Parse_Chunk_Len must raise";
      end;
   exception
      when E : Itb.Errors.Itb_Error =>
         if Itb.Errors.Status_Code (E) /= Itb.Status.Bad_Input then
            raise;
         end if;
   end;

   ------------------------------------------------------------------
   --  parse_chunk_len_zero_dim — Header_Size bytes, all zero, must
   --  raise (the encoded width = 0 sentinel is invalid).
   ------------------------------------------------------------------
   declare
      Enc : constant Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make ("blake3", 1024, "kmac256", 1);
      H : constant Stream_Element_Offset :=
        Stream_Element_Offset (Itb.Encryptor.Header_Size (Enc));
      Hdr : constant Byte_Array := [1 .. H => 0];
   begin
      declare
         Parsed : constant Natural :=
           Itb.Encryptor.Parse_Chunk_Len (Enc, Hdr);
         pragma Unreferenced (Parsed);
      begin
         raise Program_Error
           with "zero-dimension header Parse_Chunk_Len must raise";
      end;
   exception
      when Itb.Errors.Itb_Error =>
         null;
   end;

   Ada.Text_IO.Put_Line ("test_easy_streams: PASS");
end Test_Easy_Streams;
