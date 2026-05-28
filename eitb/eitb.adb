--  Ada eitb — runs every wrapper × ITB example end-to-end.
--
--  Mirrors tools/eitb/main.go adapted to the Ada binding asymmetry: the
--  binding has no Ada.Streams.Stream_IO-Driven Non-AEAD wrap surface;
--  the only Non-AEAD streaming arm is the User-Driven Loop variant.
--  Streaming AEAD is supported via Encryptor.Encrypt_Stream_Auth /
--  Decrypt_Stream_Auth (Easy) and Itb.Streams.Encrypt_Stream_Auth /
--  Decrypt_Stream_Auth (Low-Level), both of which write the inner
--  ITB transcript to a Memory_Stream that is then wrapped through a
--  single Wrap_Stream_Writer session.
--
--  Matrix: 8 examples × outer ciphers.
--
--  Usage:
--      ./eitb               # run every example × every cipher
--      ./eitb -h            # print usage
--      ./eitb --example aead --cipher aes -v

with Ada.Calendar;
with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Streams;             use Ada.Streams;
with Ada.Strings.Fixed;
with Ada.Text_IO;
with Ada.Unchecked_Deallocation;
with Interfaces;              use Interfaces;

with Itb;                     use Itb;
with Itb.Cipher;
with Itb.Encryptor;
with Itb.MAC;
with Itb.Seed;
with Itb.Streams;
with Itb.Wrapper;

procedure Eitb is

   ---------------------------------------------------------------------
   --  Configuration constants — mirror tools/eitb/main.go.
   ---------------------------------------------------------------------

   Single_Message_Bytes : constant Stream_Element_Offset :=
     Stream_Element_Offset (1024);
   Stream_Bytes         : constant Stream_Element_Offset :=
     Stream_Element_Offset (64 * 1024);
   Stream_Chunk_Size    : constant Stream_Element_Offset :=
     Stream_Element_Offset (16 * 1024);
   Stream_Primitive     : constant String := "areion512";
   Mac_Name             : constant String := "hmac-blake3";

   ---------------------------------------------------------------------
   --  Heap-resident byte buffer with grow-on-demand. Mirrors the
   --  bench Memory_Stream — duplicated so the tool can stand on its
   --  own.
   ---------------------------------------------------------------------

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

   procedure Ensure_Cap
     (Self : in out Memory_Stream'Class; Need : Stream_Element_Offset);

   procedure Free (S : in out Memory_Stream'Class);

   procedure Reset_Read (S : in out Memory_Stream'Class);

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

   procedure Reset_Read (S : in out Memory_Stream'Class) is
   begin
      S.Pos := 1;
   end Reset_Read;

   ---------------------------------------------------------------------
   --  CSPRNG-flavoured payload generator (Calendar-mixed LCG).
   ---------------------------------------------------------------------

   State : Unsigned_64 :=
     Unsigned_64 (Ada.Calendar.Seconds (Ada.Calendar.Clock) * 1.0E6)
     xor 16#FACE_F00D_DEAD_BEEF#;

   function Random_Bytes (N : Stream_Element_Offset) return Byte_Array is
      Out_Buf : Byte_Array (1 .. N);
   begin
      for I in Out_Buf'Range loop
         State := State * 6364136223846793005 + 1442695040888963407;
         Out_Buf (I) :=
           Stream_Element (Shift_Right (State, 33) and 16#FF#);
      end loop;
      return Out_Buf;
   end Random_Bytes;

   ---------------------------------------------------------------------
   --  Bytes → fingerprint helper. Returns an 8-byte hex digest of a
   --  byte buffer's content via a folded SipHash-style poly.
   --  Substitute for SHA-256 in the eitb diagnostic line — every
   --  binding produces a short fingerprint, the exact algorithm is
   --  not part of any cross-binding contract since the round-trip
   --  comparison is done byte-for-byte already.
   ---------------------------------------------------------------------

   function Fingerprint (B : Byte_Array) return String is
      H1 : Unsigned_64 := 16#736F6D6570736575#;
   begin
      for I in B'Range loop
         H1 := H1 xor Unsigned_64 (B (I));
         H1 := H1 * 1099511628211;
      end loop;
      declare
         function Hex_Nib (V : Unsigned_64) return Character is
            N : constant Unsigned_64 := V and 16#F#;
         begin
            if N < 10 then
               return Character'Val (Character'Pos ('0') + Natural (N));
            else
               return Character'Val
                 (Character'Pos ('a') + Natural (N - 10));
            end if;
         end Hex_Nib;
         Out_S : String (1 .. 16);
      begin
         for I in 0 .. 7 loop
            Out_S (1 + I * 2) :=
              Hex_Nib (Shift_Right (H1, (7 - I) * 8 + 4));
            Out_S (2 + I * 2) :=
              Hex_Nib (Shift_Right (H1, (7 - I) * 8));
         end loop;
         return Out_S;
      end;
   end Fingerprint;

   ---------------------------------------------------------------------
   --  Encryptor / Seed / MAC builders.
   ---------------------------------------------------------------------

   function Build_Easy
     (Mac : String; Key_Bits : Integer) return Itb.Encryptor.Encryptor is
   begin
      return E : Itb.Encryptor.Encryptor :=
        Itb.Encryptor.Make
          (Primitive => Stream_Primitive,
           Key_Bits  => Key_Bits,
           Mac_Name  => Mac,
           Mode      => 1)
      do
         Itb.Encryptor.Set_Nonce_Bits (E, 512);
         Itb.Encryptor.Set_Barrier_Fill (E, 4);
         Itb.Encryptor.Set_Bit_Soup (E, 1);
         Itb.Encryptor.Set_Lock_Soup (E, 1);
         Itb.Encryptor.Set_Lock_Batch (E, 1);
      end return;
   end Build_Easy;

   procedure Apply_Low_Level_Config is
   begin
      Itb.Set_Nonce_Bits (512);
      Itb.Set_Barrier_Fill (4);
      Itb.Set_Bit_Soup (1);
      Itb.Set_Lock_Soup (1);
      Itb.Set_Lock_Batch (1);
   end Apply_Low_Level_Config;

   ---------------------------------------------------------------------
   --  Per-example runners. Each returns (recovered, wire_bytes); a
   --  failure is signalled via raised exception.
   ---------------------------------------------------------------------

   --  Streaming AEAD Easy (MAC Authenticated, IO-Driven).
   procedure Run_AEAD_Easy_IO
     (Cipher    : Itb.Wrapper.Cipher_Type;
      Plain     : Byte_Array;
      Recovered : out Byte_Buf_Access;
      Wire_Bytes : out Stream_Element_Offset)
   is
      Enc : Itb.Encryptor.Encryptor :=
        Build_Easy (Mac_Name, 1024);
      Outer_Key : constant Byte_Array :=
        Itb.Wrapper.Generate_Key (Cipher);
      N_Len : constant Stream_Element_Offset :=
        Stream_Element_Offset (Itb.Wrapper.Nonce_Size (Cipher));
      Inner_Source, Inner_Sink : aliased Memory_Stream;
   begin
      Inner_Source.Write (Plain);
      Reset_Read (Inner_Source);

      Itb.Encryptor.Encrypt_Stream_Auth
        (Enc, Inner_Source'Access, Inner_Sink'Access, Stream_Chunk_Size);

      declare
         Inner_Bytes : constant Stream_Element_Offset := Inner_Sink.Used;
         Out_Nonce : Byte_Array (1 .. N_Len);
         W : Itb.Wrapper.Wrap_Stream_Writer;
         Body_Enc : Byte_Array (1 .. Inner_Bytes);
         Last : Stream_Element_Offset;
      begin
         Itb.Wrapper.Initialize (W, Cipher, Outer_Key, Out_Nonce);
         Itb.Wrapper.Update
           (W, Inner_Sink.Buf (1 .. Inner_Bytes), Body_Enc, Last);
         Itb.Wrapper.Close (W);
         Wire_Bytes := N_Len + Inner_Bytes;

         --  Receiver
         declare
            R : Itb.Wrapper.Unwrap_Stream_Reader;
            Body_Dec : Byte_Array (1 .. Inner_Bytes);
         begin
            Itb.Wrapper.Initialize (R, Cipher, Outer_Key, Out_Nonce);
            Itb.Wrapper.Update (R, Body_Enc, Body_Dec, Last);
            Itb.Wrapper.Close (R);
            declare
               Inner_Recv : aliased Memory_Stream;
               Out_Buf    : aliased Memory_Stream;
            begin
               Inner_Recv.Write (Body_Dec);
               Reset_Read (Inner_Recv);
               Itb.Encryptor.Decrypt_Stream_Auth
                 (Enc, Inner_Recv'Access, Out_Buf'Access,
                  Stream_Chunk_Size);
               Recovered :=
                 new Byte_Array'(Out_Buf.Buf (1 .. Out_Buf.Used));
               Free (Inner_Recv);
               Free (Out_Buf);
            end;
         end;
      end;

      Free (Inner_Source);
      Free (Inner_Sink);
      Itb.Encryptor.Close (Enc);
   end Run_AEAD_Easy_IO;

   --  Streaming AEAD Low-Level (MAC Authenticated, IO-Driven).
   procedure Run_AEAD_Low_Level_IO
     (Cipher    : Itb.Wrapper.Cipher_Type;
      Plain     : Byte_Array;
      Recovered : out Byte_Buf_Access;
      Wire_Bytes : out Stream_Element_Offset)
   is
      Noise : constant Itb.Seed.Seed :=
        Itb.Seed.Make (Stream_Primitive, 1024);
      Data  : constant Itb.Seed.Seed :=
        Itb.Seed.Make (Stream_Primitive, 1024);
      Start : constant Itb.Seed.Seed :=
        Itb.Seed.Make (Stream_Primitive, 1024);
      Mac_Key : constant Byte_Array := Random_Bytes (32);
      Mac     : constant Itb.MAC.MAC := Itb.MAC.Make (Mac_Name, Mac_Key);
      Outer_Key : constant Byte_Array :=
        Itb.Wrapper.Generate_Key (Cipher);
      N_Len : constant Stream_Element_Offset :=
        Stream_Element_Offset (Itb.Wrapper.Nonce_Size (Cipher));
      Inner_Source, Inner_Sink : aliased Memory_Stream;
   begin
      Apply_Low_Level_Config;

      Inner_Source.Write (Plain);
      Reset_Read (Inner_Source);

      Itb.Streams.Encrypt_Stream_Auth
        (Noise, Data, Start, Mac,
         Inner_Source'Access, Inner_Sink'Access, Stream_Chunk_Size);

      declare
         Inner_Bytes : constant Stream_Element_Offset := Inner_Sink.Used;
         Out_Nonce : Byte_Array (1 .. N_Len);
         W : Itb.Wrapper.Wrap_Stream_Writer;
         Body_Enc : Byte_Array (1 .. Inner_Bytes);
         Last : Stream_Element_Offset;
      begin
         Itb.Wrapper.Initialize (W, Cipher, Outer_Key, Out_Nonce);
         Itb.Wrapper.Update
           (W, Inner_Sink.Buf (1 .. Inner_Bytes), Body_Enc, Last);
         Itb.Wrapper.Close (W);
         Wire_Bytes := N_Len + Inner_Bytes;

         declare
            R : Itb.Wrapper.Unwrap_Stream_Reader;
            Body_Dec : Byte_Array (1 .. Inner_Bytes);
         begin
            Itb.Wrapper.Initialize (R, Cipher, Outer_Key, Out_Nonce);
            Itb.Wrapper.Update (R, Body_Enc, Body_Dec, Last);
            Itb.Wrapper.Close (R);
            declare
               Inner_Recv : aliased Memory_Stream;
               Out_Buf    : aliased Memory_Stream;
            begin
               Inner_Recv.Write (Body_Dec);
               Reset_Read (Inner_Recv);
               Itb.Streams.Decrypt_Stream_Auth
                 (Noise, Data, Start, Mac,
                  Inner_Recv'Access, Out_Buf'Access, Stream_Chunk_Size);
               Recovered :=
                 new Byte_Array'(Out_Buf.Buf (1 .. Out_Buf.Used));
               Free (Inner_Recv);
               Free (Out_Buf);
            end;
         end;
      end;

      Free (Inner_Source);
      Free (Inner_Sink);
   end Run_AEAD_Low_Level_IO;

   --  Helper: writes a u32_LE length prefix + body through a
   --  Wrap_Stream_Writer, accumulating into Out_Wire (a growable
   --  Byte_Buf_Access).
   procedure UL_Write_Frame
     (W       : in out Itb.Wrapper.Wrap_Stream_Writer;
      Out_Buf : in out Byte_Buf_Access;
      Used    : in out Stream_Element_Offset;
      Body_B  : Byte_Array)
   is
      Len_LE : Byte_Array (1 .. 4);
      U32 : constant Unsigned_32 := Unsigned_32 (Body_B'Length);
      Frame_Total : constant Stream_Element_Offset := 4 + Body_B'Length;
      Last : Stream_Element_Offset;
   begin
      Len_LE (1) := Stream_Element (U32 and 16#FF#);
      Len_LE (2) :=
        Stream_Element (Shift_Right (U32, 8) and 16#FF#);
      Len_LE (3) :=
        Stream_Element (Shift_Right (U32, 16) and 16#FF#);
      Len_LE (4) :=
        Stream_Element (Shift_Right (U32, 24) and 16#FF#);
      if Used + Frame_Total > Out_Buf'Last then
         declare
            New_Cap : Stream_Element_Offset := Out_Buf'Last;
            New_Buf : Byte_Buf_Access;
         begin
            while New_Cap < Used + Frame_Total loop
               New_Cap := New_Cap * 2;
            end loop;
            New_Buf := new Byte_Array (1 .. New_Cap);
            New_Buf (1 .. Used) := Out_Buf (1 .. Used);
            Free_Buf (Out_Buf);
            Out_Buf := New_Buf;
         end;
      end if;
      Itb.Wrapper.Update
        (W, Len_LE, Out_Buf (Used + 1 .. Used + 4), Last);
      Used := Used + 4;
      if Body_B'Length > 0 then
         Itb.Wrapper.Update
           (W, Body_B, Out_Buf (Used + 1 .. Used + Body_B'Length), Last);
         Used := Used + Body_B'Length;
      end if;
   end UL_Write_Frame;

   --  Helper: reads a u32_LE length prefix + body from an
   --  Unwrap_Stream_Reader-decrypted buffer (the reader has already
   --  XOR-decrypted every byte). Returns False on EOF.
   function UL_Read_Frame_From
     (Decrypted : Byte_Array;
      Pos       : in out Stream_Element_Offset;
      Out_Body  : out Byte_Buf_Access) return Boolean
   is
      Frame_Len : Unsigned_32;
   begin
      if Pos + 4 > Decrypted'Last + 1 then
         Out_Body := null;
         return False;
      end if;
      Frame_Len :=
        Unsigned_32 (Decrypted (Pos)) +
        Shift_Left (Unsigned_32 (Decrypted (Pos + 1)), 8) +
        Shift_Left (Unsigned_32 (Decrypted (Pos + 2)), 16) +
        Shift_Left (Unsigned_32 (Decrypted (Pos + 3)), 24);
      Pos := Pos + 4;
      if Pos + Stream_Element_Offset (Frame_Len) > Decrypted'Last + 1 then
         raise Program_Error with "ul: truncated chunk body";
      end if;
      Out_Body :=
        new Byte_Array'
              (Decrypted (Pos .. Pos + Stream_Element_Offset (Frame_Len) - 1));
      Pos := Pos + Stream_Element_Offset (Frame_Len);
      return True;
   end UL_Read_Frame_From;

   --  Streaming Easy (No MAC, User-Driven Loop).
   procedure Run_NoAEAD_Easy_UserLoop
     (Cipher    : Itb.Wrapper.Cipher_Type;
      Plain     : Byte_Array;
      Recovered : out Byte_Buf_Access;
      Wire_Bytes : out Stream_Element_Offset)
   is
      Enc : Itb.Encryptor.Encryptor := Build_Easy ("", 1024);
      Outer_Key : constant Byte_Array :=
        Itb.Wrapper.Generate_Key (Cipher);
      N_Len : constant Stream_Element_Offset :=
        Stream_Element_Offset (Itb.Wrapper.Nonce_Size (Cipher));
      Out_Nonce : Byte_Array (1 .. N_Len);
      W : Itb.Wrapper.Wrap_Stream_Writer;
      Wire : Byte_Buf_Access := new Byte_Array (1 .. 4096);
      Used : Stream_Element_Offset := 0;
      Cur  : Stream_Element_Offset := Plain'First;
   begin
      Itb.Wrapper.Initialize (W, Cipher, Outer_Key, Out_Nonce);
      while Cur <= Plain'Last loop
         declare
            Take : constant Stream_Element_Offset :=
              Stream_Element_Offset'Min
                (Stream_Chunk_Size, Plain'Last - Cur + 1);
            Ct : constant Byte_Array :=
              Itb.Encryptor.Encrypt
                (Enc, Plain (Cur .. Cur + Take - 1));
         begin
            UL_Write_Frame (W, Wire, Used, Ct);
            Cur := Cur + Take;
         end;
      end loop;
      Itb.Wrapper.Close (W);

      --  Compose the wire as nonce || encrypted body, just as the
      --  C# / Python / Rust eitb harnesses do.
      Wire_Bytes := N_Len + Used;

      --  Receiver: read the nonce, drive the unwrap reader over the
      --  encrypted body to recover the framed inner transcript, then
      --  parse u32_LE length + body and Decrypt per chunk.
      declare
         R : Itb.Wrapper.Unwrap_Stream_Reader;
         Decrypted : Byte_Array (1 .. Used);
         Last : Stream_Element_Offset;
         Pos : Stream_Element_Offset := Decrypted'First;
         Plain_Acc : Byte_Buf_Access := new Byte_Array (1 .. 4096);
         Plain_Used : Stream_Element_Offset := 0;
         Frame : Byte_Buf_Access;
      begin
         Itb.Wrapper.Initialize (R, Cipher, Outer_Key, Out_Nonce);
         Itb.Wrapper.Update (R, Wire (1 .. Used), Decrypted, Last);
         Itb.Wrapper.Close (R);
         while UL_Read_Frame_From (Decrypted, Pos, Frame) loop
            declare
               Pt : constant Byte_Array :=
                 Itb.Encryptor.Decrypt (Enc, Frame.all);
            begin
               if Plain_Used + Pt'Length > Plain_Acc'Last then
                  declare
                     New_Cap : Stream_Element_Offset := Plain_Acc'Last;
                     New_Buf : Byte_Buf_Access;
                  begin
                     while New_Cap < Plain_Used + Pt'Length loop
                        New_Cap := New_Cap * 2;
                     end loop;
                     New_Buf := new Byte_Array (1 .. New_Cap);
                     New_Buf (1 .. Plain_Used) :=
                       Plain_Acc (1 .. Plain_Used);
                     Free_Buf (Plain_Acc);
                     Plain_Acc := New_Buf;
                  end;
               end if;
               Plain_Acc (Plain_Used + 1 .. Plain_Used + Pt'Length) := Pt;
               Plain_Used := Plain_Used + Pt'Length;
            end;
            Free_Buf (Frame);
         end loop;
         Recovered := new Byte_Array'(Plain_Acc (1 .. Plain_Used));
         Free_Buf (Plain_Acc);
      end;

      Free_Buf (Wire);
      Itb.Encryptor.Close (Enc);
   end Run_NoAEAD_Easy_UserLoop;

   --  Streaming Low-Level (No MAC, User-Driven Loop).
   procedure Run_NoAEAD_Low_Level_UserLoop
     (Cipher    : Itb.Wrapper.Cipher_Type;
      Plain     : Byte_Array;
      Recovered : out Byte_Buf_Access;
      Wire_Bytes : out Stream_Element_Offset)
   is
      Noise : constant Itb.Seed.Seed :=
        Itb.Seed.Make (Stream_Primitive, 1024);
      Data  : constant Itb.Seed.Seed :=
        Itb.Seed.Make (Stream_Primitive, 1024);
      Start : constant Itb.Seed.Seed :=
        Itb.Seed.Make (Stream_Primitive, 1024);
      Outer_Key : constant Byte_Array :=
        Itb.Wrapper.Generate_Key (Cipher);
      N_Len : constant Stream_Element_Offset :=
        Stream_Element_Offset (Itb.Wrapper.Nonce_Size (Cipher));
      Out_Nonce : Byte_Array (1 .. N_Len);
      W : Itb.Wrapper.Wrap_Stream_Writer;
      Wire : Byte_Buf_Access := new Byte_Array (1 .. 4096);
      Used : Stream_Element_Offset := 0;
      Cur  : Stream_Element_Offset := Plain'First;
   begin
      Apply_Low_Level_Config;
      Itb.Wrapper.Initialize (W, Cipher, Outer_Key, Out_Nonce);
      while Cur <= Plain'Last loop
         declare
            Take : constant Stream_Element_Offset :=
              Stream_Element_Offset'Min
                (Stream_Chunk_Size, Plain'Last - Cur + 1);
            Ct : constant Byte_Array :=
              Itb.Cipher.Encrypt
                (Noise, Data, Start, Plain (Cur .. Cur + Take - 1));
         begin
            UL_Write_Frame (W, Wire, Used, Ct);
            Cur := Cur + Take;
         end;
      end loop;
      Itb.Wrapper.Close (W);
      Wire_Bytes := N_Len + Used;

      declare
         R : Itb.Wrapper.Unwrap_Stream_Reader;
         Decrypted : Byte_Array (1 .. Used);
         Last : Stream_Element_Offset;
         Pos : Stream_Element_Offset := Decrypted'First;
         Plain_Acc : Byte_Buf_Access := new Byte_Array (1 .. 4096);
         Plain_Used : Stream_Element_Offset := 0;
         Frame : Byte_Buf_Access;
      begin
         Itb.Wrapper.Initialize (R, Cipher, Outer_Key, Out_Nonce);
         Itb.Wrapper.Update (R, Wire (1 .. Used), Decrypted, Last);
         Itb.Wrapper.Close (R);
         while UL_Read_Frame_From (Decrypted, Pos, Frame) loop
            declare
               Pt : constant Byte_Array :=
                 Itb.Cipher.Decrypt (Noise, Data, Start, Frame.all);
            begin
               if Plain_Used + Pt'Length > Plain_Acc'Last then
                  declare
                     New_Cap : Stream_Element_Offset := Plain_Acc'Last;
                     New_Buf : Byte_Buf_Access;
                  begin
                     while New_Cap < Plain_Used + Pt'Length loop
                        New_Cap := New_Cap * 2;
                     end loop;
                     New_Buf := new Byte_Array (1 .. New_Cap);
                     New_Buf (1 .. Plain_Used) :=
                       Plain_Acc (1 .. Plain_Used);
                     Free_Buf (Plain_Acc);
                     Plain_Acc := New_Buf;
                  end;
               end if;
               Plain_Acc (Plain_Used + 1 .. Plain_Used + Pt'Length) := Pt;
               Plain_Used := Plain_Used + Pt'Length;
            end;
            Free_Buf (Frame);
         end loop;
         Recovered := new Byte_Array'(Plain_Acc (1 .. Plain_Used));
         Free_Buf (Plain_Acc);
      end;

      Free_Buf (Wire);
   end Run_NoAEAD_Low_Level_UserLoop;

   --  Single Message — Easy: Areion-SoEM-512 (No MAC).
   --  WrapInPlace / UnwrapInPlace defaults; the (allocating) Wrap /
   --  Unwrap alternatives are commented out below — see comment for
   --  immutability tradeoff.
   procedure Run_Message_Easy_NoMAC
     (Cipher    : Itb.Wrapper.Cipher_Type;
      Plain     : Byte_Array;
      Recovered : out Byte_Buf_Access;
      Wire_Bytes : out Stream_Element_Offset)
   is
      Enc : Itb.Encryptor.Encryptor := Build_Easy ("", 2048);
      Outer_Key : constant Byte_Array :=
        Itb.Wrapper.Generate_Key (Cipher);
      Encrypted : Byte_Array := Itb.Encryptor.Encrypt (Enc, Plain);
      N_Len : constant Stream_Element_Offset :=
        Stream_Element_Offset (Itb.Wrapper.Nonce_Size (Cipher));
   begin
      --  Wrap respects immutability of `Encrypted` (allocates a fresh
      --  wire buffer):
      --    declare
      --       Wire : constant Byte_Array :=
      --         Itb.Wrapper.Wrap (Cipher, Outer_Key, Encrypted);
      --    begin
      --       ...
      --    end;
      declare
         Out_Nonce : Byte_Array (1 .. N_Len);
      begin
         Itb.Wrapper.Wrap_In_Place
           (Cipher, Outer_Key, Encrypted, Out_Nonce);
         declare
            Wire : Byte_Array (1 .. N_Len + Encrypted'Length);
            Body_First : Stream_Element_Offset;
         begin
            Wire (1 .. N_Len) := Out_Nonce;
            Wire (N_Len + 1 .. Wire'Last) := Encrypted;
            Wire_Bytes := Wire'Length;

            --  Unwrap respects immutability of `Wire` (allocates a
            --  fresh recovered buffer):
            --    declare
            --       Recovered_Blob : constant Byte_Array :=
            --         Itb.Wrapper.Unwrap (Cipher, Outer_Key, Wire);
            --    begin
            --       ...
            --    end;
            Itb.Wrapper.Unwrap_In_Place
              (Cipher, Outer_Key, Wire, Body_First);
            declare
               Pt : constant Byte_Array :=
                 Itb.Encryptor.Decrypt
                   (Enc, Wire (Body_First .. Wire'Last));
            begin
               Recovered := new Byte_Array'(Pt);
            end;
         end;
      end;
      Itb.Encryptor.Close (Enc);
   end Run_Message_Easy_NoMAC;

   --  Single Message — Easy: Areion-SoEM-512 + HMAC-BLAKE3.
   procedure Run_Message_Easy_Auth
     (Cipher    : Itb.Wrapper.Cipher_Type;
      Plain     : Byte_Array;
      Recovered : out Byte_Buf_Access;
      Wire_Bytes : out Stream_Element_Offset)
   is
      Enc : Itb.Encryptor.Encryptor := Build_Easy (Mac_Name, 2048);
      Outer_Key : constant Byte_Array :=
        Itb.Wrapper.Generate_Key (Cipher);
      Encrypted : Byte_Array :=
        Itb.Encryptor.Encrypt_Auth (Enc, Plain);
      N_Len : constant Stream_Element_Offset :=
        Stream_Element_Offset (Itb.Wrapper.Nonce_Size (Cipher));
   begin
      declare
         Out_Nonce : Byte_Array (1 .. N_Len);
      begin
         Itb.Wrapper.Wrap_In_Place
           (Cipher, Outer_Key, Encrypted, Out_Nonce);
         declare
            Wire : Byte_Array (1 .. N_Len + Encrypted'Length);
            Body_First : Stream_Element_Offset;
         begin
            Wire (1 .. N_Len) := Out_Nonce;
            Wire (N_Len + 1 .. Wire'Last) := Encrypted;
            Wire_Bytes := Wire'Length;
            Itb.Wrapper.Unwrap_In_Place
              (Cipher, Outer_Key, Wire, Body_First);
            declare
               Pt : constant Byte_Array :=
                 Itb.Encryptor.Decrypt_Auth
                   (Enc, Wire (Body_First .. Wire'Last));
            begin
               Recovered := new Byte_Array'(Pt);
            end;
         end;
      end;
      Itb.Encryptor.Close (Enc);
   end Run_Message_Easy_Auth;

   --  Single Message — Low-Level: Areion-SoEM-512 (No MAC).
   procedure Run_Message_Low_Level_NoMAC
     (Cipher    : Itb.Wrapper.Cipher_Type;
      Plain     : Byte_Array;
      Recovered : out Byte_Buf_Access;
      Wire_Bytes : out Stream_Element_Offset)
   is
      Noise : constant Itb.Seed.Seed :=
        Itb.Seed.Make (Stream_Primitive, 2048);
      Data  : constant Itb.Seed.Seed :=
        Itb.Seed.Make (Stream_Primitive, 2048);
      Start : constant Itb.Seed.Seed :=
        Itb.Seed.Make (Stream_Primitive, 2048);
      Outer_Key : constant Byte_Array :=
        Itb.Wrapper.Generate_Key (Cipher);
   begin
      Apply_Low_Level_Config;
      declare
         Encrypted : Byte_Array :=
           Itb.Cipher.Encrypt (Noise, Data, Start, Plain);
         N_Len : constant Stream_Element_Offset :=
           Stream_Element_Offset (Itb.Wrapper.Nonce_Size (Cipher));
         Out_Nonce : Byte_Array (1 .. N_Len);
      begin
         Itb.Wrapper.Wrap_In_Place
           (Cipher, Outer_Key, Encrypted, Out_Nonce);
         declare
            Wire : Byte_Array (1 .. N_Len + Encrypted'Length);
            Body_First : Stream_Element_Offset;
         begin
            Wire (1 .. N_Len) := Out_Nonce;
            Wire (N_Len + 1 .. Wire'Last) := Encrypted;
            Wire_Bytes := Wire'Length;
            Itb.Wrapper.Unwrap_In_Place
              (Cipher, Outer_Key, Wire, Body_First);
            declare
               Pt : constant Byte_Array :=
                 Itb.Cipher.Decrypt
                   (Noise, Data, Start, Wire (Body_First .. Wire'Last));
            begin
               Recovered := new Byte_Array'(Pt);
            end;
         end;
      end;
   end Run_Message_Low_Level_NoMAC;

   --  Single Message — Low-Level: Areion-SoEM-512 + HMAC-BLAKE3.
   procedure Run_Message_Low_Level_Auth
     (Cipher    : Itb.Wrapper.Cipher_Type;
      Plain     : Byte_Array;
      Recovered : out Byte_Buf_Access;
      Wire_Bytes : out Stream_Element_Offset)
   is
      Noise : constant Itb.Seed.Seed :=
        Itb.Seed.Make (Stream_Primitive, 2048);
      Data  : constant Itb.Seed.Seed :=
        Itb.Seed.Make (Stream_Primitive, 2048);
      Start : constant Itb.Seed.Seed :=
        Itb.Seed.Make (Stream_Primitive, 2048);
      Mac_Key : constant Byte_Array := Random_Bytes (32);
      Mac     : constant Itb.MAC.MAC := Itb.MAC.Make (Mac_Name, Mac_Key);
      Outer_Key : constant Byte_Array :=
        Itb.Wrapper.Generate_Key (Cipher);
   begin
      Apply_Low_Level_Config;
      declare
         Encrypted : Byte_Array :=
           Itb.Cipher.Encrypt_Auth (Noise, Data, Start, Mac, Plain);
         N_Len : constant Stream_Element_Offset :=
           Stream_Element_Offset (Itb.Wrapper.Nonce_Size (Cipher));
         Out_Nonce : Byte_Array (1 .. N_Len);
      begin
         Itb.Wrapper.Wrap_In_Place
           (Cipher, Outer_Key, Encrypted, Out_Nonce);
         declare
            Wire : Byte_Array (1 .. N_Len + Encrypted'Length);
            Body_First : Stream_Element_Offset;
         begin
            Wire (1 .. N_Len) := Out_Nonce;
            Wire (N_Len + 1 .. Wire'Last) := Encrypted;
            Wire_Bytes := Wire'Length;
            Itb.Wrapper.Unwrap_In_Place
              (Cipher, Outer_Key, Wire, Body_First);
            declare
               Pt : constant Byte_Array :=
                 Itb.Cipher.Decrypt_Auth
                   (Noise, Data, Start, Mac,
                    Wire (Body_First .. Wire'Last));
            begin
               Recovered := new Byte_Array'(Pt);
            end;
         end;
      end;
   end Run_Message_Low_Level_Auth;

   ---------------------------------------------------------------------
   --  Matrix runner.
   ---------------------------------------------------------------------

   type Example_Tag is
     (Aead_Easy_IO, Aead_LowLevel_IO,
      NoAEAD_Easy_UserLoop, NoAEAD_LowLevel_UserLoop,
      Message_Easy_NoMAC, Message_Easy_Auth,
      Message_LowLevel_NoMAC, Message_LowLevel_Auth);

   function Tag_Name (T : Example_Tag) return String is
   begin
      case T is
         when Aead_Easy_IO             => return "aead-easy-io";
         when Aead_LowLevel_IO         => return "aead-lowlevel-io";
         when NoAEAD_Easy_UserLoop     => return "noaead-easy-userloop";
         when NoAEAD_LowLevel_UserLoop => return "noaead-lowlevel-userloop";
         when Message_Easy_NoMAC       => return "message-easy-nomac";
         when Message_Easy_Auth        => return "message-easy-auth";
         when Message_LowLevel_NoMAC   => return "message-lowlevel-nomac";
         when Message_LowLevel_Auth    => return "message-lowlevel-auth";
      end case;
   end Tag_Name;

   function Tag_PT_Bytes (T : Example_Tag) return Stream_Element_Offset is
   begin
      case T is
         when Aead_Easy_IO | Aead_LowLevel_IO
            | NoAEAD_Easy_UserLoop | NoAEAD_LowLevel_UserLoop =>
            return Stream_Bytes;
         when others =>
            return Single_Message_Bytes;
      end case;
   end Tag_PT_Bytes;

   procedure Dispatch
     (T          : Example_Tag;
      Cipher     : Itb.Wrapper.Cipher_Type;
      Plain      : Byte_Array;
      Recovered  : out Byte_Buf_Access;
      Wire_Bytes : out Stream_Element_Offset) is
   begin
      case T is
         when Aead_Easy_IO =>
            Run_AEAD_Easy_IO (Cipher, Plain, Recovered, Wire_Bytes);
         when Aead_LowLevel_IO =>
            Run_AEAD_Low_Level_IO (Cipher, Plain, Recovered, Wire_Bytes);
         when NoAEAD_Easy_UserLoop =>
            Run_NoAEAD_Easy_UserLoop
              (Cipher, Plain, Recovered, Wire_Bytes);
         when NoAEAD_LowLevel_UserLoop =>
            Run_NoAEAD_Low_Level_UserLoop
              (Cipher, Plain, Recovered, Wire_Bytes);
         when Message_Easy_NoMAC =>
            Run_Message_Easy_NoMAC
              (Cipher, Plain, Recovered, Wire_Bytes);
         when Message_Easy_Auth =>
            Run_Message_Easy_Auth
              (Cipher, Plain, Recovered, Wire_Bytes);
         when Message_LowLevel_NoMAC =>
            Run_Message_Low_Level_NoMAC
              (Cipher, Plain, Recovered, Wire_Bytes);
         when Message_LowLevel_Auth =>
            Run_Message_Low_Level_Auth
              (Cipher, Plain, Recovered, Wire_Bytes);
      end case;
   end Dispatch;

   ---------------------------------------------------------------------
   --  Argument parsing.
   ---------------------------------------------------------------------

   function Pad_Right (S : String; W : Positive) return String is
   begin
      if S'Length >= W then
         return S;
      else
         return S & [1 .. W - S'Length => ' '];
      end if;
   end Pad_Right;

   Example_Substring : String (1 .. 64) := [others => ' '];
   Example_Sub_Len   : Natural := 0;
   Cipher_Filter     : String (1 .. 16) := [others => ' '];
   Cipher_Filter_Len : Natural := 0;
   Verbose_Mode      : Boolean := False;

   function Has_Substring (Hay : String; Needle : String) return Boolean is
   begin
      if Needle'Length = 0 then
         return True;
      end if;
      if Hay'Length < Needle'Length then
         return False;
      end if;
      for I in Hay'First .. Hay'Last - Needle'Length + 1 loop
         if Hay (I .. I + Needle'Length - 1) = Needle then
            return True;
         end if;
      end loop;
      return False;
   end Has_Substring;

   procedure Parse_Args is
      I : Natural := 1;
      Cnt : constant Natural := Ada.Command_Line.Argument_Count;
   begin
      while I <= Cnt loop
         declare
            Arg : constant String := Ada.Command_Line.Argument (I);
         begin
            if Arg = "--example" and then I < Cnt then
               declare
                  V : constant String :=
                    Ada.Command_Line.Argument (I + 1);
               begin
                  Example_Substring (1 .. V'Length) := V;
                  Example_Sub_Len := V'Length;
                  I := I + 2;
               end;
            elsif Arg = "--cipher" and then I < Cnt then
               declare
                  V : constant String :=
                    Ada.Command_Line.Argument (I + 1);
               begin
                  Cipher_Filter (1 .. V'Length) := V;
                  Cipher_Filter_Len := V'Length;
                  I := I + 2;
               end;
            elsif Arg = "-v" or else Arg = "--verbose" then
               Verbose_Mode := True;
               I := I + 1;
            elsif Arg = "-h" or else Arg = "--help" then
               Ada.Text_IO.Put_Line
                 ("Usage: eitb [--example NAME] "
                  & "[--cipher ciphername] [-v]");
               Ada.Command_Line.Set_Exit_Status
                 (Ada.Command_Line.Success);
               return;
            else
               Ada.Text_IO.Put_Line
                 (Ada.Text_IO.Standard_Error,
                  "eitb: unknown argument: " & Arg);
               Ada.Command_Line.Set_Exit_Status (2);
               raise Program_Error with "unknown argument";
            end if;
         end;
      end loop;
   end Parse_Args;

   Pass : Natural := 0;
   Fail : Natural := 0;

begin
   Itb.Set_Max_Workers (0);

   Parse_Args;

   for T in Example_Tag loop
      if Example_Sub_Len = 0
        or else Has_Substring
                  (Tag_Name (T),
                   Example_Substring (1 .. Example_Sub_Len))
      then
         for C of Itb.Wrapper.All_Ciphers loop
            if Cipher_Filter_Len = 0
              or else Cipher_Filter (1 .. Cipher_Filter_Len) =
                      Itb.Wrapper.Ffi_Name (C)
            then
               declare
                  PT_N : constant Stream_Element_Offset := Tag_PT_Bytes (T);
                  Plaintext : constant Byte_Array := Random_Bytes (PT_N);
                  Recovered : Byte_Buf_Access := null;
                  Wire_Bytes : Stream_Element_Offset := 0;
                  OK : Boolean := False;
                  Err_Text : String (1 .. 256) := [others => ' '];
                  Err_Len : Natural := 0;
                  Tag_Out : constant String :=
                    Tag_Name (T);
                  Cipher_Out : constant String :=
                    Itb.Wrapper.Ffi_Name (C);
               begin
                  begin
                     Dispatch (T, C, Plaintext, Recovered, Wire_Bytes);
                     OK := Recovered /= null
                           and then Recovered.all = Plaintext;
                  exception
                     when E : others =>
                        OK := False;
                        declare
                           M : constant String :=
                             Ada.Exceptions.Exception_Message (E);
                           pragma Unreferenced (M);
                        begin
                           Err_Text (1 .. 7) := "raised ";
                           Err_Len := 7;
                        end;
                  end;
                  declare
                     Tag_Str : constant String :=
                       (if OK then "PASS" else "FAIL");
                     PT_Img  : constant String :=
                       Ada.Strings.Fixed.Trim
                         (Stream_Element_Offset'Image (PT_N),
                          Ada.Strings.Both);
                     Wire_Img : constant String :=
                       Ada.Strings.Fixed.Trim
                         (Stream_Element_Offset'Image (Wire_Bytes),
                          Ada.Strings.Both);
                  begin
                     Ada.Text_IO.Put_Line
                       ("[" & Tag_Str & "] "
                        & Pad_Right (Tag_Out, 26)
                        & " + " & Pad_Right (Cipher_Out, 8)
                        & "   pt=" & PT_Img
                        & " wire=" & Wire_Img
                        & (if OK then ""
                           else "  err: "
                                & Err_Text (1 .. Err_Len)));
                     if Verbose_Mode and then OK then
                        Ada.Text_IO.Put_Line
                          ("       pt fingerprint:  "
                           & Fingerprint (Plaintext));
                        Ada.Text_IO.Put_Line
                          ("       rcv fingerprint: "
                           & Fingerprint (Recovered.all));
                     end if;
                  end;
                  if OK then
                     Pass := Pass + 1;
                  else
                     Fail := Fail + 1;
                  end if;
                  if Recovered /= null then
                     Free_Buf (Recovered);
                  end if;
               end;
            end if;
         end loop;
      end if;
   end loop;

   Ada.Text_IO.New_Line;
   Ada.Text_IO.Put_Line
     ("=== Summary: "
      & Ada.Strings.Fixed.Trim
          (Natural'Image (Pass), Ada.Strings.Both)
      & " PASS, "
      & Ada.Strings.Fixed.Trim
          (Natural'Image (Fail), Ada.Strings.Both)
      & " FAIL ===");
   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Eitb;
