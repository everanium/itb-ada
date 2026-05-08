--  Authenticated Streaming AEAD tests covering the seed-based
--  Stream_Encryptor_Auth / Stream_Decryptor_Auth classes (Single +
--  Triple Ouroboros) and the free-subprogram convenience drivers.
--
--  Coverage: per-(width × Single/Triple × MAC) round-trip; reorder;
--  truncate-tail; cross-stream replay; stream-prefix tamper; empty
--  stream; single-chunk; closed-state preflight.

with Ada.Streams;  use Ada.Streams;
with Ada.Text_IO;
with Ada.Unchecked_Deallocation;

with Itb;          use Itb;
with Itb.Errors;
with Itb.MAC;
with Itb.Seed;
with Itb.Status;
with Itb.Streams;

procedure Test_Streams_Auth is

   ------------------------------------------------------------------
   --  In-memory Memory_Stream — same shape as test_streams.adb.
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
         Result (I) := Stream_Element (((Integer (I - 1) * 31 + 7) mod 256));
      end loop;
      return Result;
   end Pseudo_Plaintext;

   function Make_MAC_Key return Byte_Array is
      Key : Byte_Array (1 .. 32);
   begin
      for I in Key'Range loop
         Key (I) := 16#5A#;
      end loop;
      return Key;
   end Make_MAC_Key;

   procedure Drain_Auth
     (Dec  : in out Itb.Streams.Stream_Decryptor_Auth;
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
   end Drain_Auth;

   procedure Drain_Auth_Triple
     (Dec  : in out Itb.Streams.Stream_Decryptor_Auth_3;
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
   end Drain_Auth_Triple;

   --  Walks an auth-stream wire transcript, peels the 32-byte
   --  prefix, and slices the remaining bytes into per-chunk arrays.
   type Chunk_Array is array (Positive range <>) of Byte_Buf_Access;

   procedure Split_Chunks
     (CT      : Byte_Array;
      Prefix  : out Byte_Array;
      Chunks  : out Chunk_Array;
      Count   : out Natural)
   is
      Hsz  : constant Stream_Element_Offset :=
        Stream_Element_Offset (Itb.Header_Size);
      Off  : Stream_Element_Offset := CT'First + 32;
   begin
      Prefix := CT (CT'First .. CT'First + 31);
      Count := 0;
      while Off <= CT'Last loop
         declare
            Chunk_Len : constant Natural :=
              Itb.Parse_Chunk_Len (CT (Off .. Off + Hsz - 1));
            CL_Off : constant Stream_Element_Offset :=
              Stream_Element_Offset (Chunk_Len);
         begin
            Count := Count + 1;
            Chunks (Count) := new Byte_Array (1 .. CL_Off);
            Chunks (Count).all := CT (Off .. Off + CL_Off - 1);
            Off := Off + CL_Off;
         end;
      end loop;
   end Split_Chunks;

   procedure Free_All_Chunks
     (Chunks : in out Chunk_Array; Count : Natural) is
   begin
      for I in 1 .. Count loop
         if Chunks (I) /= null then
            Free_Buf (Chunks (I));
         end if;
      end loop;
   end Free_All_Chunks;

   ------------------------------------------------------------------
   --  Round-trip: Single Ouroboros across (hash × MAC) matrix.
   ------------------------------------------------------------------
   procedure Test_Single_Roundtrip is
      Hashes : constant array (1 .. 3) of String (1 .. 9) :=
        ["siphash24", "blake3   ", "areion512"];
      Hash_Lens : constant array (1 .. 3) of Positive := [9, 6, 9];
      Macs : constant array (1 .. 3) of String (1 .. 11) :=
        ["kmac256    ", "hmac-sha256", "hmac-blake3"];
      Mac_Lens : constant array (1 .. 3) of Positive := [7, 11, 11];
      Plaintext : constant Byte_Array :=
        Pseudo_Plaintext (Small_Chunk * 3 + 17);
   begin
      for HI in 1 .. 3 loop
         for MI in 1 .. 3 loop
            declare
               Hash_Name : constant String :=
                 Hashes (HI) (1 .. Hash_Lens (HI));
               Mac_Name  : constant String :=
                 Macs (MI) (1 .. Mac_Lens (MI));
               N    : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
               D    : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
               S    : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
               Mac  : constant Itb.MAC.MAC :=
                 Itb.MAC.Make (Mac_Name, Make_MAC_Key);
               CMem : aliased Memory_Stream;
               PMem : aliased Memory_Stream;
            begin
               declare
                  Enc : Itb.Streams.Stream_Encryptor_Auth :=
                    Itb.Streams.Make_Auth
                      (N, D, S, Mac, CMem'Access, Small_Chunk);
               begin
                  Itb.Streams.Write_Plaintext (Enc, Plaintext);
                  Itb.Streams.Finish (Enc);
               end;
               declare
                  Dec : Itb.Streams.Stream_Decryptor_Auth :=
                    Itb.Streams.Make_Auth (N, D, S, Mac, CMem'Access);
               begin
                  Drain_Auth (Dec, PMem);
                  Itb.Streams.Finish (Dec);
               end;
               if Snapshot (PMem) /= Plaintext then
                  raise Program_Error
                    with "Single auth roundtrip mismatch: "
                         & Hash_Name & "/" & Mac_Name;
               end if;
               Free (CMem);
               Free (PMem);
            end;
         end loop;
      end loop;
   end Test_Single_Roundtrip;

   ------------------------------------------------------------------
   --  Round-trip: Triple Ouroboros across (hash × MAC) matrix.
   ------------------------------------------------------------------
   procedure Test_Triple_Roundtrip is
      Hash_Name : constant String := "blake3";
      Mac_Names : constant array (1 .. 3) of String (1 .. 11) :=
        ["kmac256    ", "hmac-sha256", "hmac-blake3"];
      Mac_Lens : constant array (1 .. 3) of Positive := [7, 11, 11];
      Plaintext : constant Byte_Array :=
        Pseudo_Plaintext (Small_Chunk * 2 + 1);
   begin
      for MI in 1 .. 3 loop
         declare
            MN    : constant String :=
              Mac_Names (MI) (1 .. Mac_Lens (MI));
            N     : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
            D1    : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
            D2    : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
            D3    : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
            S1    : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
            S2    : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
            S3    : constant Itb.Seed.Seed := Itb.Seed.Make (Hash_Name, 1024);
            Mac   : constant Itb.MAC.MAC :=
              Itb.MAC.Make (MN, Make_MAC_Key);
            CMem  : aliased Memory_Stream;
            PMem  : aliased Memory_Stream;
         begin
            declare
               Enc : Itb.Streams.Stream_Encryptor_Auth_3 :=
                 Itb.Streams.Make_Auth_Triple
                   (N, D1, D2, D3, S1, S2, S3, Mac,
                    CMem'Access, Small_Chunk);
            begin
               Itb.Streams.Write_Plaintext (Enc, Plaintext);
               Itb.Streams.Finish (Enc);
            end;
            declare
               Dec : Itb.Streams.Stream_Decryptor_Auth_3 :=
                 Itb.Streams.Make_Auth_Triple
                   (N, D1, D2, D3, S1, S2, S3, Mac, CMem'Access);
            begin
               Drain_Auth_Triple (Dec, PMem);
               Itb.Streams.Finish (Dec);
            end;
            if Snapshot (PMem) /= Plaintext then
               raise Program_Error
                 with "Triple auth roundtrip mismatch: " & MN;
            end if;
            Free (CMem);
            Free (PMem);
         end;
      end loop;
   end Test_Triple_Roundtrip;

   ------------------------------------------------------------------
   --  Empty stream — encoder emits 32-byte prefix + 1 terminating
   --  zero-length chunk; decoder accepts.
   ------------------------------------------------------------------
   procedure Test_Empty_Stream is
      N    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      D    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Mac  : constant Itb.MAC.MAC :=
        Itb.MAC.Make ("hmac-blake3", Make_MAC_Key);
      CMem : aliased Memory_Stream;
      PMem : aliased Memory_Stream;
   begin
      declare
         Enc : Itb.Streams.Stream_Encryptor_Auth :=
           Itb.Streams.Make_Auth (N, D, S, Mac, CMem'Access, Small_Chunk);
      begin
         --  No Write_Plaintext call; Finish emits the terminating
         --  zero-length chunk.
         Itb.Streams.Finish (Enc);
      end;
      if Snapshot (CMem)'Length <= 32 then
         raise Program_Error with "empty stream lacks prefix + 1 chunk";
      end if;
      declare
         Dec : Itb.Streams.Stream_Decryptor_Auth :=
           Itb.Streams.Make_Auth (N, D, S, Mac, CMem'Access);
      begin
         Drain_Auth (Dec, PMem);
         Itb.Streams.Finish (Dec);
      end;
      if Snapshot (PMem)'Length /= 0 then
         raise Program_Error with "empty stream recovered non-zero bytes";
      end if;
      Free (CMem);
      Free (PMem);
   end Test_Empty_Stream;

   ------------------------------------------------------------------
   --  Truncate-tail — drop the last chunk, expect Stream_Truncated.
   ------------------------------------------------------------------
   procedure Test_Truncate_Tail is
      N    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      D    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Mac  : constant Itb.MAC.MAC :=
        Itb.MAC.Make ("hmac-blake3", Make_MAC_Key);
      Plaintext : constant Byte_Array :=
        Pseudo_Plaintext (Small_Chunk * 2 + 1);
      CMem      : aliased Memory_Stream;
      Trunc     : aliased Memory_Stream;
      PMem      : aliased Memory_Stream;
   begin
      declare
         Enc : Itb.Streams.Stream_Encryptor_Auth :=
           Itb.Streams.Make_Auth (N, D, S, Mac, CMem'Access, Small_Chunk);
      begin
         Itb.Streams.Write_Plaintext (Enc, Plaintext);
         Itb.Streams.Finish (Enc);
      end;
      declare
         CT          : constant Byte_Array := Snapshot (CMem);
         Prefix      : Byte_Array (1 .. 32);
         Chunks      : Chunk_Array (1 .. 16);
         Count       : Natural;
      begin
         Split_Chunks (CT, Prefix, Chunks, Count);
         Trunc.Write (Prefix);
         for I in 1 .. Count - 1 loop
            Trunc.Write (Chunks (I).all);
         end loop;
         declare
            Dec : Itb.Streams.Stream_Decryptor_Auth :=
              Itb.Streams.Make_Auth (N, D, S, Mac, Trunc'Access);
            Got_Expected : Boolean := False;
         begin
            Drain_Auth (Dec, PMem);
            begin
               Itb.Streams.Finish (Dec);
            exception
               when E : Itb.Errors.Itb_Stream_Truncated_Error =>
                  if Itb.Errors.Status_Code (E) =
                       Itb.Status.Stream_Truncated
                  then
                     Got_Expected := True;
                  end if;
            end;
            if not Got_Expected then
               raise Program_Error with "truncate-tail did not raise";
            end if;
         end;
         Free_All_Chunks (Chunks, Count);
      end;
      Free (CMem);
      Free (Trunc);
      Free (PMem);
   end Test_Truncate_Tail;

   ------------------------------------------------------------------
   --  Reorder — swap chunks 0 and 1, expect MAC failure.
   ------------------------------------------------------------------
   procedure Test_Reorder is
      N    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      D    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Mac  : constant Itb.MAC.MAC :=
        Itb.MAC.Make ("hmac-blake3", Make_MAC_Key);
      Plaintext : constant Byte_Array :=
        Pseudo_Plaintext (Small_Chunk * 2 + 1);
      CMem      : aliased Memory_Stream;
      Tampered  : aliased Memory_Stream;
      PMem      : aliased Memory_Stream;
   begin
      declare
         Enc : Itb.Streams.Stream_Encryptor_Auth :=
           Itb.Streams.Make_Auth (N, D, S, Mac, CMem'Access, Small_Chunk);
      begin
         Itb.Streams.Write_Plaintext (Enc, Plaintext);
         Itb.Streams.Finish (Enc);
      end;
      declare
         CT     : constant Byte_Array := Snapshot (CMem);
         Prefix : Byte_Array (1 .. 32);
         Chunks : Chunk_Array (1 .. 16);
         Count  : Natural;
      begin
         Split_Chunks (CT, Prefix, Chunks, Count);
         if Count < 3 then
            raise Program_Error with "need >= 3 chunks for reorder";
         end if;
         Tampered.Write (Prefix);
         --  Chunk indexes here are 1-based. Swap indices 1 and 2.
         Tampered.Write (Chunks (2).all);
         Tampered.Write (Chunks (1).all);
         for I in 3 .. Count loop
            Tampered.Write (Chunks (I).all);
         end loop;
         declare
            Dec : Itb.Streams.Stream_Decryptor_Auth :=
              Itb.Streams.Make_Auth (N, D, S, Mac, Tampered'Access);
            Got_Expected : Boolean := False;
         begin
            begin
               Drain_Auth (Dec, PMem);
               Itb.Streams.Finish (Dec);
            exception
               when E : Itb.Errors.Itb_Error =>
                  if Itb.Errors.Status_Code (E) =
                       Itb.Status.MAC_Failure
                  then
                     Got_Expected := True;
                  end if;
            end;
            if not Got_Expected then
               raise Program_Error with "reorder did not raise MAC_Failure";
            end if;
         end;
         Free_All_Chunks (Chunks, Count);
      end;
      Free (CMem);
      Free (Tampered);
      Free (PMem);
   end Test_Reorder;

   ------------------------------------------------------------------
   --  Stream-prefix tamper — flip a byte in the 32-byte prefix.
   ------------------------------------------------------------------
   procedure Test_Prefix_Tamper is
      N    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      D    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Mac  : constant Itb.MAC.MAC :=
        Itb.MAC.Make ("hmac-blake3", Make_MAC_Key);
      Plaintext : constant Byte_Array :=
        Pseudo_Plaintext (Small_Chunk * 2);
      CMem      : aliased Memory_Stream;
      Tampered  : aliased Memory_Stream;
      PMem      : aliased Memory_Stream;
   begin
      declare
         Enc : Itb.Streams.Stream_Encryptor_Auth :=
           Itb.Streams.Make_Auth (N, D, S, Mac, CMem'Access, Small_Chunk);
      begin
         Itb.Streams.Write_Plaintext (Enc, Plaintext);
         Itb.Streams.Finish (Enc);
      end;
      declare
         CT       : Byte_Array := Snapshot (CMem);
      begin
         CT (CT'First + 5) := CT (CT'First + 5) xor 16#80#;
         Tampered.Write (CT);
         declare
            Dec : Itb.Streams.Stream_Decryptor_Auth :=
              Itb.Streams.Make_Auth (N, D, S, Mac, Tampered'Access);
            Got_Expected : Boolean := False;
         begin
            begin
               Drain_Auth (Dec, PMem);
               Itb.Streams.Finish (Dec);
            exception
               when E : Itb.Errors.Itb_Error =>
                  if Itb.Errors.Status_Code (E) =
                       Itb.Status.MAC_Failure
                    or else Itb.Errors.Status_Code (E) =
                       Itb.Status.Bad_MAC
                  then
                     Got_Expected := True;
                  end if;
            end;
            if not Got_Expected then
               raise Program_Error
                 with "prefix tamper did not raise MAC_Failure";
            end if;
         end;
      end;
      Free (CMem);
      Free (Tampered);
      Free (PMem);
   end Test_Prefix_Tamper;

   ------------------------------------------------------------------
   --  After-final — append an extra chunk past the terminator.
   ------------------------------------------------------------------
   procedure Test_After_Final is
      N    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      D    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Mac  : constant Itb.MAC.MAC :=
        Itb.MAC.Make ("hmac-blake3", Make_MAC_Key);
      PA   : constant Byte_Array := Pseudo_Plaintext (64);
      PB   : constant Byte_Array :=
        Pseudo_Plaintext (Small_Chunk * 2);
      CA   : aliased Memory_Stream;
      CB   : aliased Memory_Stream;
      Tampered : aliased Memory_Stream;
      PMem : aliased Memory_Stream;
   begin
      declare
         EncA : Itb.Streams.Stream_Encryptor_Auth :=
           Itb.Streams.Make_Auth (N, D, S, Mac, CA'Access, Small_Chunk);
      begin
         Itb.Streams.Write_Plaintext (EncA, PA);
         Itb.Streams.Finish (EncA);
      end;
      declare
         EncB : Itb.Streams.Stream_Encryptor_Auth :=
           Itb.Streams.Make_Auth (N, D, S, Mac, CB'Access, Small_Chunk);
      begin
         Itb.Streams.Write_Plaintext (EncB, PB);
         Itb.Streams.Finish (EncB);
      end;
      declare
         CTA    : constant Byte_Array := Snapshot (CA);
         CTB    : constant Byte_Array := Snapshot (CB);
         Prefix : Byte_Array (1 .. 32);
         Chunks : Chunk_Array (1 .. 16);
         Count  : Natural;
      begin
         Tampered.Write (CTA);
         Split_Chunks (CTB, Prefix, Chunks, Count);
         Tampered.Write (Chunks (1).all);
         declare
            Dec : Itb.Streams.Stream_Decryptor_Auth :=
              Itb.Streams.Make_Auth (N, D, S, Mac, Tampered'Access);
            Got_Expected : Boolean := False;
         begin
            begin
               Drain_Auth (Dec, PMem);
               Itb.Streams.Finish (Dec);
            exception
               when E : Itb.Errors.Itb_Stream_After_Final_Error =>
                  if Itb.Errors.Status_Code (E) =
                       Itb.Status.Stream_After_Final
                  then
                     Got_Expected := True;
                  end if;
            end;
            if not Got_Expected then
               raise Program_Error
                 with "after-final did not raise Stream_After_Final";
            end if;
         end;
         Free_All_Chunks (Chunks, Count);
      end;
      Free (CA);
      Free (CB);
      Free (Tampered);
      Free (PMem);
   end Test_After_Final;

   ------------------------------------------------------------------
   --  Cross-stream replay — splice chunk 0 of stream B onto
   --  stream A's prefix, expect MAC failure.
   ------------------------------------------------------------------
   procedure Test_Cross_Stream_Replay is
      N    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      D    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Mac  : constant Itb.MAC.MAC :=
        Itb.MAC.Make ("hmac-blake3", Make_MAC_Key);
      PA   : constant Byte_Array :=
        Pseudo_Plaintext (Small_Chunk * 2);
      PB   : constant Byte_Array :=
        Pseudo_Plaintext (Small_Chunk * 2);
      CA   : aliased Memory_Stream;
      CB   : aliased Memory_Stream;
      Tampered : aliased Memory_Stream;
      PMem : aliased Memory_Stream;
   begin
      declare
         EncA : Itb.Streams.Stream_Encryptor_Auth :=
           Itb.Streams.Make_Auth (N, D, S, Mac, CA'Access, Small_Chunk);
      begin
         Itb.Streams.Write_Plaintext (EncA, PA);
         Itb.Streams.Finish (EncA);
      end;
      declare
         EncB : Itb.Streams.Stream_Encryptor_Auth :=
           Itb.Streams.Make_Auth (N, D, S, Mac, CB'Access, Small_Chunk);
      begin
         Itb.Streams.Write_Plaintext (EncB, PB);
         Itb.Streams.Finish (EncB);
      end;
      declare
         CTA       : constant Byte_Array := Snapshot (CA);
         CTB       : constant Byte_Array := Snapshot (CB);
         Prefix_A  : Byte_Array (1 .. 32);
         Prefix_B  : Byte_Array (1 .. 32);
         Chunks_A  : Chunk_Array (1 .. 16);
         Chunks_B  : Chunk_Array (1 .. 16);
         Count_A   : Natural;
         Count_B   : Natural;
      begin
         Split_Chunks (CTA, Prefix_A, Chunks_A, Count_A);
         Split_Chunks (CTB, Prefix_B, Chunks_B, Count_B);
         --  Splice B's chunk 1 into A's transcript at position 1.
         Tampered.Write (Prefix_A);
         Tampered.Write (Chunks_B (1).all);
         for I in 2 .. Count_A loop
            Tampered.Write (Chunks_A (I).all);
         end loop;
         declare
            Dec : Itb.Streams.Stream_Decryptor_Auth :=
              Itb.Streams.Make_Auth (N, D, S, Mac, Tampered'Access);
            Got_Expected : Boolean := False;
         begin
            begin
               Drain_Auth (Dec, PMem);
               Itb.Streams.Finish (Dec);
            exception
               when E : Itb.Errors.Itb_Error =>
                  if Itb.Errors.Status_Code (E) =
                       Itb.Status.MAC_Failure
                  then
                     Got_Expected := True;
                  end if;
            end;
            if not Got_Expected then
               raise Program_Error
                 with "cross-stream replay did not raise MAC_Failure";
            end if;
         end;
         Free_All_Chunks (Chunks_A, Count_A);
         Free_All_Chunks (Chunks_B, Count_B);
      end;
      Free (CA);
      Free (CB);
      Free (Tampered);
      Free (PMem);
   end Test_Cross_Stream_Replay;

   ------------------------------------------------------------------
   --  Truncate below prefix — feed only the partial 32-byte prefix.
   ------------------------------------------------------------------
   procedure Test_Truncate_Below_Prefix is
      N    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      D    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S    : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Mac  : constant Itb.MAC.MAC :=
        Itb.MAC.Make ("hmac-blake3", Make_MAC_Key);
      Plain : constant Byte_Array := Pseudo_Plaintext (64);
      CMem  : aliased Memory_Stream;
      Trunc : aliased Memory_Stream;
      PMem  : aliased Memory_Stream;
   begin
      declare
         Enc : Itb.Streams.Stream_Encryptor_Auth :=
           Itb.Streams.Make_Auth (N, D, S, Mac, CMem'Access, Small_Chunk);
      begin
         Itb.Streams.Write_Plaintext (Enc, Plain);
         Itb.Streams.Finish (Enc);
      end;
      Trunc.Write (Snapshot (CMem) (1 .. 16));  --  Less than 32 bytes.
      declare
         Dec : Itb.Streams.Stream_Decryptor_Auth :=
           Itb.Streams.Make_Auth (N, D, S, Mac, Trunc'Access);
         Got_Expected : Boolean := False;
      begin
         Drain_Auth (Dec, PMem);
         begin
            Itb.Streams.Finish (Dec);
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
      Free (CMem);
      Free (Trunc);
      Free (PMem);
   end Test_Truncate_Below_Prefix;

   ------------------------------------------------------------------
   --  Free-subprogram driver round-trip.
   ------------------------------------------------------------------
   procedure Test_Free_Subprogram_Driver is
      N     : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      D     : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      S     : constant Itb.Seed.Seed := Itb.Seed.Make ("blake3", 1024);
      Mac   : constant Itb.MAC.MAC :=
        Itb.MAC.Make ("kmac256", Make_MAC_Key);
      Plain : constant Byte_Array :=
        Pseudo_Plaintext (Small_Chunk * 3 + 1);
      Source : aliased Memory_Stream;
      CMem   : aliased Memory_Stream;
      PMem   : aliased Memory_Stream;
   begin
      Source.Write (Plain);
      Source.Pos := 1;
      Itb.Streams.Encrypt_Stream_Auth
        (N, D, S, Mac, Source'Access, CMem'Access, Small_Chunk);
      Itb.Streams.Decrypt_Stream_Auth
        (N, D, S, Mac, CMem'Access, PMem'Access, 4096);
      if Snapshot (PMem) /= Plain then
         raise Program_Error with "free-subprogram roundtrip mismatch";
      end if;
      Free (Source);
      Free (CMem);
      Free (PMem);
   end Test_Free_Subprogram_Driver;

begin
   Test_Single_Roundtrip;
   Test_Triple_Roundtrip;
   Test_Empty_Stream;
   Test_Truncate_Tail;
   Test_Reorder;
   Test_Prefix_Tamper;
   Test_After_Final;
   Test_Cross_Stream_Replay;
   Test_Truncate_Below_Prefix;
   Test_Free_Subprogram_Driver;
   Ada.Text_IO.Put_Line ("test_streams_auth: PASS");
end Test_Streams_Auth;
