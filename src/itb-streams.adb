--  Itb.Streams body — chunked encrypt / decrypt over
--  Ada.Streams.Root_Stream_Type'Class.

with Ada.Streams; use Ada.Streams;
with Ada.Unchecked_Deallocation;
with Interfaces.C;
with Interfaces.C.Strings;
with System;

with Itb.Errors;
with Itb.Status;

package body Itb.Streams is

   use type Interfaces.Unsigned_64;

   ---------------------------------------------------------------------
   --  Local helpers
   ---------------------------------------------------------------------

   procedure Free_Buffer is new Ada.Unchecked_Deallocation
     (Object => Byte_Array, Name => Byte_Buffer_Access);

   --  Allocates a fresh Byte_Array of the given Length on the heap.
   function Allocate (Length : Stream_Element_Offset)
     return Byte_Buffer_Access
   is
      Result : constant Byte_Buffer_Access :=
        new Byte_Array (1 .. Length);
   begin
      for I in Result'Range loop
         Result (I) := 0;
      end loop;
      return Result;
   end Allocate;

   --  Grow-on-demand + wipe-on-grow helper for the per-stream output
   --  cache. Mirrors Encryptor.Ensure_Capacity shape: zeroes the OLD
   --  buffer (if any) before discarding it so the previous-chunk
   --  ciphertext / plaintext does not linger in heap garbage between
   --  cipher calls. Used by the four AEAD per-chunk dispatchers
   --  (Encrypt_Chunk_Auth_Single_To_Sink / Triple, Decrypt_Chunk_Auth_
   --  Single / Triple) to amortise the per-chunk FFI output allocation
   --  across every chunk in the same stream.
   procedure Ensure_Stream_Cache
     (Cache : in out Byte_Buffer_Access;
      Need  : Stream_Element_Offset)
   is
   begin
      if Cache /= null and then Cache'Length >= Need then
         return;
      end if;
      if Cache /= null then
         Cache.all := [others => 0];
         Free_Buffer (Cache);
      end if;
      Cache := new Byte_Array (1 .. Need);
   end Ensure_Stream_Cache;

   --  Writes Data to the underlying Ada.Streams sink. Wraps the
   --  Stream'Class.Write primitive so call sites stay readable.
   procedure Write_All
     (Sink : not null access Root_Stream_Type'Class;
      Data : Byte_Array) is
   begin
      if Data'Length > 0 then
         Sink.all.Write (Data);
      end if;
   end Write_All;

   ---------------------------------------------------------------------
   --  Single Ouroboros — encryptor.
   ---------------------------------------------------------------------

   function Make
     (Noise      : Itb.Seed.Seed;
      Data       : Itb.Seed.Seed;
      Start      : Itb.Seed.Seed;
      Sink       : not null access Root_Stream_Type'Class;
      Chunk_Size : Stream_Element_Offset := Default_Chunk_Size)
      return Stream_Encryptor is
   begin
      if Chunk_Size <= 0 then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      return E : Stream_Encryptor do
         E.Noise_H    := Itb.Seed.Raw_Handle (Noise);
         E.Data_H     := Itb.Seed.Raw_Handle (Data);
         E.Start_H    := Itb.Seed.Raw_Handle (Start);
         E.Sink       := Sink;
         E.Chunk_Size := Chunk_Size;
         E.Buf        := Allocate (Chunk_Size);
         E.Buf_Used   := 0;
         E.Closed     := False;
      end return;
   end Make;

   ---------------------------------------------------------------------
   --  Inline encrypt / decrypt helpers — talk directly to libitb so we
   --  don't need to materialise an Itb.Seed.Seed value for each call.
   --  Mirrors Itb.Cipher.Run_*'s two-call probe / allocate / write
   --  idiom but consumes raw Itb.Sys.Handle values, which is what the
   --  streaming wrappers carry.
   ---------------------------------------------------------------------

   --  Per-chunk encrypt dispatcher that writes the resulting
   --  ciphertext directly to Sink. Returning the bytes through the
   --  sink rather than as a Byte_Array result keeps the per-chunk
   --  output buffer entirely on the heap; with a 16 MiB chunk size
   --  the ciphertext is ~20 MiB, which would burst the default 8 MiB
   --  thread stack as a returned Byte_Array.
   procedure Encrypt_Single_To_Sink
     (Noise_H : Itb.Sys.Handle;
      Data_H  : Itb.Sys.Handle;
      Start_H : Itb.Sys.Handle;
      Plain   : Byte_Array;
      Sink    : not null access Root_Stream_Type'Class)
   is
      use Interfaces.C;
      In_Addr : constant System.Address :=
        (if Plain'Length > 0 then Plain'Address else System.Null_Address);
      --  Pre-allocate from the canonical 1.25x + 128 KiB formula so
      --  the first FFI call reaches libitb with a buffer the cipher
      --  can write into directly. The C ABI runs the full encrypt on
      --  every call regardless of out-buffer capacity, so a probe-
      --  then-retry pattern doubles the cipher cost per chunk. See
      --  Itb.Encryptor.Cipher_Call for the rationale; retry once on
      --  the rare under-shoot using the returned out_len.
      Cap_LL  : constant Long_Long_Integer :=
        Long_Long_Integer'Max
          (131072,
           Long_Long_Integer (Plain'Length) * 5 / 4 + 131072);
      Cap     : constant size_t := size_t (Cap_LL);
      Result  : Byte_Buffer_Access :=
                  Allocate (Stream_Element_Offset (Cap));
      Out_Len : aliased size_t := 0;
      Status  : int;
   begin
      Status := Itb.Sys.ITB_Encrypt
                  (Noise_Handle => Noise_H,
                   Data_Handle  => Data_H,
                   Start_Handle => Start_H,
                   Plaintext    => In_Addr,
                   Pt_Len       => Plain'Length,
                   Out_Buf      => Result.all'Address,
                   Out_Cap      => Cap,
                   Out_Len      => Out_Len'Access);

      if Status = Itb.Status.Buffer_Too_Small then
         --  Pre-allocation was too tight (extremely rare given the
         --  1.25x + 128 KiB safety margin). Grow exactly to the size
         --  libitb just reported and retry. The first call already
         --  paid for the cipher work; this is the fallback path.
         declare
            Need    : constant size_t := Out_Len;
         begin
            Result.all := [others => 0];
            Free_Buffer (Result);
            Result := Allocate (Stream_Element_Offset (Need));
            Out_Len := 0;
            Status := Itb.Sys.ITB_Encrypt
                        (Noise_Handle => Noise_H,
                         Data_Handle  => Data_H,
                         Start_Handle => Start_H,
                         Plaintext    => In_Addr,
                         Pt_Len       => Plain'Length,
                         Out_Buf      => Result.all'Address,
                         Out_Cap      => Need,
                         Out_Len      => Out_Len'Access);
         end;
      end if;

      if Status /= 0 then
         Result.all := [others => 0];
         Free_Buffer (Result);
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      if Out_Len > 0 then
         Sink.all.Write (Result (1 .. Stream_Element_Offset (Out_Len)));
      end if;
      Result.all := [others => 0];
      Free_Buffer (Result);
   exception
      when others =>
         if Result /= null then
            Result.all := [others => 0];
            Free_Buffer (Result);
         end if;
         raise;
   end Encrypt_Single_To_Sink;

   --  Per-chunk decrypt dispatcher that returns the recovered
   --  plaintext as a heap-resident buffer (PT_Out) sized to the
   --  actual decoded length. Avoids a returned Byte_Array result
   --  which at large chunk sizes (~16 MiB) would materialise as a
   --  stack-resident copy on the caller's frame and burst the default
   --  8 MiB thread stack. Caller owns PT_Out and must Free_Buffer it
   --  after consuming the bytes.
   procedure Decrypt_Single_To_Buffer
     (Noise_H : Itb.Sys.Handle;
      Data_H  : Itb.Sys.Handle;
      Start_H : Itb.Sys.Handle;
      Cipher  : Byte_Array;
      PT_Out  : out Byte_Buffer_Access)
   is
      use Interfaces.C;
      In_Addr : constant System.Address :=
        (if Cipher'Length > 0 then Cipher'Address else System.Null_Address);
      --  See Encrypt_Single_To_Sink for the formula+retry-once
      --  rationale. Decrypt's plaintext is bounded above by the input
      --  ciphertext length, so the same 1.25x + 128 KiB envelope is
      --  comfortably sufficient.
      Cap_LL  : constant Long_Long_Integer :=
        Long_Long_Integer'Max
          (131072,
           Long_Long_Integer (Cipher'Length) * 5 / 4 + 131072);
      Cap     : constant size_t := size_t (Cap_LL);
      Result  : Byte_Buffer_Access :=
                  Allocate (Stream_Element_Offset (Cap));
      Out_Len : aliased size_t := 0;
      Status  : int;
   begin
      PT_Out := null;
      Status := Itb.Sys.ITB_Decrypt
                  (Noise_Handle => Noise_H,
                   Data_Handle  => Data_H,
                   Start_Handle => Start_H,
                   Ciphertext   => In_Addr,
                   Ct_Len       => Cipher'Length,
                   Out_Buf      => Result.all'Address,
                   Out_Cap      => Cap,
                   Out_Len      => Out_Len'Access);

      if Status = Itb.Status.Buffer_Too_Small then
         declare
            Need : constant size_t := Out_Len;
         begin
            Result.all := [others => 0];
            Free_Buffer (Result);
            Result := Allocate (Stream_Element_Offset (Need));
            Out_Len := 0;
            Status := Itb.Sys.ITB_Decrypt
                        (Noise_Handle => Noise_H,
                         Data_Handle  => Data_H,
                         Start_Handle => Start_H,
                         Ciphertext   => In_Addr,
                         Ct_Len       => Cipher'Length,
                         Out_Buf      => Result.all'Address,
                         Out_Cap      => Need,
                         Out_Len      => Out_Len'Access);
         end;
      end if;

      if Status /= 0 then
         Result.all := [others => 0];
         Free_Buffer (Result);
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      --  Shrink the buffer to the exact decoded length so the caller
      --  does not see uninitialised tail bytes. Allocate a fresh
      --  tight-fit buffer, copy the prefix, free the oversized one.
      --  Both buffers live on the heap so the copy does not touch
      --  the stack.
      declare
         Tight : constant Byte_Buffer_Access :=
           Allocate (Stream_Element_Offset (Out_Len));
      begin
         if Out_Len > 0 then
            Tight (1 .. Stream_Element_Offset (Out_Len)) :=
              Result (1 .. Stream_Element_Offset (Out_Len));
         end if;
         Result.all := [others => 0];
         Free_Buffer (Result);
         PT_Out := Tight;
      end;
   exception
      when others =>
         if Result /= null then
            Result.all := [others => 0];
            Free_Buffer (Result);
         end if;
         raise;
   end Decrypt_Single_To_Buffer;

   --  Triple-mode per-chunk encrypt dispatcher writing directly to
   --  Sink. See Encrypt_Single_To_Sink for the rationale.
   procedure Encrypt_Triple_To_Sink
     (Noise_H  : Itb.Sys.Handle;
      Data1_H  : Itb.Sys.Handle;
      Data2_H  : Itb.Sys.Handle;
      Data3_H  : Itb.Sys.Handle;
      Start1_H : Itb.Sys.Handle;
      Start2_H : Itb.Sys.Handle;
      Start3_H : Itb.Sys.Handle;
      Plain    : Byte_Array;
      Sink     : not null access Root_Stream_Type'Class)
   is
      use Interfaces.C;
      In_Addr : constant System.Address :=
        (if Plain'Length > 0 then Plain'Address else System.Null_Address);
      --  See Encrypt_Single_To_Sink for the formula+retry-once
      --  rationale. Triple Ouroboros expansion stays inside the same
      --  1.25x + 128 KiB envelope across the measured matrix.
      Cap_LL  : constant Long_Long_Integer :=
        Long_Long_Integer'Max
          (131072,
           Long_Long_Integer (Plain'Length) * 5 / 4 + 131072);
      Cap     : constant size_t := size_t (Cap_LL);
      Result  : Byte_Buffer_Access :=
                  Allocate (Stream_Element_Offset (Cap));
      Out_Len : aliased size_t := 0;
      Status  : int;
   begin
      Status := Itb.Sys.ITB_Encrypt3
                  (Noise_Handle  => Noise_H,
                   Data_Handle1  => Data1_H,
                   Data_Handle2  => Data2_H,
                   Data_Handle3  => Data3_H,
                   Start_Handle1 => Start1_H,
                   Start_Handle2 => Start2_H,
                   Start_Handle3 => Start3_H,
                   Plaintext     => In_Addr,
                   Pt_Len        => Plain'Length,
                   Out_Buf       => Result.all'Address,
                   Out_Cap       => Cap,
                   Out_Len       => Out_Len'Access);

      if Status = Itb.Status.Buffer_Too_Small then
         declare
            Need : constant size_t := Out_Len;
         begin
            Result.all := [others => 0];
            Free_Buffer (Result);
            Result := Allocate (Stream_Element_Offset (Need));
            Out_Len := 0;
            Status := Itb.Sys.ITB_Encrypt3
                        (Noise_Handle  => Noise_H,
                         Data_Handle1  => Data1_H,
                         Data_Handle2  => Data2_H,
                         Data_Handle3  => Data3_H,
                         Start_Handle1 => Start1_H,
                         Start_Handle2 => Start2_H,
                         Start_Handle3 => Start3_H,
                         Plaintext     => In_Addr,
                         Pt_Len        => Plain'Length,
                         Out_Buf       => Result.all'Address,
                         Out_Cap       => Need,
                         Out_Len       => Out_Len'Access);
         end;
      end if;

      if Status /= 0 then
         Result.all := [others => 0];
         Free_Buffer (Result);
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      if Out_Len > 0 then
         Sink.all.Write (Result (1 .. Stream_Element_Offset (Out_Len)));
      end if;
      Result.all := [others => 0];
      Free_Buffer (Result);
   exception
      when others =>
         if Result /= null then
            Result.all := [others => 0];
            Free_Buffer (Result);
         end if;
         raise;
   end Encrypt_Triple_To_Sink;

   --  Triple-mode per-chunk decrypt dispatcher returning a heap
   --  buffer. See Decrypt_Single_To_Buffer for the rationale.
   procedure Decrypt_Triple_To_Buffer
     (Noise_H  : Itb.Sys.Handle;
      Data1_H  : Itb.Sys.Handle;
      Data2_H  : Itb.Sys.Handle;
      Data3_H  : Itb.Sys.Handle;
      Start1_H : Itb.Sys.Handle;
      Start2_H : Itb.Sys.Handle;
      Start3_H : Itb.Sys.Handle;
      Cipher   : Byte_Array;
      PT_Out   : out Byte_Buffer_Access)
   is
      use Interfaces.C;
      In_Addr : constant System.Address :=
        (if Cipher'Length > 0 then Cipher'Address else System.Null_Address);
      --  See Encrypt_Single_To_Sink for the formula+retry-once
      --  rationale.
      Cap_LL  : constant Long_Long_Integer :=
        Long_Long_Integer'Max
          (131072,
           Long_Long_Integer (Cipher'Length) * 5 / 4 + 131072);
      Cap     : constant size_t := size_t (Cap_LL);
      Result  : Byte_Buffer_Access :=
                  Allocate (Stream_Element_Offset (Cap));
      Out_Len : aliased size_t := 0;
      Status  : int;
   begin
      PT_Out := null;
      Status := Itb.Sys.ITB_Decrypt3
                  (Noise_Handle  => Noise_H,
                   Data_Handle1  => Data1_H,
                   Data_Handle2  => Data2_H,
                   Data_Handle3  => Data3_H,
                   Start_Handle1 => Start1_H,
                   Start_Handle2 => Start2_H,
                   Start_Handle3 => Start3_H,
                   Ciphertext    => In_Addr,
                   Ct_Len        => Cipher'Length,
                   Out_Buf       => Result.all'Address,
                   Out_Cap       => Cap,
                   Out_Len       => Out_Len'Access);

      if Status = Itb.Status.Buffer_Too_Small then
         declare
            Need : constant size_t := Out_Len;
         begin
            Result.all := [others => 0];
            Free_Buffer (Result);
            Result := Allocate (Stream_Element_Offset (Need));
            Out_Len := 0;
            Status := Itb.Sys.ITB_Decrypt3
                        (Noise_Handle  => Noise_H,
                         Data_Handle1  => Data1_H,
                         Data_Handle2  => Data2_H,
                         Data_Handle3  => Data3_H,
                         Start_Handle1 => Start1_H,
                         Start_Handle2 => Start2_H,
                         Start_Handle3 => Start3_H,
                         Ciphertext    => In_Addr,
                         Ct_Len        => Cipher'Length,
                         Out_Buf       => Result.all'Address,
                         Out_Cap       => Need,
                         Out_Len       => Out_Len'Access);
         end;
      end if;

      if Status /= 0 then
         Result.all := [others => 0];
         Free_Buffer (Result);
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      declare
         Tight : constant Byte_Buffer_Access :=
           Allocate (Stream_Element_Offset (Out_Len));
      begin
         if Out_Len > 0 then
            Tight (1 .. Stream_Element_Offset (Out_Len)) :=
              Result (1 .. Stream_Element_Offset (Out_Len));
         end if;
         Result.all := [others => 0];
         Free_Buffer (Result);
         PT_Out := Tight;
      end;
   exception
      when others =>
         if Result /= null then
            Result.all := [others => 0];
            Free_Buffer (Result);
         end if;
         raise;
   end Decrypt_Triple_To_Buffer;

   ---------------------------------------------------------------------
   --  Stream_Encryptor — Write_Plaintext / Finish.
   ---------------------------------------------------------------------

   procedure Drain_Single (Self : in out Stream_Encryptor) is
   begin
      while Self.Buf_Used >= Self.Chunk_Size loop
         --  Pass the slice directly to Encrypt_Single_To_Sink so the
         --  per-chunk ciphertext never materialises as a stack-resident
         --  Byte_Array; with 16 MiB chunks the ~20 MiB output buffer
         --  stays on the heap inside the dispatcher.
         Encrypt_Single_To_Sink
           (Self.Noise_H, Self.Data_H, Self.Start_H,
            Self.Buf (1 .. Self.Chunk_Size),
            Self.Sink);
         if Self.Buf_Used > Self.Chunk_Size then
            Self.Buf (1 .. Self.Buf_Used - Self.Chunk_Size) :=
              Self.Buf
                (Self.Chunk_Size + 1 .. Self.Buf_Used);
         end if;
         Self.Buf_Used := Self.Buf_Used - Self.Chunk_Size;
         --  Zero the freed tail so plaintext does not linger in
         --  the source buffer's region the slide vacated.
         if Self.Buf_Used + 1 <= Self.Buf'Last then
            Self.Buf (Self.Buf_Used + 1 .. Self.Buf'Last)
              := [others => 0];
         end if;
      end loop;
   end Drain_Single;

   procedure Write_Plaintext
     (Self : in out Stream_Encryptor;
      Data : Byte_Array)
   is
      Cursor : Stream_Element_Offset := Data'First;
   begin
      if Self.Closed then
         Itb.Errors.Raise_For (Itb.Status.Easy_Closed);
      end if;
      while Cursor <= Data'Last loop
         declare
            Room      : constant Stream_Element_Offset :=
              Self.Buf'Length - Self.Buf_Used;
            Available : constant Stream_Element_Offset :=
              Data'Last - Cursor + 1;
            Take      : constant Stream_Element_Offset :=
              Stream_Element_Offset'Min (Room, Available);
         begin
            if Take > 0 then
               Self.Buf
                 (Self.Buf_Used + 1 .. Self.Buf_Used + Take) :=
                 Data (Cursor .. Cursor + Take - 1);
               Self.Buf_Used := Self.Buf_Used + Take;
               Cursor        := Cursor + Take;
            end if;
            if Self.Buf_Used >= Self.Chunk_Size then
               Drain_Single (Self);
            end if;
         end;
      end loop;
   end Write_Plaintext;

   procedure Finish (Self : in out Stream_Encryptor) is
   begin
      if Self.Closed then
         return;
      end if;
      if Self.Buf_Used > 0 then
         Encrypt_Single_To_Sink
           (Self.Noise_H, Self.Data_H, Self.Start_H,
            Self.Buf (1 .. Self.Buf_Used),
            Self.Sink);
         Self.Buf (1 .. Self.Buf_Used) := [others => 0];
         Self.Buf_Used := 0;
      end if;
      Self.Closed := True;
   end Finish;

   overriding procedure Finalize (Self : in out Stream_Encryptor) is
   begin
      --  Best-effort flush; errors during finalization are swallowed
      --  because there is no path to surface them. Callers that need
      --  to see flush-time errors must call Finish explicitly.
      if not Self.Closed then
         begin
            Finish (Self);
         exception
            when others => null;
         end;
      end if;
      if Self.Buf /= null then
         Self.Buf.all := [others => 0];
         Free_Buffer (Self.Buf);
      end if;
   end Finalize;

   ---------------------------------------------------------------------
   --  Stream_Decryptor — Read_Plaintext / Finish.
   ---------------------------------------------------------------------

   --  Initial read-buffer capacity for the decryptor's ciphertext
   --  staging buffer. Grows on demand if a single chunk turns out
   --  to be larger.
   Default_CT_Buffer : constant Stream_Element_Offset := 64 * 1024;

   --  Grows Self.Buf so that at least Min_Cap bytes fit.
   procedure Grow_Buf
     (Self    : in out Stream_Decryptor;
      Min_Cap : Stream_Element_Offset)
   is
      Old_Buf : Byte_Buffer_Access := Self.Buf;
      New_Cap : Stream_Element_Offset := Self.Buf'Length;
   begin
      while New_Cap < Min_Cap loop
         New_Cap := New_Cap * 2;
      end loop;
      declare
         New_Buf : constant Byte_Buffer_Access := Allocate (New_Cap);
      begin
         if Self.Buf_Used > 0 then
            New_Buf (1 .. Self.Buf_Used) :=
              Old_Buf (1 .. Self.Buf_Used);
         end if;
         Self.Buf := New_Buf;
      end;
      Free_Buffer (Old_Buf);
   end Grow_Buf;

   --  Reads up to Self.Buf'Length - Self.Buf_Used bytes from Source
   --  into the tail of Self.Buf. Sets Self.At_EOF on EOF. Returns the
   --  number of bytes actually read (0 on EOF).
   procedure Pull_Source
     (Self  : in out Stream_Decryptor;
      Read  : out Stream_Element_Offset)
   is
      First : constant Stream_Element_Offset := Self.Buf_Used + 1;
      Last  : constant Stream_Element_Offset := Self.Buf'Length;
      Got   : Stream_Element_Offset := First - 1;
   begin
      if First > Last then
         Read := 0;
         return;
      end if;
      Self.Source.all.Read
        (Self.Buf (First .. Last), Got);
      if Got < First then
         Self.At_EOF := True;
         Read        := 0;
      else
         Read          := Got - First + 1;
         Self.Buf_Used := Got;
      end if;
   end Pull_Source;

   function Make
     (Noise  : Itb.Seed.Seed;
      Data   : Itb.Seed.Seed;
      Start  : Itb.Seed.Seed;
      Source : not null access Root_Stream_Type'Class)
      return Stream_Decryptor is
   begin
      return D : Stream_Decryptor do
         D.Noise_H     := Itb.Seed.Raw_Handle (Noise);
         D.Data_H      := Itb.Seed.Raw_Handle (Data);
         D.Start_H     := Itb.Seed.Raw_Handle (Start);
         D.Source      := Source;
         D.Buf         := Allocate (Default_CT_Buffer);
         D.Buf_Used    := 0;
         D.Plain       := null;
         D.Plain_Pos   := 0;
         D.Plain_Last  := 0;
         D.Header_Size := Stream_Element_Offset (Itb.Header_Size);
         D.At_EOF      := False;
         D.Closed      := False;
      end return;
   end Make;

   --  Tries to decrypt one full chunk from Self.Buf; returns True if a
   --  chunk was decoded into Self.Plain (Plain_Pos / Plain_Last reset).
   --  Returns False when more ciphertext is required from Source. May
   --  raise on a malformed chunk header.
   function Try_Decode_Chunk
     (Self : in out Stream_Decryptor) return Boolean
   is
      Hdr_Len : constant Stream_Element_Offset := Self.Header_Size;
      Want    : Natural;
   begin
      if Self.Buf_Used < Hdr_Len then
         return False;
      end if;
      Want := Itb.Parse_Chunk_Len (Self.Buf (1 .. Hdr_Len));
      if Stream_Element_Offset (Want) > Self.Buf'Length then
         Grow_Buf (Self, Stream_Element_Offset (Want));
      end if;
      if Self.Buf_Used < Stream_Element_Offset (Want) then
         return False;
      end if;
      declare
         PT_Out : Byte_Buffer_Access;
         Tail   : constant Stream_Element_Offset :=
           Self.Buf_Used - Stream_Element_Offset (Want);
      begin
         --  Pass the slice directly to Decrypt_Single_To_Buffer so the
         --  per-chunk plaintext lives on the heap end-to-end; with
         --  large chunks a stack-resident PT copy would burst the
         --  default 8 MiB thread stack.
         Decrypt_Single_To_Buffer
           (Self.Noise_H, Self.Data_H, Self.Start_H,
            Self.Buf (1 .. Stream_Element_Offset (Want)),
            PT_Out);
         --  Slide unconsumed ciphertext bytes down.
         if Tail > 0 then
            Self.Buf (1 .. Tail) :=
              Self.Buf
                (Stream_Element_Offset (Want) + 1 .. Self.Buf_Used);
         end if;
         Self.Buf_Used := Tail;
         --  Stash the recovered plaintext for the caller to drain.
         if Self.Plain /= null then
            Self.Plain.all := [others => 0];
            Free_Buffer (Self.Plain);
         end if;
         Self.Plain      := PT_Out;
         Self.Plain_Pos  := 1;
         Self.Plain_Last := Self.Plain'Last;
         return True;
      end;
   end Try_Decode_Chunk;

   procedure Read_Plaintext
     (Self   : in out Stream_Decryptor;
      Buffer : out Byte_Array;
      Last   : out Stream_Element_Offset)
   is
      Cursor : Stream_Element_Offset := Buffer'First;
   begin
      Last := Buffer'First - 1;
      if Self.Closed then
         Itb.Errors.Raise_For (Itb.Status.Easy_Closed);
      end if;
      while Cursor <= Buffer'Last loop
         --  Drain anything already decoded.
         if Self.Plain /= null
           and then Self.Plain_Pos <= Self.Plain_Last
         then
            declare
               Avail : constant Stream_Element_Offset :=
                 Self.Plain_Last - Self.Plain_Pos + 1;
               Room  : constant Stream_Element_Offset :=
                 Buffer'Last - Cursor + 1;
               Take  : constant Stream_Element_Offset :=
                 Stream_Element_Offset'Min (Avail, Room);
            begin
               Buffer (Cursor .. Cursor + Take - 1) :=
                 Self.Plain
                   (Self.Plain_Pos .. Self.Plain_Pos + Take - 1);
               Cursor          := Cursor + Take;
               Self.Plain_Pos  := Self.Plain_Pos + Take;
               Last            := Cursor - 1;
            end;
         else
            --  Either no chunk decoded yet, or the previous one is
            --  drained — try to decode a new one.
            if not Try_Decode_Chunk (Self) then
               --  Need more ciphertext from the underlying source.
               if Self.At_EOF then
                  return;
               end if;
               declare
                  Got : Stream_Element_Offset;
               begin
                  if Self.Buf_Used = Self.Buf'Length then
                     --  Full buffer but Try_Decode said no — header
                     --  reports a chunk larger than current capacity;
                     --  enlarge.
                     Grow_Buf (Self, Self.Buf'Length * 2);
                  end if;
                  Pull_Source (Self, Got);
                  if Got = 0 and then Self.At_EOF then
                     return;
                  end if;
               end;
            end if;
         end if;
      end loop;
   end Read_Plaintext;

   procedure Finish (Self : in out Stream_Decryptor) is
   begin
      if Self.Closed then
         return;
      end if;
      --  Drain any remaining decoded plaintext silently — Finish only
      --  validates ciphertext-side framing.
      if Self.Buf_Used > 0 then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      Self.Closed := True;
   end Finish;

   overriding procedure Finalize (Self : in out Stream_Decryptor) is
   begin
      --  Mark closed without raising on partial input — Finalize has
      --  no path to surface errors. Callers who need to detect a
      --  half-chunk tail must call Finish explicitly.
      Self.Closed := True;
      if Self.Buf /= null then
         Free_Buffer (Self.Buf);
      end if;
      if Self.Plain /= null then
         Self.Plain.all := [others => 0];
         Free_Buffer (Self.Plain);
      end if;
   end Finalize;

   ---------------------------------------------------------------------
   --  Stream_Encryptor_Triple — same shape, 7 seed handles.
   ---------------------------------------------------------------------

   function Make_Triple
     (Noise      : Itb.Seed.Seed;
      Data1      : Itb.Seed.Seed;
      Data2      : Itb.Seed.Seed;
      Data3      : Itb.Seed.Seed;
      Start1     : Itb.Seed.Seed;
      Start2     : Itb.Seed.Seed;
      Start3     : Itb.Seed.Seed;
      Sink       : not null access Root_Stream_Type'Class;
      Chunk_Size : Stream_Element_Offset := Default_Chunk_Size)
      return Stream_Encryptor_Triple is
   begin
      if Chunk_Size <= 0 then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      return E : Stream_Encryptor_Triple do
         E.Noise_H    := Itb.Seed.Raw_Handle (Noise);
         E.Data1_H    := Itb.Seed.Raw_Handle (Data1);
         E.Data2_H    := Itb.Seed.Raw_Handle (Data2);
         E.Data3_H    := Itb.Seed.Raw_Handle (Data3);
         E.Start1_H   := Itb.Seed.Raw_Handle (Start1);
         E.Start2_H   := Itb.Seed.Raw_Handle (Start2);
         E.Start3_H   := Itb.Seed.Raw_Handle (Start3);
         E.Sink       := Sink;
         E.Chunk_Size := Chunk_Size;
         E.Buf        := Allocate (Chunk_Size);
         E.Buf_Used   := 0;
         E.Closed     := False;
      end return;
   end Make_Triple;

   procedure Drain_Triple (Self : in out Stream_Encryptor_Triple) is
   begin
      while Self.Buf_Used >= Self.Chunk_Size loop
         Encrypt_Triple_To_Sink
           (Self.Noise_H,
            Self.Data1_H, Self.Data2_H, Self.Data3_H,
            Self.Start1_H, Self.Start2_H, Self.Start3_H,
            Self.Buf (1 .. Self.Chunk_Size),
            Self.Sink);
         if Self.Buf_Used > Self.Chunk_Size then
            Self.Buf (1 .. Self.Buf_Used - Self.Chunk_Size) :=
              Self.Buf
                (Self.Chunk_Size + 1 .. Self.Buf_Used);
         end if;
         Self.Buf_Used := Self.Buf_Used - Self.Chunk_Size;
         if Self.Buf_Used + 1 <= Self.Buf'Last then
            Self.Buf (Self.Buf_Used + 1 .. Self.Buf'Last)
              := [others => 0];
         end if;
      end loop;
   end Drain_Triple;

   procedure Write_Plaintext
     (Self : in out Stream_Encryptor_Triple;
      Data : Byte_Array)
   is
      Cursor : Stream_Element_Offset := Data'First;
   begin
      if Self.Closed then
         Itb.Errors.Raise_For (Itb.Status.Easy_Closed);
      end if;
      while Cursor <= Data'Last loop
         declare
            Room      : constant Stream_Element_Offset :=
              Self.Buf'Length - Self.Buf_Used;
            Available : constant Stream_Element_Offset :=
              Data'Last - Cursor + 1;
            Take      : constant Stream_Element_Offset :=
              Stream_Element_Offset'Min (Room, Available);
         begin
            if Take > 0 then
               Self.Buf
                 (Self.Buf_Used + 1 .. Self.Buf_Used + Take) :=
                 Data (Cursor .. Cursor + Take - 1);
               Self.Buf_Used := Self.Buf_Used + Take;
               Cursor        := Cursor + Take;
            end if;
            if Self.Buf_Used >= Self.Chunk_Size then
               Drain_Triple (Self);
            end if;
         end;
      end loop;
   end Write_Plaintext;

   procedure Finish (Self : in out Stream_Encryptor_Triple) is
   begin
      if Self.Closed then
         return;
      end if;
      if Self.Buf_Used > 0 then
         Encrypt_Triple_To_Sink
           (Self.Noise_H,
            Self.Data1_H, Self.Data2_H, Self.Data3_H,
            Self.Start1_H, Self.Start2_H, Self.Start3_H,
            Self.Buf (1 .. Self.Buf_Used),
            Self.Sink);
         Self.Buf (1 .. Self.Buf_Used) := [others => 0];
         Self.Buf_Used := 0;
      end if;
      Self.Closed := True;
   end Finish;

   overriding procedure Finalize (Self : in out Stream_Encryptor_Triple) is
   begin
      if not Self.Closed then
         begin
            Finish (Self);
         exception
            when others => null;
         end;
      end if;
      if Self.Buf /= null then
         Self.Buf.all := [others => 0];
         Free_Buffer (Self.Buf);
      end if;
   end Finalize;

   ---------------------------------------------------------------------
   --  Stream_Decryptor_Triple — same shape, 7 seed handles.
   ---------------------------------------------------------------------

   procedure Grow_Buf
     (Self    : in out Stream_Decryptor_Triple;
      Min_Cap : Stream_Element_Offset)
   is
      Old_Buf : Byte_Buffer_Access := Self.Buf;
      New_Cap : Stream_Element_Offset := Self.Buf'Length;
   begin
      while New_Cap < Min_Cap loop
         New_Cap := New_Cap * 2;
      end loop;
      declare
         New_Buf : constant Byte_Buffer_Access := Allocate (New_Cap);
      begin
         if Self.Buf_Used > 0 then
            New_Buf (1 .. Self.Buf_Used) :=
              Old_Buf (1 .. Self.Buf_Used);
         end if;
         Self.Buf := New_Buf;
      end;
      Free_Buffer (Old_Buf);
   end Grow_Buf;

   procedure Pull_Source
     (Self  : in out Stream_Decryptor_Triple;
      Read  : out Stream_Element_Offset)
   is
      First : constant Stream_Element_Offset := Self.Buf_Used + 1;
      Last  : constant Stream_Element_Offset := Self.Buf'Length;
      Got   : Stream_Element_Offset := First - 1;
   begin
      if First > Last then
         Read := 0;
         return;
      end if;
      Self.Source.all.Read
        (Self.Buf (First .. Last), Got);
      if Got < First then
         Self.At_EOF := True;
         Read        := 0;
      else
         Read          := Got - First + 1;
         Self.Buf_Used := Got;
      end if;
   end Pull_Source;

   function Make_Triple
     (Noise  : Itb.Seed.Seed;
      Data1  : Itb.Seed.Seed;
      Data2  : Itb.Seed.Seed;
      Data3  : Itb.Seed.Seed;
      Start1 : Itb.Seed.Seed;
      Start2 : Itb.Seed.Seed;
      Start3 : Itb.Seed.Seed;
      Source : not null access Root_Stream_Type'Class)
      return Stream_Decryptor_Triple is
   begin
      return D : Stream_Decryptor_Triple do
         D.Noise_H     := Itb.Seed.Raw_Handle (Noise);
         D.Data1_H     := Itb.Seed.Raw_Handle (Data1);
         D.Data2_H     := Itb.Seed.Raw_Handle (Data2);
         D.Data3_H     := Itb.Seed.Raw_Handle (Data3);
         D.Start1_H    := Itb.Seed.Raw_Handle (Start1);
         D.Start2_H    := Itb.Seed.Raw_Handle (Start2);
         D.Start3_H    := Itb.Seed.Raw_Handle (Start3);
         D.Source      := Source;
         D.Buf         := Allocate (Default_CT_Buffer);
         D.Buf_Used    := 0;
         D.Plain       := null;
         D.Plain_Pos   := 0;
         D.Plain_Last  := 0;
         D.Header_Size := Stream_Element_Offset (Itb.Header_Size);
         D.At_EOF      := False;
         D.Closed      := False;
      end return;
   end Make_Triple;

   function Try_Decode_Chunk
     (Self : in out Stream_Decryptor_Triple) return Boolean
   is
      Hdr_Len : constant Stream_Element_Offset := Self.Header_Size;
      Want    : Natural;
   begin
      if Self.Buf_Used < Hdr_Len then
         return False;
      end if;
      Want := Itb.Parse_Chunk_Len (Self.Buf (1 .. Hdr_Len));
      if Stream_Element_Offset (Want) > Self.Buf'Length then
         Grow_Buf (Self, Stream_Element_Offset (Want));
      end if;
      if Self.Buf_Used < Stream_Element_Offset (Want) then
         return False;
      end if;
      declare
         PT_Out : Byte_Buffer_Access;
         Tail   : constant Stream_Element_Offset :=
           Self.Buf_Used - Stream_Element_Offset (Want);
      begin
         Decrypt_Triple_To_Buffer
           (Self.Noise_H,
            Self.Data1_H, Self.Data2_H, Self.Data3_H,
            Self.Start1_H, Self.Start2_H, Self.Start3_H,
            Self.Buf (1 .. Stream_Element_Offset (Want)),
            PT_Out);
         if Tail > 0 then
            Self.Buf (1 .. Tail) :=
              Self.Buf
                (Stream_Element_Offset (Want) + 1 .. Self.Buf_Used);
         end if;
         Self.Buf_Used := Tail;
         if Self.Plain /= null then
            Self.Plain.all := [others => 0];
            Free_Buffer (Self.Plain);
         end if;
         Self.Plain      := PT_Out;
         Self.Plain_Pos  := 1;
         Self.Plain_Last := Self.Plain'Last;
         return True;
      end;
   end Try_Decode_Chunk;

   procedure Read_Plaintext
     (Self   : in out Stream_Decryptor_Triple;
      Buffer : out Byte_Array;
      Last   : out Stream_Element_Offset)
   is
      Cursor : Stream_Element_Offset := Buffer'First;
   begin
      Last := Buffer'First - 1;
      if Self.Closed then
         Itb.Errors.Raise_For (Itb.Status.Easy_Closed);
      end if;
      while Cursor <= Buffer'Last loop
         if Self.Plain /= null
           and then Self.Plain_Pos <= Self.Plain_Last
         then
            declare
               Avail : constant Stream_Element_Offset :=
                 Self.Plain_Last - Self.Plain_Pos + 1;
               Room  : constant Stream_Element_Offset :=
                 Buffer'Last - Cursor + 1;
               Take  : constant Stream_Element_Offset :=
                 Stream_Element_Offset'Min (Avail, Room);
            begin
               Buffer (Cursor .. Cursor + Take - 1) :=
                 Self.Plain
                   (Self.Plain_Pos .. Self.Plain_Pos + Take - 1);
               Cursor          := Cursor + Take;
               Self.Plain_Pos  := Self.Plain_Pos + Take;
               Last            := Cursor - 1;
            end;
         else
            if not Try_Decode_Chunk (Self) then
               if Self.At_EOF then
                  return;
               end if;
               declare
                  Got : Stream_Element_Offset;
               begin
                  if Self.Buf_Used = Self.Buf'Length then
                     Grow_Buf (Self, Self.Buf'Length * 2);
                  end if;
                  Pull_Source (Self, Got);
                  if Got = 0 and then Self.At_EOF then
                     return;
                  end if;
               end;
            end if;
         end if;
      end loop;
   end Read_Plaintext;

   procedure Finish (Self : in out Stream_Decryptor_Triple) is
   begin
      if Self.Closed then
         return;
      end if;
      if Self.Buf_Used > 0 then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      Self.Closed := True;
   end Finish;

   overriding procedure Finalize (Self : in out Stream_Decryptor_Triple) is
   begin
      Self.Closed := True;
      if Self.Buf /= null then
         Free_Buffer (Self.Buf);
      end if;
      if Self.Plain /= null then
         Self.Plain.all := [others => 0];
         Free_Buffer (Self.Plain);
      end if;
   end Finalize;

   ---------------------------------------------------------------------
   --  Free-subprogram convenience drivers.
   ---------------------------------------------------------------------

   procedure Encrypt_Stream
     (Noise      : Itb.Seed.Seed;
      Data       : Itb.Seed.Seed;
      Start      : Itb.Seed.Seed;
      Source     : not null access Root_Stream_Type'Class;
      Sink       : not null access Root_Stream_Type'Class;
      Chunk_Size : Stream_Element_Offset := Default_Chunk_Size)
   is
      Enc : Stream_Encryptor :=
        Make (Noise, Data, Start, Sink, Chunk_Size);
      --  Buffer lives on the heap so 16 MB defaults don't blow the
      --  task stack. Released deterministically at scope exit.
      Buf : Byte_Buffer_Access := Allocate (Chunk_Size);
      Got : Stream_Element_Offset;
   begin
      loop
         Got := Buf'First - 1;
         Source.all.Read (Buf.all, Got);
         exit when Got < Buf'First;
         Write_Plaintext (Enc, Buf (Buf'First .. Got));
      end loop;
      Finish (Enc);
      Buf.all := [others => 0];
      Free_Buffer (Buf);
   exception
      when others =>
         if Buf /= null then
            Buf.all := [others => 0];
            Free_Buffer (Buf);
         end if;
         raise;
   end Encrypt_Stream;

   procedure Decrypt_Stream
     (Noise     : Itb.Seed.Seed;
      Data      : Itb.Seed.Seed;
      Start     : Itb.Seed.Seed;
      Source    : not null access Root_Stream_Type'Class;
      Sink      : not null access Root_Stream_Type'Class;
      Read_Size : Stream_Element_Offset := Default_Chunk_Size)
   is
   begin
      if Read_Size <= 0 then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      declare
         Dec : Stream_Decryptor := Make (Noise, Data, Start, Source);
         Buf : Byte_Buffer_Access := Allocate (Read_Size);
         Got : Stream_Element_Offset;
      begin
         loop
            Read_Plaintext (Dec, Buf.all, Got);
            exit when Got < Buf'First;
            Write_All (Sink, Buf (Buf'First .. Got));
         end loop;
         Finish (Dec);
         Buf.all := [others => 0];
         Free_Buffer (Buf);
      exception
         when others =>
            if Buf /= null then
               Buf.all := [others => 0];
               Free_Buffer (Buf);
            end if;
            raise;
      end;
   end Decrypt_Stream;

   procedure Encrypt_Stream_Triple
     (Noise      : Itb.Seed.Seed;
      Data1      : Itb.Seed.Seed;
      Data2      : Itb.Seed.Seed;
      Data3      : Itb.Seed.Seed;
      Start1     : Itb.Seed.Seed;
      Start2     : Itb.Seed.Seed;
      Start3     : Itb.Seed.Seed;
      Source     : not null access Root_Stream_Type'Class;
      Sink       : not null access Root_Stream_Type'Class;
      Chunk_Size : Stream_Element_Offset := Default_Chunk_Size)
   is
      Enc : Stream_Encryptor_Triple :=
        Make_Triple (Noise, Data1, Data2, Data3,
                     Start1, Start2, Start3, Sink, Chunk_Size);
      Buf : Byte_Buffer_Access := Allocate (Chunk_Size);
      Got : Stream_Element_Offset;
   begin
      loop
         Got := Buf'First - 1;
         Source.all.Read (Buf.all, Got);
         exit when Got < Buf'First;
         Write_Plaintext (Enc, Buf (Buf'First .. Got));
      end loop;
      Finish (Enc);
      Buf.all := [others => 0];
      Free_Buffer (Buf);
   exception
      when others =>
         if Buf /= null then
            Buf.all := [others => 0];
            Free_Buffer (Buf);
         end if;
         raise;
   end Encrypt_Stream_Triple;

   procedure Decrypt_Stream_Triple
     (Noise     : Itb.Seed.Seed;
      Data1     : Itb.Seed.Seed;
      Data2     : Itb.Seed.Seed;
      Data3     : Itb.Seed.Seed;
      Start1    : Itb.Seed.Seed;
      Start2    : Itb.Seed.Seed;
      Start3    : Itb.Seed.Seed;
      Source    : not null access Root_Stream_Type'Class;
      Sink      : not null access Root_Stream_Type'Class;
      Read_Size : Stream_Element_Offset := Default_Chunk_Size)
   is
   begin
      if Read_Size <= 0 then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      declare
         Dec : Stream_Decryptor_Triple :=
           Make_Triple (Noise, Data1, Data2, Data3,
                        Start1, Start2, Start3, Source);
         Buf : Byte_Buffer_Access := Allocate (Read_Size);
         Got : Stream_Element_Offset;
      begin
         loop
            Read_Plaintext (Dec, Buf.all, Got);
            exit when Got < Buf'First;
            Write_All (Sink, Buf (Buf'First .. Got));
         end loop;
         Finish (Dec);
         Buf.all := [others => 0];
         Free_Buffer (Buf);
      exception
         when others =>
            if Buf /= null then
               Buf.all := [others => 0];
               Free_Buffer (Buf);
            end if;
            raise;
      end;
   end Decrypt_Stream_Triple;

   ---------------------------------------------------------------------
   --  Streaming AEAD: shared helpers.
   ---------------------------------------------------------------------

   Stream_ID_Length : constant Stream_Element_Offset := 32;

   --  Generates a CSPRNG-fresh 32-byte Streaming AEAD anchor by
   --  piggybacking on libitb's CSPRNG: ITB_NewSeedFromComponents
   --  with hash_key=NULL triggers a CSPRNG draw on the Go side, and
   --  ITB_GetSeedHashKey reads back the 32-byte fixed key under the
   --  blake3 primitive. Mirrors the C reference helper in
   --  bindings/c/src/streams.c.
   procedure Generate_Stream_ID (Out_Bytes : out Stream_ID_Bytes) is
      use Interfaces.C;
      Comps   : aliased constant array (1 .. 8) of Itb.Sys.U64 :=
                  [1, 2, 3, 4, 5, 6, 7, 8];
      Cname   : Interfaces.C.Strings.chars_ptr :=
                  Interfaces.C.Strings.New_String ("blake3");
      H       : aliased Itb.Sys.Handle := 0;
      Got     : aliased size_t := 0;
      Status  : int;
   begin
      Out_Bytes := [others => 0];
      Status := Itb.Sys.ITB_NewSeedFromComponents
                  (Hash_Name      => Cname,
                   Components     => Comps'Address,
                   Components_Len => Comps'Length,
                   Hash_Key       => System.Null_Address,
                   Hash_Key_Len   => 0,
                   Out_Handle     => H'Access);
      Interfaces.C.Strings.Free (Cname);
      if Status /= Itb.Status.OK then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      Status := Itb.Sys.ITB_GetSeedHashKey
                  (H       => H,
                   Out_Buf => Out_Bytes'Address,
                   Cap     => size_t (Stream_ID_Length),
                   Out_Len => Got'Access);
      declare
         Free_Status : constant int := Itb.Sys.ITB_FreeSeed (H);
         pragma Unreferenced (Free_Status);
      begin
         null;
      end;
      if Status /= Itb.Status.OK then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      if Got /= size_t (Stream_ID_Length) then
         Itb.Errors.Raise_For (Itb.Status.Internal);
      end if;
   end Generate_Stream_ID;

   --  Reads two big-endian bytes at offset Off in Buf and returns
   --  them as Natural.
   function Read_BE16
     (Buf : Byte_Array;
      Off : Stream_Element_Offset) return Natural
   is
   begin
      return Natural (Buf (Off)) * 256 + Natural (Buf (Off + 1));
   end Read_BE16;

   --  Per-chunk encrypt dispatch (Single + MAC). Probes required
   --  size, allocates, calls again. Returns the allocated chunk.
   --  Per-chunk Single auth encrypt dispatcher writing directly to
   --  Sink. Out_Pixels carries the (W,H)-derived pixel count parsed
   --  from the cipher header so the caller can advance Cum_Pixels
   --  without re-parsing. The Cache parameter routes the FFI write
   --  target through the per-stream output buffer (grow-on-demand +
   --  wipe-on-grow + wipe-on-Finalize) instead of a fresh allocation
   --  per chunk; mirrors Encryptor.Cache discipline at the streaming-
   --  class level.
   procedure Encrypt_Chunk_Auth_Single_To_Sink
     (Width       : Integer;
      Noise_H     : Itb.Sys.Handle;
      Data_H      : Itb.Sys.Handle;
      Start_H     : Itb.Sys.Handle;
      MAC_H       : Itb.Sys.Handle;
      Plain       : Byte_Array;
      Stream_ID   : Stream_ID_Bytes;
      Cum_Pixels  : Itb.Sys.U64;
      Final_Flag  : Boolean;
      Header_Size : Stream_Element_Offset;
      Sink        : not null access Root_Stream_Type'Class;
      Cache       : in out Byte_Buffer_Access;
      Out_Pixels  : out Itb.Sys.U64)
   is
      use Interfaces.C;
      In_Addr : constant System.Address :=
        (if Plain'Length > 0 then Plain'Address else System.Null_Address);
      FF      : constant int := (if Final_Flag then 1 else 0);
      --  See Encrypt_Single_To_Sink for the formula+retry-once
      --  rationale. The 1.25x + 128 KiB envelope absorbs the +1
      --  flag byte and +32-byte MAC tag inside the container body
      --  without an extra grow on any chunk size measured in the
      --  matrix.
      Cap_LL  : constant Long_Long_Integer :=
        Long_Long_Integer'Max
          (131072,
           Long_Long_Integer (Plain'Length) * 5 / 4 + 131072);
      Cap     : constant Stream_Element_Offset :=
        Stream_Element_Offset (Cap_LL);
      Out_Len : aliased size_t := 0;
      Status  : int;

      procedure Call_FFI (Buf_Addr : System.Address;
                          Buf_Cap  : size_t;
                          OL       : access size_t;
                          St       : out int) is
      begin
         case Width is
            when 128 =>
               St := Itb.Sys.ITB_EncryptStreamAuthenticated128
                       (Noise_Handle              => Noise_H,
                        Data_Handle               => Data_H,
                        Start_Handle              => Start_H,
                        MAC_Handle                => MAC_H,
                        Plaintext                 => In_Addr,
                        Pt_Len                    => Plain'Length,
                        Stream_ID                 => Stream_ID'Address,
                        Cumulative_Pixel_Offset   => Cum_Pixels,
                        Final_Flag                => FF,
                        Out_Buf                   => Buf_Addr,
                        Out_Cap                   => Buf_Cap,
                        Out_Len                   => OL);
            when 256 =>
               St := Itb.Sys.ITB_EncryptStreamAuthenticated256
                       (Noise_Handle              => Noise_H,
                        Data_Handle               => Data_H,
                        Start_Handle              => Start_H,
                        MAC_Handle                => MAC_H,
                        Plaintext                 => In_Addr,
                        Pt_Len                    => Plain'Length,
                        Stream_ID                 => Stream_ID'Address,
                        Cumulative_Pixel_Offset   => Cum_Pixels,
                        Final_Flag                => FF,
                        Out_Buf                   => Buf_Addr,
                        Out_Cap                   => Buf_Cap,
                        Out_Len                   => OL);
            when 512 =>
               St := Itb.Sys.ITB_EncryptStreamAuthenticated512
                       (Noise_Handle              => Noise_H,
                        Data_Handle               => Data_H,
                        Start_Handle              => Start_H,
                        MAC_Handle                => MAC_H,
                        Plaintext                 => In_Addr,
                        Pt_Len                    => Plain'Length,
                        Stream_ID                 => Stream_ID'Address,
                        Cumulative_Pixel_Offset   => Cum_Pixels,
                        Final_Flag                => FF,
                        Out_Buf                   => Buf_Addr,
                        Out_Cap                   => Buf_Cap,
                        Out_Len                   => OL);
            when others =>
               Itb.Errors.Raise_For (Itb.Status.Seed_Width_Mix);
         end case;
      end Call_FFI;
   begin
      Out_Pixels := 0;
      Ensure_Stream_Cache (Cache, Cap);
      Call_FFI (Cache.all'Address, size_t (Cache.all'Length),
                Out_Len'Access, Status);

      if Status = Itb.Status.Buffer_Too_Small then
         Ensure_Stream_Cache (Cache, Stream_Element_Offset (Out_Len));
         Out_Len := 0;
         Call_FFI (Cache.all'Address, size_t (Cache.all'Length),
                   Out_Len'Access, Status);
      end if;

      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      if Stream_Element_Offset (Out_Len) >= Header_Size
        and then Header_Size >= 4
      then
         declare
            First_Idx : constant Stream_Element_Offset := Cache.all'First;
            W : constant Natural := Read_BE16
              (Cache.all, First_Idx + Header_Size - 4);
            H : constant Natural := Read_BE16
              (Cache.all, First_Idx + Header_Size - 2);
         begin
            Out_Pixels := Itb.Sys.U64 (W) * Itb.Sys.U64 (H);
         end;
      end if;
      if Out_Len > 0 then
         Sink.all.Write (Cache (1 .. Stream_Element_Offset (Out_Len)));
      end if;
   end Encrypt_Chunk_Auth_Single_To_Sink;

   --  Per-chunk Triple auth encrypt dispatcher writing directly to
   --  Sink. See Encrypt_Chunk_Auth_Single_To_Sink.
   procedure Encrypt_Chunk_Auth_Triple_To_Sink
     (Width       : Integer;
      Noise_H     : Itb.Sys.Handle;
      Data1_H     : Itb.Sys.Handle;
      Data2_H     : Itb.Sys.Handle;
      Data3_H     : Itb.Sys.Handle;
      Start1_H    : Itb.Sys.Handle;
      Start2_H    : Itb.Sys.Handle;
      Start3_H    : Itb.Sys.Handle;
      MAC_H       : Itb.Sys.Handle;
      Plain       : Byte_Array;
      Stream_ID   : Stream_ID_Bytes;
      Cum_Pixels  : Itb.Sys.U64;
      Final_Flag  : Boolean;
      Header_Size : Stream_Element_Offset;
      Sink        : not null access Root_Stream_Type'Class;
      Cache       : in out Byte_Buffer_Access;
      Out_Pixels  : out Itb.Sys.U64)
   is
      use Interfaces.C;
      In_Addr : constant System.Address :=
        (if Plain'Length > 0 then Plain'Address else System.Null_Address);
      FF      : constant int := (if Final_Flag then 1 else 0);
      --  See Encrypt_Chunk_Auth_Single_To_Sink for the formula+retry-once
      --  rationale.
      Cap_LL  : constant Long_Long_Integer :=
        Long_Long_Integer'Max
          (131072,
           Long_Long_Integer (Plain'Length) * 5 / 4 + 131072);
      Cap     : constant Stream_Element_Offset :=
        Stream_Element_Offset (Cap_LL);
      Out_Len : aliased size_t := 0;
      Status  : int;

      procedure Call_FFI (Buf_Addr : System.Address;
                          Buf_Cap  : size_t;
                          OL       : access size_t;
                          St       : out int) is
      begin
         case Width is
            when 128 =>
               St := Itb.Sys.ITB_EncryptStreamAuthenticated3x128
                       (Noise_Handle              => Noise_H,
                        Data_Handle1              => Data1_H,
                        Data_Handle2              => Data2_H,
                        Data_Handle3              => Data3_H,
                        Start_Handle1             => Start1_H,
                        Start_Handle2             => Start2_H,
                        Start_Handle3             => Start3_H,
                        MAC_Handle                => MAC_H,
                        Plaintext                 => In_Addr,
                        Pt_Len                    => Plain'Length,
                        Stream_ID                 => Stream_ID'Address,
                        Cumulative_Pixel_Offset   => Cum_Pixels,
                        Final_Flag                => FF,
                        Out_Buf                   => Buf_Addr,
                        Out_Cap                   => Buf_Cap,
                        Out_Len                   => OL);
            when 256 =>
               St := Itb.Sys.ITB_EncryptStreamAuthenticated3x256
                       (Noise_Handle              => Noise_H,
                        Data_Handle1              => Data1_H,
                        Data_Handle2              => Data2_H,
                        Data_Handle3              => Data3_H,
                        Start_Handle1             => Start1_H,
                        Start_Handle2             => Start2_H,
                        Start_Handle3             => Start3_H,
                        MAC_Handle                => MAC_H,
                        Plaintext                 => In_Addr,
                        Pt_Len                    => Plain'Length,
                        Stream_ID                 => Stream_ID'Address,
                        Cumulative_Pixel_Offset   => Cum_Pixels,
                        Final_Flag                => FF,
                        Out_Buf                   => Buf_Addr,
                        Out_Cap                   => Buf_Cap,
                        Out_Len                   => OL);
            when 512 =>
               St := Itb.Sys.ITB_EncryptStreamAuthenticated3x512
                       (Noise_Handle              => Noise_H,
                        Data_Handle1              => Data1_H,
                        Data_Handle2              => Data2_H,
                        Data_Handle3              => Data3_H,
                        Start_Handle1             => Start1_H,
                        Start_Handle2             => Start2_H,
                        Start_Handle3             => Start3_H,
                        MAC_Handle                => MAC_H,
                        Plaintext                 => In_Addr,
                        Pt_Len                    => Plain'Length,
                        Stream_ID                 => Stream_ID'Address,
                        Cumulative_Pixel_Offset   => Cum_Pixels,
                        Final_Flag                => FF,
                        Out_Buf                   => Buf_Addr,
                        Out_Cap                   => Buf_Cap,
                        Out_Len                   => OL);
            when others =>
               Itb.Errors.Raise_For (Itb.Status.Seed_Width_Mix);
         end case;
      end Call_FFI;
   begin
      Out_Pixels := 0;
      Ensure_Stream_Cache (Cache, Cap);
      Call_FFI (Cache.all'Address, size_t (Cache.all'Length),
                Out_Len'Access, Status);

      if Status = Itb.Status.Buffer_Too_Small then
         Ensure_Stream_Cache (Cache, Stream_Element_Offset (Out_Len));
         Out_Len := 0;
         Call_FFI (Cache.all'Address, size_t (Cache.all'Length),
                   Out_Len'Access, Status);
      end if;

      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      if Stream_Element_Offset (Out_Len) >= Header_Size
        and then Header_Size >= 4
      then
         declare
            First_Idx : constant Stream_Element_Offset := Cache.all'First;
            W : constant Natural := Read_BE16
              (Cache.all, First_Idx + Header_Size - 4);
            H : constant Natural := Read_BE16
              (Cache.all, First_Idx + Header_Size - 2);
         begin
            Out_Pixels := Itb.Sys.U64 (W) * Itb.Sys.U64 (H);
         end;
      end if;
      if Out_Len > 0 then
         Sink.all.Write (Cache (1 .. Stream_Element_Offset (Out_Len)));
      end if;
   end Encrypt_Chunk_Auth_Triple_To_Sink;

   --  Per-chunk decrypt dispatch (Single + MAC). On success the
   --  recovered plaintext lives in Cache (1 .. PT_Len); the caller is
   --  responsible for consuming the slice and wiping the prefix
   --  (Cache (1 .. PT_Len) := [others => 0]) before the next chunk's
   --  cipher call overwrites those bytes. Wipe-on-grow + wipe-on-
   --  Finalize discipline of the cache is preserved by the
   --  Ensure_Stream_Cache helper and the per-class Finalize.
   procedure Decrypt_Chunk_Auth_Single
     (Width      : Integer;
      Noise_H    : Itb.Sys.Handle;
      Data_H     : Itb.Sys.Handle;
      Start_H    : Itb.Sys.Handle;
      MAC_H      : Itb.Sys.Handle;
      Cipher     : Byte_Array;
      Stream_ID  : Stream_ID_Bytes;
      Cum_Pixels : Itb.Sys.U64;
      Cache      : in out Byte_Buffer_Access;
      PT_Len     : out Stream_Element_Offset;
      Final_Flag : out Boolean)
   is
      use Interfaces.C;
      In_Addr : constant System.Address :=
        (if Cipher'Length > 0 then Cipher'Address else System.Null_Address);
      FF      : aliased int := 0;
      --  See Encrypt_Single_To_Sink for the formula+retry-once
      --  rationale. Decrypt's plaintext is bounded by ciphertext
      --  length minus the constant authentication overhead, so the
      --  same envelope is comfortably sufficient.
      Cap_LL  : constant Long_Long_Integer :=
        Long_Long_Integer'Max
          (131072,
           Long_Long_Integer (Cipher'Length) * 5 / 4 + 131072);
      Cap     : constant Stream_Element_Offset :=
        Stream_Element_Offset (Cap_LL);
      Out_Len : aliased size_t := 0;
      Status  : int;

      procedure Call_FFI (Buf_Addr : System.Address;
                          Buf_Cap  : size_t;
                          OL       : access size_t;
                          St       : out int) is
      begin
         case Width is
            when 128 =>
               St := Itb.Sys.ITB_DecryptStreamAuthenticated128
                       (Noise_Handle              => Noise_H,
                        Data_Handle               => Data_H,
                        Start_Handle              => Start_H,
                        MAC_Handle                => MAC_H,
                        Ciphertext                => In_Addr,
                        Ct_Len                    => Cipher'Length,
                        Stream_ID                 => Stream_ID'Address,
                        Cumulative_Pixel_Offset   => Cum_Pixels,
                        Out_Buf                   => Buf_Addr,
                        Out_Cap                   => Buf_Cap,
                        Out_Len                   => OL,
                        Final_Flag_Out            => FF'Access);
            when 256 =>
               St := Itb.Sys.ITB_DecryptStreamAuthenticated256
                       (Noise_Handle              => Noise_H,
                        Data_Handle               => Data_H,
                        Start_Handle              => Start_H,
                        MAC_Handle                => MAC_H,
                        Ciphertext                => In_Addr,
                        Ct_Len                    => Cipher'Length,
                        Stream_ID                 => Stream_ID'Address,
                        Cumulative_Pixel_Offset   => Cum_Pixels,
                        Out_Buf                   => Buf_Addr,
                        Out_Cap                   => Buf_Cap,
                        Out_Len                   => OL,
                        Final_Flag_Out            => FF'Access);
            when 512 =>
               St := Itb.Sys.ITB_DecryptStreamAuthenticated512
                       (Noise_Handle              => Noise_H,
                        Data_Handle               => Data_H,
                        Start_Handle              => Start_H,
                        MAC_Handle                => MAC_H,
                        Ciphertext                => In_Addr,
                        Ct_Len                    => Cipher'Length,
                        Stream_ID                 => Stream_ID'Address,
                        Cumulative_Pixel_Offset   => Cum_Pixels,
                        Out_Buf                   => Buf_Addr,
                        Out_Cap                   => Buf_Cap,
                        Out_Len                   => OL,
                        Final_Flag_Out            => FF'Access);
            when others =>
               Itb.Errors.Raise_For (Itb.Status.Seed_Width_Mix);
         end case;
      end Call_FFI;
   begin
      Ensure_Stream_Cache (Cache, Cap);
      Call_FFI (Cache.all'Address, size_t (Cache.all'Length),
                Out_Len'Access, Status);

      if Status = Itb.Status.Buffer_Too_Small then
         Ensure_Stream_Cache (Cache, Stream_Element_Offset (Out_Len));
         Out_Len := 0;
         Call_FFI (Cache.all'Address, size_t (Cache.all'Length),
                   Out_Len'Access, Status);
      end if;

      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      PT_Len := Stream_Element_Offset (Out_Len);
      Final_Flag := FF /= 0;
   end Decrypt_Chunk_Auth_Single;

   procedure Decrypt_Chunk_Auth_Triple
     (Width      : Integer;
      Noise_H    : Itb.Sys.Handle;
      Data1_H    : Itb.Sys.Handle;
      Data2_H    : Itb.Sys.Handle;
      Data3_H    : Itb.Sys.Handle;
      Start1_H   : Itb.Sys.Handle;
      Start2_H   : Itb.Sys.Handle;
      Start3_H   : Itb.Sys.Handle;
      MAC_H      : Itb.Sys.Handle;
      Cipher     : Byte_Array;
      Stream_ID  : Stream_ID_Bytes;
      Cum_Pixels : Itb.Sys.U64;
      Cache      : in out Byte_Buffer_Access;
      PT_Len     : out Stream_Element_Offset;
      Final_Flag : out Boolean)
   is
      use Interfaces.C;
      In_Addr : constant System.Address :=
        (if Cipher'Length > 0 then Cipher'Address else System.Null_Address);
      FF      : aliased int := 0;
      --  See Decrypt_Chunk_Auth_Single for the formula+retry-once
      --  rationale.
      Cap_LL  : constant Long_Long_Integer :=
        Long_Long_Integer'Max
          (131072,
           Long_Long_Integer (Cipher'Length) * 5 / 4 + 131072);
      Cap     : constant Stream_Element_Offset :=
        Stream_Element_Offset (Cap_LL);
      Out_Len : aliased size_t := 0;
      Status  : int;

      procedure Call_FFI (Buf_Addr : System.Address;
                          Buf_Cap  : size_t;
                          OL       : access size_t;
                          St       : out int) is
      begin
         case Width is
            when 128 =>
               St := Itb.Sys.ITB_DecryptStreamAuthenticated3x128
                       (Noise_Handle              => Noise_H,
                        Data_Handle1              => Data1_H,
                        Data_Handle2              => Data2_H,
                        Data_Handle3              => Data3_H,
                        Start_Handle1             => Start1_H,
                        Start_Handle2             => Start2_H,
                        Start_Handle3             => Start3_H,
                        MAC_Handle                => MAC_H,
                        Ciphertext                => In_Addr,
                        Ct_Len                    => Cipher'Length,
                        Stream_ID                 => Stream_ID'Address,
                        Cumulative_Pixel_Offset   => Cum_Pixels,
                        Out_Buf                   => Buf_Addr,
                        Out_Cap                   => Buf_Cap,
                        Out_Len                   => OL,
                        Final_Flag_Out            => FF'Access);
            when 256 =>
               St := Itb.Sys.ITB_DecryptStreamAuthenticated3x256
                       (Noise_Handle              => Noise_H,
                        Data_Handle1              => Data1_H,
                        Data_Handle2              => Data2_H,
                        Data_Handle3              => Data3_H,
                        Start_Handle1             => Start1_H,
                        Start_Handle2             => Start2_H,
                        Start_Handle3             => Start3_H,
                        MAC_Handle                => MAC_H,
                        Ciphertext                => In_Addr,
                        Ct_Len                    => Cipher'Length,
                        Stream_ID                 => Stream_ID'Address,
                        Cumulative_Pixel_Offset   => Cum_Pixels,
                        Out_Buf                   => Buf_Addr,
                        Out_Cap                   => Buf_Cap,
                        Out_Len                   => OL,
                        Final_Flag_Out            => FF'Access);
            when 512 =>
               St := Itb.Sys.ITB_DecryptStreamAuthenticated3x512
                       (Noise_Handle              => Noise_H,
                        Data_Handle1              => Data1_H,
                        Data_Handle2              => Data2_H,
                        Data_Handle3              => Data3_H,
                        Start_Handle1             => Start1_H,
                        Start_Handle2             => Start2_H,
                        Start_Handle3             => Start3_H,
                        MAC_Handle                => MAC_H,
                        Ciphertext                => In_Addr,
                        Ct_Len                    => Cipher'Length,
                        Stream_ID                 => Stream_ID'Address,
                        Cumulative_Pixel_Offset   => Cum_Pixels,
                        Out_Buf                   => Buf_Addr,
                        Out_Cap                   => Buf_Cap,
                        Out_Len                   => OL,
                        Final_Flag_Out            => FF'Access);
            when others =>
               Itb.Errors.Raise_For (Itb.Status.Seed_Width_Mix);
         end case;
      end Call_FFI;
   begin
      Ensure_Stream_Cache (Cache, Cap);
      Call_FFI (Cache.all'Address, size_t (Cache.all'Length),
                Out_Len'Access, Status);

      if Status = Itb.Status.Buffer_Too_Small then
         Ensure_Stream_Cache (Cache, Stream_Element_Offset (Out_Len));
         Out_Len := 0;
         Call_FFI (Cache.all'Address, size_t (Cache.all'Length),
                   Out_Len'Access, Status);
      end if;

      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      PT_Len := Stream_Element_Offset (Out_Len);
      Final_Flag := FF /= 0;
   end Decrypt_Chunk_Auth_Triple;

   ---------------------------------------------------------------------
   --  Stream_Encryptor_Auth — Single + MAC.
   ---------------------------------------------------------------------

   function Make_Auth
     (Noise      : Itb.Seed.Seed;
      Data       : Itb.Seed.Seed;
      Start      : Itb.Seed.Seed;
      Mac        : Itb.MAC.MAC;
      Sink       : not null access Root_Stream_Type'Class;
      Chunk_Size : Stream_Element_Offset := Default_Chunk_Size)
      return Stream_Encryptor_Auth is
   begin
      if Chunk_Size <= 0 then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      return E : Stream_Encryptor_Auth do
         E.Noise_H        := Itb.Seed.Raw_Handle (Noise);
         E.Data_H         := Itb.Seed.Raw_Handle (Data);
         E.Start_H        := Itb.Seed.Raw_Handle (Start);
         E.MAC_H          := Itb.MAC.Raw_Handle (Mac);
         E.Width          := Itb.Seed.Width (Noise);
         E.Header_Size    :=
           Stream_Element_Offset (Itb.Header_Size);
         E.Sink           := Sink;
         E.Chunk_Size     := Chunk_Size;
         --  Buffer must accommodate up to Chunk_Size + 1 bytes
         --  during the deferred-final pattern (one byte of
         --  look-ahead before deciding whether the current chunk is
         --  final).
         E.Buf            := Allocate (Chunk_Size + 1);
         E.Buf_Used       := 0;
         E.Cum_Pixels     := 0;
         E.Prefix_Emitted := False;
         E.Closed         := False;
         Generate_Stream_ID (E.Stream_ID);
      end return;
   end Make_Auth;

   procedure Emit_Prefix_Single (Self : in out Stream_Encryptor_Auth) is
   begin
      if not Self.Prefix_Emitted then
         Write_All (Self.Sink, Self.Stream_ID);
         Self.Prefix_Emitted := True;
      end if;
   end Emit_Prefix_Single;

   procedure Emit_One_Single
     (Self            : in out Stream_Encryptor_Auth;
      Plaintext_Bytes : Stream_Element_Offset;
      Final_Flag      : Boolean)
   is
      Pixels : Itb.Sys.U64 := 0;
   begin
      --  Pass the buffer slice directly to the dispatcher so neither
      --  the chunk plaintext copy nor the per-chunk ciphertext (which
      --  is ~1.25x the chunk size, ~20 MiB at 16 MiB chunks) ever
      --  materialises on the Ada stack. The dispatcher routes the FFI
      --  write target through Self.Cache (per-stream cache) instead
      --  of a fresh allocation per chunk.
      Encrypt_Chunk_Auth_Single_To_Sink
        (Self.Width, Self.Noise_H, Self.Data_H, Self.Start_H,
         Self.MAC_H,
         Self.Buf (1 .. Plaintext_Bytes),
         Self.Stream_ID, Self.Cum_Pixels,
         Final_Flag, Self.Header_Size,
         Self.Sink, Self.Cache, Pixels);
      Self.Cum_Pixels := Self.Cum_Pixels + Pixels;
      --  Slide buffer down.
      if Self.Buf_Used > Plaintext_Bytes then
         Self.Buf (1 .. Self.Buf_Used - Plaintext_Bytes) :=
           Self.Buf (Plaintext_Bytes + 1 .. Self.Buf_Used);
      end if;
      Self.Buf_Used := Self.Buf_Used - Plaintext_Bytes;
      --  Zero vacated tail.
      if Self.Buf_Used + 1 <= Self.Buf'Last then
         Self.Buf (Self.Buf_Used + 1 .. Self.Buf'Last) :=
           [others => 0];
      end if;
   end Emit_One_Single;

   procedure Write_Plaintext
     (Self : in out Stream_Encryptor_Auth;
      Data : Byte_Array)
   is
      Cursor : Stream_Element_Offset := Data'First;
   begin
      if Self.Closed then
         Itb.Errors.Raise_For (Itb.Status.Easy_Closed);
      end if;
      Emit_Prefix_Single (Self);
      while Cursor <= Data'Last loop
         declare
            Room      : constant Stream_Element_Offset :=
              Self.Buf'Length - Self.Buf_Used;
            Available : constant Stream_Element_Offset :=
              Data'Last - Cursor + 1;
            Take      : constant Stream_Element_Offset :=
              Stream_Element_Offset'Min (Room, Available);
         begin
            if Take > 0 then
               Self.Buf
                 (Self.Buf_Used + 1 .. Self.Buf_Used + Take) :=
                 Data (Cursor .. Cursor + Take - 1);
               Self.Buf_Used := Self.Buf_Used + Take;
               Cursor        := Cursor + Take;
            end if;
            --  Drain non-terminal chunks: keep at least one chunk
            --  worth buffered until Finish so the deferred-final
            --  pattern can flip final_flag = true on the last chunk.
            while Self.Buf_Used > Self.Chunk_Size loop
               Emit_One_Single (Self, Self.Chunk_Size, False);
            end loop;
         end;
      end loop;
   end Write_Plaintext;

   procedure Finish (Self : in out Stream_Encryptor_Auth) is
   begin
      if Self.Closed then
         return;
      end if;
      Emit_Prefix_Single (Self);
      Emit_One_Single (Self, Self.Buf_Used, True);
      Self.Closed := True;
   end Finish;

   overriding procedure Finalize (Self : in out Stream_Encryptor_Auth) is
   begin
      if not Self.Closed then
         begin
            Finish (Self);
         exception
            when others => null;
         end;
      end if;
      if Self.Buf /= null then
         Self.Buf.all := [others => 0];
         Free_Buffer (Self.Buf);
      end if;
      if Self.Cache /= null then
         Self.Cache.all := [others => 0];
         Free_Buffer (Self.Cache);
      end if;
   end Finalize;

   ---------------------------------------------------------------------
   --  Stream_Decryptor_Auth — Single + MAC.
   ---------------------------------------------------------------------

   procedure Grow_Auth_Buf
     (Self    : in out Stream_Decryptor_Auth;
      Min_Cap : Stream_Element_Offset)
   is
      Old_Buf : Byte_Buffer_Access := Self.Buf;
      New_Cap : Stream_Element_Offset := Self.Buf'Length;
   begin
      while New_Cap < Min_Cap loop
         New_Cap := New_Cap * 2;
      end loop;
      declare
         New_Buf : constant Byte_Buffer_Access := Allocate (New_Cap);
      begin
         if Self.Buf_Used > 0 then
            New_Buf (1 .. Self.Buf_Used) :=
              Old_Buf (1 .. Self.Buf_Used);
         end if;
         Self.Buf := New_Buf;
      end;
      Free_Buffer (Old_Buf);
   end Grow_Auth_Buf;

   function Make_Auth
     (Noise  : Itb.Seed.Seed;
      Data   : Itb.Seed.Seed;
      Start  : Itb.Seed.Seed;
      Mac    : Itb.MAC.MAC;
      Source : not null access Root_Stream_Type'Class)
      return Stream_Decryptor_Auth is
   begin
      return D : Stream_Decryptor_Auth do
         D.Noise_H     := Itb.Seed.Raw_Handle (Noise);
         D.Data_H      := Itb.Seed.Raw_Handle (Data);
         D.Start_H     := Itb.Seed.Raw_Handle (Start);
         D.MAC_H       := Itb.MAC.Raw_Handle (Mac);
         D.Width       := Itb.Seed.Width (Noise);
         D.Header_Size :=
           Stream_Element_Offset (Itb.Header_Size);
         D.Source      := Source;
         D.Buf         := Allocate (Default_CT_Buffer);
         D.Buf_Used    := 0;
         D.Plain       := null;
         D.Plain_Pos   := 0;
         D.Plain_Last  := 0;
         D.Sid_Have    := 0;
         D.Cum_Pixels  := 0;
         D.Seen_Final  := False;
         D.At_EOF      := False;
         D.Closed      := False;
      end return;
   end Make_Auth;

   --  Reads bytes from Self.Source into the tail of Self.Buf. The
   --  first 32 bytes received populate Self.Stream_ID; subsequent
   --  bytes go into the chunk-accumulator. Sets Self.At_EOF on EOF.
   --  Tmp_Buf is heap-allocated (Self.Buf'Length scales with the
   --  user-supplied chunk size; a 16 MiB ciphertext chunk would burst
   --  the default 8 MiB thread stack as a stack-resident array). The
   --  buffer is zeroed and freed unconditionally on every exit path,
   --  including the EOF early-return and the propagated exception
   --  handler below.
   procedure Pull_Source_Auth
     (Self : in out Stream_Decryptor_Auth;
      Read : out Stream_Element_Offset)
   is
      Got     : Stream_Element_Offset;
   begin
      Read := 0;
      declare
         Tmp_Len : constant Stream_Element_Offset :=
           Self.Buf'Length - Self.Buf_Used;
         Tmp_Buf : Byte_Buffer_Access;
      begin
         if Tmp_Len = 0 then
            return;
         end if;
         Tmp_Buf := Allocate (Tmp_Len);
         Got := 0;
         Self.Source.all.Read (Tmp_Buf.all, Got);
         if Got = 0 then
            Self.At_EOF := True;
            Tmp_Buf.all := [others => 0];
            Free_Buffer (Tmp_Buf);
            return;
         end if;
         declare
            Off : Stream_Element_Offset := 1;
         begin
            if Self.Sid_Have < Stream_ID_Length then
               declare
                  Need : constant Stream_Element_Offset :=
                    Stream_ID_Length - Self.Sid_Have;
                  Take : constant Stream_Element_Offset :=
                    Stream_Element_Offset'Min (Need, Got);
               begin
                  Self.Stream_ID
                    (Self.Sid_Have + 1 .. Self.Sid_Have + Take) :=
                    Tmp_Buf (1 .. Take);
                  Self.Sid_Have := Self.Sid_Have + Take;
                  Off := Take + 1;
               end;
            end if;
            if Off <= Got then
               declare
                  Append_N : constant Stream_Element_Offset :=
                    Got - Off + 1;
               begin
                  Self.Buf
                    (Self.Buf_Used + 1 .. Self.Buf_Used + Append_N) :=
                    Tmp_Buf (Off .. Got);
                  Self.Buf_Used := Self.Buf_Used + Append_N;
               end;
            end if;
            Read := Got;
         end;
         Tmp_Buf.all := [others => 0];
         Free_Buffer (Tmp_Buf);
      exception
         when others =>
            if Tmp_Buf /= null then
               Tmp_Buf.all := [others => 0];
               Free_Buffer (Tmp_Buf);
            end if;
            raise;
      end;
   end Pull_Source_Auth;

   --  Tries to decode one full chunk from Self.Buf. Returns True if
   --  a chunk was decoded into Self.Plain and consumed.
   function Try_Decode_Chunk_Auth
     (Self : in out Stream_Decryptor_Auth) return Boolean
   is
      Hdr_Len : constant Stream_Element_Offset := Self.Header_Size;
      Want    : Natural;
      W, H    : Natural;
      Pixels  : Itb.Sys.U64;
   begin
      if Self.Sid_Have < Stream_ID_Length then
         return False;
      end if;
      if Self.Seen_Final then
         if Self.Buf_Used > 0 then
            Itb.Errors.Raise_For (Itb.Status.Stream_After_Final);
         end if;
         return False;
      end if;
      if Self.Buf_Used < Hdr_Len then
         return False;
      end if;
      Want := Itb.Parse_Chunk_Len (Self.Buf (1 .. Hdr_Len));
      if Stream_Element_Offset (Want) > Self.Buf'Length then
         Grow_Auth_Buf (Self, Stream_Element_Offset (Want));
      end if;
      if Self.Buf_Used < Stream_Element_Offset (Want) then
         return False;
      end if;
      W := Read_BE16 (Self.Buf.all, Hdr_Len - 3);
      H := Read_BE16 (Self.Buf.all, Hdr_Len - 1);
      Pixels := Itb.Sys.U64 (W) * Itb.Sys.U64 (H);
      declare
         PT_Len : Stream_Element_Offset := 0;
         FF     : Boolean;
         Tail   : constant Stream_Element_Offset :=
           Self.Buf_Used - Stream_Element_Offset (Want);
      begin
         --  Pass the slice directly so the per-chunk ciphertext does
         --  not materialise as a stack-resident Byte_Array copy. The
         --  recovered plaintext lives in Self.Cache (1 .. PT_Len);
         --  copy it into Self.Plain (which survives across
         --  Read_Plaintext calls until fully drained) then wipe the
         --  cache prefix so the next chunk's Ensure_Stream_Cache
         --  starts clean.
         Decrypt_Chunk_Auth_Single
           (Self.Width, Self.Noise_H, Self.Data_H, Self.Start_H,
            Self.MAC_H,
            Self.Buf (1 .. Stream_Element_Offset (Want)),
            Self.Stream_ID, Self.Cum_Pixels,
            Self.Cache, PT_Len, FF);
         if Tail > 0 then
            Self.Buf (1 .. Tail) :=
              Self.Buf
                (Stream_Element_Offset (Want) + 1 .. Self.Buf_Used);
         end if;
         Self.Buf_Used := Tail;
         if Self.Plain /= null then
            Self.Plain.all := [others => 0];
            Free_Buffer (Self.Plain);
         end if;
         Self.Plain := new Byte_Array (1 .. PT_Len);
         if PT_Len > 0 then
            Self.Plain (1 .. PT_Len) := Self.Cache (1 .. PT_Len);
            Self.Cache (1 .. PT_Len) := [others => 0];
         end if;
         Self.Plain_Pos  := 1;
         Self.Plain_Last := Self.Plain'Last;
         Self.Cum_Pixels := Self.Cum_Pixels + Pixels;
         if FF then
            Self.Seen_Final := True;
         end if;
         return True;
      end;
   end Try_Decode_Chunk_Auth;

   procedure Read_Plaintext
     (Self   : in out Stream_Decryptor_Auth;
      Buffer : out Byte_Array;
      Last   : out Stream_Element_Offset)
   is
      Cursor : Stream_Element_Offset := Buffer'First;
   begin
      Last := Buffer'First - 1;
      if Self.Closed then
         Itb.Errors.Raise_For (Itb.Status.Easy_Closed);
      end if;
      while Cursor <= Buffer'Last loop
         if Self.Plain /= null
           and then Self.Plain_Pos <= Self.Plain_Last
         then
            declare
               Avail : constant Stream_Element_Offset :=
                 Self.Plain_Last - Self.Plain_Pos + 1;
               Room  : constant Stream_Element_Offset :=
                 Buffer'Last - Cursor + 1;
               Take  : constant Stream_Element_Offset :=
                 Stream_Element_Offset'Min (Avail, Room);
            begin
               Buffer (Cursor .. Cursor + Take - 1) :=
                 Self.Plain
                   (Self.Plain_Pos .. Self.Plain_Pos + Take - 1);
               Cursor          := Cursor + Take;
               Self.Plain_Pos  := Self.Plain_Pos + Take;
               Last            := Cursor - 1;
            end;
         else
            if not Try_Decode_Chunk_Auth (Self) then
               if Self.At_EOF then
                  return;
               end if;
               declare
                  Got : Stream_Element_Offset;
               begin
                  if Self.Buf_Used = Self.Buf'Length then
                     Grow_Auth_Buf (Self, Self.Buf'Length * 2);
                  end if;
                  Pull_Source_Auth (Self, Got);
                  if Got = 0 and then Self.At_EOF then
                     return;
                  end if;
               end;
            end if;
         end if;
      end loop;
   end Read_Plaintext;

   procedure Finish (Self : in out Stream_Decryptor_Auth) is
   begin
      if Self.Closed then
         return;
      end if;
      --  Drain any remaining chunks already in Self.Buf.
      while Try_Decode_Chunk_Auth (Self) loop
         null;
      end loop;
      Self.Closed := True;
      if Self.Sid_Have < Stream_ID_Length then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      if not Self.Seen_Final then
         Itb.Errors.Raise_For (Itb.Status.Stream_Truncated);
      end if;
   end Finish;

   overriding procedure Finalize (Self : in out Stream_Decryptor_Auth) is
   begin
      Self.Closed := True;
      if Self.Buf /= null then
         Free_Buffer (Self.Buf);
      end if;
      if Self.Plain /= null then
         Self.Plain.all := [others => 0];
         Free_Buffer (Self.Plain);
      end if;
      if Self.Cache /= null then
         Self.Cache.all := [others => 0];
         Free_Buffer (Self.Cache);
      end if;
   end Finalize;

   ---------------------------------------------------------------------
   --  Stream_Encryptor_Auth_3 — Triple + MAC.
   ---------------------------------------------------------------------

   function Make_Auth_Triple
     (Noise      : Itb.Seed.Seed;
      Data1      : Itb.Seed.Seed;
      Data2      : Itb.Seed.Seed;
      Data3      : Itb.Seed.Seed;
      Start1     : Itb.Seed.Seed;
      Start2     : Itb.Seed.Seed;
      Start3     : Itb.Seed.Seed;
      Mac        : Itb.MAC.MAC;
      Sink       : not null access Root_Stream_Type'Class;
      Chunk_Size : Stream_Element_Offset := Default_Chunk_Size)
      return Stream_Encryptor_Auth_3 is
   begin
      if Chunk_Size <= 0 then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      return E : Stream_Encryptor_Auth_3 do
         E.Noise_H        := Itb.Seed.Raw_Handle (Noise);
         E.Data1_H        := Itb.Seed.Raw_Handle (Data1);
         E.Data2_H        := Itb.Seed.Raw_Handle (Data2);
         E.Data3_H        := Itb.Seed.Raw_Handle (Data3);
         E.Start1_H       := Itb.Seed.Raw_Handle (Start1);
         E.Start2_H       := Itb.Seed.Raw_Handle (Start2);
         E.Start3_H       := Itb.Seed.Raw_Handle (Start3);
         E.MAC_H          := Itb.MAC.Raw_Handle (Mac);
         E.Width          := Itb.Seed.Width (Noise);
         E.Header_Size    :=
           Stream_Element_Offset (Itb.Header_Size);
         E.Sink           := Sink;
         E.Chunk_Size     := Chunk_Size;
         E.Buf            := Allocate (Chunk_Size + 1);
         E.Buf_Used       := 0;
         E.Cum_Pixels     := 0;
         E.Prefix_Emitted := False;
         E.Closed         := False;
         Generate_Stream_ID (E.Stream_ID);
      end return;
   end Make_Auth_Triple;

   procedure Emit_Prefix_Triple (Self : in out Stream_Encryptor_Auth_3) is
   begin
      if not Self.Prefix_Emitted then
         Write_All (Self.Sink, Self.Stream_ID);
         Self.Prefix_Emitted := True;
      end if;
   end Emit_Prefix_Triple;

   procedure Emit_One_Triple
     (Self            : in out Stream_Encryptor_Auth_3;
      Plaintext_Bytes : Stream_Element_Offset;
      Final_Flag      : Boolean)
   is
      Pixels : Itb.Sys.U64 := 0;
   begin
      --  Routes the FFI write target through Self.Cache (per-stream
      --  cache) instead of a fresh allocation per chunk.
      Encrypt_Chunk_Auth_Triple_To_Sink
        (Self.Width, Self.Noise_H,
         Self.Data1_H, Self.Data2_H, Self.Data3_H,
         Self.Start1_H, Self.Start2_H, Self.Start3_H,
         Self.MAC_H,
         Self.Buf (1 .. Plaintext_Bytes),
         Self.Stream_ID, Self.Cum_Pixels,
         Final_Flag, Self.Header_Size,
         Self.Sink, Self.Cache, Pixels);
      Self.Cum_Pixels := Self.Cum_Pixels + Pixels;
      if Self.Buf_Used > Plaintext_Bytes then
         Self.Buf (1 .. Self.Buf_Used - Plaintext_Bytes) :=
           Self.Buf (Plaintext_Bytes + 1 .. Self.Buf_Used);
      end if;
      Self.Buf_Used := Self.Buf_Used - Plaintext_Bytes;
      if Self.Buf_Used + 1 <= Self.Buf'Last then
         Self.Buf (Self.Buf_Used + 1 .. Self.Buf'Last) :=
           [others => 0];
      end if;
   end Emit_One_Triple;

   procedure Write_Plaintext
     (Self : in out Stream_Encryptor_Auth_3;
      Data : Byte_Array)
   is
      Cursor : Stream_Element_Offset := Data'First;
   begin
      if Self.Closed then
         Itb.Errors.Raise_For (Itb.Status.Easy_Closed);
      end if;
      Emit_Prefix_Triple (Self);
      while Cursor <= Data'Last loop
         declare
            Room      : constant Stream_Element_Offset :=
              Self.Buf'Length - Self.Buf_Used;
            Available : constant Stream_Element_Offset :=
              Data'Last - Cursor + 1;
            Take      : constant Stream_Element_Offset :=
              Stream_Element_Offset'Min (Room, Available);
         begin
            if Take > 0 then
               Self.Buf
                 (Self.Buf_Used + 1 .. Self.Buf_Used + Take) :=
                 Data (Cursor .. Cursor + Take - 1);
               Self.Buf_Used := Self.Buf_Used + Take;
               Cursor        := Cursor + Take;
            end if;
            while Self.Buf_Used > Self.Chunk_Size loop
               Emit_One_Triple (Self, Self.Chunk_Size, False);
            end loop;
         end;
      end loop;
   end Write_Plaintext;

   procedure Finish (Self : in out Stream_Encryptor_Auth_3) is
   begin
      if Self.Closed then
         return;
      end if;
      Emit_Prefix_Triple (Self);
      Emit_One_Triple (Self, Self.Buf_Used, True);
      Self.Closed := True;
   end Finish;

   overriding procedure Finalize
     (Self : in out Stream_Encryptor_Auth_3) is
   begin
      if not Self.Closed then
         begin
            Finish (Self);
         exception
            when others => null;
         end;
      end if;
      if Self.Buf /= null then
         Self.Buf.all := [others => 0];
         Free_Buffer (Self.Buf);
      end if;
      if Self.Cache /= null then
         Self.Cache.all := [others => 0];
         Free_Buffer (Self.Cache);
      end if;
   end Finalize;

   ---------------------------------------------------------------------
   --  Stream_Decryptor_Auth_3 — Triple + MAC.
   ---------------------------------------------------------------------

   procedure Grow_Auth_Buf_3
     (Self    : in out Stream_Decryptor_Auth_3;
      Min_Cap : Stream_Element_Offset)
   is
      Old_Buf : Byte_Buffer_Access := Self.Buf;
      New_Cap : Stream_Element_Offset := Self.Buf'Length;
   begin
      while New_Cap < Min_Cap loop
         New_Cap := New_Cap * 2;
      end loop;
      declare
         New_Buf : constant Byte_Buffer_Access := Allocate (New_Cap);
      begin
         if Self.Buf_Used > 0 then
            New_Buf (1 .. Self.Buf_Used) :=
              Old_Buf (1 .. Self.Buf_Used);
         end if;
         Self.Buf := New_Buf;
      end;
      Free_Buffer (Old_Buf);
   end Grow_Auth_Buf_3;

   function Make_Auth_Triple
     (Noise  : Itb.Seed.Seed;
      Data1  : Itb.Seed.Seed;
      Data2  : Itb.Seed.Seed;
      Data3  : Itb.Seed.Seed;
      Start1 : Itb.Seed.Seed;
      Start2 : Itb.Seed.Seed;
      Start3 : Itb.Seed.Seed;
      Mac    : Itb.MAC.MAC;
      Source : not null access Root_Stream_Type'Class)
      return Stream_Decryptor_Auth_3 is
   begin
      return D : Stream_Decryptor_Auth_3 do
         D.Noise_H     := Itb.Seed.Raw_Handle (Noise);
         D.Data1_H     := Itb.Seed.Raw_Handle (Data1);
         D.Data2_H     := Itb.Seed.Raw_Handle (Data2);
         D.Data3_H     := Itb.Seed.Raw_Handle (Data3);
         D.Start1_H    := Itb.Seed.Raw_Handle (Start1);
         D.Start2_H    := Itb.Seed.Raw_Handle (Start2);
         D.Start3_H    := Itb.Seed.Raw_Handle (Start3);
         D.MAC_H       := Itb.MAC.Raw_Handle (Mac);
         D.Width       := Itb.Seed.Width (Noise);
         D.Header_Size :=
           Stream_Element_Offset (Itb.Header_Size);
         D.Source      := Source;
         D.Buf         := Allocate (Default_CT_Buffer);
         D.Buf_Used    := 0;
         D.Plain       := null;
         D.Plain_Pos   := 0;
         D.Plain_Last  := 0;
         D.Sid_Have    := 0;
         D.Cum_Pixels  := 0;
         D.Seen_Final  := False;
         D.At_EOF      := False;
         D.Closed      := False;
      end return;
   end Make_Auth_Triple;

   procedure Pull_Source_Auth_3
     (Self : in out Stream_Decryptor_Auth_3;
      Read : out Stream_Element_Offset)
   is
      Got : Stream_Element_Offset;
   begin
      Read := 0;
      declare
         Tmp_Len : constant Stream_Element_Offset :=
           Self.Buf'Length - Self.Buf_Used;
         Tmp_Buf : Byte_Buffer_Access;
      begin
         if Tmp_Len = 0 then
            return;
         end if;
         Tmp_Buf := Allocate (Tmp_Len);
         Got := 0;
         Self.Source.all.Read (Tmp_Buf.all, Got);
         if Got = 0 then
            Self.At_EOF := True;
            Tmp_Buf.all := [others => 0];
            Free_Buffer (Tmp_Buf);
            return;
         end if;
         declare
            Off : Stream_Element_Offset := 1;
         begin
            if Self.Sid_Have < Stream_ID_Length then
               declare
                  Need : constant Stream_Element_Offset :=
                    Stream_ID_Length - Self.Sid_Have;
                  Take : constant Stream_Element_Offset :=
                    Stream_Element_Offset'Min (Need, Got);
               begin
                  Self.Stream_ID
                    (Self.Sid_Have + 1 .. Self.Sid_Have + Take) :=
                    Tmp_Buf (1 .. Take);
                  Self.Sid_Have := Self.Sid_Have + Take;
                  Off := Take + 1;
               end;
            end if;
            if Off <= Got then
               declare
                  Append_N : constant Stream_Element_Offset :=
                    Got - Off + 1;
               begin
                  Self.Buf
                    (Self.Buf_Used + 1 .. Self.Buf_Used + Append_N) :=
                    Tmp_Buf (Off .. Got);
                  Self.Buf_Used := Self.Buf_Used + Append_N;
               end;
            end if;
            Read := Got;
         end;
         Tmp_Buf.all := [others => 0];
         Free_Buffer (Tmp_Buf);
      exception
         when others =>
            if Tmp_Buf /= null then
               Tmp_Buf.all := [others => 0];
               Free_Buffer (Tmp_Buf);
            end if;
            raise;
      end;
   end Pull_Source_Auth_3;

   function Try_Decode_Chunk_Auth_3
     (Self : in out Stream_Decryptor_Auth_3) return Boolean
   is
      Hdr_Len : constant Stream_Element_Offset := Self.Header_Size;
      Want    : Natural;
      W, H    : Natural;
      Pixels  : Itb.Sys.U64;
   begin
      if Self.Sid_Have < Stream_ID_Length then
         return False;
      end if;
      if Self.Seen_Final then
         if Self.Buf_Used > 0 then
            Itb.Errors.Raise_For (Itb.Status.Stream_After_Final);
         end if;
         return False;
      end if;
      if Self.Buf_Used < Hdr_Len then
         return False;
      end if;
      Want := Itb.Parse_Chunk_Len (Self.Buf (1 .. Hdr_Len));
      if Stream_Element_Offset (Want) > Self.Buf'Length then
         Grow_Auth_Buf_3 (Self, Stream_Element_Offset (Want));
      end if;
      if Self.Buf_Used < Stream_Element_Offset (Want) then
         return False;
      end if;
      W := Read_BE16 (Self.Buf.all, Hdr_Len - 3);
      H := Read_BE16 (Self.Buf.all, Hdr_Len - 1);
      Pixels := Itb.Sys.U64 (W) * Itb.Sys.U64 (H);
      declare
         PT_Len : Stream_Element_Offset := 0;
         FF     : Boolean;
         Tail   : constant Stream_Element_Offset :=
           Self.Buf_Used - Stream_Element_Offset (Want);
      begin
         --  See Try_Decode_Chunk_Auth (Single counterpart) for the
         --  cache-routing rationale: the recovered plaintext lives
         --  in Self.Cache (1 .. PT_Len); copy it into Self.Plain
         --  (which survives across Read_Plaintext calls) and wipe
         --  the cache prefix.
         Decrypt_Chunk_Auth_Triple
           (Self.Width, Self.Noise_H,
            Self.Data1_H, Self.Data2_H, Self.Data3_H,
            Self.Start1_H, Self.Start2_H, Self.Start3_H,
            Self.MAC_H,
            Self.Buf (1 .. Stream_Element_Offset (Want)),
            Self.Stream_ID, Self.Cum_Pixels,
            Self.Cache, PT_Len, FF);
         if Tail > 0 then
            Self.Buf (1 .. Tail) :=
              Self.Buf
                (Stream_Element_Offset (Want) + 1 .. Self.Buf_Used);
         end if;
         Self.Buf_Used := Tail;
         if Self.Plain /= null then
            Self.Plain.all := [others => 0];
            Free_Buffer (Self.Plain);
         end if;
         Self.Plain := new Byte_Array (1 .. PT_Len);
         if PT_Len > 0 then
            Self.Plain (1 .. PT_Len) := Self.Cache (1 .. PT_Len);
            Self.Cache (1 .. PT_Len) := [others => 0];
         end if;
         Self.Plain_Pos  := 1;
         Self.Plain_Last := Self.Plain'Last;
         Self.Cum_Pixels := Self.Cum_Pixels + Pixels;
         if FF then
            Self.Seen_Final := True;
         end if;
         return True;
      end;
   end Try_Decode_Chunk_Auth_3;

   procedure Read_Plaintext
     (Self   : in out Stream_Decryptor_Auth_3;
      Buffer : out Byte_Array;
      Last   : out Stream_Element_Offset)
   is
      Cursor : Stream_Element_Offset := Buffer'First;
   begin
      Last := Buffer'First - 1;
      if Self.Closed then
         Itb.Errors.Raise_For (Itb.Status.Easy_Closed);
      end if;
      while Cursor <= Buffer'Last loop
         if Self.Plain /= null
           and then Self.Plain_Pos <= Self.Plain_Last
         then
            declare
               Avail : constant Stream_Element_Offset :=
                 Self.Plain_Last - Self.Plain_Pos + 1;
               Room  : constant Stream_Element_Offset :=
                 Buffer'Last - Cursor + 1;
               Take  : constant Stream_Element_Offset :=
                 Stream_Element_Offset'Min (Avail, Room);
            begin
               Buffer (Cursor .. Cursor + Take - 1) :=
                 Self.Plain
                   (Self.Plain_Pos .. Self.Plain_Pos + Take - 1);
               Cursor          := Cursor + Take;
               Self.Plain_Pos  := Self.Plain_Pos + Take;
               Last            := Cursor - 1;
            end;
         else
            if not Try_Decode_Chunk_Auth_3 (Self) then
               if Self.At_EOF then
                  return;
               end if;
               declare
                  Got : Stream_Element_Offset;
               begin
                  if Self.Buf_Used = Self.Buf'Length then
                     Grow_Auth_Buf_3 (Self, Self.Buf'Length * 2);
                  end if;
                  Pull_Source_Auth_3 (Self, Got);
                  if Got = 0 and then Self.At_EOF then
                     return;
                  end if;
               end;
            end if;
         end if;
      end loop;
   end Read_Plaintext;

   procedure Finish (Self : in out Stream_Decryptor_Auth_3) is
   begin
      if Self.Closed then
         return;
      end if;
      while Try_Decode_Chunk_Auth_3 (Self) loop
         null;
      end loop;
      Self.Closed := True;
      if Self.Sid_Have < Stream_ID_Length then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      if not Self.Seen_Final then
         Itb.Errors.Raise_For (Itb.Status.Stream_Truncated);
      end if;
   end Finish;

   overriding procedure Finalize
     (Self : in out Stream_Decryptor_Auth_3) is
   begin
      Self.Closed := True;
      if Self.Buf /= null then
         Free_Buffer (Self.Buf);
      end if;
      if Self.Plain /= null then
         Self.Plain.all := [others => 0];
         Free_Buffer (Self.Plain);
      end if;
      if Self.Cache /= null then
         Self.Cache.all := [others => 0];
         Free_Buffer (Self.Cache);
      end if;
   end Finalize;

   ---------------------------------------------------------------------
   --  Free-subprogram convenience drivers (authenticated).
   ---------------------------------------------------------------------

   procedure Encrypt_Stream_Auth
     (Noise      : Itb.Seed.Seed;
      Data       : Itb.Seed.Seed;
      Start      : Itb.Seed.Seed;
      Mac        : Itb.MAC.MAC;
      Source     : not null access Root_Stream_Type'Class;
      Sink       : not null access Root_Stream_Type'Class;
      Chunk_Size : Stream_Element_Offset := Default_Chunk_Size)
   is
      Enc : Stream_Encryptor_Auth :=
        Make_Auth (Noise, Data, Start, Mac, Sink, Chunk_Size);
      Buf : Byte_Buffer_Access := Allocate (Chunk_Size);
      Got : Stream_Element_Offset;
   begin
      loop
         Got := Buf'First - 1;
         Source.all.Read (Buf.all, Got);
         exit when Got < Buf'First;
         Write_Plaintext (Enc, Buf (Buf'First .. Got));
      end loop;
      Finish (Enc);
      Buf.all := [others => 0];
      Free_Buffer (Buf);
   exception
      when others =>
         if Buf /= null then
            Buf.all := [others => 0];
            Free_Buffer (Buf);
         end if;
         raise;
   end Encrypt_Stream_Auth;

   procedure Decrypt_Stream_Auth
     (Noise     : Itb.Seed.Seed;
      Data      : Itb.Seed.Seed;
      Start     : Itb.Seed.Seed;
      Mac       : Itb.MAC.MAC;
      Source    : not null access Root_Stream_Type'Class;
      Sink      : not null access Root_Stream_Type'Class;
      Read_Size : Stream_Element_Offset := Default_Chunk_Size)
   is
   begin
      if Read_Size <= 0 then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      declare
         Dec : Stream_Decryptor_Auth :=
           Make_Auth (Noise, Data, Start, Mac, Source);
         Buf : Byte_Buffer_Access := Allocate (Read_Size);
         Got : Stream_Element_Offset;
      begin
         loop
            Read_Plaintext (Dec, Buf.all, Got);
            exit when Got < Buf'First;
            Write_All (Sink, Buf (Buf'First .. Got));
         end loop;
         Finish (Dec);
         Buf.all := [others => 0];
         Free_Buffer (Buf);
      exception
         when others =>
            if Buf /= null then
               Buf.all := [others => 0];
               Free_Buffer (Buf);
            end if;
            raise;
      end;
   end Decrypt_Stream_Auth;

   procedure Encrypt_Stream_Auth_Triple
     (Noise      : Itb.Seed.Seed;
      Data1      : Itb.Seed.Seed;
      Data2      : Itb.Seed.Seed;
      Data3      : Itb.Seed.Seed;
      Start1     : Itb.Seed.Seed;
      Start2     : Itb.Seed.Seed;
      Start3     : Itb.Seed.Seed;
      Mac        : Itb.MAC.MAC;
      Source     : not null access Root_Stream_Type'Class;
      Sink       : not null access Root_Stream_Type'Class;
      Chunk_Size : Stream_Element_Offset := Default_Chunk_Size)
   is
      Enc : Stream_Encryptor_Auth_3 :=
        Make_Auth_Triple
          (Noise, Data1, Data2, Data3, Start1, Start2, Start3,
           Mac, Sink, Chunk_Size);
      Buf : Byte_Buffer_Access := Allocate (Chunk_Size);
      Got : Stream_Element_Offset;
   begin
      loop
         Got := Buf'First - 1;
         Source.all.Read (Buf.all, Got);
         exit when Got < Buf'First;
         Write_Plaintext (Enc, Buf (Buf'First .. Got));
      end loop;
      Finish (Enc);
      Buf.all := [others => 0];
      Free_Buffer (Buf);
   exception
      when others =>
         if Buf /= null then
            Buf.all := [others => 0];
            Free_Buffer (Buf);
         end if;
         raise;
   end Encrypt_Stream_Auth_Triple;

   procedure Decrypt_Stream_Auth_Triple
     (Noise     : Itb.Seed.Seed;
      Data1     : Itb.Seed.Seed;
      Data2     : Itb.Seed.Seed;
      Data3     : Itb.Seed.Seed;
      Start1    : Itb.Seed.Seed;
      Start2    : Itb.Seed.Seed;
      Start3    : Itb.Seed.Seed;
      Mac       : Itb.MAC.MAC;
      Source    : not null access Root_Stream_Type'Class;
      Sink      : not null access Root_Stream_Type'Class;
      Read_Size : Stream_Element_Offset := Default_Chunk_Size)
   is
   begin
      if Read_Size <= 0 then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      declare
         Dec : Stream_Decryptor_Auth_3 :=
           Make_Auth_Triple
             (Noise, Data1, Data2, Data3, Start1, Start2, Start3,
              Mac, Source);
         Buf : Byte_Buffer_Access := Allocate (Read_Size);
         Got : Stream_Element_Offset;
      begin
         loop
            Read_Plaintext (Dec, Buf.all, Got);
            exit when Got < Buf'First;
            Write_All (Sink, Buf (Buf'First .. Got));
         end loop;
         Finish (Dec);
         Buf.all := [others => 0];
         Free_Buffer (Buf);
      exception
         when others =>
            if Buf /= null then
               Buf.all := [others => 0];
               Free_Buffer (Buf);
            end if;
            raise;
      end;
   end Decrypt_Stream_Auth_Triple;

end Itb.Streams;
