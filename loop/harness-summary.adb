--  The procfs read behind the resident-set figures, the pool-counter
--  snapshot layout and its differencing, and the rendering of the
--  final summary.

with Interfaces;
with Interfaces.C;
with System;

with Itb3.Error;
with Itb3.Runtime;

with Harness.Payload;
with Harness.Sizes;
with Harness.Worker;

package body Harness.Summary is

   use Harness.Sizes;
   use type Interfaces.Integer_64;

   --  Ceiling on the hash-array pool tiers a snapshot is differenced
   --  over; the live count comes from the first slot of the snapshot
   --  itself.
   Max_Tiers : constant := 64;

   type Tier_Vector is array (0 .. Max_Tiers - 1) of Count;

   --  The differenced pool figures of one run.
   type Pool_Delta is record
      Tiers              : Natural := 0;
      Starter            : Tier_Vector := [others => 0];
      Get                : Tier_Vector := [others => 0];
      Fresh              : Tier_Vector := [others => 0];
      Regrow             : Tier_Vector := [others => 0];
      New_Bytes          : Tier_Vector := [others => 0];
      Buf_Get            : Count := 0;
      Buf_New            : Count := 0;
      Buf_Regrow         : Count := 0;
      Buf_Regrow_Bytes   : Count := 0;
      Chunk_Get          : Count := 0;
      Chunk_New          : Count := 0;
      Chunk_Regrow       : Count := 0;
      Chunk_Regrow_Bytes : Count := 0;
   end record;

   --------------
   -- Read_RSS --
   --------------

   function Status_KB (Line : String) return Count is
      Colon : Natural := 0;
      First : Natural;
      Last  : Natural;
   begin
      for I in Line'Range loop
         if Line (I) = ':' then
            Colon := I;
            exit;
         end if;
      end loop;
      if Colon = 0 then
         return 0;
      end if;
      --  The separator in /proc/self/status is a tab followed by
      --  padding spaces, so both are skipped.
      First := Colon + 1;
      while First <= Line'Last
        and then (Line (First) = ' ' or else Line (First) = ASCII.HT)
      loop
         First := First + 1;
      end loop;
      Last := First;
      while Last <= Line'Last and then Line (Last) in '0' .. '9' loop
         Last := Last + 1;
      end loop;
      if Last = First then
         return 0;
      end if;
      return Count'Value (Line (First .. Last - 1)) * 1024;
   end Status_KB;

   --  Ada-specific. The procfs file reports a zero length, which the
   --  Text_IO end-of-file test takes at face value, so the bytes are
   --  pulled through the raw descriptor the same way the utility's
   --  own output goes out.
   function C_Open
     (Path : System.Address; Flags : Interfaces.C.int) return Interfaces.C.int
   with Import => True, Convention => C, External_Name => "open";

   function C_Read
     (Fd : Interfaces.C.int; Buf : System.Address; N : Interfaces.C.size_t)
      return Interfaces.C.long
   with Import => True, Convention => C, External_Name => "read";

   function C_Close (Fd : Interfaces.C.int) return Interfaces.C.int
   with Import => True, Convention => C, External_Name => "close";

   procedure Read_RSS (Current : out Count; Peak : out Count) is
      use type Interfaces.C.int;
      use type Interfaces.C.long;

      Path    : aliased constant Interfaces.C.char_array :=
        Interfaces.C.To_C ("/proc/self/status");
      Buffer  : String (1 .. 8192);
      Fd      : Interfaces.C.int;
      Got     : Interfaces.C.long;
      Filled  : Natural := 0;
      Line_At : Natural;
      Ignored : Interfaces.C.int;
      pragma Warnings (Off, Ignored);
   begin
      Current := 0;
      Peak := 0;
      Fd := C_Open (Path'Address, 0);
      if Fd < 0 then
         return;
      end if;
      loop
         Got := C_Read (Fd, Buffer (Filled + 1)'Address,
                        Interfaces.C.size_t (Buffer'Last - Filled));
         exit when Got <= 0;
         Filled := Filled + Natural (Got);
         exit when Filled >= Buffer'Last;
      end loop;
      --  A close failure cannot lose a read that already landed, so
      --  the status is discarded rather than reported.
      Ignored := C_Close (Fd);
      pragma Unreferenced (Ignored);
      Line_At := 1;
      for I in 1 .. Filled loop
         if Buffer (I) = ASCII.LF then
            if I - Line_At >= 6 then
               if Buffer (Line_At .. Line_At + 5) = "VmRSS:" then
                  Current := Status_KB (Buffer (Line_At .. I - 1));
               elsif Buffer (Line_At .. Line_At + 5) = "VmHWM:" then
                  Peak := Status_KB (Buffer (Line_At .. I - 1));
               end if;
            end if;
            Line_At := I + 1;
         end if;
      end loop;
   end Read_RSS;

   -------------------
   -- Pool counters --
   -------------------

   --  Pool counters. The shared library keeps process-wide monotonic
   --  totals at every pool checkout of its cipher core: per
   --  hash-array tier the starter width, checkouts, constructor
   --  misses, regrow replacements and bytes allocated; for the
   --  scratch byte pool and the parallax chunk pool the checkouts,
   --  constructor misses, regrows and regrow bytes. Two snapshots
   --  bracketing the main loop are differenced into per-run hit /
   --  miss figures that tell whether a pool keeps its items warm
   --  between calls or evicts them across GC cycles. The slot layout
   --  is read from the library: the first slot carries the tier count
   --  T, tier i occupies the five slots at 1 + 5*i from there, and
   --  the two byte pools occupy the eight slots at 1 + 5*T; the
   --  buffer is sized from the binding's length query, never from a
   --  constant.
   function Snapshot_Alloc (Into : out Pool_Snapshot) return Boolean is
      Slots : constant Natural := Itb3.Runtime.Pool_Stats_Len;
   begin
      Into := null;
      if Slots = 0 then
         return False;
      end if;
      Into := new Itb3.Runtime.Pool_Counters (1 .. Slots);
      Into.all := [others => 0];
      return True;
   end Snapshot_Alloc;

   procedure Snapshot_Take (Into : Pool_Snapshot) is
      Written : Natural;
   begin
      Itb3.Runtime.Pool_Stats (Into.all, Written);
   exception
      when Itb3.Error.Itb_Error =>
         Into.all := [others => 0];
   end Snapshot_Take;

   procedure Diff (D : out Pool_Delta) is
      Tiers : Natural;
      Base  : Natural;
      Tail  : Natural;
   begin
      D := (others => <>);
      if Pool_Warmup = null or else Pool_Steady = null then
         return;
      end if;
      if Pool_Steady.all'Length < 9 then
         return;
      end if;
      if Pool_Steady.all (1) < 0
        or else Pool_Steady.all (1) > Count (Max_Tiers)
      then
         return;
      end if;
      Tiers := Natural (Pool_Steady.all (1));
      if 1 + 5 * Tiers + 8 > Pool_Steady.all'Length then
         return;
      end if;
      D.Tiers := Tiers;
      for I in 0 .. Tiers - 1 loop
         Base := 2 + 5 * I;
         D.Starter (I) := Pool_Steady.all (Base);
         D.Get (I) := Pool_Steady.all (Base + 1) - Pool_Warmup.all (Base + 1);
         D.Fresh (I) := Pool_Steady.all (Base + 2) - Pool_Warmup.all (Base + 2);
         D.Regrow (I) :=
           Pool_Steady.all (Base + 3) - Pool_Warmup.all (Base + 3);
         D.New_Bytes (I) :=
           Pool_Steady.all (Base + 4) - Pool_Warmup.all (Base + 4);
      end loop;
      Tail := 2 + 5 * Tiers;
      D.Buf_Get := Pool_Steady.all (Tail) - Pool_Warmup.all (Tail);
      D.Buf_New := Pool_Steady.all (Tail + 1) - Pool_Warmup.all (Tail + 1);
      D.Buf_Regrow := Pool_Steady.all (Tail + 2) - Pool_Warmup.all (Tail + 2);
      D.Buf_Regrow_Bytes :=
        Pool_Steady.all (Tail + 3) - Pool_Warmup.all (Tail + 3);
      D.Chunk_Get := Pool_Steady.all (Tail + 4) - Pool_Warmup.all (Tail + 4);
      D.Chunk_New := Pool_Steady.all (Tail + 5) - Pool_Warmup.all (Tail + 5);
      D.Chunk_Regrow :=
        Pool_Steady.all (Tail + 6) - Pool_Warmup.all (Tail + 6);
      D.Chunk_Regrow_Bytes :=
        Pool_Steady.all (Tail + 7) - Pool_Warmup.all (Tail + 7);
   end Diff;

   --  Misses over checkouts as a percentage; zero when nothing was
   --  checked out.
   function Miss_Percent (Miss : Count; Get : Count) return Long_Float is
   begin
      if Get <= 0 then
         return 0.0;
      end if;
      return 100.0 * Long_Float (Miss) / Long_Float (Get);
   end Miss_Percent;

   --  Renders S as a JSON string literal with the escapes JSON
   --  requires.
   function JSON_String (S : String) return String is
      Nibbles : constant String := "0123456789abcdef";
      Result  : SU.Unbounded_String := SU.To_Unbounded_String ("""");
      Code    : Natural;
   begin
      for I in S'Range loop
         Code := Character'Pos (S (I));
         if S (I) = '"' then
            SU.Append (Result, "\""");
         elsif S (I) = '\' then
            SU.Append (Result, "\\");
         elsif Code = 10 then
            SU.Append (Result, "\n");
         elsif Code = 13 then
            SU.Append (Result, "\r");
         elsif Code = 9 then
            SU.Append (Result, "\t");
         elsif Code < 32 then
            SU.Append (Result, "\u00");
            SU.Append (Result, Nibbles (Code / 16 + 1));
            SU.Append (Result, Nibbles (Code mod 16 + 1));
         else
            SU.Append (Result, S (I));
         end if;
      end loop;
      SU.Append (Result, """");
      return SU.To_String (Result);
   end JSON_String;

   --  The effective GC percentage as the runtime reports it: the
   --  query form of the setter (a set-and-restore round trip inside
   --  the library) so the field is the same whether the value came
   --  from the flag, the environment, or the runtime default.
   function Effective_GoGC return Integer is
   begin
      if Cfg.GoGC > 0 then
         return Cfg.GoGC;
      end if;
      return Itb3.Runtime.GC_Percent;
   end Effective_GoGC;

   -------------------
   -- Final_Summary --
   -------------------

   function Final_Summary (Elapsed_NS : Count) return Integer is
      Total_Iters : Count := 0;
      Total_Enc   : Count := 0;
      Total_Dec   : Count := 0;
      Nanos_Enc   : Count := 0;
      Nanos_Dec   : Count := 0;
      Avg_Enc     : Count := 0;
      Avg_Dec     : Count := 0;
      Errors      : Natural := 0;
      Emitted     : Natural := 0;
      Pass        : Boolean;
      RSS_Delta   : Count;
      RSS_Growth  : Long_Float := 0.0;
      D           : Pool_Delta;
      Text        : SU.Unbounded_String;
      Parts       : SU.Unbounded_String;
      SP          : SU.Unbounded_String;
      MP          : SU.Unbounded_String;
   begin
      for I in 0 .. Cfg.Workers - 1 loop
         Total_Iters := Total_Iters + Workers (I).Iters;
         Total_Enc := Total_Enc + Workers (I).Bytes_Enc;
         Total_Dec := Total_Dec + Workers (I).Bytes_Dec;
         Nanos_Enc := Nanos_Enc + Workers (I).Nanos_Enc;
         Nanos_Dec := Nanos_Dec + Workers (I).Nanos_Dec;
         if Workers (I).Failed then
            Errors := Errors + 1;
         end if;
      end loop;

      --  Throughput. Per-direction throughput divides the sum of
      --  every worker's wall time in that direction by the worker
      --  count -- the equivalent single-stream wall time under N-way
      --  concurrency -- so each direction reports the aggregate rate
      --  it sustained rather than collapsing to combined/2 (every
      --  iteration moves equal encrypt and decrypt bytes, so a
      --  total-elapsed denominator would give both directions the
      --  same figure). The combined rate keeps total elapsed as the
      --  one-glance overall figure.
      if Nanos_Enc > 0 then
         Avg_Enc := Nanos_Enc / Count (Cfg.Workers);
      end if;
      if Nanos_Dec > 0 then
         Avg_Dec := Nanos_Dec / Count (Cfg.Workers);
      end if;

      RSS_Delta := RSS_Final - RSS_Warmup;
      if RSS_Warmup > 0 then
         RSS_Growth := 100.0 * Long_Float (RSS_Delta) / Long_Float (RSS_Warmup);
      end if;

      Diff (D);
      Pass := Errors = 0;
      if Stream_Pipe /= null then
         SP := Stream_Profile;
      end if;
      if Msg_Pipe /= null then
         MP := Msg_Profile;
      end if;

      if Cfg.JSON_Output then
         SU.Append (Text, "{""duration_seconds"":"
                    & Fixed (Long_Float (Elapsed_NS) / 1.0E9, 3));
         SU.Append (Text, ",""iterations"":" & Img (Total_Iters));
         SU.Append (Text, ",""per_worker_iterations"":[");
         for I in 0 .. Cfg.Workers - 1 loop
            if I > 0 then
               SU.Append (Text, ",");
            end if;
            SU.Append (Text, Img (Workers (I).Iters));
         end loop;
         SU.Append (Text, "]");
         SU.Append (Text, ",""bytes_encrypted"":" & Img (Total_Enc));
         SU.Append (Text, ",""bytes_decrypted"":" & Img (Total_Dec));
         SU.Append (Text, ",""encrypt_mb_per_sec"":"
                    & Fixed (MB_Per_Sec (Total_Enc, Avg_Enc), 1));
         SU.Append (Text, ",""decrypt_mb_per_sec"":"
                    & Fixed (MB_Per_Sec (Total_Dec, Avg_Dec), 1));
         SU.Append (Text, ",""combined_mb_per_sec"":"
                    & Fixed (MB_Per_Sec (Total_Enc + Total_Dec, Elapsed_NS), 1));
         SU.Append (Text, ",""rekeys"":" & Img (Rekeys));
         SU.Append (Text, ",""blob_cycles"":" & Img (Blob_Cycles));
         SU.Append (Text, ",""worker_errors"":[");
         for I in 0 .. Cfg.Workers - 1 loop
            if Workers (I).Failed then
               if Emitted > 0 then
                  SU.Append (Text, ",");
               end if;
               Emitted := Emitted + 1;
               SU.Append (Text, JSON_String (SU.To_String (Workers (I).Error)));
            end if;
         end loop;
         SU.Append (Text, "]");
         SU.Append (Text, ",""verdict"":"
                    & (if Pass then """PASS""" else """FAIL"""));
         SU.Append (Text, ",""shape"":""" & Harness.Worker.Shape_Name (Cfg.Shape)
                    & """");
         SU.Append (Text, ",""stream_profile"":"
                    & JSON_String (SU.To_String (SP)));
         SU.Append (Text, ",""message_profile"":"
                    & JSON_String (SU.To_String (MP)));
         SU.Append (Text, ",""hash"":" & JSON_String (SU.To_String (Cfg.Hash)));
         SU.Append (Text, ",""mac"":" & JSON_String (SU.To_String (Cfg.MAC)));
         SU.Append (Text, ",""payload_bytes"":" & Img (Cfg.Payload));
         SU.Append (Text, ",""payload_mode"":"""
                    & Harness.Payload.Payload_Mode_Name (Cfg.Payload_Mode)
                    & """");
         SU.Append (Text, ",""seed"":" & Img (Cfg.Seed));
         SU.Append (Text, ",""key_bits"":" & Img (Cfg.Key_Bits));
         SU.Append (Text, ",""nonce_bits"":" & Img (Cfg.Nonce_Bits));
         SU.Append (Text, ",""blob_mode"":" & Img (Cfg.Blob_Mode));
         SU.Append (Text, ",""drbg"":" & JSON_String (SU.To_String (Cfg.DRBG)));
         SU.Append (Text, ",""drbg_auto_tier"":"
                    & JSON_String (Itb3.Runtime.DRBG_Auto_Tier));
         SU.Append (Text, ",""chunk_size_bytes"":" & Img (Cfg.Chunk_Size));
         SU.Append (Text, ",""barrier_fill"":" & Img (Cfg.Barrier_Fill));
         SU.Append (Text, ",""parallax"":""" & On_Off (Cfg.Parallax) & """");
         SU.Append (Text, ",""wrapper"":""" & On_Off (Cfg.Wrapper) & """");
         SU.Append (Text, ",""goroutines_requested"":"
                    & Img (Cfg.Workers_Asked));
         SU.Append (Text, ",""goroutines"":" & Img (Cfg.Workers));
         SU.Append (Text, ",""concurrency"":""" & Concurrency & """");
         SU.Append (Text, ",""gogc"":""" & Img (Effective_GoGC) & """");
         SU.Append (Text, ",""memlimit_bytes"":" & Img (Cfg.Memlimit));
         SU.Append (Text, ",""gomaxprocs"":" & Img (Itb3.Runtime.GOMAXPROCS));
         SU.Append (Text, ",""microbatch_tiers"":"
                    & JSON_String (Policy_Label ("ITB_MICROBATCH_TIERS")));
         SU.Append (Text, ",""hashpool_starters"":"
                    & JSON_String (Policy_Label ("ITB_HASHPOOL_STARTERS")));
         SU.Append (Text, ",""rss_warmup_bytes"":" & Img (RSS_Warmup));
         SU.Append (Text, ",""rss_peak_bytes"":" & Img (RSS_Peak));
         SU.Append (Text, ",""rss_final_bytes"":" & Img (RSS_Final));
         SU.Append (Text, ",""rss_growth_percent"":" & Fixed (RSS_Growth, 2));
         SU.Append (Text, ",""hash_pool_tiers"":[");
         Emitted := 0;
         for I in 0 .. D.Tiers - 1 loop
            if D.Starter (I) /= 0 then
               if Emitted > 0 then
                  SU.Append (Text, ",");
               end if;
               Emitted := Emitted + 1;
               SU.Append (Text, "{""tier"":" & Img (I)
                          & ",""starter"":" & Img (D.Starter (I))
                          & ",""get"":" & Img (D.Get (I))
                          & ",""new"":" & Img (D.Fresh (I))
                          & ",""regrow"":" & Img (D.Regrow (I))
                          & ",""new_bytes"":" & Img (D.New_Bytes (I))
                          & ",""miss_percent"":"
                          & Fixed (Miss_Percent (D.Fresh (I) + D.Regrow (I),
                                                 D.Get (I)), 2)
                          & "}");
            end if;
         end loop;
         SU.Append (Text, "]");
         SU.Append (Text, ",""buf_pool"":{""get"":" & Img (D.Buf_Get)
                    & ",""new"":" & Img (D.Buf_New)
                    & ",""regrow"":" & Img (D.Buf_Regrow)
                    & ",""regrow_bytes"":" & Img (D.Buf_Regrow_Bytes)
                    & ",""miss_percent"":"
                    & Fixed (Miss_Percent (D.Buf_Regrow, D.Buf_Get), 2)
                    & "}");
         SU.Append (Text, ",""parallax_chunk_pool"":{""get"":"
                    & Img (D.Chunk_Get)
                    & ",""new"":" & Img (D.Chunk_New)
                    & ",""regrow"":" & Img (D.Chunk_Regrow)
                    & ",""regrow_bytes"":" & Img (D.Chunk_Regrow_Bytes)
                    & ",""miss_percent"":"
                    & Fixed (Miss_Percent (D.Chunk_Regrow, D.Chunk_Get), 2)
                    & "}");
         SU.Append (Text, "}");
         Emit (1, SU.To_String (Text));
         return (if Pass then 0 else 1);
      end if;

      Log_Line ("=== FINAL ===");
      Log_Line ("  duration: "
                & Human_Duration ((Elapsed_NS + 500_000) / 1_000_000
                                  * 1_000_000));
      for I in 0 .. Cfg.Workers - 1 loop
         if I > 0 then
            SU.Append (Parts, " + ");
         end if;
         SU.Append (Parts, Img (Workers (I).Iters));
      end loop;
      Log_Line ("  iterations: " & SU.To_String (Parts) & " = "
                & Img (Total_Iters) & " total");
      Log_Line ("  throughput: encrypt " & Human_Rate (Total_Enc, Avg_Enc)
                & ", decrypt " & Human_Rate (Total_Dec, Avg_Dec)
                & ", combined "
                & Human_Rate (Total_Enc + Total_Dec, Elapsed_NS));
      Log_Line ("  bytes: " & Human_Bytes (Total_Enc) & " encrypted, "
                & Human_Bytes (Total_Dec) & " decrypted");
      Log_Line ("  data integrity: " & Img (Total_Iters) & "/"
                & Img (Total_Iters) & " PASS");
      Log_Line ("  concurrency: " & Concurrency & ", workers "
                & Img (Cfg.Workers) & " (requested "
                & Img (Cfg.Workers_Asked) & ")");
      Log_Line ("  rss: warmup " & Human_Bytes (RSS_Warmup) & ", peak "
                & Human_Bytes (RSS_Peak) & ", final "
                & Human_Bytes (RSS_Final) & " (delta "
                & Human_Bytes_Signed (RSS_Delta) & ", "
                & Fixed (RSS_Growth, 1) & "% growth)");
      for I in 0 .. D.Tiers - 1 loop
         if D.Starter (I) /= 0 then
            Log_Line ("  hash pool tier " & Img (I) & " (starter "
                      & Img (D.Starter (I)) & "): get " & Img (D.Get (I))
                      & ", miss " & Img (D.Fresh (I) + D.Regrow (I))
                      & " (new " & Img (D.Fresh (I)) & " + regrow "
                      & Img (D.Regrow (I)) & "), miss "
                      & Fixed (Miss_Percent (D.Fresh (I) + D.Regrow (I),
                                             D.Get (I)), 2)
                      & "%, " & Human_Bytes (D.New_Bytes (I)) & " allocated");
         end if;
      end loop;
      Log_Line ("  buf pool: get " & Img (D.Buf_Get) & ", regrow "
                & Img (D.Buf_Regrow) & " (of which fresh "
                & Img (D.Buf_New) & "), miss "
                & Fixed (Miss_Percent (D.Buf_Regrow, D.Buf_Get), 2) & "%, "
                & Human_Bytes (D.Buf_Regrow_Bytes) & " regrown");
      Log_Line ("  parallax chunk pool: get " & Img (D.Chunk_Get)
                & ", regrow " & Img (D.Chunk_Regrow) & " (of which fresh "
                & Img (D.Chunk_New) & "), miss "
                & Fixed (Miss_Percent (D.Chunk_Regrow, D.Chunk_Get), 2)
                & "%, " & Human_Bytes (D.Chunk_Regrow_Bytes) & " regrown");
      if Rekeys > 0 then
         Log_Line ("  rekeys: " & Img (Rekeys));
      end if;
      if Blob_Cycles > 0 then
         Log_Line ("  blob cycles: " & Img (Blob_Cycles));
      end if;
      for I in 0 .. Cfg.Workers - 1 loop
         if Workers (I).Failed then
            Log_Line ("  ERROR: " & SU.To_String (Workers (I).Error));
         end if;
      end loop;
      if Pass then
         Log_Line ("  verdict: PASS");
         return 0;
      end if;
      Log_Line ("  verdict: FAIL (errors=" & Img (Errors) & ")");
      return 1;
   end Final_Summary;

end Harness.Summary;
