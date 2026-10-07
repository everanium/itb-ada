--  Translated from bindings/rust/tests (smoke.rs,
--  message.rs, stream_pump.rs, stream_incremental.rs,
--  stream_sticky.rs, stream_cancel.rs, rekey.rs, errors.rs,
--  persist.rs, runtime.rs, plus the opts.rs unit tests).

with Ada.Calendar;
with Ada.Streams;
with Ada.Streams.Stream_IO;
with Ada.Strings;
with Ada.Strings.Fixed;

with Interfaces;

with Itb3;
with Itb3.Error;
with Itb3.Opts;
with Itb3.Pipeline;
with Itb3.Runtime;
with Itb3.Status;
with Itb3.Stream;

with Test_Support;

package body Test_Cases is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;
   use type Ada.Streams.Stream_Element_Array;
   use type Itb3.Byte_Array_Access;

   subtype Offset is Ada.Streams.Stream_Element_Offset;
   subtype Element is Ada.Streams.Stream_Element;

   use Test_Support;

   --  Growable output accumulator used by the pump / drain loops.
   type Growable is record
      Buf : Itb3.Byte_Array_Access := null;
      Len : Offset := 0;
   end record;

   procedure Append (G : in out Growable; Chunk : Itb3.Byte_Array) is
   begin
      if G.Buf = null then
         G.Buf := new Itb3.Byte_Array (1 .. Offset'Max (65_536, Chunk'Length));
      elsif G.Len + Chunk'Length > G.Buf.all'Length then
         declare
            Bigger : constant Itb3.Byte_Array_Access :=
              new Itb3.Byte_Array
                (1 .. Offset'Max (G.Buf.all'Length * 2,
                                  G.Len + Chunk'Length));
         begin
            Bigger.all (1 .. G.Len) := G.Buf.all (1 .. G.Len);
            Itb3.Free (G.Buf);
            G.Buf := Bigger;
         end;
      end if;
      G.Buf.all (G.Len + 1 .. G.Len + Chunk'Length) := Chunk;
      G.Len := G.Len + Chunk'Length;
   end Append;

   procedure Release (G : in out Growable) is
   begin
      Itb3.Free (G.Buf);
      G.Len := 0;
   end Release;

   --  Bounded-memory pump: feed Input in 64 KiB slices, drain
   --  available output after each feed, then Finish + final drain.
   function Pump_Encrypt
     (P : Itb3.Pipeline.Pipeline; Input : Itb3.Byte_Array)
      return Itb3.Byte_Array
   is
      Sess    : Itb3.Stream.Encrypt_Stream;
      Scratch : Itb3.Byte_Array (1 .. 65_536);
      Last    : Offset;
      Fin     : Boolean;
      Pos     : Offset := Input'First;
      Acc     : Growable;
   begin
      Sess.Begin_Encrypt (P);
      while Pos <= Input'Last loop
         declare
            Hi : constant Offset := Offset'Min (Pos + 65_535, Input'Last);
         begin
            Sess.Write (Input (Pos .. Hi));
            Pos := Hi + 1;
         end;
         loop
            Sess.Read (Scratch, Last, Fin);
            exit when Last < Scratch'First;
            Append (Acc, Scratch (Scratch'First .. Last));
         end loop;
      end loop;
      Sess.Finish;
      loop
         Sess.Read (Scratch, Last, Fin);
         if Last >= Scratch'First then
            Append (Acc, Scratch (Scratch'First .. Last));
         end if;
         exit when Fin;
      end loop;
      declare
         Result : constant Itb3.Byte_Array :=
           (if Acc.Buf = null then Input (Input'First .. Input'First - 1)
            else Acc.Buf.all (1 .. Acc.Len));
      begin
         Release (Acc);
         return Result;
      end;
   end Pump_Encrypt;

   function Pump_Decrypt
     (P : Itb3.Pipeline.Pipeline; Input : Itb3.Byte_Array)
      return Itb3.Byte_Array
   is
      Sess    : Itb3.Stream.Decrypt_Stream;
      Scratch : Itb3.Byte_Array (1 .. 65_536);
      Last    : Offset;
      Fin     : Boolean;
      Pos     : Offset := Input'First;
      Acc     : Growable;
   begin
      Sess.Begin_Decrypt (P);
      while Pos <= Input'Last loop
         declare
            Hi : constant Offset := Offset'Min (Pos + 65_535, Input'Last);
         begin
            Sess.Write (Input (Pos .. Hi));
            Pos := Hi + 1;
         end;
         loop
            Sess.Read (Scratch, Last, Fin);
            exit when Last < Scratch'First;
            Append (Acc, Scratch (Scratch'First .. Last));
         end loop;
      end loop;
      Sess.Finish;
      loop
         Sess.Read (Scratch, Last, Fin);
         if Last >= Scratch'First then
            Append (Acc, Scratch (Scratch'First .. Last));
         end if;
         exit when Fin;
      end loop;
      declare
         Result : constant Itb3.Byte_Array :=
           (if Acc.Buf = null then Input (Input'First .. Input'First - 1)
            else Acc.Buf.all (1 .. Acc.Len));
      begin
         Release (Acc);
         return Result;
      end;
   end Pump_Decrypt;

   --  Fills B with (index mod Modulus) — the Rust suite's pattern
   --  payloads.
   procedure Fill_Mod (B : in out Itb3.Byte_Array; Modulus : Positive) is
      I : Natural := 0;
   begin
      for E of B loop
         E := Element (I mod Modulus);
         I := I + 1;
      end loop;
   end Fill_Mod;

   -----------
   -- Smoke --
   -----------

   procedure Smoke is
      O                : Itb3.Opts.Opts;
      Sender, Receiver : Itb3.Pipeline.Pipeline;
      Plain            : constant Itb3.Byte_Array :=
        Itb3.To_Byte_Array ("smoke round-trip payload");
   begin
      Sender.Init ("singlemsg-triple-mac-v1", O);
      Check (Sender.Save'Length > 0, "blob must be non-empty");
      Receiver.Load (Sender.Save);
      declare
         Wire : constant Itb3.Byte_Array := Sender.Encrypt_Message (Plain);
      begin
         Check (Wire /= Plain, "wire must differ from plaintext");
         Check_Eq (Receiver.Decrypt_Message (Wire), Plain,
                   "smoke round trip");
      end;
   end Smoke;

   -------------
   -- Message --
   -------------

   procedure Message is
      procedure One (Profile : String) is
         O                : Itb3.Opts.Opts;
         Sender, Receiver : Itb3.Pipeline.Pipeline;
         Sizes            : constant array (1 .. 2) of Positive :=
           [4 * 1024, 256 * 1024];
      begin
         Sender.Init (Profile, O);
         Receiver.Load (Sender.Save);
         for Size of Sizes loop
            declare
               Plain : constant Itb3.Byte_Array :=
                 Payload (Size, Interfaces.Unsigned_64 (Size));
            begin
               Check_Eq
                 (Receiver.Decrypt_Message (Sender.Encrypt_Message (Plain)),
                  Plain, Profile & " @" & Size'Image);
            end;
         end loop;
      end One;
   begin
      One ("streaming-aead-triple-mac-v1");
      One ("streaming-noaead-triple-v1");
      One ("singlemsg-triple-mac-v1");
      One ("singlemsg-triple-nomac-v1");
      One ("streaming-aead-triple-mac-mixed-v1");
      One ("streaming-noaead-triple-mixed-v1");
      One ("singlemsg-triple-mac-mixed-v1");
      One ("singlemsg-triple-nomac-mixed-v1");
   end Message;

   -----------------
   -- Stream_Pump --
   -----------------

   procedure Stream_Pump is
      O                : Itb3.Opts.Opts;
      Sender, Receiver : Itb3.Pipeline.Pipeline;
      Plain            : Itb3.Byte_Array_Access :=
        new Itb3.Byte_Array (1 .. 2 ** 20);
   begin
      Sender.Init ("streaming-aead-triple-mac-v1", O);
      Receiver.Load (Sender.Save);
      Fill_Mod (Plain.all, 251);
      declare
         Wire : Itb3.Byte_Array_Access :=
           new Itb3.Byte_Array'(Pump_Encrypt (Sender, Plain.all));
         Back : Itb3.Byte_Array_Access :=
           new Itb3.Byte_Array'(Pump_Decrypt (Receiver, Wire.all));
      begin
         Check (Wire.all'Length > 0, "pump wire must be non-empty");
         Check_Eq (Back.all, Plain.all, "pump round trip 1 MiB");
         Itb3.Free (Wire);
         Itb3.Free (Back);
      end;
      Itb3.Free (Plain);

      --  One-shot stream output round-trips through the pump and
      --  through the one-shot decrypt.
      declare
         Small : Itb3.Byte_Array (1 .. 65_536);
      begin
         Fill_Mod (Small, 199);
         declare
            Wire : constant Itb3.Byte_Array :=
              Sender.Encrypt_Stream_One_Shot (Small);
         begin
            Check_Eq (Pump_Decrypt (Receiver, Wire), Small,
                      "pump matches one-shot encrypt");
            Check_Eq (Receiver.Decrypt_Stream_One_Shot (Wire), Small,
                      "one-shot decrypt matches");
         end;
      end;
   end Stream_Pump;

   ------------------------
   -- Stream_Incremental --
   ------------------------

   procedure Stream_Incremental is
      O                : Itb3.Opts.Opts;
      Sender, Receiver : Itb3.Pipeline.Pipeline;
      Plain            : Itb3.Byte_Array (1 .. 65_536);
      Wire             : Growable;
      Back             : Growable;
   begin
      --  Small chunk size so the 64 KiB payload spans many chunks.
      O.Set_Chunk_Size (4096);
      Sender.Init ("streaming-aead-triple-mac-v1", O);
      Receiver.Load (Sender.Save);
      Fill_Mod (Plain, 241);

      --  Encrypt: 17-byte writes, then Finish + 23-byte drains.
      declare
         Sess    : Itb3.Stream.Encrypt_Stream;
         Scratch : Itb3.Byte_Array (1 .. 23);
         Pos     : Offset := Plain'First;
         Last    : Offset;
         Fin     : Boolean;
      begin
         Sess.Begin_Encrypt (Sender);
         while Pos <= Plain'Last loop
            declare
               Hi : constant Offset := Offset'Min (Pos + 16, Plain'Last);
            begin
               Sess.Write (Plain (Pos .. Hi));
               Pos := Hi + 1;
            end;
         end loop;
         Sess.Finish;
         loop
            Sess.Read (Scratch, Last, Fin);
            if Last >= Scratch'First then
               Append (Wire, Scratch (Scratch'First .. Last));
            end if;
            exit when Fin;
         end loop;
      end;
      Check (Wire.Len > 0, "incremental wire must be non-empty");

      --  Decrypt with the same pathological batch sizes.
      declare
         Sess    : Itb3.Stream.Decrypt_Stream;
         Scratch : Itb3.Byte_Array (1 .. 23);
         Pos     : Offset := 1;
         Last    : Offset;
         Fin     : Boolean;
      begin
         Sess.Begin_Decrypt (Receiver);
         while Pos <= Wire.Len loop
            declare
               Hi : constant Offset := Offset'Min (Pos + 16, Wire.Len);
            begin
               Sess.Write (Wire.Buf.all (Pos .. Hi));
               Pos := Hi + 1;
            end;
         end loop;
         Sess.Finish;
         loop
            Sess.Read (Scratch, Last, Fin);
            if Last >= Scratch'First then
               Append (Back, Scratch (Scratch'First .. Last));
            end if;
            exit when Fin;
         end loop;
      end;
      Check (Back.Buf /= null, "incremental output must be non-empty");
      Check_Eq (Back.Buf.all (1 .. Back.Len), Plain,
                "incremental round trip");
      Release (Wire);
      Release (Back);
   end Stream_Incremental;

   -------------------
   -- Stream_Sticky --
   -------------------

   procedure Stream_Sticky is
      O                : Itb3.Opts.Opts;
      Sender, Receiver : Itb3.Pipeline.Pipeline;
      Plain            : Itb3.Byte_Array (1 .. 65_536);
      Probes           : constant := 32;
   begin
      Sender.Init ("streaming-aead-triple-mac-v1", O);
      Receiver.Load (Sender.Save);
      Fill_Mod (Plain, 227);
      declare
         Base : constant Itb3.Byte_Array :=
           Sender.Encrypt_Stream_One_Shot (Plain);
         --  Evenly spread through the wire body; skip the first /
         --  last 16 bytes so a hit against the outer envelope framing
         --  does not muddy the observation.
         Body_First : constant Offset := Base'First + 16;
         Body_Last  : constant Offset := Base'Last - 16;
         Stride     : constant Offset := (Body_Last - Body_First) / Probes;
      begin
         Check (Base'Length > 128, "wire too short for distributed probe");
         for Probe in 0 .. Probes - 1 loop
            declare
               Idx  : constant Offset :=
                 Body_First + Offset (Probe) * Stride;
               Wire : Itb3.Byte_Array := Base;
               Sess : Itb3.Stream.Decrypt_Stream;
               Buf  : Itb3.Byte_Array (1 .. 4096);
               Last : Offset;
               Fin  : Boolean;
               Clean   : Boolean := False;
               Got_Err : Boolean := False;
               Code    : Integer := -1;
            begin
               Wire (Idx) := Wire (Idx) xor 1;
               Sess.Begin_Decrypt (Receiver);
               --  Ignore Write / Finish status — the failure may
               --  surface on either side or only on the drain that
               --  follows.
               begin
                  Sess.Write (Wire);
               exception
                  when Itb3.Error.Itb_Error => null;
               end;
               begin
                  Sess.Finish;
               exception
                  when Itb3.Error.Itb_Error => null;
               end;
               begin
                  loop
                     Sess.Read (Buf, Last, Fin);
                     if Fin then
                        Clean := True;
                        exit;
                     end if;
                  end loop;
               exception
                  when E : Itb3.Error.Itb_Error =>
                     Got_Err := True;
                     Code := Itb3.Error.Status_Code (E);
               end;
               if not Clean then
                  Check (Got_Err, "read loop exited without error");
                  Check (Code = Itb3.Status.MAC_Failure,
                         "expected MAC failure at probe" & Probe'Image
                         & ", got status" & Code'Image);
                  --  Sticky: a subsequent read reports the same
                  --  status.
                  declare
                     Sticky : Integer := -1;
                  begin
                     begin
                        Sess.Read (Buf, Last, Fin);
                     exception
                        when E : Itb3.Error.Itb_Error =>
                           Sticky := Itb3.Error.Status_Code (E);
                     end;
                     Check (Sticky = Code, "failure must be sticky");
                  end;
                  return;
               end if;
               --  Residue hit at this offset — try the next probe.
            end;
         end loop;
         Check (False,
                "no probe surfaced a MAC failure — authentication is "
                & "not covering the wire body it should");
      end;
   end Stream_Sticky;

   -------------------
   -- Stream_Cancel --
   -------------------

   procedure Stream_Cancel is
      O      : Itb3.Opts.Opts;
      Sender : Itb3.Pipeline.Pipeline;
   begin
      Sender.Init ("streaming-aead-triple-mac-v1", O);
      declare
         Sess : Itb3.Stream.Encrypt_Stream;
         Junk : constant Itb3.Byte_Array (1 .. 100_000) :=
           [others => 16#A5#];
      begin
         Sess.Begin_Encrypt (Sender);
         Sess.Write (Junk);
         --  Scope exit without Finish — Finalize cancels and frees
         --  the session; the test passing (process not hanging) is
         --  the assertion.
      end;
      --  The Pipeline stays usable after the cancelled session.
      declare
         Receiver : Itb3.Pipeline.Pipeline;
         Plain    : constant Itb3.Byte_Array :=
           Itb3.To_Byte_Array ("after cancel");
      begin
         Receiver.Load (Sender.Save);
         Check_Eq
           (Receiver.Decrypt_Message (Sender.Encrypt_Message (Plain)),
            Plain, "round trip after cancelled session");
      end;
   end Stream_Cancel;

   -----------
   -- Rekey --
   -----------

   procedure Rekey is
      O      : Itb3.Opts.Opts;
      Sender : Itb3.Pipeline.Pipeline;
      Perm   : constant Itb3.Byte_Array (1 .. 32) := [others => 16#11#];
      Wrap   : constant Itb3.Byte_Array (1 .. 32) := [others => 16#22#];
   begin
      Sender.Init ("singlemsg-triple-mac-v1", O);
      declare
         Blob_Before : constant Itb3.Byte_Array := Sender.Save;
         Rotated     : constant Itb3.Byte_Array := Sender.Rekey (Perm, Wrap);
      begin
         Check (Rotated /= Blob_Before, "rekey must refresh the blob");
         Check (Sender.Save = Rotated, "save must report the rotated blob");
      end;
      declare
         Receiver : Itb3.Pipeline.Pipeline;
         Plain    : constant Itb3.Byte_Array :=
           Itb3.To_Byte_Array ("post-rekey payload");
      begin
         Receiver.Load (Sender.Save);
         Check_Eq
           (Receiver.Decrypt_Message (Sender.Encrypt_Message (Plain)),
            Plain, "post-rekey round trip");
      end;
   end Rekey;

   ------------
   -- Errors --
   ------------

   procedure Errors is
      O : Itb3.Opts.Opts;
   begin
      --  Unknown profile is Unknown_Profile with a diagnostic, on Init
      --  and on Lookup alike.
      declare
         P   : Itb3.Pipeline.Pipeline;
         Got : Integer := -1;
      begin
         begin
            P.Init ("no-such-profile", O);
            Check (False, "init of unknown profile must raise");
         exception
            when E : Itb3.Error.Itb_Error =>
               Got := Itb3.Error.Status_Code (E);
               Check (Itb3.Error.Message (E)'Length > 0,
                      "diagnostic must be non-empty");
         end;
         Check (Got = Itb3.Status.Unknown_Profile, "unknown profile status");
         Got := -1;
         begin
            declare
               J : constant String :=
                 Itb3.Pipeline.Lookup ("no-such-profile");
               pragma Unreferenced (J);
            begin
               Check (False, "lookup of unknown profile must raise");
            end;
         exception
            when E : Itb3.Error.Itb_Error =>
               Got := Itb3.Error.Status_Code (E);
         end;
         Check (Got = Itb3.Status.Unknown_Profile, "lookup unknown status");
      end;

      --  A negative maxWorkers opts value is clamped, not rejected.
      declare
         Neg : Itb3.Opts.Opts;
         P   : Itb3.Pipeline.Pipeline;
      begin
         Neg.Set_Max_Workers (-1);
         P.Init ("singlemsg-triple-mac-v1", Neg);
      end;

      --  Typoed opts key (lowercase s) — Go rejects unknown keys.
      declare
         Bad : Itb3.Opts.Opts;
         P   : Itb3.Pipeline.Pipeline;
         Got : Integer := -1;
      begin
         Bad.Set ("chunksize", "4096");
         begin
            P.Init ("singlemsg-triple-mac-v1", Bad);
            Check (False, "init with unknown opts key must raise");
         exception
            when E : Itb3.Error.Itb_Error =>
               Got := Itb3.Error.Status_Code (E);
         end;
         Check (Got = Itb3.Status.Bad_Input, "unknown opts key status");
      end;

      --  Closed Pipeline reports Triple_Closed.
      declare
         P   : Itb3.Pipeline.Pipeline;
         Got : Integer := -1;
      begin
         P.Init ("singlemsg-triple-mac-v1", O);
         P.Close;
         P.Close;  --  idempotent
         begin
            declare
               Wire : constant Itb3.Byte_Array :=
                 P.Encrypt_Message (Itb3.To_Byte_Array ("payload"));
               pragma Unreferenced (Wire);
            begin
               Check (False, "encrypt on closed Pipeline must raise");
            end;
         exception
            when E : Itb3.Error.Itb_Error =>
               Got := Itb3.Error.Status_Code (E);
         end;
         Check (Got = Itb3.Status.Triple_Closed, "closed Pipeline status");
         Got := -1;
         begin
            declare
               B : constant Itb3.Byte_Array := P.Save;
               pragma Unreferenced (B);
            begin
               Check (False, "save on closed Pipeline must raise");
            end;
         exception
            when E : Itb3.Error.Itb_Error =>
               Got := Itb3.Error.Status_Code (E);
         end;
         Check (Got = Itb3.Status.Triple_Closed, "closed save status");
         Got := -1;
         begin
            P.Max_Workers (2);
            Check (False, "max_workers on closed Pipeline must raise");
         exception
            when E : Itb3.Error.Itb_Error =>
               Got := Itb3.Error.Status_Code (E);
         end;
         Check (Got = Itb3.Status.Triple_Closed, "closed max_workers status");
      end;

      --  Register a mixed profile (8-entry width-256 hashes
      --  constellation, layers off) from a profile JSON record,
      --  round-trip it, read it back, then re-register under the same
      --  name — distinct Profile_Exists status.
      declare
         RO : constant String :=
           "{""mode"":""singlemsg-nomac"",""width"":256,"
           & """hashes"":[""blake3"",""blake2s"",""areion256"","
           & """blake2b256"",""chacha20"",""blake3"",""blake2s"","
           & """areion256""],""keybits"":1024,"
           & """wrapper"":false,""parallax"":false}";
         Sender, Receiver : Itb3.Pipeline.Pipeline;
         Plain            : constant Itb3.Byte_Array :=
           Itb3.To_Byte_Array ("custom profile");
      begin
         Itb3.Pipeline.Register ("ada-binding-test-mixed", RO);

         Sender.Init ("ada-binding-test-mixed", O);
         Receiver.Load (Sender.Save);
         Check_Eq
           (Receiver.Decrypt_Message (Sender.Encrypt_Message (Plain)),
            Plain, "registered profile round trip");

         declare
            Looked : constant String :=
              Itb3.Pipeline.Lookup ("ada-binding-test-mixed");
         begin
            Check (Ada.Strings.Fixed.Index
                     (Looked, """name"":""ada-binding-test-mixed""") > 0,
                   "lookup must carry the name");
            Check (Ada.Strings.Fixed.Index
                     (Looked, """hashes"":[""blake3"",""blake2s""") > 0,
                   "lookup must carry the hashes");
         end;

         declare
            Got : Integer := -1;
         begin
            begin
               Itb3.Pipeline.Register ("ada-binding-test-mixed", RO);
               Check (False, "duplicate register must raise");
            exception
               when E : Itb3.Error.Itb_Error =>
                  Got := Itb3.Error.Status_Code (E);
            end;
            Check (Got = Itb3.Status.Profile_Exists,
                   "duplicate profile status");
         end;

         --  A non-empty name inside the record must equal the argument.
         declare
            Got : Integer := -1;
         begin
            begin
               Itb3.Pipeline.Register
                 ("ada-binding-test-mismatch",
                  "{""name"":""other"",""mode"":""singlemsg-nomac"","
                  & """width"":512,""hash"":""areion512"",""keybits"":1024,"
                  & """wrapper"":false,""parallax"":false}");
               Check (False, "name mismatch register must raise");
            exception
               when E : Itb3.Error.Itb_Error =>
                  Got := Itb3.Error.Status_Code (E);
            end;
            Check (Got = Itb3.Status.Bad_Input, "name mismatch status");
         end;
      end;

      --  An unknown inner-hash name is relayed to Go and rejected
      --  there — the binding performs no name validation of its own.
      declare
         Bad : Itb3.Opts.Opts;
         P   : Itb3.Pipeline.Pipeline;
         Got : Integer := -1;
      begin
         Bad.Set_Inner_Hash ("no-such-hash");
         begin
            P.Init ("singlemsg-triple-mac-v1", Bad);
            Check (False, "init with unknown hash name must raise");
         exception
            when E : Itb3.Error.Itb_Error =>
               Got := Itb3.Error.Status_Code (E);
         end;
         Check (Got /= Itb3.Status.OK, "opaque name relay status");
      end;

      --  An unknown drbg name is relayed to Go and rejected there as
      --  Recipe_Primitive_Unknown, with the token in the diagnostic.
      declare
         Bad   : Itb3.Opts.Opts;
         P     : Itb3.Pipeline.Pipeline;
         Got   : Integer := -1;
         Named : Boolean := False;
      begin
         Bad.Set_DRBG ("nope");
         begin
            P.Init ("singlemsg-triple-mac-v1", Bad);
            Check (False, "init with unknown drbg name must raise");
         exception
            when E : Itb3.Error.Itb_Error =>
               Got := Itb3.Error.Status_Code (E);
               Named := Ada.Strings.Fixed.Index
                          (Itb3.Error.Message (E), "nope") > 0;
         end;
         Check (Got = Itb3.Status.Recipe_Primitive_Unknown,
                "unknown drbg status");
         Check (Named, "unknown drbg diagnostic must name the token");
      end;
   end Errors;

   -----------------
   -- Opts_Render --
   -----------------

   procedure Opts_Render is
      O  : Itb3.Opts.Opts;
      PM : constant Itb3.Byte_Array (1 .. 2) := [16#AB#, 16#01#];
      WM : constant Itb3.Byte_Array (1 .. 2) := [16#CD#, 16#EF#];
   begin
      O.Set_Perm_Master (PM);
      O.Set_Wrap_Master (WM);
      O.Set_With_Parallax (True);
      O.Set_With_Wrapper (False);
      O.Set_Max_Workers (4);
      O.Set_Nonce_Bits (512);
      O.Set_Barrier_Fill (4);
      O.Set_Chunk_Size (4096);
      O.Set_Key_Bits (1024);
      O.Set_Parallax_Segment_Size (65_536);
      O.Set_MAC_Name ("hmac-blake3");
      O.Set_Inner_Hash ("areion512");
      O.Set_Outer_Cipher ("chacha20");
      O.Set_DRBG ("csprng");
      O.Set_Parallax_Palette ("aescmac,chacha20,blake3");
      Check
        (Itb3.Opts.Build (O) =
           "pm=ab01&wm=cdef&withParallax=true&withWrapper=false&"
           & "maxWorkers=4&nonceBits=512&barrierFill=4&chunkSize=4096&"
           & "keyBits=1024&parallaxSegmentSize=65536&macName=hmac-blake3&"
           & "innerHash=areion512&outerCipher=chacha20&drbg=csprng&"
           & "parallaxPalette=aescmac,chacha20,blake3",
         "typed setters render expected keys");

      declare
         R : Itb3.Opts.Opts;
      begin
         R.Set ("mode", "a b&c=d%");
         Check (Itb3.Opts.Build (R) = "mode=a%20b%26c%3Dd%25",
                "raw escape hatch encoding");
      end;

      declare
         E : Itb3.Opts.Opts;
      begin
         Check (Itb3.Opts.Build (E) = "", "empty builder renders empty");
      end;

      --  Typed setter for the per-call constellation override
      --  ("innerHashes") renders as the same query-string key that
      --  the raw escape hatch produces.
      declare
         H : Itb3.Opts.Opts;
      begin
         H.Set_Inner_Hashes
           ("blake3,blake2s,areion256,blake2b256,chacha20,"
            & "blake3,blake2s,areion256");
         Check
           (Itb3.Opts.Build (H) =
              "innerHashes=blake3,blake2s,areion256,blake2b256,chacha20,"
              & "blake3,blake2s,areion256",
            "Set_Inner_Hashes renders innerHashes key");
      end;
   end Opts_Render;

   ---------------------------------
   -- Opts_Inner_Hashes_Round_Trip --
   ---------------------------------

   procedure Opts_Inner_Hashes_Round_Trip is
      --  Base profile is a shipped single-primitive width-512
      --  Single Message profile; the per-call Set_Inner_Hashes
      --  override rebinds all 8 slots to an alternate width-512
      --  constellation for one Pipeline pair without touching the
      --  shipped registry.
      Profile_Name     : constant String := "singlemsg-triple-mac-v1";
      Override         : Itb3.Opts.Opts;
      Sender, Receiver : Itb3.Pipeline.Pipeline;
      Plain            : constant Itb3.Byte_Array :=
        Itb3.To_Byte_Array ("mixed-hashes typed override round trip");
   begin
      Override.Set_Inner_Hashes
        ("areion512,blake2b512,areion512,blake2b512,"
         & "areion512,blake2b512,areion512,blake2b512");
      Sender.Init (Profile_Name, Override);
      Receiver.Load (Sender.Save);
      Check_Eq
        (Receiver.Decrypt_Message (Sender.Encrypt_Message (Plain)),
         Plain, "Set_Inner_Hashes round trip");
   end Opts_Inner_Hashes_Round_Trip;

   -------------
   -- Persist --
   -------------

   procedure Persist is
      O      : Itb3.Opts.Opts;
      Sender : Itb3.Pipeline.Pipeline;
      Plain  : constant Itb3.Byte_Array :=
        Itb3.To_Byte_Array ("persist payload");
      Perm   : constant Itb3.Byte_Array (1 .. 32) := [others => 16#31#];
      Wrap   : constant Itb3.Byte_Array (1 .. 32) := [others => 16#32#];
      Path   : constant String :=
        "/tmp/itb-ada-persist-"
        & Ada.Strings.Fixed.Trim
            (Integer'Image
               (Integer (Ada.Calendar.Seconds (Ada.Calendar.Clock))),
             Ada.Strings.Left)
        & ".blob";
      type Name_Access is access constant String;
      Csprng_Name    : aliased constant String := "csprng";
      Aesitb128_Name : aliased constant String := "aesitb128";
      Drbg_Names     : constant array (1 .. 2) of Name_Access :=
        [Csprng_Name'Access, Aesitb128_Name'Access];
   begin
      Sender.Init ("singlemsg-triple-mac-v1", O);

      --  Save -> Load; Save is stable; Load retains the bytes.
      declare
         Blob     : constant Itb3.Byte_Array := Sender.Save;
         Receiver : Itb3.Pipeline.Pipeline;
      begin
         Check (Sender.Save = Blob, "save must be stable");
         Receiver.Load (Blob);
         Check_Eq
           (Receiver.Decrypt_Message (Sender.Encrypt_Message (Plain)),
            Plain, "in-memory round trip");
         Check (Receiver.Save = Blob, "load must retain the blob bytes");

         --  Load with master overrides equals a sender Rekey.
         declare
            Rotated : Itb3.Pipeline.Pipeline;
         begin
            Rotated.Load (Blob, Perm, Wrap);
            Check (Rotated.Save /= Blob,
                   "master overrides must rotate the blob");
            Sender.Rekey (Perm, Wrap);
            Check_Eq
              (Rotated.Decrypt_Message (Sender.Encrypt_Message (Plain)),
               Plain, "override round trip");
         end;

         --  Inspect carries the registry recipe plus the blob-only
         --  nonce_bits / barrier_fill inspection fields; Lookup
         --  returns just the recipe.
         declare
            Inspected : constant String := Itb3.Pipeline.Inspect (Blob);
            Looked    : constant String :=
              Itb3.Pipeline.Lookup ("singlemsg-triple-mac-v1");
         begin
            Check (Ada.Strings.Fixed.Index
                     (Inspected, """name"":""singlemsg-triple-mac-v1""") > 0,
                   "inspect must carry the name");
            Check (Ada.Strings.Fixed.Index
                     (Inspected, """mode"":""singlemsg-mac""") > 0,
                   "inspect must carry the mode");
            Check (Ada.Strings.Fixed.Index (Inspected, """nonce_bits"":") > 0,
                   "inspect must carry the inspection-only nonce_bits");
            Check (Ada.Strings.Fixed.Index (Inspected, """barrier_fill"":") > 0,
                   "inspect must carry the inspection-only barrier_fill");
            Check (Ada.Strings.Fixed.Index
                     (Looked, """name"":""singlemsg-triple-mac-v1""") > 0,
                   "lookup must carry the name");
            Check (Ada.Strings.Fixed.Index (Looked, """nonce_bits"":") = 0,
                   "lookup must omit the inspection-only nonce_bits");
            Check (Ada.Strings.Fixed.Index (Looked, """barrier_fill"":") = 0,
                   "lookup must omit the inspection-only barrier_fill");
         end;
      end;

      --  Inspect of garbage is Bad_Input.
      declare
         Got : Integer := -1;
      begin
         begin
            declare
               J : constant String :=
                 Itb3.Pipeline.Inspect (Itb3.To_Byte_Array ("not a blob"));
               pragma Unreferenced (J);
            begin
               Check (False, "inspect of garbage must raise");
            end;
         exception
            when E : Itb3.Error.Itb_Error =>
               Got := Itb3.Error.Status_Code (E);
         end;
         Check (Got = Itb3.Status.Bad_Input, "inspect garbage status");
      end;

      --  Profiles lists the shipped catalogue as a JSON array.
      declare
         Names : constant String := Itb3.Pipeline.Profiles;
      begin
         Check (Names'Length > 0 and then Names (Names'First) = '[',
                "profiles must be a JSON array");
         Check (Ada.Strings.Fixed.Index
                  (Names, """singlemsg-triple-mac-v1""") > 0,
                "profiles must list the shipped profile");
      end;

      --  Save_F -> Load_F on a temp file; a missing file is Bad_Input.
      declare
         Receiver : Itb3.Pipeline.Pipeline;
         F        : Ada.Streams.Stream_IO.File_Type;
      begin
         Sender.Save_F (Path);
         Receiver.Load_F (Path);
         Check_Eq
           (Receiver.Decrypt_Message (Sender.Encrypt_Message (Plain)),
            Plain, "on-disk round trip");
         Ada.Streams.Stream_IO.Open
           (F, Ada.Streams.Stream_IO.In_File, Path);
         Ada.Streams.Stream_IO.Delete (F);
      end;
      declare
         Receiver : Itb3.Pipeline.Pipeline;
         Got      : Integer := -1;
      begin
         begin
            Receiver.Load_F (Path);
            Check (False, "load_f of a missing file must raise");
         exception
            when E : Itb3.Error.Itb_Error =>
               Got := Itb3.Error.Status_Code (E);
         end;
         Check (Got = Itb3.Status.Bad_Input, "load_f missing status");
      end;

      --  Max_Workers clamps and round-trips.
      Sender.Max_Workers (2);
      Sender.Max_Workers (-1);
      Sender.Max_Workers (100_000);
      declare
         Receiver : Itb3.Pipeline.Pipeline;
      begin
         Receiver.Load (Sender.Save);
         Receiver.Max_Workers (1);
         Check_Eq
           (Receiver.Decrypt_Message (Sender.Encrypt_Message (Plain)),
            Plain, "workers round trip");
      end;

      --  The drbg recipe key: an Init under each named fill primitive
      --  round-trips through a loaded blob and is reported by
      --  Inspect; an inspected record re-registers under a new name
      --  and keeps the key. The register payload drops the name and
      --  the inspection-only nonce_bits / barrier_fill /
      --  container_mode keys, which sit contiguously between keybits
      --  and drbg.
      for Name of Drbg_Names loop
         declare
            D_Opts   : Itb3.Opts.Opts;
            D_Sender : Itb3.Pipeline.Pipeline;
            D_Recv   : Itb3.Pipeline.Pipeline;
            Tag      : constant String := Name.all;
         begin
            D_Opts.Set_DRBG (Tag);
            D_Sender.Init ("singlemsg-triple-mac-v1", D_Opts);
            declare
               Blob : constant Itb3.Byte_Array := D_Sender.Save;
               Want : constant String := """drbg"":""" & Tag & """";
            begin
               D_Recv.Load (Blob);
               Check_Eq
                 (D_Recv.Decrypt_Message (D_Sender.Encrypt_Message (Plain)),
                  Plain, "drbg round trip");
               Check_Eq
                 (D_Sender.Decrypt_Message (D_Recv.Encrypt_Message (Plain)),
                  Plain, "drbg reverse round trip");
               declare
                  Inspected : constant String :=
                    Itb3.Pipeline.Inspect (Blob);
                  P_Mode    : constant Natural :=
                    Ada.Strings.Fixed.Index (Inspected, """mode""");
                  P_Cut     : constant Natural :=
                    Ada.Strings.Fixed.Index (Inspected, """nonce_bits""");
                  P_Drbg    : constant Natural :=
                    Ada.Strings.Fixed.Index (Inspected, """drbg""");
               begin
                  Check (Ada.Strings.Fixed.Index (Inspected, Want) > 0,
                         "inspect must carry the drbg key");
                  if Tag = "csprng" then
                     Check (P_Mode > 0 and then P_Cut > P_Mode
                              and then P_Drbg > P_Cut,
                            "inspect key order for the register payload");
                     Itb3.Pipeline.Register
                       ("ada-binding-test-drbg-copy",
                        "{" & Inspected (P_Mode .. P_Cut - 1)
                        & Inspected (P_Drbg .. Inspected'Last));
                     Check (Ada.Strings.Fixed.Index
                              (Itb3.Pipeline.Lookup
                                 ("ada-binding-test-drbg-copy"),
                               Want) > 0,
                            "lookup must keep the drbg key");
                  end if;
               end;
            end;
         end;
      end loop;

      --  Default: no drbg key in Inspect, nor in a shipped Lookup.
      declare
         Plain_Opts : Itb3.Opts.Opts;
         D_Sender   : Itb3.Pipeline.Pipeline;
      begin
         D_Sender.Init ("singlemsg-triple-mac-v1", Plain_Opts);
         Check (Ada.Strings.Fixed.Index
                  (Itb3.Pipeline.Inspect (D_Sender.Save), """drbg""") = 0,
                "default inspect must omit drbg");
         Check (Ada.Strings.Fixed.Index
                  (Itb3.Pipeline.Lookup ("singlemsg-triple-mac-v1"),
                   """drbg""") = 0,
                "shipped lookup must omit drbg");
      end;
   end Persist;

   ---------------------
   -- Runtime_Surface --
   ---------------------

   procedure Runtime_Surface is
      use type Interfaces.Integer_64;

      use type Ada.Streams.Stream_IO.Count;

      Previous : Integer;
      Slots    : Natural;
      Written  : Natural;
      Tiers    : Natural;
      Path     : constant String := "itb_ada_heap.prof";
   begin
      --  GOMAXPROCS: the query form reads back what the setter
      --  installed, and the setter reports nothing of its own.
      Previous := Itb3.Runtime.GOMAXPROCS;
      Check (Previous > 0, "gomaxprocs query is positive");
      Itb3.Runtime.Set_GOMAXPROCS (2);
      Check (Itb3.Runtime.GOMAXPROCS = 2, "gomaxprocs reads back 2");
      Itb3.Runtime.Set_GOMAXPROCS (Previous);
      Check (Itb3.Runtime.GOMAXPROCS = Previous, "gomaxprocs restored");

      Check (Itb3.Runtime.Memory_Limit /= 0, "memory limit query non-zero");

      --  Pool counters: the length query sizes the destination, the
      --  first slot carries the tier count, and the whole vector is
      --  1 + 5*T + 8 slots long.
      Slots := Itb3.Runtime.Pool_Stats_Len;
      Check (Slots > 0, "pool stats length positive");
      declare
         Snapshot : Itb3.Runtime.Pool_Counters (1 .. Slots);
         Later    : Itb3.Runtime.Pool_Counters (1 .. Slots);
      begin
         Itb3.Runtime.Pool_Stats (Snapshot, Written);
         Check (Written = Slots, "pool stats fills every slot");
         Check (Snapshot (1) > 0, "slot 1 carries a tier count");
         Tiers := Natural (Snapshot (1));
         Check (1 + 5 * Tiers + 8 = Slots, "length is 1 + 5*T + 8");

         --  A destination shorter than the reported length is refused
         --  with Buffer_Too_Small.
         declare
            Narrow : Itb3.Runtime.Pool_Counters (1 .. 1);
            Got    : Integer := -1;
         begin
            begin
               Itb3.Runtime.Pool_Stats (Narrow, Written);
               Check (False, "a short pool buffer must raise");
            exception
               when E : Itb3.Error.Itb_Error =>
                  Got := Itb3.Error.Status_Code (E);
            end;
            Check (Got = Itb3.Status.Buffer_Too_Small,
                   "short pool buffer status");
            Check (Written = Slots, "short pool buffer reports the need");
         end;

         --  The counters are monotonic totals since library load, so
         --  a second snapshot after a round trip never goes
         --  backwards.
         declare
            Options : Itb3.Opts.Opts;
            Pipe    : Itb3.Pipeline.Pipeline;
            Plain   : constant Itb3.Byte_Array :=
              Test_Support.Payload (4096, 24);
         begin
            Pipe.Init ("singlemsg-triple-nomac-v1", Options);
            Check_Eq (Pipe.Decrypt_Message (Pipe.Encrypt_Message (Plain)),
                      Plain, "pool traffic round trip");
         end;
         Itb3.Runtime.Pool_Stats (Later, Written);
         for I in 1 .. Slots loop
            Check (Later (I) >= Snapshot (I), "pool counters never decrease");
         end loop;
         Check (Later (3) > Snapshot (3), "tier 0 checkouts advanced");
      end;

      --  Heap profile: the file lands on disk and carries bytes.
      Itb3.Runtime.Write_Heap_Profile (Path);
      declare
         F : Ada.Streams.Stream_IO.File_Type;
      begin
         Ada.Streams.Stream_IO.Open
           (F, Ada.Streams.Stream_IO.In_File, Path);
         Check (Ada.Streams.Stream_IO.Size (F) > 0,
                "heap profile is non-empty");
         Ada.Streams.Stream_IO.Delete (F);
      end;

      --  The hash registry is the authority the "innerHash" opts key
      --  is validated against.
      declare
         JSON : constant String := Itb3.Pipeline.Hash_Names;
      begin
         Check (JSON'Length > 2, "hash registry is non-empty");
         Check (JSON (JSON'First) = '[', "hash registry is a JSON array");
         Check (Ada.Strings.Fixed.Index (JSON, """areion512""") > 0,
                "registry lists areion512");
         Check (Ada.Strings.Fixed.Index (JSON, """aesitb128""") > 0,
                "registry lists aesitb128");
         Check (Ada.Strings.Fixed.Index (JSON, """nope""") = 0,
                "registry omits a made-up name");
      end;

      --  Auto DRBG tier: one of the two fill ciphers, resolved per
      --  host.
      declare
         Tier : constant String := Itb3.Runtime.DRBG_Auto_Tier;
      begin
         Check (Tier = "aes-256-ctr" or else Tier = "chacha20",
                "drbg auto tier: " & Tier);
      end;
   end Runtime_Surface;

end Test_Cases;
