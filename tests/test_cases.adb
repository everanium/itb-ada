--  Test_Cases body. Translated from bindings/rust/tests (smoke.rs,
--  message.rs, stream_pump.rs, stream_incremental.rs,
--  stream_sticky.rs, stream_cancel.rs, rekey.rs, errors.rs, plus the
--  opts.rs unit tests).

with Ada.Streams;

with Interfaces;

with Itb;
with Itb.Error;
with Itb.Opts;
with Itb.Pipeline;
with Itb.Status;
with Itb.Stream;

with Test_Support;

package body Test_Cases is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;
   use type Ada.Streams.Stream_Element_Array;
   use type Itb.Byte_Array_Access;

   subtype Offset is Ada.Streams.Stream_Element_Offset;
   subtype Element is Ada.Streams.Stream_Element;

   use Test_Support;

   --  Growable output accumulator used by the pump / drain loops.
   type Growable is record
      Buf : Itb.Byte_Array_Access := null;
      Len : Offset := 0;
   end record;

   procedure Append (G : in out Growable; Chunk : Itb.Byte_Array) is
   begin
      if G.Buf = null then
         G.Buf := new Itb.Byte_Array (1 .. Offset'Max (65_536, Chunk'Length));
      elsif G.Len + Chunk'Length > G.Buf.all'Length then
         declare
            Bigger : constant Itb.Byte_Array_Access :=
              new Itb.Byte_Array
                (1 .. Offset'Max (G.Buf.all'Length * 2,
                                  G.Len + Chunk'Length));
         begin
            Bigger.all (1 .. G.Len) := G.Buf.all (1 .. G.Len);
            Itb.Free (G.Buf);
            G.Buf := Bigger;
         end;
      end if;
      G.Buf.all (G.Len + 1 .. G.Len + Chunk'Length) := Chunk;
      G.Len := G.Len + Chunk'Length;
   end Append;

   procedure Release (G : in out Growable) is
   begin
      Itb.Free (G.Buf);
      G.Len := 0;
   end Release;

   --  Bounded-memory pump: feed Input in 64 KiB slices, drain
   --  available output after each feed, then Finish + final drain.
   function Pump_Encrypt
     (P : Itb.Pipeline.Pipeline; Input : Itb.Byte_Array)
      return Itb.Byte_Array
   is
      Sess    : Itb.Stream.Encrypt_Stream;
      Scratch : Itb.Byte_Array (1 .. 65_536);
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
         Result : constant Itb.Byte_Array :=
           (if Acc.Buf = null then Input (Input'First .. Input'First - 1)
            else Acc.Buf.all (1 .. Acc.Len));
      begin
         Release (Acc);
         return Result;
      end;
   end Pump_Encrypt;

   function Pump_Decrypt
     (P : Itb.Pipeline.Pipeline; Input : Itb.Byte_Array)
      return Itb.Byte_Array
   is
      Sess    : Itb.Stream.Decrypt_Stream;
      Scratch : Itb.Byte_Array (1 .. 65_536);
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
         Result : constant Itb.Byte_Array :=
           (if Acc.Buf = null then Input (Input'First .. Input'First - 1)
            else Acc.Buf.all (1 .. Acc.Len));
      begin
         Release (Acc);
         return Result;
      end;
   end Pump_Decrypt;

   --  Fills B with (index mod Modulus) — the Rust suite's pattern
   --  payloads.
   procedure Fill_Mod (B : in out Itb.Byte_Array; Modulus : Positive) is
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
      O                : Itb.Opts.Opts;
      Sender, Receiver : Itb.Pipeline.Pipeline;
      Plain            : constant Itb.Byte_Array :=
        Itb.To_Byte_Array ("smoke round-trip payload");
   begin
      Sender.Init ("singlemsg-triple-mac-v1", O);
      Check (Sender.Blob'Length > 0, "blob must be non-empty");
      Receiver.Open ("singlemsg-triple-mac-v1", Sender.Blob, O);
      declare
         Wire : constant Itb.Byte_Array := Sender.Encrypt_Message (Plain);
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
         O                : Itb.Opts.Opts;
         Sender, Receiver : Itb.Pipeline.Pipeline;
         Sizes            : constant array (1 .. 2) of Positive :=
           [4 * 1024, 256 * 1024];
      begin
         Sender.Init (Profile, O);
         Receiver.Open (Profile, Sender.Blob, O);
         for Size of Sizes loop
            declare
               Plain : constant Itb.Byte_Array :=
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
      O                : Itb.Opts.Opts;
      Sender, Receiver : Itb.Pipeline.Pipeline;
      Plain            : Itb.Byte_Array_Access :=
        new Itb.Byte_Array (1 .. 2 ** 20);
   begin
      Sender.Init ("streaming-aead-triple-mac-v1", O);
      Receiver.Open ("streaming-aead-triple-mac-v1", Sender.Blob, O);
      Fill_Mod (Plain.all, 251);
      declare
         Wire : Itb.Byte_Array_Access :=
           new Itb.Byte_Array'(Pump_Encrypt (Sender, Plain.all));
         Back : Itb.Byte_Array_Access :=
           new Itb.Byte_Array'(Pump_Decrypt (Receiver, Wire.all));
      begin
         Check (Wire.all'Length > 0, "pump wire must be non-empty");
         Check_Eq (Back.all, Plain.all, "pump round trip 1 MiB");
         Itb.Free (Wire);
         Itb.Free (Back);
      end;
      Itb.Free (Plain);

      --  One-shot stream output round-trips through the pump and
      --  through the one-shot decrypt.
      declare
         Small : Itb.Byte_Array (1 .. 65_536);
      begin
         Fill_Mod (Small, 199);
         declare
            Wire : constant Itb.Byte_Array :=
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
      O                : Itb.Opts.Opts;
      Sender, Receiver : Itb.Pipeline.Pipeline;
      Plain            : Itb.Byte_Array (1 .. 65_536);
      Wire             : Growable;
      Back             : Growable;
   begin
      --  Small chunk size so the 64 KiB payload spans many chunks.
      O.Set_Chunk_Size (4096);
      Sender.Init ("streaming-aead-triple-mac-v1", O);
      Receiver.Open ("streaming-aead-triple-mac-v1", Sender.Blob, O);
      Fill_Mod (Plain, 241);

      --  Encrypt: 17-byte writes, then Finish + 23-byte drains.
      declare
         Sess    : Itb.Stream.Encrypt_Stream;
         Scratch : Itb.Byte_Array (1 .. 23);
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
         Sess    : Itb.Stream.Decrypt_Stream;
         Scratch : Itb.Byte_Array (1 .. 23);
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
      O                : Itb.Opts.Opts;
      Sender, Receiver : Itb.Pipeline.Pipeline;
      Plain            : Itb.Byte_Array (1 .. 65_536);
      Probes           : constant := 32;
   begin
      Sender.Init ("streaming-aead-triple-mac-v1", O);
      Receiver.Open ("streaming-aead-triple-mac-v1", Sender.Blob, O);
      Fill_Mod (Plain, 227);
      declare
         Base : constant Itb.Byte_Array :=
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
               Wire : Itb.Byte_Array := Base;
               Sess : Itb.Stream.Decrypt_Stream;
               Buf  : Itb.Byte_Array (1 .. 4096);
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
                  when Itb.Error.Itb_Error => null;
               end;
               begin
                  Sess.Finish;
               exception
                  when Itb.Error.Itb_Error => null;
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
                  when E : Itb.Error.Itb_Error =>
                     Got_Err := True;
                     Code := Itb.Error.Status_Code (E);
               end;
               if not Clean then
                  Check (Got_Err, "read loop exited without error");
                  Check (Code = Itb.Status.MAC_Failure,
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
                        when E : Itb.Error.Itb_Error =>
                           Sticky := Itb.Error.Status_Code (E);
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
      O      : Itb.Opts.Opts;
      Sender : Itb.Pipeline.Pipeline;
   begin
      Sender.Init ("streaming-aead-triple-mac-v1", O);
      declare
         Sess : Itb.Stream.Encrypt_Stream;
         Junk : constant Itb.Byte_Array (1 .. 100_000) :=
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
         Receiver : Itb.Pipeline.Pipeline;
         Plain    : constant Itb.Byte_Array :=
           Itb.To_Byte_Array ("after cancel");
      begin
         Receiver.Open ("streaming-aead-triple-mac-v1", Sender.Blob, O);
         Check_Eq
           (Receiver.Decrypt_Message (Sender.Encrypt_Message (Plain)),
            Plain, "round trip after cancelled session");
      end;
   end Stream_Cancel;

   -----------
   -- Rekey --
   -----------

   procedure Rekey is
      O      : Itb.Opts.Opts;
      Sender : Itb.Pipeline.Pipeline;
      Perm   : constant Itb.Byte_Array (1 .. 32) := [others => 16#11#];
      Wrap   : constant Itb.Byte_Array (1 .. 32) := [others => 16#22#];
   begin
      Sender.Init ("singlemsg-triple-mac-v1", O);
      declare
         Blob_Before : constant Itb.Byte_Array := Sender.Blob;
      begin
         Sender.Rekey (Perm, Wrap);
         Check (Sender.Blob /= Blob_Before, "rekey must refresh the blob");
      end;
      declare
         Receiver : Itb.Pipeline.Pipeline;
         Plain    : constant Itb.Byte_Array :=
           Itb.To_Byte_Array ("post-rekey payload");
      begin
         Receiver.Open ("singlemsg-triple-mac-v1", Sender.Blob, O);
         Check_Eq
           (Receiver.Decrypt_Message (Sender.Encrypt_Message (Plain)),
            Plain, "post-rekey round trip");
      end;
   end Rekey;

   ------------
   -- Errors --
   ------------

   procedure Errors is
      O : Itb.Opts.Opts;
   begin
      --  Unknown profile is Bad_Input with a diagnostic.
      declare
         P   : Itb.Pipeline.Pipeline;
         Got : Integer := -1;
      begin
         begin
            P.Init ("no-such-profile", O);
            Check (False, "init of unknown profile must raise");
         exception
            when E : Itb.Error.Itb_Error =>
               Got := Itb.Error.Status_Code (E);
               Check (Itb.Error.Message (E)'Length > 0,
                      "diagnostic must be non-empty");
         end;
         Check (Got = Itb.Status.Bad_Input, "unknown profile status");
      end;

      --  Typoed opts key (lowercase s) — Go rejects unknown keys.
      declare
         Bad : Itb.Opts.Opts;
         P   : Itb.Pipeline.Pipeline;
         Got : Integer := -1;
      begin
         Bad.Set ("chunksize", "4096");
         begin
            P.Init ("singlemsg-triple-mac-v1", Bad);
            Check (False, "init with unknown opts key must raise");
         exception
            when E : Itb.Error.Itb_Error =>
               Got := Itb.Error.Status_Code (E);
         end;
         Check (Got = Itb.Status.Bad_Input, "unknown opts key status");
      end;

      --  Closed Pipeline reports Triple_Closed.
      declare
         P   : Itb.Pipeline.Pipeline;
         Got : Integer := -1;
      begin
         P.Init ("singlemsg-triple-mac-v1", O);
         P.Close;
         P.Close;  --  idempotent
         begin
            declare
               Wire : constant Itb.Byte_Array :=
                 P.Encrypt_Message (Itb.To_Byte_Array ("payload"));
               pragma Unreferenced (Wire);
            begin
               Check (False, "encrypt on closed Pipeline must raise");
            end;
         exception
            when E : Itb.Error.Itb_Error =>
               Got := Itb.Error.Status_Code (E);
         end;
         Check (Got = Itb.Status.Triple_Closed, "closed Pipeline status");
      end;

      --  Register a mixed profile (8-entry width-256 innerHashes
      --  constellation, layers off), round-trip it, then re-register
      --  under the same name — distinct Profile_Exists status.
      declare
         RO               : Itb.Opts.Opts;
         Sender, Receiver : Itb.Pipeline.Pipeline;
         Plain            : constant Itb.Byte_Array :=
           Itb.To_Byte_Array ("custom profile");
      begin
         RO.Set ("mode", "singlemsg-nomac");
         RO.Set ("width", "256");
         RO.Set ("innerHashes",
                 "blake3,blake2s,areion256,blake2b256,chacha20,"
                 & "blake3,blake2s,areion256");
         RO.Set ("keyBits", "1024");
         RO.Set ("parallaxOn", "false");
         RO.Set ("wrapperOn", "false");
         Itb.Pipeline.Register_Profile ("ada-binding-test-mixed", RO);

         Sender.Init ("ada-binding-test-mixed", O);
         Receiver.Open ("ada-binding-test-mixed", Sender.Blob, O);
         Check_Eq
           (Receiver.Decrypt_Message (Sender.Encrypt_Message (Plain)),
            Plain, "registered profile round trip");

         declare
            Got : Integer := -1;
         begin
            begin
               Itb.Pipeline.Register_Profile ("ada-binding-test-mixed", RO);
               Check (False, "duplicate register must raise");
            exception
               when E : Itb.Error.Itb_Error =>
                  Got := Itb.Error.Status_Code (E);
            end;
            Check (Got = Itb.Status.Profile_Exists,
                   "duplicate profile status");
         end;
      end;

      --  An unknown inner-hash name is relayed to Go and rejected
      --  there — the binding performs no name validation of its own.
      declare
         Bad : Itb.Opts.Opts;
         P   : Itb.Pipeline.Pipeline;
         Got : Integer := -1;
      begin
         Bad.Set_Inner_Hash ("no-such-hash");
         begin
            P.Init ("singlemsg-triple-mac-v1", Bad);
            Check (False, "init with unknown hash name must raise");
         exception
            when E : Itb.Error.Itb_Error =>
               Got := Itb.Error.Status_Code (E);
         end;
         Check (Got /= Itb.Status.OK, "opaque name relay status");
      end;
   end Errors;

   -----------------
   -- Opts_Render --
   -----------------

   procedure Opts_Render is
      O  : Itb.Opts.Opts;
      PM : constant Itb.Byte_Array (1 .. 2) := [16#AB#, 16#01#];
      WM : constant Itb.Byte_Array (1 .. 2) := [16#CD#, 16#EF#];
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
      O.Set_Parallax_Palette ("aescmac,chacha20,blake3");
      Check
        (Itb.Opts.Build (O) =
           "pm=ab01&wm=cdef&withParallax=true&withWrapper=false&"
           & "maxWorkers=4&nonceBits=512&barrierFill=4&chunkSize=4096&"
           & "keyBits=1024&parallaxSegmentSize=65536&macName=hmac-blake3&"
           & "innerHash=areion512&outerCipher=chacha20&"
           & "parallaxPalette=aescmac,chacha20,blake3",
         "typed setters render expected keys");

      declare
         R : Itb.Opts.Opts;
      begin
         R.Set ("mode", "a b&c=d%");
         Check (Itb.Opts.Build (R) = "mode=a%20b%26c%3Dd%25",
                "raw escape hatch encoding");
      end;

      declare
         E : Itb.Opts.Opts;
      begin
         Check (Itb.Opts.Build (E) = "", "empty builder renders empty");
      end;

      --  Typed setter for the per-call constellation override
      --  ("innerHashes") renders as the same query-string key that
      --  the raw escape hatch produces.
      declare
         H : Itb.Opts.Opts;
      begin
         H.Set_Inner_Hashes
           ("blake3,blake2s,areion256,blake2b256,chacha20,"
            & "blake3,blake2s,areion256");
         Check
           (Itb.Opts.Build (H) =
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
      Override         : Itb.Opts.Opts;
      Sender, Receiver : Itb.Pipeline.Pipeline;
      Plain            : constant Itb.Byte_Array :=
        Itb.To_Byte_Array ("mixed-hashes typed override round trip");
   begin
      Override.Set_Inner_Hashes
        ("areion512,blake2b512,areion512,blake2b512,"
         & "areion512,blake2b512,areion512,blake2b512");
      Sender.Init (Profile_Name, Override);
      Receiver.Open (Profile_Name, Sender.Blob, Override);
      Check_Eq
        (Receiver.Decrypt_Message (Sender.Encrypt_Message (Plain)),
         Plain, "Set_Inner_Hashes round trip");
   end Opts_Inner_Hashes_Round_Trip;

end Test_Cases;
