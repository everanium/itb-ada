--  Test_Cases — binding test roster mirroring the Rust reference
--  suite (bindings/rust/tests). Each procedure raises
--  Test_Support.Test_Failure (or propagates Itb.Error.Itb_Error) on
--  failure; the driver reports PASS / FAIL per procedure.

package Test_Cases is

   --  Init -> blob -> Open -> Encrypt_Message -> Decrypt_Message
   --  round trip.
   procedure Smoke;

   --  Single Message round trip across every shipped cipher profile
   --  at 4 KiB and 256 KiB payloads.
   procedure Message;

   --  Round trip through chunked feed / drain pump loops on a
   --  Streaming AEAD profile, plus one-shot cross-checks.
   procedure Stream_Pump;

   --  Explicit Write / Finish / Read round trip with pathological
   --  batch sizes (17-byte feed, 23-byte drain) across many chunks.
   procedure Stream_Incremental;

   --  A decrypt session fed a tampered wire fails with a sticky MAC
   --  failure (position-probe pattern — a flip landing in CSPRNG
   --  residue is architecturally inert, so evenly-spaced probes are
   --  used instead of a single bit flip).
   procedure Stream_Sticky;

   --  Finalizing an encrypt session mid-flight cleans up and leaves
   --  the Pipeline usable.
   procedure Stream_Cancel;

   --  Init -> Rekey -> Open receiver with the rotated blob -> round
   --  trip.
   procedure Rekey;

   --  Error-mapping surface: opaque-string relay, closed Pipeline,
   --  duplicate profile registration.
   procedure Errors;

   --  Opts builder rendering (typed setters, raw escape hatch, empty
   --  builder).
   procedure Opts_Render;

   --  Per-call constellation override via the typed
   --  Set_Inner_Hashes helper: register a bare width-512 profile,
   --  Init with an 8-entry constellation, round-trip a Single
   --  Message.
   procedure Opts_Inner_Hashes_Round_Trip;

end Test_Cases;
