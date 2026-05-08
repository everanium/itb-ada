--  Itb.MAC — RAII wrapper over an ITB_NewMAC handle.
--
--  The MAC type is a limited controlled type; its Finalize procedure
--  releases the underlying libitb handle deterministically when the
--  MAC goes out of scope.
--
--  Used in conjunction with Itb.Cipher.Encrypt_Auth and its Triple /
--  Decrypt variants for authenticated cipher mode.
--
--  Construct via Make with a canonical MAC name from Itb.List_MACs:
--  "kmac256", "hmac-sha256", or "hmac-blake3". Key length must meet
--  the primitive's Min_Key_Bytes requirement: 16 for kmac256 /
--  hmac-sha256, 32 for hmac-blake3.

private with Ada.Finalization;
private with Ada.Strings.Unbounded;

with Itb.Sys;

package Itb.MAC is
   pragma Preelaborate;

   type MAC is tagged limited private;

   --  Constructor — wraps ITB_NewMAC. Mac_Name is one of the canonical
   --  names returned by Itb.List_MACs.
   function Make (Mac_Name : String; Key : Byte_Array) return MAC;

   --  Canonical MAC name this handle was constructed with.
   function Name (Self : MAC) return String;

   --  Internal-use accessor over the raw libitb handle. Used by
   --  Itb.Cipher to build its FFI calls. External consumers should
   --  prefer the higher-level Itb.Cipher / Itb.Encryptor surfaces.
   function Raw_Handle (Self : MAC) return Itb.Sys.Handle;

private

   type MAC is new Ada.Finalization.Limited_Controlled with record
      Handle : Itb.Sys.Handle := 0;
      Name   : Ada.Strings.Unbounded.Unbounded_String;
   end record;

   overriding procedure Finalize (Self : in out MAC);

end Itb.MAC;
