--  Itb.Status — numeric status codes mirrored from the libitb C ABI
--  (cmd/cshared/internal/capi/errors.go). Numeric values are stable
--  across releases. The reserved block 11..17 (retired facade
--  sentinels) is intentionally unnamed here — Label reports it
--  generically.

package Itb.Status is

   subtype Code is Integer;

   OK                   : constant Code := 0;
   Bad_Hash             : constant Code := 1;
   Bad_Key_Bits         : constant Code := 2;
   Bad_Handle           : constant Code := 3;
   Bad_Input            : constant Code := 4;
   Buffer_Too_Small     : constant Code := 5;
   Encrypt_Failed       : constant Code := 6;
   Decrypt_Failed       : constant Code := 7;
   Seed_Width_Mix       : constant Code := 8;
   Bad_MAC              : constant Code := 9;
   MAC_Failure          : constant Code := 10;
   Blob_Mode_Mismatch   : constant Code := 19;
   Blob_Malformed       : constant Code := 20;
   Blob_Version_Too_New : constant Code := 21;
   Blob_Too_Many_Opts   : constant Code := 22;
   Stream_Truncated     : constant Code := 23;
   Stream_After_Final   : constant Code := 24;
   Triple_Closed        : constant Code := 25;
   Profile_Exists       : constant Code := 26;
   Internal_Error       : constant Code := 99;

   --  Short human-readable label for a status code.
   function Label (S : Code) return String;

end Itb.Status;
