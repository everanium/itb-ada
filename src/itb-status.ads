--  Itb.Status — named numeric constants for every libitb status code.
--
--  Source-of-truth for the codes is cmd/cshared/internal/capi/errors.go;
--  the constants here mirror it bit-identically so tests / callers can
--  match against named values rather than magic numbers.
--
--  Codes 0..10 cover the low-level Seed / Encrypt / Decrypt / MAC
--  surface. Codes 11..18 are reserved for the Easy Mode encryptor
--  (Itb.Encryptor). Codes 19..22 are reserved for the native Blob
--  surface (Itb.Blob). Code 99 is a generic "internal" sentinel for
--  paths the caller cannot recover from at the binding layer.

package Itb.Status is
   pragma Preelaborate;
   pragma SPARK_Mode (Off);

   OK                          : constant := 0;
   Bad_Hash                    : constant := 1;
   Bad_Key_Bits                : constant := 2;
   Bad_Handle                  : constant := 3;
   Bad_Input                   : constant := 4;
   Buffer_Too_Small            : constant := 5;
   Encrypt_Failed              : constant := 6;
   Decrypt_Failed              : constant := 7;
   Seed_Width_Mix              : constant := 8;
   Bad_MAC                     : constant := 9;
   MAC_Failure                 : constant := 10;

   Easy_Closed                 : constant := 11;
   Easy_Malformed              : constant := 12;
   Easy_Version_Too_New        : constant := 13;
   Easy_Unknown_Primitive      : constant := 14;
   Easy_Unknown_MAC            : constant := 15;
   Easy_Bad_Key_Bits           : constant := 16;
   Easy_Mismatch               : constant := 17;
   Easy_LockSeed_After_Encrypt : constant := 18;

   Blob_Mode_Mismatch          : constant := 19;
   Blob_Malformed              : constant := 20;
   Blob_Version_Too_New        : constant := 21;
   Blob_Too_Many_Opts          : constant := 22;

   --  Streaming AEAD: input exhausted without observing a chunk
   --  whose recovered final_flag is set. Surfaced by the auth-stream
   --  decrypt loop on truncate-tail.
   Stream_Truncated            : constant := 23;

   --  Streaming AEAD: extra chunk bytes followed the terminating
   --  chunk. Surfaced by the auth-stream decrypt loop when a
   --  transcript carries data past final_flag = 1.
   Stream_After_Final          : constant := 24;

   Internal                    : constant := 99;

end Itb.Status;
