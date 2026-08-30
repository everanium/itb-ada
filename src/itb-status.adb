--  Itb.Status body — label table.

package body Itb.Status is

   -----------
   -- Label --
   -----------

   function Label (S : Code) return String is
   begin
      case S is
         when OK                   => return "ok";
         when Bad_Hash             => return "unknown hash name";
         when Bad_Key_Bits         => return "invalid key bits";
         when Bad_Handle           => return "invalid handle";
         when Bad_Input            => return "invalid input";
         when Buffer_Too_Small     => return "output buffer too small";
         when Encrypt_Failed       => return "encrypt failed";
         when Decrypt_Failed       => return "decrypt failed";
         when Seed_Width_Mix       => return "seed width mismatch";
         when Bad_MAC              =>
            return "unknown MAC name or invalid MAC handle";
         when MAC_Failure          => return "MAC verification failed";
         when 11 .. 17             => return "reserved status";
         when Blob_Mode_Mismatch   => return "blob mode mismatch";
         when Blob_Malformed       => return "malformed state blob";
         when Blob_Version_Too_New => return "blob version too new";
         when Blob_Too_Many_Opts   => return "too many blob export opts";
         when Stream_Truncated     =>
            return "stream truncated before terminator";
         when Stream_After_Final   => return "stream chunk after terminator";
         when Triple_Closed        => return "Triple Pipeline is closed";
         when Profile_Exists       => return "profile name already registered";
         when Internal_Error       => return "internal error";
         when others               => return "unknown status";
      end case;
   end Label;

end Itb.Status;
