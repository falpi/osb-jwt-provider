package org.falpi.utils;

import java.util.List;
import java.util.Iterator;
import java.util.ArrayList;

public class StringUtils {
   
   public static String join(String[] ArrStrings, String StrSeparator) {            
      String StrOutput = "";
      for (int IntIndex=0;IntIndex<ArrStrings.length;IntIndex++){            
         StrOutput+= ((IntIndex>0)?(StrSeparator):(""))+ArrStrings[IntIndex].trim();   
      }       
      return StrOutput;
   }
   
   public static String repeat(int IntLength, String StrFiller) {
      return new String(new char[IntLength]).replace("\0", StrFiller);
   }

   public static String padRight(String StrTarget, int IntLength, String StrFiller) {
      if (IntLength > StrTarget.length()) {
         StrTarget = StrTarget + repeat(IntLength-StrTarget.length(), StrFiller);
      }
      return StrTarget;
   }

   public static String padLeft(String StrTarget, int IntLength, String StrFiller) {
      if (IntLength > StrTarget.length()) {
         StrTarget = repeat(IntLength-StrTarget.length(), StrFiller) + StrTarget;
      }
      return StrTarget;
   }
 
   public static int getMaxLength(Iterator<String> ObjIterator) {
      return getMaxLength(ObjIterator, new ArrayList());
   }

   public static int getMaxLength(Iterator<String> ObjIterator, List ArrExclusion) {
      int IntMaxLength = 0;
      while (ObjIterator.hasNext()) {
         String StrElement = ObjIterator.next();
         if (!ArrExclusion.contains(StrElement)) {
            IntMaxLength = Math.max(IntMaxLength, StrElement.length());
         }
      }
      return IntMaxLength;
   }
   
   public static String bytesToHex(byte[] ArrBytes) {
      StringBuilder ObjResult = new StringBuilder();
      for (byte ObjByte : ArrBytes) ObjResult.append(String.format("%02X", ObjByte));
      return ObjResult.toString();
   } 
}
