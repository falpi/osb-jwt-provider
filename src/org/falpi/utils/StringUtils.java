package org.falpi.utils;

import java.io.BufferedReader;

import java.io.IOException;

import java.util.List;
import java.util.Iterator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Properties;

import org.apache.commons.io.IOUtils;

public class StringUtils {

   // ==================================================================================================================================
   // Fonde le proprietà in un unica stringa
   // ==================================================================================================================================
   public static String join(Properties ObjProperties, String StrSeparator) {
      
      if (ObjProperties==null) return "";
      
      StringBuilder StrProperties = new StringBuilder();
      for (String StrKey : ObjProperties.stringPropertyNames()) {
         StrProperties.append(StrKey).append("=").append(ObjProperties.getProperty(StrKey)).append(StrSeparator);
      }
      
      // Remove the last comma
      if (StrProperties.length() > 0) {
         StrProperties.setLength(StrProperties.length() - 1);
      }
      
      return StrProperties.toString();
   }
   
   public static String join(String[] ArrStrings, String StrSeparator) {            
      String StrOutput = "";
      for (int IntIndex=0;IntIndex<ArrStrings.length;IntIndex++){            
         StrOutput+= ((IntIndex>0)?(StrSeparator):(""))+ArrStrings[IntIndex].trim();   
      }       
      return StrOutput;
   }
   
   // ==================================================================================================================================
   // Genera una sequenza di caratteri
   // ==================================================================================================================================
   public static String repeat(int IntLength, String StrFiller) {
      return new String(new char[IntLength]).replace("\0", StrFiller);
   }

   // ==================================================================================================================================
   // Esegue padding di stringhe
   // ==================================================================================================================================
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
 
   // ==================================================================================================================================
   // Calcola dimensione massima di un insieme di stringhe
   // ==================================================================================================================================
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

   public static int getMaxLength(Enumeration<String> ObjEnumerator) {
      return getMaxLength(ObjEnumerator, new ArrayList());
   }
   
   public static int getMaxLength(Enumeration<String> ObjEnumerator, List ArrExclusion) {      
      return getMaxLength(Collections.list(ObjEnumerator).iterator(),ArrExclusion);
   }
    
   // ==================================================================================================================================
   // Converte stringa di byte in esadecimale
   // ==================================================================================================================================
   public static String bytesToHex(byte[] ArrBytes) {
      StringBuilder ObjResult = new StringBuilder();
      for (byte ObjByte : ArrBytes) ObjResult.append(String.format("%02X", ObjByte));
      return ObjResult.toString();
   } 

   // ==================================================================================================================================
   // Wrapper di metodi di conversione stringa in via di deprecazione
   // ==================================================================================================================================
   public static String toString(BufferedReader ObjReader) throws IOException {
      return IOUtils.toString(ObjReader);
   }
}
