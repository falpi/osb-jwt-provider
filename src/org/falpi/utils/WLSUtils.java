package org.falpi.utils;

import java.util.ArrayList;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServletRequest;

import org.falpi.utils.JavaUtils;

public class WLSUtils {

   // ==================================================================================================================================
   // Aggiunge un header http agli header della servlet di request
   // ==================================================================================================================================
   @SuppressWarnings("unchecked")
   public static String addHeader(HttpServletRequest ObjRequest,String StrHeaderName,String StrHeaderValue) throws Exception {
      
      // Accede agli header della request
      Object ObjHeaders = JavaUtils.getField(ObjRequest,"headers");
      ArrayList<String> ArrHeaderNames = (ArrayList<String>) JavaUtils.getField(ObjHeaders, "headerNames");
      ArrayList<byte[]> ArrHeaderValues = (ArrayList<byte[]>) JavaUtils.getField(ObjHeaders, "headerValues");
      
      // Se l'header indicato esiste ne sostituisce il valore ed esce restituendo il valore precedente
      for (int IntIndex=0;IntIndex<ArrHeaderNames.size(); IntIndex++) {
         String StrName = ArrHeaderNames.get(IntIndex);
         if (StrName.equals(StrHeaderName)) {
            return new String(ArrHeaderValues.set(IntIndex,StrHeaderValue.getBytes(StandardCharsets.UTF_8)),StandardCharsets.UTF_8);
         }
      }
      
      // Imposta il nuovo header alla fine dell'array
      ArrHeaderNames.add(StrHeaderName);
      ArrHeaderValues.add(StrHeaderValue.getBytes(StandardCharsets.UTF_8)); 

      // Restituisce null in quanto header non esistente
      return null;
   }}
