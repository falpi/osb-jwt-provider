package org.falpi.utils;

import java.util.Map;

public interface JWTToken {

   // ==================================================================================================================================
   // Inizializza il token
   // ==================================================================================================================================
   public void parse(String StrToken) throws Exception;

   // ==================================================================================================================================
   // Acquisisce la versione della libreria
   // ==================================================================================================================================
   public String version() throws Exception;
         
   // ==================================================================================================================================
   // Acquisisce il keyid del token
   // ==================================================================================================================================
   public String getKeyID() throws Exception;

   // ==================================================================================================================================
   // Acquisisce l'header del token
   // ==================================================================================================================================
   public Map getHeader() throws Exception;

   // ==================================================================================================================================
   // Acquisisce il payload del token
   // ==================================================================================================================================
   public Map getPayload() throws Exception;

   // ==================================================================================================================================
   // Verifica che il token jwt sia conforme a quanto atteso
   // ==================================================================================================================================
   public boolean verify(String StrModulus, String StrExponent) throws Exception;
}
