package org.falpi.utils.jwt;

import com.nimbusds.jwt.SignedJWT;

import java.util.Map;

import java.util.logging.Logger;

import org.falpi.utils.JavaUtils;
import org.falpi.utils.logging.LogLevel;

public abstract class JWTToken<T> {
   
   // ==================================================================================================================================
   // Variabili private
   // ==================================================================================================================================
   protected T ObjToken = null;
   
   // Flag di inizializzazione avvenuta del token
   private Boolean BolReady = false;

   // ==================================================================================================================================
   // Carica nuovo provider
   // ==================================================================================================================================
   public static JWTToken create(String StrProvider) throws Exception {
      return (JWTToken) Class.forName(JWTToken.class.getCanonicalName()+StrProvider+"Impl").newInstance();
   }

   // ==================================================================================================================================
   // Inizializza il token
   // ==================================================================================================================================
   public void init(T ObjToken) throws Exception {
      this.BolReady = true;
      this.ObjToken = ObjToken;
   }
   
   // ==================================================================================================================================
   // Inizializza eseguendo parsing di una stringa base64
   // ==================================================================================================================================
   public abstract void parse(String StrToken) throws Exception;

   // ==================================================================================================================================
   // Acquisisce la versione della libreria
   // ==================================================================================================================================
   public abstract String version() throws Exception;
         
   // ==================================================================================================================================
   // Acquisisce il keyid del token
   // ==================================================================================================================================
   public abstract String getKeyID() throws Exception;

   // ==================================================================================================================================
   // Acquisisce l'header del token
   // ==================================================================================================================================
   public abstract Map getHeader() throws Exception;

   // ==================================================================================================================================
   // Acquisisce il payload del token
   // ==================================================================================================================================
   public abstract Map getPayload() throws Exception;

   // ==================================================================================================================================
   // Verifica che il token jwt sia conforme a quanto atteso
   // ==================================================================================================================================
   public abstract boolean verify(String StrModulus, String StrExponent) throws Exception;

   // ==================================================================================================================================
   // Verifica che il token jwt sia inizializzato
   // ==================================================================================================================================
   public boolean isReady() {
      return BolReady;
   }
}
