package org.falpi.utils.jwt;

import java.util.HashMap;

public class JWTCache {

   // ==================================================================================================================================
   // Sottoclasse per tipizzazione delle entry della cache
   // ==================================================================================================================================

   public class JWTCacheEntry {  
      
      public String modulus;      
      public String exponent; 
      public long timeStamp;
      
      JWTCacheEntry(String StrModulus,String StrExponent) {
         this.modulus = StrModulus;
         this.exponent = StrExponent;
         this.timeStamp = System.currentTimeMillis();
      }      
   }
   
   // ==================================================================================================================================
   // Variabili 
   // ==================================================================================================================================
   
   // Istanza della cache
   private HashMap<String,JWTCacheEntry> ObjCache = new HashMap<String,JWTCacheEntry>();
   
   // ==================================================================================================================================
   // Inserisce una chiave nella cache
   // ==================================================================================================================================

   // Crea nuova istanza del token provider specificato
   public void putKey(String StrKeyID,String StrModulus,String StrExponent) {    
      ObjCache.put(StrKeyID,new JWTCacheEntry(StrModulus,StrExponent));
   }

   // ==================================================================================================================================
   // Acquisisce chiave dalla cache
   // ==================================================================================================================================

   // Crea nuova istanza del token provider specificato
   public JWTCacheEntry getKey(String StrKeyID) {    
      return ObjCache.get(StrKeyID);
   }

}
