package org.falpi.utils.jwt;

import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;

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
   private ConcurrentHashMap<String,JWTCacheEntry> ObjCache = new ConcurrentHashMap<String,JWTCacheEntry>();
   
   // ==================================================================================================================================
   // Inserisce una chiave nella cache
   // ==================================================================================================================================
   public JWTCacheEntry putKey(String StrKeyID,String StrModulus,String StrExponent) {
      JWTCacheEntry ObjKey = new JWTCacheEntry(StrModulus,StrExponent);
      ObjCache.put(StrKeyID,ObjKey);
      return ObjKey;
   }

   // ==================================================================================================================================
   // Acquisisce chiave dalla cache
   // ==================================================================================================================================
   public JWTCacheEntry getKey(String StrKeyID) {    
      return ObjCache.get(StrKeyID);
   }

   // ==================================================================================================================================
   // Acquisisce chiave dalla cache se non è scaduta
   // ==================================================================================================================================
   public JWTCacheEntry validKey(String StrKeyID,int IntKeysTTL) {
      
      // Cerca chiave in cache
      JWTCacheEntry ObjEntry = getKey(StrKeyID);
      
      // Se la chiave esiste ma è scaduta resetta riferimento
      if ((ObjEntry!=null)&&((System.currentTimeMillis()-ObjEntry.timeStamp)>(IntKeysTTL*1000))) ObjEntry = null;
         
      // Restituisce riferimento
      return ObjEntry;
   }
}
