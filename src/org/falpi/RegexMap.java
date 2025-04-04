package org.falpi;

import java.util.Map;
import java.util.ArrayList;
import java.util.LinkedHashMap;

public class RegexMap<T> extends LinkedHashMap<String,T> {
   
   @SuppressWarnings("compatibility")
   private static final long serialVersionUID = 8264272464644480142L;

   // Ricerca il match su base espressione regolare
   public ArrayList<T> getRegex(String StrKey,Boolean BolFirst) {
      
      // Prepara array dei risultati
      ArrayList<T> ObjResults = new ArrayList<T>();
      
      // Aggiunge ai risultati tutte le entry che matchano con la chiave fornita
      for (Map.Entry<String,T> ObjEntry : entrySet()) {
         if (StrKey.matches(ObjEntry.getKey())) {
            ObjResults.add(ObjEntry.getValue());
            if (BolFirst) break;
         }
      }                  
      
      // Restituisce risultati
      return ObjResults;
   }      
}

