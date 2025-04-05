package org.falpi;

import java.util.ArrayList;
import java.util.LinkedHashMap;

public class SuperMap<T> extends LinkedHashMap<String,T> {
   
   @SuppressWarnings("compatibility")
   private static final long serialVersionUID = -8475373322215521291L;

   // Elemento speciale per espressioni regolari
   private transient RegexMap<T> ObjRegExMap = new RegexMap<T>();
      
   // Ricerca tutti i match con il contesto speciale per le espressioni regolari
   public ArrayList<T> getRegex(String StrKey,Boolean BolFirst) {
               
      // Se l'elemento regex non esiste restituisce insieme vuoto, altrimenti se non è della classe attesa genera eccezione         
      return ObjRegExMap.getRegex(StrKey,BolFirst);
   }

   // aggiunge una entry nel contesto speciale per le espressioni regolari
   public T putRegex(String StrRegexKey,T Value) {
                        
      // Aggiunge la regex all'elemento speciale
      return ObjRegExMap.put(StrRegexKey,Value);
   }
   
   public String getString(String StrKey) {
      return (String) get(StrKey);
   }
   
   public Integer getInteger(String StrKey) {
      return (Integer) get(StrKey);
   }        
}
