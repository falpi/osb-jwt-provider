package org.falpi;

import java.util.ArrayList;
import java.util.Properties;
import java.util.LinkedHashMap;

public class SuperMap<T> extends LinkedHashMap<String,T> {

   @SuppressWarnings("compatibility")
   private static final long serialVersionUID = 1L;

   // ==================================================================================================================================
   // Variabili istanza
   // ==================================================================================================================================
   
   // Elemento speciale per espressioni regolari
   private transient RegexMap<T> ObjRegExMap = new RegexMap<T>();   
      
   // ==================================================================================================================================
   // Motodi per accesso a mappa regex
   // ==================================================================================================================================
   public ArrayList<T> getRegex(String StrKey,Boolean BolFirst) {
      return ObjRegExMap.getRegex(StrKey,BolFirst);
   }

   public T putRegex(String StrRegexKey,T Value) {
      return ObjRegExMap.put(StrRegexKey,Value);
   }

   // ==================================================================================================================================
   // Motodi per estrazione tipizzata da mappa principale
   // ==================================================================================================================================      
   public Integer getInteger(String StrKey) {
      return (Integer) get(StrKey);
   }  

   public String getString(String StrKey) {
      Object ObjKey = get(StrKey);
      return (ObjKey instanceof Integer)?(Integer.toString((Integer)ObjKey)):(ObjKey.toString());
   }

   public String[] getStringArray(String StrKey) {
      return (String[]) get(StrKey);
   }
   
   public Properties getProperties(String StrKey) {
      return (Properties) get(StrKey);
   }   
}
