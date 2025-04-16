package org.falpi.utils;

import java.io.PrintWriter;
import java.io.StringWriter;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

import java.text.SimpleDateFormat;

import java.util.Date;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineFactory;
import javax.script.ScriptEngineManager;

public class JavaUtils {

   // ==================================================================================================================================
   // Gestione del tempo
   // ==================================================================================================================================
   public static String getDateTime() {
       return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date());
   }   
 
   public static Long getTimestamp() {
       return Long.valueOf(System.currentTimeMillis());
   }
   
   // ==================================================================================================================================
   // Inizializza script engine
   // ==================================================================================================================================   
   public static ScriptEngine getScriptEngine() throws Exception {   
      
      // Prova a istanziare lo sript engine built-in
      ScriptEngine ObjScriptEngine =  new ScriptEngineManager().getEngineByName("JavaScript"); 
      
      // Se lo script engine JavaScript non è disponibile prova ad utilizzare lo script engine esterno      
      if (ObjScriptEngine==null) {
         ObjScriptEngine = ((ScriptEngineFactory) Class.forName("org.mozilla.javascript.engine.RhinoScriptEngineFactory").newInstance()).getScriptEngine();
      }
      
      return ObjScriptEngine;
   }

   // ==================================================================================================================================
   // Formatta lo stack trace
   // ==================================================================================================================================
   public static String getStackTrace(int IntLines,Exception ObjException) {
            
      // Acquisisce lo stacktrace
      StringWriter ObjStringWriter = new StringWriter();
      PrintWriter ObjPrintWriter = new PrintWriter(ObjStringWriter);
      ObjException.printStackTrace(ObjPrintWriter);
      
      // Frammenta lo stacktrace in righe
      String[] ArrStackTrace = ObjStringWriter.toString().split("\n");
      
      // Filtra le righe richieste
      String StrStackTrace = "";            
      for (int IntIndex=0;IntIndex<Math.min(IntLines,ArrStackTrace.length);IntIndex++) {
         StrStackTrace+= (StrStackTrace.equals("")?(""):("\n"))+ArrStackTrace[IntIndex].toString();
      }
      
      // Restituisce stacktrace filtrato
      return StrStackTrace;
   }
   
   // ==================================================================================================================================
   // Imposta un attributo anche se privato/final mediante reflection
   // ==================================================================================================================================
   public static void setField(Object ObjInstance, String StrField, Object ObjValue) throws Exception {      
      Field ObjField = ObjInstance.getClass().getDeclaredField(StrField);      
      ObjField.setAccessible(true);
      Field ObjFieldModifiers = Field.class.getDeclaredField("modifiers");
      ObjFieldModifiers.setAccessible(true);
      ObjFieldModifiers.setInt(ObjField, ObjField.getModifiers() & ~Modifier.FINAL);
      ObjField.set(null,ObjValue);
   }
   
   // ==================================================================================================================================
   // Acquisisce un attributo anche se privato mediante reflection
   // ==================================================================================================================================
   public static Object getField(Object ObjInstance, String StrField) throws Exception {      
      Field ObjHeadersField = ObjInstance.getClass().getDeclaredField(StrField);
      ObjHeadersField.setAccessible(true);
      return ObjHeadersField.get(ObjInstance);
   }
   
   // ==================================================================================================================================
   // Acquisisce versione java
   // ==================================================================================================================================
   public static int getJavaVersion() {
      String StrVersion = System.getProperty("java.version");
      if(StrVersion.startsWith("1.")) {
          StrVersion = StrVersion.substring(2, 3);
      } else {
          int IntDotIndex = StrVersion.indexOf(".");
          if(IntDotIndex != -1) { 
             StrVersion = StrVersion.substring(0,IntDotIndex); 
          }
      } 
      return Integer.parseInt(StrVersion);
   }
}
