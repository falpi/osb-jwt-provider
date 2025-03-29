package org.falpi.utils.logging;

import java.text.SimpleDateFormat;

import java.util.Date;

import org.falpi.utils.JavaUtils;
import org.falpi.utils.StringUtils;

public class LogManager {

   // ==================================================================================================================================
   // Variabili di istanza
   // ==================================================================================================================================
   
   // Identificativo univoco del contesto di messaggi di log generati
   private String StrLoggerID;
   
   // Lughezza di padding per il logging delle proprietà
   private int IntPadLength = 0;

   // Numero massimo di righe di stacktrace filtrate   
   private int IntLoggingLines = 100;
   
   // Livello minimo di logging filtrato
   private int IntLoggingLevel = LogLevel.TRACE;

   // ==================================================================================================================================
   // Costruttore
   // ==================================================================================================================================
   public LogManager(String StrLoggerID) {      
      this.StrLoggerID = StrLoggerID;
   }   
   
   // ==================================================================================================================================
   // Imposta livello di logging
   // ==================================================================================================================================
   public void setLogLevel(int IntLevel) {
      IntLoggingLevel = IntLevel;
   } 
   
   public void setLogLevel(String StrLevel) {
      setLogLevel(LogLevel.getLevel(StrLevel));
   }   

   // ==================================================================================================================================
   // Imposta livello di logging
   // ==================================================================================================================================
   public void setLogLines(int IntLines) {
      IntLoggingLines = IntLines;
   } 
   
   // ==================================================================================================================================
   // Imposta dimensione del padding
   // ==================================================================================================================================
   public void setPadLength(int IntLength) {
      IntPadLength = IntLength;
   } 
   
   // ==================================================================================================================================
   // Formatta messaggio di log
   // ==================================================================================================================================
   public String formatMessage(int IntLevel,String StrMessage) {
      return new SimpleDateFormat("'<'yyyy-MM-dd HH:mm:ss.SSS'>'").format(new Date(System.currentTimeMillis()))+
                                  " <"+StrLoggerID+">"+
                                  " <"+Thread.currentThread().getName()+"> "+
                                  StringUtils.padRight("<"+LogLevel.getDescription(IntLevel)+">",8," ")+
                                  StrMessage;
   } 
   
   // ==================================================================================================================================
   // Logging di proprietà chiave valore con padding
   // ==================================================================================================================================

   public void logProperty(int IntLevel,String StrProperty,String StrValue) {
      logMessage(IntLevel,StringUtils.padRight(StrProperty+" ",IntPadLength,".")+": "+StrValue);
   }   

   // ==================================================================================================================================
   // Logging di messaggi generici
   // ==================================================================================================================================

   public void logMessage(int IntLevel,String StrMessage) {
      logMessage(IntLevel,StrMessage,null);
   }   

   public void logMessage(int IntLevel,String StrMessage,Object ObjDetails) {
                  
      // Se il livello di logging dichiarato è sopra la soglia di filtro esegue
      if (IntLevel>=IntLoggingLevel) {
         
         // Se i dettagli forniti sono una stringa la predispone
         String StrDetails = (ObjDetails!=null)&&(ObjDetails instanceof String)?((String)ObjDetails):("");
         
         // Se i dettagli forniti sono una eccezione la predispone
         Exception ObjException = (ObjDetails!=null)&&(ObjDetails instanceof Exception)?((Exception)ObjDetails):(null);
                  
         // Prova a costruire la stringa di suffisso del messaggio
         String StrSuffix = StrDetails+(((ObjException!=null)&&(ObjException.getCause()!=null))?(ObjException.getCause()):(""));
         
         // Se il suffisso non è stato popolato e c'è una eccezione prova a estrapolare la prima dello stacktrace
         if (StrSuffix.equals("")&&(ObjException!=null)) {
            String[] ArrSuffix = JavaUtils.getStackTrace(1,ObjException).split(":",2);
            StrSuffix = ArrSuffix[ArrSuffix.length-1].trim();
         }
                                                                                                   
         // Genera messaggio di log
         System.out.println(formatMessage(IntLevel,StrMessage)+((!StrSuffix.equals(""))?(": "+StrSuffix):("")));
         
         // Se necessario genera marker+stacktrace
         if ((ObjException!=null)&&(IntLevel>=LogLevel.WARN)&&(IntLoggingLevel==LogLevel.TRACE)&&(IntLoggingLines>0)) {            
            System.out.println("--- StackTrace ---------------------------------------------------------------------------------------------------------------");
            System.out.println(JavaUtils.getStackTrace(IntLoggingLines,ObjException));
            System.out.println("------------------------------------------------------------------------------------------------------------------------------");            
         }
      }
   }   
}
