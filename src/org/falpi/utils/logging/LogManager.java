package org.falpi.utils.logging;

import java.util.Map;
import java.util.Date;
import java.util.List;
import java.util.Iterator;
import java.text.SimpleDateFormat;

import org.falpi.utils.JavaUtils;
import org.falpi.utils.StringUtils;

public class LogManager {

   // ==================================================================================================================================
   // Variabili di istanza
   // ==================================================================================================================================
   
   // Identificativo univoco del contesto di messaggi di log generati
   private String StrModuleId;
   
   // Lughezza di padding per il logging delle proprietà
   private int IntPadLength = 0;

   // Numero massimo di righe di stacktrace filtrate   
   private int IntLoggingLines = 100;
   
   // Livello minimo di logging filtrato
   private int IntLoggingLevel = LogLevel.TRACE;

   // ==================================================================================================================================
   // Costruttore
   // ==================================================================================================================================
   public LogManager(String StrModuleId) {      
      this.StrModuleId = StrModuleId;
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
   // Logging di proprietà chiave valore
   // ==================================================================================================================================
   public void logProperty(int IntLevel,String StrProperty,String StrValue) {
      logProperty(IntLevel,StrProperty,StrValue,IntPadLength);
   }

   public void logProperty(int IntLevel,String StrProperty,String StrValue,int IntPadding) {
      if (IntLevel>=IntLoggingLevel) {
         System.out.println(formatProperty(IntLevel,StrProperty,StrValue,IntPadding));
      }
   }

   public void logProperties(int IntLevel,Map<String,Object> ObjProperties,String StrSeparator,Boolean BolQuoteStringValues) {
      if (IntLevel>=IntLoggingLevel) {
         System.out.println(formatProperties(IntLevel,ObjProperties,StrSeparator,BolQuoteStringValues));
      }
   }
   
   public String formatProperty(int IntLevel,String StrProperty,String StrValue) {
      return formatProperty(IntLevel,StrProperty,StrValue,IntPadLength);
   }
   
   public String formatProperty(int IntLevel,String StrProperty,String StrValue,int IntPadding) {
      return formatMessage(IntLevel,StringUtils.padRight(StrProperty+" ",IntPadding,".")+": "+StrValue);
   }
   
   public String formatProperties(int IntLevel,Map<String,Object> ObjProperties,String StrSeparator,Boolean BolQuoteStringValues) {
      
      String StrReturn = "\n";
      int IntMaxLength = StringUtils.getMaxLength(ObjProperties.keySet().iterator());                                                     
            
      if (!StrSeparator.equals("")) StrReturn+= formatMessage(IntLevel,StrSeparator)+"\n";
      for (Map.Entry<String,Object> ObjEntry : ObjProperties.entrySet()) {
         Object ObjValue = ObjEntry.getValue();
         
         if (ObjValue instanceof List) {
            Iterator<String> ObjIterator = ((List<String>)ObjValue).iterator();
            while (ObjIterator.hasNext()) {
               Object ObjListValue = ObjIterator.next();
               String StrQuotes = ((BolQuoteStringValues)&&(ObjListValue instanceof String))?("\""):("");
               StrReturn+= formatProperty(IntLevel,ObjEntry.getKey(),StrQuotes+ObjListValue+StrQuotes,IntMaxLength+4)+"\n";
            }
         } else {         
            String StrQuotes = ((BolQuoteStringValues)&&(ObjValue instanceof String))?("\""):("");
            StrReturn+= formatProperty(IntLevel,ObjEntry.getKey(),StrQuotes+ObjValue+StrQuotes,IntMaxLength+4)+"\n";
         }
      } 
      if (!StrSeparator.equals("")) StrReturn+= formatMessage(IntLevel,StrSeparator);
            
      return StrReturn;
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

   public String formatMessage(int IntLevel,String StrMessage) {
      return new SimpleDateFormat("'<'yyyy-MM-dd HH:mm:ss.SSS'>'").format(new Date(System.currentTimeMillis()))+
                                  " <"+StrModuleId+">"+
                                  " <"+Thread.currentThread().getName()+"> "+
                                  StringUtils.padRight("<"+LogLevel.getDescription(IntLevel)+">",8," ")+
                                  StrMessage;
   }    
}
