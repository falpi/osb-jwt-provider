package org.falpi.utils.logging;

public class LogLevel {
   
   public final static int TRACE = 0;
   public final static int DEBUG = 1;
   public final static int INFO = 2;
   public final static int WARN = 3;
   public final static int ERROR = 4;
   
   public static int getLevel(String StrLoggingLevel)  {
      switch (StrLoggingLevel) {
         case "TRACE" : return TRACE; 
         case "DEBUG" : return DEBUG; 
         case "INFO" : return INFO; 
         case "WARN" : return WARN; 
         case "ERROR" : return ERROR; 
         default : return -1;                                                            
      }
   }
   
   public static String getDescription(int IntLoggingLevel) {
      switch (IntLoggingLevel) {
         case TRACE : return "TRACE"; 
         case DEBUG : return "DEBUG"; 
         case INFO : return "INFO"; 
         case WARN : return "WARN"; 
         case ERROR : return "ERROR"; 
         default :  return "?????";
      }
   }
}

