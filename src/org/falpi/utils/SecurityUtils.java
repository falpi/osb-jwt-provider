package org.falpi.utils;

import java.io.File;
import java.io.FileWriter;

import java.util.Map;
import java.util.HashMap;

import javax.security.auth.Subject;

import org.apache.commons.io.IOUtils;

import com.sun.security.auth.module.Krb5LoginModule;

import com.bea.xbean.util.Base64;

public class SecurityUtils {
   
   // ==================================================================================================================================
   // Codifica/Decodifica Base64
   // ==================================================================================================================================
   public static String encodeBase64(String StrClearText) {
       return new String(Base64.encode(StrClearText.getBytes()));
   }   
   public static String decodeBase64(String StrEncodedText) {
       return new String(Base64.decode(StrEncodedText.getBytes()));
   }
   
   // ==================================================================================================================================
   // Sottoclasse per login kerberos
   // ==================================================================================================================================
   public static class CustomKrb5LoginModule extends Krb5LoginModule {
      
      // Mantiene una copia locale del subject autenticato
      private Subject ObjSubject = new Subject();
             
      // Costruttore
      @SuppressWarnings("unchecked")
      CustomKrb5LoginModule(String StrPrincipal, String StrPassword) {
         
         Subject ObjSubject = new Subject();
         Map<String,Object> ObjState = new HashMap();
         Map<String,Object> ObjOptions = new HashMap();

         ObjOptions.put("doNotPrompt", "true");
         ObjOptions.put("useFirstPass", "true");
         ObjOptions.put("refreshKrb5Config", "true");

         ObjState.put("javax.security.auth.login.name", StrPrincipal);
         ObjState.put("javax.security.auth.login.password", StrPassword.toCharArray());         
         
         super.initialize(ObjSubject,null,ObjState,ObjOptions);
      }
      
      // Restituisce il subject
      public Subject getSubject() {
         return ObjSubject;
      }
   };

   // ==================================================================================================================================
   // Variabili statiche
   // ==================================================================================================================================
   
   // File temporaneo per configurazione kerberos
   private static File ObjKerberosAuthConfig;

   // ==================================================================================================================================
   // Acquisisce path del file di configurazione kerberos
   // ==================================================================================================================================
   public static String getKerberosConfigPath() {
      if (ObjKerberosAuthConfig==null) {
         return "undefined";
      } else {
         return ObjKerberosAuthConfig.getPath();
      }
   }

   // ==================================================================================================================================
   // Inizializza configurazione kerberos
   // ==================================================================================================================================
   public static void configKerberos(String StrConfiguration) throws Exception {

      // Se il file temporaneo non è ancora stato creato esegue
      if (ObjKerberosAuthConfig==null) {
         
         // Crea file temporaneo e imposta la autocancellazione all'uscita
         ObjKerberosAuthConfig = File.createTempFile("krb5-", ".conf");
         ObjKerberosAuthConfig.deleteOnExit();
                                
         // Imposta proprietà di sistema kerberos 
         System.setProperty("java.security.krb5.conf",ObjKerberosAuthConfig.toURI().toString());
         System.setProperty("javax.security.auth.useSubjectCredsOnly","false");         
      }
      
      // Popola la configurazione sul file temporaneo 
      FileWriter ObjWriter = new FileWriter(ObjKerberosAuthConfig);
      IOUtils.write(StrConfiguration,ObjWriter);         
      IOUtils.closeQuietly(ObjWriter);      
   }   
   
   // ==================================================================================================================================
   // Esegue autenticazione kerberos
   // ==================================================================================================================================
   public static CustomKrb5LoginModule loginKerberos(String StrPrincipal,String StrPassword) throws Exception {
         
      CustomKrb5LoginModule ObjLoginModule = null;      
      try {         
         // Inizializza loginmodule ed esegue autenticazione
         ObjLoginModule = new CustomKrb5LoginModule(StrPrincipal,StrPassword);
         ObjLoginModule.login();
         ObjLoginModule.commit();  
         
      } catch (Exception ObjException) {     
                  
         // Abortisce il login
         if (ObjLoginModule!=null) ObjLoginModule.abort();
         
         // Ribalta l'eccezione propagando la causa         
         throw ObjException;
      }

      // Restituisce LoginModule e Subject
      return ObjLoginModule;
   }
}
