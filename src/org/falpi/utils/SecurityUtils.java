package org.falpi.utils;

import java.io.File;
import java.io.FileWriter;

import java.util.Map;
import java.util.HashMap;

import javax.security.auth.Subject;
import javax.security.auth.spi.LoginModule;

import org.apache.commons.io.IOUtils;

public class SecurityUtils {

   // ==================================================================================================================================
   // Variabili statiche
   // ==================================================================================================================================
   
   public static String StrKerberosConfiguration;
   
   // ==================================================================================================================================
   // Esegue autenticazione kerberos
   // ==================================================================================================================================
   public static Object[] kerberosLogin(String StrPrincipal,String StrPassword) throws Exception {
      
      // Crea file temporanei per configurazione kerberos
      File ObjKerberosAuthConfig = File.createTempFile("krb5-", ".conf");
      ObjKerberosAuthConfig.deleteOnExit();
      
      // Ppopla i file temporanei   
      FileWriter ObjWriter;
      ObjWriter = new FileWriter(ObjKerberosAuthConfig);
      IOUtils.write(StrKerberosConfiguration,ObjWriter);         
      IOUtils.closeQuietly(ObjWriter);
                             
      // Imposta proprietà di sistema kerberos
      System.setProperty("java.security.krb5.conf", ObjKerberosAuthConfig.toURI().toString());
      System.setProperty("javax.security.auth.useSubjectCredsOnly","false");

      // Imposta parametri del LoginModule
      Subject ObjSubject = new Subject();
      Map<String,Object> ObjState = new HashMap();
      Map<String,Object> ObjOptions = new HashMap();

      ObjOptions.put("doNotPrompt", "true");
      ObjOptions.put("useFirstPass", "true");
      ObjOptions.put("refreshKrb5Config", "true");

      ObjState.put("javax.security.auth.login.name", StrPrincipal);
      ObjState.put("javax.security.auth.login.password", StrPassword.toCharArray());

      LoginModule ObjLoginModule = null;
      try {         
         // Inizializza loginmodule ed esegue autenticazione
         ObjLoginModule = (LoginModule) Class.forName("com.sun.security.auth.module.Krb5LoginModule").newInstance();      
         ObjLoginModule.initialize(ObjSubject, null, ObjState, ObjOptions);
         ObjLoginModule.login();
         ObjLoginModule.commit();  
         
      } catch (Exception ObjException) {     
                  
         // Abortisce il login
         if (ObjLoginModule!=null) ObjLoginModule.abort();
         
         // Rimuove file temporanei
         ObjKerberosAuthConfig.delete();
         
         // Ribalta l'eccezione propagando la causa         
         throw ObjException;
      }
                  
      // Rimuove file temporanei
      ObjKerberosAuthConfig.delete();

      // Restituisce LoginModule e Subject
      return new Object[]{ObjLoginModule,ObjSubject};
   }
}
