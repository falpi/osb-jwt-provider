package org.falpi.utils;

import java.util.ArrayList;
import java.nio.charset.StandardCharsets;
import java.security.AccessController;
import javax.servlet.http.HttpServletRequest;

import weblogic.security.service.PrivilegedActions;
import weblogic.security.acl.internal.AuthenticatedSubject;
import weblogic.security.providers.authentication.EmbeddedLDAPAtnDelegate;
import weblogic.management.security.ProviderMBean;
import weblogic.management.provider.ManagementService;

public class WLSUtils {
   
   // ##################################################################################################################################
   // Sottoclassi
   // ##################################################################################################################################

   // Wrapper per incapsulare la gestione dell'autenticatore embedded di wls
   public static class Authenticator {
      
      // Prepara handle per autenticatore embedded di wls
      private EmbeddedLDAPAtnDelegate ObjAuthenticator;

      Authenticator(ProviderMBean ObjMBean, String StrRealmName,String StrDomainName) { 
         ObjAuthenticator = new EmbeddedLDAPAtnDelegate(ObjMBean, null,StrRealmName, StrDomainName, false);
      }     
      
      public String authenticate(String StrUserName,String  StrPassword) {
         return ObjAuthenticator.authenticate(StrUserName,StrPassword);  
      }
   }
   
   // ##################################################################################################################################
   // Variabili statiche
   // ##################################################################################################################################

   // Prepara handle per accesso al kernel wls
   private static final AuthenticatedSubject ObjKernelId =
      (AuthenticatedSubject) AccessController.doPrivileged(PrivilegedActions.getKernelIdentityAction());

   // ##################################################################################################################################
   // Metodi statici 
   // ##################################################################################################################################
   
   // ==================================================================================================================================
   // Aggiunge un header http agli header della servlet di request
   // ==================================================================================================================================
   public static String addHeader(HttpServletRequest ObjRequest,String StrHeaderName,String StrHeaderValue) throws Exception {
      
      // Accede agli header della request
      Object ObjHeaders = JavaUtils.getField(ObjRequest,"headers");
      ArrayList<String> ArrHeaderNames = (ArrayList<String>) JavaUtils.getField(ObjHeaders, "headerNames");
      ArrayList<byte[]> ArrHeaderValues = (ArrayList<byte[]>) JavaUtils.getField(ObjHeaders, "headerValues");
      
      // Se l'header indicato esiste ne sostituisce il valore ed esce restituendo il valore precedente
      for (int IntIndex=0;IntIndex<ArrHeaderNames.size(); IntIndex++) {
         String StrName = ArrHeaderNames.get(IntIndex);
         if (StrName.equals(StrHeaderName)) {
            return new String(ArrHeaderValues.set(IntIndex,StrHeaderValue.getBytes(StandardCharsets.UTF_8)),StandardCharsets.UTF_8);
         }
      }
      
      // Imposta il nuovo header alla fine dell'array
      ArrHeaderNames.add(StrHeaderName);
      ArrHeaderValues.add(StrHeaderValue.getBytes(StandardCharsets.UTF_8)); 

      // Restituisce null in quanto header non esisteva
      return null;
   }
   
   // ==================================================================================================================================
   // Acquisisce handle per accesso al kernel wls
   // ==================================================================================================================================
   public static AuthenticatedSubject getKernelId() {   
      return ObjKernelId;
   }

   // ==================================================================================================================================
   // Acquisisce nome dominio wls
   // ==================================================================================================================================      
   public static String getDomainName() { 
      return ManagementService.getRuntimeAccess(ObjKernelId).getDomainName();
   }

   // ==================================================================================================================================
   // Acquisisce nome del managed server wls
   // ==================================================================================================================================      
   public static String getManagedName() { 
      return ManagementService.getRuntimeAccess(ObjKernelId).getServerName();
   }   
   
   // ==================================================================================================================================
   // Acquisisce l'authenticator integrato di wls
   // ==================================================================================================================================      
   public static Authenticator getAuthenticator(ProviderMBean ObjMBean, String StrRealmName,String StrDomainName) { 
      return new Authenticator(ObjMBean,StrRealmName,StrDomainName);
   }   
}
