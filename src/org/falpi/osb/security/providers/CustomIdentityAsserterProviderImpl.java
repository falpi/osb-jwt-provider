package org.falpi.osb.security.providers;

// ##################################################################################################################################
// Referenze
// ##################################################################################################################################

import java.util.Map;
import java.util.List;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Enumeration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Iterator;
import java.util.Collections;
import java.security.AccessController;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptEngineFactory;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.AppConfigurationEntry;

import weblogic.security.service.ContextHandler;
import weblogic.security.spi.AuthenticationProviderV2;
import weblogic.security.spi.IdentityAsserterV2;
import weblogic.security.spi.IdentityAssertionException;
import weblogic.security.spi.PrincipalValidator;
import weblogic.security.spi.SecurityServices;
import weblogic.security.acl.internal.AuthenticatedSubject;
import weblogic.security.providers.authentication.EmbeddedLDAPAtnDelegate;
import weblogic.security.service.PrivilegedActions;
import weblogic.management.security.ProviderMBean;
import weblogic.management.provider.ManagementService;

import org.apache.commons.io.IOUtils;
import org.apache.xmlbeans.XmlObject;

import com.bea.wli.sb.services.ServiceInfo;
import com.bea.wli.sb.transports.TransportEndPoint;
import com.bea.xbean.util.Base64;

import org.json.XML;
import org.json.JSONObject;

import org.falpi.utils.OSBUtils;
import org.falpi.utils.XMLUtils;
import org.falpi.utils.JavaUtils;
import org.falpi.utils.HttpUtils;
import org.falpi.utils.HttpUtils.HttpMethod;
import org.falpi.utils.SecurityUtils;
import org.falpi.utils.StringUtils;
import org.falpi.utils.jwt.JWTToken;
import org.falpi.utils.logging.LogLevel;
import org.falpi.utils.logging.LogManager;

public final class CustomIdentityAsserterProviderImpl implements AuthenticationProviderV2, IdentityAsserterV2 {
   
   // ##################################################################################################################################
   // Sottoclassi 
   // ##################################################################################################################################
  
   // ==================================================================================================================================
   // Tipologie di token supportate
   // ==================================================================================================================================
   
   private static class TokenTypes {
      public final static String JWT_AUTH_ID = "JWT";
      public final static String BASIC_AUTH_ID = "BASIC";

      public final static String TOKEN_PREFIX = "CIA.";
      
      public final static String JWT_TYPE = TOKEN_PREFIX+JWT_AUTH_ID;
      public final static String BASIC_TYPE = TOKEN_PREFIX+BASIC_AUTH_ID;
      public final static String ALL_TYPE = TOKEN_PREFIX+JWT_AUTH_ID+"+"+BASIC_AUTH_ID;
      
      public final static String JWT_TYPE1 = TOKEN_PREFIX+JWT_AUTH_ID+"#1";
      public final static String ALL_TYPE1 = TOKEN_PREFIX+JWT_AUTH_ID+"+"+BASIC_AUTH_ID+"#1";

      public final static String JWT_TYPE2 = TOKEN_PREFIX+JWT_AUTH_ID+"#2";
      public final static String ALL_TYPE2 = TOKEN_PREFIX+JWT_AUTH_ID+"+"+BASIC_AUTH_ID+"#2";
      
      public final static List<String> ALL_TYPES = Arrays.asList(TokenTypes.BASIC_TYPE,
                                                                 TokenTypes.JWT_TYPE,  TokenTypes.ALL_TYPE,
                                                                 TokenTypes.JWT_TYPE1, TokenTypes.ALL_TYPE1,
                                                                 TokenTypes.JWT_TYPE2, TokenTypes.ALL_TYPE2);
   }  
   
   // ##################################################################################################################################
   // Dichiara variabili
   // ##################################################################################################################################

   // ==================================================================================================================================
   // Variabili di istanza
   // ==================================================================================================================================

   // Gestione del logging
   private LogManager Logger;

   // Gestione dell'identificazione
   private String StrAuthType = "";
   private String StrIdentity = "";
   private String StrUserName = "";
   
   // Variabili di contesto
   private String StrRealmName;
   private String StrDomainName;
   private String StrManagedName;
   private String StrProjectName;   
   private String StrServiceName;
   private String StrServicePath;

   private String StrClientHost;
   private String StrClientAddr;
   private String StrServerHost;
   private String StrServerAddr;
   private String StrServerName;
   private String StrServerPort;
   private String StrRequestURL;
   private String StrContentType;
   
   private ServiceInfo ObjService;
   private TransportEndPoint ObjEndpoint;
   private HttpServletRequest ObjRequest;
   private HttpServletResponse ObjResponse;  
   
   // Gestione del token jwt
   private String StrJwtKeyID;
   private JWTToken ObjJwtToken;
   private HashMap ObjJwtKeysCache = new HashMap();
           
   // Altre variabili di supporto
   private ScriptEngine ObjScriptEngine;   
   private AuthenticatedSubject ObjKernelId;
   private EmbeddedLDAPAtnDelegate ObjEmbeddedAuthenticator;

   private String StrDescription;   
   private CustomIdentityAsserterMBean ObjProviderMBean;

   // ##################################################################################################################################
   // Implementa interfacce di inbound security (AuthenticationProviderV2, IdentityAsserterV2)
   // ##################################################################################################################################

   @Override
   public void initialize(ProviderMBean ObjMBean, SecurityServices ObjSecurityServices) {
      
      // Inizializza logger
      Logger = new LogManager("CIA");
                  
      // Genera logging
      Logger.logMessage(LogLevel.INFO,"##########################################################################################");
      Logger.logMessage(LogLevel.INFO,"INITIALIZE");
      Logger.logMessage(LogLevel.INFO,"##########################################################################################");
      
      // Inizializza lo mbean
      ObjProviderMBean = (CustomIdentityAsserterMBean) ObjMBean;

      // Inizializza descrizione
      StrDescription = ObjMBean.getDescription() + "n" + ObjMBean.getVersion();

      // ==================================================================================================================================
      // Inizializza script engine
      // ==================================================================================================================================
            
      try {
         ObjScriptEngine = JavaUtils.getScriptEngine();
      } catch (Exception ObjException) {
         String StrError = "Script engine error";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         System.exit(0);
      }

      // ==================================================================================================================================
      // Inizializza token provider 
      // ==================================================================================================================================

      try {
         // Se il target � weblogic 12.1.3 (java=7) la libreria originale nimbus pu� essere integrata perch� non � presente a sistema
         // Se il target � weblogic 12.2.1 (7<java<17) poich� integra nimbus di una versione incompatibile occorre integrare una versione shaded 
         // Se il target � weblogic 14.1.2 (java>=17) poich� integra nimbus di una versione compatibile la si pu� usare diretamente
         ObjJwtToken = JWTToken.create((JavaUtils.getJavaVersion()>7)&&(JavaUtils.getJavaVersion()<17)?("NimbusShaded"):("Nimbus"));
         
      } catch (Exception ObjException) {
         String StrError = "Token provider error";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         System.exit(0);
      } 
      
      // ==================================================================================================================================
      // Inizializza autenticazione kerberos
      // ==================================================================================================================================

      try {
         SecurityUtils.configKerberos(StringUtils.join(ObjProviderMBean.getKERBEROS_CONFIGURATION(),System.lineSeparator()));
      } catch (Exception ObjException) {
         String StrError = "Kerberos config error";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         System.exit(0);
      }

      // ==================================================================================================================================
      // Prepara contesto server
      // ==================================================================================================================================
      
      // Inizializza provider di autenticazione di default per supporto alla basic authentication
      ObjKernelId = (AuthenticatedSubject) AccessController.doPrivileged(PrivilegedActions.getKernelIdentityAction());
      
      StrRealmName = ObjProviderMBean.getRealm().getName();
      StrDomainName = ManagementService.getRuntimeAccess(ObjKernelId).getDomainName();
      StrManagedName = ManagementService.getRuntimeAccess(ObjKernelId). getServerName();
      
      ObjEmbeddedAuthenticator = new EmbeddedLDAPAtnDelegate(ObjMBean, null,StrRealmName, StrDomainName, false);     

      // ==================================================================================================================================
      // Genera logging 
      // ==================================================================================================================================
    
      Logger.logMessage(LogLevel.INFO,"==========================================================================================");
      Logger.logMessage(LogLevel.INFO,"CONTEXT");
      Logger.logMessage(LogLevel.INFO,"==========================================================================================");
      Logger.logMessage(LogLevel.INFO,"Realm Name ...........: " + StrRealmName);
      Logger.logMessage(LogLevel.INFO,"Domain Name ..........: " + StrDomainName);
      Logger.logMessage(LogLevel.INFO,"Managed Name .........: " + StrManagedName);  
      Logger.logMessage(LogLevel.INFO,"------------------------------------------------------------------------------------------");
      Logger.logMessage(LogLevel.INFO,"JWT Provider .........: " + ObjJwtToken.getClass().getCanonicalName());  
      Logger.logMessage(LogLevel.INFO,"Kerberos Config ......: " + SecurityUtils.getKerberosConfigPath());
      Logger.logMessage(LogLevel.INFO,"Scripting Engine .....: " + ObjScriptEngine.getFactory().getEngineName()+" ("+ObjScriptEngine.getFactory().getEngineVersion()+")");  
      Logger.logMessage(LogLevel.INFO,"Scripting Language ...: " + ObjScriptEngine.getFactory().getLanguageName()+" ("+ObjScriptEngine.getFactory().getLanguageVersion()+")");  
      Logger.logMessage(LogLevel.INFO,"##########################################################################################");      
   }

   @Override
   public void shutdown() {
      Logger.logMessage(LogLevel.INFO,"##########################################################################################");      
      Logger.logMessage(LogLevel.INFO,"SHUTDOWN");
      Logger.logMessage(LogLevel.INFO,"##########################################################################################");      
   }

   @Override
   public String getDescription() {
      return StrDescription;
   }

   @Override
   public IdentityAsserterV2 getIdentityAsserter() {
      return this;
   }

   @Override
   public PrincipalValidator getPrincipalValidator() {
      return null;
   }

   @Override
   public AppConfigurationEntry getLoginModuleConfiguration() {
      return null;
   }

   @Override
   public AppConfigurationEntry getAssertionModuleConfiguration() {
      return null;
   }

   // ##################################################################################################################################
   // Implementa metodo principale per l'autenticazione
   // ##################################################################################################################################

   @Override
   public CallbackHandler assertIdentity(String StrTokenType, Object ObjToken, ContextHandler ObjContext) throws IdentityAssertionException {
      
      // ==================================================================================================================================
      // Acquisisce configurazione
      // ==================================================================================================================================
                     
      String StrLoggingLevel = ObjProviderMBean.getLOGGING_LEVEL();
      Integer IntLoggingLines = ObjProviderMBean.getLOGGING_LINES();
                     
      String StrBasicAuthStatus = ObjProviderMBean.getBASIC_AUTH();
      String StrJwtAuthStatus = ObjProviderMBean.getJWT_AUTH();
      
      String StrJwtKeysURL = ObjProviderMBean.getJWT_KEYS_URL();
      String StrJwtKeysFormat = ObjProviderMBean.getJWT_KEYS_FORMAT();
      String StrJwtKeysModulusXPath = ObjProviderMBean.getJWT_KEYS_MODULUS_XPATH();
      String StrJwtKeysExponentXPath = ObjProviderMBean.getJWT_KEYS_EXPONENT_XPATH();
      Integer IntJwtKeysCacheTTL = ObjProviderMBean.getJWT_KEYS_CACHE_TTL();
      Integer IntJwtKeysConnTimeout = ObjProviderMBean.getJWT_KEYS_CONN_TIMEOUT();
      Integer IntJwtKeysReadTimeout = ObjProviderMBean.getJWT_KEYS_READ_TIMEOUT();
      String StrJwtKeysSSLVerify = ObjProviderMBean.getJWT_KEYS_SSL_VERIFY();
      String StrJwtKeysHostAuthMode = ObjProviderMBean.getJWT_KEYS_HOST_AUTH_MODE();
      String StrJwtKeysHostAccountPath = ObjProviderMBean.getJWT_KEYS_HOST_ACCOUNT_PATH();
      String StrJwtKeysProxyServerMode = ObjProviderMBean.getJWT_KEYS_PROXY_SERVER_MODE();
      String StrJwtKeysProxyServerPath = ObjProviderMBean.getJWT_KEYS_PROXY_SERVER_PATH(); 
      
      String StrJwtIdentityMappingMode = ObjProviderMBean.getJWT_IDENTITY_MAPPING_MODE();
      String StrJwtIdentityMappingPath = ObjProviderMBean.getJWT_IDENTITY_MAPPING_PATH();
      String[] ArrJwtIdentityAssertion = ObjProviderMBean.getJWT_IDENTITY_ASSERTION();
      
      String[] ArrValidationAssertion = ObjProviderMBean.getVALIDATION_ASSERTION();
      String[] ArrDebuggingAssertion = ObjProviderMBean.getDEBUGGING_ASSERTION();
      String[] ArrDebuggingProperties = ObjProviderMBean.getDEBUGGING_PROPERTIES();
      
      // Comprime gli array multiriga
      String StrJwtIdentityAssertion = StringUtils.join(ArrJwtIdentityAssertion,System.lineSeparator());
      String StrValidationAssertion = StringUtils.join(ArrValidationAssertion,System.lineSeparator());
      String StrDebuggingAssertion = StringUtils.join(ArrDebuggingAssertion,System.lineSeparator());
      String StrDebuggingProperties = StringUtils.join(ArrDebuggingProperties,",");
            
      // ==================================================================================================================================
      // Prepara contesto
      // ==================================================================================================================================

      // Resetta identit�
      StrIdentity = "";
      StrUserName = "";

      ObjService = (ServiceInfo) ObjContext.getValue("com.bea.contextelement.alsb.service-info");
      //ObjEndpoint = (TransportEndPoint) ObjContext.getValue("com.bea.contextelement.alsb.transport.endpoint");
      ObjRequest = (HttpServletRequest) ObjContext.getValue("com.bea.contextelement.alsb.transport.http.http-request");
      //ObjResponse = (HttpServletResponse) ObjContext.getValue("com.bea.contextelement.alsb.transport.http.http-response");
      
      // Salva contesto osb
      StrProjectName = ObjService.getRef().getProjectName();
      StrServiceName = ObjService.getRef().getLocalName();
      StrServicePath = ObjService.getRef().getFullName();
      
      // Salva contesto client
      StrClientHost = ObjRequest.getRemoteHost(); 
      StrClientAddr = ObjRequest.getRemoteAddr();
      StrServerHost = ObjRequest.getLocalName();
      StrServerAddr = ObjRequest.getLocalAddr();
      StrServerName = ObjRequest.getServerName();
      StrServerPort = String.valueOf(ObjRequest.getServerPort());
      StrRequestURL = ObjRequest.getRequestURL().toString();
      StrContentType = ObjRequest.getContentType();
      
      // ==================================================================================================================================
      // Imposta livelli di logging (eventuali errori sull'asserzione di debug sono silenziati per non pregiudicare l'autenticazione)
      // ==================================================================================================================================   
      
      // Prepara livelli di logging di default
      Logger.setLogLevel(StrLoggingLevel);
      Logger.setLogLines(IntLoggingLines);

      // Se ecessario verifica del filtro per i messaggi di log di livello pi� basso
      if (!StrDebuggingAssertion.equals("")) {
         try {
            if (!((Boolean) evaluateScript(StrDebuggingAssertion,"Boolean"))) {
               Logger.setLogLevel(LogLevel.INFO);
            }
         } catch (Exception ObjException) {
            String StrError = "Debugging assertion error";
            Logger.logMessage(LogLevel.WARN,StrError,ObjException);
         }
      }

      // ==================================================================================================================================
      // Genera logging di debug per dump configurazione
      // ==================================================================================================================================

      // Genera logging 
      Logger.logMessage(LogLevel.DEBUG,"##########################################################################################");
      Logger.logMessage(LogLevel.DEBUG,"ASSERT IDENTITY");
      Logger.logMessage(LogLevel.DEBUG,"##########################################################################################");

      // Genera logging
      Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
      Logger.logMessage(LogLevel.DEBUG,"CONFIGURATION");
      Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
      Logger.logMessage(LogLevel.DEBUG,"LOGGING_LEVEL ................: " + StrLoggingLevel);
      Logger.logMessage(LogLevel.DEBUG,"LOGGING_LINES ................: " + IntLoggingLines);
      Logger.logMessage(LogLevel.DEBUG,"BASIC_AUTH ...................: " + StrBasicAuthStatus);
      Logger.logMessage(LogLevel.DEBUG,"JWT_AUTH .....................: " + StrJwtAuthStatus);
      Logger.logMessage(LogLevel.DEBUG,"JWT_KEYS_URL .................: " + StrJwtKeysURL);
      Logger.logMessage(LogLevel.DEBUG,"JWT_KEYS_FORMAT ..............: " + StrJwtKeysFormat);
      Logger.logMessage(LogLevel.DEBUG,"JWT_KEYS_MODULUS_XPATH .......: " + StrJwtKeysModulusXPath);
      Logger.logMessage(LogLevel.DEBUG,"JWT_KEYS_EXPONENT_XPATH ......: " + StrJwtKeysExponentXPath);
      Logger.logMessage(LogLevel.DEBUG,"JWT_KEYS_CACHE_TTL ...........: " + IntJwtKeysCacheTTL);
      Logger.logMessage(LogLevel.DEBUG,"JWT_KEYS_CONN_TIMEOUT ........: " + IntJwtKeysConnTimeout);
      Logger.logMessage(LogLevel.DEBUG,"JWT_KEYS_READ_TIMEOUT ........: " + IntJwtKeysReadTimeout);
      Logger.logMessage(LogLevel.DEBUG,"JWT_KEYS_SSL_VERIFY ..........: " + StrJwtKeysSSLVerify);
      Logger.logMessage(LogLevel.DEBUG,"JWT_KEYS_HOST_AUTH_MODE ......: " + StrJwtKeysHostAuthMode);
      Logger.logMessage(LogLevel.DEBUG,"JWT_KEYS_HOST_ACCOUNT_PATH ...: " + StrJwtKeysHostAccountPath);
      Logger.logMessage(LogLevel.DEBUG,"JWT_KEYS_PROXY_SERVER_MODE ...: " + StrJwtKeysProxyServerMode);
      Logger.logMessage(LogLevel.DEBUG,"JWT_KEYS_PROXY_SERVER_PATH ...: " + StrJwtKeysProxyServerPath);
      Logger.logMessage(LogLevel.DEBUG,"JWT_IDENTITY_MAPPING_MODE ....: " + StrJwtIdentityMappingMode);
      Logger.logMessage(LogLevel.DEBUG,"JWT_IDENTITY_MAPPING_PATH ....: " + StrJwtIdentityMappingPath);
      Logger.logMessage(LogLevel.DEBUG,"JWT_IDENTITY_ASSERTION .......: " + StrJwtIdentityAssertion.replaceAll("\n",""));
      Logger.logMessage(LogLevel.DEBUG,"VALIDATION_ASSERTION .........: " + StrValidationAssertion.replaceAll("\n",""));
      Logger.logMessage(LogLevel.DEBUG,"DEBUGGING_ASSERTION ..........: " + StrDebuggingAssertion.replaceAll("\n",""));
      Logger.logMessage(LogLevel.DEBUG,"DEBUGGING_PROPERTIES .........: " + StrDebuggingProperties);      
            
      // Controlli di congruenza configurazione
      Logger.logMessage(LogLevel.TRACE,"------------------------------------------------------------------------------------------");
      StrJwtKeysURL = (String) validateParameter("JWT_KEYS_URL", StrJwtKeysURL);
      StrJwtKeysModulusXPath = (String) validateParameter("JWT_KEYS_MODULUS_XPATH", StrJwtKeysModulusXPath);
      StrJwtKeysExponentXPath = (String) validateParameter("JWT_KEYS_EXPONENT_XPATH", StrJwtKeysExponentXPath);      
      validateParameter("JWT_KEYS_CACHE_TTL",IntJwtKeysCacheTTL);
      validateParameter("JWT_KEYS_CONN_TIMEOUT",IntJwtKeysConnTimeout);
      validateParameter("JWT_KEYS_READ_TIMEOUT",IntJwtKeysReadTimeout);      
      if (!StrJwtKeysHostAuthMode.equals("ANONYMOUS")) StrJwtKeysHostAccountPath = (String) validateParameter("JWT_KEYS_HOST_ACCOUNT_PATH", StrJwtKeysHostAccountPath);
      if (!StrJwtKeysProxyServerMode.equals("DIRECT")) StrJwtKeysProxyServerPath = (String) validateParameter("JWT_KEYS_PROXY_SERVER_PATH", StrJwtKeysProxyServerPath);
      if (!StrJwtIdentityMappingMode.equals("DISABLE")) StrJwtIdentityMappingPath = (String) validateParameter("JWT_IDENTITY_MAPPING_PATH", StrJwtIdentityMappingPath);
      StrJwtIdentityAssertion = (String) validateParameter("JWT_IDENTITY_ASSERTION", StrJwtIdentityAssertion);

      // ==================================================================================================================================
      // Genera logging di debug per dump contesto
      // ==================================================================================================================================
      
      Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
      Logger.logMessage(LogLevel.DEBUG,"CONTEXT");
      Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
      Logger.logMessage(LogLevel.DEBUG,"Managed Name .....: "+StrManagedName);
      Logger.logMessage(LogLevel.DEBUG,"Project Name .....: "+StrProjectName);
      Logger.logMessage(LogLevel.DEBUG,"Service Name .....: "+StrServiceName);           
      Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
      Logger.logMessage(LogLevel.DEBUG,"Server Host ......: "+StrServerHost);               
      Logger.logMessage(LogLevel.DEBUG,"Server Addr ......: "+StrServerAddr);               
      Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
      Logger.logMessage(LogLevel.DEBUG,"Client Host ......: "+StrClientHost);               
      Logger.logMessage(LogLevel.DEBUG,"Client Addr ......: "+StrClientAddr);               
      Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
      Logger.logMessage(LogLevel.DEBUG,"Request URL ......: "+StrRequestURL);               
      Logger.logMessage(LogLevel.DEBUG,"Content Type .....: "+StrContentType);               
      Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
      
      // ==================================================================================================================================
      // Verifica che le informazioni sul token ricevuto sono corrette e coerenti con i tipi attivi
      // ==================================================================================================================================

      // Verifica la tipologia del token
      if (!(ObjToken instanceof String)) {
         String StrError = "Unsupported token class";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjToken.getClass().getSimpleName());
         throw new IdentityAssertionException(StrError);
      }

      // Verifica la correttezza del tipo di token
      if (!TokenTypes.ALL_TYPES.contains(StrTokenType)) {        
         String StrError = "Unknown token type";
         Logger.logMessage(LogLevel.ERROR,StrError,StrTokenType);
         throw new IdentityAssertionException(StrError);
      }

      // Se necessario genera logging di debug
      Logger.logMessage(LogLevel.DEBUG,"Selected Token ...: "+StrTokenType);
      
      // ==================================================================================================================================
      // Esegue parsing del token e verifica la modalit� di autenticazione
      // ==================================================================================================================================
      
      // Verifica se il token in ingresso � un BASIC o un JWT
      String StrJwtPayload = (String)ObjToken;
      
      if (StrJwtPayload.startsWith("Basic ")) {
         StrAuthType = TokenTypes.BASIC_AUTH_ID;         
         StrJwtPayload = StrJwtPayload.substring("Basic ".length());         
      } else {
         StrAuthType = TokenTypes.JWT_AUTH_ID;
         if (StrJwtPayload.startsWith("Bearer ")) {
            StrJwtPayload = StrJwtPayload.substring("Bearer ".length());
         }
      }
     
      // Se necessario genera logging di debug
      Logger.logMessage(LogLevel.DEBUG,"Detected Auth ....: "+StrAuthType);

      // Verifica la ammissibilit� dell'autenticazione rilevata rispetto al token selezionato e ai flag di disattivazione
      if ((!StrTokenType.contains(StrAuthType))||
          (StrAuthType.equals(TokenTypes.JWT_AUTH_ID)&&StrJwtAuthStatus.equals("DISABLE"))||
          (StrAuthType.equals(TokenTypes.BASIC_AUTH_ID)&&StrBasicAuthStatus.equals("DISABLE"))) {
         String StrError = "Disabled auth type";
         Logger.logMessage(LogLevel.ERROR,StrError,StrAuthType);
         throw new IdentityAssertionException(StrError);
      } 
        
      // ==================================================================================================================================
      // Gestisce l'autenticazione BASIC
      // ==================================================================================================================================
      
      // Se si tratta di una basic authentication prova ad autenticare l'utenza con le credenziali fornite      
      if (StrAuthType.equals(TokenTypes.BASIC_AUTH_ID)) {
         
         // Se necessario genera logging di debug
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
         Logger.logMessage(LogLevel.DEBUG,"BASIC AUTH");
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");  
                           
         try {          
                        
            // Dedodifica il token basic
            String[] ArrCredential = new String(Base64.decode(StrJwtPayload.getBytes())).split(":",2);            
            Logger.logMessage(LogLevel.DEBUG,"UserName: "+ArrCredential[0]);   
            
            // Prova ad autenticare le credenziali sul realm weblogic
            StrUserName = ObjEmbeddedAuthenticator.authenticate(ArrCredential[0], ArrCredential[1]);
            
            // Se l'utenza non � autenticata genera eccezione
            if ((StrUserName==null)||StrUserName.equals("")) {
               throw new Exception("wrong credentials");
            }
                  
         } catch (Exception ObjException) {
            String StrError = "Basic auth error";
            Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
            throw new IdentityAssertionException(StrError);        
         }      
      }
 
      // ==================================================================================================================================
      // Gestisce l'autenticazione JWT
      // ==================================================================================================================================

      if (StrAuthType.equals(TokenTypes.JWT_AUTH_ID)) {   
         
         // Se necessario genera logging di debug
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
         Logger.logMessage(LogLevel.DEBUG,"JWT AUTH");
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
               
         try {            
            
            // Esegue il parsing del token
            ObjJwtToken.parse(StrJwtPayload);                     
            
            // Acquisisce l'id della chiave di firma del token
            StrJwtKeyID =  ObjJwtToken.getKeyID();        
            
         } catch (Exception ObjException) {
            String StrError = "Token parsing error";
            Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
            throw new IdentityAssertionException(StrError);        
         }
            
         // ==================================================================================================================================
         // Prepara chiave di firma
         // ==================================================================================================================================

         // Dichiara variabili         
         String StrKeyModulus;
         String StrKeyExponent;
         Number IntSystemTimeStamp = System.currentTimeMillis();

         // Verifica se la chiave � gi� in cache         
         HashMap ObjKey = (HashMap) ObjJwtKeysCache.get(StrJwtKeyID);
         
         // Se la chiave � in cache e il suo timestamp non � scaduto esegue altrimenti procede
         if ((ObjKey!=null)&&
             ((IntSystemTimeStamp.longValue()-((Number)ObjKey.get("timestamp")).longValue())<(IntJwtKeysCacheTTL*1000))) {
            
            // Acuisisce parametri chiave dalla cache
            StrKeyModulus = (String) ObjKey.get("modulus");
            StrKeyExponent = (String) ObjKey.get("exponent");            
            
         } else {
                           
            // Acquisisce elenco chiavi di firma via http
            try {
               
               // Se necessario genera logging di debug
               Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
               Logger.logMessage(LogLevel.DEBUG,"KEYS RETRIEVE");
               Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");

               // Imposta livello di padding
               Logger.setPadLength(31);

               // Acquisisce payload delle chiavi pubbliche in formato stringa
               String StrJwtKeys = HttpUtils.fetch(HttpMethod.GET,StrJwtKeysURL,StrJwtKeysFormat.equals("XML")?("text/xml"):("application/json"),
                                                   StrJwtKeysHostAuthMode, StrJwtKeysHostAccountPath,
                                                   StrJwtKeysProxyServerMode, StrJwtKeysProxyServerPath, 
                                                   StrJwtKeysSSLVerify.equals("ENABLE"), 
                                                   IntJwtKeysConnTimeout, IntJwtKeysReadTimeout, Logger);

               // Inizializza
               XmlObject ObjJwtKeys;
                        
                  // Gestisce parsing json o xml
               if (StrJwtKeysFormat.equals("XML")) {

                  // Se necessario genera logging di debug
                  Logger.logProperty(LogLevel.TRACE,"Payload (XML)",StrJwtKeys);

                  // Acquisisce chiavi in formato xml
                  ObjJwtKeys = XmlObject.Factory.parse(StrJwtKeys);

               } else {

                  // Acquisisce payload in formato json
                  JSONObject ObjJSON = new JSONObject(StrJwtKeys);

                  // Se necessario genera logging di debug
                  Logger.logProperty(LogLevel.TRACE,"Payload (JSON)",ObjJSON.toString());

                  // Converte da JSON a XML
                  StrJwtKeys = "<root>"+XML.toString(ObjJSON)+"</root>";
                                                   
                  // Se necessario genera logging di debug
                  Logger.logProperty(LogLevel.TRACE,"Payload (XML)",StrJwtKeys);

                  // Acquisisce chiavi dal formato xml
                  ObjJwtKeys = XmlObject.Factory.parse(StrJwtKeys);
               }

               // Prepara espressioni xpath ed eventuale logging
               String StrJwtKeysModulusParsedXPath = replaceTemplates(StrJwtKeysModulusXPath);
               Logger.logProperty(LogLevel.DEBUG,"Modulus XPath Parsed",StrJwtKeysModulusParsedXPath);

               String StrJwtKeysExponentParsedXPath = replaceTemplates(StrJwtKeysExponentXPath);
               Logger.logProperty(LogLevel.DEBUG,"Exponent XPath Parsed",StrJwtKeysExponentParsedXPath);            

               // Estrapola modulo ed esponente
               StrKeyModulus = XMLUtils.getTextValue(ObjJwtKeys,StrJwtKeysModulusParsedXPath);
               StrKeyExponent = XMLUtils.getTextValue(ObjJwtKeys,StrJwtKeysExponentParsedXPath);
               
               // Se non � stata trovata alcuna chiave genera eccezione
               if (StrKeyModulus.equals("")||StrKeyExponent.equals("")) {
                  throw new Exception("unable to extract key");
               }               
            } catch (Exception ObjException) {
               String StrError = "Keys retrieving error";
               Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
               throw new IdentityAssertionException(StrError);
            }   
                           
            // Pone chiave di firma in cache
            ObjKey = new HashMap();
            ObjKey.put("timestamp",IntSystemTimeStamp);
            ObjKey.put("modulus",StrKeyModulus);
            ObjKey.put("exponent",StrKeyExponent);
            ObjJwtKeysCache.put(StrJwtKeyID,ObjKey);
         }

         // ==================================================================================================================================
         // Verifica la firma del token
         // ==================================================================================================================================

         // Se necessario genera logging di debug
         Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
         Logger.logMessage(LogLevel.DEBUG,"TOKEN VALIDATION");
         Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");

         // Se necessario genera logging di debug
         Logger.logMessage(LogLevel.DEBUG,"Key ID .........: "+StrJwtKeyID);
         Logger.logMessage(LogLevel.TRACE,"Key Modulus ....: "+StrKeyModulus);
         Logger.logMessage(LogLevel.TRACE,"Key Exponent ...: "+StrKeyExponent);            

         try {            
            // Verifica token jwt e genera logging
            Logger.logMessage(LogLevel.DEBUG,"Validation .....: "+ObjJwtToken.verify(StrKeyModulus, StrKeyExponent));            
            
         } catch (Exception ObjException) {
            String StrError = "Token validation error";
            Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
            throw new IdentityAssertionException(StrError);
         }
            
         // ==================================================================================================================================
         // Determina l'identit�
         // ==================================================================================================================================

         // Se necessario genera logging di debug
         Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
         Logger.logMessage(LogLevel.DEBUG,"IDENTITY ASSERTION");
         Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
         
         // Se l'asserzione di identit� non � definita esegue, altrimenti procede
         if (!StrJwtIdentityAssertion.equals("")) {
            
            try {
               // Estrapola l'identit� dallo script di asserzione
               StrIdentity = (String) evaluateScript(StrJwtIdentityAssertion,"String");     
                           
               if (StrIdentity.equals("")) {
                  throw new Exception("evaluate to blank");               
               }
               
            } catch (Exception ObjException) {
               String StrError = "Identity assertion error";
               Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
               throw new IdentityAssertionException(StrError);
            }
         }

         // Se necessario genera logging di debug
         Logger.logMessage(LogLevel.DEBUG,"Token Identity ....: " + StrIdentity);
            
         // ==================================================================================================================================
         // Gestisce l'eventuale identity mapping
         // ==================================================================================================================================
         
         // Se non � richiesto il mapping esegue, altrimenti procede
         if (StrJwtIdentityMappingMode.equals("DISABLE")) {
            
            // Pone lo username pari all'identit� 
            StrUserName = StrIdentity;
            
         } else {            
            try {               
               
               // Se presenti rimpiazza i template nel path della risorsa osb
               StrJwtIdentityMappingPath = replaceTemplates(StrJwtIdentityMappingPath);
               
               // Genera logging di debug
               Logger.logMessage(LogLevel.DEBUG,"Mapping Account ...: "+StrJwtIdentityMappingPath);
               
               // Prova a mappare l'identit� allo username mediante un service account OSB di mapping
               StrUserName = OSBUtils.getMappedUser(StrJwtIdentityMappingPath,StrIdentity);

               // Se il mapping � fallito genera eccezione
               if (StrUserName.equals("")) {
                  throw new Exception("unknown identity");               
               }            
            } catch (Exception ObjException) {
               String StrError = "Identity mapping error";
               Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
               throw new IdentityAssertionException(StrError);
            }
         }
         
         // Se necessario genera logging di debug
         Logger.logMessage(LogLevel.DEBUG,"Realm UserName ....: " + StrUserName);
      }
      
      // ==================================================================================================================================
      // Valuta l'eventuale script di validazione
      // ==================================================================================================================================

      if (!StrValidationAssertion.equals("")) {

         // Se necessario genera logging di debug
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
         Logger.logMessage(LogLevel.DEBUG,"VALIDATION ASSERTION");
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
         
         try { 
            // Se l'espressione di validazione � positiva genera logging altrimenti eccezione
            if ((Boolean) evaluateScript(StrValidationAssertion,"Boolean"))  {
               Logger.logMessage(LogLevel.DEBUG,"Result: TRUE");
            } else {
               Logger.logMessage(LogLevel.DEBUG,"Result: FALSE");
               throw new Exception("evaluate to false");               
            }
         } catch (Exception ObjException) {
            String StrError = "Validation assertion error";
            Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
            throw new IdentityAssertionException(StrError);
         }
      }
      
      // ==================================================================================================================================
      // Se sono presenti proprietè da mandare in debug le gestisce
      // ==================================================================================================================================

      if (ArrDebuggingProperties.length>0) {

         // Se necessario genera logging di debug
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
         Logger.logMessage(LogLevel.DEBUG,"DEBUGGING PROPERTIES");
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
         
         try {
            for (String StrProperty : ArrDebuggingProperties) {
               Logger.logMessage(LogLevel.DEBUG,StrProperty+" => "+replaceTemplates(StrProperty));
            }  
         } catch (Exception ObjException) {
            String StrError = "Debug properties error";
            Logger.logMessage(LogLevel.WARN,StrError,ObjException);
         }
      }
      
      // Genera logging di debug
      Logger.logMessage(LogLevel.DEBUG,"##########################################################################################");

      // Genera logging di info su sintesi autenticazione
      Logger.logMessage(LogLevel.INFO,"Inbound Assertion ("+StrAuthType+") =>"+
                               " Proxy:"+StrServiceName+
                               ", User:"+StrUserName+((!StrIdentity.equals("")&&!StrIdentity.equals(StrUserName))?(" ("+StrIdentity+")"):(""))+
                               ", Client:"+StrClientHost+((!StrClientHost.equals(StrClientAddr))?(" ("+StrClientAddr+")"):(""))+
                               ", Server:"+StrManagedName);

      // Restituisce utente autenticato
      return new CustomIdentityAsserterCallbackHandlerImpl(StrUserName);
   }

   // ##################################################################################################################################
   // Evaluate script
   // ##################################################################################################################################
   private Object evaluateScript(String StrScript, String StrClassName) throws Exception {
            
      // ==================================================================================================================================
      // Esegue lo script e ne verifica la classe di output
      // ==================================================================================================================================
      
      // Esegue lo script fornito
      Object ObjResult = ObjScriptEngine.eval(replaceTemplates(StrScript));
      String StrResultClassName = ObjResult.getClass().getSimpleName();
      
      // Se la tipologia di oggetto restituita non � quella attesa genera eccezione
      if (!StrResultClassName.equals(StrClassName)) {
         throw new Exception("expression must return '"+StrClassName+"' instead of '"+StrResultClassName+"'");
      }

      // Restrituisce l'oggetto risultante
      return ObjResult;
   }

   // ##################################################################################################################################
   // Replace template variables
   // ##################################################################################################################################

   private String replaceTemplates(String StrText) throws Exception {
      
      // ==================================================================================================================================
      // Gestisce variabili di sostituzione
      // ==================================================================================================================================
      
      int IntIndex = 0;
      String StrTemplate;
      String StrVariableName;
      String StrVariableValue;
      String[] ArrVariableTokens;
      
      Pattern ObjPattern = Pattern.compile("(\\$\\{([a-z|\\.|\\*]*)\\})");
      Matcher ObjMatcher = ObjPattern.matcher(StrText);
      
      while (ObjMatcher.find()) {
      
         IntIndex++;
         StrTemplate = ObjMatcher.group(1);
         StrVariableName = ObjMatcher.group(2);
         ArrVariableTokens = StrVariableName.split("\\.");
         StrVariableValue = null;
         
         switch (ArrVariableTokens.length) {
            
            case 1:
               switch (ArrVariableTokens[0]) { 
                  case "identity": StrVariableValue = StrIdentity; break;
                  case "username": StrVariableValue = StrUserName; break;
               }
               break;

            case 2:
               switch (ArrVariableTokens[0]) {                  
                  case "osb" :
                     switch (ArrVariableTokens[1]) {
                        case "server": StrVariableValue = StrServerName; break;
                        case "project": StrVariableValue = StrProjectName; break;
                     }
                     break;
               }
               break;
            
            case 3:
               switch (ArrVariableTokens[0]) {
                  case "osb" :
                     switch (ArrVariableTokens[1]) {
                        case "service": 
                           switch (ArrVariableTokens[2]) {
                              case "name": StrVariableValue = StrServiceName; break;
                              case "path": StrVariableValue = StrServicePath; break;
                           }
                           break;                        
                     }
                     break;                  
                  case "token" :
                     switch (ArrVariableTokens[1]) {
                        case "header": 
                           if (!ArrVariableTokens[2].equals("*")) {
                              StrVariableValue = (String) ObjJwtToken.getHeader().get(ArrVariableTokens[2]);
                           } else if (!ObjJwtToken.isReady()) {
                              StrVariableValue = "''";
                           } else {                 
                              Map<String,Object> ObjMapper = ObjJwtToken.getHeader();   
                              int IntMaxLength = StringUtils.getMaxLength(ObjMapper.keySet().iterator());                                                     
                              
                              StrVariableValue = "\n"+Logger.formatMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------\n");                              
                              for (Map.Entry<String,Object> ObjEntry : ObjMapper.entrySet()) {
                                 Object ObjValue = ObjEntry.getValue();
                                 String StrQuotes = ((ObjValue instanceof String)?("\""):(""));
                                 StrVariableValue+= Logger.formatMessage(LogLevel.DEBUG,StringUtils.padRight(ObjEntry.getKey()+" ",IntMaxLength+4,".")+": "+StrQuotes+ObjValue+StrQuotes+"\n");
                              }                              
                              StrVariableValue+= Logger.formatMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
                              }
                           break;                     
                        case "payload":
                           if (!ArrVariableTokens[2].equals("*")) {
                              StrVariableValue = (String) ObjJwtToken.getPayload().get(ArrVariableTokens[2]);
                           } else if (!ObjJwtToken.isReady()) {
                              StrVariableValue = "''";
                           } else {     
                              Map<String,Object> ObjMapper = ObjJwtToken.getPayload();   
                              int IntMaxLength = StringUtils.getMaxLength(ObjMapper.keySet().iterator());                                                     
                              
                              StrVariableValue = "\n"+Logger.formatMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------\n");                              
                              for (Map.Entry<String,Object> ObjEntry : ObjMapper.entrySet()) {
                                 Object ObjValue = ObjEntry.getValue();
                                 String StrQuotes = ((ObjValue instanceof String)?("\""):(""));
                                 StrVariableValue+= Logger.formatMessage(LogLevel.DEBUG,StringUtils.padRight(ObjEntry.getKey()+" ",IntMaxLength+4,".")+": "+StrQuotes+ObjValue+StrQuotes+"\n");
                              }                              
                              StrVariableValue+= Logger.formatMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
                           }
                           break;
                     }
                     break;
                  case "http" :
                     switch (ArrVariableTokens[1]) {
                        case "client": 
                           switch (ArrVariableTokens[2]) {
                              case "host": StrVariableValue = StrClientHost; break;
                              case "addr": StrVariableValue = StrClientAddr; break;
                           }
                           break;
                        case "server": 
                           switch (ArrVariableTokens[2]) {
                              case "host": StrVariableValue = StrServerHost; break;
                              case "addr": StrVariableValue = StrServerAddr; break;
                              case "name": StrVariableValue = StrServerName; break;
                              case "port": StrVariableValue = StrServerPort; break;
                           }
                           break;
                        case "content": 
                           switch (ArrVariableTokens[2]) {
                              case "type": StrVariableValue = StrContentType; break;
                              case "body": StrVariableValue = IOUtils.toString(ObjRequest.getReader()); break;
                              case "length": StrVariableValue = String.valueOf(ObjRequest.getContentLength()); break;
                           }
                           break;
                        case "request": 
                           switch (ArrVariableTokens[2]) {
                              case "url": StrVariableValue = StrRequestURL; break;
                              case "proto": StrVariableValue = ObjRequest.getProtocol(); break;
                              case "scheme": StrVariableValue = ObjRequest.getScheme(); break;
                           }
                           break;
                        
                        case "header": 
                           if (!ArrVariableTokens[2].equals("*")) {
                              StrVariableValue = (String) ObjRequest.getHeader(ArrVariableTokens[2]); 
                           } else {
                              String StrHeaderName;
                              String StrHeaderValue;   
                              
                              List<String> ArrExclusions = Arrays.asList("Authorization");
                              Enumeration<String> ObjEnumerator = ObjRequest.getHeaderNames();
                              Iterator<String> ObjIterator = Collections.list(ObjEnumerator).iterator();                                                           
                              int IntMaxLength = StringUtils.getMaxLength(ObjIterator,ArrExclusions);
                              ObjEnumerator = ObjRequest.getHeaderNames();
                              
                              StrVariableValue = "\n"+Logger.formatMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------\n");
                              while (ObjEnumerator.hasMoreElements()) {
                                 StrHeaderName = ObjEnumerator.nextElement();
                                 if (!ArrExclusions.contains(StrHeaderName)) {
                                    StrHeaderValue = ObjRequest.getHeader(StrHeaderName);
                                    StrVariableValue+= Logger.formatMessage(LogLevel.DEBUG,StringUtils.padRight(StrHeaderName+" ",IntMaxLength+4,".")+": "+StrHeaderValue+"\n");
                                 }
                              }
                              StrVariableValue+= Logger.formatMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
                           }
                           break;
                     }
                     break;
               } 
               break;  
         }
         
         if (StrVariableValue==null) {
            throw new Exception("invalid template variable '"+StrVariableName+"'");
         }
         
         // Esegue sostituzione della variabile template         
         StrText = StrText.replace(StrTemplate,StrVariableValue);
      }
      
      // Restituisce stringa con i template sostituiti
      return StrText;
   }
    
   // ==================================================================================================================================
   // Verifica se un parametro obbligatorio e valorizzato
   // ==================================================================================================================================
   private Object validateParameter(String StrParameterName,Object ObjParameterValue) throws IdentityAssertionException {

      // Prepara nome della classe del parametro
      String StrClassName = (ObjParameterValue==null)?("null"):(ObjParameterValue.getClass().getSimpleName());

      // Se si tratta di un parametro stringa esegue trim
      if (StrClassName.equals("String")) {
         ObjParameterValue = ((String)ObjParameterValue).trim();
      }
      
      // Se necessario genera trace
      Logger.logMessage(LogLevel.TRACE,
                 "Checking Parameter "+StrParameterName+": "+
                 ((ObjParameterValue==null)?("is null"):
                  ("class '"+StrClassName+"' "+
                   ((!StrClassName.equals("String"))?(""):
                    (ObjParameterValue.equals("")?("is empty"):(""))))));
      
      // Verifica se il parametro
      if ((ObjParameterValue==null)||
          ((StrClassName.equals("String"))&&((String)ObjParameterValue).equals(""))) {
         String StrError = "Configuration error";
         Logger.logMessage(LogLevel.ERROR,StrError,"mandatory parameter missing '"+StrParameterName+"'");
         throw new IdentityAssertionException(StrError);
      }
      
      // Restituisce valore eventualmente corretto con trim
      return ObjParameterValue;
   }   
}
