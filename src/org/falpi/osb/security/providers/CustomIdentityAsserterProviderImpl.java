package org.falpi.osb.security.providers;

// ##################################################################################################################################
// Referenze
// ##################################################################################################################################

import java.util.Map;
import java.util.List;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Properties;
import java.util.Enumeration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Iterator;
import java.util.Collections;
import java.security.AccessController;
import javax.script.ScriptEngine;
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
import org.falpi.utils.HttpUtils.*;
import org.falpi.utils.SecurityUtils;
import org.falpi.utils.StringUtils;
import org.falpi.utils.WLSUtils;
import org.falpi.utils.jwt.JWTToken;
import org.falpi.utils.jwt.JWTCache;
import org.falpi.utils.jwt.JWTCache.*;
import org.falpi.utils.logging.LogLevel;
import org.falpi.utils.logging.LogManager;

public final class CustomIdentityAsserterProviderImpl implements AuthenticationProviderV2, IdentityAsserterV2 {
   
   // ##################################################################################################################################
   // Sottoclassi 
   // ##################################################################################################################################

   // ==================================================================================================================================
   // Helper per functional programming
   // ==================================================================================================================================  
   private interface TemplateFunction<T> { String apply(T t) throws Exception; }   
   private interface RequestTemplateFunction extends TemplateFunction<HttpServletRequest> {};

   // ==================================================================================================================================
   // Helper per configurazione di runtime
   // ==================================================================================================================================  
   private static class RuntimeContext extends HashMap<String,Object> {
            
      public String getString(String StrKey) {
         return (String) get(StrKey);
      }
      
      public Integer getInteger(String StrKey) {
         return (Integer) get(StrKey);
      }      
   }
   
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
   // Variabili statiche
   // ==================================================================================================================================

   private static long IntThreadCount = 0;

   // ==================================================================================================================================
   // Variabili locali al thread
   // ==================================================================================================================================

   // Istanzia un logger per ciascun thread
   private static final ThreadLocal<LogManager> ObjThreadLogger = new ThreadLocal<LogManager>() {
      @Override protected LogManager initialValue() { return new LogManager("CIA"); }
   };

   // Istanzia un context per ciascun thread
   private static final ThreadLocal<RuntimeContext> ObjThreadContext = new ThreadLocal<RuntimeContext>() {
      @Override protected RuntimeContext initialValue() { return new RuntimeContext(); }
   };
      
   // ==================================================================================================================================
   // Variabili di istanza
   // ==================================================================================================================================
     
   // Parametri weblogic
   private String StrRealmName;
   private String StrDomainName;
   private String StrManagedName;
   
   // Gestione del provider jwt
   private JWTToken ObjJwtProvider;
   private JWTCache ObjJwtKeysCache;
           
   // Altre variabili di supporto
   private ScriptEngine ObjScriptEngine;   
   private AuthenticatedSubject ObjKernelId;
   private EmbeddedLDAPAtnDelegate ObjEmbeddedAuthenticator;

   // Gestione del mbean
   private String StrProviderDescr;   
   private CustomIdentityAsserterMBean ObjProviderMBean;

   // ##################################################################################################################################
   // Implementa interfacce di inbound security (AuthenticationProviderV2, IdentityAsserterV2)
   // ##################################################################################################################################

   @Override
   public void initialize(ProviderMBean ObjMBean, SecurityServices ObjSecurityServices) {

      // ==================================================================================================================================
      // Inizializzazioni preliminari
      // ==================================================================================================================================
      
      // Inizializza nome del thread con la rappresentazione esadecimale del contatore di esecuzione
      setThreadName();
         
      // Referenzia il logger del thread
      LogManager Logger = getLogger();

      // Inizializza variabili mbean
      ObjProviderMBean = (CustomIdentityAsserterMBean) ObjMBean;
      StrProviderDescr = ObjMBean.getDescription() + "n" + ObjMBean.getVersion();
               
      // ==================================================================================================================================
      // Genera logging 
      // ==================================================================================================================================
      Logger.logMessage(LogLevel.INFO,"##########################################################################################");
      Logger.logMessage(LogLevel.INFO,"INITIALIZE");
      Logger.logMessage(LogLevel.INFO,"##########################################################################################");     

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
      // Inizializza provider jwt 
      // ==================================================================================================================================
      try {
         // Se il target è weblogic 12.1.3 (java=7) la libreria originale nimbus può essere integrata perchè non è presente a sistema
         // Se il target è weblogic 12.2.1 (7<java<17) poichè integra nimbus di una versione incompatibile occorre integrare una versione shaded 
         // Se il target è weblogic 14.1.2 (java>=17) poichè integra nimbus di una versione compatibile la si può usare diretamente
         ObjJwtProvider = JWTToken.create((JavaUtils.getJavaVersion()>7)&&(JavaUtils.getJavaVersion()<17)?("NimbusShaded"):("Nimbus"));
         
         // Inizializza cache delle chiavi jwt
         ObjJwtKeysCache = new JWTCache();
         
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
      // Prepara contesto weblogic
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
      Logger.logMessage(LogLevel.INFO,"JWT Provider .........: " + ObjJwtProvider.getClass().getCanonicalName());  
      Logger.logMessage(LogLevel.INFO,"Kerberos Config ......: " + SecurityUtils.getKerberosConfigPath());
      Logger.logMessage(LogLevel.INFO,"Scripting Engine .....: " + ObjScriptEngine.getFactory().getEngineName()+" ("+ObjScriptEngine.getFactory().getEngineVersion()+")");  
      Logger.logMessage(LogLevel.INFO,"Scripting Language ...: " + ObjScriptEngine.getFactory().getLanguageName()+" ("+ObjScriptEngine.getFactory().getLanguageVersion()+")");  
      Logger.logMessage(LogLevel.INFO,"##########################################################################################");      
   }

   @Override
   public void shutdown() {
      
      // Inizializza nome del thread con la rappresentazione esadecimale del contatore di esecuzione
      setThreadName();
         
      // Referenzia il logger del thread
      LogManager Logger = getLogger();

      // Genera logging      
      Logger.logMessage(LogLevel.INFO,"##########################################################################################");      
      Logger.logMessage(LogLevel.INFO,"SHUTDOWN");
      Logger.logMessage(LogLevel.INFO,"##########################################################################################");      
   }

   @Override
   public String getDescription() {
      return StrProviderDescr;
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
   public CallbackHandler assertIdentity(String StrTokenType, Object ObjToken, ContextHandler ObjRequestContext) throws IdentityAssertionException {
      
      // Esegue in modo sincrono o asincrono in base a configurazione
      if (ObjProviderMBean.getRUNNING_MODE().equals("SERIAL")) {
         return assertIdentitySynchImpl(StrTokenType,ObjToken,ObjRequestContext);
      } else {      
         return assertIdentityAsynchImpl(StrTokenType,ObjToken,ObjRequestContext);
      }
   }

   // Implementazione sincrona (serializza le richieste consentendo solo un thread alla volta)
   private synchronized CallbackHandler assertIdentitySynchImpl(String StrTokenType, Object ObjToken, ContextHandler ObjRequestContext) throws IdentityAssertionException {
      return assertIdentityAsynchImpl(StrTokenType,ObjToken,ObjRequestContext);
   }                                     

   // Implementazione asincrona (consente esecuzione parallela le richieste)
   private CallbackHandler assertIdentityAsynchImpl(String StrTokenType, Object ObjToken, ContextHandler ObjRequestContext) throws IdentityAssertionException {

      // ==================================================================================================================================
      // Inizializzazioni preliminari
      // ==================================================================================================================================

      // Inizializza nome del thread con la rappresentazione esadecimale del contatore di esecuzione
      setThreadName();
         
      // Referenzia il logger del thread
      LogManager Logger = getLogger();

      // Referenzia il context del thread
      RuntimeContext ObjRuntimeContext = getContext();

      // ==================================================================================================================================
      // Acquisisce configurazione
      // ==================================================================================================================================
                  
      String StrRunningMode = ObjProviderMBean.getRUNNING_MODE();
      
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
      Properties ObjCustomRequestHeaders = ObjProviderMBean.getCUSTOM_REQUEST_HEADERS();
      Properties ObjCustomResponseHeaders = ObjProviderMBean.getCUSTOM_RESPONSE_HEADERS();
      String[] ArrDebuggingAssertion = ObjProviderMBean.getDEBUGGING_ASSERTION();
      String[] ArrDebuggingProperties = ObjProviderMBean.getDEBUGGING_PROPERTIES();
      
      // Comprime gli array multiriga
      String StrJwtIdentityAssertion = StringUtils.join(ArrJwtIdentityAssertion,System.lineSeparator());
      String StrValidationAssertion = StringUtils.join(ArrValidationAssertion,System.lineSeparator());
      String StrDebuggingAssertion = StringUtils.join(ArrDebuggingAssertion,System.lineSeparator());
      String StrDebuggingProperties = StringUtils.join(ArrDebuggingProperties,",");
                              
      // ==================================================================================================================================
      // Prepara contesto di runtime
      // ==================================================================================================================================

      // ----------------------------------------------------------------------------------------------------------------------------------
      // Acquisisce contesto weblogic
      // ----------------------------------------------------------------------------------------------------------------------------------
      ServiceInfo ObjService = (ServiceInfo) ObjRequestContext.getValue("com.bea.contextelement.alsb.service-info");
      //TransportEndPoint ObjEndpoint = (TransportEndPoint) ObjRequestContext.getValue("com.bea.contextelement.alsb.transport.endpoint");
      HttpServletRequest ObjRequest = (HttpServletRequest) ObjRequestContext.getValue("com.bea.contextelement.alsb.transport.http.http-request");
      HttpServletResponse ObjResponse = (HttpServletResponse) ObjRequestContext.getValue("com.bea.contextelement.alsb.transport.http.http-response");

      // ----------------------------------------------------------------------------------------------------------------------------------
      // Acquisisce contesto weblogic
      // ----------------------------------------------------------------------------------------------------------------------------------

      ObjRuntimeContext.put("token",null); 
      ObjRuntimeContext.put("request",ObjRequest);      
      ObjRuntimeContext.put("scriptengine",ObjScriptEngine); 
      
      // ----------------------------------------------------------------------------------------------------------------------------------
      // Prepara contesto base                
      // ----------------------------------------------------------------------------------------------------------------------------------
      String StrAuthType = "";
      String StrIdentity = "";
      String StrUserName = ""; 
      
      ObjRuntimeContext.put("authtype","");
      ObjRuntimeContext.put("identity","");
      ObjRuntimeContext.put("username","");            
      
      ObjRuntimeContext.put("thread.counter",Thread.currentThread().getName());   
      ObjRuntimeContext.put("thread.identifier",Thread.currentThread().getId());   
      
      // ----------------------------------------------------------------------------------------------------------------------------------
      // Prepara contesto osb
      // ----------------------------------------------------------------------------------------------------------------------------------
      String StrProjectName = ObjService.getRef().getProjectName();
      String StrServiceName = ObjService.getRef().getLocalName();
      String StrServicePath = ObjService.getRef().getFullName();
      
      ObjRuntimeContext.put("osb.server",StrManagedName);      
      ObjRuntimeContext.put("osb.project",StrProjectName);  
      ObjRuntimeContext.put("osb.service.name",StrServiceName);      
      ObjRuntimeContext.put("osb.service.path",StrServicePath);
      
      // ----------------------------------------------------------------------------------------------------------------------------------
      // Prepara contesto http
      // ----------------------------------------------------------------------------------------------------------------------------------
      String StrClientHost = ObjRequest.getRemoteHost(); 
      String StrClientAddr = ObjRequest.getRemoteAddr();
      String StrServerHost = ObjRequest.getLocalName();
      String StrServerAddr = ObjRequest.getLocalAddr();
      String StrRequestURL = ObjRequest.getRequestURL().toString();
      String StrContentType = ObjRequest.getContentType();

      ObjRuntimeContext.put("http.request.url",StrRequestURL);      
      ObjRuntimeContext.put("http.request.proto",ObjRequest.getProtocol());      
      ObjRuntimeContext.put("http.request.scheme",ObjRequest.getScheme());      
      
      ObjRuntimeContext.put("http.client.host",StrClientHost);      
      ObjRuntimeContext.put("http.client.addr",StrClientAddr);  
      
      ObjRuntimeContext.put("http.server.host",StrServerHost);      
      ObjRuntimeContext.put("http.server.addr",StrServerAddr);      
      ObjRuntimeContext.put("http.server.name",ObjRequest.getServerName());      
      ObjRuntimeContext.put("http.server.port",String.valueOf(ObjRequest.getServerPort()));      

      ObjRuntimeContext.put("http.content.type",StrContentType);      
      ObjRuntimeContext.put("http.content.length",String.valueOf(ObjRequest.getContentLength()));      
      ObjRuntimeContext.put("http.content.body",new RequestTemplateFunction() {
         public String apply(HttpServletRequest ObjRequest) throws Exception {
            return IOUtils.toString(ObjRequest.getReader());
         }
      });                                                                                        
      
      // ==================================================================================================================================
      // Imposta livelli di logging (eventuali errori sull'asserzione di debug sono silenziati per non pregiudicare l'autenticazione)
      // ==================================================================================================================================   
      
      // Prepara livelli di logging di default
      Logger.setLogLevel(StrLoggingLevel);
      Logger.setLogLines(IntLoggingLines);

      // Se ecessario verifica del filtro per i messaggi di log di livello più basso
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
      Logger.logMessage(LogLevel.DEBUG,"RUNNING_MODE .................: " + StrRunningMode);
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
      Logger.logMessage(LogLevel.DEBUG,"JWT_IDENTITY_ASSERTION .......: " + StrJwtIdentityAssertion.replaceAll("\n"," "));
      Logger.logMessage(LogLevel.DEBUG,"VALIDATION_ASSERTION .........: " + StrValidationAssertion.replaceAll("\n"," "));
      Logger.logMessage(LogLevel.DEBUG,"CUSTOM_REQUEST_HEADERS .......: " + StringUtils.join(ObjCustomRequestHeaders,","));
      Logger.logMessage(LogLevel.DEBUG,"CUSTOM_RESPONSE_HEADERS ......: " + StringUtils.join(ObjCustomResponseHeaders,","));
      Logger.logMessage(LogLevel.DEBUG,"DEBUGGING_ASSERTION ..........: " + StrDebuggingAssertion.replaceAll("\n"," "));
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
      // Esegue parsing del token e verifica la modalità di autenticazione
      // ==================================================================================================================================
      
      // Verifica se il token in ingresso è un BASIC o un JWT
      String StrToken = (String)ObjToken;
      
      if (StrToken.startsWith("Basic ")) {
         StrAuthType = TokenTypes.BASIC_AUTH_ID;         
         StrToken = StrToken.substring("Basic ".length());         
      } else {
         StrAuthType = TokenTypes.JWT_AUTH_ID;
         if (StrToken.startsWith("Bearer ")) {
            StrToken = StrToken.substring("Bearer ".length());
         }
      }
     
      // Aggiorna il contesto di runtime
      ObjRuntimeContext.put("authtype",StrAuthType);
     
      // Se necessario genera logging di debug
      Logger.logMessage(LogLevel.DEBUG,"Detected Auth ....: "+StrAuthType);

      // Verifica la ammissibilità dell'autenticazione rilevata rispetto al token selezionato e ai flag di disattivazione
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
            String[] ArrCredential = new String(Base64.decode(StrToken.getBytes())).split(":",2);            
            Logger.logMessage(LogLevel.DEBUG,"UserName: "+ArrCredential[0]);   
            
            // Prova ad autenticare le credenziali sul realm weblogic
            StrUserName = ObjEmbeddedAuthenticator.authenticate(ArrCredential[0], ArrCredential[1]);

            // Aggiorna il contesto di runtime
            ObjRuntimeContext.put("username",StrUserName);
            
            // Se l'utenza non à autenticata genera eccezione
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
                           
         // ==================================================================================================================================
         // Inizializza token provider 
         // ==================================================================================================================================
         JWTToken ObjJwtToken = null;         
         try {

            // Crea nuova istanza del token
            ObjJwtToken = ObjJwtProvider.createInstance();   
            
            // Aggiorna il contesto di runtime
            ObjRuntimeContext.put("token",ObjJwtToken);            

         } catch (Exception ObjException) {
            String StrError = "Token provider error";
            Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
            System.exit(0);
         } 
           
         // ==================================================================================================================================
         // Inizializza token
         // ==================================================================================================================================
         String StrJwtKeyID;
         try {            
            
            // Esegue il parsing del token
            ObjJwtToken.parse(StrToken);                     
            
            // Acquisisce l'id della chiave di firma del token
            StrJwtKeyID =  ObjJwtToken.getKeyID();        
            
         } catch (Exception ObjException) {
            String StrError = "Token parsing error";
            Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
            throw new IdentityAssertionException(StrError);        
         }
            
         // ==================================================================================================================================
         // Prepara chiave per la verifica della firma
         // ==================================================================================================================================

         // Dichiara variabili         
         String StrKeyModulus;
         String StrKeyExponent;

         // Verifica se la chiave è già in cache e non è scaduta         
         JWTCacheEntry ObjKey = ObjJwtKeysCache.validKey(StrJwtKeyID,IntJwtKeysCacheTTL);
         
         // Se la chiave è in cache e il suo timestamp non è scaduto esegue altrimenti procede
         if (ObjKey!=null) {
            
            // Acuisisce parametri chiave dalla cache
            StrKeyModulus = ObjKey.modulus;
            StrKeyExponent = ObjKey.exponent;            
            
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
               
               // Se non è stata trovata alcuna chiave genera eccezione
               if (StrKeyModulus.equals("")||StrKeyExponent.equals("")) {
                  throw new Exception("unable to extract key");
               }               
            } catch (Exception ObjException) {
               String StrError = "Keys retrieving error";
               Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
               throw new IdentityAssertionException(StrError);
            }   
                           
            // Salva la chiave in cache
            ObjJwtKeysCache.putKey(StrJwtKeyID,StrKeyModulus,StrKeyExponent);
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
         // Determina l'identità
         // ==================================================================================================================================

         // Se necessario genera logging di debug
         Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
         Logger.logMessage(LogLevel.DEBUG,"IDENTITY ASSERTION");
         Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
         
         // Se l'asserzione di identità non è definita esegue, altrimenti procede
         if (!StrJwtIdentityAssertion.equals("")) {
            
            try {
               // Estrapola l'identità dallo script di asserzione
               StrIdentity = (String) evaluateScript(StrJwtIdentityAssertion,"String");     

               // Aggiorna il contesto di runtime
               ObjRuntimeContext.put("identity",StrIdentity);
                           
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
         
         // Se non è richiesto il mapping esegue, altrimenti procede
         if (StrJwtIdentityMappingMode.equals("DISABLE")) {
            
            // Pone lo username pari all'identità 
            StrUserName = StrIdentity;

            // Aggiorna il contesto di runtime
            ObjRuntimeContext.put("username",StrIdentity);
            
         } else {            
            try {               
               
               // Se presenti rimpiazza i template nel path della risorsa osb
               StrJwtIdentityMappingPath = replaceTemplates(StrJwtIdentityMappingPath);
               
               // Genera logging di debug
               Logger.logMessage(LogLevel.DEBUG,"Mapping Account ...: "+StrJwtIdentityMappingPath);
               
               // Prova a mappare l'identità allo username mediante un service account OSB di mapping
               StrUserName = OSBUtils.getMappedUser(StrJwtIdentityMappingPath,StrIdentity);

               // Aggiorna il contesto di runtime
               ObjRuntimeContext.put("username",StrUserName);

               // Se il mapping è fallito genera eccezione
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
            // Se l'espressione di validazione è positiva genera logging altrimenti eccezione
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
      // Se sono presenti custom headers li gestisce
      // ==================================================================================================================================
                              
      if ((ObjCustomRequestHeaders!=null)&&(ObjCustomResponseHeaders!=null)) {

         // Se necessario genera logging di debug
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
         Logger.logMessage(LogLevel.DEBUG,"CUSTOM HEADERS");
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
                  
         try {
            for (String StrKey : ObjCustomRequestHeaders.stringPropertyNames()) {
               String StrHeaderName = StrKey;
               String StrHeaderValue = replaceTemplates(ObjCustomRequestHeaders.getProperty(StrKey));
               
               if (StrHeaderValue!="") {
                  Logger.logMessage(LogLevel.DEBUG,"Request: "+StrHeaderName+"="+StrHeaderValue);
                  WLSUtils.addHeader(ObjRequest,StrHeaderName,StrHeaderValue);
               }
            }
         } catch (Exception ObjException) {
            String StrError = "Custom request headers error";
            Logger.logMessage(LogLevel.WARN,StrError,ObjException);
         }
         
         try {
            for (String StrKey : ObjCustomResponseHeaders.stringPropertyNames()) {
               String StrHeaderName = StrKey;
               String StrHeaderValue = replaceTemplates(ObjCustomResponseHeaders.getProperty(StrKey));
               
               if (StrHeaderValue!="") {
                  Logger.logMessage(LogLevel.DEBUG,"Response: "+StrHeaderName+"="+StrHeaderValue);
                  ObjResponse.addHeader(StrHeaderName,StrHeaderValue);
               }
            }
         } catch (Exception ObjException) {
            String StrError = "Custom response headers error";
            Logger.logMessage(LogLevel.WARN,StrError,ObjException);
         }         
      }
      
      // ==================================================================================================================================
      // Se sono presenti proprietà da mandare in debug le gestisce
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
      Logger.logMessage(LogLevel.INFO,"Inbound ("+StrAuthType+") =>"+
                               " Proxy: "+StrServiceName+
                               ", User: "+StrUserName+((!StrIdentity.equals("")&&!StrIdentity.equals(StrUserName))?(" ("+StrIdentity+")"):(""))+
                               ", Client: "+StrClientHost+((!StrClientHost.equals(StrClientAddr))?(" ("+StrClientAddr+")"):("")));

      // Restituisce utente autenticato
      return new CustomIdentityAsserterCallbackHandlerImpl(StrUserName);
   }

   // ##################################################################################################################################
   // Metodi privati di supporto
   // ##################################################################################################################################
   
   // ==================================================================================================================================
   // Evaluate script
   // ==================================================================================================================================
   private static Object evaluateScript(String StrScript, String StrClassName) throws Exception {

      // Referenzia il context del thread
      RuntimeContext ObjRuntimeContext = getContext();
         
      // ==================================================================================================================================
      // Esegue lo script e ne verifica la classe di output
      // ==================================================================================================================================
      
      // Esegue lo script fornito
      Object ObjResult = ((ScriptEngine)ObjRuntimeContext.get("scriptengine")).eval(replaceTemplates(StrScript));
      String StrResultClassName = ObjResult.getClass().getSimpleName();
      
      // Se la tipologia di oggetto restituita non è quella attesa genera eccezione
      if (!StrResultClassName.equals(StrClassName)) {
         throw new Exception("expression must return '"+StrClassName+"' instead of '"+StrResultClassName+"'");
      }

      // Restrituisce l'oggetto risultante
      return ObjResult;
   }

   // ==================================================================================================================================
   // Replace template variables
   // ==================================================================================================================================
   private static String replaceTemplates(String StrText) throws Exception {
         
      // Referenzia il logger del thread
      LogManager Logger = getLogger();

      // Referenzia il context del thread
      RuntimeContext ObjRuntimeContext = getContext();
      
      // ==================================================================================================================================
      // Acquisisce variabili di contesto di tipo oggetto
      // ==================================================================================================================================
      JWTToken ObjJwtToken = (JWTToken) ObjRuntimeContext.get("token");
      HttpServletRequest ObjRequest = (HttpServletRequest) ObjRuntimeContext.get("http.request");
      
      // ==================================================================================================================================
      // Gestisce variabili di sostituzione
      // ==================================================================================================================================     
      String StrTemplate;
      String StrVariableName;
      String StrVariableValue;
      Object ObjVariableValue;
      String[] ArrVariableTokens;
      
      Pattern ObjPattern = Pattern.compile("(\\$\\{([a-z|\\.|\\*]*)\\})");
      Matcher ObjMatcher = ObjPattern.matcher(StrText);
      
      while (ObjMatcher.find()) {
      
         StrTemplate = ObjMatcher.group(1);
         StrVariableName = ObjMatcher.group(2);
         ArrVariableTokens = StrVariableName.split("\\.");
         StrVariableValue = null;

         // ----------------------------------------------------------------------------------------------------------------------------------
         // Gestisce variabili speciali
         // ----------------------------------------------------------------------------------------------------------------------------------         
         switch (ArrVariableTokens.length) {
                        
            case 3:
               switch (ArrVariableTokens[0]) {
                  case "http" :
                     switch (ArrVariableTokens[1]) {
                        case "header": 
                           if (!ArrVariableTokens[2].equals("*")) {
                              StrVariableValue = ObjRequest.getHeader(ArrVariableTokens[2]); 
                           } else {
                              String StrHeaderName;
                              String StrHeaderValue;   
                              
                              List<String> ArrExclusions = Arrays.asList("Authorization");
                              int IntMaxLength = StringUtils.getMaxLength(ObjRequest.getHeaderNames(),ArrExclusions);
                              Enumeration<String> ObjEnumerator = ObjRequest.getHeaderNames();
                              
                              StrVariableValue = "\n"+Logger.formatMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------\n");
                              while (ObjEnumerator.hasMoreElements()) {
                                 StrHeaderName = ObjEnumerator.nextElement();
                                 if (!ArrExclusions.contains(StrHeaderName)) {
                                    StrHeaderValue = ObjRequest.getHeader(StrHeaderName);
                                    StrVariableValue+= Logger.formatProperty(LogLevel.DEBUG,StrHeaderName,StrHeaderValue,IntMaxLength+4)+"\n";
                                 }
                              }
                              StrVariableValue+= Logger.formatMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
                           }
                           break;
                     }
                     break;
                  case "token" : 
                     if (ObjJwtToken!=null) {
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
                                    StrVariableValue+= Logger.formatProperty(LogLevel.DEBUG,ObjEntry.getKey(),StrQuotes+ObjValue+StrQuotes,IntMaxLength+4)+"\n";
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
                                    StrVariableValue+= Logger.formatProperty(LogLevel.DEBUG,ObjEntry.getKey(),StrQuotes+ObjValue+StrQuotes,IntMaxLength+4)+"\n";
                                 }                              
                                 StrVariableValue+= Logger.formatMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
                              }
                              break;
                        }
                        break;
                     }
               } 
               break;                 
         }

         // ----------------------------------------------------------------------------------------------------------------------------------
         // Se la variabile non è stata ancora identificata esegue
         // ----------------------------------------------------------------------------------------------------------------------------------
         if (StrVariableValue==null) {
            
            // Cerca la variabile nel contesto di runtime
            ObjVariableValue = ObjRuntimeContext.get(StrVariableName);
         
            // Se si tratta di una funzione la esegue, altrimeni se è una stringa la converte, altrimenti genera eccezione
            if (ObjVariableValue instanceof TemplateFunction) {
               StrVariableValue = ((RequestTemplateFunction) ObjVariableValue).apply(ObjRequest);
            } else if (ObjVariableValue instanceof String) {
               StrVariableValue = (String) ObjVariableValue;
            } else {
               throw new Exception("invalid template variable '"+StrVariableName+"'");               
            }
         }
         
         // ----------------------------------------------------------------------------------------------------------------------------------
         // Esegue sostituzione della variabile template         
         // ----------------------------------------------------------------------------------------------------------------------------------
         StrText = StrText.replace(StrTemplate,StrVariableValue);
      }
      
      // Restituisce stringa con i template sostituiti
      return StrText;
   }
    
   // ==================================================================================================================================
   // Verifica se un parametro obbligatorio e valorizzato
   // ==================================================================================================================================
   private static Object validateParameter(String StrParameterName,Object ObjParameterValue) throws IdentityAssertionException {
         
      // Referenzia il logger del thread   
      LogManager Logger = getLogger();

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
   
   // ==================================================================================================================================
   // Inizializza nome del thread con la rappresentazione esadecimale del contatore di esecuzione
   // ==================================================================================================================================
   private static synchronized void setThreadName()  {
      Thread.currentThread().setName(StringUtils.padLeft(String.valueOf(IntThreadCount++),10,"0"));
   }
   
   // ==================================================================================================================================
   // Acquisisce riferimento a logger di thread
   // ==================================================================================================================================   
   private static LogManager getLogger() {
      return CustomIdentityAsserterProviderImpl.ObjThreadLogger.get();   
   }
   
   // ==================================================================================================================================
   // Acquisisce riferimento a context di thread
   // ==================================================================================================================================   
   private static RuntimeContext getContext() {
      return CustomIdentityAsserterProviderImpl.ObjThreadContext.get();   
   }
}
