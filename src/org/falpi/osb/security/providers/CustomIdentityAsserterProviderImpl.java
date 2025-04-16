// ##################################################################################################################################
// VERSIONING
// ##################################################################################################################################
// $Revision: 1712 $
// $Date: 2025-04-16 19:02:55 +0200 (Wed, 16 Apr 2025) $
// ##################################################################################################################################

package org.falpi.osb.security.providers;

// ##################################################################################################################################
// Referenze
// ##################################################################################################################################

import java.util.Date;
import java.util.List;
import java.util.Arrays;
import java.util.Properties;
import java.text.SimpleDateFormat;

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
import weblogic.management.security.ProviderMBean;

import com.bea.wli.sb.services.ServiceInfo;
import com.bea.wli.sb.transports.TransportEndPoint;

import java.util.Iterator;

import org.apache.xmlbeans.XmlObject;

import org.json.XML;
import org.json.JSONObject;

import org.falpi.*;
import org.falpi.utils.*;
import org.falpi.utils.WLSUtils.*;
import org.falpi.utils.HttpUtils.*;
import org.falpi.utils.StringUtils.*;
import org.falpi.utils.jwt.*;
import org.falpi.utils.jwt.JWTCache.*;
import org.falpi.utils.jwt.JWTProvider;
import org.falpi.utils.logging.*;

public final class CustomIdentityAsserterProviderImpl implements AuthenticationProviderV2, IdentityAsserterV2 {
   
   // ##################################################################################################################################
   // Costanti 
   // ##################################################################################################################################
   
   // Identificativi dei parametri di configurazione
   private static final String LOGGING_LEVEL              = "LOGGING_LEVEL";
   private static final String LOGGING_LINES              = "LOGGING_LINES";
   private static final String LOGGING_INFO               = "LOGGING_INFO";
   private static final String THREADING_MODE             = "THREADING_MODE";
   private static final String BASIC_AUTH                 = "BASIC_AUTH";
   private static final String JWT_AUTH                   = "JWT_AUTH";
   private static final String JWT_KEYS_URL               = "JWT_KEYS_URL";
   private static final String JWT_KEYS_FORMAT            = "JWT_KEYS_FORMAT";
   private static final String JWT_KEYS_MODULUS_XPATH     = "JWT_KEYS_MODULUS_XPATH";
   private static final String JWT_KEYS_EXPONENT_XPATH    = "JWT_KEYS_EXPONENT_XPATH";
   private static final String JWT_KEYS_CACHE_TTL         = "JWT_KEYS_CACHE_TTL";
   private static final String JWT_KEYS_CONN_TIMEOUT      = "JWT_KEYS_CONN_TIMEOUT";
   private static final String JWT_KEYS_READ_TIMEOUT      = "JWT_KEYS_READ_TIMEOUT";
   private static final String JWT_KEYS_SSL_VERIFY        = "JWT_KEYS_SSL_VERIFY";
   private static final String JWT_KEYS_HOST_AUTH_MODE    = "JWT_KEYS_HOST_AUTH_MODE";
   private static final String JWT_KEYS_HOST_ACCOUNT_PATH = "JWT_KEYS_HOST_ACCOUNT_PATH";
   private static final String JWT_KEYS_PROXY_SERVER_MODE = "JWT_KEYS_PROXY_SERVER_MODE";
   private static final String JWT_KEYS_PROXY_SERVER_PATH = "JWT_KEYS_PROXY_SERVER_PATH";
   private static final String JWT_IDENTITY_MAPPING_MODE  = "JWT_IDENTITY_MAPPING_MODE";
   private static final String JWT_IDENTITY_MAPPING_PATH  = "JWT_IDENTITY_MAPPING_PATH";
   private static final String JWT_IDENTITY_ASSERTION     = "JWT_IDENTITY_ASSERTION";
   private static final String VALIDATION_ASSERTION       = "VALIDATION_ASSERTION";
   private static final String CUSTOM_REQUEST_HEADERS     = "CUSTOM_REQUEST_HEADERS";
   private static final String CUSTOM_RESPONSE_HEADERS    = "CUSTOM_RESPONSE_HEADERS";
   private static final String DEBUGGING_ASSERTION        = "DEBUGGING_ASSERTION";
   private static final String DEBUGGING_PROPERTIES       = "DEBUGGING_PROPERTIES";   
   
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

   // ==================================================================================================================================
   // Gestore della configurazione e  contesto di runtime
   // ==================================================================================================================================
   private static class RuntimeConfig extends SuperMap<Object> {}
   private static class RuntimeContext extends SuperMap<Object> {       
      // Meotodi shortcut per variabili più utilizzate
      public String getAuthType() { return getString("authtype"); }
      public String getUserName() { return getString("username"); }
      public String getIdentity() { return getString("identity"); }
      
      public void putAuthType(String StrAuthType) { put("authtype",StrAuthType); }
      public void putUserName(String StrUserName) { put("username",StrUserName); }
      public void putIdentity(String StrIdentity) { put("identity",StrIdentity); }
   }
   
   // ##################################################################################################################################
   // Dichiara variabili
   // ##################################################################################################################################

   // ==================================================================================================================================
   // Variabili globali 
   // ==================================================================================================================================

   // Contatore istanze del provider
   private static byte IntProviderCount = 0;
      
   // ==================================================================================================================================
   // Variabili globali di thread
   // ==================================================================================================================================

   // Logger, config e context di thread
   private static final ThreadLocal<LogManager> ObjThreadLogger = new ThreadLocal<LogManager>();
   private static final ThreadLocal<RuntimeConfig> ObjThreadConfig = new ThreadLocal<RuntimeConfig>();
   private static final ThreadLocal<RuntimeContext> ObjThreadContext = new ThreadLocal<RuntimeContext>();
      
   // ==================================================================================================================================
   // Variabili locali di istanza
   // ==================================================================================================================================
      
   // Contatore esecuzioni thread (di fatto è il numero di request gestite per provider)
   private long IntThreadCount = 0;
     
   // Parametri weblogic
   private String StrRealmName;
   private String StrDomainName;
   private String StrManagedName;
   
   // Gestione del provider jwt
   private JWTCache ObjJwtCache;
   private JWTProvider ObjJwtProvider;
           
   // Altre variabili di supporto
   private ScriptEngine ObjScriptEngine;   
   private Authenticator ObjAuthenticator;

   // Gestione del mbean
   private String StrInstanceName = "CIA"+IntProviderCount++;
   private String StrProviderName;
   private String StrProviderDescr;   
   private CustomIdentityAsserterMBean ObjProviderMBean;

   // ##################################################################################################################################
   // Implementa interfacce di inbound security (AuthenticationProviderV2, IdentityAsserterV2)
   // ##################################################################################################################################

   @Override
   public void initialize(ProviderMBean ObjMBean, SecurityServices ObjSecurityServices) {
      
      // Inizializza nome del thread
      setThreadName();
         
      // Prepara logger
      LogManager Logger = createLogger();
      
      // Inizializza contesto mbean
      StrProviderName = ObjMBean.getName();
      StrProviderDescr = ObjMBean.getDescription() + "n" + ObjMBean.getVersion();
      ObjProviderMBean = (CustomIdentityAsserterMBean) ObjMBean;
      
      // ==================================================================================================================================
      // Genera logging      
      // ==================================================================================================================================
      Logger.logMessage(LogLevel.INFO,"##########################################################################################");
      Logger.logMessage(LogLevel.INFO,"INITIALIZE");
      Logger.logMessage(LogLevel.INFO,"##########################################################################################");     

      // ==================================================================================================================================
      // Prepara contesto weblogic
      // ==================================================================================================================================
            
      StrRealmName = ObjProviderMBean.getRealm().getName();
      StrDomainName = WLSUtils.getDomainName();
      StrManagedName = WLSUtils.getManagedName();      
      ObjAuthenticator = WLSUtils.getAuthenticator(ObjMBean,StrRealmName,StrDomainName);     

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
         ObjJwtProvider =
            JWTProvider.create((JavaUtils.getJavaVersion()>7)&&(JavaUtils.getJavaVersion()<17)?("NimbusShaded"):("Nimbus"));
         
         // Inizializza cache delle chiavi jwt
         ObjJwtCache = new JWTCache();
         
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
      // Genera logging 
      // ==================================================================================================================================    
      Logger.logMessage(LogLevel.INFO,"==========================================================================================");
      Logger.logMessage(LogLevel.INFO,"CONTEXT");
      Logger.logMessage(LogLevel.INFO,"==========================================================================================");
      Logger.logMessage(LogLevel.INFO,"Realm Name ...........: " + StrRealmName);
      Logger.logMessage(LogLevel.INFO,"Domain Name ..........: " + StrDomainName);
      Logger.logMessage(LogLevel.INFO,"Managed Name .........: " + StrManagedName);  
      Logger.logMessage(LogLevel.INFO,"Provider Name ........: " + StrProviderName);  
      Logger.logMessage(LogLevel.INFO,"Instance Name ........: " + StrInstanceName);  
      Logger.logMessage(LogLevel.INFO,"------------------------------------------------------------------------------------------");
      Logger.logMessage(LogLevel.INFO,"JWT Provider .........: " + ObjJwtProvider.getClass().getCanonicalName());  
      Logger.logMessage(LogLevel.INFO,"Kerberos Config ......: " + SecurityUtils.getKerberosConfigPath());
      Logger.logMessage(LogLevel.INFO,"Scripting Engine .....: " + ObjScriptEngine.getFactory().getEngineName()+" ("+ObjScriptEngine.getFactory().getEngineVersion()+")");  
      Logger.logMessage(LogLevel.INFO,"Scripting Language ...: " + ObjScriptEngine.getFactory().getLanguageName()+" ("+ObjScriptEngine.getFactory().getLanguageVersion()+")");  
      Logger.logMessage(LogLevel.INFO,"##########################################################################################");      
   }

   @Override
   public void shutdown() {
      
      // Inizializza nome del thread
      setThreadName();
         
      // Prepara logger
      LogManager Logger = createLogger();

      // ==================================================================================================================================
      // Genera logging      
      // ==================================================================================================================================
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
   // Implementa identiti asserter
   // ##################################################################################################################################
   
   @Override
   public CallbackHandler assertIdentity(String StrTokenType,Object ObjToken,ContextHandler ObjRequestContext) throws IdentityAssertionException {
      
      // Inizializza nome del thread
      setThreadName();
         
      // Crea logger,config e context
      LogManager Logger = createLogger();
      RuntimeConfig Config = createConfig();      
      RuntimeContext Context = createContext(ObjRequestContext);      
      
      // Prepara livelli di logging di default
      Logger.setLogLevel(Config.getString(LOGGING_LEVEL));
      Logger.setLogLines(Config.getInteger(LOGGING_LINES));
      
      // Esegue in modo sincrono o asincrono in base a configurazione
      CallbackHandler ObjCallback;
      if (Config.getString(THREADING_MODE).equals("SERIAL")) {
         ObjCallback = assertIdentitySynchImpl(Logger,Config,Context,StrTokenType,ObjToken);
      } else {      
         ObjCallback = assertIdentityAsynchImpl(Logger,Config,Context,StrTokenType,ObjToken);
      }
      
      // Ripulisce esplicitamente le variabili di thread
      Config.clear();
      Context.clear();      
      ObjThreadLogger.remove();
      ObjThreadConfig.remove();
      ObjThreadContext.remove();      
      
      // Restituisce callback
      return ObjCallback;
   }

   // ==================================================================================================================================
   // Implementazione sincrona (serializza le richieste consentendo solo un thread alla volta)
   // ==================================================================================================================================
   private synchronized CallbackHandler assertIdentitySynchImpl(LogManager Logger,RuntimeConfig Config, RuntimeContext Context,
                                                                String StrTokenType, Object ObjToken) throws IdentityAssertionException {
      
      return assertIdentityAsynchImpl(Logger,Config,Context,StrTokenType,ObjToken);
   }                                     

   // ==================================================================================================================================
   // Implementazione asincrona (consente esecuzione parallela le richieste)
   // ==================================================================================================================================
   private CallbackHandler assertIdentityAsynchImpl(LogManager Logger,RuntimeConfig Config, RuntimeContext Context,
                                                    String StrTokenType, Object ObjToken) throws IdentityAssertionException {  
      
      // ==================================================================================================================================
      // Gestisce asserzione di debug
      // ==================================================================================================================================   
      String StrDebuggingAssertion = StringUtils.join(Config.getStringArray(DEBUGGING_ASSERTION),System.lineSeparator());

      // Se l'asserzione è definita esegue
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
      // Logging configurazione
      // ==================================================================================================================================
      if (Logger.checkLogLevel(LogLevel.DEBUG)) {
         Logger.logMessage(LogLevel.DEBUG,"##########################################################################################");
         Logger.logMessage(LogLevel.DEBUG,"ASSERT IDENTITY");
         Logger.logMessage(LogLevel.DEBUG,"##########################################################################################");
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
         Logger.logMessage(LogLevel.DEBUG,"CONFIGURATION");
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
         Logger.logMessage(LogLevel.DEBUG,"LOGGING_LEVEL ................: " + Config.getString(LOGGING_LEVEL));
         Logger.logMessage(LogLevel.DEBUG,"LOGGING_LINES ................: " + Config.getString(LOGGING_LINES));
         Logger.logMessage(LogLevel.DEBUG,"LOGGING_INFO .................: " + Config.getString(LOGGING_INFO));
         Logger.logMessage(LogLevel.DEBUG,"THREADING_MODE ...............: " + Config.getString(THREADING_MODE));
         Logger.logMessage(LogLevel.DEBUG,"BASIC_AUTH ...................: " + Config.getString(BASIC_AUTH));
         Logger.logMessage(LogLevel.DEBUG,"JWT_AUTH .....................: " + Config.getString(JWT_AUTH));
         Logger.logMessage(LogLevel.DEBUG,"JWT_KEYS_URL .................: " + Config.getString(JWT_KEYS_URL));
         Logger.logMessage(LogLevel.DEBUG,"JWT_KEYS_FORMAT ..............: " + Config.getString(JWT_KEYS_FORMAT));
         Logger.logMessage(LogLevel.DEBUG,"JWT_KEYS_MODULUS_XPATH .......: " + Config.getString(JWT_KEYS_MODULUS_XPATH));
         Logger.logMessage(LogLevel.DEBUG,"JWT_KEYS_EXPONENT_XPATH ......: " + Config.getString(JWT_KEYS_EXPONENT_XPATH));
         Logger.logMessage(LogLevel.DEBUG,"JWT_KEYS_CACHE_TTL ...........: " + Config.getString(JWT_KEYS_CACHE_TTL));
         Logger.logMessage(LogLevel.DEBUG,"JWT_KEYS_CONN_TIMEOUT ........: " + Config.getString(JWT_KEYS_CONN_TIMEOUT));
         Logger.logMessage(LogLevel.DEBUG,"JWT_KEYS_READ_TIMEOUT ........: " + Config.getString(JWT_KEYS_READ_TIMEOUT));
         Logger.logMessage(LogLevel.DEBUG,"JWT_KEYS_SSL_VERIFY ..........: " + Config.getString(JWT_KEYS_SSL_VERIFY));
         Logger.logMessage(LogLevel.DEBUG,"JWT_KEYS_HOST_AUTH_MODE ......: " + Config.getString(JWT_KEYS_HOST_AUTH_MODE));
         Logger.logMessage(LogLevel.DEBUG,"JWT_KEYS_HOST_ACCOUNT_PATH ...: " + Config.getString(JWT_KEYS_HOST_ACCOUNT_PATH));
         Logger.logMessage(LogLevel.DEBUG,"JWT_KEYS_PROXY_SERVER_MODE ...: " + Config.getString(JWT_KEYS_PROXY_SERVER_MODE));
         Logger.logMessage(LogLevel.DEBUG,"JWT_KEYS_PROXY_SERVER_PATH ...: " + Config.getString(JWT_KEYS_PROXY_SERVER_PATH));
         Logger.logMessage(LogLevel.DEBUG,"JWT_IDENTITY_MAPPING_MODE ....: " + Config.getString(JWT_IDENTITY_MAPPING_MODE));
         Logger.logMessage(LogLevel.DEBUG,"JWT_IDENTITY_MAPPING_PATH ....: " + Config.getString(JWT_IDENTITY_MAPPING_PATH));      
         Logger.logMessage(LogLevel.DEBUG,"JWT_IDENTITY_ASSERTION .......: " + StringUtils.join(Config.getStringArray(JWT_IDENTITY_ASSERTION)," "));
         Logger.logMessage(LogLevel.DEBUG,"VALIDATION_ASSERTION .........: " + StringUtils.join(Config.getStringArray(VALIDATION_ASSERTION)," "));
         Logger.logMessage(LogLevel.DEBUG,"CUSTOM_REQUEST_HEADERS .......: " + StringUtils.join(Config.getProperties(CUSTOM_REQUEST_HEADERS),","));
         Logger.logMessage(LogLevel.DEBUG,"CUSTOM_RESPONSE_HEADERS ......: " + StringUtils.join(Config.getProperties(CUSTOM_RESPONSE_HEADERS),","));
         Logger.logMessage(LogLevel.DEBUG,"DEBUGGING_ASSERTION ..........: " + StringUtils.join(Config.getStringArray(DEBUGGING_ASSERTION)," "));
         Logger.logMessage(LogLevel.DEBUG,"DEBUGGING_PROPERTIES .........: " + StringUtils.join(Config.getStringArray(DEBUGGING_PROPERTIES),","));                
         Logger.logMessage(LogLevel.TRACE,"------------------------------------------------------------------------------------------");
      }
      
      // ==================================================================================================================================
      // Controlli di congruenza ed eventuale pulizia della configurazione
      // ==================================================================================================================================      
      validateParameter(JWT_KEYS_URL);
      validateParameter(JWT_KEYS_MODULUS_XPATH);
      validateParameter(JWT_KEYS_EXPONENT_XPATH);         
      validateParameter(JWT_KEYS_CACHE_TTL);
      validateParameter(JWT_KEYS_CONN_TIMEOUT);
      validateParameter(JWT_KEYS_READ_TIMEOUT);
      if (!Config.getString(JWT_KEYS_HOST_AUTH_MODE).equals("ANONYMOUS")) validateParameter(JWT_KEYS_HOST_ACCOUNT_PATH);
      if (!Config.getString(JWT_KEYS_PROXY_SERVER_MODE).equals("DIRECT")) validateParameter(JWT_KEYS_PROXY_SERVER_MODE);      
      if (!Config.getString(JWT_IDENTITY_MAPPING_MODE).equals("DISABLE")) validateParameter(JWT_IDENTITY_MAPPING_MODE);
      validateParameter(JWT_IDENTITY_ASSERTION);

      // ==================================================================================================================================
      // Logging contesto
      // ==================================================================================================================================
      if (Logger.checkLogLevel(LogLevel.DEBUG)) {
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
         Logger.logMessage(LogLevel.DEBUG,"CONTEXT");
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
         Logger.logMessage(LogLevel.DEBUG,"Managed Name .....: "+ Context.getString("wls.managed"));
         Logger.logMessage(LogLevel.DEBUG,"Project Name .....: "+ Context.getString("osb.project"));
         Logger.logMessage(LogLevel.DEBUG,"Service Name .....: "+ Context.getString("osb.service.name"));           
         Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
         Logger.logMessage(LogLevel.DEBUG,"Server Host ......: "+ Context.getString("http.server.host"));               
         Logger.logMessage(LogLevel.DEBUG,"Server Addr ......: "+ Context.getString("http.server.addr"));               
         Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
         Logger.logMessage(LogLevel.DEBUG,"Client Host ......: "+ Context.getString("http.client.host"));        
         Logger.logMessage(LogLevel.DEBUG,"Client Addr ......: "+ Context.getString("http.client.addr")); 
         Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
         Logger.logMessage(LogLevel.DEBUG,"Request URL ......: "+ Context.getString("http.request.url"));        
         Logger.logMessage(LogLevel.DEBUG,"Content Type .....: "+ Context.getString("http.content.type"));        
         Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
      }

      // ==================================================================================================================================
      // Gestisce l'asserzione di identità
      // ==================================================================================================================================      
      assertIdentity(StrTokenType,ObjToken);
      
      // ==================================================================================================================================
      // Gestisce asserzione di validazione
      // ==================================================================================================================================      
      String StrValidationAssertion = StringUtils.join(Config.getStringArray(VALIDATION_ASSERTION),System.lineSeparator());
      
      if (!StrValidationAssertion.equals("")) {

         // Genera logging
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
      // Gestisce custom headers
      // ==================================================================================================================================
      Properties ObjCustomRequestHeaders  = Config.getProperties(CUSTOM_REQUEST_HEADERS);
      Properties ObjCustomResponseHeaders = Config.getProperties(CUSTOM_RESPONSE_HEADERS);
      
      if ((ObjCustomRequestHeaders!=null)||(ObjCustomResponseHeaders!=null)) {
         manageCustomHeaders(ObjCustomRequestHeaders,ObjCustomResponseHeaders);
      }
      
      // ==================================================================================================================================
      // Gestisce debugging properties
      // ==================================================================================================================================
      String[] ArrDebuggingProperties  = Config.getStringArray(DEBUGGING_PROPERTIES);

      if (ArrDebuggingProperties.length>0) {

         // Genera logging
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
         Logger.logMessage(LogLevel.DEBUG,"DEBUGGING PROPERTIES");
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
         
         for (String StrProperty : ArrDebuggingProperties) {
            try {
               Logger.logMessage(LogLevel.DEBUG,StrProperty+" => "+StringUtils.replaceTemplates(Context,StrProperty));
            } catch (Exception ObjException) {
               String StrError = "Debug property error '"+StrProperty+"'";
               Logger.logMessage(LogLevel.WARN,StrError,ObjException);
            }
         }
      }
      
      // Genera logging
      Logger.logMessage(LogLevel.DEBUG,"##########################################################################################");

      // ==================================================================================================================================
      // Gestisce logging informativo
      // ==================================================================================================================================
      try {
         // Genera logging di sintesi della asserzione
         Logger.logMessage(LogLevel.INFO,"Inbound ("+Context.getAuthType()+") => "+StringUtils.replaceTemplates(Context,Config.getString(LOGGING_INFO)));
      } catch (Exception ObjException) {
         String StrError = "Logging info error";
         Logger.logMessage(LogLevel.WARN,StrError,ObjException);
      }         

      // ==================================================================================================================================
      
      // Restituisce utente autenticato
      return new CustomIdentityAsserterCallbackHandlerImpl(Context.getUserName());
   }

   // ##################################################################################################################################
   // Metodi privati di supporto
   // ##################################################################################################################################

   // ==================================================================================================================================
   // Gestitsce l'asserzione
   // ==================================================================================================================================      
   private void assertIdentity(String StrTokenType,Object ObjToken) throws IdentityAssertionException {
         
      // Prepara logger e context
      LogManager Logger = getLogger();
      RuntimeConfig Config = getConfig();
      RuntimeContext Context = getContext();
   
      String StrToken = "";
      try {
         
         // Verifica la tipologia del token
         if (!(ObjToken instanceof String)) {
            String StrError = "Unsupported token class";
            Logger.logMessage(LogLevel.ERROR,StrError,ObjToken.getClass().getSimpleName());
            throw new Exception(StrError);
         }

         // Verifica la correttezza del tipo di token
         if (!TokenTypes.ALL_TYPES.contains(StrTokenType)) {        
            String StrError = "Unknown token type";
            Logger.logMessage(LogLevel.ERROR,StrError,StrTokenType);
            throw new Exception(StrError);
         }   
         
         // Se necessario genera logging di debug
         Logger.logMessage(LogLevel.DEBUG,"Selected Token ...: "+StrTokenType);
         
         // Verifica se il token in ingresso è un BASIC o un JWT
         StrToken = (String)ObjToken;
         
         if (StrToken.startsWith("Basic ")) {
            Context.putAuthType(TokenTypes.BASIC_AUTH_ID);         
            StrToken = StrToken.substring("Basic ".length());         
         } else {
            Context.putAuthType(TokenTypes.JWT_AUTH_ID);
            if (StrToken.startsWith("Bearer ")) {
               StrToken = StrToken.substring("Bearer ".length());
            }
         }

         // Genera logging      
         Logger.logMessage(LogLevel.DEBUG,"Detected Auth ....: "+Context.getAuthType());
               
         // Verifica la ammissibilità dell'autenticazione rilevata rispetto al token selezionato e ai flag di disattivazione
         if ((!StrTokenType.contains(Context.getAuthType()))||
             (Context.getAuthType().equals(TokenTypes.JWT_AUTH_ID)&&Config.getString("JWT_AUTH").equals("DISABLE"))||
             (Context.getAuthType().equals(TokenTypes.BASIC_AUTH_ID)&&Config.getString("BASIC_AUTH").equals("DISABLE"))) {
            throw new Exception("Disabled auth type");
         }
         
      } catch (Exception ObjException) {
         String StrError = "Token preparation error";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new IdentityAssertionException(StrError);         
      }
     
      // ==================================================================================================================================
      // Gestisce l'autenticazione
      // ==================================================================================================================================      
      switch (Context.getAuthType()) {
       
         case TokenTypes.JWT_AUTH_ID: manageJwtAuth(StrToken,ObjJwtProvider,ObjJwtCache); break;
         case TokenTypes.BASIC_AUTH_ID: manageBasicAuth(StrToken,ObjAuthenticator); break;
      }     
   }     
   
   // ==================================================================================================================================
   // Gestisce autenticazione JWT
   // ==================================================================================================================================      
   private static void manageJwtAuth(String StrToken,JWTProvider ObjJwtProvider,JWTCache ObjJwtCache) throws IdentityAssertionException {

      // Prepara logger e context
      LogManager Logger = getLogger();
      RuntimeConfig Config = getConfig();
      RuntimeContext Context = getContext();      
      
      // Genera logging
      Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
      Logger.logMessage(LogLevel.DEBUG,"JWT AUTH");
      Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
                        
      // ----------------------------------------------------------------------------------------------------------------------------------
      // Inizializza jwt provider 
      // ----------------------------------------------------------------------------------------------------------------------------------
      JWTProvider ObjJwtToken = null;         
      try {

         // Crea nuova istanza del token
         ObjJwtToken = ObjJwtProvider.createInstance();   
         
         // Aggiorna il contesto di runtime
         Context.put("token",ObjJwtToken);            

      } catch (Exception ObjException) {
         String StrError = "Token provider error";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new IdentityAssertionException(StrError); 
      } 
        
      // ----------------------------------------------------------------------------------------------------------------------------------
      // Inizializza jwt token
      // ----------------------------------------------------------------------------------------------------------------------------------
      String StrJwtKeyID = "";
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
         
      // ----------------------------------------------------------------------------------------------------------------------------------
      // Prepara chiave per la verifica della firma
      // ----------------------------------------------------------------------------------------------------------------------------------
      String StrKeyModulus = "";
      String StrKeyExponent = "";         
      try {

         // Prepara la chiave       
         JWTCacheEntry ObjKey = prepareKey(StrJwtKeyID,ObjJwtCache);

         // Acuisisce parametri chiave dalla cache
         StrKeyModulus = ObjKey.modulus;
         StrKeyExponent = ObjKey.exponent;            
         
      } catch (Exception ObjException) {
         String StrError = "Keys retrieving error";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new IdentityAssertionException(StrError);
      } 

      // ----------------------------------------------------------------------------------------------------------------------------------
      // Verifica la firma del token jwt
      // ----------------------------------------------------------------------------------------------------------------------------------

      // Genera logging
      Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
      Logger.logMessage(LogLevel.DEBUG,"TOKEN VALIDATION");
      Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
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
         
      // ----------------------------------------------------------------------------------------------------------------------------------
      // Gestisce asserzione dell'identità
      // ----------------------------------------------------------------------------------------------------------------------------------
      
      // Genera logging
      Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
      Logger.logMessage(LogLevel.DEBUG,"IDENTITY ASSERTION");
      Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
               
      try {
         
         // Prepara lo script di asserzione
         String StrJwtIdentityAssertion  = StringUtils.join(Config.getStringArray(JWT_IDENTITY_ASSERTION),System.lineSeparator());

         // Estrapola l'identità dallo script di asserzione
         Context.putIdentity((String)evaluateScript(StrJwtIdentityAssertion,"String"));     
                     
         if (Context.getIdentity().equals("")) {
            throw new Exception("evaluate to blank");               
         }
         
      } catch (Exception ObjException) {
         String StrError = "Identity assertion error";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new IdentityAssertionException(StrError);
      }

      // Genera logging
      Logger.logMessage(LogLevel.DEBUG,"Token Identity ....: " + Context.getIdentity());
         
      // ----------------------------------------------------------------------------------------------------------------------------------
      // Gestisce l'eventuale identity mapping
      // ----------------------------------------------------------------------------------------------------------------------------------
      if (Config.getString(JWT_IDENTITY_MAPPING_MODE).equals("DISABLE")) {

         // Pone lo username pari all'identità 
         Context.putUserName(Context.getIdentity());
         
      } else {            
         try {               
            
            // Se presenti rimpiazza i template nel path della risorsa osb
            String StrJwtIdentityMappingParsedPath = StringUtils.replaceTemplates(Context,Config.getString(JWT_IDENTITY_MAPPING_PATH));
            
            // Genera logging
            Logger.logMessage(LogLevel.DEBUG,"Mapping Account ...: "+StrJwtIdentityMappingParsedPath);
            
            // Prova a mappare l'identità allo username mediante un service account OSB di mapping
            Context.putUserName(OSBUtils.getMappedLocalUser(StrJwtIdentityMappingParsedPath,Context.getIdentity()));

            // Se il mapping è fallito genera eccezione
            if (Context.getUserName().equals("")) {
               throw new Exception("unknown identity");               
            }            
         } catch (Exception ObjException) {
            String StrError = "Identity mapping error";
            Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
            throw new IdentityAssertionException(StrError);
         }
      }
      
      // Genera logging
      Logger.logMessage(LogLevel.DEBUG,"Realm UserName ....: " + Context.getUserName());
   }
   
   // ==================================================================================================================================
   // Gestisce autenticazione BASIC
   // ==================================================================================================================================      
   private static void manageBasicAuth(String StrToken,Authenticator ObjAuthenticator) throws IdentityAssertionException {

      // Prepara logger e context
      LogManager Logger = getLogger();
      RuntimeConfig Config = getConfig();
      RuntimeContext Context = getContext();
         
      // Genera logging
      Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
      Logger.logMessage(LogLevel.DEBUG,"BASIC AUTH");
      Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");  
                        
      try {          
         
         // Dedodifica il token basic
         String[] ArrCredential = SecurityUtils.decodeBase64(StrToken).split(":",2);            
         Logger.logMessage(LogLevel.DEBUG,"UserName: "+ArrCredential[0]);   
         
         // Prova ad autenticare le credenziali sul realm weblogic
         Context.putUserName(ObjAuthenticator.authenticate(ArrCredential[0], ArrCredential[1]));
         
         // Se l'utenza non à autenticata genera eccezione
         if ((Context.getUserName()==null)||Context.getUserName().equals("")) {
            throw new Exception("wrong credentials");
         }
               
      } catch (Exception ObjException) {
         String StrError = "Basic auth error";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new IdentityAssertionException(StrError);        
      }      
   }
   
   // ==================================================================================================================================
   // Gestisce custom headers
   // ==================================================================================================================================      
   private static void manageCustomHeaders(Properties ObjRequestHeaders,Properties ObjResponseHeaders) throws IdentityAssertionException {

      // Prepara logger e context
      LogManager Logger = getLogger();
      RuntimeConfig Config = getConfig();
      RuntimeContext Context = getContext();

      // Genera logging
      Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
      Logger.logMessage(LogLevel.DEBUG,"CUSTOM HEADERS");
      Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");

      // Gestisce cutom request headers              
      if (ObjRequestHeaders!=null) {    
         HttpServletRequest ObjRequest = (HttpServletRequest) Context.get("http.request");        
         for (String StrHeaderName : ObjRequestHeaders.stringPropertyNames()) {
            try {
               String StrHeaderValue = StringUtils.replaceTemplates(Context,ObjRequestHeaders.getProperty(StrHeaderName));
               
               if (StrHeaderValue!="") {
                  Logger.logMessage(LogLevel.DEBUG,"Request: "+StrHeaderName+"="+StrHeaderValue);
                  WLSUtils.addHeader(ObjRequest,StrHeaderName,StrHeaderValue);
               }
            } catch (Exception ObjException) {
               String StrError = "Custom request header error '"+StrHeaderName+"'";
               Logger.logMessage(LogLevel.WARN,StrError,ObjException);
            }
         }
      }
      
      // Gestisce cutom response headers              
      if (ObjResponseHeaders!=null) {    
         HttpServletResponse ObjResponse = (HttpServletResponse) Context.get("http.response");        
         for (String StrHeaderName : ObjResponseHeaders.stringPropertyNames()) {
            try {
               String StrHeaderValue = StringUtils.replaceTemplates(Context,ObjResponseHeaders.getProperty(StrHeaderName));
               
               if (StrHeaderValue!="") {
                  Logger.logMessage(LogLevel.DEBUG,"Response: "+StrHeaderName+"="+StrHeaderValue);
                  ObjResponse.addHeader(StrHeaderName,StrHeaderValue);
               }
            } catch (Exception ObjException) {
               String StrError = "Custom response header error '"+StrHeaderName+"'";
               Logger.logMessage(LogLevel.WARN,StrError,ObjException);
            }  
         }
      }
   }
   
   // ==================================================================================================================================
   // Gestisce preparazione chiave di firma jwt
   // ==================================================================================================================================      
   private static JWTCacheEntry prepareKey(String StrJwtKeyID,JWTCache ObjJwtKeysCache) throws Exception {

      // Prepara logger e context
      LogManager Logger = getLogger();
      RuntimeConfig Config = getConfig();
      RuntimeContext Context = getContext();
   
      // Verifica se la chiave è già in cache e non è scaduta         
      JWTCacheEntry ObjKey = ObjJwtKeysCache.validKey(StrJwtKeyID,Config.getInteger(JWT_KEYS_CACHE_TTL));
      
      // Se la chiave non è in cache  esegue
      if (ObjKey==null) {
         
         // ----------------------------------------------------------------------------------------------------------------------------------
         // Acquisisce le chiavi
         // ----------------------------------------------------------------------------------------------------------------------------------
         
         // Inizializza variabili
         String StrJwtKeysHostUserName = "";
         String StrJwtKeysHostPassword = "";
         String StrJwtKeysProxyUserName = "";
         String StrJwtKeysProxyPassword = "";
         String StrJwtKeysProxyHost = "";
         int IntJwtKeysProxyPort = 0;
         
         // Genera logging
         Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
         Logger.logMessage(LogLevel.DEBUG,"KEYS RETRIEVE");
         Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");

         // Imposta livello di padding
         Logger.setPadLength(31);
         
         // Prepara autenticazione server
         if (!Config.getString(JWT_KEYS_HOST_AUTH_MODE).equals("ANONYMOUS")) {

            // Genera logging e acquisisce risorsa ESB proxy in formato XML
            Logger.logProperty(LogLevel.DEBUG,"Host Auth Account",Config.getString(JWT_KEYS_HOST_ACCOUNT_PATH));                  
            XmlObject ObjServiceAccount = OSBUtils.getResource("ServiceAccount", Config.getString(JWT_KEYS_HOST_ACCOUNT_PATH));

            // Acquisisce credenziali
            StrJwtKeysHostUserName = XMLUtils.getTextValue(ObjServiceAccount, "//*:username/text()");
            StrJwtKeysHostPassword = XMLUtils.getTextValue(ObjServiceAccount, "//*:password/text()");
         }

         // Prepara parametri proxy
         if (!Config.getString(JWT_KEYS_PROXY_SERVER_MODE).equals("DIRECT")) {
         
            // Genera logging e acquisisce risorsa ESB proxy in formato XML
            Logger.logProperty(LogLevel.DEBUG,"Proxy Server Resource",Config.getString(JWT_KEYS_PROXY_SERVER_PATH));                  
            XmlObject ObjProxyServer = OSBUtils.getResource("ProxyServer", Config.getString(JWT_KEYS_PROXY_SERVER_PATH));

            // Esegue parsing dei vari parametri del proxy
            StrJwtKeysProxyHost = XMLUtils.getTextValue(ObjProxyServer, "//*:server/@host");
            IntJwtKeysProxyPort = Integer.valueOf(XMLUtils.getTextValue(ObjProxyServer, "//*:server/@port"));
            
            // Prepara autenticazione proxy
            if (!Config.getString(JWT_KEYS_PROXY_SERVER_MODE).equals("ANONYMOUS")) {
   
                // Acquisisce credenziali
                StrJwtKeysProxyUserName = XMLUtils.getTextValue(ObjProxyServer, "//*:username/text()");
                StrJwtKeysProxyPassword = XMLUtils.getTextValue(ObjProxyServer, "//*:password/text()");
            }
         }
         
         // Acquisisce payload delle chiavi pubbliche in formato stringa
         String StrJwtKeys = HttpUtils.fetch(HttpMethod.GET, Config.getString(JWT_KEYS_URL),  
                                             Config.getString(JWT_KEYS_FORMAT).equals("XML")?("text/xml"):("application/json"),
                                             Config.getString(JWT_KEYS_HOST_AUTH_MODE), StrJwtKeysHostUserName, StrJwtKeysHostPassword,
                                             Config.getString(JWT_KEYS_PROXY_SERVER_MODE), StrJwtKeysProxyUserName, StrJwtKeysProxyPassword,
                                             StrJwtKeysProxyHost,IntJwtKeysProxyPort, 
                                             Config.getString(JWT_KEYS_SSL_VERIFY).equals("ENABLE"), 
                                             Config.getInteger(JWT_KEYS_CONN_TIMEOUT), 
                                             Config.getInteger(JWT_KEYS_READ_TIMEOUT), Logger);
         
         // ----------------------------------------------------------------------------------------------------------------------------------
         // Gestisce parsing e caching delle chiavi
         // ----------------------------------------------------------------------------------------------------------------------------------

         // Inizializza variabile
         XmlObject ObjJwtKeys;
                  
            // Gestisce parsing json
         if (Config.getString(JWT_KEYS_FORMAT).equals("JSON")) {

            // Acquisisce payload in formato json e genera logging
            JSONObject ObjJSON = new JSONObject(StrJwtKeys);

            // Genera logging
            Logger.logProperty(LogLevel.TRACE,"Payload (JSON)",ObjJSON.toString());

            // Converte da JSON a XML
            StrJwtKeys = "<root>"+XML.toString(ObjJSON)+"</root>";                                          
         }

         // Genera logging
         Logger.logProperty(LogLevel.TRACE,"Payload (XML)",StrJwtKeys);

         // Acquisisce chiavi dal formato xml
         ObjJwtKeys = XmlObject.Factory.parse(StrJwtKeys);

         // Prepara espressioni xpath e logging
         String StrJwtKeysModulusParsedXPath = StringUtils.replaceTemplates(Context,Config.getString(JWT_KEYS_MODULUS_XPATH));
         Logger.logProperty(LogLevel.DEBUG,"Modulus XPath Parsed",StrJwtKeysModulusParsedXPath);

         String StrJwtKeysExponentParsedXPath = StringUtils.replaceTemplates(Context,Config.getString(JWT_KEYS_EXPONENT_XPATH));
         Logger.logProperty(LogLevel.DEBUG,"Exponent XPath Parsed",StrJwtKeysExponentParsedXPath);            

         // Estrapola modulo ed esponente
         String StrKeyModulus = XMLUtils.getTextValue(ObjJwtKeys,StrJwtKeysModulusParsedXPath);
         String StrKeyExponent = XMLUtils.getTextValue(ObjJwtKeys,StrJwtKeysExponentParsedXPath);
         
         // Se non è stata trovata alcuna chiave genera eccezione
         if (StrKeyModulus.equals("")||StrKeyExponent.equals("")) {
            throw new Exception("unable to extract key");
         } 
         
         // Salva la chiave in cache e la restituisce
         ObjKey = ObjJwtKeysCache.putKey(StrJwtKeyID,StrKeyModulus,StrKeyExponent);
      }                        
      
      // Restituisce chiave
      return ObjKey;
   }
   
   // ==================================================================================================================================
   // Evaluate script
   // ==================================================================================================================================
   private static Object evaluateScript(String StrScript, String StrClassName) throws Exception {
      
      // Prepara logger & context
      RuntimeContext Context = getContext();               
      
      // Esegue lo script fornito
      Object ObjResult = ((ScriptEngine)Context.get("java.scripting")).eval(StringUtils.replaceTemplates(Context,StrScript));
      String StrResultClassName = ObjResult.getClass().getSimpleName();
      
      // Se la tipologia di oggetto restituita non è quella attesa genera eccezione
      if (!StrResultClassName.equals(StrClassName)) {
         throw new Exception("expression must return '"+StrClassName+"' instead of '"+StrResultClassName+"'");
      }

      // Restrituisce l'oggetto risultante
      return ObjResult;
   }
    
   // ==================================================================================================================================
   // Verifica se un parametro obbligatorio e valorizzato
   // ==================================================================================================================================
   private static void validateParameter(String StrParameterName) throws IdentityAssertionException {
         
      // Prepara logger & context
      LogManager Logger = getLogger();
      RuntimeConfig Config = getConfig();
      
      // Acquisisce il parametro indicato dalla configurazione
      Object ObjParameterValue = Config.get(StrParameterName);
      
      // Prepara nome della classe del parametro
      String StrClassName = (ObjParameterValue==null)?("null"):(ObjParameterValue.getClass().getSimpleName());

      // Se si tratta di un parametro stringa esegue trim
      if (StrClassName.equals("String")) {
         ObjParameterValue = ((String)ObjParameterValue).trim();
      }
      
      // Se necessario genera trace
      Logger.logMessage(LogLevel.TRACE,"Checking Parameter "+StrParameterName+": "+
                                       ((ObjParameterValue==null)?("is null"):
                                        ("class '"+StrClassName+"' "+
                                         ((!StrClassName.equals("String"))?(""):
                                          (ObjParameterValue.equals("")?("is empty"):("")))))); 
      
      // Verifica se il parametro è null o blank
      if ((ObjParameterValue==null)||((StrClassName.equals("String"))&&((String)ObjParameterValue).equals(""))) {
         String StrError = "Configuration error";
         Logger.logMessage(LogLevel.ERROR,StrError,"mandatory parameter missing '"+StrParameterName+"'");
         throw new IdentityAssertionException(StrError);
      }
      
      // Reimposta il parametro di configurazione dopo l'eventuale correzione
      Config.put(StrParameterName,ObjParameterValue);
   }   

   // ==================================================================================================================================
   // Acquisisce logger di thread
   // ==================================================================================================================================    
   private static LogManager getLogger() {      
      return ObjThreadLogger.get();   
   }    
   
   // ==================================================================================================================================
   // Crea logger di thread
   // ==================================================================================================================================    
   private LogManager createLogger() {      
      LogManager ObjLogger = new LogManager(StrInstanceName);      
      ObjThreadLogger.set(ObjLogger);
      return ObjLogger;   
   }   

   // ==================================================================================================================================
   // Acquisisce config di thread
   // ==================================================================================================================================    
   private static RuntimeConfig getConfig() {      
      return ObjThreadConfig.get();   
   }    

   // ==================================================================================================================================
   // Crea nuovo context di thread
   // ==================================================================================================================================    
   private RuntimeConfig createConfig() {   
      
      // Prepara nuova config
      RuntimeConfig Config = new RuntimeConfig();     
      
      Config.put(LOGGING_LEVEL,ObjProviderMBean.getLOGGING_LEVEL());
      Config.put(LOGGING_LINES,ObjProviderMBean.getLOGGING_LINES());
      Config.put(LOGGING_INFO,ObjProviderMBean.getLOGGING_INFO());
      
      Config.put(THREADING_MODE,ObjProviderMBean.getTHREADING_MODE());
                     
      Config.put(BASIC_AUTH,ObjProviderMBean.getBASIC_AUTH());
      Config.put(JWT_AUTH,ObjProviderMBean.getJWT_AUTH());
      
      Config.put(JWT_KEYS_URL,ObjProviderMBean.getJWT_KEYS_URL());
      Config.put(JWT_KEYS_FORMAT,ObjProviderMBean.getJWT_KEYS_FORMAT());
      Config.put(JWT_KEYS_MODULUS_XPATH,ObjProviderMBean.getJWT_KEYS_MODULUS_XPATH());
      Config.put(JWT_KEYS_EXPONENT_XPATH,ObjProviderMBean.getJWT_KEYS_EXPONENT_XPATH());
      Config.put(JWT_KEYS_CACHE_TTL,ObjProviderMBean.getJWT_KEYS_CACHE_TTL());
      Config.put(JWT_KEYS_CONN_TIMEOUT,ObjProviderMBean.getJWT_KEYS_CONN_TIMEOUT());
      Config.put(JWT_KEYS_READ_TIMEOUT,ObjProviderMBean.getJWT_KEYS_READ_TIMEOUT());
      Config.put(JWT_KEYS_SSL_VERIFY,ObjProviderMBean.getJWT_KEYS_SSL_VERIFY());
      Config.put(JWT_KEYS_HOST_AUTH_MODE,ObjProviderMBean.getJWT_KEYS_HOST_AUTH_MODE());
      Config.put(JWT_KEYS_HOST_ACCOUNT_PATH,ObjProviderMBean.getJWT_KEYS_HOST_ACCOUNT_PATH());
      Config.put(JWT_KEYS_PROXY_SERVER_MODE,ObjProviderMBean.getJWT_KEYS_PROXY_SERVER_MODE());
      Config.put(JWT_KEYS_PROXY_SERVER_PATH,ObjProviderMBean.getJWT_KEYS_PROXY_SERVER_PATH());      
      Config.put(JWT_IDENTITY_MAPPING_MODE,ObjProviderMBean.getJWT_IDENTITY_MAPPING_MODE());
      Config.put(JWT_IDENTITY_MAPPING_PATH,ObjProviderMBean.getJWT_IDENTITY_MAPPING_PATH());
      Config.put(JWT_IDENTITY_ASSERTION,ObjProviderMBean.getJWT_IDENTITY_ASSERTION());      
      Config.put(VALIDATION_ASSERTION,ObjProviderMBean.getVALIDATION_ASSERTION());
      
      Config.put(CUSTOM_REQUEST_HEADERS,ObjProviderMBean.getCUSTOM_REQUEST_HEADERS());
      Config.put(CUSTOM_RESPONSE_HEADERS,ObjProviderMBean.getCUSTOM_RESPONSE_HEADERS());
      
      Config.put(DEBUGGING_ASSERTION,ObjProviderMBean.getDEBUGGING_ASSERTION());
      Config.put(DEBUGGING_PROPERTIES,ObjProviderMBean.getDEBUGGING_PROPERTIES());
      
      // Imposta varibile di trhead e restituisce referenza
      ObjThreadConfig.set(Config);
      return Config;   
   } 
   
   // ==================================================================================================================================
   // Acquisisce context di thread
   // ==================================================================================================================================    
   private static RuntimeContext getContext() {      
      return ObjThreadContext.get();   
   }    

   // ==================================================================================================================================
   // Crea nuovo context di thread
   // ==================================================================================================================================    
   private RuntimeContext createContext(ContextHandler ObjRequestContext) {   

      // Prepara nuovo context
      RuntimeContext Context = new RuntimeContext();     
         
      // Estrapola il contesto di request
      ServiceInfo ObjService = (ServiceInfo) ObjRequestContext.getValue("com.bea.contextelement.alsb.service-info");
      TransportEndPoint ObjEndpoint = (TransportEndPoint) ObjRequestContext.getValue("com.bea.contextelement.alsb.transport.endpoint"); 
      HttpServletRequest ObjRequest = (HttpServletRequest) ObjRequestContext.getValue("com.bea.contextelement.alsb.transport.http.http-request");
      HttpServletResponse ObjResponse = (HttpServletResponse) ObjRequestContext.getValue("com.bea.contextelement.alsb.transport.http.http-response");
      
      // ----------------------------------------------------------------------------------------------------------------------------------
      // Prepara variabili di contesto statiche
      // ----------------------------------------------------------------------------------------------------------------------------------
      
      // Contesto autenticazione
      Context.putAuthType("");
      Context.putIdentity("");
      Context.putUserName("");    
      
      // Contesto generale
      Context.put("token",null); 
      Context.put("thread",String.valueOf(Thread.currentThread().getId()));   
      Context.put("provider",StrProviderName);   
      Context.put("instance",StrInstanceName); 
      
      Context.put("request.counter",Thread.currentThread().getName());   
      Context.put("request.datetime",JavaUtils.getDateTime());          
      Context.put("request.timestamp",String.valueOf(JavaUtils.getTimestamp()));            

      // Contesto weblogic     
      Context.put("wls.realm",StrRealmName);   
      Context.put("wls.domain",StrDomainName);   
      Context.put("wls.managed",StrManagedName);   

      // Contesto java
      Context.put("java.version",String.valueOf(JavaUtils.getJavaVersion())); 
      Context.put("java.scripting",ObjScriptEngine); 
      
      // Contesto osb
      Context.put("osb.service",ObjService);  
      Context.put("osb.endpoint",ObjEndpoint);  

      Context.put("osb.project",ObjService.getRef().getProjectName());  
      Context.put("osb.service.name",ObjService.getRef().getLocalName());      
      Context.put("osb.service.path",ObjService.getRef().getFullName());

      // Contesto http
      Context.put("http.request",ObjRequest); 
      Context.put("http.response",ObjResponse); 
      
      Context.put("http.request.url",ObjRequest.getRequestURL().toString());      
      Context.put("http.request.proto",ObjRequest.getProtocol());      
      Context.put("http.request.scheme",ObjRequest.getScheme());                  
      Context.put("http.client.host",ObjRequest.getRemoteHost());      
      Context.put("http.client.addr",ObjRequest.getRemoteAddr());     
      Context.put("http.server.host",ObjRequest.getLocalName());      
      Context.put("http.server.addr",ObjRequest.getLocalAddr());      
      Context.put("http.server.name",ObjRequest.getServerName());      
      Context.put("http.server.port",String.valueOf(ObjRequest.getServerPort()));      
      Context.put("http.content.type",ObjRequest.getContentType());      
      Context.put("http.content.length",String.valueOf(ObjRequest.getContentLength()));    
      
      // ----------------------------------------------------------------------------------------------------------------------------------
      // Prepara variabili di contesto dinamiche semplici
      // ----------------------------------------------------------------------------------------------------------------------------------
      Context.put("current.datetime",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date(System.currentTimeMillis())); 
         }
      });              
      Context.put("current.timestamp",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            return String.valueOf(System.currentTimeMillis());
         }
      });             
      Context.put("http.content.body",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            HttpServletRequest ObjRequest = (HttpServletRequest) ObjContext.get("http.request");
            return StringUtils.toString(ObjRequest.getInputStream());
         }
      });             
      Context.put("http.header.*",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            LogManager Logger = getLogger();
            HttpServletRequest ObjRequest = (HttpServletRequest) ObjContext.get("http.request");
            return Logger.formatProperties(LogLevel.DEBUG,HttpUtils.getHeaders(ObjRequest, Arrays.asList("Authorization")),StringUtils.repeat(90,"-"),false);
         }
      });        
      Context.put("token.header.*",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            LogManager Logger = getLogger();
            JWTProvider ObjJwtToken = (JWTProvider) ObjContext.get("token"); 
            return ((ObjJwtToken!=null)&&(ObjJwtToken.isReady()))?(Logger.formatProperties(LogLevel.DEBUG,ObjJwtToken.getHeader(),StringUtils.repeat(90,"-"),true)):("");
         }
      });                                                         
      Context.put("token.payload.*",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            LogManager Logger = getLogger();
            JWTProvider ObjJwtToken = (JWTProvider) ObjContext.get("token"); 
            return ((ObjJwtToken!=null)&&(ObjJwtToken.isReady()))?(Logger.formatProperties(LogLevel.DEBUG,ObjJwtToken.getPayload(),StringUtils.repeat(90,"-"),true)):("");
         }
      }); 
      
      // ----------------------------------------------------------------------------------------------------------------------------------
      // Prepara variabili di contesto dinamiche regex
      // ----------------------------------------------------------------------------------------------------------------------------------
      Context.putRegex("^http\\.header\\.[^\\.]*$",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            HttpServletRequest ObjRequest = (HttpServletRequest) ObjContext.get("http.request");
            return StringUtils.join(ObjRequest.getHeaders(StrVariableName.split("\\.")[2]),"|") ; 
         }
      }); 
      Context.putRegex("^token\\.header\\.[^\\.]*$",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            JWTProvider ObjJwtToken = (JWTProvider) ObjContext.get("token"); 
            return ((ObjJwtToken!=null)&&(ObjJwtToken.isReady()))?((String) ObjJwtToken.getHeader().get(StrVariableName.split("\\.")[2])):("");
         }
      });       
      Context.putRegex("^token\\.payload\\.[^\\.]*$",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            JWTProvider ObjJwtToken = (JWTProvider) ObjContext.get("token"); 
            return (ObjJwtToken!=null)?((String) ObjJwtToken.getPayload().get(StrVariableName.split("\\.")[2])):("");
         }
      });

      // ----------------------------------------------------------------------------------------------------------------------------------
      
      // Imposta varibile di trhead e restituisce referenza
      ObjThreadContext.set(Context);
      return Context;   
   }    
   
   // ==================================================================================================================================
   // Inizializza nome del thread (contatore di esecuzione)
   // ==================================================================================================================================
   private synchronized void setThreadName()  {
      Thread.currentThread().setName(StringUtils.padLeft(String.valueOf(IntThreadCount++),7,"0"));
   }
}
