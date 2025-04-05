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

import org.apache.commons.io.IOUtils;
import org.apache.xmlbeans.XmlObject;

import com.bea.xbean.util.Base64;
import com.bea.wli.sb.services.ServiceInfo;
import com.bea.wli.sb.transports.TransportEndPoint;

import org.json.XML;
import org.json.JSONObject;

import org.falpi.*;
import org.falpi.utils.*;
import org.falpi.utils.WLSUtils.*;
import org.falpi.utils.HttpUtils.*;
import org.falpi.utils.StringUtils.*;
import org.falpi.utils.jwt.*;
import org.falpi.utils.jwt.JWTCache.*;
import org.falpi.utils.logging.*;

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

   // ==================================================================================================================================
   // Gestore del contesto di runtime
   // ==================================================================================================================================
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

   // Logger di thread
   private static final ThreadLocal<LogManager> ObjThreadLogger = new ThreadLocal<LogManager>();
   
   // Context di thread
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
   private JWTToken ObjJwtProvider;
   private JWTCache ObjJwtKeysCache;
           
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
      
      // Inizializza nome del thread con la rappresentazione esadecimale del contatore di esecuzione
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
      
      // Inizializza nome del thread (contatore di esecuzione)
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
   // Implementa metodo principale per l'autenticazione
   // ##################################################################################################################################
   
   @Override
   public CallbackHandler assertIdentity(String StrTokenType, Object ObjToken, ContextHandler ObjRequestContext) throws IdentityAssertionException {
      
      // Esegue in modo sincrono o asincrono in base a configurazione
      if (ObjProviderMBean.getTHREADING_MODE().equals("SERIAL")) {
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

      // Inizializza nome del thread (contatore di esecuzione)
      setThreadName();
         
      // Prepara logger e context
      LogManager Logger = createLogger();
      RuntimeContext Context = createContext();

      // ==================================================================================================================================
      // Prepara configurazione
      // ==================================================================================================================================
                        
      String StrLoggingLevel = ObjProviderMBean.getLOGGING_LEVEL();
      Integer IntLoggingLines = ObjProviderMBean.getLOGGING_LINES();
      String StrLoggingInfo = ObjProviderMBean.getLOGGING_INFO();
      
      String StrThreadingMode = ObjProviderMBean.getTHREADING_MODE();
                     
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

      // Completa la preparazione del context con i template di dettaglio
      prepareContext(ObjRequestContext);

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
      // Logging configurazione e controlli congruenza
      // ==================================================================================================================================
      Logger.logMessage(LogLevel.DEBUG,"##########################################################################################");
      Logger.logMessage(LogLevel.DEBUG,"ASSERT IDENTITY");
      Logger.logMessage(LogLevel.DEBUG,"##########################################################################################");
      Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
      Logger.logMessage(LogLevel.DEBUG,"CONFIGURATION");
      Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
      Logger.logMessage(LogLevel.DEBUG,"LOGGING_LEVEL ................: " + StrLoggingLevel);
      Logger.logMessage(LogLevel.DEBUG,"LOGGING_LINES ................: " + IntLoggingLines);
      Logger.logMessage(LogLevel.DEBUG,"LOGGING_INFO .................: " + StrLoggingInfo);
      Logger.logMessage(LogLevel.DEBUG,"THREADING_MODE ...............: " + StrThreadingMode);
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
            
      // Controlli di congruenza
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
      // Logging contesto
      // ==================================================================================================================================
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
      
      // ==================================================================================================================================
      // Esegue verifica e parsing del token e rileva la modalità di autenticazione
      // ==================================================================================================================================      
      String StrToken = "";
      try {
         // Prepara token
         StrToken = prepareToken(StrTokenType,ObjToken);
               
         // Verifica la ammissibilità dell'autenticazione rilevata rispetto al token selezionato e ai flag di disattivazione
         if ((!StrTokenType.contains(Context.getAuthType()))||
             (Context.getAuthType().equals(TokenTypes.JWT_AUTH_ID)&&StrJwtAuthStatus.equals("DISABLE"))||
             (Context.getAuthType().equals(TokenTypes.BASIC_AUTH_ID)&&StrBasicAuthStatus.equals("DISABLE"))) {
            throw new Exception("Disabled auth type");
         }
         
      } catch (Exception ObjException) {
         String StrError = "Token preparation error";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new IdentityAssertionException(StrError);         
      }

      // ==================================================================================================================================
      // Gestisce l'autenticazione BASIC
      // ==================================================================================================================================
      
      // Se si tratta di una basic authentication esegue
      if (Context.getAuthType().equals(TokenTypes.BASIC_AUTH_ID)) {
         
         // Genera logging
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
         Logger.logMessage(LogLevel.DEBUG,"BASIC AUTH");
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");  
                           
         try {          
                        
            // Dedodifica il token basic
            String[] ArrCredential = new String(Base64.decode(StrToken.getBytes())).split(":",2);            
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
      // Gestisce l'autenticazione JWT
      // ==================================================================================================================================

      // Se si tratta di una jwt authentication esegue
      if (Context.getAuthType().equals(TokenTypes.JWT_AUTH_ID)) {   
         
         // Genera logging
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
            Context.put("token",ObjJwtToken);            

         } catch (Exception ObjException) {
            String StrError = "Token provider error";
            Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
            throw new IdentityAssertionException(StrError); 
         } 
           
         // ==================================================================================================================================
         // Inizializza token
         // ==================================================================================================================================
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
            
         // ==================================================================================================================================
         // Prepara chiave per la verifica della firma
         // ==================================================================================================================================

         // Dichiara variabili         
         String StrKeyModulus = "";
         String StrKeyExponent = "";

         // Verifica se la chiave è già in cache e non è scaduta         
         JWTCacheEntry ObjKey = ObjJwtKeysCache.validKey(StrJwtKeyID,IntJwtKeysCacheTTL);
         
         // Se la chiave è in cache e il suo timestamp non è scaduto esegue altrimenti procede
         if (ObjKey!=null) {
            
            // Acuisisce parametri chiave dalla cache
            StrKeyModulus = ObjKey.modulus;
            StrKeyExponent = ObjKey.exponent;            
            
         } else {
            try {

               // ----------------------------------------------------------------------------------------------------------------------------------
               // Gestisce acquisizione chiavi 
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
               if (!StrJwtKeysHostAuthMode.equals("ANONYMOUS")) {

                  // Genera logging e acquisisce risorsa ESB proxy in formato XML
                  Logger.logProperty(LogLevel.DEBUG,"Host Auth Account",StrJwtKeysHostAccountPath);                  
                  XmlObject ObjServiceAccount = OSBUtils.getResource("ServiceAccount", StrJwtKeysHostAccountPath);

                  // Acquisisce credenziali
                  StrJwtKeysHostUserName = XMLUtils.getTextValue(ObjServiceAccount, "//*:username/text()");
                  StrJwtKeysHostPassword = XMLUtils.getTextValue(ObjServiceAccount, "//*:password/text()");
               }

               // Prepara parametri proxy
               if (!StrJwtKeysProxyServerMode.equals("DIRECT")) {
               
                  // Genera logging e acquisisce risorsa ESB proxy in formato XML
                  Logger.logProperty(LogLevel.DEBUG,"Proxy Server Resource",StrJwtKeysProxyServerPath);                  
                  XmlObject ObjProxyServer = OSBUtils.getResource("ProxyServer", StrJwtKeysProxyServerPath);

                  // Esegue parsing dei vari parametri del proxy
                  StrJwtKeysProxyHost = XMLUtils.getTextValue(ObjProxyServer, "//*:server/@host");
                  IntJwtKeysProxyPort = Integer.valueOf(XMLUtils.getTextValue(ObjProxyServer, "//*:server/@port"));
                  
                  // Prepara autenticazione proxy
                  if (!StrJwtKeysProxyServerMode.equals("ANONYMOUS")) {
   
                      // Acquisisce credenziali
                      StrJwtKeysProxyUserName = XMLUtils.getTextValue(ObjProxyServer, "//*:username/text()");
                      StrJwtKeysProxyPassword = XMLUtils.getTextValue(ObjProxyServer, "//*:password/text()");
                  }
               }
               
               // Acquisisce payload delle chiavi pubbliche in formato stringa
               String StrJwtKeys = HttpUtils.fetch(HttpMethod.GET, StrJwtKeysURL,  
                                                   StrJwtKeysFormat.equals("XML")?("text/xml"):("application/json"),
                                                   StrJwtKeysHostAuthMode, StrJwtKeysHostUserName, StrJwtKeysHostPassword,
                                                   StrJwtKeysProxyServerMode, StrJwtKeysProxyUserName, StrJwtKeysProxyPassword,
                                                   StrJwtKeysProxyHost,IntJwtKeysProxyPort, StrJwtKeysSSLVerify.equals("ENABLE"), 
                                                   IntJwtKeysConnTimeout, IntJwtKeysReadTimeout, Logger);
               
               // ----------------------------------------------------------------------------------------------------------------------------------
               // Gestisce parsing e caching delle chiavi
               // ----------------------------------------------------------------------------------------------------------------------------------

               // Inizializza variabile
               XmlObject ObjJwtKeys;
                        
                  // Gestisce parsing json o xml
               if (StrJwtKeysFormat.equals("XML")) {

                  // Genera logging
                  Logger.logProperty(LogLevel.TRACE,"Payload (XML)",StrJwtKeys);

                  // Acquisisce chiavi in formato xml
                  ObjJwtKeys = XmlObject.Factory.parse(StrJwtKeys);

               } else {

                  // Acquisisce payload in formato json
                  JSONObject ObjJSON = new JSONObject(StrJwtKeys);

                  // Genera logging
                  Logger.logProperty(LogLevel.TRACE,"Payload (JSON)",ObjJSON.toString());

                  // Converte da JSON a XML
                  StrJwtKeys = "<root>"+XML.toString(ObjJSON)+"</root>";
                                                   
                  // Genera logging
                  Logger.logProperty(LogLevel.TRACE,"Payload (XML)",StrJwtKeys);

                  // Acquisisce chiavi dal formato xml
                  ObjJwtKeys = XmlObject.Factory.parse(StrJwtKeys);
               }

               // Prepara espressioni xpath e logging
               String StrJwtKeysModulusParsedXPath = StringUtils.replaceTemplates(Context,StrJwtKeysModulusXPath);
               Logger.logProperty(LogLevel.DEBUG,"Modulus XPath Parsed",StrJwtKeysModulusParsedXPath);

               String StrJwtKeysExponentParsedXPath = StringUtils.replaceTemplates(Context,StrJwtKeysExponentXPath);
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
            
         // ==================================================================================================================================
         // Determina l'identità
         // ==================================================================================================================================

         // Genera logging
         Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
         Logger.logMessage(LogLevel.DEBUG,"IDENTITY ASSERTION");
         Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
         
         // Se l'asserzione di identità non è definita esegue, altrimenti procede
         if (!StrJwtIdentityAssertion.equals("")) {
            
            try {
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
         }

         // Genera logging
         Logger.logMessage(LogLevel.DEBUG,"Token Identity ....: " + Context.getIdentity());
            
         // ==================================================================================================================================
         // Gestisce l'eventuale identity mapping
         // ==================================================================================================================================         
         if (StrJwtIdentityMappingMode.equals("DISABLE")) {

            // Pone lo username pari all'identità 
            Context.putUserName(Context.getIdentity());
            
         } else {            
            try {               
               
               // Se presenti rimpiazza i template nel path della risorsa osb
               StrJwtIdentityMappingPath = StringUtils.replaceTemplates(Context,StrJwtIdentityMappingPath);
               
               // Genera logging
               Logger.logMessage(LogLevel.DEBUG,"Mapping Account ...: "+StrJwtIdentityMappingPath);
               
               // Prova a mappare l'identità allo username mediante un service account OSB di mapping
               Context.putUserName(OSBUtils.getMappedUser(StrJwtIdentityMappingPath,Context.getIdentity()));

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
      // Valuta l'eventuale script di validazione
      // ==================================================================================================================================
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
      // Se sono presenti custom headers li gestisce
      // ==================================================================================================================================                            
      if ((ObjCustomRequestHeaders!=null)||(ObjCustomResponseHeaders!=null)) {

         // Genera logging
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
         Logger.logMessage(LogLevel.DEBUG,"CUSTOM HEADERS");
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");

         // Gestisce cutom request headers              
         if (ObjCustomRequestHeaders!=null) {    
            HttpServletRequest ObjRequest = (HttpServletRequest) Context.get("http.request");        
            for (String StrHeaderName : ObjCustomRequestHeaders.stringPropertyNames()) {
               try {
                  String StrHeaderValue = StringUtils.replaceTemplates(Context,ObjCustomRequestHeaders.getProperty(StrHeaderName));
                  
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
         if (ObjCustomResponseHeaders!=null) {    
            HttpServletResponse ObjResponse = (HttpServletResponse) Context.get("http.response");        
            for (String StrHeaderName : ObjCustomResponseHeaders.stringPropertyNames()) {
               try {
                  String StrHeaderValue = StringUtils.replaceTemplates(Context,ObjCustomResponseHeaders.getProperty(StrHeaderName));
                  
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
      // Se sono presenti proprietà da mandare in debug le gestisce
      // ==================================================================================================================================
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
      // Gestione logging informativo finale dell'asserzione
      // ==================================================================================================================================
      try {
         // Genera logging di sintesi della asserzione
         Logger.logMessage(LogLevel.INFO,"Inbound ("+Context.getAuthType()+") => "+StringUtils.replaceTemplates(Context,StrLoggingInfo));
      } catch (Exception ObjException) {
         String StrError = "Logging info error";
         Logger.logMessage(LogLevel.WARN,StrError,ObjException);
      }         
      
      // Restituisce utente autenticato
      return new CustomIdentityAsserterCallbackHandlerImpl(Context.getUserName());
   }

   // ##################################################################################################################################
   // Metodi privati di supporto
   // ##################################################################################################################################
    
   // ==================================================================================================================================
   // Verifica se un parametro obbligatorio e valorizzato
   // ==================================================================================================================================
   private static Object validateParameter(String StrParameterName,Object ObjParameterValue) throws IdentityAssertionException {
         
      // Prepara logger & context
      LogManager Logger = getLogger();
      RuntimeContext Context = getContext();
      
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
      
      // Restituisce valore eventualmente corretto con trim
      return ObjParameterValue;
   }   
   
   // ==================================================================================================================================
   // Esegue parsing del token e rileva la modalità di autenticazione
   // ==================================================================================================================================      
   private static String prepareToken(String StrTokenType,Object ObjToken) throws Exception {
         
      // Prepara logger e context
      LogManager Logger = getLogger();
      RuntimeContext Context = getContext();
   
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
      String StrToken = (String)ObjToken;
      
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
      
      // Restituisce payload del token
      return StrToken;
   }     
   
   // ==================================================================================================================================
   // Prepare runtime context
   // ==================================================================================================================================
   private void prepareContext(ContextHandler ObjRequestContext) {
         
      // Prepara logger & context
      LogManager Logger = getLogger();
      RuntimeContext Context = getContext();
         
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
      Context.put("thread",Thread.currentThread().getId());   
      Context.put("counter",Thread.currentThread().getName());   
      Context.put("provider",StrProviderName);   
      Context.put("instance",StrInstanceName);   
      Context.put("datetime",new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date(System.currentTimeMillis())));          
      Context.put("timestamp",System.currentTimeMillis());            

      // Contesto weblogic     
      Context.put("wls.realm",StrRealmName);   
      Context.put("wls.domain",StrDomainName);   
      Context.put("wls.managed",StrManagedName);   

      // Contesto java
      Context.put("java.version",JavaUtils.getJavaVersion()); 
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
      Context.put("http.content.body",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            HttpServletRequest ObjRequest = (HttpServletRequest) ObjContext.get("http.request");
            return IOUtils.toString(ObjRequest.getInputStream());
         }
      });             
      Context.put("http.header.*",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            HttpServletRequest ObjRequest = (HttpServletRequest) ObjContext.get("http.request");
            return Logger.formatProperties(LogLevel.DEBUG,HttpUtils.getHeaders(ObjRequest, Arrays.asList("Authorization")),StringUtils.repeat(90,"-"),false);
         }
      });        
      Context.put("token.header.*",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            JWTToken ObjJwtToken = (JWTToken) ObjContext.get("token"); 
            return ((ObjJwtToken!=null)&&(ObjJwtToken.isReady()))?(Logger.formatProperties(LogLevel.DEBUG,ObjJwtToken.getHeader(),StringUtils.repeat(90,"-"),true)):("");
         }
      });                                                         
      Context.put("token.payload.*",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            JWTToken ObjJwtToken = (JWTToken) ObjContext.get("token"); 
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
            JWTToken ObjJwtToken = (JWTToken) ObjContext.get("token"); 
            return ((ObjJwtToken!=null)&&(ObjJwtToken.isReady()))?((String) ObjJwtToken.getHeader().get(StrVariableName.split("\\.")[2])):("");
         }
      });       
      Context.putRegex("^token\\.payload\\.[^\\.]*$",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            JWTToken ObjJwtToken = (JWTToken) ObjContext.get("token"); 
            return (ObjJwtToken!=null)?((String) ObjJwtToken.getPayload().get(StrVariableName.split("\\.")[2])):("");
         }
      });
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
   // Inizializza nome del thread (contatore di esecuzione)
   // ==================================================================================================================================
   private synchronized void setThreadName()  {
      Thread.currentThread().setName(StringUtils.padLeft(String.valueOf(IntThreadCount++),7,"0"));
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
   // Acquisisce context di thread
   // ==================================================================================================================================    
   private static RuntimeContext getContext() {      
      return ObjThreadContext.get();   
   }    

   // ==================================================================================================================================
   // Crea nuovo context di thread
   // ==================================================================================================================================    
   private RuntimeContext createContext() {   
      RuntimeContext ObjContext = new RuntimeContext();      
      ObjThreadContext.set(ObjContext);
      return ObjContext;   
   }    
}
