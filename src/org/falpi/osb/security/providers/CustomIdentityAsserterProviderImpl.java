package org.falpi.osb.security.providers;

// ##################################################################################################################################
// Referenze
// ##################################################################################################################################

import java.net.URL;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.SimpleDateFormat;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

import java.util.Map;
import java.util.Date;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HashMap;
import java.util.Enumeration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedAction;

import javax.security.auth.Subject;
import javax.security.auth.spi.LoginModule;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.AppConfigurationEntry;

import javax.xml.namespace.QName;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
import org.apache.commons.codec.binary.Base64;

import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlCursor;
import org.apache.xmlbeans.XmlOptions;

import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.NTCredentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.impl.auth.NTLMSchemeFactory;
import org.apache.http.impl.auth.BasicSchemeFactory;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.auth.SPNegoSchemeFactory;
import org.apache.http.ssl.SSLContextBuilder;

import com.bea.wli.config.Ref;
import com.bea.wli.sb.ALSBConfigService;
import com.bea.wli.sb.services.ServiceInfo;
import com.bea.wli.sb.transports.TransportEndPoint;
import com.bea.wli.security.encryption.PBE_EncryptionService;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.JWSObject.State;

import org.json.XML;
import org.json.JSONObject;

public final class CustomIdentityAsserterProviderImpl implements AuthenticationProviderV2, IdentityAsserterV2 {

   // ##################################################################################################################################
   // Dichiara sottoclassi 
   // ##################################################################################################################################
   
   // ==================================================================================================================================
   // Livelli di logging
   // ==================================================================================================================================
   
   static class LogLevel {
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
   
   // ==================================================================================================================================
   // Tipologie di token supportate
   // ==================================================================================================================================
   
   static class TokenTypes {
      public final static String JWT_AUTH_ID = "JWT";
      public final static String BASIC_AUTH_ID = "BASIC";

      public final static String TOKEN_PREFIX = "CIA.";
      public final static String JWT_TYPE = TOKEN_PREFIX+JWT_AUTH_ID;
      public final static String BASIC_TYPE = TOKEN_PREFIX+BASIC_AUTH_ID;
      public final static String ALL_TYPE = TOKEN_PREFIX+JWT_AUTH_ID+"+"+BASIC_AUTH_ID;
   } 
   
   // ##################################################################################################################################
   // Dichiara variabili
   // ##################################################################################################################################

   // ==================================================================================================================================
   // Variabili di istanza
   // ==================================================================================================================================

   // Gestione del logging
   private int IntLoggingLevel = LogLevel.DEBUG;
   private int IntLoggingLevelMin = LogLevel.TRACE;
   private String StrLoggingLevel;

   // Gestione dell'identificazione
   private String StrAuthType = "";
   private String StrIdentity = "";
   private String StrUserName = "";
   
   // Variabili di contesto
   private String StrRealmName;
   private String StrDomainName;
   private String StrServerName;
   private String StrProjectName;   
   private String StrServiceName;
   
   private ServiceInfo ObjService;
   private TransportEndPoint ObjEndpoint;
   private HttpServletRequest ObjRequest;
   private HttpServletResponse ObjResponse; 
   
   // Gestione del token jwt
   private String StrJwtKeyID;
   private SignedJWT ObjSignedJWT;
   private HashMap ObjJwtKeysCache = new HashMap();
        
   // Altre variabili di supporto
   private String StrDescription = "";   
   private String StrKerberosConfiguration = "";

   private ScriptEngine ObjScriptEngine;
   private CustomIdentityAsserterMBean ObjProviderMBean;
   
   private AuthenticatedSubject ObjKernelId;
   private EmbeddedLDAPAtnDelegate ObjEmbeddedAuthenticator;
   
   // ##################################################################################################################################
   // Implementa metodi di supporto
   // ##################################################################################################################################

   @Override
   public void initialize(ProviderMBean ObjMBean, SecurityServices ObjSecurityServices) {

      // Genera logging
      LogMessage(LogLevel.INFO,"##########################################################################################");
      LogMessage(LogLevel.INFO,"INITIALIZE");
      LogMessage(LogLevel.INFO,"##########################################################################################");
      
      // Inizializza lo mbean
      ObjProviderMBean = (CustomIdentityAsserterMBean) ObjMBean;

      // Inizializza descrizione
      StrDescription = ObjMBean.getDescription() + "n" + ObjMBean.getVersion();
      
      // Inizializza lo script engine javascript
      ObjScriptEngine =  new ScriptEngineManager().getEngineByName("JavaScript");   
         
      // Inizializza provider di autenticazione di default per supporto alla basic authentication
      ObjKernelId = (AuthenticatedSubject) AccessController.doPrivileged(PrivilegedActions.getKernelIdentityAction());
      
      StrRealmName = ObjProviderMBean.getRealm().getName();
      StrDomainName = ManagementService.getRuntimeAccess(ObjKernelId).getDomainName();
      StrServerName = ManagementService.getRuntimeAccess(ObjKernelId). getServerName();
      
      ObjEmbeddedAuthenticator = new EmbeddedLDAPAtnDelegate(ObjMBean, null,StrRealmName, StrDomainName, false);     
      
      // Se necessario genera logging di debug
      LogMessage(LogLevel.INFO,"==========================================================================================");
      LogMessage(LogLevel.INFO,"CONTEXT");
      LogMessage(LogLevel.INFO,"==========================================================================================");
      LogMessage(LogLevel.INFO,"Realm Name: " + StrRealmName);
      LogMessage(LogLevel.INFO,"Domain Name: " + StrDomainName);
      LogMessage(LogLevel.INFO,"Server Name: " + StrServerName);
      LogMessage(LogLevel.INFO,"##########################################################################################");      
   }

   @Override
   public void shutdown() {
      LogMessage(LogLevel.INFO,"##########################################################################################");      
      LogMessage(LogLevel.INFO,"SHUTDOWN");
      LogMessage(LogLevel.INFO,"##########################################################################################");      
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
                     
      StrLoggingLevel = ObjProviderMBean.getLOGGING_LEVEL();
      String StrBasicAuthStatus = ObjProviderMBean.getBASIC_AUTH_STATUS();
      String StrJwtAuthStatus = ObjProviderMBean.getJWT_AUTH_STATUS();
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
      String[] ArrKerberosConfiguration = ObjProviderMBean.getKERBEROS_CONFIGURATION();      
            
      // Comprime gli array multiriga
      String StrJwtIdentityAssertion = joinStringArray(ArrJwtIdentityAssertion,System.lineSeparator());
      String StrValidationAssertion = joinStringArray(ArrValidationAssertion,System.lineSeparator());
      String StrDebuggingAssertion = joinStringArray(ArrDebuggingAssertion,System.lineSeparator());
      String StrDebuggingProperties = joinStringArray(ArrDebuggingProperties,",");
      StrKerberosConfiguration = joinStringArray(ArrKerberosConfiguration,System.lineSeparator());
      
      // ==================================================================================================================================
      // Imposta livelli di logging
      // ==================================================================================================================================

      IntLoggingLevel = LogLevel.getLevel(StrLoggingLevel);
      IntLoggingLevelMin = LogLevel.TRACE;

      // Genera logging 
      LogMessage(LogLevel.DEBUG,"##########################################################################################");
      LogMessage(LogLevel.DEBUG,"ASSERT IDENTITY");
      LogMessage(LogLevel.DEBUG,"##########################################################################################");
            
      // ==================================================================================================================================
      // Acquisisce contesto
      // ==================================================================================================================================

      ObjService = (ServiceInfo) ObjContext.getValue("com.bea.contextelement.alsb.service-info");
      //ObjEndpoint = (TransportEndPoint) ObjContext.getValue("com.bea.contextelement.alsb.transport.endpoint");
      ObjRequest = (HttpServletRequest) ObjContext.getValue("com.bea.contextelement.alsb.transport.http.http-request");
      //ObjResponse = (HttpServletResponse) ObjContext.getValue("com.bea.contextelement.alsb.transport.http.http-response");
      
      StrProjectName = ObjService.getRef().getProjectName();
      StrServiceName = ObjService.getRef().getLocalName();
      
      // ==================================================================================================================================
      // Valuta l'abilitazione del logging (eventuali errori sono silenziati per non pregiudicare l'autenticazione)
      // ==================================================================================================================================

      // Se ecessario verifica del filtro per i messaggi di log di livello più basso
      if (!StrDebuggingAssertion.equals("")) {
         try {
            if (!((Boolean) evaluateScript(StrDebuggingAssertion,"Boolean"))) {
               IntLoggingLevelMin = LogLevel.INFO;
            }
         } catch (Exception ObjException) {
            String StrError = "Debugging assertion error";
            LogMessage(LogLevel.WARN,StrError,ObjException.getMessage());
         }
      }

      // ==================================================================================================================================
      // Se logging  attivo genera loggini preliminare
      // ==================================================================================================================================

      // Se necessario genera logging di debug
      LogMessage(LogLevel.DEBUG,"==========================================================================================");
      LogMessage(LogLevel.DEBUG,"CONFIGURATION");
      LogMessage(LogLevel.DEBUG,"==========================================================================================");
      LogMessage(LogLevel.DEBUG,"LOGGING_LEVEL: " + StrLoggingLevel);
      LogMessage(LogLevel.DEBUG,"BASIC_AUTH_STATUS: " + StrBasicAuthStatus);
      LogMessage(LogLevel.DEBUG,"JWT_AUTH_STATUS: " + StrJwtAuthStatus);
      LogMessage(LogLevel.DEBUG,"JWT_KEYS_URL: " + StrJwtKeysURL);
      LogMessage(LogLevel.DEBUG,"JWT_KEYS_FORMAT: " + StrJwtKeysFormat);
      LogMessage(LogLevel.DEBUG,"JWT_KEYS_MODULUS_XPATH: " + StrJwtKeysModulusXPath);
      LogMessage(LogLevel.DEBUG,"JWT_KEYS_EXPONENT_XPATH: " + StrJwtKeysExponentXPath);
      LogMessage(LogLevel.DEBUG,"JWT_KEYS_CACHE_TTL: " + IntJwtKeysCacheTTL);
      LogMessage(LogLevel.DEBUG,"JWT_KEYS_CONN_TIMEOUT: " + IntJwtKeysConnTimeout);
      LogMessage(LogLevel.DEBUG,"JWT_KEYS_READ_TIMEOUT: " + IntJwtKeysReadTimeout);
      LogMessage(LogLevel.DEBUG,"JWT_KEYS_SSL_VERIFY: " + StrJwtKeysSSLVerify);
      LogMessage(LogLevel.DEBUG,"JWT_KEYS_HOST_AUTH_MODE: " + StrJwtKeysHostAuthMode);
      LogMessage(LogLevel.DEBUG,"JWT_KEYS_HOST_ACCOUNT_PATH: " + StrJwtKeysHostAccountPath);
      LogMessage(LogLevel.DEBUG,"JWT_KEYS_PROXY_SERVER_MODE: " + StrJwtKeysProxyServerMode);
      LogMessage(LogLevel.DEBUG,"JWT_KEYS_PROXY_SERVER_PATH: " + StrJwtKeysProxyServerPath);
      LogMessage(LogLevel.DEBUG,"JWT_IDENTITY_MAPPING_MODE: " + StrJwtIdentityMappingMode);
      LogMessage(LogLevel.DEBUG,"JWT_IDENTITY_MAPPING_PATH: " + StrJwtIdentityMappingPath);
      LogMessage(LogLevel.DEBUG,"JWT_IDENTITY_ASSERTION: " + StrJwtIdentityAssertion.replaceAll("\n",""));
      LogMessage(LogLevel.DEBUG,"VALIDATION_ASSERTION: " + StrValidationAssertion.replaceAll("\n",""));
      LogMessage(LogLevel.DEBUG,"DEBUGGING_ASSERTION: " + StrDebuggingAssertion.replaceAll("\n",""));
      LogMessage(LogLevel.DEBUG,"DEBUGGING_PROPERTIES: " + StrDebuggingProperties);      
      LogMessage(LogLevel.DEBUG,"KERBEROS_CONFIGURATION: " + StrKerberosConfiguration);      
      LogMessage(LogLevel.DEBUG,"==========================================================================================");
      LogMessage(LogLevel.DEBUG,"CONTEXT");
      LogMessage(LogLevel.DEBUG,"==========================================================================================");
      LogMessage(LogLevel.DEBUG,"Server Name: "+StrServerName);
      LogMessage(LogLevel.DEBUG,"Project Name: "+StrProjectName);
      LogMessage(LogLevel.DEBUG,"Service Name: "+StrServiceName);               
      
      // ==================================================================================================================================
      // Verifica che le informazioni sul token ricevuto sono corrette e coerenti con i tipi attivi
      // ==================================================================================================================================

      // Verifica la tipologia del token
      if (!(ObjToken.getClass().getSimpleName()).equals("String")) {
         String StrError = "Unsupported token class";
         LogMessage(LogLevel.ERROR,StrError,ObjToken.getClass().getSimpleName());
         throw new IdentityAssertionException(StrError);
      }

      // Verifica la correttezza del tipo di token
      if (!Arrays.asList(TokenTypes.JWT_TYPE, TokenTypes.BASIC_TYPE, TokenTypes.ALL_TYPE).contains(StrTokenType)) {        
         String StrError = "Unknown token type";
         LogMessage(LogLevel.ERROR,StrError,StrTokenType);
         throw new IdentityAssertionException(StrError);
      }

      // Se necessario genera logging di debug
      LogMessage(LogLevel.DEBUG,"Selected Token Type: "+StrTokenType);
      
      // ==================================================================================================================================
      // Esegue parsing del token e verifica la modalità di autenticazione
      // ==================================================================================================================================
      
      // Verifica se il token in ingresso è un BASIC o un JWT
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
      LogMessage(LogLevel.DEBUG,"Detected Auth Type: "+StrAuthType);

      // Verifica la ammissibilità dell'autenticazione rilevata rispetto al token selezionato e ai flag di disattivazione
      if ((!StrTokenType.contains(StrAuthType))||
          (StrAuthType.equals(TokenTypes.JWT_AUTH_ID)&&StrJwtAuthStatus.equals("DISABLE"))||
          (StrAuthType.equals(TokenTypes.BASIC_AUTH_ID)&&StrBasicAuthStatus.equals("DISABLE"))) {
         String StrError = "Disabled auth type";
         LogMessage(LogLevel.ERROR,StrError,StrAuthType);
         throw new IdentityAssertionException(StrError);
      }
        
      // ==================================================================================================================================
      // Gestisce l'autenticazione BASIC
      // ==================================================================================================================================
      
      // Se si tratta di una basic authentication prova ad autenticare l'utenza con le credenziali fornite      
      if (StrAuthType.equals(TokenTypes.BASIC_AUTH_ID)) {
         
         // Se necessario genera logging di debug
         LogMessage(LogLevel.DEBUG,"==========================================================================================");
         LogMessage(LogLevel.DEBUG,"BASIC AUTH");
         LogMessage(LogLevel.DEBUG,"==========================================================================================");  
                           
         try {          
                        
            // Dedodifica il token basic
            String[] ArrCredential = new String(Base64.decodeBase64(StrJwtPayload)).split(":",2);            
            LogMessage(LogLevel.DEBUG,"UserName: "+ArrCredential[0]);   
            
            // Prova ad autenticare le credenziali sul realm weblogic
            StrUserName = ObjEmbeddedAuthenticator.authenticate(ArrCredential[0], ArrCredential[1]);
            
            // Se l'utenza non è autenticata genera eccezione
            if ((StrUserName==null)||StrUserName.equals("")) {
               throw new Exception("wrong credentials");
            }
                  
         } catch (Exception ObjException) {
            String StrError = "Basic auth error";
            LogMessage(LogLevel.ERROR,StrError,ObjException.getMessage());
            throw new IdentityAssertionException(StrError);        
         }      
      }
 
      // ==================================================================================================================================
      // Gestisce l'autenticazione JWT
      // ==================================================================================================================================

      if (StrAuthType.equals(TokenTypes.JWT_AUTH_ID)) {   
         
         // Se necessario genera logging di debug
         LogMessage(LogLevel.DEBUG,"==========================================================================================");
         LogMessage(LogLevel.DEBUG,"JWT AUTH");
         LogMessage(LogLevel.DEBUG,"==========================================================================================");
               
         try {            
            
            // Decodifica il token JWT
            ObjSignedJWT = SignedJWT.parse(StrJwtPayload);
            
            // Acquisisce l'id della chiave di firma del token
            StrJwtKeyID = ObjSignedJWT.getHeader().getKeyID();        
            
         } catch (Exception ObjException) {
            String StrError = "Token parsing error";
            LogMessage(LogLevel.ERROR,StrError,ObjException.getMessage());
            throw new IdentityAssertionException(StrError);        
         }
            
         // ==================================================================================================================================
         // Prepara chiave di firma
         // ==================================================================================================================================

         // Dichiara variabili         
         String StrKeyModulus;
         String StrKeyExponent;
         Number IntSystemTimeStamp = System.currentTimeMillis();

         // Verifica se la chiave è già in cache         
         HashMap ObjKey = (HashMap) ObjJwtKeysCache.get(StrJwtKeyID);
         
         // Se la chiave è in cache e il suo timestamp è valido esegue altrimenti procede
         if ((ObjKey!=null)&&
             ((IntSystemTimeStamp.longValue()-((Number)ObjKey.get("timestamp")).longValue())<(IntJwtKeysCacheTTL*1000))) {
            
            // Acuisisce parametri chiave dalla cache
            StrKeyModulus = (String) ObjKey.get("modulus");
            StrKeyExponent = (String) ObjKey.get("exponent");            
            
         } else {
                           
            // Acquisisce elenco chiavi di firma via http
            try {
               
               // Se necessario genera logging di debug
               LogMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
               LogMessage(LogLevel.DEBUG,"KEYS RETRIEVE");
               LogMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");

               // Acquisisce payload delle chiavi pubbliche in formato stringa
               String StrJwtKeys = getHttpResource(StrJwtKeysURL, 
                                                   StrJwtKeysFormat.equals("XML")?("text/xml"):("application/json"),
                                                   StrJwtKeysHostAuthMode, StrJwtKeysHostAccountPath,
                                                   StrJwtKeysProxyServerMode, StrJwtKeysProxyServerPath, 
                                                   StrJwtKeysSSLVerify.equals("ENABLE"), 
                                                   IntJwtKeysConnTimeout, IntJwtKeysReadTimeout);

               // Inizializza
               XmlObject ObjJwtKeys;
                        
                  // Gestisce parsing json o xml
               if (StrJwtKeysFormat.equals("XML")) {

                  // Se necessario genera logging di debug
                  LogMessage(LogLevel.DEBUG, "Payload (XML):" + StrJwtKeys);

                  // Acquisisce chiavi in formato xml
                  ObjJwtKeys = XmlObject.Factory.parse(StrJwtKeys);

               } else {

                  // Acquisisce payload in formato json
                  JSONObject ObjJSON = new JSONObject(StrJwtKeys);

                  // Se necessario genera logging di debug
                  LogMessage(LogLevel.DEBUG,"Payload (JSON): " + ObjJSON.toString());

                  // Converte da JSON a XML
                  StrJwtKeys = "<root>"+XML.toString(ObjJSON)+"</root>";
                                                   
                  // Se necessario genera logging di debug
                  LogMessage(LogLevel.DEBUG, "Payload (XML): " + StrJwtKeys);

                  // Acquisisce chiavi dal formato xml
                  ObjJwtKeys = XmlObject.Factory.parse(StrJwtKeys);
               }

               // Prepara espressioni xpath ed eventuale logging
               String StrJwtKeysModulusParsedXPath = replaceTemplates(StrJwtKeysModulusXPath);
               LogMessage(LogLevel.DEBUG,"Modulus XPath Parsed: "+StrJwtKeysModulusParsedXPath);

               String StrJwtKeysExponentParsedXPath = replaceTemplates(StrJwtKeysExponentXPath);
               LogMessage(LogLevel.DEBUG,"Exponent XPath Parsed: "+StrJwtKeysExponentParsedXPath);            

               // Estrapola modulo ed esponente
               StrKeyModulus = getXMLTextValue(ObjJwtKeys,StrJwtKeysModulusParsedXPath);
               StrKeyExponent = getXMLTextValue(ObjJwtKeys,StrJwtKeysExponentParsedXPath);
               
               // Se non è stata trovata alcuna chiave genera eccezione
               if (StrKeyModulus.equals("")||StrKeyExponent.equals("")) {
                  throw new Exception("unable to extract key");
               }               
            } catch (Exception ObjException) {
               String StrError = "Error retrieving keys";
               LogMessage(LogLevel.ERROR,StrError,ObjException.getMessage());
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
         LogMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
         LogMessage(LogLevel.DEBUG,"TOKEN VALIDATION");
         LogMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");

         // Se necessario genera logging di debug
         LogMessage(LogLevel.DEBUG,"Key ID: "+StrJwtKeyID);
         LogMessage(LogLevel.DEBUG,"Key Modulus: "+StrKeyModulus);
         LogMessage(LogLevel.DEBUG,"Key Exponent: "+StrKeyExponent);            

         try {
            // Verifica token jwt
            verifyJwt(ObjSignedJWT, StrKeyModulus, StrKeyExponent);            
            
         } catch (Exception ObjException) {
            String StrError = "Error validating token";
            LogMessage(LogLevel.ERROR,StrError,ObjException.getMessage());
            throw new IdentityAssertionException(StrError);
         }
         
            
         // ==================================================================================================================================
         // Determina l'identità
         // ==================================================================================================================================

         // Se necessario genera logging di debug
         LogMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
         LogMessage(LogLevel.DEBUG,"IDENTITY ASSERTION");
         LogMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
         
         // Se l'asserzione di identità non è definita esegue, altrimenti procede
         if (!StrJwtIdentityAssertion.equals("")) {
            
            // Estrapola l'identità dallo script di asserzione
            try {
               StrIdentity = (String) evaluateScript(StrJwtIdentityAssertion,"String");     
                           
               if (StrIdentity.equals("")) {
                  throw new Exception("evaluate to blank");               
               }
               
            } catch (Exception ObjException) {
               String StrError = "Identity assertion error";
               LogMessage(LogLevel.ERROR,StrError,ObjException.getMessage());
               throw new IdentityAssertionException(StrError);
            }
         }

         // Se necessario genera logging di debug
         LogMessage(LogLevel.DEBUG,"Token Identity: " + StrIdentity);
            
         // ==================================================================================================================================
         // Gestisce l'eventuale identity mapping
         // ==================================================================================================================================
         
         // Se non è richiesto il mapping esegue, altrimenti procede
         if (StrJwtIdentityMappingMode.equals("DISABLE")) {
            
            // Pone lo username pari all'identità 
            StrUserName = StrIdentity;
            
         } else {            
            try {               
               
               // Se presenti rimpiazza i template nel path della risorsa osb
               StrJwtIdentityMappingPath = replaceTemplates(StrJwtIdentityMappingPath);
               
               // Genera logging di debug
               LogMessage(LogLevel.DEBUG,"Mapping Service Account: "+StrJwtIdentityMappingPath);
               
               // Prova a mappare l'identità allo username mediante un service account OSB di mapping
               StrUserName = getOSBMappedUser(StrJwtIdentityMappingPath,StrIdentity);

               // Se il mapping è fallito genera eccezione
               if (StrUserName.equals("")) {
                  throw new Exception("unknown identity");               
               }            
            } catch (Exception ObjException) {
               String StrError = "Identity mapping error";
               LogMessage(LogLevel.ERROR,StrError,ObjException.getMessage());
               throw new IdentityAssertionException(StrError);
            }
         }
         
         // Se necessario genera logging di debug
         LogMessage(LogLevel.DEBUG,"Realm UserName: " + StrUserName);
      }
      
      // ==================================================================================================================================
      // Valuta l'eventuale script di validazione
      // ==================================================================================================================================

      if (!StrValidationAssertion.equals("")) {

         // Se necessario genera logging di debug
         LogMessage(LogLevel.DEBUG,"==========================================================================================");
         LogMessage(LogLevel.DEBUG,"VALIDATION ASSERTION");
         LogMessage(LogLevel.DEBUG,"==========================================================================================");
         
         try {
            // Se l'espressione di validazione è positiva genera logging altrimenti eccezione
            if ((Boolean) evaluateScript(StrValidationAssertion,"Boolean"))  {
               LogMessage(LogLevel.DEBUG,"Result: TRUE");
            } else {
               LogMessage(LogLevel.DEBUG,"Result: FALSE");
               throw new Exception("evaluate to false");               
            }
         } catch (Exception ObjException) {
            String StrError = "Validation assertion error";
            LogMessage(LogLevel.ERROR,StrError,ObjException.getMessage());
            throw new IdentityAssertionException(StrError);
         }
      }
      
      // ==================================================================================================================================
      // Se sono presenti proprietà da mandare in debug le gestisce
      // ==================================================================================================================================

      if (ArrDebuggingProperties.length>0) {

         // Se necessario genera logging di debug
         LogMessage(LogLevel.DEBUG,"==========================================================================================");
         LogMessage(LogLevel.DEBUG,"LOGGING PROPERTIES");
         LogMessage(LogLevel.DEBUG,"==========================================================================================");
         
         try {
            for (String StrProperty : ArrDebuggingProperties) {
               LogMessage(LogLevel.DEBUG,StrProperty+" => "+replaceTemplates(StrProperty));
            }  
         } catch (Exception ObjException) {
            String StrError = "Debug properties error";
            LogMessage(LogLevel.WARN,StrError,ObjException.getMessage());
         }
      }
      
      LogMessage(LogLevel.DEBUG,"##########################################################################################");

      // Restituisce utente autenticato
      return new CustomIdentityAsserterCallbackHandlerImpl(StrUserName);
   }

   // ##################################################################################################################################
   // Evaluate Script
   // ##################################################################################################################################
   public Object evaluateScript(String StrScript, String StrClassName) throws Exception {
            
      // ==================================================================================================================================
      // Esegue lo script e ne verifica la classe di output
      // ==================================================================================================================================
      
      // Esegue lo script fornito
      Object ObjResult = ObjScriptEngine.eval(replaceTemplates(StrScript));
      String StrResultClassName = ObjResult.getClass().getSimpleName();
      
      // Se la tipologia di oggetto restituita non è quella attesa genera eccezione
      if (!StrResultClassName.equals(StrClassName)) {
         throw new Exception("expression must return '"+StrClassName+"' instead of '"+StrResultClassName+"'");
      }

      // Restrituisce l'oggetto risultante
      return ObjResult;
   }

   // ##################################################################################################################################
   // Evaluate templates
   // ##################################################################################################################################
   public String replaceTemplates(String StrText) throws Exception {
      
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
                        case "service": StrVariableValue = StrServiceName; break;
                     }
                     break;
               }
               break;
            
            case 3:
               switch (ArrVariableTokens[0]) {
                  case "token" :
                     switch (ArrVariableTokens[1]) {
                        case "header": StrVariableValue = (String) ObjSignedJWT.getHeader().toJSONObject().get(ArrVariableTokens[2]); break;
                        case "payload": StrVariableValue = (String) ObjSignedJWT.getPayload().toJSONObject().get(ArrVariableTokens[2]); break;
                     }
                     break;
                  case "http" :
                     switch (ArrVariableTokens[1]) {
                        case "client": 
                           switch (ArrVariableTokens[2]) {
                              case "host": StrVariableValue = ObjRequest.getRemoteHost(); break;
                              case "addr": StrVariableValue = ObjRequest.getRemoteAddr(); break;
                           }
                           break;
                        case "server": 
                           switch (ArrVariableTokens[2]) {
                              case "host": StrVariableValue = ObjRequest.getLocalName(); break;
                              case "addr": StrVariableValue = ObjRequest.getLocalAddr(); break;
                              case "name": StrVariableValue = ObjRequest.getServerName(); break;
                              case "port": StrVariableValue = String.valueOf(ObjRequest.getServerPort()) ; break;
                           }
                           break;
                        case "content": 
                           switch (ArrVariableTokens[2]) {
                              case "type": StrVariableValue = ObjRequest.getContentType(); break;
                              case "body": StrVariableValue = IOUtils.toString(ObjRequest.getReader()); break;
                              case "length": StrVariableValue = String.valueOf(ObjRequest.getContentLength()); break;
                           }
                           break;
                        case "request": 
                           switch (ArrVariableTokens[2]) {
                              case "url": StrVariableValue = ObjRequest.getRequestURL().toString(); break;
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
                              Enumeration ObjEnumeration = ObjRequest.getHeaderNames();
                              
                              // Costruire elenco header ad esclusione di "Authorization" per evitare dati sensibili nei log in caso di basic auth
                              StrVariableValue = "\n-------------------------------------------------\n";
                              while (ObjEnumeration.hasMoreElements()) {
                                 StrHeaderName = (String) ObjEnumeration.nextElement();
                                 if (!StrHeaderName.equals("Authorization")) {
                                    StrHeaderValue = ObjRequest.getHeader(StrHeaderName);
                                    StrVariableValue+= StrHeaderName+": "+StrHeaderValue+"\n";
                                 }
                              }
                              StrVariableValue+= "--------------------------------------------------";
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
         
         // Genera logging
         LogMessage(LogLevel.TRACE,"Template Variable #"+IntIndex+": "+StrTemplate+" => "+((StrVariableValue.equals("null")||StrVariableValue.equals(""))?("empty"):(StrVariableValue)));
         
         // Esegue sostituzione della variabile template         
         StrText = StrText.replace(StrTemplate,StrVariableValue);
      }
      
      // Restituisce stringa con i template sostituiti
      return StrText;
   }

   // ##################################################################################################################################
   // Acquisisce le informazioni sul contesto di sicurzza
   // ##################################################################################################################################
   public String getHttpResource(String StrRequestURL, 
                                 String StrContentType, 
                                 String StrAuthMode,String StrAuthPath, 
                                 String StrProxyMode, String StrProxyPath,
                                 Boolean BolSSLEnforce, int IntConnectTimeout,int IntRequestTimeout) throws Exception {

      // ==================================================================================================================================
      // Dichiara variabili
      // ==================================================================================================================================
      String StrPayload;
      HttpResponse ObjHttpResponse;
      final Map ObjContext = new HashMap();
      final CloseableHttpClient ObjHttpClient;
      final HttpGet ObjHttpRequest = new HttpGet(StrRequestURL);
      ArrayList<Object[]> ArrLoginContext = new ArrayList<Object[]>();

 
      // ==================================================================================================================================
      // Prepara la request e la esegue
      // ==================================================================================================================================
      ObjHttpClient = buildHttpClient(StrRequestURL, 
                                      StrAuthMode, StrAuthPath, StrProxyMode, StrProxyPath, 
                                      BolSSLEnforce, IntConnectTimeout, IntRequestTimeout, ArrLoginContext);
   
      // Se non è stato allocato alcun login context kerberos esegue, altrimenti procede
      if (ArrLoginContext.size() == 0) {
         
         // Esegue la request nel contesto ordinario, altimenti procede
         ObjHttpResponse = ObjHttpClient.execute(ObjHttpRequest);
                        
      } else {
         
         // Acquisisce i login context kerberos (al momento supportato solo un context)
         Object[] ArrObject = ArrLoginContext.get(0);
         LoginModule ObjLoginModule = (LoginModule) ArrObject[0];
         Subject ObjSubject = (Subject) ArrObject[1];
         
         // Racchiude la request in contesto privilegiato
         PrivilegedAction ObjAction = new PrivilegedAction() {
            @Override
            public Object run() {
               try {
                  ObjContext.put("response",ObjHttpClient.execute(ObjHttpRequest));
               } catch (Exception ObjException) {
                  ObjContext.put("exception",ObjException);
               }                       
               
               return true;
            }
         };

         // Esecuzione privilegiata della request
         Subject.doAs(ObjSubject, ObjAction);
         
         // Esegue logout e svuota l'array
         ObjLoginModule.logout();
         ArrLoginContext.clear();
         
         // Se c'è stata eccezione la genera
         if (ObjContext.containsKey("exception")) {
            throw (Exception) ObjContext.get("exception");
         }
         
         // Acquisisce response
         ObjHttpResponse = (HttpResponse) ObjContext.get("response");
      }

      // ==================================================================================================================================
      // Gestisce la response
      // ==================================================================================================================================

      // Se lo statuscode è diverso da 200 genera eccezione
      if (ObjHttpResponse.getStatusLine().getStatusCode() != 200) {
         throw new Exception("HTTP "+ObjHttpResponse.getStatusLine().getStatusCode() + " - " + ObjHttpResponse.getStatusLine().getReasonPhrase());
      }

      // Se il content-type non è corretto genera eccezione
      if (!ObjHttpResponse.getEntity().getContentType().getValue().startsWith(StrContentType)) {
         throw new Exception("Unexpected content-type '" + ObjHttpResponse.getEntity().getContentType().getValue() + "'");
      }

      // Acquisisce payload in formato testo
      StrPayload = IOUtils.toString(ObjHttpResponse.getEntity().getContent());

      // Restituisce payload al chiamante
      return StrPayload;
   }

   // ##################################################################################################################################
   // Acquisisce le informazioni sul contesto di sicurzza
   // ##################################################################################################################################
   public CloseableHttpClient buildHttpClient(String StrRequestURL, 
                                              String StrHostAuthMode, String StrHostAccountPath, 
                                              String StrProxyAuthMode, String StrProxyServerPath, 
                                              Boolean BolSSLEnforce, int IntConnectTimeout,int IntRequestTimeout,
                                              ArrayList<Object[]> ArrLoginContext) throws Exception {
               
      // ==================================================================================================================================
      // Dichiara variabili
      // ==================================================================================================================================
      String[] ArrParts;
      String StrSplitDomain;
      String StrSplitUserName;
      
      // ==================================================================================================================================
      // Prepara configurazione request di base
      // ==================================================================================================================================

      // Configurazione base
      RequestConfig.Builder ObjRequestConfigBuilder =
         RequestConfig.custom().setConnectTimeout(IntConnectTimeout * 1000).setConnectionRequestTimeout(IntRequestTimeout * 1000);

      // ==================================================================================================================================
      // Prepara configurazione per autenticazione
      // ==================================================================================================================================

      // Prepara provider delle credenziali
      BasicCredentialsProvider ObjAuthCredsProvider = new BasicCredentialsProvider();

      // Prepara schemi di autenticazione supportati
      RegistryBuilder<AuthSchemeProvider> ObjAuthSchemeRegistry = RegistryBuilder.<AuthSchemeProvider>create();         
      
      // ==================================================================================================================================
      // Se richiesto gestisce url con autenticazione
      // ==================================================================================================================================

      if (!StrHostAuthMode.equals("ANONYMOUS")) {
         
         // Se presenti rimpiazza i template nel path osb del service account
         StrHostAccountPath = replaceTemplates(StrHostAccountPath);
         
         // Genera logging di debug
         LogMessage(LogLevel.DEBUG,"Host Auth Service Account: "+StrHostAccountPath);                  

         // Acquisisce risorsa service accountin formato XML
         XmlObject ObjServiceAccount = getOSBResource("ServiceAccount", StrHostAccountPath);

         // Acquisisce credenziali
         String StrHostUserName = getXMLTextValue(ObjServiceAccount, "//*:username/text()");
         String StrHostPassword = getXMLTextValue(ObjServiceAccount, "//*:password/text()");

         // Prepara auth scope dell'host
         URL ObjRequestURL = new URL(StrRequestURL);
         AuthScope ObjHostAuthScope = new AuthScope(new HttpHost(ObjRequestURL.getHost(), ObjRequestURL.getPort()));

         switch (StrHostAuthMode) {

            // ----------------------------------------------------------------------------------------------------------------------------------
            // Autenticazione BASIC
            // ----------------------------------------------------------------------------------------------------------------------------------
            case "BASIC":
               
               // Genera logging di debug
               LogMessage(LogLevel.DEBUG,"Host Auth UserName: "+StrHostUserName);                  

               // Predispone schema di autenticazione
               ObjAuthSchemeRegistry.register(AuthSchemes.BASIC,new BasicSchemeFactory());

               // Predispone credenziali
               ObjAuthCredsProvider.setCredentials(ObjHostAuthScope,new UsernamePasswordCredentials(StrHostUserName, StrHostPassword));
               break;
            
            // ----------------------------------------------------------------------------------------------------------------------------------
            // Autenticazione NTLM
            // ----------------------------------------------------------------------------------------------------------------------------------
            case "NTLM":
               
               // Prepara credenziali
               ArrParts = StrHostUserName.split("\\\\", 2);
               
               StrSplitDomain = null;
               StrSplitUserName = null;
                                       
               if (ArrParts.length>1) {
                  StrSplitDomain = ArrParts[0];
                  StrSplitUserName = ArrParts[1];               
               } else {
                  StrSplitUserName = ArrParts[0];               
               }
               
               // Genera logging di debug
               LogMessage(LogLevel.DEBUG,"Host Auth Domain : "+StrSplitDomain);                  
               LogMessage(LogLevel.DEBUG,"Host Auth UserName: "+StrSplitUserName);   

               // Predispone schema di autenticazione
               ObjAuthSchemeRegistry.register(AuthSchemes.NTLM,new NTLMSchemeFactory());

               // Predispone credenziali
               ObjAuthCredsProvider.setCredentials(ObjHostAuthScope,new NTCredentials(StrSplitUserName, StrHostPassword, null, StrSplitDomain));
               break;
               
            // ----------------------------------------------------------------------------------------------------------------------------------
            // Autenticazione KERBEROS
            // ----------------------------------------------------------------------------------------------------------------------------------
            case "KERBEROS":
               
               // Genera logging di debug
               LogMessage(LogLevel.DEBUG,"Host Auth Principal: "+StrHostUserName);   
               
               // Esegue login kerberos
               ArrLoginContext.add(loginKerberos(StrKerberosConfiguration,StrHostUserName,StrHostPassword));
               
               // Predispone schema di autenticazione
               ObjAuthSchemeRegistry.register(AuthSchemes.SPNEGO,new SPNegoSchemeFactory());

               // Predispone credenziali
               ObjAuthCredsProvider.setCredentials(ObjHostAuthScope,
                  new Credentials() {
                     public String getPassword() { return null; }
                     public Principal getUserPrincipal() { return null; } 
                  });
               
               break;        
            }
      }

      // ==================================================================================================================================
      // Se richiesto acquisisce parametri proxy
      // ==================================================================================================================================
      if (!StrProxyAuthMode.equals("DIRECT")) {
         
         // Se presenti rimpiazza i template nel path osb del service account
         StrProxyServerPath = replaceTemplates(StrProxyServerPath);
         
         // Genera logging di debug
         LogMessage(LogLevel.DEBUG,"Proxy Server Resource: "+StrProxyServerPath);                  

         // Acquisisce risorsa ESB proxy in formato XML
         XmlObject ObjProxyServer = getOSBResource("ProxyServer", StrProxyServerPath);

         // Esegue parsing dei vari parametri del proxy
         String StrProxyHost = getXMLTextValue(ObjProxyServer, "//*:server/@host");
         int IntProxyPort = Integer.valueOf(getXMLTextValue(ObjProxyServer, "//*:server/@port"));

         // Se necessario genera logging di debug
         LogMessage(LogLevel.DEBUG,"Proxy Server Host: "+StrProxyHost);                  
         LogMessage(LogLevel.DEBUG,"Proxy Server Port: "+IntProxyPort);                  
         
         // Prepara auth scope del proxy
         HttpHost ObjProxyHost = new HttpHost(StrProxyHost, IntProxyPort);
         AuthScope ObjProxyAuthScope = new AuthScope(ObjProxyHost);

         // Aggiunge parametro proxy a request client
         ObjRequestConfigBuilder.setProxy(ObjProxyHost);

         // Gestisce autenticazione proxy
         if (!StrProxyAuthMode.equals("ANONYMOUS")) {

            // Acquisisce credenziali
            String StrProxyUserName = getXMLTextValue(ObjProxyServer, "//*:username/text()");
            String StrProxyPassword = getXMLTextValue(ObjProxyServer, "//*:password/text()");
            
            switch (StrProxyAuthMode) {

               // ----------------------------------------------------------------------------------------------------------------------------------
               // Autenticazione BASIC
               // ----------------------------------------------------------------------------------------------------------------------------------
               case "BASIC":
                  
                  // Genera logging di debug
                  LogMessage(LogLevel.DEBUG,"Proxy Server Auth UserName: "+StrProxyUserName);                  
   
                  // Se necessario predispone schema di autenticazione
                  if (!StrHostAuthMode.equals("BASIC"))
                     ObjAuthSchemeRegistry.register(AuthSchemes.BASIC,new BasicSchemeFactory());

                  // Predispone credenziali
                  ObjAuthCredsProvider.setCredentials(ObjProxyAuthScope,new UsernamePasswordCredentials(StrProxyUserName,StrProxyPassword));
                  break;

               // ----------------------------------------------------------------------------------------------------------------------------------
               // Autenticazione NTLM
               // ----------------------------------------------------------------------------------------------------------------------------------
               case "NTLM":
                  
                  // Prepara credenziali
                  ArrParts = StrProxyUserName.split("\\\\", 2);   
                  
                  StrSplitDomain = null;
                  StrSplitUserName = null;
                                       
                  if (ArrParts.length>1) {
                     StrSplitDomain = ArrParts[0];
                     StrSplitUserName = ArrParts[1];               
                  } else {
                     StrSplitUserName = ArrParts[0];               
                  }

                  // Genera logging di debug
                  LogMessage(LogLevel.TRACE,"Proxy Server Auth Domain : "+StrSplitDomain);                  
                  LogMessage(LogLevel.TRACE,"Proxy Server Auth UserName: "+StrSplitUserName);  
                  
                  // Se necessario predispone schema di autenticazione
                  if (!StrHostAuthMode.equals("NTLM"))
                     ObjAuthSchemeRegistry.register(AuthSchemes.NTLM,new NTLMSchemeFactory());

                  // Predispone credenziali
                  ObjAuthCredsProvider.setCredentials(ObjProxyAuthScope,new NTCredentials(StrSplitUserName, StrProxyPassword, null,StrSplitDomain));
                  break;
               
               // ----------------------------------------------------------------------------------------------------------------------------------
               // Autenticazione KERBEROS
               // ----------------------------------------------------------------------------------------------------------------------------------
               case "KERBEROS":
                  
                  // Genera logging di debug
                  LogMessage(LogLevel.DEBUG,"Proxy Server Auth Principal: "+StrProxyUserName);   
                  
                  // Esegue login kerberos
                  ArrLoginContext.add(loginKerberos(StrKerberosConfiguration,StrProxyUserName,StrProxyPassword));                  

                  // Se necessario predispone schema di autenticazione
                  if (!StrHostAuthMode.equals("KERBEROS"))
                     ObjAuthSchemeRegistry.register(AuthSchemes.SPNEGO,new SPNegoSchemeFactory());

                  // Predispone credenziali
                  ObjAuthCredsProvider.setCredentials(ObjProxyAuthScope,                     
                     new Credentials() {
                        public String getPassword() { return null; }
                        public Principal getUserPrincipal() { return null; } 
                     });
                  
                  break;        
            }
         }         
      }

      // ==================================================================================================================================
      // Prepara request client
      // ==================================================================================================================================

      // Request client base
      HttpClientBuilder ObjHttpClientBuilder = HttpClients.custom()
         .setDefaultCredentialsProvider(ObjAuthCredsProvider)
         .setDefaultAuthSchemeRegistry(ObjAuthSchemeRegistry.build())
         .setDefaultRequestConfig(ObjRequestConfigBuilder.build());

      // Aggiunge eventuale tolleranza errori certificati ssl
      if (!BolSSLEnforce)
         ObjHttpClientBuilder.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                             .setSSLContext(new SSLContextBuilder().loadTrustMaterial(null,TrustAllStrategy.INSTANCE).build());
            
      // Restituisce client http
      return ObjHttpClientBuilder.build();
   }
      
   // ##################################################################################################################################
   // Security Utilities
   // ##################################################################################################################################

   // ==================================================================================================================================
   // Verifica che il token jwt sia conforme a quanto atteso
   // ==================================================================================================================================
   public static boolean verifyJwt(SignedJWT ObjJwt, String StrModulus, String StrExponent) throws Exception {
            
      // Predispone per la verifica della firma
      RSAKey ObjKey = new RSAKey.Builder(Base64URL.from(StrModulus),Base64URL.from(StrExponent))
         .keyUse(KeyUse.SIGNATURE)
         .keyID(ObjJwt.getHeader().getKeyID())
         .algorithm(ObjJwt.getHeader().getAlgorithm())
         .build(); 
      
      JWKSet ObjKeySet = new JWKSet(ObjKey);
      JWKSource<SecurityContext> ObjKeySource = new ImmutableJWKSet<SecurityContext>(ObjKeySet);
      JWSKeySelector<SecurityContext> ObjKeySelector = new JWSVerificationKeySelector<>(ObjJwt.getHeader().getAlgorithm(),ObjKeySource);
            
      // Predispone per la verifica dei claim
      JWTClaimsSetVerifier<SecurityContext> ObjClaimSetVerifier = 
         new DefaultJWTClaimsVerifier<>(
            new JWTClaimsSet.Builder().build(),
            new HashSet<>(Arrays.asList(JWTClaimNames.EXPIRATION_TIME, JWTClaimNames.NOT_BEFORE)));
      
      // Predispone il processore per la verifica del token
      ConfigurableJWTProcessor<SecurityContext> ObjProcessor = new DefaultJWTProcessor<>();
      
      ObjProcessor.setJWSKeySelector(ObjKeySelector);      
      ObjProcessor.setJWTClaimsSetVerifier(ObjClaimSetVerifier);
            
      // Esegue la verifica dei claim
      JWTClaimsSet ObjClaimSet = ObjProcessor.process(ObjJwt, null);
      
      // Restituisce l'esito della verifica
      return (ObjJwt.getState()==State.VERIFIED);
   }
   
   // ==================================================================================================================================
   // Esegue autenticazione kerberos
   // ==================================================================================================================================
   private static Object[] loginKerberos(String StrKerberosConfiguration, 
                                         String StrPrincipal,String StrPassword) throws Exception {
      
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
      sun.security.krb5.Config.refresh();

      // Imposta parametri del LoginModule
      Map ObjState = new HashMap();
      Map ObjOptions = new HashMap();
      Subject ObjSubject = new Subject();

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
   
   // ##################################################################################################################################
   // OSB Utilities
   // ##################################################################################################################################

   // ==================================================================================================================================
   // Esegue credential mapping del client_id sull'utenza del realm
   // ==================================================================================================================================
   public static String getOSBMappedUser(String StrServiceAccountPath, String StrRemoteUser) throws Exception {
      return getXMLTextValue(getOSBResource("ServiceAccount", StrServiceAccountPath),"//*:user-mapping[@remote-user='" + StrRemoteUser + "']/@local-user");
   }

   // ==================================================================================================================================
   // Acquisisce risorsa OSB in formato XML
   // ==================================================================================================================================
   public static XmlObject getOSBResource(String StrResourceType, String StrResourcePath) throws Exception {

      // Prepara puntamento al service account per il mapping delle utenze
      Ref ObjResourceRef = getOSBResourceRef(StrResourceType, StrResourcePath);

      // Acquisisce la risorsa con l'interfaccia generale che restituisce l'istanza nella classe specifica
      Object ObjResourceData =
         ALSBConfigService.get().getConfigService().getConfigContext().getResourceData(ObjResourceRef, true);

      // Prepara estrazione della risorsa per mezzo della reflection per bypassare gli eventuali controlli di accesso
      Method ObjMethod = ObjResourceData.getClass().getDeclaredMethod("toExportedForm", PBE_EncryptionService.class);
      ObjMethod.setAccessible(true);

      // Esegue estrazione e ne riesegue il parsing dell'XML per poter creare un elemento radice appropriato (altrimenti si genera un xml-fragment problematico)
      XmlObject ObjResourceXML = XmlObject.Factory.parse(XmlObject.class.cast(ObjMethod.invoke(ObjResourceData, new Object[] {null})).xmlText(new XmlOptions().setSaveSyntheticDocumentElement(new QName("root"))));

      // Restituisce service account
      return ObjResourceXML;
   }

   // ==================================================================================================================================
   // Acquisisce puntamento a risorsa OSB
   // ==================================================================================================================================
   private static Ref getOSBResourceRef(String StrResourceType, String StrResourcePath) {
      return new com.bea.wli.config.Ref(StrResourceType, Ref.getNames(StrResourcePath));
   }

   // ##################################################################################################################################
   // String Utilities
   // ##################################################################################################################################

   // ==================================================================================================================================
   // Fonde array di stringhe
   // ==================================================================================================================================
   private static String joinStringArray(String[] ArrStrings, String StrSeparator) {
            
      String StrOutput = "";
      for (int IntIndex=0;IntIndex<ArrStrings.length;IntIndex++){            
         StrOutput+= ((IntIndex>0)?(StrSeparator):(""))+ArrStrings[IntIndex].trim();   
      } 
      
      return StrOutput;
   }

   // ##################################################################################################################################
   // XML Utilities
   // ##################################################################################################################################

   // ==================================================================================================================================
   // Estrare valore testuale del primo nodo selzionato dall'espressione xpath
   // ==================================================================================================================================
   public static String getXMLTextValue(XmlObject ObjDocument, String StrSelectPath) {

      // Variabli locali
      XmlCursor ObjCursor;
      String StrTextValue = "";

      // Seleziona il path richiesto
      ObjCursor = ObjDocument.newCursor();
      ObjCursor.selectPath(StrSelectPath);

      // Estrae il valore dell'attributo richiesto
      if (ObjCursor.toNextSelection())
         StrTextValue = ObjCursor.getTextValue();

      // Dealloca il cursore
      ObjCursor.dispose();

      // Restituisce return-code
      return StrTextValue;
   }

   // ##################################################################################################################################
   // Logging Utilities
   // ##################################################################################################################################

   // ==================================================================================================================================
   // Formatta lo stack trace
   // ==================================================================================================================================

   public static String getStackTrace(Exception ObjException) {
      StringWriter ObjStringWriter = new StringWriter();
      PrintWriter ObjPrintWriter = new PrintWriter(ObjStringWriter);
      ObjException.printStackTrace(ObjPrintWriter);
      return ObjStringWriter.toString(); 
   }
   
   // ==================================================================================================================================
   // Genera messaggio di logging
   // ==================================================================================================================================
   public void LogMessage(int Level,String StrMessage) {
      LogMessage(Level,StrMessage,"");
   }   

   public void LogMessage(int Level,String StrMessage,String StrDetails) {
      if (Math.max(IntLoggingLevel,IntLoggingLevelMin)<=Level) {
         System.out.println(new SimpleDateFormat("'<'yyyy-MM-dd HH:mm:ss'>'").format(new Date(System.currentTimeMillis()))+
                            " <CIA> "+
                            String.format("%-8s","<" + LogLevel.getDescription(Level)+">")+
                            StrMessage+
                            ((!StrDetails.equals(""))?(": "+StrDetails):("")));
      }
   }   

   // ##################################################################################################################################
   // Other Utilities
   // ##################################################################################################################################
   
   public static void setFinalStatic(Field ObjField, Object ObjValue) throws Exception {
      ObjField.setAccessible(true);
      Field ObjModifiersField = Field.class.getDeclaredField("modifiers");
      ObjModifiersField.setAccessible(true);
      ObjModifiersField.setInt(ObjField, ObjField.getModifiers() & ~Modifier.FINAL);
      ObjField.set(null,ObjValue);
   }
}
