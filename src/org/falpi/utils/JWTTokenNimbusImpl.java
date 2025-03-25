package org.falpi.utils;

// ##################################################################################################################################
// Referenze
// ##################################################################################################################################

import java.util.Map;
import java.util.Arrays;
import java.util.HashSet;

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
import com.nimbusds.jose.JWSObject;

public class JWTTokenNimbusImpl implements JWTToken {
   
   // ==================================================================================================================================
   // Variabili private
   // ==================================================================================================================================
   private SignedJWT ObjSignedJWT;

   // ==================================================================================================================================
   // Costruttore
   // ==================================================================================================================================
   @Override
   public void parse(String StrToken) throws Exception {
      ObjSignedJWT = SignedJWT.parse(StrToken);
   }      

   // ==================================================================================================================================
   // Acquisisce la versione della classe
   // ==================================================================================================================================
   @Override
   public String version() throws Exception {
      return ObjSignedJWT.getClass().getPackage().toString();
   }      

   // ==================================================================================================================================
   // Acquisisce il keyid del token
   // ==================================================================================================================================
   @Override
   public String getKeyID() throws Exception {
      return ObjSignedJWT.getHeader().getKeyID();
   }      

   // ==================================================================================================================================
   // Acquisisce l'header del token
   // ==================================================================================================================================
   @Override
   public Map getHeader() throws Exception {
      return ObjSignedJWT.getHeader().toJSONObject();
   }      

   // ==================================================================================================================================
   // Acquisisce il payload del token
   // ==================================================================================================================================
   @Override
   public Map getPayload() throws Exception {
      return ObjSignedJWT.getPayload().toJSONObject();
   }         

   // ==================================================================================================================================
   // Verifica che il token jwt sia conforme a quanto atteso
   // ==================================================================================================================================
   @Override
   public boolean verify(String StrModulus, String StrExponent) throws Exception {
            
      // Predispone per la verifica della firma
      RSAKey ObjKey = new RSAKey.Builder(Base64URL.from(StrModulus),Base64URL.from(StrExponent))
         .keyUse(KeyUse.SIGNATURE)
         .keyID(ObjSignedJWT.getHeader().getKeyID())
         .algorithm(ObjSignedJWT.getHeader().getAlgorithm())
         .build(); 
      
      JWKSet ObjKeySet = new JWKSet(ObjKey);
      JWKSource<SecurityContext> ObjKeySource = new ImmutableJWKSet<SecurityContext>(ObjKeySet);
      JWSKeySelector<SecurityContext> ObjKeySelector = new JWSVerificationKeySelector<>(ObjSignedJWT.getHeader().getAlgorithm(),ObjKeySource);
            
      // Predispone per la verifica dei claim
      JWTClaimsSetVerifier<SecurityContext> ObjClaimSetVerifier = 
         new DefaultJWTClaimsVerifier<>(
            new JWTClaimsSet.Builder().build(),
            new HashSet<>(Arrays.asList(JWTClaimNames.EXPIRATION_TIME,JWTClaimNames.NOT_BEFORE)));
      
      // Predispone il processore per la verifica del token
      ConfigurableJWTProcessor<SecurityContext> ObjProcessor = new DefaultJWTProcessor<>();
      
      ObjProcessor.setJWSKeySelector(ObjKeySelector);      
      ObjProcessor.setJWTClaimsSetVerifier(ObjClaimSetVerifier);
            
      // Esegue la verifica dei claim
      JWTClaimsSet ObjClaimSet = ObjProcessor.process(ObjSignedJWT, null);
      
      // Restituisce l'esito della verifica
      return (ObjSignedJWT.getState() == JWSObject.State.VERIFIED);
   }
}
