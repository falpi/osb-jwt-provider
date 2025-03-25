package org.falpi.utils;

// ##################################################################################################################################
// Referenze
// ##################################################################################################################################

import java.util.Map;
import java.util.Arrays;
import java.util.HashSet;

import org.nimbusds.jwt.SignedJWT;
import org.nimbusds.jwt.JWTClaimsSet;
import org.nimbusds.jwt.JWTClaimNames;
import org.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import org.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import org.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import org.nimbusds.jose.jwk.JWKSet;
import org.nimbusds.jose.jwk.RSAKey;
import org.nimbusds.jose.jwk.KeyUse;
import org.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.nimbusds.jose.jwk.source.JWKSource;
import org.nimbusds.jose.proc.JWSKeySelector;
import org.nimbusds.jose.proc.JWSVerificationKeySelector;
import org.nimbusds.jose.proc.SecurityContext;
import org.nimbusds.jose.util.Base64URL;
import org.nimbusds.jose.JWSObject;

public class JWTTokenNimbusShadedImpl implements JWTToken {
   
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
