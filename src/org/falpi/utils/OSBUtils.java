package org.falpi.utils;

import com.bea.wli.config.Ref;
import com.bea.wli.sb.ALSBConfigService;
import com.bea.wli.security.encryption.PBE_EncryptionService;

import java.lang.reflect.Method;
import javax.xml.namespace.QName;

import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlOptions;

import org.falpi.utils.XMLUtils;

public class OSBUtils {

   // ==================================================================================================================================
   // Esegue credential mapping del remote user su local user mediante un service account di mapping
   // ==================================================================================================================================
   public static String getMappedUser(String StrServiceAccountPath, String StrRemoteUser) throws Exception {
      return XMLUtils.getTextValue(getResource("ServiceAccount", StrServiceAccountPath),"//*:user-mapping[@remote-user='" + StrRemoteUser + "']/@local-user");
   }

   // ==================================================================================================================================
   // Acquisisce risorsa OSB in formato XML
   // ==================================================================================================================================
   public static XmlObject getResource(String StrResourceType, String StrResourcePath) throws Exception {

      // Prepara puntamento al service account per il mapping delle utenze
      Ref ObjResourceRef = getResourceRef(StrResourceType, StrResourcePath);

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
   private static Ref getResourceRef(String StrResourceType, String StrResourcePath) {
      return new com.bea.wli.config.Ref(StrResourceType, Ref.getNames(StrResourcePath));
   }
   
}
