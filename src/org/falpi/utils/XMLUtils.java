package org.falpi.utils;

import org.apache.xmlbeans.XmlCursor;
import org.apache.xmlbeans.XmlObject;

public class XMLUtils {
   
   // ==================================================================================================================================
   // Estrare valore testuale del primo nodo selzionato dall'espressione xpath
   // ==================================================================================================================================
   public static String getTextValue(XmlObject ObjDocument, String StrSelectPath) {

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
}
