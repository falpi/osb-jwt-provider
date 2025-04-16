package org.falpi.utils;

import com.bea.xbean.xb.xsdschema.SchemaDocument;

import java.util.ArrayList;

import org.apache.xmlbeans.SchemaTypeLoader;
import org.apache.xmlbeans.XmlBeans;
import org.apache.xmlbeans.XmlCursor;
import org.apache.xmlbeans.XmlError;
import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlOptions;

public class XMLUtils {

   // ==================================================================================================================================
   // Estrae valore testuale del primo nodo selezionato dall'espressione xpath
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

   // ==================================================================================================================================
   // Imposta valore testuale del primo nodo selezionato dall'espressione xpath
   // ==================================================================================================================================
   public static void setTextValue(XmlObject ObjDocument, String StrTextValue, String StrSelectPath) {

      // Variabli locali
      XmlCursor ObjCursor;

      // Seleziona il path richiesto
      ObjCursor = ObjDocument.newCursor();
      ObjCursor.selectPath(StrSelectPath);

      // Estrae il valore dell'attributo richiesto
      if (ObjCursor.toNextSelection())
         ObjCursor.setTextValue(StrTextValue);

      // Dealloca il cursore
      ObjCursor.dispose();
   }

   // ==================================================================================================================================
   // Imposta valore testuale del nodo indicato dall'array di nodi fornito
   // ==================================================================================================================================
   public static boolean setTextValueEx(XmlObject ObjDocument, String StrTextValue, String... ArrChildNodes) {

      // Variabli locali
      boolean BolResult;
      XmlCursor ObjCursor;

      // Inizializza return-code
      BolResult = true;

      // Posiziona il cursore XML sul nodo desiderato scorrendo i child
      ObjCursor = ObjDocument.newCursor();
      ObjCursor.toStartDoc();

      for (int IntIndex = 0; IntIndex < ArrChildNodes.length; IntIndex++) {
         BolResult = ObjCursor.toChild(ArrChildNodes[IntIndex]);
         if (!BolResult)
            break;
      }

      // Se il percorso esiste imposta il valore di testo
      if (BolResult)
         ObjCursor.setTextValue(StrTextValue);

      // Dealloca il cursore
      ObjCursor.dispose();

      // Restituisce return-code
      return BolResult;
   }

   // ==================================================================================================================================
   // Copia un frammento di XML indicato da un xpath su un altro XML nella posizione indicata da xpath
   // ==================================================================================================================================
   public static void copy(XmlObject ObjSource, String StrSourcePath, XmlObject ObjDestination,
                           String StrDestinationPath, boolean BolRootElement) {

      // Dichiara variabili
      XmlCursor ObjSourceCursor = null;
      XmlCursor ObjDestinationCursor = null;

      // Apre i cursori sugli xml forniti
      ObjSourceCursor = ObjSource.newCursor();
      ObjDestinationCursor = ObjDestination.newCursor();

      // Se necessario corregge il path sorgente
      if (StrSourcePath.equals("") && BolRootElement)
         StrSourcePath = "/*";

      // Se necessario posiziona il cursore sorgente
      if (!StrSourcePath.equals("")) {
         ObjSourceCursor.selectPath(StrSourcePath);
         if (!ObjSourceCursor.toNextSelection())
            throw new RuntimeException("Unable to find source path '" + StrSourcePath + "'");
      }

      // Posiziona il cursore di destinazione
      ObjDestinationCursor.selectPath(StrDestinationPath);
      if (!ObjDestinationCursor.toNextSelection())
         throw new RuntimeException("Unable to find target path '" + StrDestinationPath + "'");

      // Esegue la copia da sorgente a destinazione
      ObjDestinationCursor.toFirstContentToken();

      try {
         do {
            if (BolRootElement) {
               ObjSourceCursor.copyXml(ObjDestinationCursor);
            } else {
               ObjSourceCursor.copyXmlContents(ObjDestinationCursor);
            }
         } while (ObjSourceCursor.toNextSelection());
      } catch (Exception ObjException) {
         throw new RuntimeException("Error while coping source path '" + StrSourcePath + "' to target path '" +
                                    StrDestinationPath + "' :" + ObjException.toString());
      }

      // Chiude i cursori aperti
      ObjSourceCursor.dispose();
      ObjDestinationCursor.dispose();
   }

   // ==================================================================================================================================
   // Esegue la validazione di un payload rispetto ad un elenco di schema
   // ==================================================================================================================================
   public static ArrayList<XmlError> validate(XmlObject ObjPayload,SchemaDocument[] ArrSchemaDocuments) throws XmlException {

      // Prepara variabili locali
      ArrayList<XmlError> ObjErrors = new ArrayList<XmlError>();

      // Alloca un array di XmlObject pari agli schema forniti
      XmlObject[] ArrSchemaObjects = new XmlObject[ArrSchemaDocuments.length];

      // Converte gli schema document negli xmlobject al fine della validazione
      for (int IntIndex=0;IntIndex<ArrSchemaDocuments.length; IntIndex++) {

         ArrSchemaObjects[IntIndex] =
            XmlObject.Factory.parse(ArrSchemaDocuments[IntIndex].xmlText(),new XmlOptions().setLoadLineNumbers().setLoadMessageDigest());
      }

      // Prepara il loader per la validazione del payload
      SchemaTypeLoader ObjLoader = 
         XmlBeans.compileXsd(ArrSchemaObjects, null, new XmlOptions().setErrorListener(null).setCompileDownloadUrls().setCompileNoPvrRule());

      // Prepara il loader per il caricamento del payload
      XmlObject ObjDocument =
         ObjLoader.parse(ObjPayload.xmlText(new XmlOptions().setSaveOuter()), null,
                         new XmlOptions().setLoadLineNumbers(XmlOptions.LOAD_LINE_NUMBERS_END_ELEMENT));

      // Esegue la validazione del documento sulla base dei schema forniti
      ObjDocument.validate(new XmlOptions().setErrorListener(ObjErrors));

      // Restituisce eventuali errori di validazione
      return ObjErrors;
   }
}
