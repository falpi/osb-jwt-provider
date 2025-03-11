package org.falpi.osb.security.providers;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

class CustomIdentityAsserterCallbackHandlerImpl implements CallbackHandler {
   private String StrUserName;

   CustomIdentityAsserterCallbackHandlerImpl(String StrUser) {
      StrUserName = StrUser;
   }

   @Override
   public void handle(Callback[] ArrCallbacks) throws UnsupportedCallbackException {
      for (int i = 0; i < ArrCallbacks.length; i++) {
         Callback ObjCallback = ArrCallbacks[i];
         if (!(ObjCallback instanceof NameCallback)) {
            throw new UnsupportedCallbackException(ObjCallback, "Unrecognized Callback");
         }
         NameCallback nameCallback = (NameCallback) ObjCallback;
         nameCallback.setName(StrUserName);
      }
   }
}