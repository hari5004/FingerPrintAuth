package com.dbl.fingerprint.fingerprintauthentication;


import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.CancellationSignal;
import android.support.v4.app.ActivityCompat;
import android.widget.Toast;

import java.security.KeyPair;
import java.security.PrivateKey;

import javax.crypto.Cipher;


public class FingerprintHandler extends FingerprintManager.AuthenticationCallback {

    private CancellationSignal cancellationSignal;
    private Context context;
    FingerprintManager.CryptoObject cryptoObject;
    int mode = 0;

    public FingerprintHandler(Context mContext) {
        context = mContext;
    }

    public void startAuth(FingerprintManager manager, FingerprintManager.CryptoObject cryptoObject, int mode) {
        cancellationSignal = new CancellationSignal();
        this.mode = mode;
        this.cryptoObject = cryptoObject;
        if (ActivityCompat.checkSelfPermission(context, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            return;
        }
        manager.authenticate(cryptoObject, cancellationSignal, 0, this, null);
    }

    @Override
    public void onAuthenticationError(int errMsgId,
                                      CharSequence errString) {
        Toast.makeText(context,
                "Authentication error\n" + errString,
                Toast.LENGTH_LONG).show();
    }

    @Override
    public void onAuthenticationFailed() {
        Toast.makeText(context,
                "Authentication failed",
                Toast.LENGTH_LONG).show();
    }

    @Override
    public void onAuthenticationHelp(int helpMsgId,
                                     CharSequence helpString) {
        Toast.makeText(context,
                "Authentication help\n" + helpString,
                Toast.LENGTH_LONG).show();
    }


    @Override
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
        if(mode==0)
        saveData(cryptoObject.getCipher());
        else if(mode==1){
            retriveData(cryptoObject.getCipher());

        }
    }
private void retriveData(Cipher cipher) {
        try {
           KeyHandler keyHandler = new KeyHandler(context);
            PrivateKey privateKey = keyHandler.getPrivateKey();
            String decryptedString = keyHandler.getLoginCredentials(privateKey,cipher);
            Toast.makeText(context,
                    decryptedString,
                    Toast.LENGTH_LONG).show();
        }
        catch (Exception e)
        {
            Toast.makeText(context,
                    e.getMessage()+"!!!!",
                    Toast.LENGTH_LONG).show();
        }
}
    private void saveData(Cipher cipher) {
        KeyHandler keyHandler = new KeyHandler(context);
        //KeyPair keyPair = keyHandler.generateKey();
       // if (keyPair != null)
            keyHandler.saveLoginCredentials(cipher);
        Intent intent = new Intent(context, FingerPrint.class);
        context.startActivity(intent);
    }
//    private void verifyKeys() {
//        try{
//            if(mode==0) {
//                KeyHandler keyHandler = new KeyHandler(context);
//                KeyPair keyPair = keyHandler.generateKey();
//
//                if(keyPair != null)
//                    keyHandler.saveLoginCredentials(keyPair);
//            }
//            else if(mode==1) {
//                Signature signature = cryptoObject.getSignature();
//               signature.update(GenerateKey.data);
//               byte[] sigBytes = signature.sign();
//                Signature verificationFunction = Signature.getInstance("SHA256withRSA");
//                verificationFunction.initVerify(GenerateKey.pubkey);
//                verificationFunction.update(GenerateKey.data);
//                if (verificationFunction.verify(sigBytes)) {
//                    // Transaction is verified with the public key associated with the user
//                    // Do some post purchase processing in the server
//                    Toast.makeText(context,
//                            "Verified" ,
//                            Toast.LENGTH_LONG).show();
//                }
//                else {
//                    Toast.makeText(context,
//                            "Verification failed",
//                            Toast.LENGTH_LONG).show();
//                }
//
//            }
//        } catch (Exception e){
//            Toast.makeText(context,
//                    e.getCause()+"$$$$$$$$$$$$$$$4",
//                    Toast.LENGTH_LONG).show();
//        }
//    }


}
