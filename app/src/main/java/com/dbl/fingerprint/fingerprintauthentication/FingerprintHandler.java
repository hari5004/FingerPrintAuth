package  com.dbl.fingerprint.fingerprintauthentication;


import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.Manifest;
import android.os.CancellationSignal;
import android.support.v4.app.ActivityCompat;
import android.widget.Toast;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;


public class FingerprintHandler extends FingerprintManager.AuthenticationCallback {

    private CancellationSignal cancellationSignal;
    private Context context;
    FingerprintManager.CryptoObject cryptoObject;
    PublicKey publicKey;
    int mode=0;
    PrivateKey privateKey;
    public FingerprintHandler(Context mContext) {
        context = mContext;
    }

    public void startAuth(FingerprintManager manager, FingerprintManager.CryptoObject cryptoObject,int mode) {
        cancellationSignal = new CancellationSignal();
        this.mode=mode;
        this.cryptoObject=cryptoObject;
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
    public void onAuthenticationSucceeded(
            FingerprintManager.AuthenticationResult result) {
        try{
            if(mode==0) {
                GenerateKey generateKey = new GenerateKey(context);
                generateKey.storeKeyInKeyStore();
                Toast.makeText(context,
                        "ADded to keystore" ,
                        Toast.LENGTH_LONG).show();
                Intent i = new Intent(context, FingerPrint.class);
                context.startActivity(i);
            }
            else if(mode==1) {
                Signature signature = cryptoObject.getSignature();
               signature.update(GenerateKey.data);
               byte[] sigBytes = signature.sign();
                Signature verificationFunction = Signature.getInstance("SHA256withRSA");
                verificationFunction.initVerify(GenerateKey.pubkey);
                verificationFunction.update(GenerateKey.data);
                if (verificationFunction.verify(sigBytes)) {
                    // Transaction is verified with the public key associated with the user
                    // Do some post purchase processing in the server
                    Toast.makeText(context,
                            "Verified" ,
                            Toast.LENGTH_LONG).show();
                }
                else {
                    Toast.makeText(context,
                            "Verification failed",
                            Toast.LENGTH_LONG).show();
                }

            }
        } catch (Exception e){

        }
    }


}
