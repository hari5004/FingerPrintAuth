package com.dbl.fingerprint.fingerprintauthentication;

import android.Manifest;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.ContextThemeWrapper;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import org.w3c.dom.Text;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import static android.content.Context.FINGERPRINT_SERVICE;

public class FingerPrint extends AppCompatActivity {
   Context context =this;
    public static final String KEY_NAME = "RSAKEY";
    private FingerprintManager fingerprintManager;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_finger_print);

    }
    public void EnrollFingerprint(View view) {
        Intent intent= new Intent(this,FingerPrintscan.class);
        this.startActivity(intent);
    }
    public void Login(View view){
        try{
            fingerprintManager =
                    (FingerprintManager) getSystemService(FINGERPRINT_SERVICE);
            GenerateKey generateKey=new GenerateKey(context,fingerprintManager);
            generateKey .keyPairGen();
        } catch (Exception e){

        }
    }

}
 class GenerateKey {
    Context thiscontext;
     public static FingerprintManager fingerprintManager;
     public static FingerprintManager.CryptoObject cryptoObject;
     public static PublicKey pubkey;
     public static int mode=0;
     public static byte[] data;
     public static byte[] sigBytes;
     public GenerateKey(Context context) {
         thiscontext=context;
     }
    public  GenerateKey(Context context,FingerprintManager fingerprintManager) {
        thiscontext=context;
        this.fingerprintManager=fingerprintManager;
    }
    public void keyPairGen()  throws Exception {
        Log.d("EncryptionS", "Starting");
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            if (keyStore != null) {
                PrivateKey privateKeyEntry = (PrivateKey) keyStore.getKey("fedSmekey", null);
               Signature signature=  Signature.getInstance("SHA256withRSA");
                data = "hello".getBytes("UTF8");
                signature.initSign(privateKeyEntry);
                cryptoObject = new FingerprintManager.CryptoObject(signature);
                PublicKey publicKey =
                        keyStore.getCertificate("fedSmekey").getPublicKey();
                pubkey=publicKey;
                mode=1;
                Intent intent =new Intent(thiscontext,FingerPrintscan.class);
                thiscontext.startActivity(intent);
//
//                FingerprintHandler helper = new FingerprintHandler(thiscontext);
//                helper.startAuth(fingerprintManager, cryptoObject,1);
                String PublickeyStr = Base64.encodeToString(publicKey.getEncoded(), Base64.DEFAULT);

            }
            else {
                Toast.makeText(thiscontext,
                        "Not authenticated",
                        Toast.LENGTH_LONG).show();
            }
        } catch (Exception e) {
            Toast.makeText(thiscontext,
                    e.getCause()+" !!!!!",
                    Toast.LENGTH_LONG).show();
            e.printStackTrace();
        }

    }
    public void storeKeyInKeyStore(){
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            if(keyStore != null) {
                KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder("fedSmekey",
                        KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setAlgorithmParameterSpec(new RSAKeyGenParameterSpec(1024, RSAKeyGenParameterSpec.F4))
                        .setUserAuthenticationRequired(true)
                        .setRandomizedEncryptionRequired(true)
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                        .build();
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
                keyPairGenerator.initialize(keyGenParameterSpec);
                keyPairGenerator.generateKeyPair();

            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("Forced crash!");
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            throw new RuntimeException("Forced crash!");
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            throw new RuntimeException("Forced crash!");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }
}
