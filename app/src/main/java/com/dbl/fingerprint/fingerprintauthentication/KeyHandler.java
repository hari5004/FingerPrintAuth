package com.dbl.fingerprint.fingerprintauthentication;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import static android.content.Context.MODE_PRIVATE;

/**
 * Created by hari on 18/4/18.
 */

public class KeyHandler {
    public static SharedPreferences sharedPreferences;
    Context thiscontext;
    byte[] encryptedBytes, decryptedBytes;

    public KeyHandler(Context context) {
        thiscontext = context;
        sharedPreferences = thiscontext.getSharedPreferences("rsakey", MODE_PRIVATE);
    }

    public PrivateKey getPrivateKey() throws Exception {
        Log.d("EncryptionS", "Starting");
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            return (PrivateKey) keyStore.getKey("fedSmekey", null);

        } catch (Exception e) {
            Log.e("Finger", e.getMessage());
            e.printStackTrace();
            return null;
        }

    }

    public String getLoginCredentials(PrivateKey privateKeyEntry) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String encryptString = sharedPreferences.getString("data_for_login", "");
        return decryptRSA(privateKeyEntry, encryptString);
    }

    public KeyPair generateKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            if (keyStore != null) {
                KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(
                        "fedSmekey",
                        KeyProperties.PURPOSE_DECRYPT)
                        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                        .build();
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
                keyPairGenerator.initialize(keyGenParameterSpec);
                return keyPairGenerator.generateKeyPair();
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            Log.e("FINGER", e.getMessage());
            return null;
        } catch (KeyStoreException e) {
            Log.e("FINGER", e.getMessage());
            e.printStackTrace();
            return null;
        }
        return null;
    }

    public void saveLoginCredentials(KeyPair keypair) {
        SharedPreferences.Editor editor = sharedPreferences.edit();
        try {
            PublicKey publicKey = keypair.getPublic();
            String encryptedString = encryptRSA(publicKey, "Hello");
            editor.putString("data_for_login", encryptedString);
            editor.apply();
        } catch (Exception e) {
            Log.e("FINGER", e.getMessage());
        }
    }

    private String encryptRSA(PublicKey publicKey, String plainString) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        encryptedBytes = cipher.doFinal(plainString.getBytes());
        return Base64.encodeToString(encryptedBytes,Base64.DEFAULT);
    }

    private String decryptRSA(PrivateKey privateKey, String encryptedString) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        decryptedBytes = cipher.doFinal(Base64.decode(encryptedString,Base64.DEFAULT));
        return new String(decryptedBytes);
    }
}
