package com.dbl.fingerprint.fingerprintauthentication;

import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;

public class FingerPrintScan extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_finger_printscan);
        FingerprintManager fingerprintManager =
                    (FingerprintManager) getSystemService(FINGERPRINT_SERVICE);
        FingerprintHandler helper = new FingerprintHandler(this);
        helper.startAuth(fingerprintManager, null, 0);

//            if(GenerateKey.mode==0) {
//                helper.startAuth(fingerprintManager, null, 0);
//            }
//            else {
//                try {
//
//                    helper.startAuth(fingerprintManager, GenerateKey.cryptoObject, 1);
//                } catch (Exception e) {
//
//                }
//            }
//        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
//
//
//            keyguardManager =
//                    (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
//            fingerprintManager =
//                    (FingerprintManager) getSystemService(FINGERPRINT_SERVICE);
//
//            textView = (TextView) findViewById(R.id.description);
//
//            if (!fingerprintManager.isHardwareDetected()) {
//
//                textView.setText("Your device doesn't support fingerprint authentication");
//
//            }
//
//
//            if (ActivityCompat.checkSelfPermission(this, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
//                textView.setText("Please enable the fingerprint permission");
//
//            }
//
//            if (!fingerprintManager.hasEnrolledFingerprints()) {
//                textView.setText("No fingerprint configured. Please register at least one fingerprint in your device's Settings");
//
//            }
//
//            if (!keyguardManager.isKeyguardSecure()) {
//                textView.setText("Please enable lockscreen security in your device's Settings");
//            } else {
//                try {
//
//                    generateKey();
//                } catch (FingerPrintScan.FingerprintException e) {
//                    e.printStackTrace();
//                }
//                if (initCipher()) {
//                    cryptoObject = new FingerprintManager.CryptoObject(cipher);
//                    FingerprintHandler helper = new FingerprintHandler(this);
//                    helper.startAuth(fingerprintManager, cryptoObject,0);
//                }
//            }
//        }
    }
}
