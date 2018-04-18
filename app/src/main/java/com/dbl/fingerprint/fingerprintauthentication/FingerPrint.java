package com.dbl.fingerprint.fingerprintauthentication;

import android.content.Intent;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.Toast;

import java.security.PrivateKey;

public class FingerPrint extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_finger_print);

    }

    public void EnrollFingerprint(View view) {
        Intent intent = new Intent(this, FingerPrintScan.class);
        this.startActivity(intent);
    }

    public void Login(View view) {
        try {
            KeyHandler keyHandler = new KeyHandler(this);
            PrivateKey privateKey = keyHandler.getPrivateKey();
            String decryptedString = keyHandler.getLoginCredentials(privateKey);
            Toast.makeText(this,
                    decryptedString,
                    Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            Log.d("Finger", e.getMessage());
        }
    }

}
