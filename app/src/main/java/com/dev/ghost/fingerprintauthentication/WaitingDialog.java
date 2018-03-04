package com.dev.ghost.fingerprintauthentication;

import android.content.Intent;
import android.hardware.fingerprint.FingerprintManager;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;

public class WaitingDialog extends AppCompatActivity {


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_waiting_dialog);
        Intent intent = getIntent(); //Get the calling intent
        String ip = intent.getStringExtra("ip_address"); //Get the IP Address of the PC
        Integer port = intent.getIntExtra("port_number", 9624); //Get the port number of the PC
        String extra = intent.getStringExtra("request_string"); //Get the requested resource
        FingerprintManager fpManager = (FingerprintManager) getSystemService(FINGERPRINT_SERVICE); //Get the fingerprint manager service
        NetworkClient nc = new NetworkClient(this); //Create a new network client
        nc.execute(ip, port, extra, fpManager); //Execute the network client
    }
}
