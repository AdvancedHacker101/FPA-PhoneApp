package com.dev.ghost.fingerprintauthentication;

import android.arch.persistence.room.Room;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Handler;
import android.preference.PreferenceManager;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Toast;

public class MainActivity extends AppCompatActivity {

    public static final String LOG_TAG = "FP Authentication"; //Log tag for Logcat
    public static SharedPreferences sp; //Shared Preferences for GetCryptoObjectTask
    public static AppDatabase appDatabase; //Instance of the application database
    static TextCallback createToast; //Toast pushing callback

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        LoadDatabase(); //Load the application database
        sp = PreferenceManager.getDefaultSharedPreferences(this); //Get shared preferences
        //Configure the Toast pushing callback
        final Context ctx = this; //Provide a context for the inner class
        createToast = new TextCallback() {
            @Override
            public void call(final String text) { //Called from other classes
                //Invoke function on the UI thread
                Handler uiHandler = new Handler(ctx.getMainLooper());
                uiHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        Toast.makeText(ctx, text, Toast.LENGTH_LONG).show(); //Display toast
                    }
                });
            }
        };
    }

    public void WipeLogin(View v)
    {
        //Create a new thread for database operations
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                appDatabase.loginDataDAO().wipeTable(); //Wipe credentials
                appDatabase.keyStorageDAO().wipeTable(); //Wipe keys
                //Check the total number of remaining elements
                int lngth = appDatabase.loginDataDAO().getAllLoginData().length;
                int lngth2 = appDatabase.keyStorageDAO().getAllKeys().length;
                Log.d(LOG_TAG, "Got " + (lngth + lngth2) + " entries");
            }
        });

        t.start(); //Start the thread
    }

    public void NetworkTest(View v)
    {
        NetworkClient nc = new NetworkClient(this);
        nc.execute("192.168.10.103", 9624);
    }

    public void DetectQRCode(View v)
    {
        Intent qrDetector = new Intent(this, CameraActivity.class); //Create a new intent to CameraActivity
        startActivity(qrDetector); //Start the activity
    }

    private void LoadDatabase()
    {
        appDatabase = Room.databaseBuilder(getApplicationContext(), AppDatabase.class, "fpauth-database").build(); //Get an instance of our database
    }
}