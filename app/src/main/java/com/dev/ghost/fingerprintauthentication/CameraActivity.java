package com.dev.ghost.fingerprintauthentication;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.support.annotation.NonNull;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.util.SparseArray;
import android.view.SurfaceHolder;
import android.view.SurfaceView;

import com.google.android.gms.vision.CameraSource;
import com.google.android.gms.vision.Detector;
import com.google.android.gms.vision.barcode.Barcode;
import com.google.android.gms.vision.barcode.BarcodeDetector;

import java.io.IOException;

public class CameraActivity extends AppCompatActivity {

    public SurfaceView imageHolder; //UI element to display the image of the camera
    BarcodeDetector barCodeDetector; //Detecting QR Codes in camera frames
    CameraSource cameraSource; //The camera object
    boolean cameraRunning = false; //Indicates if the camera is running

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {

        switch (requestCode)
        {
            case 1000:
                if (grantResults[0] == PackageManager.PERMISSION_GRANTED) //Permission Granted
                {
                    //Check permission state
                    if (ActivityCompat.checkSelfPermission(getApplicationContext(), Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED)
                        return;

                    try {
                        cameraSource.start(imageHolder.getHolder()); //Start the camera
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
                break;
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_camera);

        imageHolder = findViewById(R.id.cameraPlaceholder); //Get the surfaceView

        StartCamera(); //Start the camera

        imageHolder.getHolder().addCallback(new SurfaceHolder.Callback() { //Set display callback
            @Override
            public void surfaceCreated(SurfaceHolder surfaceHolder) {
                //Check permission to the camera
                if (ActivityCompat.checkSelfPermission(getApplicationContext(), Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {

                    //Permission not granted, so request it
                    ActivityCompat.requestPermissions(CameraActivity.this,
                            new String[] { Manifest.permission.CAMERA},
                            1000);
                    return;
                }

                try {
                    cameraSource.start(imageHolder.getHolder()); //Permission granted, start the camera
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

            @Override
            public void surfaceChanged(SurfaceHolder surfaceHolder, int i, int i1, int i2) {

            }

            @Override
            public void surfaceDestroyed(SurfaceHolder surfaceHolder) {
                ReleaseCamera(); //Release the camera resource
            }
        });
    }

    @Override
    protected void onPause() {
        super.onPause();
        ReleaseCamera(); //Application in background, release camera resource
    }

    @Override
    protected void onStop() {
        super.onStop();
        ReleaseCamera(); //Activity stopping, release the camera
    }

    @Override
    protected void onResume() {
        super.onResume();
        StartCamera(); //Application in foreground again, restart the camera
    }

    private void StartCamera()
    {
        //Init the QR Code detector
        barCodeDetector = new BarcodeDetector.Builder(this)
                .setBarcodeFormats(Barcode.QR_CODE)
                .build();

        //Init the camera
        cameraSource = new CameraSource.Builder(this, barCodeDetector)
                .setAutoFocusEnabled(true)
                .build();

        //Set result callback for QR code detection
        barCodeDetector.setProcessor(new Detector.Processor<Barcode>() {

            @Override
            public void release() {
                //We Don't have anything to release
            }

            @Override
            public void receiveDetections(Detector.Detections<Barcode> detections) {
                SparseArray<Barcode> detectionResults = detections.getDetectedItems(); //Get the detection results

                if (detectionResults.size() > 0) //At least 1 detection
                {
                    //Release the camera on the UI thread
                    Handler handler = new Handler(Looper.getMainLooper());
                    handler.post(new Runnable() {
                        @Override
                        public void run() {
                            ReleaseCamera();
                        }
                    });

                    Log.d(MainActivity.LOG_TAG, "QR Code detected");
                    String payloadData = detectionResults.valueAt(0).displayValue; //Get the data of the QR Code
                    Log.d(MainActivity.LOG_TAG, "Message Received: \r\n" + payloadData);
                    //Parse the data of the QR Code
                    String[] firstSplit = payloadData.split(":");
                    String[] secondSplit = firstSplit[1].split("-");
                    String ip = firstSplit[0];
                    Integer port = Integer.parseInt(secondSplit[0]);
                    int delimiter = payloadData.indexOf("-") + 1;
                    String requestString = payloadData.substring(delimiter);
                    Intent i = new Intent(CameraActivity.this, WaitingDialog.class); //Create intent to call the waiting dialog
                    i.putExtra("ip_address", ip); //Set the IP Address
                    i.putExtra("port_number", port); //Set the port
                    i.putExtra("request_string", requestString); //Set the requested resource
                    startActivity(i); //Start the activity

                    //Finish the current activity on the UI thread
                    handler.post(new Runnable() {
                        @Override
                        public void run() {
                            finish();
                        }
                    });
                }
            }
        });

        //Camera is now running
        cameraRunning = true;
    }

    private void ReleaseCamera()
    {
        if (cameraRunning) //If camera is started
        {
            cameraRunning = false; //Set the state of the camera to stopped
            cameraSource.stop(); //Stop the camera
            cameraSource.release(); //Release resources
        }
    }
}
