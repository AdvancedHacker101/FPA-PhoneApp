package com.dev.ghost.fingerprintauthentication;

import android.hardware.fingerprint.FingerprintManager;
import android.os.CancellationSignal;

public class FingerPrintHandler extends FingerprintManager.AuthenticationCallback
{
    private FingerprintHelperListener listener; //Result listener

    FingerPrintHandler(FingerprintHelperListener listener) {
        this.listener = listener; //Set the listener
    }

    private CancellationSignal cancellationSignal; //Authentication Cancel Signal

    void startAuth(FingerprintManager manager, FingerprintManager.CryptoObject cryptoObject) {
        cancellationSignal = new CancellationSignal(); //Create a new signal

        try {
            manager.authenticate(cryptoObject, cancellationSignal, 0, this, null); //Authenticate fingerprint
        } catch (SecurityException ex) {
            listener.authenticationFailed("An error occurred:\n" + ex.getMessage()); //Authentication failed
        } catch (Exception ex) {
            listener.authenticationFailed("An error occurred\n" + ex.getMessage()); //Authentication failed
        }
    }

    void cancel() {
        if (cancellationSignal != null) //If signal is set
            cancellationSignal.cancel(); //Cancel the ongoing authentication
    }

    interface FingerprintHelperListener {
        void authenticationFailed(String error); //Authentication fail callback
        void authenticationSucceeded(FingerprintManager.AuthenticationResult result); //Authentication success callback
    }

    @Override
    public void onAuthenticationError(int errMsgId, CharSequence errString) {
        listener.authenticationFailed("Authentication error\n" + errString); //Authentication error occurred
    }

    @Override
    public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
        listener.authenticationFailed("Authentication help\n" + helpString); //Authentication Help requested
    }

    @Override
    public void onAuthenticationFailed() {
        listener.authenticationFailed("Authentication failed."); //Authentication failed
    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
        listener.authenticationSucceeded(result); //Authentication success
    }
}
