package com.dev.ghost.fingerprintauthentication;

import android.app.AlertDialog;
import android.content.DialogInterface;
import android.hardware.fingerprint.FingerprintManager;
import android.os.AsyncTask;
import android.os.Handler;
import android.os.Looper;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class NetworkClient extends AsyncTask<Object, Object, Void>
{
    private IvParameterSpec ivParameterSpec; //IV to use for crypto
    private SecretKeySpec secretKeySpec; //Our key protected by the fingerprint
    private AppCompatActivity activity; //WaitingDialog activity
    private Socket clientSocket; //Socket connected to the PC
    private AlertDialog dialog; //Alert dialog on authentication

    NetworkClient(AppCompatActivity parent)
    {
        activity = parent; //Set the parent activity
    }

    @Override
    protected Void doInBackground(Object... objects)
    {
        if (objects.length < 4) //Check if all parameters are given
        {
            //Too few arguments
            Log.e(MainActivity.LOG_TAG, "Too few arguments given to the Network Handler");
            return null;
        }
        String connectionAddress = objects[0].toString(); //Get the IP Address
        Integer connectionPort = Integer.parseInt(objects[1].toString()); //Get the port
        String resourceToReturn = objects[2].toString(); //Get the requested resource
        FingerprintManager fpManager = (FingerprintManager)objects[3]; //Get the fingerprint manager
        try {
            clientSocket = new Socket(connectionAddress, connectionPort); //Connect to the PC
            PrintWriter outputBuffer = new PrintWriter(new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream())), true); //Get the output stream
            BufferedReader inputBuffer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream())); // Get the input stream
            try
            {
                if (DoHandshake(inputBuffer, outputBuffer)) //Encryption handshake with the PC
                {
                    Log.d(MainActivity.LOG_TAG, "Session Established"); //Encryption successful
                    HandleRequest(resourceToReturn, outputBuffer, inputBuffer, fpManager); //Handle the actual request
                }
                else //Handshake failed
                {
                    Log.e(MainActivity.LOG_TAG, "Failed to establish session");
                }
            }
            catch (Exception ex)
            {
                ex.printStackTrace(); //Something failed
            }
        } catch (IOException e) {
            e.printStackTrace(); //Socket couldn't connect
        }

        return null;
    }

    @Override
    protected void onProgressUpdate(Object... objects)
    {
        Boolean openDialog = (Boolean)objects[0]; //Open or Close the dialog
        if (!openDialog) DismissFingerprintDialog(); //Close the dialog
        else //Open the dialog
        {
            FingerPrintHandler fph = (FingerPrintHandler) objects[1]; //Get the fingerprint handler (for cancel)
            PrintWriter output = (PrintWriter) objects[2]; //Get the output (for notifying server of cancel)
            ShowFingerprintDialog(fph, output); //Show the dialog
        }
    }

    private FingerprintManager.CryptoObject GetCryptoObject(int mode)
    {
        GetCryptoObjectTask gco = new GetCryptoObjectTask(mode); //Create a new Task
        if (gco.RunTask()) return gco.mCryptoObject; //Get the crypto object
        else return null; //Failed to get the crypto object
    }

    private void FinishActivity()
    {
        //Invoke on UI thread
        Handler uiHandler = new Handler(Looper.getMainLooper());
        uiHandler.post(new Runnable() {
            @Override
            public void run() {
                activity.finish(); //Finish the parent activity
            }
        });
    }

    private void DismissFingerprintDialog()
    {
        dialog.dismiss(); //Dismiss the authentication dialog
    }

    private void ShowFingerprintDialog(final FingerPrintHandler handler, final PrintWriter output)
    {
        AlertDialog.Builder builder = new AlertDialog.Builder(activity); //Get the dialog builder
        builder.setIcon(R.drawable.ic_fingerprint_black_24dp); //Set the cool fingerprint icon
        builder.setTitle("Authentication"); //Set the title of the box
        builder.setMessage("Please touch the fingerprint sensor"); //Set the text of the box
        builder.setNegativeButton("Cancel", new DialogInterface.OnClickListener() { //Add cancel button callback
            @Override
            public void onClick(DialogInterface dialogInterface, int i) {
                handler.cancel(); //Cancel the authentication
                Thread networkThread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try
                        {
                            SendMessage(output, EncryptData("no-fp")); //Send message to server
                        }
                        catch (Exception ex)
                        {
                            Log.e(MainActivity.LOG_TAG, "Failed to send no-fp message to server: " + ex.toString()); //Failed to send message
                        }

                        CloseConnection(); //Close the connection to the server
                    }
                });

                networkThread.start(); //Start the network thread
                dialogInterface.dismiss(); //Dismiss the dialog
                FinishActivity(); //Finish the parent activity
                MainActivity.createToast.call("Fingerprint Authentication Denied!");
            }
        });

        dialog = builder.create(); //Create the dialog
        dialog.show(); //Display the dialog
    }

    private void CloseConnection()
    {
        try
        {
            clientSocket.shutdownInput(); //Close input stream
            clientSocket.shutdownOutput(); //Close output stream
            clientSocket.close(); //Close socket
        }
        catch (Exception ex) //Failed to close connection
        {
            Log.e(MainActivity.LOG_TAG, "Error occurred while closing socket: " + ex.toString());
        }
    }

    private void SendPassword(final FingerprintManager manager, String urlHash, final PrintWriter output)
    {
        Log.d(MainActivity.LOG_TAG, "Starting fingerprint authentication");
        final FingerprintManager.CryptoObject cryptoObject = GetCryptoObject(Cipher.DECRYPT_MODE); //Get password decrypt object

        if (cryptoObject == null) //Failed to get the decrypt object
        {
            Log.e(MainActivity.LOG_TAG, "Failed to get the crypto object");
            CloseConnection(); //Close the connection
            FinishActivity();
            MainActivity.createToast.call("Internal Failure");
            return;
        }

        String toDecrypt;
        final String userName;

        LoginData[] webLoginData = MainActivity.appDatabase.loginDataDAO().getLoginDataByWebsite(urlHash); //Get the login data for the web site
        if (webLoginData.length > 0) //Website stored in DB
        {
            toDecrypt = webLoginData[0].passwordCipher; //Get the encrypted password
            userName = webLoginData[0].userName; //Get the username
        }
        else //Website not found in DB
        {
            try
            {
                SendMessage(output, EncryptData("no-register")); //Notify the server

            }
            catch (Exception ex)
            {
                Log.e(MainActivity.LOG_TAG, "Failed to send message: " + ex.getMessage());
            }

            CloseConnection();
            FinishActivity();
            MainActivity.createToast.call("Credentials not stored for this site");
            return;
        }

        FPListener fpListener = new FPListener(); //Create a new authentication listener
        final FingerPrintHandler fpHandler = new FingerPrintHandler(fpListener); //Create a new authentication handler
        fpListener.encrypt = false; //Decrypt data
        fpListener.inputValue = toDecrypt; //Decrypt this data
        fpListener.resultCallback = new ListenerCallback() { //Result callback
            @Override
            public void call(Object... obj) {

                final Object[] objects = obj; //Get the objects
                Thread t = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        Log.d(MainActivity.LOG_TAG, "Got fingerprint decrypt result");
                        FPListener listener = (FPListener)objects[0]; //Get the listener
                        String cipherText = listener.outputResult; //Get the decrypted password
                        try {
                            SendMessage(output, EncryptData("pwresp-" + cipherText)); //Send password to the PC
                            SendMessage(output, EncryptData("usresp-" + userName)); //Send username to the PC
                        } catch (Exception e) {
                            e.printStackTrace(); //Something went wrong
                        }
                        CloseConnection(); //Close the connection to the PC
                        publishProgress(false, fpHandler, output);
                        FinishActivity();
                        MainActivity.createToast.call("Credentials sent to PC");
                    }
                });

                t.start(); //Start the thread
            }
        };
        fpHandler.startAuth(manager, cryptoObject); //Start the authentication
        publishProgress(true, fpHandler, output);
    }

    private void StorePassword(final FingerprintManager manager, final String url, final String user, final String pass, final PrintWriter output)
    {
        Log.d(MainActivity.LOG_TAG, "Starting fingerprint authentication");
        FingerprintManager.CryptoObject cryptoObject = GetCryptoObject(Cipher.ENCRYPT_MODE); //Get password encrypt object

        if (cryptoObject == null) //Failed to get the object
        {
            Log.e(MainActivity.LOG_TAG, "Failed to get the crypto object");
            CloseConnection(); //Close connection to the PC
            FinishActivity();
            MainActivity.createToast.call("Internal Failure");
            return;
        }

        FPListener fpListener = new FPListener(); //Create a new authentication listener
        final FingerPrintHandler fpHandler = new FingerPrintHandler(fpListener); //Create a new authentication handler
        fpListener.encrypt = true; //Encrypt the data
        fpListener.inputValue = pass; //Encrypt this data (the password)
        fpListener.resultCallback = new ListenerCallback() { //Result callback
            @Override
            public void call(Object... obj) {

                //This gets invoked on the main thread
                //Run code on a new thread because of DB and Networking actions

                final Object[] objects = obj; // Get the object

                Thread t = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        Log.d(MainActivity.LOG_TAG, "Got fingerprint encrypt result");
                        FPListener listener = (FPListener)objects[0]; //Get the listener
                        String cipherText = listener.outputResult; //Get the encrypted password
                        LoginData loginData = new LoginData(); //Create a new entry
                        loginData.webSiteUrl = url; //Set the URL hash
                        loginData.userName = user; //Set the username
                        loginData.passwordCipher = cipherText; //Set the encrypted password
                        MainActivity.appDatabase.loginDataDAO().insertLoginData(loginData); //Insert entry to the DB
                        Log.d(MainActivity.LOG_TAG, "Credentials stored");
                        CloseConnection(); //Close connection to the PC
                        publishProgress(false, fpHandler, output);
                        FinishActivity();
                        MainActivity.createToast.call("Credentials Stored!");
                    }
                });

                t.start(); //Start the thread
            }
        };
        fpHandler.startAuth(manager, cryptoObject); //Start the authentication
        publishProgress(true, fpHandler, output);
    }

    private void StoreKey(final FingerprintManager manager, final String name, String value, final PrintWriter output, final String outputMessage)
    {
        Log.d(MainActivity.LOG_TAG, "Starting fingerprint authentication");
        FingerprintManager.CryptoObject cryptoObject = GetCryptoObject(Cipher.ENCRYPT_MODE); //Get the password encrypt object

        if (cryptoObject == null) //Failed to get the object
        {
            Log.e(MainActivity.LOG_TAG, "Failed to get the crypto object");
            CloseConnection(); //Close the connection to the PC
            return;
        }

        FPListener fpListener = new FPListener(); //Create a new authentication listener
        final FingerPrintHandler fpHandler = new FingerPrintHandler(fpListener); //Create a new authentication handler
        fpListener.encrypt = true; //Encrypt data
        fpListener.inputValue = value; //Encrypt the key
        fpListener.resultCallback = new ListenerCallback() { //Result callback
            @Override
            public void call(Object... obj) {

                //This gets invoked on the main thread
                //Run code on a new thread because of DB and Networking actions

                final Object[] objects = obj; //Get the objects
                Thread t = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        Log.d(MainActivity.LOG_TAG, "Got fingerprint encrypt result");
                        FPListener listener = (FPListener)objects[0]; //Get the listener
                        String cipherText = listener.outputResult; //Get the encrypted password
                        KeyStorage ks = new KeyStorage(); //Create a new entry
                        ks.keyValueBase64 = cipherText; //Set the value of the key
                        ks.keyNameHash = name; //Set the hashed name of the key
                        MainActivity.appDatabase.keyStorageDAO().addKey(ks); //Insert the entry to the DB
                        Log.d(MainActivity.LOG_TAG, "Key stored");
                        CloseConnection(); //Close the connection to the PC
                        publishProgress(false, fpHandler, output); //Dismiss authentication dialog
                        FinishActivity(); //Finish the parent activity
                        MainActivity.createToast.call(outputMessage); //Display toast on MainActivity
                    }
                });

                t.start(); //Start the thread
            }
        };
        fpHandler.startAuth(manager, cryptoObject); //Start the authentication
        publishProgress(true, fpHandler, output); //Show authentication dialog
    }

    private void GetKey(final FingerprintManager manager, String name, final PrintWriter output, final String outputMessage)
    {
        Log.d(MainActivity.LOG_TAG, "Starting fingerprint authentication");
        FingerprintManager.CryptoObject cryptoObject = GetCryptoObject(Cipher.DECRYPT_MODE); //Get the key decrypt object

        if (cryptoObject == null) //Failed to get decrypt object
        {
            Log.e(MainActivity.LOG_TAG, "Failed to get the crypto object");
            CloseConnection(); //Close connection to the PC
            FinishActivity();
            MainActivity.createToast.call("Internal Failure");
            return;
        }

        KeyStorage[] key = MainActivity.appDatabase.keyStorageDAO().getKeyByName(name); //Get the key entry by the name of the key

        if (key.length <= 0) //No entries found
        {
            Log.w(MainActivity.LOG_TAG, "Failed to find the specified key: " + name);
            try
            {
                SendMessage(output, EncryptData("no-setup")); //Notify the server
            }
            catch (Exception ex) //Failed to send message to the server
            {
                Log.e(MainActivity.LOG_TAG, "Failed to send message to server: " + ex.toString());
            }
            CloseConnection(); //Close connection to the PC
            FinishActivity();
            MainActivity.createToast.call("Authentication not setup");
            return;
        }

        String value = key[0].keyValueBase64; // Get the encrypted key

        FPListener fpListener = new FPListener(); //Create a new authentication listener
        final FingerPrintHandler fpHandler = new FingerPrintHandler(fpListener); //Create a new authentication handler
        fpListener.encrypt = false; //Decrypt data
        fpListener.inputValue = value; //Decrypt the key
        fpListener.resultCallback = new ListenerCallback() {
            @Override
            public void call(Object... obj) { //Result callback

                //This gets invoked on the main thread
                //Run code on a new thread because of DB and Networking actions

                final Object[] objects = obj; //Get hte objects
                Thread t = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        Log.d(MainActivity.LOG_TAG, "Got fingerprint decrypt result");
                        FPListener listener = (FPListener)objects[0]; //Get the listener
                        String cipherText = listener.outputResult; //Get the decrypted key
                        try
                        {
                            SendMessage(output, EncryptData("pushkey-" + cipherText)); //Send the key to the server
                            Log.d(MainActivity.LOG_TAG, "Key sent");
                        }
                        catch (Exception ex) //Failed to send key to the server
                        {
                            Log.e(MainActivity.LOG_TAG, "Error occurred while sending data: " + ex.toString());
                            CloseConnection(); //Close connection to the PC
                            publishProgress(false, fpHandler, output); //Dismiss the authentication dialog
                            FinishActivity(); //Finish the parent activity
                            MainActivity.createToast.call("Failed to send key to PC"); //Display toast on MainActivity
                            return;
                        }


                        CloseConnection(); //Close the connection to the PC
                        publishProgress(false, fpHandler, output); //Dismiss the authentication dialog
                        FinishActivity(); //Finish the parent activity
                        MainActivity.createToast.call(outputMessage); //Display toast on MainActivity
                    }
                });
                t.start(); //Start the thread
            }
        };
        fpHandler.startAuth(manager, cryptoObject); //Start the authentication
        publishProgress(true, fpHandler, output); //Show authentication dialog
    }

    private void HandleRequest(String requestString, PrintWriter output, BufferedReader input, FingerprintManager fpManager)
    {
        try {

            if (!SendMessage(output, EncryptData("res-" + requestString))) return; //Send request string to the server
            ReadData(input); //Block execution, wait for the server to take actions

            if (requestString.startsWith("pw-")) //Credentials requested
            {
                int delimiter = requestString.indexOf("-") + 1; //Get the split index
                String url = requestString.substring(delimiter); //Remove the header
                Log.d(MainActivity.LOG_TAG, "URL Hash: " + url);

                SendPassword(fpManager, url, output);
            }
            else if (requestString.startsWith("storpw-"))
            {
                int delimiter = requestString.indexOf("-") + 1; //Get the split index
                String url = requestString.substring(delimiter); //Remove the header
                SendMessage(output, EncryptData("getuser"));
                String userName = DecryptData(ReadData(input));
                SendMessage(output, EncryptData("getpass"));
                String password = DecryptData(ReadData(input));
                StorePassword(fpManager, url, userName, password, output);
            }
            else if (requestString.equals("win") || requestString.equals("lock")) //Lock or Unlock PC
            {
                String msg = (requestString.equals("win")) ? "PC Unlocked" : "PC Locked"; //Get the success message
                String keyName = DigestData("windowsLogon"); //Hash the name of the key
                GetKey(fpManager, keyName, output, msg); //Decrypt the key, and send it to the server
            }
            else if (requestString.startsWith("getkvalue-"))
            {
                int delimiter = requestString.indexOf("-") + 1; //Get the split index
                String keyName = requestString.substring(delimiter); //Remove the header
                keyName = DigestData(keyName); //hash the name of the key
                GetKey(fpManager, keyName, output, "Authentication Token Sent"); //Decrypt the key, nad sent it to the server
            }
            else if (requestString.startsWith("getkname-")) //Install a new key to the DB
            {
                int delimiter = requestString.indexOf("-") + 1; //Get the split index
                String keyName = requestString.substring(delimiter); //Remove the header
                SendMessage(output, EncryptData("getkvalue")); //Request key value from the server
                String keyValue = DecryptData(ReadData(input)); //Read the key value
                keyName = DigestData(keyName); //Hash the name of the key

                if (keyValue.equals("fail")) //Key value is fail
                {
                    Log.w(MainActivity.LOG_TAG, "Server didn't send the key");
                    CloseConnection();
                    FinishActivity();
                    MainActivity.createToast.call("Key Exchange Failed");
                    return;
                }

                StoreKey(fpManager, keyName, keyValue, output, "Key added to database"); //Encrypt and Install the key

                Log.d(MainActivity.LOG_TAG, "Key added to DB");
            }
            else //Unknown command
            {
                Log.e(MainActivity.LOG_TAG, "Unknown request string");
            }

        } catch (Exception e) {
            e.printStackTrace(); //Something went wrong
        }
    }

    private String DigestData(String dataToDigest) throws NoSuchAlgorithmException, UnsupportedEncodingException {

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256"); //Create a new hash object
        byte[] result = messageDigest.digest(dataToDigest.getBytes("UTF-8")); //Hash the input string
        return Base64.encodeToString(result, Base64.DEFAULT); //Return the base64 encoded hashed string
    }

    private boolean CheckPublicKey(String publicKeyData) throws UnsupportedEncodingException, NoSuchAlgorithmException {

        //Key "Pinning" Function

        String keyToFind = DigestData("mainKey"); //Hash the name of the key
        KeyStorage[] keys = MainActivity.appDatabase.keyStorageDAO().getKeyByName(keyToFind); //Get the key from the DB
        if (keys.length > 0) //Key stored in DB
        {
            String keyValue = keys[0].keyValueBase64; //Get the public key
            return keyValue.equals(publicKeyData); //Check if the stored key matches with the specified
        }
        else //No keys in the DB (first time connection only or DB Wipe)
        {
            KeyStorage mainKey = new KeyStorage(); //Create a new entry
            mainKey.keyNameHash = keyToFind; //Set the name of the key
            mainKey.keyValueBase64 = publicKeyData; //Set the key
            MainActivity.appDatabase.keyStorageDAO().addKey(mainKey); //Insert the entry to the DB
            return true; //Continue process
        }
    }

    private boolean DoHandshake(BufferedReader input, PrintWriter output) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException {

        SendMessage(output, "auth-msg"); //Send authentication request to the server
        String publicKey = ReadData(input); //Read the public key
        if (publicKey == null) return false; //Check if the read failed
        if (!CheckPublicKey(publicKey)) //Check if the public key is valid
        {
            Log.e(MainActivity.LOG_TAG, "Wrong public key supplied");
            return false; //Handshake failed
        }
        PublicKey pk = GetPublicKey(publicKey); //Parse the public key
        if (pk == null) return false; //Parse failed
        String aesTextKey = GetEncryptionKey(); //Get the session key
        String encryptedAesKey = EncryptWithKey(pk, aesTextKey); //Encrypt the session key with the public key

        return SendMessage(output, "set-session-key" + encryptedAesKey); //Send the session key to the server
    }

    private String ReadData(BufferedReader input)
    {
        try {
            return input.readLine().replace("rpwenter\\n", "\r\n"); //Read data from the input stream (parse newline chars)
        } catch (IOException e) {
            e.printStackTrace(); //Failed to read from stream
            return null;
        }
    }

    private String EncryptData(String inputData) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        //Encrypt with session key
        byte[] toEncrypt = inputData.getBytes("UTF-8"); //Get the bytes of the input string
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //Create a new cipher
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec); //Init the cipher with the session key
        byte[] encrypted = cipher.doFinal(toEncrypt); //Encrypt the input data
        return Base64.encodeToString(encrypted, Base64.DEFAULT); //Return the Base64 of the encrypted data
    }

    private String DecryptData(String inputData) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
        byte[] toDecrypt = Base64.decode(inputData, Base64.DEFAULT); //Get the bytes of the input data
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //Get the new cipher
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec); //Init the new cipher with the session key
        byte[] decrypted = cipher.doFinal(toDecrypt); //Decrypt the input data
        return new String(decrypted, "UTF-8"); //Return the decrypted data in String
    }

    private String GetEncryptionKey() throws NoSuchAlgorithmException
    {
        byte[] IV = GetRandomKey(); //Generate random IV
        byte[] pass = GetRandomKey(); //Generate random password
        secretKeySpec = new SecretKeySpec(pass, "AES"); //Parse the password
        ivParameterSpec = new IvParameterSpec(IV); //Parse the IV
        return Base64.encodeToString(IV, Base64.DEFAULT) + "|" +
                Base64.encodeToString(pass, Base64.DEFAULT); //Return the session key and IV
    }

    private byte[] GetRandomKey()
    {
        SecureRandom random = new SecureRandom(); //Create a new SecureRandom value generator
        byte[] byteKey = new byte[16]; //Create buffer for the data
        random.nextBytes(byteKey); //Get random bytes
        return byteKey; //Return the random data
    }

    private String EncryptWithKey(PublicKey key, String message)
    {
        //Encrypt data with public key
        Cipher cipher; //RSA Cipher

        try {
            cipher = Cipher.getInstance("RSA"); //Create the RSA cipher
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        }

        try {
            cipher.init(Cipher.ENCRYPT_MODE, key); //Init the cipher with the public key
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }

        byte[] encrypted; //Buffer for encrypted data

        try {
            encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8)); //Encrypt the bytes of the input data
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            return null;
        } catch (BadPaddingException e) {
            e.printStackTrace();
            return null;
        }


        return Base64.encodeToString(encrypted, Base64.DEFAULT); //Return the Base64 of the encrypted data
    }

    private PublicKey GetPublicKey(String derPublicKey)
    {
        byte[] keyDataBytes = Base64.decode(derPublicKey, Base64.DEFAULT); //Decode the Base64 key

        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyDataBytes); //Parse the key
        KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance("RSA"); //Get new RSA key generator
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }

        try {
            return keyFactory.generatePublic(spec); //Generate the public key from the inputted public key
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    private boolean SendMessage(PrintWriter writeChannel, String message)
    {
        if (writeChannel != null && !writeChannel.checkError()) //Check if we can write to the output stream
        {
            writeChannel.println(message); //Print the message to the output stream
            writeChannel.flush(); //Flush the output stream
            return true; //Write successful
        }

        return false; //Write failed
    }
}

class FPListener implements FingerPrintHandler.FingerprintHelperListener
{
    //Authentication result listener
    String inputValue = null; //The input value
    String outputResult = null; //The result of the crypt
    boolean encrypt = true; //Encrypt or Decrypt
    ListenerCallback resultCallback = null; //Result callback
    private Object[] extraData; //Extra data to pass to the callback

    @Override
    public void authenticationFailed(String error)
    {
        //Authentication failed
        Log.e(MainActivity.LOG_TAG, "Finger Print Authentication Failed! Reason: " + error);
    }

    @Override
    public void authenticationSucceeded(FingerprintManager.AuthenticationResult result)
    {
        Log.d(MainActivity.LOG_TAG, "Finger Print Authentication Succeeded!");
        Cipher cipher = result.getCryptoObject().getCipher(); //Get the cipher of the crypto object
        if (encrypt) //Encrypt data
        {
            HandleEncryption(cipher); //Handle the encryption
        }
        else //Decrypt data
        {
            HandleDecryption(cipher); //Handler the decryption
        }

        if (resultCallback != null) //If result callback is specified
        {
            try {
                resultCallback.call(this, extraData); //Call the callback
            } catch (Exception e) {
                Log.e(MainActivity.LOG_TAG, "Failed result callback call, Reason:\r\n" + e.getMessage());
            }
        }
    }

    private void HandleDecryption(Cipher c)
    {
        try {
            byte[] bytes = Base64.decode(inputValue, Base64.NO_WRAP); //Decode Base64 input
            String finalText = new String(c.doFinal(bytes)); //Decrypt the data and covert it to string
            outputResult = finalText; //Set the result variable
            Log.d(MainActivity.LOG_TAG, "Data Decrypted: " + finalText);
        } catch (Exception e) {
            Log.e(MainActivity.LOG_TAG, "Failed to decrypt data, Reason:\r\n" + e.getMessage());
        }
    }

    private void HandleEncryption(Cipher c)
    {
        try {
            byte[] bytes = c.doFinal(inputValue.getBytes()); //Encrypt the input data
            String encryptedText = Base64.encodeToString(bytes, Base64.NO_WRAP); //Encode the encrypted bytes to Base64
            outputResult = encryptedText; //Set the outputResult variable
            Log.d(MainActivity.LOG_TAG, "Success, text encrypted is: " + encryptedText);
        } catch (Exception e) {
            Log.e(MainActivity.LOG_TAG, "Encryption failed, Reason:\r\n" + e.getMessage());
        }
    }
}