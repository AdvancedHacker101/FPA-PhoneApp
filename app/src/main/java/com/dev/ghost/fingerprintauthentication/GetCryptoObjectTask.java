package com.dev.ghost.fingerprintauthentication;

import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

class GetCryptoObjectTask
{
    private KeyStore mKeyStore; //Android Default Key Storage
    private String KEYSTORE = "AndroidKeyStore"; //Name of the key store
    private String KEYNAME = "windowsLoginKey"; //Name of the stored key
    private String IVNAME = "fpauthIV"; //Name of the SharedPreference for storing the IV
    private Cipher mCipher; //Cipher generated from the key
    FingerprintManager.CryptoObject mCryptoObject; //The crypto object unlocked with fingerprint
    private Integer mode; //Encrypt or Decrypt


    GetCryptoObjectTask(Integer runMode)
    {
        mode = runMode; //Set the crypt mode
    }

    boolean RunTask()
    {
        //Try to get the crypto object
        return !(!GenerateKeyStore() || !GenerateNewKey() || !GetCipher() || !CipherInit(mode) || !InitCryptoObject());
    }

    private boolean InitCryptoObject()
    {
        try {
            mCryptoObject = new FingerprintManager.CryptoObject(mCipher); //Create a crypto object using our cipher
            return true; //Crypto object generated
        } catch (Exception ex) {
            Log.e(MainActivity.LOG_TAG, "An error occurred, while initializing new crypto object:\r\n" + ex.getMessage());
            return false; //Failed to generate crypto object
        }
    }

    private boolean CipherInit(int generationMode)
    {
        Log.d(MainActivity.LOG_TAG, "Cipher Initialization Running");

        try
        {
            mKeyStore.load(null); //Load a new emtpy keystore
            SecretKey myKey = (SecretKey) mKeyStore.getKey(KEYNAME, null); //Get our generated key

            if (generationMode == Cipher.ENCRYPT_MODE) //Encryption mode
            {
                Log.d(MainActivity.LOG_TAG, "Generating Encryption Cipher");
                mCipher.init(generationMode, myKey); //Init the cipher using our key

                SharedPreferences.Editor spEdit = MainActivity.sp.edit(); //Get a new SharedPreferences editor
                spEdit.putString(IVNAME, Base64.encodeToString(mCipher.getIV(), Base64.NO_WRAP)); //Store the IV in shared preferences
                spEdit.commit(); //Commit the shared preferences
            }
            else //Decryption
            {
                Log.d(MainActivity.LOG_TAG, "Generating Decryption Cipher");
                byte[] iv = Base64.decode(MainActivity.sp.getString(IVNAME, ""), Base64.NO_WRAP); //Get the IV from shared preferences
                IvParameterSpec ivParameter = new IvParameterSpec(iv); //Convert the bytes to an IV
                mCipher.init(generationMode, myKey, ivParameter); //Init the cipher
            }

            return true; //Cipher initialized
        }
        catch (Exception ex)
        {
            Log.e(MainActivity.LOG_TAG, "Error occurred while initializing cipher:\r\n" + ex.getMessage());
            return false; //Failed to initialize cipher
        }
    }

    private boolean GetCipher()
    {
        Log.d(MainActivity.LOG_TAG, "Getting new cipher");
        try
        {
            //Create a corresponding AES cipher
            mCipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + //AES Cipher
                KeyProperties.BLOCK_MODE_CBC + "/" + //CBC block mode
                KeyProperties.ENCRYPTION_PADDING_PKCS7); //PKCS7 Padding

            Log.d(MainActivity.LOG_TAG, "Cipher created successfully");
            return true; //Cipher generated
        }
        catch (Exception ex)
        {
            Log.e(MainActivity.LOG_TAG, "Error occurred while creating cipher:\r\n" + ex.getMessage());
            return false; //Failed to generate cipher
        }
    }

    private boolean GenerateNewKey()
    {
        Log.d(MainActivity.LOG_TAG, "Generating new key");

        try
        {
            if (!mKeyStore.containsAlias(KEYNAME)) //If key not yet created
            {
                KeyGenerator mKeyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE); //Get a new AES key generator
                //Init the key generator
                mKeyGen.init(new KeyGenParameterSpec.Builder (KEYNAME, //The name of our key
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT) //Used for encrypt/decrypt
                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC) //CBC Mode for AES
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7) //PKCS7 padding for AES
                        .setUserAuthenticationRequired(true) //Require auth (lock with fingerprint)
                        .build() //Build the key generator
                );

                mKeyGen.generateKey(); //Generate the key
                Log.d(MainActivity.LOG_TAG, "Key generated successfully");
                return true; //Key generated successfully
            }
            else //Key is created
            {
                Log.w(MainActivity.LOG_TAG, "Key already exists");
                return true; //Success, but not needed to regenerate
            }
        }
        catch (Exception ex)
        {
            Log.e(MainActivity.LOG_TAG, "Error occurred while generating key:\r\n" + ex.getMessage());
            return false; //Failed to generate key
        }
    }

    private boolean GenerateKeyStore()
    {
        Log.d(MainActivity.LOG_TAG, "Generating New Empty Keystore");
        try
        {
            mKeyStore = KeyStore.getInstance(KEYSTORE); //Get the android key store
            mKeyStore.load(null); //Load an empty key store
            Log.d(MainActivity.LOG_TAG, "Key Store generated successfully");
            return true; //Load successful
        }
        catch (Exception ex)
        {
            Log.e(MainActivity.LOG_TAG, "Error occurred while generating new empty keystore:\r\n" + ex.getMessage());
            return false; //Failed to load
        }
    }
}
