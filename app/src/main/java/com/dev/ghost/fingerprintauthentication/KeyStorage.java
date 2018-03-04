package com.dev.ghost.fingerprintauthentication;

import android.arch.persistence.room.Entity;
import android.arch.persistence.room.PrimaryKey;
import android.support.annotation.NonNull;

//Table for storing login keys
@Entity
public class KeyStorage
{
    @PrimaryKey
    @NonNull
    public String keyNameHash; //SHA256 Hash of the name of the key

    public String keyValueBase64; //The Base64 value of the hash
}
