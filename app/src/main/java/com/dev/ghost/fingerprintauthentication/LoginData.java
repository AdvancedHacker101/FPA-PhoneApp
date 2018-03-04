package com.dev.ghost.fingerprintauthentication;

import android.arch.persistence.room.Entity;
import android.arch.persistence.room.PrimaryKey;
import android.support.annotation.NonNull;

//Table for storing user credentials
@Entity
public class LoginData
{
    @PrimaryKey
    @NonNull
    public String webSiteUrl; //SHA256 Hash of the web site URL the credentials belong to

    public String userName; //The username
    public String passwordCipher; //The password
}
