package com.dev.ghost.fingerprintauthentication;

import android.arch.persistence.room.Database;
import android.arch.persistence.room.RoomDatabase;

//Database for the application
@Database(entities = {LoginData.class, KeyStorage.class}, version = 1)
public abstract class AppDatabase extends RoomDatabase
{
    public abstract LoginDataDAO loginDataDAO(); //Credentials table
    public abstract KeyStorageDAO keyStorageDAO(); //Login keys table
}
