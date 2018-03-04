package com.dev.ghost.fingerprintauthentication;

import android.arch.persistence.room.Dao;
import android.arch.persistence.room.Delete;
import android.arch.persistence.room.Insert;
import android.arch.persistence.room.Query;
import android.arch.persistence.room.Update;

//Interface for the key storage table
@Dao
public interface KeyStorageDAO
{
    //Remove a key
    @Delete
    void removeKey(KeyStorage... keysToRemove);

    //Modify a key
    @Update
    void updateKey(KeyStorage... keysToUpdate);

    //Add a new key
    @Insert
    void addKey(KeyStorage... keysToAdd);

    //Get a key by it's name
    @Query("SELECT * FROM KeyStorage WHERE keyNameHash = :keyHashName")
    KeyStorage[] getKeyByName(String keyHashName);

    //Get all stored keys
    @Query("SELECT * FROM KeyStorage")
    KeyStorage[] getAllKeys();

    //Wipe the table
    @Query("DELETE FROM KeyStorage")
    void wipeTable();
}