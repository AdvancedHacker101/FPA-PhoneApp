package com.dev.ghost.fingerprintauthentication;

import android.arch.persistence.room.Dao;
import android.arch.persistence.room.Delete;
import android.arch.persistence.room.Insert;
import android.arch.persistence.room.OnConflictStrategy;
import android.arch.persistence.room.Query;
import android.arch.persistence.room.Update;

//Interface for the credentials table
@Dao
public interface LoginDataDAO
{
    //Add new credentials to the table
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    void insertLoginData(LoginData... loginData);

    //Remove credentials from the table
    @Delete
    void removeLoginData(LoginData... loginData);

    //Modify credentials in the table
    @Update
    void updateLoginData(LoginData... loginData);

    //Get all the credentials from the Table
    @Query("SELECT * FROM LoginData;")
    LoginData[] getAllLoginData();

    //Get the credentials of a web site
    @Query("SELECT * FROM LoginData WHERE webSiteUrl = :websiteUrl")
    LoginData[] getLoginDataByWebsite(String websiteUrl);

    //Wipe the table
    @Query("DELETE FROM LoginData")
    void wipeTable();
}
