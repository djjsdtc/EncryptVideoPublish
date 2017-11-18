package cookiework.encryptedvideopublish.util;

import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import org.spongycastle.util.encoders.UrlBase64;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;

import static cookiework.encryptedvideopublish.Constants.*;

/**
 * Created by Administrator on 2017/01/16.
 */

public class DBHelper extends SQLiteOpenHelper {
    private static final String CREATE_PUBLISHER_STATEMENT =
            //"create table publisher(username text unique, publicKey text, privateKey text)";
            "create table publisher(username text unique, oldPrivateKey text, privateKey text)";
    private static final String SELECT_KEY_STATEENT =
            "select * from publisher where username=?";
    private static final String INSERT_KEY_STATEMENT =
            //"insert into publisher(username, publicKey, privateKey) values(?,?,?)";
            "insert into publisher(username, oldPrivateKey, privateKey) values(?,null,?)";
    private static final String DELETE_KEY_STATEMENT =
            "delete from publisher where username=?";
    private static final String UPDATE_KEY_STATEMENT =
            //"update publisher set publicKey=?, privateKey=? where username=?";
            "update publisher set oldPrivateKey=?, privateKey=? where username=?";

    private static final String CREATE_VIDEOLOG_STATEMENT =
            "create table videolog(videoid int unique, tags text, key text)";
    private static final String ADD_VIDEOLOG_STATEMENT =
            "insert into videolog(videoid, tags, key) values(?,?,?)";
    private static final String DELETE_VIDEOLOG_STATEMENT =
            "delete from videolog where videoid=?";
    private static final String SELECT_VIDEOLOG_STATEMENT =
            "select * from videolog where videoid=?";

    public DBHelper(Context context) {
        super(context, DB_NAME, null, DB_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL(CREATE_PUBLISHER_STATEMENT);
        db.execSQL(CREATE_VIDEOLOG_STATEMENT);
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        if(oldVersion == 1 && newVersion == 2){
            db.execSQL(CREATE_VIDEOLOG_STATEMENT);
        }
    }

    public String getPrivateKey(String username){
        SQLiteDatabase db = getReadableDatabase();
        Cursor cursor = db.rawQuery(SELECT_KEY_STATEENT, new String[]{username});
        String result = null;
        if(cursor.moveToNext()){
            result = cursor.getString(cursor.getColumnIndex("privateKey"));
        }
        cursor.close();
        db.close();
        return result;
    }

    public String replaceKey(String username, String newKey){
        //returns oldkey
        if(getPrivateKey(username) == null){
            return null;
        } else {
            String oldKey = getPrivateKey(username);
            SQLiteDatabase db = getWritableDatabase();
            System.out.println(oldKey);
            System.out.println(newKey);
            System.out.println(username);
            db.execSQL(UPDATE_KEY_STATEMENT, new Object[]{oldKey, newKey, username});
            db.close();
            System.out.println("replace key ended.");
            return oldKey;
        }
    }

    public boolean addKey(String username, String privateKey){
        if(getPrivateKey(username) != null){
            return false;
        } else {
            SQLiteDatabase db = getWritableDatabase();
            db.execSQL(INSERT_KEY_STATEMENT, new Object[]{username, privateKey});
            db.close();
        }
        return true;
    }

    public void addVideoLog(int videoId, String tags, String key){
        SQLiteDatabase db = getWritableDatabase();
        db.execSQL(DELETE_VIDEOLOG_STATEMENT, new Object[]{videoId});
        db.execSQL(ADD_VIDEOLOG_STATEMENT, new Object[]{videoId, tags, key});
        db.close();
    }

    public HashMap<String, String> getVideoLog(int videoId){
        SQLiteDatabase db = getReadableDatabase();
        Cursor cursor = db.rawQuery(SELECT_VIDEOLOG_STATEMENT, new String[]{Integer.toString(videoId)});
        HashMap<String, String> result = null;
        if(cursor.moveToNext()){
            result = new HashMap<>();
            result.put("videoId", cursor.getString(cursor.getColumnIndex("videoid")));
            result.put("tags", cursor.getString(cursor.getColumnIndex("tags")));
            result.put("key", cursor.getString(cursor.getColumnIndex("key")));
        }
        cursor.close();
        db.close();
        return result;
    }
}
