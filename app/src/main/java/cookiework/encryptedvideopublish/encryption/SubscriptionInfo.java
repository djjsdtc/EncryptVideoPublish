package cookiework.encryptedvideopublish.encryption;

import com.google.gson.Gson;
import com.google.gson.JsonElement;

/**
 * Created by Administrator on 2017/01/12.
 */
public class SubscriptionInfo {
    public static final String SUBSCRIPTION_ISSUE = "issue";
    public static final String SUBSCRIPTION_APPROVE = "approve";
    public static final String SUBSCRIPTION_FINALIZE = "finalize";

    private int id;
    private String userID;
    private String status;
    private String m;
    private String destUserID;
    private String tagName;
    private String MPrime;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getUserID() {
        return userID;
    }

    public void setUserID(String userID) {
        this.userID = userID;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getM() {
        return m;
    }

    public void setM(String m) {
        this.m = m;
    }

    public String getDestUserID() {
        return destUserID;
    }

    public void setDestUserID(String destUserID) {
        this.destUserID = destUserID;
    }

    public String getTagName() {
        return tagName;
    }

    public void setTagName(String tagName) {
        this.tagName = tagName;
    }

    public String getMPrime() {
        return MPrime;
    }

    public void setMPrime(String MPrime) {
        this.MPrime = MPrime;
    }

    @Override
    public String toString() {
        return getUserID();
    }
}
