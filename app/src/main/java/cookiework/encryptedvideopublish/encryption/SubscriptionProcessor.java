/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package cookiework.encryptedvideopublish.encryption;
import android.content.Context;
import android.util.Log;

import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.spongycastle.math.ec.ECFieldElement;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.util.encoders.UrlBase64;

import static cookiework.encryptedvideopublish.Constants.ECCURVE;
import static cookiework.encryptedvideopublish.Constants.ECCURVE_NAME;
import static cookiework.encryptedvideopublish.Constants.TIME_LOG_TAG;

/**
 *
 * @author Andrew
 *
 * This class is designed encapsulate methods that are used in the subscription process.
 * Subscribe, Approve and Finalize.  It uses the methods from PtwittEnc to accomplish
 * this task and provide the Firefox extension an simplier way to do different subscription methods.
 */
public class SubscriptionProcessor {

    private PtWittEnc enc;
    
    //Constructor generates random 'r' value from a using the java secruity secure random class with specified number of bits
    public SubscriptionProcessor(Context context)
    {
        this.enc = new PtWittEnc(context);
    }

    public ECPoint generateResponse(BigInteger d, ECPoint M)
    {
        // mPrime = dm
        ECPoint mPrime = M.multiply(d);
        return mPrime;
    }

    public String getResponseString(String dStr, String MStr)
    {
        String mPrimeStr = "";

        try
        {
            long beginTime = System.currentTimeMillis();

            BigInteger d =  new BigInteger(dStr);
            byte[] mByte = UrlBase64.decode(MStr);
            ECPoint M = ECCURVE.decodePoint(mByte);
            ECPoint mPrime = generateResponse(d, M);
            mPrimeStr = new String(UrlBase64.encode(mPrime.getEncoded(true)));

            long endTime = System.currentTimeMillis();
            Log.i(TIME_LOG_TAG, "generateResponse(): " + (endTime - beginTime));
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }

        return mPrimeStr;
    }
}
