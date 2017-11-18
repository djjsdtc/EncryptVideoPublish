package cookiework.encryptedvideopublish;

import org.spongycastle.math.ec.custom.sec.SecP256K1Curve;

/**
 * Created by Cookie on 2017-01-15.
 */

public interface Constants {
    String SERVER_ADDRESS = "http://10.21.238.153:8080/encryptvideoweb";
    String PUBLISH_ADDRESS = "rtmp://10.21.238.153/live/[stream_name]";
    //replace [stream_name] with real stream name
    String UPLOAD_ADDRESS = "http://10.21.238.153/upload.php";
    String EXECUTE_ADDRESS = "http://10.21.238.153/execute_enc.php";
    String ECCURVE_NAME = "secp256k1";
    SecP256K1Curve ECCURVE = new SecP256K1Curve();
    String SHARED_PREFERENCES = "cookiework.encryptedvideopublish.sp";
    int CONNECT_TIMEOUT = 8000;
    int READ_TIMEOUT = 8000;
    String DB_NAME = "publisher_db";
    int DB_VERSION = 2;
    String TIME_LOG_TAG = "TIME_LOG";
}
