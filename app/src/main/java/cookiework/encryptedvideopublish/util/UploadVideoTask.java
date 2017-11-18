package cookiework.encryptedvideopublish.util;

import android.app.Activity;
import android.app.ProgressDialog;
import android.content.DialogInterface;
import android.os.AsyncTask;
import android.widget.Toast;

import com.google.gson.JsonObject;

import org.spongycastle.util.encoders.UrlBase64;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;

import cookiework.encryptedvideopublish.CreateVodActivity;
import cookiework.encryptedvideopublish.R;
import cookiework.encryptedvideopublish.encryption.PtWittEnc;
import cookiework.encryptedvideopublish.encryption.VideoInfo;

import static cookiework.encryptedvideopublish.Constants.EXECUTE_ADDRESS;
import static cookiework.encryptedvideopublish.Constants.SERVER_ADDRESS;
import static cookiework.encryptedvideopublish.Constants.UPLOAD_ADDRESS;
import static java.net.HttpURLConnection.HTTP_OK;

/**
 * Created by CookieWork on 2017/5/3.
 */

public class UploadVideoTask extends AsyncTask<Void, Integer, Boolean> {
    private File file;
    private String title;
    private String intro;
    private CreateVodActivity activity;
    private PtWittEnc enc;
    private String username;
    private String plainTags;
    private String tags;
    private String encKeys;
    private ProgressDialog progressDialog;

    private int filesize;

    private static final String end = "\r\n";
    private static final String Hyphens = "--";
    private static final String boundary = "*****";

    public UploadVideoTask(File file, String username, String title, String intro, String plainTags, CreateVodActivity activity) {
        this.file = file;
        this.filesize = (int) file.length();
        this.title = title;
        this.intro = intro;
        this.activity = activity;
        this.enc = new PtWittEnc(activity);
        this.username = username;
        this.plainTags = plainTags.replaceAll(" +", " ").trim();
        createProgressDialog(activity);
    }

    protected void createProgressDialog(Activity activity) {
        progressDialog = new ProgressDialog(activity);
        progressDialog.setCancelable(true);
        progressDialog.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL);
        progressDialog.setMax(filesize);
        progressDialog.setProgress(0);
        progressDialog.setTitle("Uploading");
        progressDialog.setMessage("Please wait.");
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() {
            @Override
            public void onCancel(DialogInterface dialog) {
                UploadVideoTask.this.cancel(false);
            }
        });
    }

    @Override
    protected void onPreExecute() {
        progressDialog.show();
    }

    @Override
    protected void onCancelled() {
        progressDialog.dismiss();
        activity.setUploadVideoTask(null);
        Toast.makeText(activity, "您取消了上传。", Toast.LENGTH_LONG).show();
    }

    @Override
    protected void onPostExecute(Boolean success) {
        progressDialog.dismiss();
        activity.setUploadVideoTask(null);
        if(success){
            Toast.makeText(activity, "创建直播完成。", Toast.LENGTH_LONG).show();
            activity.finish();
        } else {
            Toast.makeText(activity, R.string.info_network_error, Toast.LENGTH_LONG).show();
        }
    }

    @Override
    protected void onProgressUpdate(Integer... values) {
        int progress = progressDialog.getProgress();
        progress += values[0];
        progressDialog.setProgress(progress);
    }

    @Override
    protected Boolean doInBackground(Void... params) {
        String filename = uploadFile(file);
        if(filename == null){
            return false;
        }
        String dStr = enc.dbHelper.getPrivateKey(username);
        String[] tagArray = plainTags.split(" ");
        VideoInfo info = enc.send(tagArray, title, intro, filename, dStr, "pending");
        int id = createVodItem(info);
        if(id == -1){
            return false;
        }
        return executeTransformAsync(filename, id);
    }

    protected String uploadFile(File file){
        try {
            System.setProperty("http.keepAlive", "false");
            String filename = file.getName();
            String str1 = Hyphens + boundary + end;
            String str2 = "Content-Disposition: form-data; " + "name=\"demo\"; filename=\"" + filename + "\"" + end;
            String str3 = Hyphens + boundary + Hyphens + end;
            URL url = new URL(UPLOAD_ADDRESS);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            /* 允许Input、Output，不使用Cache */
            con.setDoInput(true);
            con.setDoOutput(true);
            con.setUseCaches(false);
            con.setFixedLengthStreamingMode(str1.getBytes().length + str2.getBytes().length + end.getBytes().length + filesize + end.getBytes().length + str3.getBytes().length);
            /* 设定传送的method=POST */
            con.setRequestMethod("POST");
            /* setRequestProperty */
            //con.setRequestProperty("Connection", "Keep-Alive");
            con.setRequestProperty("connection", "close");
            con.setRequestProperty("Charset", "UTF-8");
            con.setRequestProperty("Content-Type",
                    "multipart/form-data;boundary=" + boundary);
            /* 设定DataOutputStream */
            DataOutputStream ds = new DataOutputStream(con.getOutputStream());
            ds.writeBytes(str1);
            ds.writeBytes(str2);
            ds.writeBytes(end);
            /* 取得文件的FileInputStream */
            FileInputStream fStream = new FileInputStream(file);
            /* 设定每次写入1024bytes */
            byte[] buffer = new byte[1024];
            int length = -1;
            /* 从文件读取数据到缓冲区 */
            while (!isCancelled() && (length = fStream.read(buffer)) != -1) {
            /* 将数据写入DataOutputStream中 */
                ds.write(buffer, 0, length);
                publishProgress(length);
            }
            if(!isCancelled()) {
                ds.writeBytes(end);
                ds.writeBytes(str3);
            }
            fStream.close();
            /* 取得Response内容 */
            if(!isCancelled()) {
                InputStream is = con.getInputStream();
                int ch;
                StringBuffer b = new StringBuffer();
                while ((ch = is.read()) != -1) {
                    b.append((char) ch);
                }
                ds.close();
                return b.toString();
            } else {
                ds.close();
                return null;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    protected void preprocessTags(VideoInfo info){
        StringBuilder tags_builder = new StringBuilder();
        StringBuilder encKeys_builder = new StringBuilder();
        for(String tag : info.getTagsAndEncKeys().keySet()){
            String encKey = info.getTagsAndEncKeys().get(tag);
            tags_builder.append(tag).append(" ");
            encKeys_builder.append(encKey).append(" ");
        }
        try {
            this.tags = new String(UrlBase64.encode(tags_builder.toString().getBytes("utf-8")), "utf-8");
            this.encKeys = new String(UrlBase64.encode(encKeys_builder.toString().getBytes("utf-8")), "utf-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    protected int createVodItem(VideoInfo info){
        preprocessTags(info);
        HashMap<String, String> vodParam = new HashMap<>();
        /*String userID = request.getParameter("userID");
        String title = request.getParameter("title");
        String intro = request.getParameter("intro");
        String addr = request.getParameter("addr");
        String status = request.getParameter("status");
        String tags_b64 = new String(UrlBase64.decode(request.getParameter("tags")), "utf-8");
        String encKeys_b64 = new String(UrlBase64.decode(request.getParameter("encKeys")), "utf-8");*/
        vodParam.put("userID", username);
        vodParam.put("title", info.getCipherTitle());
        vodParam.put("intro", info.getCipherIntro());
        vodParam.put("addr", info.getCipherAddr());
        vodParam.put("status", "transform");
        vodParam.put("tags", tags);
        vodParam.put("encKeys", encKeys);
        HttpUtil util = new HttpUtil();
        try{
            util.setMethod(HttpUtil.HttpRequestMethod.POST)
                    .setUrl(SERVER_ADDRESS + "/publisher/publishvideo")
                    .setQuery(vodParam)
                    .sendHttpRequest();
            if(util.getResponseCode() != HTTP_OK){
                return -1;
            }else {
                InputStream resultStream = util.getInputStream();
                String result = HttpUtil.convertInputStreamToString(resultStream);
                JsonObject resultObj = JsonUtil.getJsonObj(result);
                int id = resultObj.get("id").getAsInt();
                enc.dbHelper.addVideoLog(id, plainTags, info.getKey());
                return id;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return -1;
        }
    }

    protected boolean executeTransformAsync(String filename, int id){
        HttpUtil util = new HttpUtil();
        HashMap<String, String> transParam = new HashMap<>();
        transParam.put("id", Integer.toString(id));
        transParam.put("input", filename);
        try{
            util.setMethod(HttpUtil.HttpRequestMethod.POST)
                    .setUrl(EXECUTE_ADDRESS)
                    .setQuery(transParam)
                    .sendHttpRequest();
            if(util.getResponseCode() != HTTP_OK){
                return false;
            }else {
                InputStream resultStream = util.getInputStream();
                String result = HttpUtil.convertInputStreamToString(resultStream);
                if("success".equals(result)){
                    return true;
                } else {
                    return false;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
