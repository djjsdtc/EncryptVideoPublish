package cookiework.encryptedvideopublish;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.annotation.TargetApi;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.support.design.widget.FloatingActionButton;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.MenuItem;
import android.view.View;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.Toast;

import com.google.gson.JsonObject;

import org.spongycastle.util.encoders.UrlBase64;

import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.UUID;

import cookiework.encryptedvideopublish.encryption.PtWittEnc;
import cookiework.encryptedvideopublish.encryption.VideoInfo;
import cookiework.encryptedvideopublish.util.HttpUtil;
import cookiework.encryptedvideopublish.util.JsonUtil;

import static cookiework.encryptedvideopublish.Constants.SERVER_ADDRESS;
import static cookiework.encryptedvideopublish.Constants.SHARED_PREFERENCES;
import static java.net.HttpURLConnection.HTTP_OK;

public class CreateLiveActivity extends AppCompatActivity {
    private EditText txtTitle;
    private EditText txtTags;
    private EditText txtIntro;
    private FloatingActionButton fab;
    private PtWittEnc enc;
    private SharedPreferences sp;
    private View progressView;
    private View createLiveForm;
    private CreateLiveTask mAuthTask;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_create_live);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        txtTitle = (EditText) findViewById(R.id.txtTitle);
        txtTags = (EditText) findViewById(R.id.txtTags);
        txtIntro = (EditText) findViewById(R.id.txtIntro);
        enc = new PtWittEnc(this);
        sp = getSharedPreferences(SHARED_PREFERENCES, MODE_PRIVATE);

        fab = (FloatingActionButton) findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                processOkButton();
            }
        });
        getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        progressView = findViewById(R.id.createlive_progress);
        createLiveForm = findViewById(R.id.createlive_form);
    }

    @Override
    public void onBackPressed() {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle("返回").setMessage("返回主界面将丢弃所有未保存的更改。确认？");
        builder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                CreateLiveActivity.super.onBackPressed();
            }
        }).setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
            }
        });
        builder.show();
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if(item.getItemId() == android.R.id.home)
        {
            onBackPressed();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void processOkButton(){
        if(mAuthTask != null){
            return;
        }
        txtTitle.setError(null);
        txtTags.setError(null);
        String title = txtTitle.getText().toString();
        if(title.equals("")){
            txtTitle.setError("请输入直播名称");
            txtTitle.requestFocus();
            return;
        }
        String[] tags = txtTags.getText().toString().split(" +");
        if(tags.length == 1 && tags[0].equals("")){
            txtTags.setError("请输入至少一个直播标签");
            txtTags.requestFocus();
            return;
        }
        String intro = txtIntro.getText().toString();
        String username = sp.getString("username", null);
        String dStr = enc.dbHelper.getPrivateKey(username);
        String addr = UUID.randomUUID().toString();
        VideoInfo info = enc.send(tags, title, intro, addr, dStr, "pending");
        showProgress(true);
        mAuthTask = new CreateLiveTask(username, info, txtTags.getText().toString());
        mAuthTask.execute((Void) null);
    }

    /**
     * Shows the progress UI and hides the login form.
     */
    @TargetApi(Build.VERSION_CODES.HONEYCOMB_MR2)
    private void showProgress(final boolean show) {
        // On Honeycomb MR2 we have the ViewPropertyAnimator APIs, which allow
        // for very easy animations. If available, use these APIs to fade-in
        // the progress spinner.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.HONEYCOMB_MR2) {
            int shortAnimTime = getResources().getInteger(android.R.integer.config_shortAnimTime);

            createLiveForm.setVisibility(show ? View.GONE : View.VISIBLE);
            createLiveForm.animate().setDuration(shortAnimTime).alpha(
                    show ? 0 : 1).setListener(new AnimatorListenerAdapter() {
                @Override
                public void onAnimationEnd(Animator animation) {
                    createLiveForm.setVisibility(show ? View.GONE : View.VISIBLE);
                }
            });

            progressView.setVisibility(show ? View.VISIBLE : View.GONE);
            progressView.animate().setDuration(shortAnimTime).alpha(
                    show ? 1 : 0).setListener(new AnimatorListenerAdapter() {
                @Override
                public void onAnimationEnd(Animator animation) {
                    progressView.setVisibility(show ? View.VISIBLE : View.GONE);
                }
            });
        } else {
            // The ViewPropertyAnimator APIs are not available, so simply show
            // and hide the relevant UI components.
            progressView.setVisibility(show ? View.VISIBLE : View.GONE);
            createLiveForm.setVisibility(show ? View.GONE : View.VISIBLE);
        }
        fab.setVisibility(show ? View.GONE : View.VISIBLE);
    }

    public class CreateLiveTask extends AsyncTask<Void, Void, Boolean>{
        private VideoInfo videoInfo;
        private String username;
        private String tags;
        private String encKeys;
        private String plainTags;

        public CreateLiveTask(String username, VideoInfo videoInfo, String plainTags) {
            this.username = username;
            this.videoInfo = videoInfo;
            this.plainTags = plainTags.replaceAll(" +", " ").trim();
            StringBuilder tags_builder = new StringBuilder();
            StringBuilder encKeys_builder = new StringBuilder();
            for(String tag : videoInfo.getTagsAndEncKeys().keySet()){
                String encKey = videoInfo.getTagsAndEncKeys().get(tag);
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

        @Override
        protected void onCancelled() {
            mAuthTask = null;
            showProgress(false);
        }

        @Override
        protected void onPostExecute(Boolean success) {
            mAuthTask = null;
            showProgress(false);

            if(success){
                Toast.makeText(CreateLiveActivity.this, "创建直播完成。", Toast.LENGTH_LONG).show();
                setResult(VideoDetailActivity.RESULT_REFRESH);
                CreateLiveActivity.this.finish();
            } else {
                Toast.makeText(CreateLiveActivity.this, R.string.info_network_error, Toast.LENGTH_LONG).show();
            }
        }

        @Override
        protected Boolean doInBackground(Void... params) {
            HashMap<String, String> liveParam = new HashMap<>();
            /*String userID = request.getParameter("userID");
        String title = request.getParameter("title");
        String intro = request.getParameter("intro");
        String addr = request.getParameter("addr");
        String status = request.getParameter("status");
        String tags_b64 = new String(UrlBase64.decode(request.getParameter("tags")), "utf-8");
        String encKeys_b64 = new String(UrlBase64.decode(request.getParameter("encKeys")), "utf-8");*/
            liveParam.put("userID", username);
            liveParam.put("title", videoInfo.getCipherTitle());
            liveParam.put("intro", videoInfo.getCipherIntro());
            liveParam.put("addr", videoInfo.getCipherAddr());
            liveParam.put("status", "pending");
            liveParam.put("tags", tags);
            liveParam.put("encKeys", encKeys);
            HttpUtil util = new HttpUtil();
            try{
                util.setMethod(HttpUtil.HttpRequestMethod.POST)
                        .setUrl(SERVER_ADDRESS + "/publisher/publishvideo")
                        .setQuery(liveParam)
                        .sendHttpRequest();
                if(util.getResponseCode() != HTTP_OK){
                    return false;
                }else {
                    InputStream resultStream = util.getInputStream();
                    String result = HttpUtil.convertInputStreamToString(resultStream);
                    JsonObject resultObj = JsonUtil.getJsonObj(result);
                    int id = resultObj.get("id").getAsInt();
                    enc.dbHelper.addVideoLog(id, plainTags, videoInfo.getKey());
                    return true;
                }
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }
    }
}
