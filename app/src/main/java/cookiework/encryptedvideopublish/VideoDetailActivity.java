package cookiework.encryptedvideopublish;

import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.AsyncTask;
import android.preference.PreferenceManager;
import android.support.annotation.IntegerRes;
import android.support.v4.net.ConnectivityManagerCompat;
import android.support.v4.widget.TextViewCompat;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import java.io.InputStream;
import java.util.HashMap;

import cookiework.encryptedvideopublish.encryption.VideoInfo;
import cookiework.encryptedvideopublish.util.HttpUtil;

import static cookiework.encryptedvideopublish.Constants.SERVER_ADDRESS;
import static java.net.HttpURLConnection.HTTP_OK;

public class VideoDetailActivity extends AppCompatActivity {
    private VideoInfo info;
    private String tags;
    public static final int RESULT_NULL = 0, RESULT_REFRESH = 1;
    private ProgressDialog progressDialog;
    private FinishLiveTask mAuthTask;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_video_detail);
        getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        setResult(RESULT_NULL);

        Intent intent = getIntent();
        info = intent.getParcelableExtra("videoInfo");
        tags = intent.getStringExtra("tags");

        TextView lblTitle = (TextView) findViewById(R.id.lblTitle_Detail);
        TextView lblTags = (TextView) findViewById(R.id.lblTags_Detail);
        TextView lblIntro = (TextView) findViewById(R.id.lblIntro_Detail);

        lblTitle.setText("标题：" + info.getCipherTitle());
        lblTags.setText("标签：" + tags);
        lblIntro.setText("简介：" + info.getCipherIntro());

        Button btnBeginLive = (Button) findViewById(R.id.btnBeginLive);
        btnBeginLive.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                boolean checkWifi = PreferenceManager.getDefaultSharedPreferences(VideoDetailActivity.this).getBoolean("onlyWifiAllowed", true);
                if(checkWifi && !isWifiAvailable()){
                    Toast.makeText(VideoDetailActivity.this, "Wi-Fi网络未连接，请连接Wi-Fi网络或在设置中取消Wi-Fi检测。", Toast.LENGTH_LONG).show();
                    return;
                }
                Intent intent = new Intent(VideoDetailActivity.this, StreamingActivity.class);
                intent.putExtra("push_url", info.getCipherAddr());
                startActivity(intent);
            }
        });
        Button btnEndLive = (Button) findViewById(R.id.btnEndLive);
        btnEndLive.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                removeLive();
            }
        });
        if(!info.getStatus().equals("live") && !info.getStatus().equals("pending")){
            btnBeginLive.setVisibility(View.INVISIBLE);
            btnEndLive.setVisibility(View.INVISIBLE);
        }

        progressDialog = new ProgressDialog(this);
        progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
        progressDialog.setMessage(getString(R.string.info_requirelist_progress));
        progressDialog.setIndeterminate(false);
        progressDialog.setCancelable(false);
    }

    private void showProgress(final boolean show) {
        if (show) {
            progressDialog.show();
        } else {
            progressDialog.hide();
        }
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

    public void removeLive(){
        if (mAuthTask != null) {
            return;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle("确认").setMessage("确实要结束本次直播吗？该操作不可撤销。");
        builder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                showProgress(true);
                mAuthTask = new FinishLiveTask(info.getId(), info.getCipherAddr());
                mAuthTask.execute((Void) null);
            }
        }).setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
            }
        });
        builder.show();
    }

    public boolean isWifiAvailable(){
        ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        NetworkInfo networkInfo = connectivityManager.getActiveNetworkInfo();
        if(networkInfo == null) return false;
        return (networkInfo.getType() == ConnectivityManager.TYPE_WIFI);
    }

    public class FinishLiveTask extends AsyncTask<Void, Void, Boolean> {
        private int id;
        private String input;

        public FinishLiveTask(int id, String input) {
            this.id = id;
            this.input = input;
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
                Toast.makeText(VideoDetailActivity.this, "直播已结束。", Toast.LENGTH_LONG).show();
                setResult(VideoDetailActivity.RESULT_REFRESH);
                VideoDetailActivity.this.finish();
            } else {
                Toast.makeText(VideoDetailActivity.this, R.string.info_network_error, Toast.LENGTH_LONG).show();
            }
        }

        @Override
        protected Boolean doInBackground(Void... params) {
            HashMap<String, String> endliveParam = new HashMap<>();
            endliveParam.put("input", input);
            endliveParam.put("id", Integer.toString(id));
            HttpUtil util = new HttpUtil();
            try{
                util.setMethod(HttpUtil.HttpRequestMethod.POST)
                        .setUrl(SERVER_ADDRESS + "/publisher/finishlive")
                        .setQuery(endliveParam)
                        .sendHttpRequest();
                if(util.getResponseCode() != HTTP_OK){
                    return false;
                }else {
                    InputStream resultStream = util.getInputStream();
                    String result = HttpUtil.convertInputStreamToString(resultStream);
                    if("success".equals(result)) {
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
}
