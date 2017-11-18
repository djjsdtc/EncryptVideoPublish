package cookiework.encryptedvideopublish;

import android.app.ProgressDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.ListViewCompat;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Toast;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;

import cookiework.encryptedvideopublish.encryption.PtWittEnc;
import cookiework.encryptedvideopublish.encryption.VideoInfo;
import cookiework.encryptedvideopublish.util.HttpUtil;
import cookiework.encryptedvideopublish.util.JsonUtil;

import static cookiework.encryptedvideopublish.Constants.SERVER_ADDRESS;
import static cookiework.encryptedvideopublish.Constants.SHARED_PREFERENCES;
import static java.net.HttpURLConnection.HTTP_OK;

/**
 * Created by Administrator on 2017/02/27.
 */

public class MyVideosActivity extends AppCompatActivity {
    private ProgressDialog progressDialog;
    private ListViewTask mAuthTask;
    private ListViewCompat listView;
    private PtWittEnc enc;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.layout_list);
        listView = (ListViewCompat) this.findViewById(R.id.main_list);
        progressDialog = new ProgressDialog(this);
        progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
        progressDialog.setMessage(getString(R.string.info_requirelist_progress));
        progressDialog.setIndeterminate(false);
        progressDialog.setCancelable(false);
        enc = new PtWittEnc(this);

        if (mAuthTask == null) {
            showProgress(true);
            mAuthTask = new ListViewTask();
            mAuthTask.execute((Void) null);
        }
    }

    private void showProgress(final boolean show) {
        if (show) {
            progressDialog.show();
        } else {
            progressDialog.hide();
        }
    }

    private class ListViewTask extends AsyncTask<Void, Void, Boolean>{
        private ArrayList<VideoInfo> list;

        @Override
        protected Boolean doInBackground(Void... params) {
            HashMap<String, String> liveListParam = new HashMap<>();
            SharedPreferences sp = getSharedPreferences(SHARED_PREFERENCES, MODE_PRIVATE);
            liveListParam.put("username", sp.getString("username", null));
            liveListParam.put("type", "all");
            HttpUtil util = new HttpUtil();
            try{
                util.setMethod(HttpUtil.HttpRequestMethod.POST)
                        .setUrl(SERVER_ADDRESS + "/publisher/mymessages")
                        .setQuery(liveListParam)
                        .sendHttpRequest();
                if(util.getResponseCode() != HTTP_OK){
                    return false;
                } else {
                    InputStream resultStream = util.getInputStream();
                    String result = HttpUtil.convertInputStreamToString(resultStream);
                    list = JsonUtil.convertJsonToArray(result, VideoInfo.class);
                    VideoInfo.decryptVideoInfo(enc, list);
                    return true;
                }
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }

        @Override
        protected void onPostExecute(Boolean success) {
            mAuthTask = null;
            showProgress(false);

            if (success) {
                listView.setAdapter(new ArrayAdapter<VideoInfo>(MyVideosActivity.this, android.R.layout.simple_expandable_list_item_1, list));
                listView.setOnItemClickListener(new AdapterView.OnItemClickListener(){
                    @Override
                    public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                        VideoInfo info = (VideoInfo) parent.getItemAtPosition(position);
                        String tags = enc.dbHelper.getVideoLog(info.getId()).get("tags");
                        Intent intent = new Intent(MyVideosActivity.this, VideoDetailActivity.class);
                        intent.putExtra("videoInfo", info);
                        intent.putExtra("tags", tags);
                        startActivityForResult(intent, 0);
                    }
                });
            } else {
                Toast.makeText(MyVideosActivity.this, R.string.info_network_error, Toast.LENGTH_LONG).show();
            }
        }

        @Override
        protected void onCancelled() {
            mAuthTask = null;
            showProgress(false);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if(resultCode == VideoDetailActivity.RESULT_REFRESH){
            setResult(VideoDetailActivity.RESULT_REFRESH);
            if (mAuthTask == null) {
                showProgress(true);
                mAuthTask = new ListViewTask();
                mAuthTask.execute((Void) null);
            }
        }
    }
}
