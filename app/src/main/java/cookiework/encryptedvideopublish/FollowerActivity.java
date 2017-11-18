package cookiework.encryptedvideopublish;

import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.ListViewCompat;
import android.util.SparseBooleanArray;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.CheckedTextView;
import android.widget.Toast;

import org.spongycastle.util.encoders.UrlBase64;

import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

import cookiework.encryptedvideopublish.encryption.PtWittEnc;
import cookiework.encryptedvideopublish.encryption.SubscriptionInfo;
import cookiework.encryptedvideopublish.encryption.SubscriptionProcessor;
import cookiework.encryptedvideopublish.util.DBHelper;
import cookiework.encryptedvideopublish.util.HttpUtil;
import cookiework.encryptedvideopublish.util.JsonUtil;

import static cookiework.encryptedvideopublish.Constants.SERVER_ADDRESS;
import static cookiework.encryptedvideopublish.Constants.SHARED_PREFERENCES;
import static java.net.HttpURLConnection.HTTP_OK;

public class FollowerActivity extends AppCompatActivity {
    private ProgressDialog progressDialog;
    private ApproveListTask mAuthTask;
    private RequestKeyReplaceTask requestKeyReplaceTask;
    private ListViewCompat listView;
    private ArrayList<Follower> infos;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.layout_list);
        listView = (ListViewCompat) this.findViewById(R.id.main_list);
        progressDialog = new ProgressDialog(this);
        progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
        progressDialog.setMessage(getString(R.string.info_requirelist_progress));
        progressDialog.setIndeterminate(false);
        progressDialog.setCancelable(false);

        if (mAuthTask == null) {
            showProgress(true);
            mAuthTask = new ApproveListTask(this);
            mAuthTask.execute((Void) null);
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.follower, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if(id == R.id.menu_choose){
            StringBuffer sb_replace = new StringBuffer();
            StringBuffer sb_remove = new StringBuffer();
            for(int i = 0; i < infos.size(); i++){
                Follower follower = (Follower)listView.getItemAtPosition(i);
                if(listView.isItemChecked(i)){
                    sb_replace.append(follower.tagNum + " ");
                } else {
                    sb_remove.append(follower.tagNum + " ");
                }
            }
            if (requestKeyReplaceTask == null) {
                showProgress(true);
                requestKeyReplaceTask = new RequestKeyReplaceTask(sb_replace.toString(), sb_remove.toString(), this);
                requestKeyReplaceTask.execute((Void) null);
            }
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    public class ApproveListTask extends AsyncTask<Void, Void, Boolean>{
        private HttpUtil util = new HttpUtil();

        private Context context;

        public ApproveListTask(Context context) {
            this.context = context;
        }

        @Override
        protected void onPostExecute(Boolean success) {
            mAuthTask = null;
            showProgress(false);

            if (success) {
                if(infos.size() == 0){
                    listView.setAdapter(new ArrayAdapter<String>(context, android.R.layout.simple_expandable_list_item_1, new String[]{"没有待确认的请求"}));
                } else {
                    listView.setChoiceMode(ListViewCompat.CHOICE_MODE_MULTIPLE);
                    listView.setAdapter(new ArrayAdapter<Follower>(context, android.R.layout.select_dialog_multichoice, infos));
                }
            } else {
                Toast.makeText(context, R.string.info_network_error, Toast.LENGTH_LONG).show();
            }
        }

        @Override
        protected void onCancelled() {
            mAuthTask = null;
            showProgress(false);
        }

        @Override
        protected Boolean doInBackground(Void... unused) {
            try{
                SharedPreferences sp = getSharedPreferences(SHARED_PREFERENCES, MODE_PRIVATE);
                String username = sp.getString("username", null);
                HashMap<String, String> params = new HashMap<>();
                params.put("username", username);
                util.setMethod(HttpUtil.HttpRequestMethod.POST)
                        .setUrl(SERVER_ADDRESS + "/publisher/myfollowers")
                        .setQuery(params)
                        .sendHttpRequest();
                if (util.getResponseCode() != HTTP_OK) {
                    System.out.println(util.getResponseMessage());
                    return false;
                } else {
                    InputStream resultStream = util.getInputStream();
                    String result = HttpUtil.convertInputStreamToString(resultStream);
                    infos = JsonUtil.convertJsonToArray(result, Follower.class);
                    return true;
                }
            }
            catch (Exception e){
                e.printStackTrace();
                return false;
            }
        }
    }

    public class RequestKeyReplaceTask extends AsyncTask<Void, Void, Boolean>{
        private HttpUtil util = new HttpUtil();
        private String replaceids = null;
        private String removeids = null;
        private Context context;
        private PtWittEnc enc;

        public RequestKeyReplaceTask(String replaceids, String removeids, Context context) {
            this.context = context;

            try {
                if(replaceids != null && !replaceids.trim().equals(""))
                    this.replaceids = new String(UrlBase64.encode(replaceids.getBytes("utf-8")), "utf-8");
                Toast.makeText(context, replaceids, Toast.LENGTH_SHORT).show();
                Toast.makeText(context, this.replaceids, Toast.LENGTH_SHORT).show();
                if(removeids != null && !removeids.trim().equals(""))
                    this.removeids = new String(UrlBase64.encode(removeids.getBytes("utf-8")), "utf-8");
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            this.enc = new PtWittEnc(context);
        }

        @Override
        protected void onPostExecute(Boolean success) {
            requestKeyReplaceTask = null;
            showProgress(false);

            if (success) {
                SharedPreferences sp = getSharedPreferences(SHARED_PREFERENCES, MODE_PRIVATE);
                String username = sp.getString("username", null);
                Toast.makeText(context, "续约成功。", Toast.LENGTH_LONG).show();
                enc.replaceKeyLocal(username);
                if (mAuthTask == null) {
                    showProgress(true);
                    mAuthTask = new ApproveListTask(FollowerActivity.this);
                    mAuthTask.execute((Void) null);
                }
            } else {
                Toast.makeText(context, R.string.info_network_error, Toast.LENGTH_LONG).show();
            }
        }

        @Override
        protected void onCancelled() {
            requestKeyReplaceTask = null;
            showProgress(false);
        }

        @Override
        protected Boolean doInBackground(Void... unused) {
            try{

                HashMap<String, String> params = new HashMap<>();
                if(replaceids != null) params.put("replaceid", replaceids);
                if(removeids != null) params.put("removeid", removeids);
                params.put("c", enc.replaceKey());
                util.setMethod(HttpUtil.HttpRequestMethod.POST)
                        .setUrl(SERVER_ADDRESS + "/publisher/requestkeyreplace")
                        .setQuery(params)
                        .sendHttpRequest();
                if (util.getResponseCode() != HTTP_OK) {
                    System.out.println(util.getResponseMessage());
                    return false;
                } else {
                    return true;
                }
            }
            catch (Exception e){
                e.printStackTrace();
                return false;
            }
        }
    }

    private void showProgress(final boolean show) {
        if (show) {
            progressDialog.show();
        } else {
            progressDialog.hide();
        }
    }

    protected class Follower{
        public String name;
        public String tagNum;
        @Override
        public String toString(){
            return name + "(" + tagNum + ")";
        }
    }
}
