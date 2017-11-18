package cookiework.encryptedvideopublish;

import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.support.v7.widget.ListViewCompat;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Toast;

import com.google.gson.JsonObject;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;

import cookiework.encryptedvideopublish.encryption.SubscriptionInfo;
import cookiework.encryptedvideopublish.encryption.SubscriptionProcessor;
import cookiework.encryptedvideopublish.util.DBHelper;
import cookiework.encryptedvideopublish.util.HttpUtil;
import cookiework.encryptedvideopublish.util.JsonUtil;

import static cookiework.encryptedvideopublish.Constants.SERVER_ADDRESS;
import static cookiework.encryptedvideopublish.Constants.SHARED_PREFERENCES;
import static java.net.HttpURLConnection.HTTP_OK;

public class ApproveActivity extends AppCompatActivity {
    private ProgressDialog progressDialog;
    private ApproveListTask mAuthTask;
    private ListViewCompat listView;

    private static final String[] options = {"接受关注请求", "拒绝关注请求", "取消"};

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

    public class ApproveListTask extends AsyncTask<Void, Void, Boolean>{
        private HttpUtil util = new HttpUtil();
        private ArrayList<SubscriptionInfo> infos;
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
                    listView.setAdapter(new ArrayAdapter<SubscriptionInfo>(context, android.R.layout.simple_expandable_list_item_1, infos));
                    listView.setOnItemClickListener(new ApproveListItemClickListener(context));
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
                        .setUrl(SERVER_ADDRESS + "/publisher/myrequest")
                        .setQuery(params)
                        .sendHttpRequest();
                if (util.getResponseCode() != HTTP_OK) {
                    System.out.println(util.getResponseMessage());
                    return false;
                } else {
                    InputStream resultStream = util.getInputStream();
                    String result = HttpUtil.convertInputStreamToString(resultStream);
                    infos = JsonUtil.convertJsonToArray(result, SubscriptionInfo.class);
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

    public class ApproveListItemClickListener implements AdapterView.OnItemClickListener{
        private SubscriptionProcessor processor;
        private Context context;
        private DBHelper dbHelper;
        private AcceptTask acceptTask;
        private RefuseTask refuseTask;

        public ApproveListItemClickListener(Context context) {
            this.context = context;
            this.processor = new SubscriptionProcessor(context);
            this.dbHelper = new DBHelper(context);
        }

        @Override
        public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
            SubscriptionInfo info = (SubscriptionInfo) parent.getItemAtPosition(position);
            AlertDialog.Builder builder = new AlertDialog.Builder(context);
            builder.setTitle(info.getUserID());
            builder.setItems(options, new ChooseOperationListener(info));
            builder.show();
        }

        public class ChooseOperationListener implements DialogInterface.OnClickListener {
            private SubscriptionInfo info;

            public ChooseOperationListener(SubscriptionInfo info) {
                this.info = info;
            }

            @Override
            public void onClick(DialogInterface dialog, int which) {
                switch(which){
                    case 0:
                        String mPrime = processor.getResponseString(dbHelper.getPrivateKey(info.getDestUserID()), info.getM());
                        if(acceptTask != null){
                            return;
                        }
                        showProgress(true);
                        acceptTask = new AcceptTask();
                        acceptTask.execute(Integer.toString(info.getId()), mPrime);
                        break;
                    case 1:
                        if(refuseTask != null){
                            return;
                        }
                        showProgress(true);
                        refuseTask = new RefuseTask();
                        refuseTask.execute(Integer.toString(info.getId()));
                        break;
                    default:
                        //取消
                        break;
                }
            }
        }

        public class AcceptTask extends AsyncTask<String, Void, Boolean>{
            private HttpUtil util = new HttpUtil();

            @Override
            protected void onPostExecute(Boolean success) {
                acceptTask = null;
                showProgress(false);

                if (success) {
                    Toast.makeText(ApproveActivity.this, "已经确认请求", Toast.LENGTH_LONG).show();
                    if (mAuthTask == null) {
                        showProgress(true);
                        mAuthTask = new ApproveListTask(ApproveActivity.this);
                        mAuthTask.execute((Void) null);
                    }
                } else {
                    Toast.makeText(ApproveActivity.this, R.string.info_network_error, Toast.LENGTH_LONG).show();
                }
            }

            @Override
            protected void onCancelled() {
                acceptTask = null;
                showProgress(false);
            }

            @Override
            protected Boolean doInBackground(String... param) {
                try{
                    HashMap<String, String> params = new HashMap<>();
                    params.put("id", param[0]);
                    params.put("MPrime", param[1]);
                    util.setMethod(HttpUtil.HttpRequestMethod.POST)
                            .setUrl(SERVER_ADDRESS + "/publisher/updatesubscribe")
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

        public class RefuseTask extends AsyncTask<String, Void, Boolean>{
            private HttpUtil util = new HttpUtil();

            @Override
            protected void onPostExecute(Boolean success) {
                refuseTask = null;
                showProgress(false);

                if (success) {
                    Toast.makeText(ApproveActivity.this, "已经拒绝请求", Toast.LENGTH_LONG).show();
                    if (mAuthTask == null) {
                        showProgress(true);
                        mAuthTask = new ApproveListTask(ApproveActivity.this);
                        mAuthTask.execute((Void) null);
                    }
                } else {
                    Toast.makeText(ApproveActivity.this, R.string.info_network_error, Toast.LENGTH_LONG).show();
                }
            }

            @Override
            protected void onCancelled() {
                refuseTask = null;
                showProgress(false);
            }

            @Override
            protected Boolean doInBackground(String... param) {
                try{
                    HashMap<String, String> params = new HashMap<>();
                    params.put("removeid", param[0]);
                    util.setMethod(HttpUtil.HttpRequestMethod.POST)
                            .setUrl(SERVER_ADDRESS + "/publisher/removesub")
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
    }
}
