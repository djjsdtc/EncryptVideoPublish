package cookiework.encryptedvideopublish;

import android.app.ProgressDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.design.widget.NavigationView;
import android.support.v4.view.GravityCompat;
import android.support.v4.widget.DrawerLayout;
import android.support.v7.app.ActionBarDrawerToggle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.ListViewCompat;
import android.support.v7.widget.Toolbar;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.TextView;
import android.widget.Toast;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;

import cookiework.encryptedvideopublish.encryption.PtWittEnc;
import cookiework.encryptedvideopublish.encryption.VideoInfo;
import cookiework.encryptedvideopublish.util.HttpUtil;
import cookiework.encryptedvideopublish.util.JsonUtil;

import static cookiework.encryptedvideopublish.Constants.*;
import static java.net.HttpURLConnection.HTTP_OK;

public class MainActivity extends AppCompatActivity
        implements NavigationView.OnNavigationItemSelectedListener {
    private LogoutThread logoutThread;
    private ProgressDialog progressDialog;
    private LiveListThread liveListThread;
    private ListViewCompat listView;
    private PtWittEnc enc;

    private void showProgress(final boolean show) {
        if(show){
            progressDialog.show();
        }else{
            progressDialog.hide();
        }
    }

    private String getUsername(){
        SharedPreferences sp = getSharedPreferences(SHARED_PREFERENCES, MODE_PRIVATE);
        return sp.getString("username", null);
    }

    private String getSessionId(){
        SharedPreferences sp = getSharedPreferences(SHARED_PREFERENCES, MODE_PRIVATE);
        return sp.getString("sessionID", null);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        SharedPreferences sp = getSharedPreferences(SHARED_PREFERENCES, MODE_PRIVATE);

        DrawerLayout drawer = (DrawerLayout) findViewById(R.id.drawer_layout);
        ActionBarDrawerToggle toggle = new ActionBarDrawerToggle(
                this, drawer, toolbar, R.string.navigation_drawer_open, R.string.navigation_drawer_close);
        drawer.setDrawerListener(toggle);
        toggle.syncState();

        NavigationView navigationView = (NavigationView) findViewById(R.id.nav_view);
        navigationView.setNavigationItemSelectedListener(this);
        TextView txtUsername = (TextView) navigationView.getHeaderView(0).findViewById(R.id.txtUsername);
        String username = sp.getString("username", getString(R.string.app_name));
        txtUsername.setText(username);

        progressDialog = new ProgressDialog(this);
        progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
        progressDialog.setMessage(getString(R.string.info_logout_progress));
        progressDialog.setIndeterminate(false);
        progressDialog.setCancelable(false);

        listView = (ListViewCompat) this.findViewById(R.id.main_list);
        enc = new PtWittEnc(this);
        enc.loadKeyFile(username);

        if (liveListThread == null) {
            liveListThread = new LiveListThread();
            liveListThread.execute((Void) null);
        }
    }

    @Override
    public void onBackPressed() {
        DrawerLayout drawer = (DrawerLayout) findViewById(R.id.drawer_layout);
        if (drawer.isDrawerOpen(GravityCompat.START)) {
            drawer.closeDrawer(GravityCompat.START);
        } else {
            super.onBackPressed();
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if(id == R.id.menu_settings){
            Intent intent = new Intent(this, SettingsActivity.class);
            startActivity(intent);
            return true;
        }
        else if (id == R.id.menu_quit) {
            finish();
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    private void clearSessionId(){
        SharedPreferences sp = getSharedPreferences(SHARED_PREFERENCES, MODE_PRIVATE);
        SharedPreferences.Editor editor = sp.edit();
        editor.remove("username");
        editor.remove("sessionID");
        editor.commit();
    }

    public class LogoutThread extends AsyncTask<Void, Void, Boolean>{
        @Override
        protected Boolean doInBackground(Void... params) {
            HashMap<String, String> logoutParam = new HashMap<>();
            logoutParam.put("username", getUsername());
            logoutParam.put("sessionID", getSessionId());
            HttpUtil util = new HttpUtil();
            try{
                util.setMethod(HttpUtil.HttpRequestMethod.POST)
                        .setUrl(SERVER_ADDRESS + "/publisher_logout")
                        .setQuery(logoutParam)
                        .sendHttpRequest();
                if(util.getResponseCode() != HTTP_OK){
                    return false;
                } else {
                    clearSessionId();
                    return true;
                }
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }

        @Override
        protected void onPostExecute(Boolean success) {
            logoutThread = null;
            showProgress(false);

            if (success) {
                Intent intent = new Intent(MainActivity.this, LoginActivity.class);
                startActivity(intent);
                finish();
            } else {
                Toast.makeText(MainActivity.this, R.string.info_network_error, Toast.LENGTH_LONG).show();
            }
        }
    }

    private void logout(){
        String username;
    }

    @SuppressWarnings("StatementWithEmptyBody")
    @Override
    public boolean onNavigationItemSelected(MenuItem item) {
        // Handle navigation view item clicks here.
        int id = item.getItemId();

        if (id == R.id.menu_live) {
            Intent intent = new Intent(this, CreateLiveActivity.class);
            startActivityForResult(intent, 0);
        } else if (id == R.id.menu_upload) {
            Intent intent = new Intent(this, CreateVodActivity.class);
            startActivity(intent);
        } else if(id == R.id.menu_videos){
            Intent intent = new Intent(this, MyVideosActivity.class);
            startActivityForResult(intent, 0);
        } else if (id == R.id.menu_approve) {
            Intent intent = new Intent(this, ApproveActivity.class);
            startActivity(intent);
        } else if (id == R.id.menu_follower) {
            Intent intent = new Intent(this, FollowerActivity.class);
            startActivity(intent);
        }/* else if (id == R.id.menu_changepswd) {

        }*/ else if (id == R.id.menu_logout) {
            if (logoutThread == null) {
                showProgress(true);
                logoutThread = new LogoutThread();
                logoutThread.execute((Void) null);
            }
        }

        DrawerLayout drawer = (DrawerLayout) findViewById(R.id.drawer_layout);
        drawer.closeDrawer(GravityCompat.START);
        return true;
    }

    public class LiveListThread extends AsyncTask<Void, Void, Boolean>{
        private ArrayList<VideoInfo> list;

        @Override
        protected void onPreExecute() {
            listView.setAdapter(new ArrayAdapter<String>(MainActivity.this, android.R.layout.simple_expandable_list_item_1, new String[]{"列表获取中，请稍候……"}));
            listView.setOnItemClickListener(null);
        }

        @Override
        protected Boolean doInBackground(Void... params) {
            HashMap<String, String> liveListParam = new HashMap<>();
            liveListParam.put("username", getUsername());
            liveListParam.put("type", "live_pending");
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
            liveListThread = null;

            if (success) {
                listView.setAdapter(new ArrayAdapter<VideoInfo>(MainActivity.this, android.R.layout.simple_expandable_list_item_1, list));
                listView.setOnItemClickListener(new AdapterView.OnItemClickListener(){
                    @Override
                    public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                        VideoInfo info = (VideoInfo) parent.getItemAtPosition(position);
                        String tags = enc.dbHelper.getVideoLog(info.getId()).get("tags");
                        Intent intent = new Intent(MainActivity.this, VideoDetailActivity.class);
                        intent.putExtra("videoInfo", info);
                        intent.putExtra("tags", tags);
                        startActivityForResult(intent, 0);
                    }
                });
            } else {
                listView.setAdapter(new ArrayAdapter<String>(MainActivity.this, android.R.layout.simple_expandable_list_item_1, new String[]{"网络错误，请稍后再试。单击此处可再试。"}));
                listView.setOnItemClickListener(new AdapterView.OnItemClickListener(){
                    @Override
                    public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                        if(liveListThread == null){
                            if (liveListThread == null) {
                                liveListThread = new LiveListThread();
                                liveListThread.execute((Void) null);
                            }
                        }
                    }
                });
            }
        }

        @Override
        protected void onCancelled() {
            liveListThread = null;
            listView.setAdapter(new ArrayAdapter<String>(MainActivity.this, android.R.layout.simple_expandable_list_item_1, new String[]{"网络错误，请稍后再试。单击此处可再试。"}));
            listView.setOnItemClickListener(new AdapterView.OnItemClickListener(){
                @Override
                public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                    if(liveListThread == null){
                        if (liveListThread == null) {
                            liveListThread = new LiveListThread();
                            liveListThread.execute((Void) null);
                        }
                    }
                }
            });
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if(resultCode == VideoDetailActivity.RESULT_REFRESH){
            if (liveListThread == null) {
                liveListThread = new LiveListThread();
                liveListThread.execute((Void) null);
            }
        }
    }
}
