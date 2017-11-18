package cookiework.encryptedvideopublish;

import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.MediaStore;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;

import cookiework.encryptedvideopublish.encryption.VideoInfo;
import cookiework.encryptedvideopublish.util.UploadVideoTask;

import static cookiework.encryptedvideopublish.Constants.SHARED_PREFERENCES;

public class CreateVodActivity extends AppCompatActivity {
    private UploadVideoTask uploadVideoTask;
    private EditText txtVodTitle;
    private EditText txtVodTags;
    private TextView lblFilename;
    private Button btnPick;
    private EditText txtVodIntro;
    private FloatingActionButton fab;
    private SharedPreferences sp;

    public void setUploadVideoTask(UploadVideoTask uploadVideoTask) {
        this.uploadVideoTask = uploadVideoTask;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_create_vod);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        sp = getSharedPreferences(SHARED_PREFERENCES, MODE_PRIVATE);
        txtVodIntro = (EditText) findViewById(R.id.txtVodIntro);
        txtVodTags = (EditText) findViewById(R.id.txtVodTags);
        txtVodTitle = (EditText) findViewById(R.id.txtVodTitle);
        lblFilename = (TextView) findViewById(R.id.lblFilename);
        btnPick = (Button) findViewById(R.id.btnPick);
        fab = (FloatingActionButton) findViewById(R.id.fab);

        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
            processOkButton();
            }
        });
        btnPick.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                processPickButton();
            }
        });
        getSupportActionBar().setDisplayHomeAsUpEnabled(true);
    }

    protected void processPickButton(){
        Intent intent = new Intent(Intent.ACTION_PICK);
        intent.setType("video/mp4");
        intent.setData(MediaStore.Video.Media.EXTERNAL_CONTENT_URI);
        //intent.addCategory(Intent.CATEGORY_OPENABLE);
        startActivityForResult(intent, 1);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if(requestCode == 1 && resultCode == RESULT_OK){
            Uri uri = data.getData();
            String[] proj = {MediaStore.Files.FileColumns.DATA};
            Cursor fileCursor = getContentResolver().query(uri, proj, null, null, null);
            int columnIndex = fileCursor.getColumnIndex(proj[0]);
            fileCursor.moveToFirst();
            String filePath = fileCursor.getString(columnIndex);
            lblFilename.setText(filePath);
        }
        super.onActivityResult(requestCode, resultCode, data);
    }

    @Override
    public void onBackPressed() {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle("返回").setMessage("返回主界面将丢弃所有未保存的更改。确认？");
        builder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                CreateVodActivity.super.onBackPressed();
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
        if(uploadVideoTask != null){
            return;
        }
        txtVodTitle.setError(null);
        txtVodTags.setError(null);
        String title = txtVodTitle.getText().toString();
        if(title.equals("")){
            txtVodTitle.setError("请输入直播名称");
            txtVodTitle.requestFocus();
            return;
        }
        String tags = txtVodTags.getText().toString();
        if(tags.matches("^ *$")){
            txtVodTags.setError("请输入至少一个直播标签");
            txtVodTags.requestFocus();
            return;
        }
        String filename = lblFilename.getText().toString();
        File file = new File(filename);
        if(!new File(filename).exists()){
            Toast.makeText(this, "请选择要上传的视频文件。", Toast.LENGTH_LONG).show();
            return;
        }
        if(file.length() > Integer.MAX_VALUE){
            Toast.makeText(this, "上传文件超过2GB，请重新选择。", Toast.LENGTH_LONG).show();
            return;
        }
        String intro = txtVodIntro.getText().toString();
        String username = sp.getString("username", null);
        uploadVideoTask = new UploadVideoTask(file, username, title, intro, tags, this);
        uploadVideoTask.execute((Void) null);
    }

}
