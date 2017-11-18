package cookiework.encryptedvideopublish;

import android.app.Activity;
import android.os.Bundle;
import android.preference.Preference;
import android.preference.PreferenceFragment;
import android.support.v7.app.AppCompatActivity;

public class SettingsActivity extends AppCompatActivity {
    public static class SettingsFragment extends PreferenceFragment{
        @Override
        public void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            addPreferencesFromResource(R.xml.pref_settings);
        }

        @Override
        public void onStart() {
            super.onStart();
            Preference videoResoultionPreference = findPreference("videoResolution");
            String videoResolution = videoResoultionPreference.getSharedPreferences().getString("videoResolution", "1920x1080");
            videoResoultionPreference.setSummary(videoResolution);
            videoResoultionPreference.setOnPreferenceChangeListener(new Preference.OnPreferenceChangeListener() {
                @Override
                public boolean onPreferenceChange(Preference preference, Object newValue) {
                    preference.setSummary(newValue.toString());
                    return true;
                }
            });
            Preference timeoutPreference = findPreference("reconnectTimeout");
            String timeout = timeoutPreference.getSharedPreferences().getString("reconnectTimeout", "5");
            if(timeout.equals("0") || timeout.equals("")) timeoutPreference.setSummary("不重连");
            else timeoutPreference.setSummary(timeout);
            timeoutPreference.setOnPreferenceChangeListener(new Preference.OnPreferenceChangeListener() {
                @Override
                public boolean onPreferenceChange(Preference preference, Object newValue) {
                    if(newValue.equals("0") || newValue.equals("")) preference.setSummary("不重连");
                    else preference.setSummary(newValue.toString());
                    return true;
                }
            });
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);

        SettingsFragment settingsFragment = new SettingsFragment();
        getFragmentManager().beginTransaction().replace(R.id.settingsFrameLayout, settingsFragment).commit();
    }
}
