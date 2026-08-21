package com.v2ray.ang.ui.settings

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.v2ray.ang.R

class DeviceKitSettingsActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_devicekit_settings)
        if (savedInstanceState == null) {
            supportFragmentManager.beginTransaction()
                .replace(R.id.devicekit_settings_container, DeviceKitSettingsFragment())
                .commit()
        }
    }
}
