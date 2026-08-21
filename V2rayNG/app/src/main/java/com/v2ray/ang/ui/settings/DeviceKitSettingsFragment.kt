package com.v2ray.ang.ui.settings

import android.os.Bundle
import androidx.preference.PreferenceFragmentCompat
import com.v2ray.devicekit.SettingsUi

class DeviceKitSettingsFragment : PreferenceFragmentCompat() {
    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        SettingsUi.install(this)
    }
}
