package uk.ac.york.emrys

import android.content.Context
import android.util.Log

class SecureKeyStore(context: Context) {
    companion object {
        private const val TAG = "SecureKeyStore"
        private const val PREFS_NAME = "setup_secure"
    }

    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun clear() {
        try {
            prefs.edit().clear().apply()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to clear legacy secure prefs", e)
        }
    }
}