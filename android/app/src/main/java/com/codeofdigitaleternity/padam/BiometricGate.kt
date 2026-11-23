package com.codeofdigitaleternity.padam

import android.app.KeyguardManager
import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import androidx.appcompat.app.AppCompatActivity

/**
 * Системная биометрическая защита PADAM Studio на Android (API 29+, без сторонних библиотек — Фишка 16).
 */
class BiometricGate(private val ownerActivity: AppCompatActivity) {

    fun isDeviceSecured(): Boolean {
        val km = ownerActivity.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
        return km?.isDeviceSecure == true
    }

    fun requestOwnerUnlock(titleText: String, noteText: String, onFinished: (Boolean, String) -> Unit) {
        ownerActivity.runOnUiThread {
            if (!isDeviceSecured()) {
                onFinished(false, "device_lock_not_set")
                return@runOnUiThread
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val prompt = BiometricPrompt.Builder(ownerActivity)
                    .setTitle(titleText.ifBlank { "PADAM Studio" })
                    .setSubtitle(noteText.ifBlank { "Подтвердите личность владельца" })
                    .setAllowedAuthenticators(
                        BiometricManager.Authenticators.BIOMETRIC_WEAK or
                            BiometricManager.Authenticators.DEVICE_CREDENTIAL
                    )
                    .build()
                val signal = CancellationSignal()
                prompt.authenticate(
                    signal,
                    ownerActivity.mainExecutor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(res: BiometricPrompt.AuthenticationResult) {
                            onFinished(true, "verified")
                        }

                        override fun onAuthenticationError(errCode: Int, errMsg: CharSequence) {
                            onFinished(false, "err_$errCode:$errMsg")
                        }
                    },
                )
            } else {
                onFinished(false, "requires_android_11_plus")
            }
        }
    }
}
