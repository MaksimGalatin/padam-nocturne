package com.codeofdigitaleternity.padam

import android.Manifest
import android.annotation.SuppressLint
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.webkit.JavascriptInterface
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.FrameLayout
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import org.json.JSONObject

/**
 * Главный экран PADAM Studio на Android (v0.8.0):
 * - Chaquopy локальный сервер PADAM Studio на 127.0.0.1;
 * - Фишка 16: биометрический замок владельца (BiometricGate);
 * - Фишка 17: системное «Поделиться в PADAM» (ACTION_SEND) через Agentic Shield;
 * - Фишка 18: LAN Sync с ПК по QR (AES-256-GCM);
 * - Фишка 19: голосовые команды и непрерывный Wake Word «Айфа…» с озвучкой TTS;
 * - Фишка 20: виджет домашнего экрана PADAM.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var webView: WebView
    private lateinit var biometricGate: BiometricGate
    private lateinit var voiceManager: VoiceAssistantManager
    private var fileUploadCallback: ValueCallback<Array<Uri>>? = null
    @Volatile
    private var studioReady = false
    private var pendingSharedText: String? = null
    private var pendingWidgetAction: String? = null

    private val openDocLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        val cb = fileUploadCallback
        fileUploadCallback = null
        if (cb != null) {
            cb.onReceiveValue(if (uri != null) arrayOf(uri) else null)
        }
    }

    private val micPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted: Boolean ->
        if (granted) {
            voiceManager.startOneShot()
        } else {
            Toast.makeText(this, "Разрешение на микрофон не выдано", Toast.LENGTH_SHORT).show()
        }
    }

    fun openExternalUrl(rawUrl: String): Boolean {
        val uri = runCatching { Uri.parse(rawUrl) }.getOrNull() ?: return false
        if (uri.scheme?.lowercase() != "https") return false
        return try {
            runOnUiThread {
                startActivity(Intent(Intent.ACTION_VIEW, uri))
            }
            true
        } catch (_: Exception) {
            false
        }
    }

    inner class PadamAndroidBridge {
        @JavascriptInterface
        fun authenticateBiometric(reason: String) {
            biometricGate.requestOwnerUnlock("PADAM Studio", reason) { ok, msg ->
                val safeMsg = JSONObject.quote(msg)
                runOnUiThread {
                    webView.evaluateJavascript("window.__padamBiometricResult && window.__padamBiometricResult($ok, $safeMsg);", null)
                }
            }
        }

        @JavascriptInterface
        fun startVoice() {
            runOnUiThread {
                if (hasMicPermission()) {
                    voiceManager.startOneShot()
                } else {
                    micPermissionLauncher.launch(Manifest.permission.RECORD_AUDIO)
                }
            }
        }

        @JavascriptInterface
        fun setWakeWordEnabled(enabled: Boolean) {
            runOnUiThread {
                if (enabled && !hasMicPermission()) {
                    micPermissionLauncher.launch(Manifest.permission.RECORD_AUDIO)
                    return@runOnUiThread
                }
                voiceManager.setWakeWordEnabled(enabled)
            }
        }

        @JavascriptInterface
        fun isWakeWordEnabled(): Boolean = voiceManager.isWakeWordEnabled()

        @JavascriptInterface
        fun speakText(text: String) {
            voiceManager.speak(text)
        }

        @JavascriptInterface
        fun syncLanFromUri(uriOrJson: String): String {
            return try {
                val rt = Python.getInstance().getModule("android_runtime")
                val res = rt.callAttr("sync_lan_with_pc", uriOrJson).toString()
                refreshWidgetFromPython()
                res
            } catch (e: Exception) {
                """{"ok":false,"error":${JSONObject.quote(e.message ?: "sync_error")}}"""
            }
        }

        @JavascriptInterface
        fun updateWidgetStats(activeCount: Int, quarantinedCount: Int) {
            PadamWidgetProvider.updateStats(applicationContext, activeCount, quarantinedCount)
        }
    }

    private fun hasMicPermission(): Boolean {
        return ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED
    }

    private fun refreshWidgetFromPython() {
        Thread {
            runCatching {
                val rt = Python.getInstance().getModule("android_runtime")
                val raw = rt.callAttr("get_widget_stats").toString()
                val obj = JSONObject(raw)
                PadamWidgetProvider.updateStats(
                    applicationContext,
                    obj.optInt("active", 0),
                    obj.optInt("quarantined", 0),
                )
            }
        }.start()
    }

    private fun handleIncomingIntent(intent: Intent?) {
        if (intent == null) return
        if (intent.action == Intent.ACTION_SEND && intent.type == "text/plain") {
            val shared = intent.getStringExtra(Intent.EXTRA_TEXT)?.trim()
            if (!shared.isNullOrEmpty()) {
                if (studioReady) {
                    ingestSharedAsync(shared)
                } else {
                    pendingSharedText = shared
                }
            }
        }
        val widgetAct = intent.getStringExtra(PadamWidgetProvider.EXTRA_WIDGET_ACTION)
        if (!widgetAct.isNullOrBlank()) {
            if (studioReady) {
                dispatchWidgetAction(widgetAct)
            } else {
                pendingWidgetAction = widgetAct
            }
        }
    }

    private fun ingestSharedAsync(text: String) {
        Thread {
            runCatching {
                val rt = Python.getInstance().getModule("android_runtime")
                val raw = rt.callAttr("ingest_shared_text", text, "android_share").toString()
                val obj = JSONObject(raw)
                val outcome = obj.optString("outcome", "saved")
                refreshWidgetFromPython()
                runOnUiThread {
                    val msg = if (outcome == "quarantined") {
                        "PADAM: текст отправлен на проверку (карантин)"
                    } else {
                        "PADAM: сохранено в память ($outcome)"
                    }
                    Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
                }
            }
        }.start()
    }

    private fun dispatchWidgetAction(actionKey: String) {
        runOnUiThread {
            when (actionKey) {
                "voice" -> {
                    if (hasMicPermission()) voiceManager.startOneShot()
                    else micPermissionLauncher.launch(Manifest.permission.RECORD_AUDIO)
                }
                "search" -> webView.evaluateJavascript("typeof openCmdK==='function' && openCmdK();", null)
                "aifa" -> webView.evaluateJavascript("typeof switchTab==='function' && switchTab('aifa');", null)
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIncomingIntent(intent)
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        biometricGate = BiometricGate(this)
        voiceManager = VoiceAssistantManager(applicationContext) { transcript, fromWake ->
            Thread {
                runCatching {
                    val rt = Python.getInstance().getModule("android_runtime")
                    val raw = rt.callAttr("handle_voice_command", transcript, fromWake).toString()
                    val obj = JSONObject(raw)
                    if (!obj.optBoolean("ignored", false)) {
                        val reply = obj.optString("spoken_reply", "")
                        if (reply.isNotBlank()) {
                            voiceManager.speak(reply)
                        }
                        refreshWidgetFromPython()
                        val safeText = JSONObject.quote(transcript)
                        runOnUiThread {
                            webView.evaluateJavascript(
                                "window.__padamOnAndroidVoiceResult && window.__padamOnAndroidVoiceResult($safeText, $fromWake);",
                                null,
                            )
                        }
                    }
                }
            }.start()
        }

        webView = WebView(this)
        val root = FrameLayout(this).apply { setBackgroundColor(0xFF080B12.toInt()) }
        root.addView(webView, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT))
        setContentView(root)

        ViewCompat.setOnApplyWindowInsetsListener(root) { v, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout() or WindowInsetsCompat.Type.ime())
            v.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }

        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            allowFileAccess = false
            allowContentAccess = true
            mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
        }
        webView.addJavascriptInterface(PadamAndroidBridge(), "PadamAndroid")

        webView.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
                val uri = request?.url ?: return false
                val host = uri.host?.lowercase() ?: ""
                if (host == "127.0.0.1" || host == "localhost") {
                    return false
                }
                return openExternalUrl(uri.toString())
            }
        }

        webView.webChromeClient = object : WebChromeClient() {
            override fun onShowFileChooser(
                view: WebView?,
                filePathCallback: ValueCallback<Array<Uri>>?,
                fileChooserParams: FileChooserParams?,
            ): Boolean {
                fileUploadCallback?.onReceiveValue(null)
                fileUploadCallback = filePathCallback
                openDocLauncher.launch(arrayOf("*/*"))
                return true
            }
        }

        handleIncomingIntent(intent)

        Thread {
            if (!Python.isStarted()) {
                Python.start(AndroidPlatform(applicationContext))
            }
            val py = Python.getInstance()
            val runtime = py.getModule("android_runtime")
            val vault = KeystoreVault(applicationContext)
            val studioUrl = runtime.callAttr(
                "start_studio",
                filesDir.absolutePath,
                vault,
                this,
            ).toString()

            studioReady = true
            refreshWidgetFromPython()
            pendingSharedText?.let { txt ->
                pendingSharedText = null
                ingestSharedAsync(txt)
            }
            runOnUiThread {
                webView.loadUrl(studioUrl)
                pendingWidgetAction?.let { act ->
                    pendingWidgetAction = null
                    dispatchWidgetAction(act)
                }
            }
        }.start()
    }

    override fun onDestroy() {
        voiceManager.release()
        super.onDestroy()
    }
}
