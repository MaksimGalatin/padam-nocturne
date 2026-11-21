package com.codeofdigitaleternity.padam

import android.annotation.SuppressLint
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.FrameLayout
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform

/**
 * Главный экран PADAM Studio на Android:
 * - в фоне запускает настоящий Python-пакет padam через Chaquopy на 127.0.0.1;
 * - отображает полный интерфейс Studio в изолированном WebView;
 * - переезд из архива работает через системный OpenDocument без лишних разрешений;
 * - внешние ссылки (оплата тарифов) открываются исключительно во внешнем браузере.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var webView: WebView
    private var fileUploadCallback: ValueCallback<Array<Uri>>? = null

    private val openDocLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        val cb = fileUploadCallback
        fileUploadCallback = null
        if (cb != null) {
            cb.onReceiveValue(if (uri != null) arrayOf(uri) else null)
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

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        webView = WebView(this)
        // WebView сам отступы содержимого не соблюдает — отступ даёт рамка вокруг него.
        val root = FrameLayout(this).apply { setBackgroundColor(0xFF080B12.toInt()) }   // цвет фона Студии под шторкой
        root.addView(webView, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT))
        setContentView(root)
        // Android 15 (targetSdk 35+) рисует окно от края до края: без отступов Студия заходила под системные
        // часы и значки сети (отчёт Сестры по APK 0.7.0, 20.11.2026). Отступаем на высоту системных панелей и выреза.
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

            runOnUiThread {
                webView.loadUrl(studioUrl)
            }
        }.start()
    }
}
