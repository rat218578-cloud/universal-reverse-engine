package dev.ure.desktop

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AlertDialog
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import java.io.File
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.ServerSocket
import java.net.URL
import java.security.SecureRandom

private const val TAG = "URE"
private const val HEALTH_TIMEOUT_MS = 40_000L
private const val WEB_ASSET_DIR = "ure-web"

/**
 * Hospeda o backend Python do URE no próprio processo do aplicativo (Chaquopy).
 *
 * Fluxo: escolhe uma porta livre e gera um token novo a cada abertura; o módulo `ure_android`
 * sobe o servidor em 127.0.0.1; ao responder a /api/v1/health, a janela carrega a interface
 * na própria origem do backend. O token chega à página por um script de início de documento,
 * restrito a essa origem, igual ao desktop. Nada é gravado em disco.
 */
class MainActivity : TauriActivity() {
  private data class Session(val port: Int, val token: String)

  private val mainHandler = Handler(Looper.getMainLooper())

  @Volatile private var session: Session? = null
  @Volatile private var pendingWebView: WebView? = null
  private var starting = false // protegido por `this`

  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
  }

  override fun onWebViewCreate(webView: WebView) {
    super.onWebViewCreate(webView)
    pendingWebView = webView
    session?.let { ready ->
      mainHandler.post { attach(webView, ready) }
      return
    }
    val begin = synchronized(this) {
      if (starting) false else { starting = true; true }
    }
    if (begin) Thread({ startBackend() }, "ure-start").start()
  }

  override fun onDestroy() {
    if (isFinishing) stopBackend()
    pendingWebView = null
    super.onDestroy()
  }

  private fun startBackend() {
    try {
      val port = freePort()
      val token = newToken()
      val dataDir = File(filesDir, "ure-data").apply { mkdirs() }
      val webDir = prepareWebAssets()
      if (!Python.isStarted()) Python.start(AndroidPlatform(this))
      val module = Python.getInstance().getModule("ure_android")
      val actualPort = module.callAttr("start", dataDir.absolutePath, webDir.absolutePath, port, token).toInt()
      waitHealthy(actualPort)
      val ready = Session(actualPort, token)
      session = ready
      mainHandler.post { pendingWebView?.let { attach(it, ready) } }
    } catch (e: Exception) {
      Log.e(TAG, "falha ao iniciar o backend", e)
      synchronized(this) { starting = false }
      mainHandler.post { showError(e.message ?: e.toString()) }
    }
  }

  private fun attach(webView: WebView, ready: Session) {
    if (isDestroyed) return
    val origin = "http://127.0.0.1:${ready.port}"
    if (!WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT)) {
      showError("O WebView instalado é antigo demais para iniciar o URE com segurança. Atualize o Android System WebView pela Play Store.")
      return
    }
    // Token só para a origem do backend; o script roda antes de qualquer script da página.
    WebViewCompat.addDocumentStartJavaScript(
      webView,
      "window.URE_DESKTOP = { token: \"${ready.token}\" };",
      setOf(origin),
    )
    webView.webViewClient = BackendOnlyClient(origin)
    webView.loadUrl("$origin/")
  }

  private fun waitHealthy(port: Int) {
    val deadline = System.currentTimeMillis() + HEALTH_TIMEOUT_MS
    var last = "sem resposta"
    while (System.currentTimeMillis() < deadline) {
      try {
        val conn = URL("http://127.0.0.1:$port/api/v1/health").openConnection() as HttpURLConnection
        conn.connectTimeout = 2_000
        conn.readTimeout = 2_000
        try {
          if (conn.responseCode == 200) return
          last = "HTTP ${conn.responseCode}"
        } finally {
          conn.disconnect()
        }
      } catch (e: Exception) {
        last = e.message ?: e.toString()
      }
      Thread.sleep(300)
    }
    throw IllegalStateException("o backend não respondeu em 40 s ($last)")
  }

  private fun stopBackend() {
    try {
      if (Python.isStarted()) Python.getInstance().getModule("ure_android").callAttr("stop")
    } catch (e: Exception) {
      Log.w(TAG, "falha ao encerrar o backend", e)
    }
    session = null
    synchronized(this) { starting = false }
  }

  /** Copia a interface (assets/ure-web) para o armazenamento privado, uma vez por versão do app. */
  private fun prepareWebAssets(): File {
    val target = File(filesDir, WEB_ASSET_DIR)
    val marker = File(target, ".version")
    val version = "${BuildConfig.VERSION_NAME}-${BuildConfig.VERSION_CODE}"
    if (marker.isFile && marker.readText() == version) return target
    target.deleteRecursively()
    copyAssetTree(WEB_ASSET_DIR, target)
    marker.writeText(version)
    return target
  }

  private fun copyAssetTree(assetPath: String, dest: File) {
    val children = assets.list(assetPath) ?: emptyArray()
    if (children.isEmpty()) {
      dest.parentFile?.mkdirs()
      assets.open(assetPath).use { input -> dest.outputStream().use { input.copyTo(it) } }
    } else {
      dest.mkdirs()
      for (child in children) copyAssetTree("$assetPath/$child", File(dest, child))
    }
  }

  private fun showError(message: String) {
    if (isDestroyed) return
    AlertDialog.Builder(this)
      .setTitle("Universal Reverse Engine")
      .setMessage("Não foi possível iniciar o analisador.\n\n$message")
      .setCancelable(false)
      .setPositiveButton(android.R.string.ok) { _, _ -> finish() }
      .show()
  }

  private fun freePort(): Int =
    ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { it.localPort }

  private fun newToken(): String {
    val bytes = ByteArray(32)
    SecureRandom().nextBytes(bytes)
    return bytes.joinToString("") { "%02x".format(it) }
  }
}

/** Permite apenas a navegação dentro do backend local. Outros destinos não são abertos. */
private class BackendOnlyClient(private val origin: String) : WebViewClient() {
  override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
    val url = request.url.toString()
    return !(url == origin || url.startsWith("$origin/"))
  }
}
