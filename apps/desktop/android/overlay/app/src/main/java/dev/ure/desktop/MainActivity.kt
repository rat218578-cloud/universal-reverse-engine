package dev.ure.desktop

import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.util.Log
import android.view.View
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AlertDialog
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import com.chaquo.python.PyException
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
 * restrito a essa origem, igual ao desktop.
 *
 * Armazenamento: o backend local não grava segredos em disco. Apenas o token do servidor remoto,
 * quando o usuário escolhe conectar, é guardado cifrado com chave do Android Keystore
 * ([RemoteCredentialStore]). O token nunca passa pela interface web: ela só pede os diálogos
 * nativos pela ponte [RemoteBridge].
 */
class MainActivity : TauriActivity() {
  private data class Session(val port: Int, val token: String)

  private val mainHandler = Handler(Looper.getMainLooper())
  private val remoteStore by lazy { RemoteCredentialStore(this) }

  @Volatile private var session: Session? = null
  @Volatile private var pendingWebView: WebView? = null
  private var starting = false // protegido por `this`

  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
  }

  override fun onWebViewCreate(webView: WebView) {
    super.onWebViewCreate(webView)
    Log.i(TAG, "onWebViewCreate")
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
      Log.i(TAG, "iniciando backend")
      val port = freePort()
      val token = newToken()
      val dataDir = File(filesDir, "ure-data").apply { mkdirs() }
      val webDir = prepareWebAssets()
      Log.i(TAG, "interface em ${webDir.absolutePath}")
      if (!Python.isStarted()) Python.start(AndroidPlatform(this))
      Log.i(TAG, "python iniciado")
      val module = Python.getInstance().getModule("ure_android")
      val actualPort = module.callAttr("start", dataDir.absolutePath, webDir.absolutePath, port, token).toInt()
      Log.i(TAG, "servidor escutando em $actualPort")
      waitHealthy(actualPort)
      Log.i(TAG, "backend pronto em 127.0.0.1:$actualPort")
      val ready = Session(actualPort, token)
      session = ready
      mainHandler.post { pendingWebView?.let { attach(it, ready) } }
      restoreRemote()
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
    // Ponte só para abrir diálogos nativos; nenhum segredo sai ou entra por ela.
    webView.addJavascriptInterface(
      RemoteBridge(
        onConfigure = { mainHandler.post { showRemoteSetup() } },
        onDisconnect = { mainHandler.post { disconnectRemote() } },
      ),
      "UreNative",
    )
    Log.i(TAG, "carregando $origin/")
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

  /** Ao iniciar: reconfigura o servidor a partir do Keystore. Se a chave mudou, pede o token de novo. */
  private fun restoreRemote() {
    when (val result = remoteStore.load()) {
      is RemoteCredentialStore.LoadResult.Empty -> Unit
      is RemoteCredentialStore.LoadResult.Ready -> {
        try {
          Python.getInstance().getModule("ure_android").callAttr("set_remote", result.baseUrl, result.token)
          Log.i(TAG, "servidor remoto configurado a partir do armazenamento cifrado")
        } catch (e: PyException) {
          // A mensagem do backend não contém o token; ainda assim não é registrada.
          Log.w(TAG, "configuração guardada recusada pelo backend; pedindo novamente")
          remoteStore.clear()
          mainHandler.post {
            showRemoteSetup("A configuração salva foi recusada. Informe o endereço e o token novamente.", result.baseUrl)
          }
        }
      }
      is RemoteCredentialStore.LoadResult.NeedsToken -> mainHandler.post {
        showRemoteSetup(
          "A chave de segurança do aparelho mudou ou os dados guardados estão inválidos. Informe o token novamente.",
          result.baseUrl,
        )
      }
    }
  }

  /** Diálogo nativo para endereço e token. O token é apagado do campo depois de enviado. */
  private fun showRemoteSetup(message: String? = null, prefillUrl: String? = null) {
    if (isDestroyed) return
    val urlField = EditText(this).apply {
      hint = "https://servidor.exemplo"
      setText(prefillUrl ?: "")
      inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
      disableAutofill(this)
    }
    val tokenField = EditText(this).apply {
      hint = "token (mínimo 32 caracteres)"
      inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
      disableAutofill(this)
    }
    val box = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      val pad = (20 * resources.displayMetrics.density).toInt()
      setPadding(pad, 0, pad, 0)
      addView(urlField)
      addView(tokenField)
    }
    AlertDialog.Builder(this)
      .setTitle("Servidor remoto")
      .setMessage(
        message
          ?: "O token é guardado cifrado com a chave do Android Keystore. Ele não aparece em logs nem na tela.",
      )
      .setView(box)
      .setNegativeButton(android.R.string.cancel, null)
      .setPositiveButton("Salvar") { _, _ ->
        val url = urlField.text.toString().trim()
        val token = tokenField.text.toString()
        tokenField.text.clear()
        Thread({ saveRemote(url, token) }, "ure-remote-save").start()
      }
      .show()
  }

  private fun saveRemote(url: String, token: String) {
    try {
      Python.getInstance().getModule("ure_android").callAttr("set_remote", url, token)
    } catch (e: PyException) {
      // Mensagens do backend são controladas e não incluem o token.
      mainHandler.post {
        showRemoteSetup("Não foi possível usar essa configuração: ${e.message ?: "dados recusados"}", url)
      }
      return
    }
    try {
      remoteStore.save(url, token)
      mainHandler.post { toast("Servidor remoto configurado.") }
    } catch (e: Exception) {
      Log.w(TAG, "configuração válida, mas não foi possível guardar (${e.javaClass.simpleName})")
      mainHandler.post {
        toast("Configurado nesta sessão, mas não foi possível guardar com segurança. Será preciso informar o token de novo.")
      }
    }
  }

  private fun disconnectRemote() {
    Thread({
      remoteStore.clear()
      try {
        if (Python.isStarted()) Python.getInstance().getModule("ure_android").callAttr("clear_remote")
      } catch (e: Exception) {
        Log.w(TAG, "falha ao esquecer o servidor remoto nesta sessão (${e.javaClass.simpleName})")
      }
      mainHandler.post { toast("Servidor remoto desconectado. Credenciais apagadas.") }
    }, "ure-remote-clear").start()
  }

  /** importantForAutofill existe desde API 26; o minSdk é 24, então a chamada é protegida. */
  private fun disableAutofill(view: View) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) view.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
  }

  private fun toast(text: String) {
    if (!isDestroyed) Toast.makeText(this, text, Toast.LENGTH_LONG).show()
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
