package dev.ure.desktop

import android.webkit.JavascriptInterface

/**
 * Ponte mínima exposta à interface como `UreNative`. Ela só abre diálogos nativos:
 * a página não recebe o token, não envia o token e não lê o estado do Keystore.
 * Os callbacks rodam na thread do WebView; quem os recebe deve voltar para a thread principal.
 */
class RemoteBridge(
  private val onConfigure: () -> Unit,
  private val onDisconnect: () -> Unit,
) {
  @JavascriptInterface
  fun configure() {
    onConfigure()
  }

  @JavascriptInterface
  fun disconnect() {
    onDisconnect()
  }
}
