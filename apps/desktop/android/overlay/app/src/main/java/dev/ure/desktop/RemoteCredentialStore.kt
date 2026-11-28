package dev.ure.desktop

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

private const val TAG = "URE"
private const val KEYSTORE = "AndroidKeyStore"
private const val KEY_ALIAS = "ure_remote_token_v1"
private const val PREFS = "ure_remote"
private const val PREF_URL = "base_url"
private const val PREF_IV = "iv"
private const val PREF_CT = "ct"
private const val TRANSFORMATION = "AES/GCM/NoPadding"
private const val GCM_TAG_BITS = 128

/**
 * Guarda o token do servidor remoto cifrado com AES-GCM. A chave fica no Android Keystore
 * (hardware quando disponível) e não pode ser exportada. Em disco há somente IV e texto cifrado.
 *
 * Regras:
 * - O token nunca é gravado em texto puro e nunca aparece em logs ou mensagens de erro.
 * - Se a chave foi invalidada ou a descriptografia falha, os dados são apagados e
 *   [LoadResult.NeedsToken] pede um novo token ao usuário.
 * - [clear] apaga os dados cifrados e a chave do Keystore (desconectar).
 */
class RemoteCredentialStore(context: Context) {
  private val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

  sealed class LoadResult {
    object Empty : LoadResult()
    data class Ready(val baseUrl: String, val token: String) : LoadResult()
    data class NeedsToken(val baseUrl: String?) : LoadResult()
  }

  /** Cifra e grava. Lança exceção se o Keystore não estiver disponível; nesse caso nada é gravado. */
  fun save(baseUrl: String, token: String) {
    val cipher = Cipher.getInstance(TRANSFORMATION)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey())
    val cipherText = cipher.doFinal(token.toByteArray(Charsets.UTF_8))
    val iv = cipher.iv
    val ok = prefs.edit()
      .putString(PREF_URL, baseUrl)
      .putString(PREF_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
      .putString(PREF_CT, Base64.encodeToString(cipherText, Base64.NO_WRAP))
      .commit()
    if (!ok) throw IllegalStateException("não foi possível gravar a configuração do servidor")
    Log.i(TAG, "credenciais do servidor remoto gravadas (cifradas)")
  }

  fun load(): LoadResult {
    val baseUrl = prefs.getString(PREF_URL, null)
    val iv = prefs.getString(PREF_IV, null)
    val ct = prefs.getString(PREF_CT, null)
    if (baseUrl == null || iv == null || ct == null) return LoadResult.Empty
    return try {
      val cipher = Cipher.getInstance(TRANSFORMATION)
      cipher.init(
        Cipher.DECRYPT_MODE,
        existingKey() ?: throw GeneralSecurityException("chave do Keystore ausente"),
        GCMParameterSpec(GCM_TAG_BITS, Base64.decode(iv, Base64.NO_WRAP)),
      )
      val token = String(cipher.doFinal(Base64.decode(ct, Base64.NO_WRAP)), Charsets.UTF_8)
      LoadResult.Ready(baseUrl, token)
    } catch (e: Exception) {
      // Inclui KeyPermanentlyInvalidatedException, AEADBadTagException e dados corrompidos.
      // Só o tipo do erro é registrado; o conteúdo cifrado e o token não entram no log.
      Log.w(TAG, "credenciais remotas inválidas (${e.javaClass.simpleName}); pedindo novo token")
      clear()
      LoadResult.NeedsToken(baseUrl)
    }
  }

  /** Apaga os dados cifrados e a chave. Seguro para chamadas repetidas. */
  fun clear() {
    prefs.edit().clear().commit()
    try {
      val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
      if (ks.containsAlias(KEY_ALIAS)) ks.deleteEntry(KEY_ALIAS)
    } catch (e: Exception) {
      Log.w(TAG, "não foi possível remover a chave do Keystore (${e.javaClass.simpleName})")
    }
  }

  private fun existingKey(): SecretKey? {
    val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
    return ks.getKey(KEY_ALIAS, null) as? SecretKey
  }

  private fun secretKey(): SecretKey {
    existingKey()?.let { return it }
    val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
    generator.init(
      KeyGenParameterSpec.Builder(
        KEY_ALIAS,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
      )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(256)
        .setRandomizedEncryptionRequired(true)
        .build(),
    )
    return generator.generateKey()
  }
}
