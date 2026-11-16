package com.codeofdigitaleternity.padam

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Хранилище сессии кабинета CODE Eternal на базе аппаратного Android Keystore (AES-256-GCM).
 * Сам ключ шифрования никогда не покидает AndroidKeyStore и не попадает в обычные файлы.
 */
class KeystoreVault(context: Context) {
    private val prefs = context.getSharedPreferences("padam_keystore_vault", Context.MODE_PRIVATE)
    private val alias = "padam_cabinet_aes_key_v1"

    private fun getOrCreateKey(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val existing = ks.getKey(alias, null) as? SecretKey
        if (existing != null) return existing

        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        gen.init(spec)
        return gen.generateKey()
    }

    fun saveSession(plainJson: String) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plainJson.toByteArray(Charsets.UTF_8))
        val packed = ByteArray(1 + iv.size + ciphertext.size)
        packed[0] = iv.size.toByte()
        System.arraycopy(iv, 0, packed, 1, iv.size)
        System.arraycopy(ciphertext, 0, packed, 1 + iv.size, ciphertext.size)
        val b64 = Base64.encodeToString(packed, Base64.NO_WRAP)
        prefs.edit().putString("session_blob", b64).apply()
    }

    fun loadSession(): String? {
        val b64 = prefs.getString("session_blob", null) ?: return null
        return try {
            val packed = Base64.decode(b64, Base64.DEFAULT)
            if (packed.size < 2) return null
            val ivLen = packed[0].toInt() and 0xFF
            if (packed.size <= 1 + ivLen) return null
            val iv = packed.copyOfRange(1, 1 + ivLen)
            val ciphertext = packed.copyOfRange(1 + ivLen, packed.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, iv))
            String(cipher.doFinal(ciphertext), Charsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }

    fun clearSession(): Boolean {
        val had = prefs.contains("session_blob")
        prefs.edit().remove("session_blob").apply()
        return had
    }
}
