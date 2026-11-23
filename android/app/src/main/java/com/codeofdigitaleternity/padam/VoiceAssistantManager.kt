package com.codeofdigitaleternity.padam

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.speech.RecognitionListener
import android.speech.RecognizerIntent
import android.speech.SpeechRecognizer
import android.speech.tts.TextToSpeech
import java.util.Locale

/**
 * Голосовой контур PADAM Android (Фишка 19 + непрерывное прослушивание кодового слова «Айфа…»).
 * Поддерживает разовую диктовку и фоновой режим пробуждения (как «Окей Гугл»), пока переключатель включён.
 */
class VoiceAssistantManager(
    private val appContext: Context,
    private val onTranscript: (text: String, fromWakeWord: Boolean) -> Unit,
) {
    private val mainHandler = Handler(Looper.getMainLooper())
    private var recognizer: SpeechRecognizer? = null
    private var tts: TextToSpeech? = null
    private var ttsReady = false
    @Volatile
    private var wakeModeEnabled = false
    @Volatile
    private var activeListenWake = false

    init {
        tts = TextToSpeech(appContext) { status ->
            ttsReady = (status == TextToSpeech.SUCCESS)
            if (ttsReady) {
                val res = tts?.setLanguage(Locale("ru", "RU"))
                if (res == TextToSpeech.LANG_MISSING_DATA || res == TextToSpeech.LANG_NOT_SUPPORTED) {
                    tts?.setLanguage(Locale.US)
                }
            }
        }
    }

    fun isWakeWordEnabled(): Boolean = wakeModeEnabled

    fun speak(reply: String) {
        val clean = reply.trim()
        if (clean.isEmpty() || !ttsReady) return
        mainHandler.post {
            tts?.speak(clean.take(260), TextToSpeech.QUEUE_FLUSH, null, "padam_voice_reply")
        }
    }

    fun startOneShot() {
        mainHandler.post {
            activeListenWake = false
            launchRecognition(continuousWake = false)
        }
    }

    fun setWakeWordEnabled(enabled: Boolean) {
        wakeModeEnabled = enabled
        mainHandler.post {
            if (!enabled) {
                stopRecognition()
            } else {
                activeListenWake = true
                launchRecognition(continuousWake = true)
            }
        }
    }

    private fun stopRecognition() {
        try {
            recognizer?.stopListening()
            recognizer?.cancel()
            recognizer?.destroy()
        } catch (_: Exception) {
        }
        recognizer = null
    }

    private fun launchRecognition(continuousWake: Boolean) {
        if (!SpeechRecognizer.isRecognitionAvailable(appContext)) return
        stopRecognition()
        val sr = SpeechRecognizer.createSpeechRecognizer(appContext)
        recognizer = sr
        sr.setRecognitionListener(object : RecognitionListener {
            override fun onReadyForSpeech(params: Bundle?) {}
            override fun onBeginningOfSpeech() {}
            override fun onRmsChanged(rmsdB: Float) {}
            override fun onBufferReceived(buffer: ByteArray?) {}
            override fun onEndOfSpeech() {}
            override fun onPartialResults(partialResults: Bundle?) {}
            override fun onEvent(eventType: Int, params: Bundle?) {}

            override fun onResults(results: Bundle?) {
                val list = results?.getStringArrayList(SpeechRecognizer.RESULTS_RECOGNITION)
                val phrase = list?.firstOrNull()?.trim().orEmpty()
                if (phrase.isNotEmpty()) {
                    onTranscript(phrase, continuousWake)
                }
                if (wakeModeEnabled) {
                    scheduleWakeRestart()
                }
            }

            override fun onError(error: Int) {
                if (wakeModeEnabled) {
                    scheduleWakeRestart()
                }
            }
        })

        val intent = Intent(RecognizerIntent.ACTION_RECOGNIZE_SPEECH).apply {
            putExtra(RecognizerIntent.EXTRA_LANGUAGE_MODEL, RecognizerIntent.LANGUAGE_MODEL_FREE_FORM)
            putExtra(RecognizerIntent.EXTRA_LANGUAGE, "ru-RU")
            putExtra(RecognizerIntent.EXTRA_PREFER_OFFLINE, true)
            putExtra(RecognizerIntent.EXTRA_MAX_RESULTS, 1)
        }
        try {
            sr.startListening(intent)
        } catch (_: Exception) {
            if (wakeModeEnabled) scheduleWakeRestart()
        }
    }

    private fun scheduleWakeRestart() {
        mainHandler.removeCallbacksAndMessages("wake_restart")
        mainHandler.postDelayed({
            if (wakeModeEnabled) {
                activeListenWake = true
                launchRecognition(continuousWake = true)
            }
        }, 700L)
    }

    fun release() {
        wakeModeEnabled = false
        mainHandler.post {
            stopRecognition()
            try {
                tts?.stop()
                tts?.shutdown()
            } catch (_: Exception) {
            }
            tts = null
        }
    }
}
