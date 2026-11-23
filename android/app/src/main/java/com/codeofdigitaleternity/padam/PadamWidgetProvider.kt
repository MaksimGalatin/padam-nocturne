package com.codeofdigitaleternity.padam

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.widget.RemoteViews

/**
 * Виджет домашнего экрана PADAM (Фишка 20): счётчик памяти, статус Grade S и 3 быстрые кнопки.
 */
class PadamWidgetProvider : AppWidgetProvider() {

    override fun onUpdate(context: Context, appWidgetManager: AppWidgetManager, appWidgetIds: IntArray) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val active = prefs.getInt(KEY_ACTIVE, 0)
        val held = prefs.getInt(KEY_HELD, 0)
        for (wid in appWidgetIds) {
            appWidgetManager.updateAppWidget(wid, buildViews(context, active, held))
        }
    }

    companion object {
        private const val PREFS_NAME = "padam_widget_stats"
        private const val KEY_ACTIVE = "active_count"
        private const val KEY_HELD = "held_count"
        const val EXTRA_WIDGET_ACTION = "padam_widget_action"

        fun updateStats(context: Context, activeCount: Int, quarantinedCount: Int) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putInt(KEY_ACTIVE, activeCount)
                .putInt(KEY_HELD, quarantinedCount)
                .apply()
            val mgr = AppWidgetManager.getInstance(context)
            val ids = mgr.getAppWidgetIds(ComponentName(context, PadamWidgetProvider::class.java))
            if (ids.isNotEmpty()) {
                val views = buildViews(context, activeCount, quarantinedCount)
                for (wid in ids) {
                    mgr.updateAppWidget(wid, views)
                }
            }
        }

        private fun actionIntent(context: Context, actionKey: String, reqCode: Int): PendingIntent {
            val intent = Intent(context, MainActivity::class.java).apply {
                putExtra(EXTRA_WIDGET_ACTION, actionKey)
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
            }
            return PendingIntent.getActivity(
                context,
                reqCode,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
        }

        private fun buildViews(context: Context, active: Int, held: Int): RemoteViews {
            val rv = RemoteViews(context.packageName, R.layout.padam_widget)
            val isRu = java.util.Locale.getDefault().language.equals("ru", ignoreCase = true)
            rv.setTextViewText(R.id.widget_title, "PADAM · Grade S")
            rv.setTextViewText(R.id.widget_stats, if (isRu) "Память: $active · Карантин: $held" else "Memory: $active · Quarantine: $held")
            rv.setTextViewText(R.id.widget_btn_voice, if (isRu) "🎙 Айфа" else "🎙 AIfa")
            rv.setTextViewText(R.id.widget_btn_search, if (isRu) "🔍 Поиск" else "🔍 Search")
            rv.setTextViewText(R.id.widget_btn_chat, if (isRu) "💬 Чат" else "💬 Chat")
            rv.setOnClickPendingIntent(R.id.widget_btn_voice, actionIntent(context, "voice", 101))
            rv.setOnClickPendingIntent(R.id.widget_btn_search, actionIntent(context, "search", 102))
            rv.setOnClickPendingIntent(R.id.widget_btn_chat, actionIntent(context, "aifa", 103))
            return rv
        }
    }
}
