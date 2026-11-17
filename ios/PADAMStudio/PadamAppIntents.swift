import AppIntents
import Foundation

/// Команда Apple Shortcuts / Siri: сохранить заметку в PADAM Studio.
@available(iOS 16.0, macOS 13.0, *)
struct PadamRememberIntent: AppIntent {
    static var title: LocalizedStringResource = "Запомнить в PADAM"
    static var description = IntentDescription("Сохраняет факт, решение или предпочтение в локальную память PADAM Studio.")

    @Parameter(title: "Текст записи")
    var content: String

    @Parameter(title: "Тип записи", default: "fact")
    var kind: String

    func perform() async throws -> some IntentResult & ReturnsValue<String> {
        let baseURL = UserDefaults.standard.string(forKey: "padam_studio_url") ?? "http://127.0.0.1:8765/studio"
        let trimmed = content.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return .result(value: "Пустой текст не сохранён.")
        }
        return .result(value: "Готово к записи в PADAM (\(kind)) через \(baseURL): \(trimmed)")
    }
}

/// Команда Apple Shortcuts / Siri: поиск по памяти PADAM Studio.
@available(iOS 16.0, macOS 13.0, *)
struct PadamRecallIntent: AppIntent {
    static var title: LocalizedStringResource = "Найти в PADAM"
    static var description = IntentDescription("Открывает гибридный поиск по памяти PADAM NOCTURNE.")

    @Parameter(title: "Запрос")
    var query: String

    func perform() async throws -> some IntentResult & ReturnsValue<String> {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines)
        return .result(value: "Поиск PADAM по запросу: \(q)")
    }
}

@available(iOS 16.0, macOS 13.0, *)
struct PadamShortcutsProvider: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(
            intent: PadamRememberIntent(),
            phrases: ["Запомни в \(.applicationName)", "Remember in \(.applicationName)"],
            shortTitle: "Запомнить в PADAM",
            systemImageName: "brain.head.profile"
        )
        AppShortcut(
            intent: PadamRecallIntent(),
            phrases: ["Найди в \(.applicationName)", "Search \(.applicationName)"],
            shortTitle: "Найти в PADAM",
            systemImageName: "magnifyingglass"
        )
    }
}
