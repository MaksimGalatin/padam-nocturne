import Foundation
import SQLite3
import CryptoKit

/// Нативное оффлайн-хранилище памяти PADAM для iOS / iPadOS / macOS (SQLite3 + FTS5 + HMAC-SHA256).
/// Работает полностью без интернета на процессоре iPhone и совместимо с дельтами `live_mesh.py`.
public final class LocalMemoryStore {
    public struct MemoryRecord: Codable, Identifiable {
        public let id: String
        public let kind: String
        public let scope: String
        public let content: String
        public let createdAt: String
        public let status: String
    }

    private var db: OpaquePointer?
    private let dbPath: String

    public init(filename: String = "padam_ios_memory.db") throws {
        let fm = FileManager.default
        let supportDir = try fm.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        self.dbPath = supportDir.appendingPathComponent(filename).path
        if sqlite3_open(self.dbPath, &self.db) != SQLITE_OK {
            throw NSError(domain: "PADAMLocalStore", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to open SQLite DB"])
        }
        try bootstrapSchema()
    }

    deinit {
        if db != nil {
            sqlite3_close(db)
        }
    }

    private func bootstrapSchema() throws {
        let ddl = """
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS memory (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL DEFAULT 'fact',
            scope TEXT NOT NULL DEFAULT 'global',
            content TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL,
            owner_sig TEXT
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(id UNINDEXED, content);
        CREATE TABLE IF NOT EXISTS forget_receipt (
            memory_id TEXT PRIMARY KEY,
            content_sha256 TEXT NOT NULL,
            forgotten_at TEXT NOT NULL
        );
        """
        if sqlite3_exec(db, ddl, nil, nil, nil) != SQLITE_OK {
            throw NSError(domain: "PADAMLocalStore", code: 2, userInfo: [NSLocalizedDescriptionKey: "Failed to initialize schema"])
        }
    }

    public static func redactSecrets(_ text: String) -> String {
        let patterns = [
            "sk-ant-[A-Za-z0-9_\\-]{16,}",
            "sk-(?:proj-)?[A-Za-z0-9_\\-]{20,}",
            "gh[pousr]_[A-Za-z0-9]{20,}"
        ]
        var result = text
        for pat in patterns {
            if let regex = try? NSRegularExpression(pattern: pat, options: []) {
                let range = NSRange(result.startIndex..<result.endIndex, in: result)
                result = regex.stringByReplacingMatches(in: result, options: [], range: range, withTemplate: "[REDACTED:secret]")
            }
        }
        return result
    }

    public func remember(content: String, kind: String = "fact", scope: String = "global", hmacKey: SymmetricKey? = nil) throws -> String {
        let id = UUID().uuidString.lowercased()
        let clean = Self.redactSecrets(content)
        let now = ISO8601DateFormatter().string(from: Date())
        var sigHex: String? = nil
        if let key = hmacKey {
            let msg = "\(id)\u{001F}\(kind)\u{001F}\(clean)".data(using: .utf8)!
            let mac = HMAC<SHA256>.authenticationCode(for: msg, using: key)
            sigHex = mac.map { String(format: "%02x", $0) }.joined()
        }

        let sql = "INSERT INTO memory (id, kind, scope, content, status, created_at, owner_sig) VALUES (?, ?, ?, ?, 'active', ?, ?);"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw NSError(domain: "PADAMLocalStore", code: 3, userInfo: nil)
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, (id as NSString).utf8String, -1, nil)
        sqlite3_bind_text(stmt, 2, (kind as NSString).utf8String, -1, nil)
        sqlite3_bind_text(stmt, 3, (scope as NSString).utf8String, -1, nil)
        sqlite3_bind_text(stmt, 4, (clean as NSString).utf8String, -1, nil)
        sqlite3_bind_text(stmt, 5, (now as NSString).utf8String, -1, nil)
        if let s = sigHex {
            sqlite3_bind_text(stmt, 6, (s as NSString).utf8String, -1, nil)
        } else {
            sqlite3_bind_null(stmt, 6)
        }
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            throw NSError(domain: "PADAMLocalStore", code: 4, userInfo: nil)
        }

        let ftsSql = "INSERT INTO memory_fts (id, content) VALUES (?, ?);"
        var ftsStmt: OpaquePointer?
        if sqlite3_prepare_v2(db, ftsSql, -1, &ftsStmt, nil) == SQLITE_OK {
            sqlite3_bind_text(ftsStmt, 1, (id as NSString).utf8String, -1, nil)
            sqlite3_bind_text(ftsStmt, 2, (clean as NSString).utf8String, -1, nil)
            _ = sqlite3_step(ftsStmt)
            sqlite3_finalize(ftsStmt)
        }
        return id
    }

    public func search(query: String, limit: Int = 10) -> [MemoryRecord] {
        let sql = """
        SELECT m.id, m.kind, m.scope, m.content, m.created_at, m.status
        FROM memory m
        WHERE m.status = 'active' AND LOWER(m.content) LIKE ?
        ORDER BY m.created_at DESC LIMIT ?;
        """
        var stmt: OpaquePointer?
        var out: [MemoryRecord] = []
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return out }
        defer { sqlite3_finalize(stmt) }
        let likePattern = "%\(query.lowercased())%"
        sqlite3_bind_text(stmt, 1, (likePattern as NSString).utf8String, -1, nil)
        sqlite3_bind_int(stmt, 2, Int32(limit))
        while sqlite3_step(stmt) == SQLITE_ROW {
            let id = String(cString: sqlite3_column_text(stmt, 0))
            let kind = String(cString: sqlite3_column_text(stmt, 1))
            let scope = String(cString: sqlite3_column_text(stmt, 2))
            let content = sqlite3_column_text(stmt, 3).map { String(cString: $0) } ?? ""
            let createdAt = String(cString: sqlite3_column_text(stmt, 4))
            let status = String(cString: sqlite3_column_text(stmt, 5))
            out.append(MemoryRecord(id: id, kind: kind, scope: scope, content: content, createdAt: createdAt, status: status))
        }
        return out
    }

    public func forget(id: String) -> String {
        let now = ISO8601DateFormatter().string(from: Date())
        let digest = SHA256.hash(data: Data(id.utf8)).map { String(format: "%02x", $0) }.joined()
        var stmt: OpaquePointer?
        if sqlite3_prepare_v2(db, "UPDATE memory SET content = NULL, status = 'forgotten' WHERE id = ?;", -1, &stmt, nil) == SQLITE_OK {
            sqlite3_bind_text(stmt, 1, (id as NSString).utf8String, -1, nil)
            _ = sqlite3_step(stmt)
            sqlite3_finalize(stmt)
        }
        if sqlite3_prepare_v2(db, "DELETE FROM memory_fts WHERE id = ?;", -1, &stmt, nil) == SQLITE_OK {
            sqlite3_bind_text(stmt, 1, (id as NSString).utf8String, -1, nil)
            _ = sqlite3_step(stmt)
            sqlite3_finalize(stmt)
        }
        if sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO forget_receipt (memory_id, content_sha256, forgotten_at) VALUES (?, ?, ?);", -1, &stmt, nil) == SQLITE_OK {
            sqlite3_bind_text(stmt, 1, (id as NSString).utf8String, -1, nil)
            sqlite3_bind_text(stmt, 2, (digest as NSString).utf8String, -1, nil)
            sqlite3_bind_text(stmt, 3, (now as NSString).utf8String, -1, nil)
            _ = sqlite3_step(stmt)
            sqlite3_finalize(stmt)
        }
        return digest
    }
}
