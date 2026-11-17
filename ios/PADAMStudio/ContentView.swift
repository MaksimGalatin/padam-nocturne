import SwiftUI
import WebKit

/// Экран PADAM Studio для iOS на базе изолированного WKWebView.
/// Локальный адрес (127.0.0.1 / localhost) открывается внутри приложения;
/// внешние ссылки (оплата тарифов, политика, GitHub) открываются в системном Safari.
struct ContentView: View {
    @AppStorage("padam_studio_url") private var studioURL: String = "https://aifa.works/nocturne"
    @State private var showEndpointSheet: Bool = false
    @State private var draftURL: String = ""

    var body: some View {
        NavigationStack {
            PadamWebView(urlString: studioURL)
                .ignoresSafeArea(edges: .bottom)
                .navigationTitle("PADAM Studio")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .topBarTrailing) {
                        Button {
                            draftURL = studioURL
                            showEndpointSheet = true
                        } label: {
                            Image(systemName: "slider.horizontal.3")
                        }
                        .accessibilityLabel("Studio Endpoint")
                    }
                }
                .sheet(isPresented: $showEndpointSheet) {
                    NavigationStack {
                        Form {
                            Section("Studio URL (LAN / 127.0.0.1 / Cloud)") {
                                TextField("https://aifa.works/nocturne", text: $draftURL)
                                    .keyboardType(.URL)
                                    .textInputAutocapitalization(.never)
                                    .autocorrectionDisabled()
                            }
                            Section {
                                Button("Использовать облако AIfa (aifa.works/nocturne)") {
                                    draftURL = "https://aifa.works/nocturne"
                                }
                                Button("Использовать локальный узел (127.0.0.1:8765)") {
                                    draftURL = "http://127.0.0.1:8765/studio"
                                }
                            }
                        }
                        .navigationTitle("Подключение")
                        .toolbar {
                            ToolbarItem(placement: .cancellationAction) {
                                Button("Отмена") { showEndpointSheet = false }
                            }
                            ToolbarItem(placement: .confirmationAction) {
                                Button("Сохранить") {
                                    let trimmed = draftURL.trimmingCharacters(in: .whitespacesAndNewlines)
                                    if !trimmed.isEmpty {
                                        studioURL = trimmed
                                    }
                                    showEndpointSheet = false
                                }
                            }
                        }
                    }
                }
        }
    }
}

private struct PadamWebView: UIViewRepresentable {
    let urlString: String

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    func makeUIView(context: Context) -> WKWebView {
        let cfg = WKWebViewConfiguration()
        cfg.websiteDataStore = .default()
        let webView = WKWebView(frame: .zero, configuration: cfg)
        webView.navigationDelegate = context.coordinator
        webView.allowsBackForwardNavigationGestures = true
        if let url = URL(string: urlString) {
            webView.load(URLRequest(url: url))
        }
        return webView
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {
        guard let target = URL(string: urlString) else { return }
        if uiView.url?.absoluteString != target.absoluteString {
            uiView.load(URLRequest(url: target))
        }
    }

    final class Coordinator: NSObject, WKNavigationDelegate {
        func webView(
            _ webView: WKWebView,
            decidePolicyFor navigationAction: WKNavigationAction,
            decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
        ) {
            guard let url = navigationAction.request.url else {
                decisionHandler(.allow)
                return
            }
            let host = (url.host ?? "").lowercased()
            let allowedInside = host == "127.0.0.1"
                || host == "localhost"
                || host == "aifa.works"
                || host.hasSuffix(".aifa.works")
            if allowedInside || navigationAction.navigationType == .other {
                decisionHandler(.allow)
                return
            }
            if url.scheme?.lowercased() == "https" {
                UIApplication.shared.open(url)
            }
            decisionHandler(.cancel)
        }
    }
}
