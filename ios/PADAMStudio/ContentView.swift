import SwiftUI
import WebKit

/// Экран PADAM Studio для iPhone, iPad (iOS 16+) и macOS 13+ на базе изолированного WKWebView.
/// Локальный адрес (127.0.0.1 / localhost / LAN) открывается внутри приложения;
/// внешние ссылки (оплата тарифов, политика, GitHub) открываются в системном браузере.
struct ContentView: View {
    @AppStorage("padam_studio_url") private var studioURL: String = "https://aifa.works/nocturne"
    @State private var showEndpointSheet: Bool = false
    @State private var draftURL: String = ""

    var body: some View {
        NavigationStack {
            PadamWebView(urlString: studioURL)
                .ignoresSafeArea(edges: .bottom)
                .navigationTitle("PADAM Studio")
                #if os(iOS)
                .navigationBarTitleDisplayMode(.inline)
                #endif
                .toolbar {
                    ToolbarItemGroup(placement: .automatic) {
                        if let shareURL = URL(string: studioURL) {
                            ShareLink(item: shareURL) {
                                Image(systemName: "square.and.arrow.up")
                            }
                            .accessibilityLabel("Share PADAM Studio")
                        }
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
                            Section("Studio URL (LAN / Tailscale / 127.0.0.1 / Cloud)") {
                                TextField("https://aifa.works/nocturne", text: $draftURL)
                                    #if os(iOS)
                                    .keyboardType(.URL)
                                    .textInputAutocapitalization(.never)
                                    #endif
                                    .autocorrectionDisabled()
                            }
                            Section("Быстрые профили") {
                                Button("Облако AIfa (aifa.works/nocturne)") {
                                    draftURL = "https://aifa.works/nocturne"
                                }
                                Button("Локальный узел (127.0.0.1:8765)") {
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

#if os(iOS)
private struct PadamWebView: UIViewRepresentable {
    let urlString: String
    func makeCoordinator() -> PadamWebCoordinator { PadamWebCoordinator() }
    func makeUIView(context: Context) -> WKWebView { context.coordinator.makeWebView(urlString: urlString) }
    func updateUIView(_ uiView: WKWebView, context: Context) { context.coordinator.updateWebView(uiView, urlString: urlString) }
}
#else
private struct PadamWebView: NSViewRepresentable {
    let urlString: String
    func makeCoordinator() -> PadamWebCoordinator { PadamWebCoordinator() }
    func makeNSView(context: Context) -> WKWebView { context.coordinator.makeWebView(urlString: urlString) }
    func updateNSView(_ nsView: WKWebView, context: Context) { context.coordinator.updateWebView(nsView, urlString: urlString) }
}
#endif

private final class PadamWebCoordinator: NSObject, WKNavigationDelegate, WKDownloadDelegate {
    func makeWebView(urlString: String) -> WKWebView {
        let cfg = WKWebViewConfiguration()
        cfg.websiteDataStore = .default()
        let webView = WKWebView(frame: .zero, configuration: cfg)
        webView.navigationDelegate = self
        webView.allowsBackForwardNavigationGestures = true
        if let url = URL(string: urlString) {
            webView.load(URLRequest(url: url))
        }
        return webView
    }

    func updateWebView(_ webView: WKWebView, urlString: String) {
        guard let target = URL(string: urlString) else { return }
        if webView.url?.absoluteString != target.absoluteString {
            webView.load(URLRequest(url: target))
        }
    }

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
            || host.hasSuffix(".local")
            || host.hasPrefix("192.168.")
            || host.hasPrefix("10.")
            || host.hasPrefix("100.")
        if allowedInside || navigationAction.navigationType == .other {
            decisionHandler(.allow)
            return
        }
        if url.scheme?.lowercased() == "https" {
            #if os(iOS)
            UIApplication.shared.open(url)
            #else
            NSWorkspace.shared.open(url)
            #endif
        }
        decisionHandler(.cancel)
    }

    func webView(
        _ webView: WKWebView,
        decidePolicyFor navigationResponse: WKNavigationResponse,
        decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void
    ) {
        decisionHandler(navigationResponse.canShowMIMEType ? .allow : .download)
    }

    func webView(_ webView: WKWebView, navigationResponse: WKNavigationResponse, didBecome download: WKDownload) {
        download.delegate = self
    }

    func download(
        _ download: WKDownload,
        decideDestinationUsing response: URLResponse,
        suggestedFilename: String,
        completionHandler: @escaping (URL?) -> Void
    ) {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
        completionHandler(docs?.appendingPathComponent(suggestedFilename))
    }
}
