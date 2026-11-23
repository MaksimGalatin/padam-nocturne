# Third-Party Notices — PADAM NOCTURNE & PADAM Studio

PADAM is licensed under the PADAM License 1.0 ([`LICENSE`](LICENSE)). It uses the third-party components below,
each under its own licence. Nothing in the PADAM License 1.0 limits your rights under these licences. None of them is
GPL or AGPL. The two LGPL libraries are used unmodified, as separate Python packages that you can replace with your
own version; the MPL-2.0 package is used unmodified.

Licences checked on 23.11.2026 from each package's own metadata or licence file.

| Component | Version checked | Licence | Used for | Source |
|---|---|---|---|---|
| numpy | 2.5.2 | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 | vectors | https://numpy.org |
| requests | 2.33.1 | Apache-2.0 | HTTP | https://github.com/psf/requests |
| urllib3 | 2.6.3 | MIT | HTTP (via requests) | https://github.com/urllib3/urllib3 |
| charset-normalizer | 3.4.7 | MIT | HTTP (via requests) | https://github.com/jawah/charset_normalizer |
| idna | 3.13 | BSD-3-Clause | HTTP (via requests) | https://github.com/kjd/idna |
| certifi | 2026.4.22 | MPL-2.0 | root certificates (via requests) | https://github.com/certifi/python-certifi |
| cryptography | 50.0.0 | Apache-2.0 OR BSD-3-Clause | encryption | https://github.com/pyca/cryptography |
| cffi | 2.1.0 | MIT-0 | (via cryptography) | https://github.com/python-cffi/cffi |
| pycparser | 3.0 | BSD-3-Clause | (via cffi) | https://github.com/eliben/pycparser |
| solders *(optional `[l3]`)* | 0.29.0 | Apache-2.0 | Solana anchoring | https://github.com/kevinheavey/solders |
| opentimestamps *(optional `[l3]`)* | 0.4.5 | LGPL-3.0-or-later | Bitcoin timestamps | https://github.com/opentimestamps/python-opentimestamps |
| python-bitcoinlib *(optional, via opentimestamps)* | 0.12.2 | LGPL-3.0-or-later | Bitcoin timestamps | https://github.com/petertodd/python-bitcoinlib |
| model2vec *(optional `[embed]`)* | 0.10.0 | MIT | local embeddings | https://github.com/MinishLab/model2vec |
| onnxruntime *(optional `[guard]`)* | 1.29.0 | MIT | local injection classifier | https://onnxruntime.ai |
| tokenizers *(optional `[guard]`)* | 0.23.1 | Apache-2.0 | local injection classifier | https://github.com/huggingface/tokenizers |
| Tauri 2 and its plugins *(PADAM Studio desktop)* | 2.x | MIT OR Apache-2.0 | desktop shell and updater | https://github.com/tauri-apps/tauri |
| Python runtime *(bundled in PADAM Studio for Windows)* | 3.x | PSF License 2.0 | runs PADAM | https://www.python.org/psf/license/ |
| Microsoft Edge WebView2 Runtime *(system component on Windows)* | — | Microsoft Software License Terms | Studio window | https://developer.microsoft.com/microsoft-edge/webview2/ |

The full text of each licence ships inside each installed package (its `*.dist-info/licenses` folder) and is available at
the source address above. LGPL-3.0: https://www.gnu.org/licenses/lgpl-3.0.html · MPL-2.0: https://www.mozilla.org/MPL/2.0/
