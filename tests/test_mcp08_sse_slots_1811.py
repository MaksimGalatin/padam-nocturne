"""Фаза 2 аудита GLM, MCP-08: одновременных постоянных SSE-потоков не больше предела — лишний получает 429."""
import http.client
import threading
import time

from padam import mcp_server
from padam.memory import Memory
from padam.store import Store


def _open_stream(host_port, tok, sid):
    c = http.client.HTTPConnection(host_port, timeout=10)
    c.request("GET", "/mcp", headers={"Authorization": f"Bearer {tok}", "Accept": "text/event-stream",
                                     "Mcp-Session-Id": sid, "Host": host_port})
    return c, c.getresponse()


def _delete_session(host_port, tok, sid):
    c = http.client.HTTPConnection(host_port, timeout=10)
    c.request("DELETE", "/mcp", headers={"Authorization": f"Bearer {tok}", "Mcp-Session-Id": sid, "Host": host_port})
    st = c.getresponse().status
    c.close()
    return st


def test_лишний_sse_поток_получает_429(tmp_path, monkeypatch):
    monkeypatch.setenv("PADAM_MCP_MAX_SSE", "2")
    m = Memory(user_id="u", store=Store(tmp_path / "s.db"))
    srv, url, tok = mcp_server.make_mcp_http_server(memory=m, host="127.0.0.1", port=0, token="sse-secret-token-1234")
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    hp = url.split("://", 1)[1].split("/", 1)[0]
    try:
        a = _open_stream(hp, tok, "sse-a"); b = _open_stream(hp, tok, "sse-b")
        assert a[1].status == 200 and b[1].status == 200
        c = _open_stream(hp, tok, "sse-c")
        assert c[1].status == 429                  # третий сверх предела 2
        c[0].close()
        assert _delete_session(hp, tok, "sse-a") < 300   # штатное закрытие сессии останавливает её поток
        ok = False
        for _ in range(20):                        # цикл потока проверяет остановку каждые 0,3 с
            time.sleep(0.2)
            d = _open_stream(hp, tok, "sse-d")
            if d[1].status == 200:
                ok = True; d[0].close(); break
            d[0].close()
        a[0].close(); b[0].close()
        assert ok, "слот не освободился после закрытия сессии"
    finally:
        srv.shutdown(); srv.server_close(); m.close()
