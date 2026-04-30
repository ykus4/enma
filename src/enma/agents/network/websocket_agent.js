"use strict";
/**
 * WebSocket Monitor Agent
 *
 * Captures WebSocket frames from:
 *   1. OkHttp3 WebSocket (WebSocketListener callbacks)
 *   2. Java WebSocket API (javax.websocket / Tyrus)
 *   3. Native libwebsockets (if present)
 *
 * Output: websocket_log.json
 */

function log(msg) { send({ event: "log", message: msg }); }
function sendJson(name, data) { send({ event: "json", name: name, data: data }); }

const wsLog  = [];
const MAX    = 2000;

function record(dir, type, payload) {
    if (wsLog.length >= MAX) return;
    const entry = { ts: Date.now(), direction: dir, type, payload };
    wsLog.push(entry);
    log(`[ws] ${dir} ${type}: ${String(payload).slice(0, 120)}`);
}

// ── 1. OkHttp3 WebSocket ──────────────────────────────────────────────────────

function hookOkHttp3WS() {
    Java.perform(() => {
        // Hook OkHttpClient.newWebSocket to wrap the listener
        try {
            const OHC = Java.use("okhttp3.OkHttpClient");
            const WSL = Java.use("okhttp3.WebSocketListener");

            OHC.newWebSocket.implementation = function (request, listener) {
                const url = request.url().toString();
                log(`[ws] OkHttp3 WebSocket opened: ${url}`);

                const WrappedListener = Java.registerClass({
                    name: "com.enma.WsListenerWrapper",
                    superClass: WSL,
                    methods: {
                        onOpen(ws, resp) {
                            record("OPEN", "connection", url);
                            listener.onOpen(ws, resp);
                        },
                        onMessage$okhttp3_WebSocket_String(ws, text) {
                            record("RECV", "text", text.toString());
                            listener.onMessage(ws, text);
                        },
                        onMessage$okhttp3_WebSocket_ByteString(ws, bytes) {
                            try {
                                record("RECV", "binary", bytes.hex().toString());
                            } catch (_) { record("RECV", "binary", "<bytes>"); }
                            listener.onMessage(ws, bytes);
                        },
                        onClosing(ws, code, reason) {
                            record("CLOSE", "closing", `${code} ${reason}`);
                            listener.onClosing(ws, code, reason);
                        },
                        onClosed(ws, code, reason) {
                            record("CLOSE", "closed", `${code} ${reason}`);
                            listener.onClosed(ws, code, reason);
                        },
                        onFailure(ws, t, resp) {
                            record("ERROR", "failure", t.toString());
                            listener.onFailure(ws, t, resp);
                        },
                    },
                });

                // Also hook send() on the WebSocket to capture outgoing messages
                const ws = this.newWebSocket(request, WrappedListener.$new());

                // Wrap ws.send to log outgoing
                try {
                    const WS = Java.use("okhttp3.internal.ws.RealWebSocket");
                    WS.send.overload("java.lang.String").implementation = function (text) {
                        record("SEND", "text", text.toString());
                        return this.send(text);
                    };
                    WS.send.overload("okio.ByteString").implementation = function (bytes) {
                        try { record("SEND", "binary", bytes.hex().toString()); } catch (_) {}
                        return this.send(bytes);
                    };
                } catch (_) {}

                return ws;
            };
            log("[ws] OkHttp3 WebSocket hooked");
        } catch (e) { log(`[ws] OkHttp3 WS hook failed: ${e}`); }
    });
}

// ── 2. javax.websocket (Tyrus / standard JSR-356) ────────────────────────────

function hookJavaxWS() {
    Java.perform(() => {
        for (const cls of [
            "javax.websocket.Session",
            "org.glassfish.tyrus.core.TyrusSession",
        ]) {
            try {
                const C = Java.use(cls);
                if (C.getBasicRemote) {
                    C.getBasicRemote.implementation = function () {
                        const remote = this.getBasicRemote();
                        try {
                            const JRemote = Java.use(remote.getClass().getName());
                            JRemote.sendText.overload("java.lang.String").implementation = function (msg) {
                                record("SEND", "text", msg.toString());
                                return this.sendText(msg);
                            };
                        } catch (_) {}
                        return remote;
                    };
                }
            } catch (_) {}
        }
    });
}

// ── Flush ─────────────────────────────────────────────────────────────────────

function flush() {
    if (wsLog.length > 0) sendJson("websocket_log.json", wsLog);
}

// ── Entry point ───────────────────────────────────────────────────────────────

log("[ws] Agent loaded");
Java.performNow(() => {
    hookOkHttp3WS();
    hookJavaxWS();
});

setInterval(flush, 10000);
setTimeout(flush, 60000);
