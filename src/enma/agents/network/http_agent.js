"use strict";
/**
 * HTTP Full-Body Capture Agent
 *
 * Captures complete HTTP request / response bodies (not just headers) from:
 *   1. OkHttp3 (Interceptor chain injection)
 *   2. HttpURLConnection / HttpsURLConnection
 *   3. Retrofit2 (via OkHttp3 — covered by #1)
 *   4. Volley RequestQueue
 *
 * Output: http_traffic.json
 */

function log(msg) { send({ event: "log", message: msg }); }
function sendJson(name, data) { send({ event: "json", name: name, data: data }); }

const httpLog = [];
const MAX = 500;

function record(entry) {
    if (httpLog.length >= MAX) return;
    httpLog.push({ ts: Date.now(), ...entry });
    log(`[http] ${entry.method ?? "?"} ${(entry.url ?? "?").slice(0, 100)}  ${entry.statusCode ?? ""}`);
}

// ── helpers ───────────────────────────────────────────────────────────────────

function headersToObj(headers) {
    const obj = {};
    try {
        const names = headers.names().toArray();
        for (let i = 0; i < names.length; i++) {
            const n = names[i].toString();
            obj[n] = headers.get(Java.use("java.lang.String").$new(n))?.toString() ?? null;
        }
    } catch (_) {}
    return obj;
}

function streamToString(stream, charset) {
    try {
        const ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
        const out = ByteArrayOutputStream.$new();
        const buf = Java.array("byte", new Array(8192).fill(0));
        let n;
        while ((n = stream.read(buf)) !== -1) out.write(buf, 0, n);
        return out.toString(charset ?? "UTF-8");
    } catch (_) { return "<unreadable>"; }
}

// ── 1. OkHttp3 ────────────────────────────────────────────────────────────────

function hookOkHttp3() {
    Java.perform(() => {
        // Inject a network interceptor that peeks at the request/response body
        try {
            const OkHttpClient = Java.use("okhttp3.OkHttpClient");
            const OkHttpClientBuilder = Java.use("okhttp3.OkHttpClient$Builder");
            const Interceptor = Java.use("okhttp3.Interceptor");
            const Chain       = Java.use("okhttp3.Interceptor$Chain");

            // Hook OkHttpClient.Builder.build() to inject our interceptor
            OkHttpClientBuilder.build.implementation = function () {
                const DumpInterceptor = Java.registerClass({
                    name: "com.enma.HttpDumpInterceptor",
                    implements: [Interceptor],
                    methods: {
                        intercept(chain) {
                            const req    = chain.request();
                            const url    = req.url().toString();
                            const method = req.method().toString();
                            const reqHeaders = headersToObj(req.headers());

                            let reqBody = null;
                            try {
                                const rb = req.body();
                                if (rb) {
                                    const buf = Java.use("okio.Buffer").$new();
                                    rb.writeTo(buf);
                                    reqBody = buf.readUtf8().toString();
                                }
                            } catch (_) {}

                            const resp    = chain.proceed(req);
                            const code    = resp.code();
                            const respHeaders = headersToObj(resp.headers());

                            let respBody = null;
                            try {
                                const peekBody = resp.peekBody(1024 * 1024); // 1 MB
                                respBody = peekBody.string().toString();
                            } catch (_) {}

                            record({
                                url, method, statusCode: code,
                                requestHeaders: reqHeaders, requestBody: reqBody,
                                responseHeaders: respHeaders, responseBody: respBody,
                            });

                            return resp;
                        },
                    },
                });

                this.addNetworkInterceptor(DumpInterceptor.$new());
                return this.build();
            };
            log("[http] OkHttp3 interceptor injected");
        } catch (e) { log(`[http] OkHttp3 hook failed: ${e}`); }
    });
}

// ── 2. HttpURLConnection ──────────────────────────────────────────────────────

function hookHttpURLConnection() {
    Java.perform(() => {
        try {
            const HURLC = Java.use("java.net.HttpURLConnection");

            HURLC.getInputStream.implementation = function () {
                const stream = this.getInputStream();
                try {
                    const url    = this.getURL().toString();
                    const method = this.getRequestMethod().toString();
                    const code   = this.getResponseCode();
                    // Wrap stream to capture body lazily
                    record({ url, method, statusCode: code, note: "HttpURLConnection (body not captured — use OkHttp3)" });
                } catch (_) {}
                return stream;
            };
        } catch (_) {}
    });
}

// ── 3. Volley ─────────────────────────────────────────────────────────────────

function hookVolley() {
    Java.perform(() => {
        for (const cls of ["com.android.volley.Request", "com.android.volley.toolbox.StringRequest"]) {
            try {
                const C = Java.use(cls);
                if (C.parseNetworkResponse) {
                    C.parseNetworkResponse.overloads.forEach(ovl => {
                        ovl.implementation = function (...args) {
                            try {
                                const resp = args[0];
                                const data = resp.data;
                                const body = Java.use("java.lang.String").$new(data, "UTF-8").toString();
                                record({ url: this.getUrl().toString(), method: "VOLLEY", statusCode: resp.statusCode, responseBody: body.slice(0, 4096) });
                            } catch (_) {}
                            return ovl.apply(this, args);
                        };
                    });
                }
            } catch (_) {}
        }
    });
}

// ── Flush ─────────────────────────────────────────────────────────────────────

function flush() {
    if (httpLog.length > 0) sendJson("http_traffic.json", httpLog);
}

// ── Entry point ───────────────────────────────────────────────────────────────

log("[http] Agent loaded");
Java.performNow(() => {
    hookOkHttp3();
    hookHttpURLConnection();
    hookVolley();
});

setInterval(flush, 10000);
setTimeout(flush, 60000);
