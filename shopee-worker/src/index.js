/**
 * Gooby Shopee Live Worker V40 (VPS) — sharded Firestore + conflict-safe writes.
 *
 * Changes from V37:
 * - Never rewrites liveDashboard/main.data as one large object.
 * - Reads/writes one shift per document: liveDashboardShifts/{shiftId}.
 * - Uses Firestore updateTime preconditions (CAS) when mutating a shift.
 * - Worker only patches shift.shopeeLiveMetrics + worker bookkeeping fields.
 * - Connection status patches only nested settings fields in main.
 * - Supports legacy liveDashboard/main.data.shifts during migration.
 * - Still uses auth_type=user and signs Livestream APIs with user_id.
 * - Never falls back to Order API / whole-shop GMV.
 *
 * Required Worker vars/secrets:
 *   SHOPEE_PARTNER_ID
 *   SHOPEE_PARTNER_KEY
 *   LIVE_API_BASE        (V40: https://188-245-105-61.sslip.io/live-api)
 *   LIVE_SERVICE_TOKEN   (V40: token dịch vụ của máy chủ dữ liệu, đặt dạng Secret)
 *
 * Optional:
 *   SHOPEE_API_BASE=https://partner.shopeemobile.com
 *   SHOPEE_LIVE_METRIC_PATH=/api/v2/livestream/get_session_metric
 *   SHOPEE_LIVE_DETAIL_PATH=/api/v2/livestream/get_session_detail
 *   SHOPEE_SHOP_ID_MAP_JSON={"Gooby":889519230}
 *   FIREBASE_DOC_PATH=liveDashboard/main
 *   FIREBASE_SHOPEE_DOC_PATH=liveDashboardShopee/connections
 *   FIREBASE_SHIFT_COLLECTION=liveDashboardShifts
 *   DASHBOARD_ALLOWED_ORIGIN=*
 */

const WORKER_VERSION = "V40.4 live-board";
const AUTH_PARTNER_PATH = "/api/v2/shop/auth_partner";
const TOKEN_GET_PATH = "/api/v2/auth/token/get";
const TOKEN_REFRESH_PATH = "/api/v2/auth/access_token/get";
const DEFAULT_LIVE_METRIC_PATH = "/api/v2/livestream/get_session_metric";
const DEFAULT_LIVE_DETAIL_PATH = "/api/v2/livestream/get_session_detail";
const DEFAULT_FIREBASE_DOC_PATH = "liveDashboard/main";
const DEFAULT_FIREBASE_SHOPEE_DOC_PATH = "liveDashboardShopee/connections";
const DEFAULT_SHIFT_COLLECTION = "liveDashboardShifts";
const TOKEN_REFRESH_BUFFER_SECONDS = 30 * 60;
const MAX_CAS_RETRIES = 4;
function clone(value) { return value == null ? value : JSON.parse(JSON.stringify(value)); }

function json(data, status = 200, req = null, env = null) {
  // V40.2: DASHBOARD_ALLOWED_ORIGIN nhận nhiều địa chỉ, cách nhau bằng dấu phẩy (web chạy ở cả workers.dev và pages.dev).
  const allowed = String(env?.DASHBOARD_ALLOWED_ORIGIN || "*").split(",").map(s => s.trim()).filter(Boolean);
  const requestOrigin = req?.headers?.get("origin") || "";
  const origin = !allowed.length || allowed.includes("*") ? "*" : (allowed.includes(requestOrigin) ? requestOrigin : allowed[0]);
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "access-control-allow-origin": origin,
      "vary": "Origin",
      "access-control-allow-methods": "GET,POST,OPTIONS",
      "access-control-allow-headers": "content-type,authorization",
      "cache-control": "no-store"
    }
  });
}

function html(body, status = 200) {
  return new Response(body, {
    status,
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" }
  });
}

function mustEnv(env, key) {
  const value = String(env[key] || "").trim();
  if (!value) throw new Error(`Thiếu biến ${key}`);
  return value;
}

function apiBase(env) {
  return String(env.SHOPEE_API_BASE || "https://partner.shopeemobile.com").trim().replace(/\/$/, "");
}

function dashboardDocPath(env) { return String(env.FIREBASE_DOC_PATH || DEFAULT_FIREBASE_DOC_PATH).trim(); }
function shopeeDocPath(env) { return String(env.FIREBASE_SHOPEE_DOC_PATH || DEFAULT_FIREBASE_SHOPEE_DOC_PATH).trim(); }
function shiftCollection(env) { return String(env.FIREBASE_SHIFT_COLLECTION || DEFAULT_SHIFT_COLLECTION).trim(); }
function shiftDocPath(env, shiftId) { return `${shiftCollection(env)}/${encodeURIComponent(String(shiftId))}`; }

function firstNonEmpty(...values) {
  for (const value of values) if (value !== undefined && value !== null && String(value).trim() !== "") return String(value).trim();
  return "";
}
function uniqueStrings(values) { return [...new Set((values || []).map(String).map(v => v.trim()).filter(Boolean))]; }
function envJson(env, key) { try { return JSON.parse(env[key] || "{}"); } catch (_) { return {}; } }
function nowTextVN() {
  return new Date().toLocaleString("vi-VN", {
    timeZone: "Asia/Ho_Chi_Minh", hour: "2-digit", minute: "2-digit", second: "2-digit",
    day: "2-digit", month: "2-digit", year: "numeric"
  });
}
function escapeHtml(value) {
  return String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}
function escapeAttr(value) { return escapeHtml(value).replaceAll("'", "&#39;"); }
function hex(buffer) { return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, "0")).join(""); }
async function hmacSha256(message, secret) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message)));
}
async function signBase(env, path, timestamp) {
  return hmacSha256(`${mustEnv(env, "SHOPEE_PARTNER_ID")}${path}${timestamp}`, mustEnv(env, "SHOPEE_PARTNER_KEY"));
}
async function signAccessApi(env, path, timestamp, accessToken, principalId) {
  return hmacSha256(`${mustEnv(env, "SHOPEE_PARTNER_ID")}${path}${timestamp}${accessToken}${principalId}`, mustEnv(env, "SHOPEE_PARTNER_KEY"));
}

async function shopeePostToken(env, path, body) {
  const partnerId = Number(mustEnv(env, "SHOPEE_PARTNER_ID"));
  const timestamp = Math.floor(Date.now() / 1000);
  const sign = await signBase(env, path, timestamp);
  const url = new URL(apiBase(env) + path);
  url.searchParams.set("partner_id", String(partnerId));
  url.searchParams.set("timestamp", String(timestamp));
  url.searchParams.set("sign", sign);
  const response = await fetch(url.toString(), {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...body, partner_id: partnerId })
  });
  const text = await response.text();
  let data = null; try { data = text ? JSON.parse(text) : null; } catch (_) {}
  if (!response.ok || !data) throw new Error(`Shopee Token HTTP ${response.status}${text ? `: ${text.replace(/\s+/g," ").slice(0,300)}` : ""}`);
  if (data.error) throw new Error(`${data.error}: ${data.message || "Shopee token error"}`);
  return data.response || data;
}

async function performShopeeApiFetch(url) {
  const response = await fetch(url.toString(), { method: "GET" });
  const text = await response.text();
  let data = null; try { data = text ? JSON.parse(text) : null; } catch (_) {}
  if (!response.ok || !data) throw new Error(`Shopee HTTP ${response.status}${text ? `: ${text.replace(/\s+/g," ").slice(0,300)}` : ""}`);
  if (data.error) throw new Error(`${data.error}: ${data.message || "Shopee API error"}`);
  return data.response || data;
}

async function shopeeGetByUser(env, path, params, cfg) {
  const partnerId = String(mustEnv(env, "SHOPEE_PARTNER_ID"));
  const accessToken = String(cfg.access_token || "");
  const userId = String(cfg.user_id || "");
  if (!accessToken) throw new Error("Kết nối chưa có access_token");
  if (!userId) throw new Error("Kết nối chưa có user_id đã xác minh");
  const timestamp = Math.floor(Date.now() / 1000);
  const sign = await signAccessApi(env, path, timestamp, accessToken, userId);
  const url = new URL(apiBase(env) + path);
  for (const [k, v] of Object.entries({ partner_id: partnerId, timestamp, access_token: accessToken, user_id: userId, sign, ...(params || {}) })) {
    if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, String(v));
  }
  return performShopeeApiFetch(url);
}

// ---------- Firestore REST helpers ----------
function fromFirestoreValue(value) {
  if (!value || typeof value !== "object") return null;
  if ("nullValue" in value) return null;
  if ("stringValue" in value) return value.stringValue;
  if ("integerValue" in value) return Number(value.integerValue || 0);
  if ("doubleValue" in value) return Number(value.doubleValue || 0);
  if ("booleanValue" in value) return Boolean(value.booleanValue);
  if ("timestampValue" in value) return value.timestampValue;
  if ("arrayValue" in value) return (value.arrayValue.values || []).map(fromFirestoreValue);
  if ("mapValue" in value) {
    const out = {}; for (const [k, v] of Object.entries(value.mapValue.fields || {})) out[k] = fromFirestoreValue(v); return out;
  }
  return null;
}
function toFirestoreValue(value) {
  if (value === null || value === undefined) return { nullValue: null };
  if (typeof value === "string") return { stringValue: value };
  if (typeof value === "boolean") return { booleanValue: value };
  if (typeof value === "number") return Number.isInteger(value) ? { integerValue: String(value) } : { doubleValue: value };
  if (Array.isArray(value)) return { arrayValue: { values: value.map(toFirestoreValue) } };
  if (typeof value === "object") {
    const fields = {}; for (const [k, v] of Object.entries(value)) fields[k] = toFirestoreValue(v); return { mapValue: { fields } };
  }
  return { stringValue: String(value) };
}
function decodeDocument(doc) {
  if (!doc) return null;
  const data = {}; for (const [k, v] of Object.entries(doc.fields || {})) data[k] = fromFirestoreValue(v);
  return { data, updateTime: doc.updateTime || "", name: doc.name || "" };
}
// ---------- V40: đọc/ghi máy chủ dữ liệu trên VPS thay cho Firestore ----------
// LIVE_API_BASE = https://188-245-105-61.sslip.io/live-api ; LIVE_SERVICE_TOKEN = token dịch vụ của máy chủ.
// Giữ nguyên tên hàm cũ để phần logic Shopee bên dưới không đổi; "updateTime" giờ là số phiên bản tài liệu.
async function vpsRequest(env, route, body) {
  const res = await fetch(`${String(mustEnv(env, "LIVE_API_BASE")).replace(/\/$/, "")}${route}`, {
    method: body ? "POST" : "GET",
    headers: { "content-type": "application/json", authorization: `Bearer ${mustEnv(env, "LIVE_SERVICE_TOKEN")}` },
    body: body ? JSON.stringify(body) : undefined
  });
  const out = await res.json().catch(() => null);
  return { res, out };
}
// V40.1: người gọi phải gửi token phiên đăng nhập của web (Authorization: Bearer ...). Máy chủ VPS xác nhận vai trò qua /api/me.
async function requireLogin(req, env, roles = null) {
  const token = String(req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "").trim();
  const fail = (status, message) => { const err = new Error(message); err.status = status; return err; };
  if (!token) throw fail(401, "Cần đăng nhập web để dùng chức năng Shopee");
  const res = await fetch(`${String(mustEnv(env, "LIVE_API_BASE")).replace(/\/$/, "")}/api/me`, { headers: { authorization: `Bearer ${token}` } });
  const me = await res.json().catch(() => null);
  if (res.status === 401) throw fail(401, "Phiên đăng nhập đã hết hạn, hãy đăng nhập lại");
  if (!res.ok || !me?.role) throw fail(502, `Không xác thực được với máy chủ dữ liệu: HTTP ${res.status}`);
  if (roles && !roles.includes(me.role)) throw fail(403, "Chỉ Admin được dùng chức năng này");
  return me;
}
const requireAdmin = (req, env) => requireLogin(req, env, ["admin", "service"]);
async function readFirestoreDocRaw(env, path) {
  const { res, out } = await vpsRequest(env, `/api/doc?path=${encodeURIComponent(path)}`);
  if (!res.ok || !out) throw new Error(`Không đọc được dữ liệu ${path}: HTTP ${res.status} ${out?.error || ""}`);
  if (!out.exists) return null;
  return { data: out.data, updateTime: String(out.version), name: path };
}
async function patchFirestoreFields(env, path, fieldMap, preconditionUpdateTime = "") {
  const write = { op: "update", path, data: fieldMap || {} };
  if (preconditionUpdateTime) write.ifVersion = Number(preconditionUpdateTime);
  const { res, out } = await vpsRequest(env, "/api/commit", { writes: [write] });
  if (!res.ok) {
    const err = new Error(`Không ghi được dữ liệu ${path}: HTTP ${res.status} ${out?.error || ""}`);
    err.status = res.status === 409 ? 412 : res.status; throw err;
  }
  return { data: null, updateTime: String(out?.results?.[0]?.version || ""), name: path };
}
async function setFirestoreDoc(env, path, data) {
  const { res, out } = await vpsRequest(env, "/api/commit", { writes: [{ op: "set", path, data: data || {} }] });
  if (!res.ok) throw new Error(`Không ghi được dữ liệu ${path}: HTTP ${res.status} ${out?.error || ""}`);
  return { data, updateTime: String(out?.results?.[0]?.version || ""), name: path };
}
async function runCollectionQuery(env, collectionId, field, value, limit = 100) {
  const { res, out } = await vpsRequest(env, "/api/query", { parent: collectionId, where: [[field, "==", value]], limit: Math.max(1, Math.min(500, limit)) });
  if (!res.ok || !Array.isArray(out?.docs)) throw new Error(`Truy vấn dữ liệu lỗi: HTTP ${res.status}`);
  return out.docs.map(d => ({ data: d.data, updateTime: String(d.version), name: d.path }));
}
async function appendWorkerLog(env, payload) {
  try {
    const id = `worker_${Date.now().toString(36)}${Math.random().toString(36).slice(2,8)}`;
    await setFirestoreDoc(env, `${dashboardDocPath(env)}/activityLogs/${id}`, {
      id, module: "shopee_live_snapshot_sync", action: payload.action || "Worker đồng bộ Shopee Live",
      time: nowTextVN(), ts: Date.now(), actor: "Shopee Live Worker", details: payload.details || {}, storage: "Firestore sharded V38"
    });
  } catch (e) { console.warn("Không ghi được worker log", e.message); }
}
async function patchDashboardSettings(env, patch) {
  const fields = {};
  for (const [k, v] of Object.entries(patch || {})) fields[`data.settings.${k}`] = v;
  try { await patchFirestoreFields(env, dashboardDocPath(env), fields); } catch (e) { console.warn("Không patch được dashboard settings", e.message); }
}

// ---------- Connections: CAS-safe ----------
async function readShopeeConnectionsRaw(env) {
  const raw = await readFirestoreDocRaw(env, shopeeDocPath(env));
  return { connections: raw?.data?.connections && typeof raw.data.connections === "object" ? raw.data.connections : {}, updateTime: raw?.updateTime || "" };
}
async function mutateConnections(env, mutator) {
  for (let attempt = 0; attempt < MAX_CAS_RETRIES; attempt++) {
    const current = await readShopeeConnectionsRaw(env);
    const next = clone(current.connections || {});
    await mutator(next);
    try {
      await patchFirestoreFields(env, shopeeDocPath(env), {
        connections: next, updatedAtText: nowTextVN(), updatedBy: "Shopee OAuth Worker"
      }, current.updateTime);
      return next;
    } catch (e) {
      if (e.status === 409 || e.status === 412) continue;
      throw e;
    }
  }
  throw new Error("Xung đột cập nhật kết nối Shopee; đã thử lại nhiều lần");
}
function sanitizeConnection(connection) {
  if (!connection) return null;
  const { access_token, refresh_token, ...safe } = connection;
  return { ...safe, hasAccessToken: Boolean(access_token), hasRefreshToken: Boolean(refresh_token) };
}
function sanitizeConnections(connections) {
  const out = {}; for (const [k, v] of Object.entries(connections || {})) out[k] = sanitizeConnection(v); return out;
}
async function updateDashboardConnectionStatus(env, connections) {
  await patchDashboardSettings(env, { shopeeConnections: sanitizeConnections(connections), shopeeLastConnectionUpdate: nowTextVN() });
}
async function markConnectionSync(env, channel, patch) {
  try {
    const next = await mutateConnections(env, connections => {
      if (!connections[channel]) return;
      connections[channel] = { ...connections[channel], ...(patch || {}), updatedAt: nowTextVN() };
    });
    await updateDashboardConnectionStatus(env, next);
  } catch (e) { console.warn("Không cập nhật trạng thái kết nối", channel, e.message); }
}

function buildAuthorizedPairs(token, fallbackShopId = "") {
  const shopIds = Array.isArray(token.shop_id_list) ? token.shop_id_list.map(String) : [];
  const userIds = Array.isArray(token.user_id_list) ? token.user_id_list.map(String) : [];
  if (!userIds.length && token.user_id) userIds.push(String(token.user_id));
  if (!shopIds.length && token.shop_id) shopIds.push(String(token.shop_id));
  if (!shopIds.length && fallbackShopId) shopIds.push(String(fallbackShopId));
  if (!userIds.length) throw new Error("Shopee không trả user_id_list/user_id. Kiểm tra auth_type=user và quyền Livestream của app.");
  if (shopIds.length !== userIds.length) throw new Error(`Shopee trả shop_id_list (${shopIds.length}) và user_id_list (${userIds.length}) không cùng số phần tử.`);
  return shopIds.map((shop_id, i) => ({ shop_id: String(shop_id), user_id: String(userIds[i]) }));
}
function selectAuthorizedPair(pairs, targetShopId) {
  targetShopId = String(targetShopId || "");
  if (!targetShopId && pairs.length === 1) return pairs[0];
  if (!targetShopId) throw new Error("Tài khoản chính đã ủy quyền nhiều shop. Hãy cấu hình SHOPEE_SHOP_ID_MAP_JSON cho từng channel.");
  const pair = pairs.find(x => x.shop_id === targetShopId);
  if (!pair) throw new Error(`Không tìm thấy shop_id ${targetShopId} trong shop_id_list được Shopee trả về.`);
  return pair;
}

async function handleConnect(req, env) {
  await requireAdmin(req, env);
  const u = new URL(req.url);
  const channel = String(u.searchParams.get("channel") || "").trim();
  const returnUrl = String(u.searchParams.get("return_url") || "").trim();
  if (!channel) throw new Error("Thiếu channel");
  const timestamp = Math.floor(Date.now() / 1000);
  const sign = await signBase(env, AUTH_PARTNER_PATH, timestamp);
  const sig = await hmacSha256(`${channel}|${returnUrl}`, mustEnv(env, "SHOPEE_PARTNER_KEY"));
  const callback = new URL(req.url);
  callback.pathname = "/api/shopee/callback"; callback.search = "";
  callback.searchParams.set("channel", channel); callback.searchParams.set("sig", sig);
  if (returnUrl) callback.searchParams.set("return_url", returnUrl);
  const authUrl = new URL(apiBase(env) + AUTH_PARTNER_PATH);
  authUrl.searchParams.set("partner_id", mustEnv(env,"SHOPEE_PARTNER_ID"));
  authUrl.searchParams.set("timestamp", String(timestamp)); authUrl.searchParams.set("sign", sign);
  authUrl.searchParams.set("redirect", callback.toString()); authUrl.searchParams.set("auth_type", "user");
  // Web gọi bằng fetch kèm token rồi tự mở trang ủy quyền (không thể gửi token qua chuyển hướng trình duyệt).
  return json({ ok: true, url: authUrl.toString() }, 200, req, env);
}

async function handleCallback(req, env) {
  const u = new URL(req.url);
  const channel = String(u.searchParams.get("channel") || "").trim();
  const signature = String(u.searchParams.get("sig") || "");
  const returnUrl = String(u.searchParams.get("return_url") || "");
  const code = String(u.searchParams.get("code") || "").trim();
  const callbackShopId = Number(u.searchParams.get("shop_id") || 0);
  const callbackMainAccountId = Number(u.searchParams.get("main_account_id") || 0);
  if (!channel || !code || (!callbackShopId && !callbackMainAccountId)) throw new Error("Shopee callback thiếu channel/code/shop_id hoặc main_account_id");
  const expected = await hmacSha256(`${channel}|${returnUrl}`, mustEnv(env,"SHOPEE_PARTNER_KEY"));
  if (signature !== expected) throw new Error("Callback không hợp lệ hoặc channel đã bị thay đổi");
  const token = await shopeePostToken(env, TOKEN_GET_PATH, callbackShopId ? { code, shop_id: callbackShopId } : { code, main_account_id: callbackMainAccountId });
  if (!token.access_token || !token.refresh_token) throw new Error("Shopee không trả access_token/refresh_token");
  const existing = (await readShopeeConnectionsRaw(env)).connections;
  const shopMap = envJson(env, "SHOPEE_SHOP_ID_MAP_JSON");
  const configuredShopId = firstNonEmpty(shopMap[channel], shopMap[channel.toLowerCase()], existing[channel]?.shop_id, callbackShopId);
  const pairs = buildAuthorizedPairs(token, callbackShopId);
  const selected = selectAuthorizedPair(pairs, configuredShopId);
  const now = Math.floor(Date.now() / 1000);
  const nextConnections = await mutateConnections(env, connections => {
    connections[channel] = {
      channel, shop_id: Number(selected.shop_id), user_id: selected.user_id,
      user_id_source: "token.user_id_list paired with token.shop_id_list",
      authorized_pairs: pairs, shop_id_list: uniqueStrings(pairs.map(x=>x.shop_id)), user_id_list: uniqueStrings(pairs.map(x=>x.user_id)),
      main_account_id: callbackMainAccountId || Number(token.main_account_id || 0), access_token: token.access_token, refresh_token: token.refresh_token,
      expire_in: Number(token.expire_in || 0), expire_at: now + Number(token.expire_in || 0),
      refresh_expire_in: Number(token.refresh_expire_in || 0), refresh_expire_at: token.refresh_expire_in ? now + Number(token.refresh_expire_in) : 0,
      status: "connected", connectedAt: nowTextVN(), updatedAt: nowTextVN(), lastError: ""
    };
  });
  await updateDashboardConnectionStatus(env, nextConnections);
  const backUrl = returnUrl || "/";
  return html(`<!doctype html><html lang="vi"><head><meta charset="utf-8"><title>Kết nối Shopee thành công</title><style>body{font-family:Arial;padding:40px;line-height:1.6}a{display:inline-block;margin-top:16px;background:#ff7a2f;color:#fff;padding:10px 14px;border-radius:10px;text-decoration:none;font-weight:bold}</style></head><body><h2>Đã kết nối Shopee thành công</h2><p>Kênh <b>${escapeHtml(channel)}</b> đã liên kết với shop_id <b>${escapeHtml(selected.shop_id)}</b>.</p><p>Livestream user_id đã xác minh: <b>${escapeHtml(selected.user_id)}</b>.</p><a href="${escapeAttr(backUrl)}">Quay lại dashboard</a><script>setTimeout(()=>{try{window.close()}catch(e){}},2500)<\/script></body></html>`);
}

async function refreshUserTokenIfNeeded(env, channel, cfg) {
  const now = Math.floor(Date.now() / 1000);
  if (!cfg.refresh_token || Number(cfg.expire_at || 0) > now + TOKEN_REFRESH_BUFFER_SECONDS) return { shopCfg: cfg, refreshed: false };
  const userId = Number(cfg.user_id || 0);
  if (!userId) throw new Error("Kết nối thiếu user_id đã xác minh để refresh token");
  const token = await shopeePostToken(env, TOKEN_REFRESH_PATH, { refresh_token: cfg.refresh_token, user_id: userId });
  const returned = Array.isArray(token.user_id_list) ? token.user_id_list.map(String) : token.user_id ? [String(token.user_id)] : [];
  if (returned.length && !returned.includes(String(userId))) throw new Error(`Token refresh trả user_id không khớp user_id đã lưu ${userId}.`);
  let next;
  const all = await mutateConnections(env, connections => {
    const current = connections[channel] || cfg;
    next = {
      ...current, access_token: token.access_token || current.access_token, refresh_token: token.refresh_token || current.refresh_token,
      expire_in: Number(token.expire_in || current.expire_in || 0), expire_at: now + Number(token.expire_in || current.expire_in || 0),
      refresh_expire_in: Number(token.refresh_expire_in || current.refresh_expire_in || 0),
      refresh_expire_at: token.refresh_expire_in ? now + Number(token.refresh_expire_in) : Number(current.refresh_expire_at || 0),
      user_id: String(userId), status: "connected", updatedAt: nowTextVN(), lastError: ""
    };
    connections[channel] = next;
  });
  await updateDashboardConnectionStatus(env, all);
  return { shopCfg: next, refreshed: true };
}
async function getShopConfig(env, channel) {
  const { connections } = await readShopeeConnectionsRaw(env);
  const cfg = connections[channel];
  if (!cfg) throw new Error(`Kênh ${channel} chưa kết nối Shopee. Hãy kết nối lại bằng auth_type=user.`);
  if (!cfg.user_id || !String(cfg.user_id_source || "").startsWith("token.")) throw new Error(`Kênh ${channel} đang dùng kết nối cũ hoặc user_id chưa được xác minh. Hãy ngắt kết nối và kết nối lại.`);
  return (await refreshUserTokenIfNeeded(env, channel, cfg)).shopCfg;
}

function pickFirst(object, keys, fallback = undefined) {
  for (const key of keys) if (object && object[key] !== undefined && object[key] !== null && object[key] !== "") return object[key];
  return fallback;
}
function numberOrNull(object, keys) { const raw = pickFirst(object, keys); if (raw === undefined) return null; const n = Number(raw); return Number.isFinite(n) ? n : null; }
function stringOrEmpty(object, keys) { const raw = pickFirst(object, keys); return raw === undefined ? "" : String(raw); }
function unwrapShopeeResponse(raw) { return raw?.data || raw?.result || raw?.response || raw || {}; }
function returnedSessionId(raw) { const d = unwrapShopeeResponse(raw); return firstNonEmpty(d.session_id, d.live_id, d.liveId); }
// V40.4: chi tiết phiên của Shopee có stream_url_list chứa khóa phát sóng (push_key/txSecret). Chỉ giữ các trường an toàn
// vì số liệu được lưu vào ca mà mọi nhân viên đều đọc được.
function safeLiveDetail(detail) {
  const keep = ["session_id","title","description","status","is_test","create_time","update_time","start_time","end_time","share_url","cover_image_url"];
  return Object.fromEntries(keep.filter(k => detail && detail[k] !== undefined).map(k => [k, detail[k]]));
}
function formatWatchDuration(ms) {
  const s = Math.round(Number(ms || 0) / 1000);
  return s >= 60 ? `${Math.floor(s / 60)} phút ${s % 60} giây` : `${s} giây`;
}
// Sản phẩm nổi bật trong phiên: bán nhiều, rồi thêm giỏ, rồi click. Lỗi ở đây không làm hỏng số liệu phiên.
async function getLiveTopItems(env, cfg, sessionId, limit = 10) {
  try {
    const data = unwrapShopeeResponse(await shopeeGetByUser(env, "/api/v2/livestream/get_session_item_metric", { session_id: sessionId, offset: 0, page_size: 50 }, cfg));
    return (data.list || []).map(x => ({
      item_id: String(x.item?.item_id || ""), name: String(x.item?.name || ""), image_url: String(x.item?.image_url || ""),
      price: Number(x.item?.price?.current_price || 0), clicks: Number(x.metric?.item_clicks || 0), atc: Number(x.metric?.atc || 0), sold: Number(x.metric?.sold_items || 0)
    })).sort((a, b) => b.sold - a.sold || b.atc - a.atc || b.clicks - a.clicks).slice(0, limit);
  } catch (e) { console.warn("Không lấy được sản phẩm của phiên", sessionId, e.message); return null; }
}
function normalizeLiveSessionMetrics(rawMetric, rawDetail, channel, cfg, liveId, timeFrom, timeTo) {
  const metric = unwrapShopeeResponse(rawMetric), detail = unwrapShopeeResponse(rawDetail);
  const gmv = numberOrNull(metric,["gmv","GMV","revenue","sales","total_gmv","total_amount"]);
  const orders = numberOrNull(metric,["orders","order_count","total_orders","orderCnt","order_num"]);
  const view = numberOrNull(metric,["view","views","viewer","viewers","total_views","pv"]);
  const atc = numberOrNull(metric,["atc","add_to_cart","addToCart","cart_count"]);
  const comments = numberOrNull(metric,["comments","comment","comment_count","chat_count"]);
  const likes = numberOrNull(metric,["likes","like","like_count"]), shares = numberOrNull(metric,["shares","share","share_count"]);
  const ccu = numberOrNull(metric,["ccu"]), peakCcu = numberOrNull(metric,["peak_ccu","peakCcu","pcu"]), engageCcu1m = numberOrNull(metric,["engage_ccu_1m","engageCcu1m"]);
  const coins = numberOrNull(metric,["coins","coin","coin_spent","coins_spent"]), ctr = stringOrEmpty(metric,["ctr","CTR","click_through_rate"]), co = stringOrEmpty(metric,["co","CO","conversion_rate","conversion"]);
  // Shopee trả avg_viewing_duration theo mili-giây (phiên 43 phút trả 28260 ≈ 28 giây).
  const avgWatchMs = numberOrNull(metric,["avg_viewing_duration"]);
  const avgWatch = avgWatchMs !== null ? formatWatchDuration(avgWatchMs) : stringOrEmpty(metric,["avgWatch","avg_watch","average_watch_time","avg_view_duration"]);
  const apiAov = numberOrNull(metric,["aov","AOV"]), aov = apiAov !== null ? apiAov : (gmv !== null && orders > 0 ? Math.round(gmv/orders) : null);
  const commerceAvailable = gmv !== null || orders !== null;
  const engagementAvailable = [view,comments,likes,shares,ccu,peakCcu].some(v=>v!==null);
  return {
    source:"shopee_get_session_metric", dataMode:"live_session_metric", channel, shop_id:Number(cfg.shop_id||0), user_id:String(cfg.user_id||""),
    live_id:String(liveId), session_id:String(liveId), session_status:firstNonEmpty(detail.status,detail.session_status,detail.live_status),
    time_from:timeFrom, time_to:timeTo, gmv:gmv===null?null:Math.round(gmv), orders:orders===null?null:Math.round(orders), coins:coins===null?null:Math.round(coins),
    view:view===null?null:Math.round(view), ctr, co, aov:aov===null?null:Math.round(aov), atc:atc===null?null:Math.round(atc), comments:comments===null?null:Math.round(comments),
    likes:likes===null?null:Math.round(likes), shares:shares===null?null:Math.round(shares), ccu:ccu===null?null:Math.round(ccu), peak_ccu:peakCcu===null?null:Math.round(peakCcu), peakCcu:peakCcu===null?null:Math.round(peakCcu),
    engage_ccu_1m:engageCcu1m===null?null:Math.round(engageCcu1m), engageCcu1m:engageCcu1m===null?null:Math.round(engageCcu1m), avgWatch, avgWatchMs,
    commerceMetricsAvailable:commerceAvailable, engagementMetricsAvailable:engagementAvailable, currency:firstNonEmpty(metric.currency,detail.currency),
    title:String(detail.title||""), liveStartTs:Number(detail.start_time||0), liveEndTs:Number(detail.end_time||0),
    rawMetric:metric, rawDetail:safeLiveDetail(detail), syncedAt:nowTextVN(), syncedAtTs:Date.now(), lastError:"", lastAttemptError:"",
    note:commerceAvailable ? "Dữ liệu lấy từ Shopee Livestream API theo đúng session_id." : "Shopee Livestream API đã trả dữ liệu phiên nhưng không có trường GMV/đơn trong response này."
  };
}
async function getShopeeLiveSessionMetrics(env, channel, cfg, liveId, timeFrom, timeTo) {
  const sessionId = String(liveId || "").trim();
  if (!/^\d+$/.test(sessionId)) throw new Error("Live ID không hợp lệ; session_id phải là dãy số.");
  const detail = await shopeeGetByUser(env, String(env.SHOPEE_LIVE_DETAIL_PATH || DEFAULT_LIVE_DETAIL_PATH).trim(), {session_id:sessionId}, cfg);
  const dId = returnedSessionId(detail); if (dId && dId !== sessionId) throw new Error(`Shopee trả chi tiết phiên ${dId}, không khớp Live ID ${sessionId}.`);
  const metric = await shopeeGetByUser(env, String(env.SHOPEE_LIVE_METRIC_PATH || DEFAULT_LIVE_METRIC_PATH).trim(), {session_id:sessionId}, cfg);
  const mId = returnedSessionId(metric); if (mId && mId !== sessionId) throw new Error(`Shopee trả metric phiên ${mId}, không khớp Live ID ${sessionId}.`);
  const result = normalizeLiveSessionMetrics(metric, detail, channel, cfg, sessionId, timeFrom, timeTo);
  const items = await getLiveTopItems(env, cfg, sessionId);
  if (items) result.items = items;
  return result;
}
// V40.3: đọc mã phiên từ mọi dạng link live (Creator Center, link chia sẻ của app, link rút gọn shp.ee) hoặc mã số.
function parseLiveSessionId(text) {
  const value = String(text || "").trim();
  if (/^\d+$/.test(value)) return value;
  const m = value.match(/\/live\/(\d+)/i) || value.match(/[?&](?:session|session_id|sessionId|live_id|liveId)=(\d+)/i);
  if (m) return m[1];
  try { const u = new URL(value); if (/live\.shopee/i.test(u.host) && /^\d+$/.test(u.searchParams.get("id") || "")) return u.searchParams.get("id"); } catch (_) {}
  return "";
}
async function resolveLiveSessionId(input) {
  let text = String(input || "").trim();
  for (let i = 0; i < 3 && /^https?:\/\/(shp\.ee|s\.shopee\.vn)\//i.test(text); i++) {
    const res = await fetch(text, { redirect: "manual" });
    const location = res.headers.get("location");
    if (!location) break;
    text = new URL(location, text).toString();
  }
  return parseLiveSessionId(text);
}
// Chỉ Admin: thử lấy số liệu một phiên live bất kỳ, không ghi gì vào ca. Không truyền channel thì thử lần lượt các shop đã kết nối.
async function handleProbeSession(req, env) {
  await requireAdmin(req, env);
  const u = new URL(req.url);
  const input = u.searchParams.get("live") || "";
  const sessionId = await resolveLiveSessionId(input);
  if (!sessionId) return json({ ok: false, error: "Không đọc được mã phiên live từ link", input }, 400, req, env);
  const { connections } = await readShopeeConnectionsRaw(env);
  const wanted = String(u.searchParams.get("channel") || "").trim();
  const attempts = [];
  for (const channel of wanted ? [wanted] : Object.keys(connections)) {
    try {
      const cfg = await getShopConfig(env, channel);
      const now = Math.floor(Date.now() / 1000);
      const metrics = await getShopeeLiveSessionMetrics(env, channel, cfg, sessionId, now - 3600, now);
      return json({ ok: true, channel, session_id: sessionId, metrics, attempts }, 200, req, env);
    } catch (e) { attempts.push({ channel, error: e.message }); }
  }
  return json({ ok: false, session_id: sessionId, error: "Không shop nào lấy được số liệu phiên này", attempts }, 200, req, env);
}
async function getShopeeLiveReport(env, channel, timeFrom, timeTo, liveId) {
  if (!channel) throw new Error("Thiếu channel"); if (!liveId) throw new Error("Ca live chưa có Live ID");
  if (!timeFrom || !timeTo || timeTo <= timeFrom) throw new Error("time_from/time_to không hợp lệ");
  try {
    const cfg = await getShopConfig(env, channel);
    const result = await getShopeeLiveSessionMetrics(env, channel, cfg, liveId, timeFrom, timeTo);
    await markConnectionSync(env, channel, { lastSyncAt:nowTextVN(), lastSyncAtTs:Date.now(), lastSyncGmv:result.gmv, lastSyncOrders:result.orders, lastSyncLiveId:String(liveId), lastSyncTimeFrom:timeFrom, lastSyncTimeTo:timeTo, lastError:"", status:"connected" });
    return result;
  } catch (e) {
    await markConnectionSync(env, channel, { lastError:e.message, lastErrorAt:nowTextVN(), status:"connected" }); throw e;
  }
}

function vnDateTimeToSeconds(date,time){ if(!date||!time)return 0; const ms=Date.parse(`${date}T${time}:00+07:00`); return Number.isFinite(ms)?Math.floor(ms/1000):0; }
function shiftLifecycle(shift){
  const hostStarted=!!shift?.host?.checkinTs;
  const supportStarted=!!(shift?.supportId && shift?.support?.checkinTs);
  const hostLive=!!(hostStarted && !shift?.host?.endTs);
  const supportLive=!!(supportStarted && !shift?.support?.endTs);
  const endTs=Math.max(Number(shift?.host?.endTs||0),Number(shift?.support?.endTs||0));
  return {anyStarted:hostStarted||supportStarted,anyLive:hostLive||supportLive,endTs};
}
function shiftWindowSeconds(shift){
  const scheduledFrom=vnDateTimeToSeconds(shift.date,shift.start);
  let scheduledTo=vnDateTimeToSeconds(shift.date,shift.end);
  if(scheduledTo&&scheduledFrom&&scheduledTo<=scheduledFrom)scheduledTo+=24*60*60;
  const starts=[shift.host?.checkinTs,shift.support?.checkinTs].filter(Boolean).map(v=>Math.floor(Number(v)/1000));
  const ends=[shift.host?.endTs,shift.support?.endTs].filter(Boolean).map(v=>Math.floor(Number(v)/1000));
  const lifecycle=shiftLifecycle(shift), now=Math.floor(Date.now()/1000);
  const timeFrom=starts.length?Math.min(...starts):scheduledFrom;
  const timeTo=lifecycle.anyLive?now:(ends.length?Math.max(...ends):scheduledTo);
  return {time_from:timeFrom,time_to:timeTo};
}
function hasMatchingSnapshot(shift){
  const m=shift?.shopeeLiveMetrics, expected=String(shift?.shopeeLiveId||""), stored=String(m?.live_id||m?.session_id||"");
  return Boolean(m&&expected&&stored===expected&&m.syncedAtTs&&m.capturedWhileLive===true);
}
function liveMetricsForStorage(data,shift,window){
  return { ...data, dataMode:"live_session_metric", channel:shift.shop, live_id:String(data.live_id||shift.shopeeLiveId||""), session_id:String(data.session_id||shift.shopeeLiveId||""),
    capturedWhileLive:true, finalized:false, finalizedAt:"", finalizedAtTs:0, time_from:window.time_from, time_to:window.time_to, syncedAt:nowTextVN(), syncedAtTs:Date.now(), lastError:"", lastAttemptError:"" };
}
function workerStateForShift(shift){
  const lifecycle=shiftLifecycle(shift);
  if (!shift?.shopeeLiveId || !lifecycle.anyStarted) return "idle";
  if (lifecycle.anyLive) return "active";
  if (hasMatchingSnapshot(shift) && !shift.shopeeLiveMetrics?.finalized) return "finalize_pending";
  return "done";
}

async function readShiftById(env, shiftId) {
  const raw = await readFirestoreDocRaw(env, shiftDocPath(env, shiftId));
  if (raw?.data?.shift) return { mode:"sharded", shift:raw.data.shift, updateTime:raw.updateTime, doc:raw.data };
  // Legacy fallback during migration.
  const main = await readFirestoreDocRaw(env, dashboardDocPath(env));
  const legacy = (main?.data?.data?.shifts || []).find(s => String(s.id||"") === String(shiftId));
  return legacy ? { mode:"legacy", shift:legacy, updateTime:main.updateTime, mainData:main.data.data } : null;
}

async function casPatchShiftMetrics(env, shiftId, mutator) {
  for (let attempt=0; attempt<MAX_CAS_RETRIES; attempt++) {
    const current = await readShiftById(env, shiftId);
    if (!current) throw new Error("Không tìm thấy ca live");
    if (current.mode === "legacy") {
      // Legacy is only a bridge. Use CAS on the whole legacy data until dashboard migrates.
      const nextDb = clone(current.mainData);
      const s = (nextDb.shifts||[]).find(x=>String(x.id||"")===String(shiftId));
      const result = await mutator(s);
      try {
        await patchFirestoreFields(env, dashboardDocPath(env), { data:nextDb, updatedAtText:nowTextVN(), updatedBy:"Shopee Live Worker V38" }, current.updateTime);
        return { shift:s, result, mode:"legacy" };
      } catch(e){ if(e.status===409||e.status===412) continue; throw e; }
    }
    const shift = clone(current.shift);
    const result = await mutator(shift);
    const state = workerStateForShift(shift);
    const fields = {
      "shift.shopeeLiveMetrics": shift.shopeeLiveMetrics || {},
      workerState: state,
      hostCheckinTs: Number(shift.host?.checkinTs||0),
      hostEndTs: Number(shift.host?.endTs||0),
      supportCheckinTs: Number(shift.support?.checkinTs||0),
      supportEndTs: Number(shift.support?.endTs||0),
      liveId: String(shift.shopeeLiveId||""),
      shop: String(shift.shop||""),
      date: String(shift.date||""),
      updatedAtText: nowTextVN(),
      updatedBy: "Shopee Live Worker V38"
    };
    try {
      await patchFirestoreFields(env, shiftDocPath(env, shiftId), fields, current.updateTime);
      return { shift, result, mode:"sharded" };
    } catch(e){ if(e.status===409||e.status===412) continue; throw e; }
  }
  throw new Error(`Ca ${shiftId} thay đổi liên tục; Worker không ghi đè dữ liệu mới hơn`);
}

async function syncOneActiveShift(env, shiftId) {
  const initial = await readShiftById(env, shiftId);
  if (!initial) throw new Error("Không tìm thấy ca live");
  const initialShift = initial.shift;
  const initialLifecycle=shiftLifecycle(initialShift);
  if (!initialShift?.shop || !initialShift?.shopeeLiveId || !initialLifecycle.anyLive) {
    return { shift: initialShift, result:{skipped:true,reason:"Ca không còn active"} };
  }
  const initialLiveId=String(initialShift.shopeeLiveId||"");
  const window = shiftWindowSeconds(initialShift);
  if (!window.time_from || !window.time_to || window.time_to <= window.time_from) {
    return { shift: initialShift, result:{skipped:true,reason:"Khung giờ không hợp lệ"} };
  }
  try {
    // Network I/O happens before the CAS mutation. If the employee ends the shift
    // while Shopee is replying, the successful snapshot is still preserved and
    // finalized atomically on the current shift document instead of being lost.
    const data = await getShopeeLiveReport(env, initialShift.shop, window.time_from, window.time_to, initialLiveId);
    return casPatchShiftMetrics(env, shiftId, async shift => {
      if(String(shift?.shopeeLiveId||"")!==initialLiveId) return {skipped:true,reason:"Live ID đã đổi trong lúc đồng bộ"};
      let metrics=liveMetricsForStorage(data, shift, window);
      let finalizedDuringSync=false;
      const lifecycle=shiftLifecycle(shift);
      if(!lifecycle.anyLive && lifecycle.endTs){
        metrics={...metrics,finalized:true,finalizedAt:nowTextVN(),finalizedAtTs:Date.now(),dashboardEndTs:lifecycle.endTs,note:"Snapshot lấy thành công ngay trước/khi toàn bộ ca được kết thúc; đã khóa atomically bởi Worker V38.1."};
        finalizedDuringSync=true;
      }
      shift.shopeeLiveMetrics = metrics;
      return {changed:true,finalizedDuringSync,gmv:metrics.gmv,orders:metrics.orders};
    });
  } catch(e) {
    // Do not erase the previous good snapshot on an API failure.
    return casPatchShiftMetrics(env, shiftId, async shift => {
      if(String(shift?.shopeeLiveId||"")!==initialLiveId) return {skipped:true,reason:"Live ID đã đổi trong lúc đồng bộ"};
      if (hasMatchingSnapshot(shift)) {
        shift.shopeeLiveMetrics = { ...shift.shopeeLiveMetrics, lastAttemptError:e.message, lastAttemptAt:nowTextVN(), lastAttemptAtTs:Date.now() };
      } else {
        shift.shopeeLiveMetrics = { source:"shopee_get_session_metric", dataMode:"live_session_metric", channel:shift.shop, live_id:String(shift.shopeeLiveId||""), session_id:String(shift.shopeeLiveId||""), lastError:e.message, lastAttemptError:e.message, syncedAt:nowTextVN(), syncedAtTs:Date.now(), capturedWhileLive:false, finalized:false };
      }
      return {failed:true,error:e.message};
    });
  }
}

async function finalizeOneShift(env, shiftId) {
  return casPatchShiftMetrics(env, shiftId, async shift => {
    const lifecycle=shiftLifecycle(shift);
    if (!lifecycle.anyStarted || lifecycle.anyLive || !lifecycle.endTs || !hasMatchingSnapshot(shift) || shift.shopeeLiveMetrics?.finalized) return {skipped:true,reason:"Không cần finalize"};
    shift.shopeeLiveMetrics = { ...shift.shopeeLiveMetrics, finalized:true, finalizedAt:nowTextVN(), finalizedAtTs:Date.now(), dashboardEndTs:lifecycle.endTs, lastError:"", note:"Snapshot cuối lấy thành công khi phiên còn live; đã khóa khi toàn bộ ca kết thúc." };
    return {finalized:true,gmv:shift.shopeeLiveMetrics.gmv,orders:shift.shopeeLiveMetrics.orders};
  });
}

async function autoSyncAll(env) {
  let checked=0, changed=0, finalized=0, failed=0;
  let activeDocs = [], finalizeDocs = [];
  try {
    activeDocs = await runCollectionQuery(env, shiftCollection(env), "workerState", "active", 200);
    finalizeDocs = await runCollectionQuery(env, shiftCollection(env), "workerState", "finalize_pending", 200);
  } catch(e) { console.warn("Không query được shift collection", e.message); }

  // Legacy fallback until V38 dashboard migration is completed.
  if (!activeDocs.length && !finalizeDocs.length) {
    const main = await readFirestoreDocRaw(env, dashboardDocPath(env));
    const legacyShifts = main?.data?.data?.shifts || [];
    for (const s of legacyShifts) {
      const state = workerStateForShift(s);
      if (state === "active") activeDocs.push({data:{shift:s}});
      if (state === "finalize_pending") finalizeDocs.push({data:{shift:s}});
    }
  }

  for (const doc of activeDocs) {
    const id = String(doc.data?.shift?.id || ""); if(!id) continue; checked++;
    try {
      const r = await syncOneActiveShift(env,id); const x=r.result||{};
      if(x.changed) changed++; if(x.finalizedDuringSync) finalized++; if(x.failed) failed++;
      await appendWorkerLog(env,{action:x.failed?"Lỗi cập nhật snapshot khi đang live":"Cập nhật snapshot đúng phiên khi đang live",details:{shiftId:id,channel:r.shift.shop,liveId:String(r.shift.shopeeLiveId||""),gmv:r.shift.shopeeLiveMetrics?.gmv,orders:r.shift.shopeeLiveMetrics?.orders,error:x.error||""}});
    } catch(e){ failed++; await appendWorkerLog(env,{action:"Lỗi Worker cập nhật ca",details:{shiftId:id,error:e.message}}); }
  }
  for (const doc of finalizeDocs) {
    const id = String(doc.data?.shift?.id || ""); if(!id) continue;
    try {
      const r=await finalizeOneShift(env,id); if(r.result?.finalized) finalized++;
      await appendWorkerLog(env,{action:"Chốt snapshot Shopee khi kết thúc ca",details:{shiftId:id,channel:r.shift.shop,liveId:String(r.shift.shopeeLiveId||""),gmv:r.shift.shopeeLiveMetrics?.gmv,orders:r.shift.shopeeLiveMetrics?.orders}});
    } catch(e){ failed++; await appendWorkerLog(env,{action:"Lỗi chốt snapshot",details:{shiftId:id,error:e.message}}); }
  }
  const summary=`${checked} ca đang live kiểm tra · ${changed} thay đổi · ${finalized} ca chốt · ${failed} lỗi`;
  await patchDashboardSettings(env,{shopeeLastWorkerSyncAt:nowTextVN(),shopeeLastWorkerSyncAtTs:Date.now(),shopeeLastWorkerSyncSummary:summary,shopeeSyncMode:"v38_sharded_live_snapshot_then_finalize",storageMode:"v38_sharded"});
  return {ok:true,version:WORKER_VERSION,checked,changed,finalized,failed,time:nowTextVN(),summary};
}

async function handleLiveReport(req, env) {
  const u=new URL(req.url), shiftId=String(u.searchParams.get("shift_id")||"").trim(), requestedChannel=String(u.searchParams.get("channel")||"").trim(), requestedLiveId=String(u.searchParams.get("live_id")||"").trim();
  if(!shiftId) return json({ok:false,error:"Thiếu shift_id"},400,req,env);
  const found=await readShiftById(env,shiftId); if(!found) return json({ok:false,error:"Không tìm thấy ca live"},404,req,env);
  const shift=found.shift; const lifecycle=shiftLifecycle(shift); if(!lifecycle.anyStarted) return json({ok:false,error:"Ca chưa có người check-in"},409,req,env);
  const channel=String(shift.shop||"").trim(), liveId=String(shift.shopeeLiveId||"").trim();
  if(!channel) return json({ok:false,error:"Ca chưa chọn kênh bán"},400,req,env); if(!liveId) return json({ok:false,error:"Ca chưa có Live ID"},400,req,env);
  if(requestedChannel&&requestedChannel.toLowerCase()!==channel.toLowerCase()) return json({ok:false,error:"Kênh gửi lên không khớp ca"},409,req,env);
  if(requestedLiveId&&requestedLiveId!==liveId) return json({ok:false,error:"Live ID gửi lên không khớp ca"},409,req,env);
  if(!lifecycle.anyLive){
    if(!hasMatchingSnapshot(shift)||!shift.shopeeLiveMetrics?.capturedWhileLive) return json({ok:false,error:"Ca đã kết thúc nhưng chưa có snapshot lấy thành công khi phiên còn live. Shopee không cho get_session_metric sau khi phiên kết thúc."},409,req,env);
    const r=await finalizeOneShift(env,shiftId); return json({ok:true,shift_id:shiftId,fromStoredSnapshot:true,...r.shift.shopeeLiveMetrics},200,req,env);
  }
  const window=shiftWindowSeconds(shift), result=await getShopeeLiveReport(env,channel,window.time_from,window.time_to,liveId);
  // Persist immediately so dashboard/client failure cannot lose the snapshot. If the
  // host ends the dashboard shift while this request is in flight, keep the successful
  // result and finalize it in the same CAS write.
  const persisted=await casPatchShiftMetrics(env,shiftId,async latest=>{
    if(String(latest.shopeeLiveId||"")!==liveId) return {skipped:true};
    let metrics=liveMetricsForStorage(result,latest,window);
    const latestLifecycle=shiftLifecycle(latest);
    if(!latestLifecycle.anyLive && latestLifecycle.endTs){
      metrics={...metrics,finalized:true,finalizedAt:nowTextVN(),finalizedAtTs:Date.now(),dashboardEndTs:latestLifecycle.endTs,note:"Snapshot lấy thành công trong request đang chạy khi toàn bộ ca kết thúc; đã khóa atomically bởi Worker V38.1."};
    }
    latest.shopeeLiveMetrics=metrics;
    return {saved:true};
  });
  return json({ok:true,shift_id:shiftId,...result,capturedWhileLive:true,finalized:Boolean(persisted.shift?.shopeeLiveMetrics?.finalized)},200,req,env);
}
async function handleConnections(req,env){ await requireAdmin(req,env); const {connections}=await readShopeeConnectionsRaw(env); await updateDashboardConnectionStatus(env,connections); return json({ok:true,connections:sanitizeConnections(connections)},200,req,env); }
async function handleDisconnect(req,env){ if(req.method!=="POST")return json({ok:false,error:"Method not allowed"},405,req,env); await requireAdmin(req,env); const channel=String(new URL(req.url).searchParams.get("channel")||"").trim(); if(!channel)throw new Error("Thiếu channel"); const next=await mutateConnections(env,c=>{delete c[channel];}); await updateDashboardConnectionStatus(env,next); return json({ok:true,connections:sanitizeConnections(next)},200,req,env); }
async function handleAutoSyncAll(req,env){ if(!["GET","POST"].includes(req.method))return json({error:"Method not allowed"},405,req,env); await requireAdmin(req,env); return json(await autoSyncAll(env),200,req,env); }

export default {
  async fetch(req,env){
    if(req.method==="OPTIONS") return json({ok:true},200,req,env);
    const path=new URL(req.url).pathname;
    try{
      // "return await" để lỗi bất đồng bộ rơi vào catch bên dưới (trả JSON có CORS thay vì lỗi 1101 của Cloudflare).
      if(path==="/api/shopee/connect")return await handleConnect(req,env);
      if(path==="/api/shopee/callback")return await handleCallback(req,env);
      if(path==="/api/shopee/connections")return await handleConnections(req,env);
      if(path==="/api/shopee/disconnect")return await handleDisconnect(req,env);
      if(path==="/api/shopee/live-report"){ await requireLogin(req,env); return await handleLiveReport(req,env); }
      if(path==="/api/shopee/auto-sync-all")return await handleAutoSyncAll(req,env);
      if(path==="/api/shopee/probe-session")return await handleProbeSession(req,env);
      if(path==="/api/shopee/all-channel-data")return json({ok:false,error:"Endpoint toàn shop đã tắt. Worker chỉ lấy snapshot đúng Live ID khi phiên đang live."},410,req,env);
      if(path==="/api/debug/version")return json({ok:true,version:WORKER_VERSION,mode:"v38_sharded_live_snapshot_then_finalize",shiftCollection:shiftCollection(env)},200,req,env);
      return json({ok:true,version:WORKER_VERSION,mode:"v38_sharded_live_snapshot_then_finalize",message:"V38: mỗi ca live là một Firestore document; Worker CAS-safe và chỉ cập nhật đúng ca/Live ID.",endpoints:["/api/shopee/connect","/api/shopee/connections","/api/shopee/live-report","/api/shopee/auto-sync-all","/api/debug/version"]},200,req,env);
    }catch(e){ if(!(Number(e.status)>=400&&Number(e.status)<500)) console.error(e); return json({ok:false,error:e.message||"Worker error",version:WORKER_VERSION},Number(e.status)>=400&&Number(e.status)<600?Number(e.status):500,req,env); }
  },
  async scheduled(_controller,env,ctx){ ctx.waitUntil(autoSyncAll(env)); }
};
