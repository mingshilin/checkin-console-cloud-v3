/* eslint-disable no-await-in-loop */

const SITE_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const SESSION_TTL_HOURS = 24 * 7;
const LOGIN_CHALLENGE_TTL_MIN = 5;
const DEFAULT_2FA_CODE = "123456";
const API_TIMEOUT_MS = 12000;
const PROBE_REQUEST_BUDGET = 8;
const RETRY_POLICY_DEFAULT = Object.freeze({
  max_attempts: 4,
  base_delay_s: 2,
  multiplier: 2,
  max_delay_s: 60,
  jitter_ratio: 0.2,
  timeout_ms: 12000,
});
const ALERT_POLICY_DEFAULT = Object.freeze({
  preset: "balanced",
  daily_cost: 20,
  daily_tokens: 2_000_000,
  failure_rate_15m: 0.25,
  failure_rate_15m_min_samples: 20,
  consecutive_failures: 3,
});
const RETRYABLE_STATUS_CODES = new Set([408, 409, 425, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524]);
const NON_RETRYABLE_STATUS_CODES = new Set([400, 401, 403, 404, 422]);
let schemaEnsurePromise = null;

function nowIso() {
  return new Date().toISOString();
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...headers,
    },
  });
}

function ok(item = {}, status = 200) {
  return json({ ok: true, item }, status);
}

function fail(message, status = 400, extra = {}) {
  return json({ ok: false, message, ...extra }, status);
}

function withTimeout(promise, ms, code, message) {
  let timer = null;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const err = new Error(message || "operation timeout");
      err.code = code || "timeout";
      reject(err);
    }, ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

async function parseBody(request) {
  if (!request.body) return {};
  try {
    return await request.json();
  } catch (_) {
    throw new Error("JSON 格式错误");
  }
}

function parseCookie(raw) {
  const out = {};
  String(raw || "")
    .split(";")
    .map((x) => x.trim())
    .filter(Boolean)
    .forEach((part) => {
      const idx = part.indexOf("=");
      if (idx > 0) {
        const k = decodeURIComponent(part.slice(0, idx));
        const v = decodeURIComponent(part.slice(idx + 1));
        out[k] = v;
      }
    });
  return out;
}

function randomId() {
  return crypto.randomUUID().replace(/-/g, "");
}

function randString(len = 24) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return Array.from(arr)
    .map((x) => (x % 36).toString(36))
    .join("");
}

function normalizeBaseUrl(raw) {
  const value = String(raw || "").trim();
  if (!value) throw new Error("站点地址不能为空");
  const fixed = value.startsWith("http://") || value.startsWith("https://") ? value : `https://${value}`;
  const u = new URL(fixed);
  return `${u.protocol}//${u.host}`;
}

function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch (_) {
    return "";
  }
}

function detectSiteShellType(site, profile = null) {
  const host = hostOf(site?.base_url || "");
  const meta = profile?.probe_meta || {};
  const saved = String(meta?.shell_detection?.shell_type || "").trim();
  if (saved) return saved;
  if (host.includes("lamclod")) return "oidc_console";
  if (host.includes("gettoken")) return "marketing_console";
  return "";
}

function isAuthShellFamily(site, profile = null) {
  return resolveSiteFamily(site, profile) === "auth_shell";
}

function isProbeBudgetErrorMessage(message = "") {
  return /too many subrequests|probe budget exhausted/i.test(String(message || ""));
}

function extractHtmlTitle(html = "") {
  const match = String(html || "").match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return match ? match[1].replace(/\s+/g, " ").trim() : "";
}

function extractCanonicalHref(html = "") {
  const match = String(html || "").match(/<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']+)["']/i);
  return match ? String(match[1] || "").trim() : "";
}

function extractConsoleEntrypoints(html = "") {
  const matches = String(html || "").match(/href=["']([^"']*(?:\/console|\/dashboard|\/login)[^"']*)["']/gi) || [];
  return Array.from(
    new Set(
      matches
        .map((item) => {
          const hit = item.match(/href=["']([^"']+)["']/i);
          return hit ? String(hit[1] || "").trim() : "";
        })
        .filter(Boolean)
    )
  ).slice(0, 12);
}

function buildCredentialMaterials(site) {
  const creds = site?.credentials || {};
  return [
    { key: "token", present: Boolean(String(creds.token || creds.auth_token || creds.access_token || "").trim()) },
    { key: "refresh_token", present: Boolean(String(creds.refresh_token || "").trim()) },
    { key: "cookie", present: Boolean(String(creds.cookie || "").trim()) },
    { key: "new_api_user", present: Boolean(String(creds.new_api_user || "").trim()) },
    { key: "token_expires_at", present: Boolean(String(creds.token_expires_at || "").trim()) },
  ].filter((item) => item.present);
}

function inferRepairMode(site, profile = null) {
  const supportStatus = inferSupportStatus(site, profile);
  const shellType = detectSiteShellType(site, profile);
  const authState = describeAuthState(site, profile ? { capabilities: profile.capabilities || {}, probe_errors: profile.probe_errors || [] } : null);
  if (shellType === "oidc_console") return "edge_bridge";
  if (authState.status === "expired" || supportStatus === "supported_but_auth_expired") return "auto_refresh";
  if (authState.status === "auth_warning") return "browser_challenge";
  if (shellType) return "edge_bridge";
  return "unsupported";
}

function buildRepairSteps(site, profile = null) {
  const shellType = detectSiteShellType(site, profile);
  const authState = describeAuthState(site, profile ? { capabilities: profile.capabilities || {}, probe_errors: profile.probe_errors || [] } : null);
  const supportStatus = inferSupportStatus(site, profile);
  if (shellType === "oidc_console") {
    return [
      { code: "open-edge", title: "在 Edge 中打开站点", detail: `打开 ${site.base_url} 并保持标签页打开`, status: "todo" },
      { code: "finish-oidc", title: "完成授权回跳", detail: "确认已从授权页跳回业务站点首页或控制台，而不是停留在 authorize 页面", status: "todo" },
      { code: "extract-session", title: "重新提取登录态", detail: "返回控制台点击修复登录态，复用 Edge 中当前标签页的 cookie/token/session", status: "todo" },
      { code: "light-verify", title: "执行轻量验证", detail: "提取成功后立即验证身份、额度和模型首探，不再直接全量探测", status: "todo" },
    ];
  }
  if (shellType === "marketing_console") {
    return [
      { code: "open-console", title: "在 Edge 中打开控制台入口", detail: "确认不是停留在营销首页，而是已经进入实际控制台或登录弹层完成态", status: "todo" },
      { code: "keep-tab", title: "保持已登录标签页打开", detail: "不要关闭已登录的站点标签页，桥接提取会优先读取当前会话", status: "todo" },
      { code: "extract-session", title: "重新提取站内会话", detail: "点击修复登录态，优先提取 session / cookie，再识别是否存在 API 能力", status: "todo" },
      { code: "confirm-scope", title: "确认能力范围", detail: "若仅识别到控制台会话但没有开放 API，会明确显示为“站内会话可用 / API 待验证”", status: "todo" },
    ];
  }
  if (resolveSiteFamily(site, profile) === "qingyi") {
    return [
      { code: "refresh-token", title: "优先自动刷新 token", detail: supportStatus === "supported_but_auth_expired" ? "系统会先尝试自动刷新 auth_token，再决定是否需要浏览器介入" : "当前优先检查 token 是否已过期", status: authState.status === "expired" ? "blocked" : "todo" },
      { code: "browser-challenge", title: "必要时在 Edge 完成挑战页验证", detail: "如果接口返回 HTML/挑战页，请在 Edge 打开站点并完成页面验证", status: authState.status === "auth_warning" ? "blocked" : "todo" },
      { code: "extract-again", title: "重新提取登录态", detail: "挑战页或登录状态恢复后，再点击修复登录态重新保存凭据", status: "todo" },
      { code: "verify-qingyi", title: "验证 Usage / 额度 / 模型", detail: "提取完成后立即触发 qingyi 轻量验证，避免误判为接口未开放", status: "todo" },
    ];
  }
  return [
    { code: "relogin", title: "重新确认浏览器登录态", detail: `在 Edge 中打开 ${site.base_url} 并确认已登录`, status: "todo" },
    { code: "extract", title: "重新提取 cookie/token", detail: "返回控制台点击修复登录态", status: "todo" },
    { code: "light-verify", title: "轻量验证", detail: "只做身份/额度/模型首探，避免一次性打满全部候选接口", status: "todo" },
  ];
}

function monthNow() {
  const d = new Date();
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
}

function shanghaiDateTime() {
  const now = new Date();
  const local = new Date(now.getTime() + 8 * 60 * 60 * 1000);
  const date = `${local.getUTCFullYear()}-${String(local.getUTCMonth() + 1).padStart(2, "0")}-${String(local.getUTCDate()).padStart(2, "0")}`;
  const time = `${String(local.getUTCHours()).padStart(2, "0")}:${String(local.getUTCMinutes()).padStart(2, "0")}`;
  return { date, time };
}

function maskSecret(raw, head = 6, tail = 4) {
  const s = String(raw || "").trim();
  if (!s) return "";
  if (s.length <= head + tail + 2) return s;
  return `${s.slice(0, head)}${"*".repeat(s.length - head - tail)}${s.slice(-tail)}`;
}

function likeChecked(message) {
  const t = String(message || "").toLowerCase();
  return /already|已签到|今天已签到|重复签到/.test(t);
}

function likeSuccess(message) {
  const t = String(message || "").toLowerCase();
  return /success|成功|ok|签到成功/.test(t);
}

function pickMessage(payload, fallbackText = "") {
  if (!payload) return fallbackText || "";
  if (typeof payload === "string") return payload;
  if (typeof payload === "object") {
    const errObj = payload.error && typeof payload.error === "object" ? payload.error : null;
    return String(
      payload.message ||
        payload.msg ||
        (errObj && (errObj.message || errObj.detail || errObj.type || errObj.code)) ||
        payload.error ||
        payload.detail ||
        payload.reason ||
        fallbackText ||
        ""
    );
  }
  return fallbackText || "";
}

function parseDataItems(payload) {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== "object") return [];
  const data = payload.data;
  if (Array.isArray(data)) return data;
  if (data && typeof data === "object") {
    if (Array.isArray(data.items)) return data.items;
    if (Array.isArray(data.list)) return data.list;
    if (Array.isArray(data.records)) return data.records;
    if (Array.isArray(data.rows)) return data.rows;
  }
  if (Array.isArray(payload.items)) return payload.items;
  if (Array.isArray(payload.records)) return payload.records;
  if (Array.isArray(payload.rows)) return payload.rows;
  return [];
}

function parseModelList(value) {
  if (!value) return [];
  if (Array.isArray(value)) {
    return value
      .map((x) => String(typeof x === "string" ? x : x?.id || x?.name || "").trim())
      .filter(Boolean);
  }
  if (typeof value === "string") {
    return value
      .split(/[,\n|;]+/g)
      .map((x) => x.trim())
      .filter(Boolean);
  }
  if (typeof value === "object") {
    return Object.keys(value).filter(Boolean);
  }
  return [];
}

function asObjectMap(value) {
  if (value && typeof value === "object" && !Array.isArray(value)) return value;
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return parsed;
    } catch (_) {
      return {};
    }
  }
  return {};
}

function normalizePriceEntry(raw) {
  if (raw == null) return {};
  if (typeof raw === "number") return { price: raw, model_ratio: raw };
  if (typeof raw === "string") {
    const n = toNumber(raw);
    return n == null ? { raw } : { price: n, model_ratio: n };
  }
  if (typeof raw !== "object") return {};
  return {
    price: toNumber(raw.price ?? raw.value ?? raw.ratio ?? raw.multiplier ?? raw.modelRatio),
    model_ratio: toNumber(raw.model_ratio ?? raw.modelRatio ?? raw.ratio ?? raw.multiplier ?? raw.model_multiplier),
    group_ratio: toNumber(raw.group_ratio ?? raw.groupRatio ?? raw.group_multiplier ?? raw.groupMultiplier),
    user_group_ratio: toNumber(raw.user_group_ratio ?? raw.userGroupRatio ?? raw.user_ratio ?? raw.userRatio),
    completion_ratio: toNumber(raw.completion_ratio ?? raw.completionRatio ?? raw.output_ratio ?? raw.outputRatio),
    cache_ratio: toNumber(raw.cache_ratio ?? raw.cacheRatio ?? raw.cached_ratio ?? raw.cachedRatio),
    model_price: toNumber(raw.model_price ?? raw.modelPrice ?? raw.fixed_price ?? raw.fixedPrice ?? raw.price),
    model_price_unit: String(raw.model_price_unit ?? raw.modelPriceUnit ?? raw.price_unit ?? raw.priceUnit ?? raw.unit ?? ""),
    quota_type: String(raw.quota_type ?? raw.quotaType ?? raw.type ?? ""),
    input_price: toNumber(raw.input_price ?? raw.inputPrice ?? raw.prompt_price ?? raw.promptPrice ?? raw.in_price),
    output_price: toNumber(raw.output_price ?? raw.outputPrice ?? raw.completion_price ?? raw.completionPrice ?? raw.out_price),
    cached_price: toNumber(raw.cached_price ?? raw.cachedPrice ?? raw.cache_price ?? raw.cachePrice),
    cache_read_price: toNumber(raw.cache_read_price ?? raw.cacheReadPrice ?? raw.read_cache_price ?? raw.readCachePrice),
    cache_write_price: toNumber(raw.cache_write_price ?? raw.cacheWritePrice ?? raw.write_cache_price ?? raw.writeCachePrice),
    per_request_price: toNumber(raw.per_request_price ?? raw.perRequestPrice ?? raw.request_price ?? raw.requestPrice),
    billing_mode: String(raw.billing_mode ?? raw.billingMode ?? raw.mode ?? ""),
    unit: String(raw.unit ?? ""),
    raw,
  };
}

function formatPricingText(p) {
  if (!p) return "-";
  const parts = [];
  if (p.model_ratio != null) parts.push(`模型倍率:${p.model_ratio}`);
  if (p.group_ratio != null) parts.push(`分组倍率:${p.group_ratio}`);
  if (p.user_group_ratio != null) parts.push(`用户组:${p.user_group_ratio}`);
  if (p.completion_ratio != null) parts.push(`补全:${p.completion_ratio}`);
  if (p.cache_ratio != null) parts.push(`缓存倍率:${p.cache_ratio}`);
  if (p.model_price != null) parts.push(`固定价:${p.model_price}${p.model_price_unit ? `/${p.model_price_unit}` : ""}`);
  if (p.input_price != null) parts.push(`输入:${p.input_price}`);
  if (p.output_price != null) parts.push(`输出:${p.output_price}`);
  if (p.cached_price != null) parts.push(`缓存:${p.cached_price}`);
  if (p.cache_read_price != null) parts.push(`缓存读:${p.cache_read_price}`);
  if (p.cache_write_price != null) parts.push(`缓存写:${p.cache_write_price}`);
  if (p.per_request_price != null) parts.push(`按次:${p.per_request_price}`);
  if (p.price != null) parts.push(`单价:${p.price}`);
  if (!parts.length && p.billing_mode) parts.push(`模式:${p.billing_mode}`);
  return parts.join(" | ") || "-";
}

function hasPricingValue(p = {}) {
  return [
    "price",
    "model_ratio",
    "group_ratio",
    "user_group_ratio",
    "completion_ratio",
    "cache_ratio",
    "model_price",
    "input_price",
    "output_price",
    "cached_price",
    "cache_read_price",
    "cache_write_price",
    "per_request_price",
  ].some((k) => p[k] != null);
}

function mergePricing(base = {}, next = {}) {
  const out = { ...base };
  for (const k of [
    "price",
    "model_ratio",
    "group_ratio",
    "user_group_ratio",
    "completion_ratio",
    "cache_ratio",
    "model_price",
    "model_price_unit",
    "quota_type",
    "input_price",
    "output_price",
    "cached_price",
    "cache_read_price",
    "cache_write_price",
    "per_request_price",
    "billing_mode",
    "unit",
  ]) {
    if ((out[k] == null || out[k] === "") && next[k] != null && next[k] !== "") out[k] = next[k];
  }
  out.raw = next.raw ?? base.raw;
  return out;
}

function classifyPriceSource(sourceFields = [], pricing = {}) {
  const fields = sourceFields.map((x) => String(x || ""));
  if (!hasPricingValue(pricing)) {
    if (fields.some((x) => x.includes("channel:") || x.includes("channel_mapping"))) {
      return {
        price_confidence: "mapping_only",
        price_source: "渠道映射",
        missing_price_reason: "站点接口只返回渠道/账号映射，未返回模型倍率或固定价格",
      };
    }
    return {
      price_confidence: "missing",
      price_source: "站点未开放",
      missing_price_reason: "站点未在已知模型/价格接口返回计价字段",
    };
  }
  if (fields.some((x) => x.includes("frontend-confirmed") || x.includes("channel:") || x.includes("/channels/available"))) {
    return { price_confidence: "high", price_source: "前端真实渠道定价", missing_price_reason: "" };
  }
  if (fields.some((x) => /pricing|price/i.test(x))) {
    return { price_confidence: "high", price_source: "价格接口", missing_price_reason: "" };
  }
  if (fields.some((x) => /group/i.test(x))) {
    return { price_confidence: "medium", price_source: "分组继承", missing_price_reason: "" };
  }
  return { price_confidence: "medium", price_source: "模型目录", missing_price_reason: "" };
}

function normalizeModelCatalogItems(payload) {
  const items = parseDataItems(payload);
  const rows = items
    .flatMap((x) => {
      const supportedModels = Array.isArray(x?.supported_models) ? x.supported_models : Array.isArray(x?.supportedModels) ? x.supportedModels : [];
      if (supportedModels.length) {
        const channelLabel = String(x.name || x.channel_name || x.label || x.id || x.channel_id || "channel").trim() || "channel";
        return supportedModels
          .map((model) => {
            const id = String(model.model ?? model.model_name ?? model.name ?? model.id ?? "").trim();
            if (!id || /^\d+$/.test(id)) return null;
            const pricing = mergePricing(normalizePriceEntry(model.pricing), normalizePriceEntry(model));
            return {
              id,
              name: String(model.name ?? model.model_name ?? id),
              platform: String(model.platform || model.provider || x.provider || x.platform || ""),
              pricing,
              source_fields: [
                "frontend-confirmed",
                `channel:${channelLabel}`,
                "/channels/available",
                ...Object.keys(model || {}).slice(0, 30),
              ],
            };
          })
          .filter(Boolean);
      }
      const id = String(x.model ?? x.model_name ?? x.model_name_en ?? x.name ?? x.id ?? "").trim();
      if (!id) return [];
      const idCameOnlyFromNumericId =
        /^\d+$/.test(id) &&
        x.model == null &&
        x.model_name == null &&
        x.model_name_en == null &&
        x.name == null;
      if (idCameOnlyFromNumericId) return [];
      const fieldPricing = {
        input_price: x.input_price ?? x.inputPrice ?? x.prompt_price ?? x.promptPrice,
        output_price: x.output_price ?? x.outputPrice ?? x.completion_price ?? x.completionPrice,
        cache_read_price: x.cache_read_price ?? x.cacheReadPrice,
        cache_write_price: x.cache_write_price ?? x.cacheWritePrice,
        per_request_price: x.per_request_price ?? x.perRequestPrice,
        price: x.price ?? x.ratio,
        model_ratio: x.model_ratio ?? x.modelRatio ?? x.ratio,
        group_ratio: x.group_ratio ?? x.groupRatio,
        user_group_ratio: x.user_group_ratio ?? x.userGroupRatio,
        completion_ratio: x.completion_ratio ?? x.completionRatio,
        cache_ratio: x.cache_ratio ?? x.cacheRatio,
        model_price: x.model_price ?? x.modelPrice ?? x.fixed_price ?? x.fixedPrice,
        model_price_unit: x.model_price_unit ?? x.modelPriceUnit ?? x.price_unit ?? x.priceUnit,
        quota_type: x.quota_type ?? x.quotaType,
        billing_mode: x.billing_mode ?? x.billingMode ?? x.mode,
        unit: x.unit,
      };
      const pricing = mergePricing(normalizePriceEntry(x.pricing), normalizePriceEntry(fieldPricing));
      return {
        id,
        name: String(x.name ?? x.model_name ?? x.model_name_en ?? id),
        platform: String(x.platform || x.provider || ""),
        pricing,
        source_fields: Object.keys(x || {}).slice(0, 40),
      };
    })
    .filter(Boolean);

  if (rows.length) return rows;

  const base = (payload && (payload.data || payload)) || {};
  if (!base || typeof base !== "object" || Array.isArray(base)) return [];

  const mappedModelLists = Object.entries(base)
    .filter(([k, v]) => k && !["success", "message", "code"].includes(k) && Array.isArray(v))
    .map(([k, v]) => ({ source: k, models: parseModelList(v) }))
    .filter((x) => x.models.length);
  if (mappedModelLists.length) {
    const modelSources = new Map();
    for (const row of mappedModelLists) {
      for (const model of row.models) {
        if (!modelSources.has(model)) modelSources.set(model, []);
        modelSources.get(model).push(row.source);
      }
    }
    return Array.from(modelSources.entries()).map(([model, sources]) => ({
      id: model,
      name: model,
      pricing: {
        quota_type: "channel_mapping",
        raw: { sources: sources.slice(0, 12) },
      },
      source_fields: sources.slice(0, 12).map((x) => `channel:${x}`),
    }));
  }

  const ratioMap = asObjectMap(base.model_ratio ?? base.ratio ?? base.modelRatio ?? {});
  const priceMap = asObjectMap(base.model_price ?? base.model_prices ?? base.pricing ?? base.price ?? {});
  const groupRatioMap = asObjectMap(base.group_ratio ?? base.groupRatio ?? base.group_ratios ?? {});
  const userGroupRatioMap = asObjectMap(base.user_group_ratio ?? base.userGroupRatio ?? {});
  const completionRatioMap = asObjectMap(base.completion_ratio ?? base.completionRatio ?? base.completion_ratios ?? {});
  const cacheRatioMap = asObjectMap(base.cache_ratio ?? base.cacheRatio ?? base.cache_ratios ?? {});
  const fixedPriceMap = asObjectMap(base.fixed_price ?? base.fixedPrice ?? {});
  const modelSet = new Set([
    ...Object.keys(ratioMap),
    ...Object.keys(priceMap),
    ...Object.keys(groupRatioMap),
    ...Object.keys(userGroupRatioMap),
    ...Object.keys(completionRatioMap),
    ...Object.keys(cacheRatioMap),
    ...Object.keys(fixedPriceMap),
  ]);
  if (!modelSet.size) {
    Object.keys(base).forEach((k) => {
      if (!k || ["success", "message", "code"].includes(k)) return;
      const v = base[k];
      if (typeof v === "number" || typeof v === "string" || (v && typeof v === "object")) modelSet.add(k);
    });
  }

  return Array.from(modelSet)
    .map((name) => {
      const priceObj = normalizePriceEntry(priceMap[name] ?? base[name]);
      const ratioObj = normalizePriceEntry(ratioMap[name]);
      const pricing = {
        ...priceObj,
        price: priceObj.price != null ? priceObj.price : ratioObj.price,
        model_ratio: priceObj.model_ratio != null ? priceObj.model_ratio : ratioObj.model_ratio,
        group_ratio: priceObj.group_ratio != null ? priceObj.group_ratio : normalizePriceEntry(groupRatioMap[name]).model_ratio,
        user_group_ratio: priceObj.user_group_ratio != null ? priceObj.user_group_ratio : normalizePriceEntry(userGroupRatioMap[name]).model_ratio,
        completion_ratio: priceObj.completion_ratio != null ? priceObj.completion_ratio : normalizePriceEntry(completionRatioMap[name]).model_ratio,
        cache_ratio: priceObj.cache_ratio != null ? priceObj.cache_ratio : normalizePriceEntry(cacheRatioMap[name]).model_ratio,
        model_price: priceObj.model_price != null ? priceObj.model_price : normalizePriceEntry(fixedPriceMap[name]).model_ratio,
      };
      return {
        id: String(name),
        name: String(name),
        platform: "",
        pricing,
        source_fields: [
          ratioMap[name] != null ? "model_ratio" : "",
          priceMap[name] != null ? "model_price" : "",
          groupRatioMap[name] != null ? "group_ratio" : "",
          userGroupRatioMap[name] != null ? "user_group_ratio" : "",
          completionRatioMap[name] != null ? "completion_ratio" : "",
          cacheRatioMap[name] != null ? "cache_ratio" : "",
          fixedPriceMap[name] != null ? "fixed_price" : "",
        ].filter(Boolean),
      };
    })
    .filter((x) => x.id);
}

function normalizeGroupItems(payload) {
  let items = parseDataItems(payload);
  if (!items.length) {
    const base = (payload && (payload.data || payload)) || {};
    if (base && typeof base === "object" && !Array.isArray(base)) {
      if (Array.isArray(base.groups)) items = base.groups;
      else if (Array.isArray(base.group_list)) items = base.group_list;
      else if (Array.isArray(base.records)) items = base.records;
      else if (base.groups && typeof base.groups === "object") {
        items = Object.keys(base.groups).map((k) => ({
          id: k,
          name: k,
          ...(base.groups[k] && typeof base.groups[k] === "object" ? base.groups[k] : {}),
        }));
      }
    }
  }

  return items
    .map((x) => {
      if (typeof x === "string") {
        const g = x.trim();
        if (!g) return null;
        return {
          id: g,
          name: g,
          model_ids: [],
          model_price_map: {},
        };
      }
      if (!x || typeof x !== "object") return null;
      const id = String(x.id ?? x.value ?? x.group ?? "").trim();
      const name = String(x.name ?? x.group_name ?? x.label ?? id).trim();
      if (!id && !name) return null;
      const supportedModels = Array.isArray(x.supported_models) ? x.supported_models : Array.isArray(x.supportedModels) ? x.supportedModels : [];
      const modelIds = Array.from(
        new Set([
          ...parseModelList(x.models ?? x.model_ids ?? x.model_names ?? x.available_models),
          ...supportedModels.map((m) => String(m?.model ?? m?.name ?? m?.id ?? "").trim()).filter(Boolean),
        ])
      );
      const modelPriceMap = {
        ...asObjectMap(x.model_price ?? x.model_prices ?? x.pricing ?? x.price_map),
        ...Object.fromEntries(
          supportedModels
            .map((m) => {
              const modelId = String(m?.model ?? m?.name ?? m?.id ?? "").trim();
              return modelId ? [modelId, m.pricing || m] : null;
            })
            .filter(Boolean)
        ),
      };
      return {
        id: id || name,
        name: name || id,
        model_ids: modelIds,
        model_price_map: modelPriceMap,
        group_ratio: toNumber(x.group_ratio ?? x.groupRatio ?? x.ratio ?? x.rate),
        group_desc: String(x.description ?? x.desc ?? x.note ?? ""),
        pricing_source: supportedModels.length ? "/groups/available" : "",
        supported_models: supportedModels.map((m) => String(m?.model ?? m?.name ?? m?.id ?? "").trim()).filter(Boolean),
      };
    })
    .filter(Boolean);
}

function toNumber(v) {
  if (v == null) return null;
  if (typeof v === "number") return Number.isFinite(v) ? v : null;
  const n = Number(String(v).replace(/,/g, "").trim());
  return Number.isFinite(n) ? n : null;
}

function scaleQuotaNumber(v) {
  const n = toNumber(v);
  if (n == null) return null;
  const abs = Math.abs(n);
  if (abs >= 1_000_000) return Number((n / 500000).toFixed(6));
  return n;
}

const NEW_API_QUOTA_UNIT_RATE = 500000;

function looksLikeRawQuotaUnit(value) {
  const n = toNumber(value);
  return n != null && Math.abs(n) >= 1_000_000;
}

function quotaDisplayNumber(value, preferRawQuota = false) {
  const n = toNumber(value);
  if (n == null) return null;
  if (preferRawQuota || looksLikeRawQuotaUnit(n)) return Number((n / NEW_API_QUOTA_UNIT_RATE).toFixed(6));
  return n;
}

function decorateQuotaDisplay(info = {}) {
  const rawBalance = info.raw_balance ?? info.balance;
  const quotaLike = Boolean(info.normalized_unit === "quota/500000" || looksLikeRawQuotaUnit(rawBalance) || looksLikeRawQuotaUnit(info.raw_quota));
  const hasCurrency = Boolean(info.currency);
  const displayBalance = hasCurrency ? toNumber(rawBalance) : quotaDisplayNumber(rawBalance, quotaLike);
  const displayToday = hasCurrency ? toNumber(info.today_spend) : quotaDisplayNumber(info.today_spend, quotaLike);
  const displayTotalSpend = hasCurrency ? toNumber(info.total_spend) : quotaDisplayNumber(info.raw_total_spend ?? info.total_spend, quotaLike);
  const displayTotalQuota = hasCurrency ? toNumber(info.total_quota) : quotaDisplayNumber(info.total_quota, quotaLike);
  const displayUsedQuota = hasCurrency ? toNumber(info.used_quota) : quotaDisplayNumber(info.used_quota, quotaLike);
  const unit = hasCurrency ? info.currency : quotaLike ? "站点计费单位" : "额度";
  return {
    ...info,
    raw_balance: rawBalance,
    display_balance: displayBalance,
    display_today_spend: displayToday,
    display_total_spend: displayTotalSpend,
    display_total_quota: displayTotalQuota,
    display_used_quota: displayUsedQuota,
    display_unit: unit,
    billing_style: hasCurrency ? "currency" : quotaLike ? "new_api_quota" : "native_credit",
    conversion_rate: quotaLike ? NEW_API_QUOTA_UNIT_RATE : 1,
    conversion_note: hasCurrency
      ? `站点返回币种 ${info.currency}，按原生金额显示`
      : quotaLike
        ? `${NEW_API_QUOTA_UNIT_RATE} quota = 1 站点计费单位；已保留原始 quota 供核对`
        : "站点返回原生额度数值，未做 quota 换算",
  };
}

function toIsoTimestamp(v) {
  if (v == null || v === "") return nowIso();
  if (typeof v === "number") {
    const ms = v > 1e12 ? v : v * 1000;
    return new Date(ms).toISOString();
  }
  const s = String(v).trim();
  if (!s) return nowIso();
  if (/^\d+$/.test(s)) {
    const n = Number(s);
    const ms = n > 1e12 ? n : n * 1000;
    return new Date(ms).toISOString();
  }
  const d = new Date(s);
  if (!Number.isNaN(d.getTime())) return d.toISOString();
  return nowIso();
}

function parseJsonSafe(raw, fallback) {
  if (!raw) return fallback;
  try {
    const parsed = JSON.parse(raw);
    return parsed == null ? fallback : parsed;
  } catch (_) {
    return fallback;
  }
}

function clampNumber(value, min, max, fallback) {
  const n = toNumber(value);
  if (n == null) return fallback;
  return Math.max(min, Math.min(max, n));
}

function startOfDayUtcIso() {
  const d = new Date();
  d.setUTCHours(0, 0, 0, 0);
  return d.toISOString();
}

function minutesAgoIso(minutes) {
  return new Date(Date.now() - minutes * 60 * 1000).toISOString();
}

function sumTokens(raw) {
  const direct = toNumber(raw.token || raw.tokens || raw.total_tokens || raw.token_count);
  if (direct != null) return direct;
  const prompt = toNumber(raw.prompt_tokens);
  const completion = toNumber(raw.completion_tokens);
  if (prompt != null || completion != null) return (prompt || 0) + (completion || 0);
  return null;
}

function b64FromBytes(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function bytesFromB64(b64) {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

async function hashPassword(password, saltB64 = null, iterations = 100000) {
  const salt = saltB64 ? bytesFromB64(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations,
    },
    keyMaterial,
    256
  );
  const hash = b64FromBytes(new Uint8Array(bits));
  const saltOut = b64FromBytes(salt);
  return `pbkdf2$${iterations}$${saltOut}$${hash}`;
}

async function verifyPassword(raw, stored) {
  if (!stored) return false;
  if (!stored.startsWith("pbkdf2$")) {
    return raw === stored;
  }
  const parts = stored.split("$");
  if (parts.length !== 4) return false;
  const iterations = Number(parts[1]);
  const salt = parts[2];
  const expected = parts[3];
  const calc = await hashPassword(raw, salt, iterations);
  return calc.split("$")[3] === expected;
}

async function ensureExtendedSchema(env) {
  if (schemaEnsurePromise) {
    await schemaEnsurePromise;
    return;
  }
  schemaEnsurePromise = (async () => {
    await env.DB.batch([
      env.DB.prepare(
        `CREATE TABLE IF NOT EXISTS workspace_settings (
          workspace_id TEXT PRIMARY KEY,
          retry_policy_json TEXT NOT NULL DEFAULT '{}',
          alert_policy_json TEXT NOT NULL DEFAULT '{}',
          ui_prefs_json TEXT NOT NULL DEFAULT '{}',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )`
      ),
      env.DB.prepare(
        `CREATE TABLE IF NOT EXISTS site_profiles (
          workspace_id TEXT NOT NULL,
          site_id TEXT NOT NULL,
          family TEXT NOT NULL,
          capabilities_json TEXT NOT NULL DEFAULT '{}',
          last_probe_at TEXT,
          probe_errors_json TEXT NOT NULL DEFAULT '[]',
          probe_meta_json TEXT NOT NULL DEFAULT '{}',
          updated_at TEXT NOT NULL,
          PRIMARY KEY (workspace_id, site_id)
        )`
      ),
      env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_site_profiles_workspace ON site_profiles(workspace_id, updated_at DESC)"),
      env.DB.prepare(
        `CREATE TABLE IF NOT EXISTS alert_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          workspace_id TEXT NOT NULL,
          site_id TEXT,
          level TEXT NOT NULL,
          rule_key TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'open',
          title TEXT NOT NULL,
          detail TEXT,
          metric_value REAL,
          threshold_value REAL,
          sample_size INTEGER,
          first_triggered_at TEXT NOT NULL,
          last_triggered_at TEXT NOT NULL,
          acked_at TEXT,
          resolved_at TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )`
      ),
      env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_alert_events_workspace ON alert_events(workspace_id, created_at DESC)"),
      env.DB.prepare(
        "CREATE INDEX IF NOT EXISTS idx_alert_events_filter ON alert_events(workspace_id, status, level, rule_key, created_at DESC)"
      ),
      env.DB.prepare(
        `CREATE TABLE IF NOT EXISTS quota_snapshots (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          workspace_id TEXT NOT NULL,
          site_id TEXT NOT NULL,
          display_balance REAL,
          display_unit TEXT,
          raw_balance REAL,
          raw_quota REAL,
          total_spend REAL,
          today_spend REAL,
          source TEXT,
          billing_style TEXT,
          created_at TEXT NOT NULL
        )`
      ),
      env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_quota_snapshots_workspace ON quota_snapshots(workspace_id, created_at DESC)"),
      env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_quota_snapshots_site ON quota_snapshots(workspace_id, site_id, created_at DESC)"),
      env.DB.prepare(
        `CREATE TABLE IF NOT EXISTS health_snapshots (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          workspace_id TEXT NOT NULL,
          site_id TEXT NOT NULL,
          score INTEGER NOT NULL,
          status TEXT NOT NULL,
          human_status TEXT,
          issue_codes TEXT NOT NULL DEFAULT '[]',
          created_at TEXT NOT NULL
        )`
      ),
      env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_health_snapshots_workspace ON health_snapshots(workspace_id, created_at DESC)"),
      env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_health_snapshots_site ON health_snapshots(workspace_id, site_id, created_at DESC)"),
      env.DB.prepare(
        `CREATE TABLE IF NOT EXISTS auth_refresh_history (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          workspace_id TEXT NOT NULL,
          site_id TEXT NOT NULL,
          ok INTEGER NOT NULL DEFAULT 0,
          http_status INTEGER,
          source_endpoint TEXT,
          message TEXT,
          created_at TEXT NOT NULL
        )`
      ),
      env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_auth_refresh_history_workspace ON auth_refresh_history(workspace_id, created_at DESC)"),
      env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_auth_refresh_history_site ON auth_refresh_history(workspace_id, site_id, created_at DESC)"),
    ]);

    const alterSql = [
      "ALTER TABLE usage_logs ADD COLUMN prompt_tokens REAL",
      "ALTER TABLE usage_logs ADD COLUMN completion_tokens REAL",
      "ALTER TABLE usage_logs ADD COLUMN parse_status TEXT",
      "ALTER TABLE usage_logs ADD COLUMN parse_note TEXT",
      "ALTER TABLE sites ADD COLUMN duplicate_replaced_by TEXT",
    ];
    for (const sql of alterSql) {
      try {
        // Ignore duplicate-column errors on already-migrated databases.
        // eslint-disable-next-line no-await-in-loop
        await env.DB.prepare(sql).run();
      } catch (_) {
        // no-op
      }
    }
  })();

  try {
    await schemaEnsurePromise;
  } catch (err) {
    schemaEnsurePromise = null;
    throw err;
  }
}

async function ensureBootstrapUser(env) {
  const countRow = await env.DB.prepare("SELECT COUNT(*) AS c FROM users").first();
  if ((countRow && Number(countRow.c)) > 0) return;

  const username = String(env.ADMIN_USERNAME || "admin").trim() || "admin";
  const password = String(env.ADMIN_PASSWORD || "");
  if (!password) {
    throw new Error("ADMIN_PASSWORD secret is required before bootstrap user creation");
  }
  const passwordHash = await hashPassword(password);
  const userId = randomId();
  const workspaceId = randomId();
  const now = nowIso();

  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO users (id, username, password_hash, workspace_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5)"
    ).bind(userId, username, passwordHash, workspaceId, now),
    env.DB.prepare(
      "INSERT OR REPLACE INTO schedules (workspace_id, enabled, time_hhmm, timezone, last_run_date) VALUES (?1, 1, '09:05', 'Asia/Shanghai', NULL)"
    ).bind(workspaceId),
  ]);
}

async function createSession(env, userId) {
  const token = randString(48);
  const now = new Date();
  const expires = new Date(now.getTime() + SESSION_TTL_HOURS * 3600 * 1000).toISOString();
  await env.DB.prepare("INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?1, ?2, ?3, ?4)")
    .bind(token, userId, expires, now.toISOString())
    .run();
  return { token, expires };
}

async function getUserBySession(env, request) {
  const cookies = parseCookie(request.headers.get("cookie") || "");
  const token = cookies.cf_session;
  if (!token) return null;
  const now = nowIso();
  const row = await env.DB.prepare(
    "SELECT u.id, u.username, u.workspace_id FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?1 AND s.expires_at > ?2"
  )
    .bind(token, now)
    .first();
  return row || null;
}

function validateSitePayload(payload) {
  const id = String(payload.id || "").trim();
  if (!SITE_ID_RE.test(id)) {
    throw new Error("site.id must match [A-Za-z0-9_-], length 1-64");
  }
  let adapter = String(payload.adapter || "").trim();
  if (!["new_api", "qingyi", "onetoken", "auth_shell"].includes(adapter)) {
    throw new Error("adapter must be new_api, qingyi, onetoken or auth_shell");
  }
  const baseUrl = normalizeBaseUrl(payload.base_url);
  const name = String(payload.name || id).trim() || id;
  const credentials = typeof payload.credentials === "object" && payload.credentials ? { ...payload.credentials } : {};
  const host = new URL(baseUrl).hostname.toLowerCase();

  if (host.includes("onetoken")) {
    adapter = "onetoken";
  }
  if (host.includes("lamclod") || host.includes("gettoken")) {
    adapter = "auth_shell";
  }
  // Auto-correct common misconfiguration: qingyi-like site saved as new_api.
  if (adapter === "new_api" && (host.includes("qingyi.xuya.dev") || credentials.auth_token || credentials.refresh_token)) {
    adapter = "qingyi";
  }
  // Backward compatibility: old field name `token` for qingyi auth.
  if (adapter === "qingyi" && !credentials.auth_token && credentials.token) {
    credentials.auth_token = credentials.token;
  }

  return {
    id,
    name,
    adapter,
    base_url: baseUrl,
    enabled: payload.enabled === false ? 0 : 1,
    credentials,
    extra_headers: typeof payload.extra_headers === "object" && payload.extra_headers ? payload.extra_headers : {},
    duplicate_replaced_by: payload.duplicate_replaced_by ? String(payload.duplicate_replaced_by).trim() : "",
    retry_override:
      payload.retry_override && typeof payload.retry_override === "object"
        ? payload.retry_override
        : payload.retry_override === null
          ? null
          : null,
  };
}

function credentialKeys(credentials = {}) {
  return Object.keys(credentials || {}).filter((key) => {
    const value = credentials[key];
    return value !== undefined && value !== null && String(value).trim() !== "";
  });
}

function publicSite(site) {
  const { credentials, ...rest } = site || {};
  return {
    ...rest,
    credential_keys: credentialKeys(credentials),
  };
}

async function loadSiteProfileMap(env, workspaceId) {
  let profileRows = { results: [] };
  try {
    profileRows = await env.DB.prepare(
      "SELECT site_id, family, capabilities_json, last_probe_at, probe_errors_json, probe_meta_json FROM site_profiles WHERE workspace_id = ?1"
    )
      .bind(workspaceId)
      .all();
  } catch (_) {
    profileRows = { results: [] };
  }
  return new Map(
    (profileRows.results || []).map((r) => [
      String(r.site_id || ""),
      {
        family: r.family || "",
        capabilities: parseJsonSafe(r.capabilities_json, {}),
        last_probe_at: r.last_probe_at || null,
        probe_errors: parseJsonSafe(r.probe_errors_json, []),
        probe_meta: parseJsonSafe(r.probe_meta_json, {}),
      },
    ])
  );
}

function publicSiteWithProfile(site, profile = null) {
  const resolvedFamily = resolveSiteFamily(site);
  const meta = profile?.probe_meta || {};
  const profileInfo = meta.profile || {};
  const quotaSnapshot = meta.quota_snapshot || null;
  const capabilities = profile?.capabilities ? { ...profile.capabilities } : null;
  if (capabilities && quotaSnapshot?.quota_status !== "available") {
    capabilities.can_read_quota = false;
  }
  const display = chooseDisplayName(site, profileInfo);
  const profileForCredential = profile
    ? { capabilities: profile.capabilities || {}, probe_errors: profile.probe_errors || [], probe_meta: profile.probe_meta || {} }
    : null;
  return {
    ...publicSite(site),
    display_name: display.display_name,
    name_source: display.name_source,
    site_title: profileInfo.site_title || "",
    credential_status: summarizeCredentialStatus(site, profileForCredential),
    auth_state: describeAuthState(site, profileForCredential),
    profile_summary: {
      username: profileInfo.username || "",
      email: profileInfo.email || "",
      plan: profileInfo.plan || "",
      profile_source: meta.profile_source || "",
    },
    quota_snapshot: quotaSnapshot,
    family: resolvedFamily,
    site_shell_type: meta.shell_detection?.shell_type || detectSiteShellType(site, profile),
    repair_mode: meta.repair_mode || inferRepairMode(site, profile),
    probe_budget_status: meta.probe_budget?.status || "ok",
    support_status: inferSupportStatus(site, profile),
    source_confidence_summary: summarizeSourceConfidence(meta),
    capability_verdicts: meta.capability_verdicts || {},
    frontend_confirmed_endpoints: meta.frontend_confirmed_endpoints || [],
    console_entrypoints: meta.console_entrypoints || meta.shell_detection?.console_entrypoints || [],
    capabilities_cache: capabilities,
    last_probe_at: profile?.last_probe_at || null,
    probe_errors: profile?.probe_errors || [],
  };
}

async function loadLatestCheckinResultMap(env, workspaceId) {
  const rows = await env.DB.prepare(
    "SELECT result_json FROM jobs WHERE workspace_id = ?1 AND result_json IS NOT NULL ORDER BY created_at DESC LIMIT 20"
  )
    .bind(workspaceId)
    .all();
  const map = new Map();
  for (const row of rows.results || []) {
    const data = parseJsonSafe(row.result_json, {});
    const results = data?.report?.results || [];
    for (const item of results) {
      const siteId = String(item.site || item.site_id || "");
      if (siteId && !map.has(siteId)) map.set(siteId, item);
    }
  }
  return map;
}

function summarizeCheckinByLevel(report = null) {
  const out = {
    total: 0,
    success: 0,
    already_checked_in: 0,
    no_interface: 0,
    need_auth: 0,
    network_error: 0,
    request_failed: 0,
    info: 0,
    warning: 0,
    error: 0,
  };
  for (const item of report?.results || []) {
    out.total += 1;
    const title = String(item.result_title || "");
    const level = String(item.result_level || "");
    const text = `${title} ${item.result_reason || ""} ${item.message || ""} ${item.http_status || ""}`;
    if (level && out[level] != null) out[level] += 1;
    if (/签到成功|自动刷新后签到成功/.test(title)) out.success += 1;
    else if (/今日已签到/.test(title) || item.status === "already_checked_in") out.already_checked_in += 1;
    else if (/协议无签到接口|无需签到接口|未开放签到接口/.test(title)) out.no_interface += 1;
    else if (/登录态|鉴权|凭据|401|403|token/i.test(text)) out.need_auth += 1;
    else if (/530|1016|DNS|network|timeout|超时|网络/i.test(text)) out.network_error += 1;
    else if (level === "error" || item.ok === false) out.request_failed += 1;
  }
  return out;
}

function buildCheckinDiagnostic(site, latestCheckin = null, recentLogs = []) {
  const family = resolveSiteFamily(site);
  const checkinLogs = (recentLogs || []).filter((row) => /checkin|签到/i.test(`${row.path || ""} ${row.message || ""}`)).slice(0, 8);
  const allText = `${latestCheckin?.result_title || ""} ${latestCheckin?.result_reason || ""} ${latestCheckin?.message || ""} ${checkinLogs.map((x) => `${x.status || ""} ${x.message || ""}`).join(" ")}`;
  let result_level = latestCheckin?.result_level || "info";
  let result_title = latestCheckin?.result_title || "暂无签到记录";
  let result_reason = latestCheckin?.result_reason || "还没有最近一次签到证据；可以先执行单站仅检查。";
  let blocking = false;
  let next_action = latestCheckin?.next_action || "执行单站仅检查";

  if (family === "onetoken" && !latestCheckin) {
    result_title = "协议无签到接口";
    result_reason = "OneToken/Router 类站点通常没有站内签到入口，按 API、额度和模型健康验收即可。";
    next_action = "刷新额度和模型确认站点健康";
  } else if (family === "onetoken" && /协议无签到接口|无需签到接口|未开放签到接口/.test(String(latestCheckin?.result_title || ""))) {
    return {
      result_level: "info",
      result_title: latestCheckin.result_title || "协议无签到接口",
      result_reason: latestCheckin.result_reason || "OneToken/Router 类站点通常没有站内签到入口，按 API、额度和模型健康验收即可。",
      blocking: false,
      next_action: latestCheckin.next_action || "刷新额度和模型确认站点健康",
      latest_result: latestCheckin,
      evidence: latestCheckin.evidence || {},
      recent_checkin_logs: checkinLogs,
    };
  } else if (family === "auth_shell" && !latestCheckin) {
    result_title = "无需签到接口";
    result_reason = "该站点是控制台外壳 / 授权跳转型站点，优先完成协议识别与登录态桥接。";
    next_action = "打开协议报告或登录态修复向导";
  } else if (family === "auth_shell" && /协议无签到接口|无需签到接口|未开放签到接口/.test(String(latestCheckin?.result_title || ""))) {
    return {
      result_level: "info",
      result_title: latestCheckin.result_title || "无需签到接口",
      result_reason: latestCheckin.result_reason || "控制台外壳站点尚未确认有独立签到接口，这不计为签到失败。",
      blocking: false,
      next_action: latestCheckin.next_action || "先完成协议识别与登录态桥接",
      latest_result: latestCheckin,
      evidence: latestCheckin.evidence || {},
      recent_checkin_logs: checkinLogs,
    };
  }

  if (/401|403|token|未登录|鉴权|登录态|凭据/i.test(allText)) {
    result_level = "warning";
    result_title = "需要修复登录态";
    result_reason = "最近证据显示当前凭据不足或 Token 已失效，签到需要先修复登录态。";
    blocking = true;
    next_action = "在 Edge 重新登录目标站点，然后点击修复登录态";
  } else if (/530|1016|DNS|network|timeout|超时|网络/i.test(allText)) {
    result_level = "warning";
    result_title = "站点网络异常";
    result_reason = "最近签到链路遇到目标站点网络、DNS 或超时问题，这通常不是控制台代码错误。";
    blocking = true;
    next_action = "稍后重试，或提高该站点超时时间";
  } else if (/HTML|challenge|expected json|挑战页/i.test(allText)) {
    result_level = "warning";
    result_title = "挑战页需要处理";
    result_reason = "站点返回 HTML/挑战页。如果签到接口也遇到挑战页，需要在 Edge 完成验证后重新提取登录态。";
    blocking = Boolean(checkinLogs.length);
    next_action = "在 Edge 打开目标站点并完成验证，再重新提取";
  } else if (latestCheckin?.result_level === "success" || latestCheckin?.result_level === "info") {
    blocking = false;
  }

  return {
    result_level,
    result_title,
    result_reason,
    blocking,
    next_action,
    latest_result: latestCheckin || null,
    evidence: latestCheckin?.evidence || {
      http_status: latestCheckin?.http_status || null,
      message: latestCheckin?.message || "",
      source_endpoint: latestCheckin?.source_endpoint || "",
      attempts: latestCheckin?.attempts || 0,
    },
    recent_checkin_logs: checkinLogs,
  };
}

function readinessForSite(site, profile = null, latestCheckin = null) {
  const view = publicSiteWithProfile(site, profile);
  const cap = view.capabilities_cache || {};
  const quota = view.quota_snapshot || null;
  const blockers = [];
  const checkinUnsupportedOk = view.family === "onetoken";
  const credentialStatus = view.credential_status?.status || "unknown";
  const latestCheckinOk = Boolean(latestCheckin && latestCheckin.ok && latestCheckin.status !== "skipped");
  const checkinReady = Boolean(cap.can_checkin || latestCheckinOk || checkinUnsupportedOk);
  if (view.enabled) {
    if (credentialStatus === "missing") blockers.push({ code: "missing_credentials", label: "缺少登录态", action: "点击修复登录态，重新提取 cookie/token" });
    if (credentialStatus === "expired") blockers.push({ code: "expired_credentials", label: "登录态过期", action: "重新登录目标站点后修复登录态" });
    if (credentialStatus === "auth_warning") blockers.push({ code: "auth_warning", label: "鉴权异常", action: "重新提取登录态或检查账号权限" });
    if (!checkinReady) blockers.push({ code: "checkin_unverified", label: "签到能力未验证", action: "执行检测额度或单站签到 dry-run" });
    if (quota?.quota_status !== "available") blockers.push({ code: "quota_unavailable", label: "额度不可见", action: "修复登录态后重新检测额度" });
  }
  const ready = !view.enabled || blockers.length === 0;
  return {
    site_id: view.id,
    display_name: view.display_name || view.name || view.id,
    family: view.family,
    site_shell_type: view.site_shell_type || "",
    repair_mode: view.repair_mode || "unsupported",
    probe_budget_status: view.probe_budget_status || "ok",
    enabled: Boolean(view.enabled),
    required: Boolean(view.enabled),
    ready,
    credential_status: view.credential_status,
    quota_status: quota?.quota_status || "none",
    quota_balance: quota?.balance ?? null,
    quota_source: quota?.quota_source || quota?.source || "",
    can_checkin: checkinReady,
    checkin_note: checkinUnsupportedOk ? "该协议未发现签到接口，验收按额度/API能力通过" : "",
    can_read_quota: Boolean(cap.can_read_quota),
    latest_checkin_status: latestCheckin?.status || "",
    latest_checkin_message: latestCheckin?.message || "",
    retry_override_enabled: Boolean(view.retry_override && view.retry_override.enabled),
    last_probe_at: view.last_probe_at,
    blockers,
  };
}

const HEALTH_ISSUE_META = {
  duplicate_disabled: {
    label: "已被新站点替换",
    action: "默认隐藏旧站点；保留历史日志即可",
    severity: "info",
    penalty: 0,
    must: false,
  },
  site_disabled: {
    label: "站点已禁用",
    action: "需要参与任务时重新启用",
    severity: "info",
    penalty: 0,
    must: false,
  },
  auth_missing: {
    label: "缺少登录态",
    action: "打开目标站点并执行登录态修复",
    severity: "critical",
    penalty: 35,
    must: true,
  },
  auth_expired: {
    label: "登录态过期",
    action: "重新登录目标站点后修复登录态",
    severity: "critical",
    penalty: 35,
    must: true,
  },
  auth_warning: {
    label: "鉴权异常",
    action: "重新提取 Cookie/Token，并确认账号权限",
    severity: "critical",
    penalty: 30,
    must: true,
  },
  html_challenge: {
    label: "接口返回 HTML/挑战页",
    action: "在浏览器通过目标站点挑战页后重新修复登录态",
    severity: "critical",
    penalty: 25,
    must: true,
  },
  site_network_failed: {
    label: "站点网络异常",
    action: "稍后重试；若持续 530/1016/timeout，需要检查目标域名 DNS、Cloudflare 或源站可达性",
    severity: "critical",
    penalty: 32,
    must: true,
  },
  quota_parse_failed: {
    label: "额度不可见",
    action: "执行检测额度；仍失败时查看额度来源诊断",
    severity: "warn",
    penalty: 18,
    must: true,
  },
  checkin_failed: {
    label: "签到未验证",
    action: "执行单站签到或仅检查，查看签到证据",
    severity: "warn",
    penalty: 14,
    must: true,
  },
  model_catalog_missing: {
    label: "模型目录不可读",
    action: "刷新模型缓存；若仍失败则查看模型诊断矩阵",
    severity: "warn",
    penalty: 10,
    must: true,
  },
  model_catalog_limited: {
    label: "模型目录受限",
    action: "按协议报告确认是否需要 Router Key、控制台会话或更高账号权限",
    severity: "info",
    penalty: 4,
    must: false,
  },
  model_price_missing: {
    label: "模型价格未开放",
    action: "打开价格诊断；站点不开放时可作为可忽略缺口",
    severity: "info",
    penalty: 6,
    must: false,
  },
  usage_unsupported: {
    label: "Usage 接口未开放",
    action: "站点不支持用户日志时可忽略，按额度/API 健康验收",
    severity: "info",
    penalty: 5,
    must: false,
  },
  probe_budget_exhausted: {
    label: "探测预算已耗尽",
    action: "使用轻量探测或单项验证，避免一次性请求过多接口",
    severity: "warn",
    penalty: 12,
    must: false,
  },
  auth_shell_pending: {
    label: "控制台会话已识别",
    action: "先确认是否已进入真实控制台，再执行轻量探测识别 API 能力",
    severity: "info",
    penalty: 6,
    must: false,
  },
  oidc_pending_callback: {
    label: "等待授权回跳",
    action: "在 Edge 中完成 OIDC 授权并回到业务站点后，再重新提取登录态",
    severity: "warn",
    penalty: 10,
    must: false,
  },
};

function classifyHealthIssue(code, label = "", action = "", severity = "", detail = "") {
  const meta = HEALTH_ISSUE_META[code] || {};
  return {
    code,
    label: label || meta.label || code,
    human_label: label || meta.label || code,
    action: action || meta.action || "查看诊断详情",
    severity: severity || meta.severity || "warn",
    detail,
    score_penalty: Number(meta.penalty || 5),
    must_fix: Boolean(meta.must),
  };
}

function buildDiagnosticMatrix(view, quota, modelCache, latestCheckin, probeErrors) {
  const cap = view.capabilities_cache || {};
  const credentialStatus = view.credential_status?.status || "unknown";
  const checkinStatus = latestCheckin?.status || "";
  const family = view.family || resolveSiteFamily(view);
  const matrix = [];
  const push = (area, title, status, evidence, next_action) => {
    matrix.push({ area, title, status, evidence: evidence || "", next_action: next_action || "" });
  };

  if (!view.enabled && view.duplicate_replaced_by) {
    push("archive", "重复站点已归档", "info", `已被 ${view.duplicate_replaced_by} 替换`, "保留历史日志，不参与主任务");
  } else if (!view.enabled) {
    push("archive", "站点已禁用", "info", "enabled=false", "需要参与任务时重新启用");
  }

  if (["ok", "available", "unknown"].includes(credentialStatus)) {
    push("auth", credentialStatus === "ok" ? "登录态可用" : "登录态未发现明显阻塞", "ok", `credential=${credentialStatus}`, "保持监控");
  } else {
    push("auth", "登录态需要处理", "error", `credential=${credentialStatus}`, "重新登录目标站点并修复登录态");
  }

  if (view.site_shell_type) {
    push("shell", "控制台外壳已识别", "info", `shell=${view.site_shell_type}`, "优先走 Edge 登录态桥接和协议报告，而不是继续盲探接口");
  }

  if (view.probe_budget_status === "probe_budget_exhausted") {
    push("probe-budget", "本次探测预算已耗尽", "warn", "probe_budget_exhausted", "改用轻量探测或单项验证，避免一次调用打太多接口");
  }

  if (quota?.quota_status === "available") {
    push("quota", "额度可读", "ok", `${quota.quota_source || quota.source || "-"} | ${quota.quota_parse_note || "解析成功"}`, "可继续按当前站点计费单位观察");
  } else {
    push("quota", "额度不可读", "warn", quota?.quota_parse_note || quota?.quota_status || "未缓存额度快照", "执行检测额度并查看来源接口");
  }

  const modelCount = Number(modelCache?.model_count || 0);
  const pricedCount = Number(modelCache?.priced_count || 0);
  if (modelCount > 0 && pricedCount > 0) {
    push("models", "模型和计价已缓存", "ok", `模型 ${modelCount} 个，有计价 ${pricedCount} 个`, "打开模型页核对具体倍率");
  } else if (modelCount > 0) {
    push("models", "模型可读但计价缺失", "info", `模型 ${modelCount} 个，价格接口未返回可识别字段`, "打开价格诊断确认是否站点未开放");
  } else {
    const reason = family === "onetoken" ? "Router 未公开模型目录或当前 Router Key 权限不足" : "未从已知接口解析到模型目录";
    push("models", "模型目录不可读", "warn", reason, "刷新模型缓存或检查账号权限");
  }

  if (cap.can_read_usage === false) {
    push("usage", "Usage 接口未开放", "info", "站点未开放用户日志接口", "这不是阻塞项；需要趋势时先尝试单站拉取 Usage");
  } else if (cap.can_read_usage) {
    push("usage", "Usage 可读取", "ok", "capability=can_read_usage", "可进入日志中心查看 token/cost");
  } else {
    push("usage", "Usage 状态未知", "info", "尚未验证日志接口", "执行拉取 Usage");
  }

  if (family === "onetoken") {
    push("checkin", "协议无站内签到接口", "info", "OneToken 按 Router/API/额度健康验收", "无需把跳过视为失败");
  } else if (["checked_in", "already_checked_in"].includes(checkinStatus)) {
    push("checkin", checkinStatus === "already_checked_in" ? "今日已签到" : "签到成功", "ok", latestCheckin?.message || checkinStatus, "保持每日任务");
  } else if (checkinStatus === "skipped") {
    push("checkin", "签到被跳过", "info", latestCheckin?.message || "可能是协议不支持或鉴权不可用", "查看签到结果证据");
  } else if (latestCheckin && latestCheckin.ok === false) {
    push("checkin", "签到失败", "error", latestCheckin.message || "请求失败", "修复登录态或查看请求日志");
  } else {
    push("checkin", "签到未验证", "warn", "暂无最近签到结果", "执行仅检查或单站签到");
  }

  for (const err of probeErrors.slice(0, 4)) {
    push("probe", "最近探测异常", /html|challenge/i.test(String(err)) ? "error" : "warn", String(err), "查看系统日志并重新检测");
  }
  return matrix;
}

function healthHumanStatus(score, view, issues) {
  if (!view.enabled && view.duplicate_replaced_by) return "已归档";
  if (!view.enabled) return "已禁用";
  if (issues.some((x) => x.severity === "critical")) return "阻塞任务";
  if (score >= 90) return "运行良好";
  if (score >= 75) return "可用但有缺口";
  return "需要处理";
}

function healthHumanSummary(view, score, issues, mustFix, optionalIssues) {
  if (!view.enabled && view.duplicate_replaced_by) return `旧站点已被 ${view.duplicate_replaced_by} 替换，不再参与签到/额度/Usage 任务。`;
  if (!view.enabled) return "站点当前禁用，不参与自动任务；历史日志仍保留。";
  if (view.family === "auth_shell" && view.site_shell_type) {
    return `当前先识别到 ${view.site_shell_type} 控制台外壳；建议优先在 Edge 中修复登录态并确认控制台/API入口，再继续额度和模型探测。`;
  }
  if (!issues.length) return "关键能力正常，当前可以参与自动任务。";
  if (mustFix.length) return `${mustFix[0].human_label} 是当前首要问题；健康分 ${score}，建议先执行：${mustFix[0].action}。`;
  if (optionalIssues.length) return `站点可用，但存在 ${optionalIssues.length} 个可忽略缺口：${optionalIssues.map((x) => x.human_label).join("、")}。`;
  return `健康分 ${score}，建议查看诊断矩阵定位问题。`;
}

function buildSiteHealth(site, profile = null, latestCheckin = null) {
  const view = publicSiteWithProfile(site, profile);
  const cap = view.capabilities_cache || {};
  const meta = profile?.probe_meta || {};
  const quota = view.quota_snapshot || null;
  const issues = [];
  const credentialStatus = view.credential_status?.status || "unknown";
  const probeErrors = Array.isArray(view.probe_errors) ? view.probe_errors : [];
  const latestOk = Boolean(latestCheckin && latestCheckin.ok && latestCheckin.status !== "skipped");
  const protocolDoesNotGuaranteeCheckin = view.family === "onetoken" || view.family === "auth_shell";
  const checkinOk = Boolean(cap.can_checkin || latestOk || protocolDoesNotGuaranteeCheckin);
  const modelCache = meta.model_catalog_cache || {};
  const modelCount = Number(modelCache.model_count || 0);
  const pricedCount = Number(modelCache.priced_count || 0);
  const networkEvidence = [
    ...probeErrors,
    latestCheckin?.message || "",
    latestCheckin?.reason || "",
    quota?.quota_parse_note || "",
  ].join(" | ");
  const hasNetworkFailure = /error code:\s*1016|status[=: ]*530|network error|timeout|dns|fetch failed/i.test(networkEvidence);

  if (!view.enabled) {
    issues.push(
      classifyHealthIssue(
        view.duplicate_replaced_by ? "duplicate_disabled" : "site_disabled",
        view.duplicate_replaced_by ? "重复站点已禁用" : "站点已禁用",
        view.duplicate_replaced_by ? "保留新导入站点，旧站点无需参与任务" : "如需参与任务请重新启用",
        view.duplicate_replaced_by ? "info" : "warn",
        view.duplicate_replaced_by ? `已被 ${view.duplicate_replaced_by} 替换` : ""
      )
    );
  }
  if (view.enabled) {
    if (credentialStatus === "missing") issues.push(classifyHealthIssue("auth_missing", "缺少登录态", "打开目标站点并点击修复登录态", "critical"));
    if (credentialStatus === "expired") issues.push(classifyHealthIssue("auth_expired", "登录态过期", "重新登录目标站点后修复登录态", "critical"));
    if (credentialStatus === "auth_warning") issues.push(classifyHealthIssue("auth_warning", "鉴权异常", "重新提取登录态或检查账号权限", "critical"));
    if (view.family === "auth_shell" && view.site_shell_type) {
      issues.push(classifyHealthIssue("auth_shell_pending", "控制台会话已识别", "优先使用 Edge 登录态桥接，再确认是否开放 API / 模型 / 额度接口", "info", `shell=${view.site_shell_type}`));
    }
    if (view.family === "auth_shell" && credentialStatus === "auth_warning") {
      issues.push(classifyHealthIssue("oidc_pending_callback", "等待授权回跳", "若当前是授权页或登录页，请在 Edge 完成回跳后再重新提取", "warn", "OIDC / console session pending"));
    }
    if (hasNetworkFailure) {
      issues.push(classifyHealthIssue("site_network_failed", "", "", "", networkEvidence.slice(0, 240)));
    }
    if (!hasNetworkFailure && probeErrors.some((x) => /html|challenge|expected json/i.test(String(x)))) {
      issues.push(classifyHealthIssue("html_challenge", "接口返回 HTML/挑战页", "在浏览器确认站点已登录并通过挑战，再修复登录态", "critical"));
    }
    if (view.probe_budget_status === "probe_budget_exhausted") {
      issues.push(classifyHealthIssue("probe_budget_exhausted", "", "", "", "本次探测因子请求预算耗尽而提前停止"));
    }
    if (!hasNetworkFailure && view.family !== "auth_shell" && quota?.quota_status !== "available") {
      issues.push(classifyHealthIssue("quota_parse_failed", "", "", "", quota?.quota_parse_note || ""));
    }
    if (!hasNetworkFailure && !checkinOk) issues.push(classifyHealthIssue("checkin_failed", "", "", "", latestCheckin?.message || ""));
    if (cap.can_read_usage === false) issues.push(classifyHealthIssue("usage_unsupported", "", "", "", "站点未开放用户日志接口时不阻塞签到/额度验收"));
    if (modelCount > 0 && pricedCount === 0) {
      issues.push(classifyHealthIssue("model_price_missing", "", "", "", "已拿到模型名，但未在已知接口发现倍率/固定价字段"));
    } else if (!hasNetworkFailure && cap.can_read_models === false) {
      if (view.family === "onetoken" || view.family === "auth_shell") {
        issues.push(classifyHealthIssue("model_catalog_limited", "", "", "", view.family === "onetoken" ? "Router Key 权限不足或未公开模型目录" : "控制台外壳站点需先确认真实 API 能力"));
      } else {
        issues.push(classifyHealthIssue("model_catalog_missing"));
      }
    }
  }

  let score = 100;
  const scoreBreakdown = issues.map((issue) => ({
    code: issue.code,
    label: issue.human_label || issue.label,
    penalty: Number(issue.score_penalty || 5),
    severity: issue.severity,
    evidence: issue.detail || issue.action || "",
  }));
  for (const issue of issues) score -= Number(issue.score_penalty || 5);
  if (!view.enabled && view.duplicate_replaced_by) score = Math.min(score, 92);
  score = Math.max(0, Math.min(100, Math.round(score)));
  const status = score >= 85 ? "healthy" : score >= 65 ? "warning" : "critical";
  const mustFixIssues = issues.filter((x) => x.must_fix);
  const optionalIssues = issues.filter((x) => !x.must_fix);
  const diagnosticMatrix = buildDiagnosticMatrix(view, quota, modelCache, latestCheckin, probeErrors);
  const humanStatus = healthHumanStatus(score, view, issues);
  const humanSummary = healthHumanSummary(view, score, issues, mustFixIssues, optionalIssues);
  const recommendedActions = Array.from(
    new Map(
      issues
        .map((issue) => [
          issue.code,
          {
            code: issue.code,
            label: issue.action,
            priority: issue.must_fix ? "must" : "optional",
          },
        ])
        .concat(
          issues.length
            ? []
            : [["monitor", { code: "monitor", label: "保持监控并定期刷新健康快照", priority: "normal" }]]
        )
    ).values()
  );

  return {
    site_id: view.id,
    display_name: view.display_name || view.name || view.id,
    family: view.family,
    enabled: Boolean(view.enabled),
    support_status: view.support_status || "supported",
    auth_state: view.auth_state || null,
    capability_verdicts: view.capability_verdicts || {},
    source_confidence_summary: view.source_confidence_summary || {},
    score,
    status,
    human_status: humanStatus,
    human_summary: humanSummary,
    issues,
    issue_codes: issues.map((x) => x.code),
    score_breakdown: scoreBreakdown,
    must_fix_issues: mustFixIssues,
    optional_issues: optionalIssues,
    recommended_actions: recommendedActions,
    diagnostic_matrix: diagnosticMatrix,
    next_action: issues[0]?.action || "保持监控",
    quota_status: quota?.quota_status || "none",
    quota_balance: quota?.display_balance ?? quota?.balance ?? null,
    quota_unit: quota?.display_unit || quota?.currency || "",
    model_count: modelCount,
    priced_model_count: pricedCount,
    usage_supported: Boolean(cap.can_read_usage),
    last_probe_at: view.last_probe_at || null,
    latest_checkin_status: latestCheckin?.status || "",
    latest_checkin_message: latestCheckin?.message || "",
    diagnostic: {
      credential_status: view.credential_status,
      auth_state: view.auth_state,
      support_status: view.support_status,
      capabilities: cap,
      capability_verdicts: view.capability_verdicts || {},
      source_confidence_summary: view.source_confidence_summary || {},
      probe_errors: probeErrors,
      quota,
      model_cache: modelCache,
      profile_source: view.profile_summary?.profile_source || "",
      diagnostic_matrix: diagnosticMatrix,
    },
  };
}

async function saveHealthSnapshots(env, workspaceId, items) {
  const now = nowIso();
  const batch = (items || []).map((item) =>
    env.DB.prepare(
      "INSERT INTO health_snapshots (workspace_id, site_id, score, status, human_status, issue_codes, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
    ).bind(
      workspaceId,
      item.site_id,
      Number(item.score || 0),
      item.status || "",
      item.human_status || "",
      JSON.stringify(item.issue_codes || []),
      now
    )
  );
  if (batch.length) await env.DB.batch(batch);
}

function normalizedSiteBase(site) {
  try {
    const u = new URL(site.base_url);
    return `${u.protocol}//${u.hostname.toLowerCase()}${u.port ? `:${u.port}` : ""}`.replace(/\/$/, "");
  } catch (_) {
    return String(site.base_url || "").trim().replace(/\/$/, "").toLowerCase();
  }
}

function normalizeSiteConfig(site) {
  const family = resolveSiteFamily(site);
  const credentials = { ...(site.credentials || {}) };
  if (family === "qingyi" && !credentials.auth_token && credentials.token) {
    credentials.auth_token = credentials.token;
  }
  return {
    ...site,
    adapter: family === "onetoken" ? "onetoken" : family === "qingyi" ? "qingyi" : "new_api",
    credentials,
  };
}

async function repairSiteConfigurations(env, workspaceId) {
  const sites = await dbListSites(env, workspaceId);
  const seen = new Map();
  const actions = [];
  for (const original of sites) {
    let site = normalizeSiteConfig(original);
    let changed = site.adapter !== original.adapter || JSON.stringify(site.credentials || {}) !== JSON.stringify(original.credentials || {});
    const key = normalizedSiteBase(site);
    const first = seen.get(key);
    if (first) {
      if (site.enabled) {
        site = { ...site, enabled: 0 };
        changed = true;
        actions.push({ site_id: site.id, action: "disabled_duplicate", duplicate_of: first.id, base_url: site.base_url });
      }
    } else {
      seen.set(key, site);
    }
    if (site.adapter !== original.adapter) {
      actions.push({ site_id: site.id, action: "adapter_normalized", from: original.adapter, to: site.adapter });
    }
    if (changed) {
      await dbSaveSite(env, workspaceId, site);
    }
  }
  return { actions, changed: actions.length };
}

async function validateCredentialsForSite(env, workspaceId, site) {
  const family = resolveSiteFamily(site);
  const path =
    family === "onetoken"
      ? "/api/v1/users/me"
      : family === "qingyi"
        ? "/user/profile"
        : family === "auth_shell"
          ? "/"
          : "/api/user/self";
  const r = await siteRequest(env, workspaceId, site, "GET", path, { timeout_ms: 12000 });
  if (family === "auth_shell") {
    const reachable = Number(r.status) >= 200 && Number(r.status) < 500;
    if (reachable && hasAuthMaterial(site)) {
      return { ok: true, path, status: r.status, message: r.message || "session captured; downstream api pending" };
    }
  }
  if (r.status >= 200 && r.status < 300 && r.payload) {
    return { ok: true, path, status: r.status, message: pickMessage(r.payload, r.message) || "validated" };
  }
  return {
    ok: false,
    path,
    status: r.status || null,
    message: r.message || `status=${r.status}`,
  };
}

function pickOpenClawAccessToken(extract = {}) {
  const sources = [
    extract.openclaw_auth,
    extract.openclawAuth,
    extract.localStorage?.openclaw_auth,
    extract.local_storage?.openclaw_auth,
    extract.storage?.openclaw_auth,
  ];
  for (const value of sources) {
    if (!value) continue;
    if (typeof value === "string") {
      try {
        const parsed = JSON.parse(value);
        const token = String(parsed.accessToken || parsed.access_token || parsed.token || "").trim();
        if (token) return token;
      } catch (_) {
        if (value.split(".").length === 3) return value.trim();
      }
    } else if (typeof value === "object") {
      const token = String(value.accessToken || value.access_token || value.token || "").trim();
      if (token) return token;
    }
  }
  return "";
}

function suggestSiteId(baseUrl, used) {
  const u = new URL(baseUrl);
  let slug = u.hostname.toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "");
  if (!slug) slug = "site";
  slug = slug.slice(0, 50);
  if (!used.has(slug)) return slug;
  let idx = 2;
  while (idx < 9999) {
    const c = `${slug.slice(0, 45)}-${idx}`;
    if (!used.has(c)) return c;
    idx += 1;
  }
  return `${slug}-${Date.now()}`;
}

function sameSiteBaseUrl(a, b) {
  try {
    return normalizeBaseUrl(a) === normalizeBaseUrl(b);
  } catch (_) {
    return String(a || "").trim().replace(/\/+$/, "") === String(b || "").trim().replace(/\/+$/, "");
  }
}

async function dbListSites(env, workspaceId) {
  const rows = await env.DB.prepare(
    "SELECT id, name, adapter, base_url, enabled, credentials, extra_headers, retry_override, duplicate_replaced_by, created_at, updated_at FROM sites WHERE workspace_id = ?1 ORDER BY created_at ASC"
  )
    .bind(workspaceId)
    .all();
  const list = (rows.results || []).map((row) => {
    const rawId = String(row.id || "");
    const prefix = `${workspaceId}:`;
    const shortId = rawId.startsWith(prefix) ? rawId.slice(prefix.length) : rawId;
    return {
      ...row,
      id: shortId,
      enabled: Number(row.enabled) === 1,
      credentials: parseJsonSafe(row.credentials, {}),
      extra_headers: parseJsonSafe(row.extra_headers, {}),
      retry_override: parseJsonSafe(row.retry_override, null),
    };
  });
  return list;
}

async function dbGetSite(env, workspaceId, siteId) {
  const prefixed = `${workspaceId}:${siteId}`;
  const row = await env.DB.prepare(
    "SELECT id, name, adapter, base_url, enabled, credentials, extra_headers, retry_override, duplicate_replaced_by, created_at, updated_at FROM sites WHERE workspace_id = ?1 AND (id = ?2 OR id = ?3)"
  )
    .bind(workspaceId, siteId, prefixed)
    .first();
  if (!row) return null;
  const rawId = String(row.id || "");
  const prefix = `${workspaceId}:`;
  const shortId = rawId.startsWith(prefix) ? rawId.slice(prefix.length) : rawId;
  return {
    ...row,
    id: shortId,
    enabled: Number(row.enabled) === 1,
    credentials: parseJsonSafe(row.credentials, {}),
    extra_headers: parseJsonSafe(row.extra_headers, {}),
    retry_override: parseJsonSafe(row.retry_override, null),
  };
}

async function dbSaveSite(env, workspaceId, site) {
  const now = nowIso();
  const dbId = `${workspaceId}:${site.id}`;
  await env.DB.prepare(
    `INSERT INTO sites (id, workspace_id, name, adapter, base_url, enabled, credentials, extra_headers, retry_override, duplicate_replaced_by, created_at, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11)
     ON CONFLICT(id) DO UPDATE SET
      name = excluded.name,
      adapter = excluded.adapter,
      base_url = excluded.base_url,
      enabled = excluded.enabled,
      credentials = excluded.credentials,
      extra_headers = excluded.extra_headers,
      retry_override = excluded.retry_override,
      duplicate_replaced_by = excluded.duplicate_replaced_by,
      updated_at = excluded.updated_at`
  )
    .bind(
      dbId,
      workspaceId,
      site.name,
      site.adapter,
      site.base_url,
      site.enabled ? 1 : 0,
      JSON.stringify(site.credentials || {}),
      JSON.stringify(site.extra_headers || {}),
      site.retry_override ? JSON.stringify(site.retry_override) : null,
      site.duplicate_replaced_by || null,
      now
    )
    .run();
}

async function disableDuplicateSitesForImport(env, workspaceId, newSite) {
  const sites = await dbListSites(env, workspaceId);
  const duplicates = sites.filter((site) => site.id !== newSite.id && sameSiteBaseUrl(site.base_url, newSite.base_url));
  const replaced = [];
  for (const site of duplicates) {
    const patched = {
      ...site,
      enabled: 0,
      duplicate_replaced_by: newSite.id,
    };
    // eslint-disable-next-line no-await-in-loop
    await dbSaveSite(env, workspaceId, patched);
    replaced.push({
      id: site.id,
      name: site.name,
      base_url: site.base_url,
      replaced_by: newSite.id,
    });
  }
  return replaced;
}

async function dbDeleteSite(env, workspaceId, siteId) {
  const prefixed = `${workspaceId}:${siteId}`;
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sites WHERE workspace_id = ?1 AND (id = ?2 OR id = ?3)").bind(workspaceId, siteId, prefixed),
    env.DB.prepare("DELETE FROM site_profiles WHERE workspace_id = ?1 AND site_id = ?2").bind(workspaceId, siteId),
  ]);
}

function normalizeRetryPolicy(raw, fallback = RETRY_POLICY_DEFAULT) {
  const base = raw && typeof raw === "object" ? raw : {};
  return {
    max_attempts: Math.round(clampNumber(base.max_attempts, 1, 8, fallback.max_attempts)),
    base_delay_s: clampNumber(base.base_delay_s, 0.1, 30, fallback.base_delay_s),
    multiplier: clampNumber(base.multiplier, 1, 5, fallback.multiplier),
    max_delay_s: clampNumber(base.max_delay_s, 1, 300, fallback.max_delay_s),
    jitter_ratio: clampNumber(base.jitter_ratio, 0, 0.8, fallback.jitter_ratio),
    timeout_ms: Math.round(clampNumber(base.timeout_ms, 1000, 60000, fallback.timeout_ms)),
  };
}

function normalizeAlertPolicy(raw, fallback = ALERT_POLICY_DEFAULT) {
  const base = raw && typeof raw === "object" ? raw : {};
  return {
    preset: String(base.preset || fallback.preset || "balanced"),
    daily_cost: clampNumber(base.daily_cost, 0, 1_000_000, fallback.daily_cost),
    daily_tokens: Math.round(clampNumber(base.daily_tokens, 0, 100_000_000_000, fallback.daily_tokens)),
    failure_rate_15m: clampNumber(base.failure_rate_15m, 0, 1, fallback.failure_rate_15m),
    failure_rate_15m_min_samples: Math.round(
      clampNumber(base.failure_rate_15m_min_samples, 1, 10000, fallback.failure_rate_15m_min_samples)
    ),
    consecutive_failures: Math.round(clampNumber(base.consecutive_failures, 1, 200, fallback.consecutive_failures)),
  };
}

async function ensureWorkspaceSettings(env, workspaceId) {
  const row = await env.DB.prepare("SELECT workspace_id FROM workspace_settings WHERE workspace_id = ?1").bind(workspaceId).first();
  if (row) return;
  const now = nowIso();
  await env.DB.prepare(
    "INSERT INTO workspace_settings (workspace_id, retry_policy_json, alert_policy_json, ui_prefs_json, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5)"
  )
    .bind(workspaceId, JSON.stringify(RETRY_POLICY_DEFAULT), JSON.stringify(ALERT_POLICY_DEFAULT), "{}", now)
    .run();
}

async function getWorkspaceSettings(env, workspaceId) {
  await ensureWorkspaceSettings(env, workspaceId);
  const row = await env.DB.prepare(
    "SELECT retry_policy_json, alert_policy_json, ui_prefs_json, created_at, updated_at FROM workspace_settings WHERE workspace_id = ?1"
  )
    .bind(workspaceId)
    .first();
  return {
    retry_policy: normalizeRetryPolicy(parseJsonSafe(row?.retry_policy_json, {})),
    alert_policy: normalizeAlertPolicy(parseJsonSafe(row?.alert_policy_json, {})),
    ui_prefs: parseJsonSafe(row?.ui_prefs_json, {}),
    created_at: row?.created_at || null,
    updated_at: row?.updated_at || null,
  };
}

async function saveWorkspacePolicies(env, workspaceId, patch = {}) {
  const current = await getWorkspaceSettings(env, workspaceId);
  const retryPolicy = patch.retry_policy ? normalizeRetryPolicy(patch.retry_policy, current.retry_policy) : current.retry_policy;
  const alertPolicy = patch.alert_policy ? normalizeAlertPolicy(patch.alert_policy, current.alert_policy) : current.alert_policy;
  const uiPrefs =
    patch.ui_prefs && typeof patch.ui_prefs === "object"
      ? {
          ...(current.ui_prefs || {}),
          ...patch.ui_prefs,
        }
      : current.ui_prefs;
  const now = nowIso();
  await env.DB.prepare(
    `UPDATE workspace_settings
       SET retry_policy_json = ?1,
           alert_policy_json = ?2,
           ui_prefs_json = ?3,
           updated_at = ?4
     WHERE workspace_id = ?5`
  )
    .bind(JSON.stringify(retryPolicy), JSON.stringify(alertPolicy), JSON.stringify(uiPrefs || {}), now, workspaceId)
    .run();
  return {
    retry_policy: retryPolicy,
    alert_policy: alertPolicy,
    ui_prefs: uiPrefs || {},
    updated_at: now,
  };
}

function resolveSiteFamily(site) {
  const host = new URL(site.base_url).hostname.toLowerCase();
  if (site.adapter === "auth_shell" || host.includes("lamclod") || host.includes("gettoken")) return "auth_shell";
  if (host.includes("onetoken") || site.adapter === "onetoken") return "onetoken";
  if (host.includes("qingyi") || site.adapter === "qingyi") return "qingyi";
  if (site.adapter === "qingyi") return "qingyi";
  if (site.adapter === "new_api") return "new_api";
  return "new_api";
}

async function dbSaveSiteProfile(env, workspaceId, siteId, profile) {
  const now = nowIso();
  await env.DB.prepare(
    `INSERT INTO site_profiles (workspace_id, site_id, family, capabilities_json, last_probe_at, probe_errors_json, probe_meta_json, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
     ON CONFLICT(workspace_id, site_id) DO UPDATE SET
       family = excluded.family,
       capabilities_json = excluded.capabilities_json,
       last_probe_at = excluded.last_probe_at,
       probe_errors_json = excluded.probe_errors_json,
       probe_meta_json = excluded.probe_meta_json,
       updated_at = excluded.updated_at`
  )
    .bind(
      workspaceId,
      siteId,
      String(profile.family || "new_api"),
      JSON.stringify(profile.capabilities || {}),
      profile.last_probe_at || now,
      JSON.stringify(profile.probe_errors || []),
      JSON.stringify(profile.probe_meta || {}),
      now
    )
    .run();
}

async function dbGetSiteProfile(env, workspaceId, siteId) {
  const row = await env.DB.prepare(
    "SELECT family, capabilities_json, last_probe_at, probe_errors_json, probe_meta_json, updated_at FROM site_profiles WHERE workspace_id = ?1 AND site_id = ?2"
  )
    .bind(workspaceId, siteId)
    .first();
  if (!row) return null;
  return {
    family: row.family,
    capabilities: parseJsonSafe(row.capabilities_json, {}),
    last_probe_at: row.last_probe_at,
    probe_errors: parseJsonSafe(row.probe_errors_json, []),
    probe_meta: parseJsonSafe(row.probe_meta_json, {}),
    updated_at: row.updated_at,
  };
}

async function saveQuotaSnapshot(env, workspaceId, siteId, quota) {
  if (!quota || quota.quota_status !== "available") return;
  await env.DB.prepare(
    `INSERT INTO quota_snapshots (
      workspace_id, site_id, display_balance, display_unit, raw_balance, raw_quota,
      total_spend, today_spend, source, billing_style, created_at
    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`
  )
    .bind(
      workspaceId,
      siteId,
      quota.display_balance == null ? null : Number(quota.display_balance),
      quota.display_unit || quota.currency || "",
      quota.raw_balance == null ? null : Number(quota.raw_balance),
      quota.raw_quota == null ? null : Number(quota.raw_quota),
      quota.display_total_spend == null ? quota.total_spend == null ? null : Number(quota.total_spend) : Number(quota.display_total_spend),
      quota.display_today_spend == null ? quota.today_spend == null ? null : Number(quota.today_spend) : Number(quota.display_today_spend),
      quota.quota_source || quota.source || "",
      quota.billing_style || "",
      nowIso()
    )
    .run();
}

async function patchSiteProbeMeta(env, workspaceId, siteId, patch = {}) {
  const existing = await dbGetSiteProfile(env, workspaceId, siteId);
  const site = await dbGetSite(env, workspaceId, siteId);
  const family = existing?.family || (site ? resolveSiteFamily(site) : "new_api");
  await dbSaveSiteProfile(env, workspaceId, siteId, {
    family,
    capabilities: existing?.capabilities || {},
    last_probe_at: existing?.last_probe_at || nowIso(),
    probe_errors: existing?.probe_errors || [],
    probe_meta: {
      ...(existing?.probe_meta || {}),
      ...patch,
    },
  });
}

function resolveRetryPolicyForSite(workspacePolicy, site) {
  const override = site.retry_override && typeof site.retry_override === "object" ? site.retry_override : null;
  if (!override || override.enabled !== true) {
    return {
      source: "workspace-default",
      policy: normalizeRetryPolicy(workspacePolicy),
    };
  }
  return {
    source: "site-override",
    policy: normalizeRetryPolicy({ ...workspacePolicy, ...override }, workspacePolicy),
  };
}

function computeRetryDelayMs(policy, attemptIndex) {
  const base = policy.base_delay_s * 1000;
  const factor = Math.pow(policy.multiplier, Math.max(0, attemptIndex - 1));
  const capped = Math.min(policy.max_delay_s * 1000, base * factor);
  const jitter = capped * policy.jitter_ratio;
  const delta = (Math.random() * 2 - 1) * jitter;
  return Math.max(0, Math.round(capped + delta));
}

function shouldRetryCheckin(result) {
  if (!result || result.ok) return false;
  if (NON_RETRYABLE_STATUS_CODES.has(Number(result.http_status))) return false;
  if (RETRYABLE_STATUS_CODES.has(Number(result.http_status))) return true;
  const reason = String(result.reason || result.message || "").toLowerCase();
  if (reason.includes("timeout") || reason.includes("network")) return true;
  if (reason.includes("status=52")) return true;
  if (reason.includes("status=5")) return true;
  return false;
}

function siteHeaders(site) {
  const base = site.base_url;
  const family = resolveSiteFamily(site);
  const headers = {
    Accept: "application/json, text/plain, */*",
    "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    Origin: base,
    Referer: `${base}/console`,
  };

  const creds = site.credentials || {};
  if (family === "new_api") {
    if (creds.token) headers.Authorization = `Bearer ${String(creds.token).trim()}`;
    if (creds.cookie) headers.Cookie = String(creds.cookie).trim();
    if (creds.new_api_user) headers["New-Api-User"] = String(creds.new_api_user).trim();
  } else if (family === "auth_shell") {
    const auth = String(creds.token || creds.auth_token || creds.access_token || "").trim();
    if (auth) headers.Authorization = `Bearer ${auth}`;
    if (creds.cookie) headers.Cookie = String(creds.cookie).trim();
  } else if (family === "qingyi") {
    const auth = String(creds.auth_token || creds.token || "").trim();
    if (auth) headers.Authorization = `Bearer ${auth}`;
    if (creds.cookie) headers.Cookie = String(creds.cookie).trim();
  } else if (family === "onetoken") {
    const auth = String(creds.token || creds.auth_token || creds.access_token || "").trim();
    if (auth) headers.Authorization = `Bearer ${auth}`;
    if (creds.cookie) headers.Cookie = String(creds.cookie).trim();
  }

  const extra = site.extra_headers || {};
  Object.keys(extra).forEach((k) => {
    if (k && extra[k] != null) headers[k] = String(extra[k]);
  });

  return headers;
}

async function insertSystemLog(env, payload) {
  await env.DB.prepare(
    `INSERT INTO system_logs (workspace_id, site_id, trace_id, method, path, status, elapsed_ms, ok, message, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)`
  )
    .bind(
      payload.workspace_id,
      payload.site_id || null,
      payload.trace_id || null,
      payload.method || null,
      payload.path || null,
      payload.status == null ? null : Number(payload.status),
      payload.elapsed_ms == null ? null : Number(payload.elapsed_ms),
      payload.ok ? 1 : 0,
      payload.message || "",
      nowIso()
    )
    .run();
}

async function recordAuthRefreshHistory(env, workspaceId, siteId, payload = {}) {
  await env.DB.prepare(
    `INSERT INTO auth_refresh_history (workspace_id, site_id, ok, http_status, source_endpoint, message, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`
  )
    .bind(
      workspaceId,
      siteId,
      payload.ok ? 1 : 0,
      payload.http_status == null ? null : Number(payload.http_status),
      payload.source_endpoint || "/auth/refresh",
      payload.message || "",
      nowIso()
    )
    .run();
}

async function listAuthRefreshHistory(env, workspaceId, siteId, limit = 30) {
  const rows = await env.DB.prepare(
    "SELECT ok, http_status, source_endpoint, message, created_at FROM auth_refresh_history WHERE workspace_id = ?1 AND site_id = ?2 ORDER BY id DESC LIMIT ?3"
  )
    .bind(workspaceId, siteId, Math.max(1, Math.min(200, Number(limit || 30))))
    .all();
  return rows.results || [];
}

function qingyiRefreshExpiresAt(payload = {}) {
  const expiresAt = String(payload.token_expires_at || payload.expires_at || "").trim();
  if (expiresAt) return expiresAt;
  const expiresIn = Number(payload.expires_in || payload.expiresIn || 0);
  if (Number.isFinite(expiresIn) && expiresIn > 0) {
    return new Date(Date.now() + expiresIn * 1000).toISOString();
  }
  return "";
}

async function tryRefreshQingyiAuth(env, workspaceId, site, context = {}) {
  if (resolveSiteFamily(site) !== "qingyi") {
    return { ok: false, status: null, message: "not qingyi family", auth_refreshed: false };
  }
  const refreshToken = String(site.credentials?.refresh_token || "").trim();
  if (!refreshToken) {
    await recordAuthRefreshHistory(env, workspaceId, site.id, {
      ok: false,
      http_status: null,
      source_endpoint: "/auth/refresh",
      message: `missing refresh_token${context.reason ? ` | ${context.reason}` : ""}`,
    });
    return { ok: false, status: null, message: "missing refresh_token", auth_refreshed: false };
  }

  const url = `${site.base_url}/auth/refresh`;
  const traceId = randomId().slice(0, 16);
  const start = Date.now();
  let status = null;
  let bodyText = "";
  let payload = null;
  let message = "";
  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: {
        ...siteHeaders(site),
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    status = resp.status;
    bodyText = await resp.text();
    const contentType = String(resp.headers.get("content-type") || "").toLowerCase();
    try {
      payload = bodyText ? JSON.parse(bodyText) : null;
    } catch (_) {
      payload = null;
    }
    const htmlLike = !payload && (contentType.includes("text/html") || /^\s*</.test(bodyText || ""));
    if (htmlLike) {
      const html = String(bodyText || "").toLowerCase();
      if (html.includes("_guard/auto.js") || html.includes("turnstile") || html.includes("challenge") || html.includes("cf-chl")) {
        message = "refresh endpoint returned challenge page (html)";
      } else {
        message = "refresh endpoint returned html shell (expected json)";
      }
    } else {
      message = pickMessage(payload, bodyText.slice(0, 300));
    }
  } catch (err) {
    message = `network error: ${String(err?.message || err)}`;
  }

  await insertSystemLog(env, {
    workspace_id: workspaceId,
    site_id: site.id,
    trace_id: traceId,
    method: "POST",
    path: "/auth/refresh",
    status,
    elapsed_ms: Date.now() - start,
    ok: status >= 200 && status < 300 && !!payload,
    message,
  });

  if (!(status >= 200 && status < 300) || !payload) {
    await recordAuthRefreshHistory(env, workspaceId, site.id, {
      ok: false,
      http_status: status,
      source_endpoint: "/auth/refresh",
      message: message || context.reason || "refresh failed",
    });
    return { ok: false, status, message: message || "refresh failed", auth_refreshed: false };
  }

  const data = (payload && (payload.data || payload)) || {};
  const newAuth = String(data.access_token || data.auth_token || data.token || "").trim();
  const newRefresh = String(data.refresh_token || "").trim() || refreshToken;
  if (!newAuth) {
    const noTokenMsg = "refresh succeeded but no access_token returned";
    await recordAuthRefreshHistory(env, workspaceId, site.id, {
      ok: false,
      http_status: status,
      source_endpoint: "/auth/refresh",
      message: noTokenMsg,
    });
    return { ok: false, status, message: noTokenMsg, auth_refreshed: false };
  }

  site.credentials = {
    ...(site.credentials || {}),
    auth_token: newAuth,
    refresh_token: newRefresh,
    token_expires_at: qingyiRefreshExpiresAt(data),
  };
  await dbSaveSite(env, workspaceId, site);
  await recordAuthRefreshHistory(env, workspaceId, site.id, {
    ok: true,
    http_status: status,
    source_endpoint: "/auth/refresh",
    message: context.reason ? `refreshed via ${context.reason}` : "refreshed",
  });
  return {
    ok: true,
    status,
    message: message || "refreshed",
    auth_refreshed: true,
    refreshed_credentials: {
      token_expires_at: site.credentials.token_expires_at || "",
    },
  };
}

async function siteRequest(env, workspaceId, site, method, path, options = {}) {
  const traceId = randomId().slice(0, 16);
  const start = Date.now();
  const timeoutMs = options.timeout_ms || API_TIMEOUT_MS;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort("timeout"), timeoutMs);
  const url = path.startsWith("http://") || path.startsWith("https://") ? path : `${site.base_url}${path}`;
  let status = null;
  let bodyText = "";
  let payload = null;
  let okResp = false;
  let message = "";
  let authRefreshed = false;

  const doFetch = async () => {
    const resp = await fetch(url, {
      method,
      headers: {
        ...siteHeaders(site),
        ...(options.headers || {}),
        ...(options.json_body ? { "Content-Type": "application/json" } : {}),
      },
      body: options.json_body ? JSON.stringify(options.json_body) : undefined,
      signal: controller.signal,
    });
    return resp;
  };

  try {
    const parseResponse = async (resp) => {
      status = resp.status;
      bodyText = await resp.text();
      const contentType = String(resp.headers.get("content-type") || "").toLowerCase();
      try {
        payload = bodyText ? JSON.parse(bodyText) : null;
      } catch (_) {
        payload = null;
      }
      const htmlLike = !payload && (contentType.includes("text/html") || /^\s*</.test(bodyText || ""));
      if (htmlLike) {
        const t = String(bodyText || "").toLowerCase();
        if (t.includes("_guard/auto.js") || t.includes("turnstile") || t.includes("challenge") || t.includes("cf-chl")) {
          message = "site challenge page returned (html)";
        } else {
          message = "unexpected html response (expected json)";
        }
        okResp = false;
      } else {
        message = pickMessage(payload, bodyText.slice(0, 300));
        okResp = status >= 200 && status < 400;
      }
    };

    let resp = await doFetch();
    await parseResponse(resp);

    const qingyiExpired =
      resolveSiteFamily(site) === "qingyi" &&
      !options.skip_auth_refresh &&
      method === "GET" &&
      Number(status) === 401 &&
      /token has expired|expired|invalid refresh|unauthorized/i.test(String(message || bodyText || ""));

    if (qingyiExpired) {
      const refreshed = await tryRefreshQingyiAuth(env, workspaceId, site, { reason: path });
      if (refreshed.ok) {
        authRefreshed = true;
        resp = await doFetch();
        await parseResponse(resp);
      }
    }
  } catch (err) {
    message = `network error: ${String((err && err.message) || err)}`;
  } finally {
    clearTimeout(timer);
  }

  await insertSystemLog(env, {
    workspace_id: workspaceId,
    site_id: site.id,
    trace_id: traceId,
    method,
    path: new URL(url).pathname,
    status,
    elapsed_ms: Date.now() - start,
    ok: okResp,
    message,
  });

  return { status, payload, message, ok: okResp, text: bodyText, trace_id: traceId, auth_refreshed: authRefreshed };
}

async function probeSite(baseUrl) {
  const normalized = normalizeBaseUrl(baseUrl);
  const tests = [
    { adapter: "onetoken", path: "/api/v1/users/me" },
    { adapter: "onetoken", path: "/api/v1/wallet/balance" },
    { adapter: "qingyi", path: "/keys" },
    { adapter: "qingyi", path: "/user/profile" },
    { adapter: "qingyi", path: "/api/v1/checkin/status" },
    { adapter: "new_api", path: "/api/user/self" },
    { adapter: "new_api", path: "/api/token/?p=1&size=1" },
    { adapter: "new_api", path: `/api/user/checkin?month=${monthNow()}` },
    { adapter: "new_api", path: "/v1/dashboard/billing/subscription" },
  ];

  let reachable = false;
  let guess = "unknown";
  let message = "";

  for (const t of tests) {
    try {
      const resp = await fetch(`${normalized}${t.path}`, { method: "GET" });
      reachable = true;
      const contentType = String(resp.headers.get("content-type") || "").toLowerCase();
      const isHtml = contentType.includes("text/html");
      if (resp.status !== 404 && !isHtml) {
        guess = t.adapter;
        message = `detected by ${t.path} (status ${resp.status})`;
        break;
      }
      if (resp.status !== 404 && isHtml) {
        message = `reachable but ${t.path} returned html page`;
      } else {
        message = `reachable but ${t.path} returned 404`;
      }
    } catch (err) {
      message = String((err && err.message) || err);
    }
  }

  if (guess === "unknown") {
    const host = new URL(normalized).hostname.toLowerCase();
    if (host.includes("lamclod") || host.includes("gettoken")) {
      guess = "auth_shell";
      message = message || "fallback by auth-shell hostname pattern";
    } else
    if (host.includes("onetoken")) {
      guess = "onetoken";
      message = message || "fallback by hostname pattern";
    } else if (host.includes("newapi") || host.includes("oneapi")) {
      guess = "new_api";
      message = message || "fallback by hostname pattern";
    } else if (host.includes("qingyi")) {
      guess = "qingyi";
      message = message || "fallback by hostname pattern";
    }
  }

  return {
    base_url: normalized,
    reachable,
    adapter_guess: guess,
    message,
  };
}

function normalizeExtract(adapter, extract) {
  if (!extract || typeof extract !== "object") {
    throw new Error("缺少提取结果 extract_result");
  }
  if (adapter === "onetoken") {
    const token = String(
      pickOpenClawAccessToken(extract) || extract.accessToken || extract.access_token || extract.token || extract.auth_token || ""
    ).trim();
    const cookie = String(extract.cookie || "").trim();
    if (!token && !cookie) throw new Error("未提取到 OneToken openclaw_auth.accessToken 或 cookie");
    return {
      token,
      cookie,
      new_api_user: String(extract.new_api_user || extract.user_id || "").trim(),
    };
  }
  if (adapter === "qingyi") {
    const auth = String(extract.auth_token || extract.token || extract.access_token || "").trim();
    const refresh = String(extract.refresh_token || extract.refresh || "").trim();
    if (!auth && !refresh) throw new Error("未提取到 auth_token / refresh_token");
    return {
      auth_token: auth,
      refresh_token: refresh,
      token_expires_at: String(extract.token_expires_at || extract.expires_at || "").trim(),
      cookie: String(extract.cookie || "").trim(),
    };
  }

  if (adapter === "auth_shell") {
    const token = String(extract.token || extract.auth_token || extract.access_token || "").trim();
    const cookie = String(extract.cookie || "").trim();
    const session = String(extract.session || extract.session_token || "").trim();
    if (!token && !cookie && !session) throw new Error("未提取到 auth_shell 的 token / cookie / session");
    return {
      token,
      cookie: cookie || (session ? `session_token=${session}` : ""),
      session,
      new_api_user: String(extract.new_api_user || extract.user_id || "").trim(),
    };
  }

  const token = String(extract.token || extract.auth_token || extract.access_token || "").trim();
  const cookie = String(extract.cookie || "").trim();
  if (!token && !cookie) throw new Error("未提取到 token 或 cookie");
  return {
    token,
    cookie,
    new_api_user: String(extract.new_api_user || extract.user_id || "").trim(),
  };
}

async function fetchModelCatalog(env, workspaceId, site) {
  const family = resolveSiteFamily(site);
  const merged = new Map();
  const sources = [];
  const diagnostics = [];
  if (family === "auth_shell") {
    return {
      source: "",
      diagnostics: [
        {
          type: "model_catalog",
          path: "auth_shell",
          status: null,
          ok: false,
          parsed_count: 0,
          priced_count: 0,
          message: "协议待确认：需要先完成 Edge 登录态桥接和控制台入口识别，再判断是否开放模型目录",
          diagnostic_reason: "adapter_gap",
        },
      ],
      items: [],
      byId: new Map(),
    };
  }

  const orderedPaths =
    family === "new_api"
      ? [
          { type: "pricing", path: "/api/pricing", timeout_ms: 6000, stop_on_priced: true },
          { type: "model_catalog", path: "/api/models", timeout_ms: 35000, stop_on_models: true },
          { type: "model_catalog", path: "/api/user/groups", timeout_ms: 4500 },
        ]
      : family === "qingyi"
        ? [
            { type: "model_catalog", path: "/channels/available", timeout_ms: 6000, stop_on_priced: true, stop_on_models: true },
            { type: "model_catalog", path: "/groups/available", timeout_ms: 4500, stop_on_models: true },
            { type: "pricing", path: "/groups/rates", timeout_ms: 4500, stop_on_priced: true },
            { type: "model_catalog", path: "/usage/dashboard/models", timeout_ms: 4500, stop_on_priced: true, stop_on_models: true },
            { type: "model_catalog", path: "/api/v1/models", timeout_ms: 4500, stop_on_models: true },
          ]
        : [
            { type: "model_catalog", path: "https://router.onetoken.sh/v1/models", timeout_ms: 8000, stop_on_models: true },
            { type: "model_catalog", path: "/v1/models", timeout_ms: 4500, stop_on_models: true },
            { type: "pricing", path: "/api/v1/pricing", timeout_ms: 4500, stop_on_priced: true },
          ];

  const addModels = (models, source) => {
    if (!models.length) return;
    sources.push(source);
    for (const model of models) {
      const id = String(model.id || model.name || "").trim();
      if (!id) continue;
      const current = merged.get(id);
      const sourceFields = Array.from(new Set([...(model.source_fields || []), `api:${source}`]));
      if (!current) {
        merged.set(id, { ...model, source_fields: sourceFields });
        continue;
      }
      const pricing = mergePricing(current.pricing || {}, model.pricing || {});
      merged.set(id, {
        ...current,
        name: current.name || model.name || id,
        pricing,
        source_fields: Array.from(new Set([...(current.source_fields || []), ...sourceFields])),
      });
    }
  };

  let requestCount = 0;
  const maxCatalogRequests = family === "new_api" ? 3 : family === "qingyi" ? 5 : 3;
  for (const entry of orderedPaths) {
    if (requestCount >= maxCatalogRequests) {
      diagnostics.push({
        type: entry.type,
        path: entry.path,
        status: null,
        ok: false,
        parsed_count: 0,
        priced_count: 0,
        message: "模型探测预算已用完，已停止后续候选接口",
      });
      break;
    }
    requestCount += 1;
    const r = await siteRequest(env, workspaceId, site, "GET", entry.path, { timeout_ms: entry.timeout_ms || 4500 });
    const models = r.ok ? normalizeModelCatalogItems(r.payload) : [];
    const pricedModels = models.filter((m) => hasPricingValue(m.pricing || {}));
    diagnostics.push({
      type: entry.type,
      path: entry.path,
      status: r.status,
      ok: r.ok,
      auth_refreshed: Boolean(r.auth_refreshed),
      parsed_count: models.length,
      priced_count: pricedModels.length,
      message:
        r.message ||
        (family === "onetoken" && (Number(r.status) === 401 || Number(r.status) === 403)
          ? "模型目录受 Router Key / token 权限限制"
          : family === "onetoken" && !models.length
            ? "Router 未公开模型目录或当前 Router Key 权限不足"
            : ""),
    });
    if (isProbeBudgetErrorMessage(r.message) || /html|challenge|expected json/i.test(String(r.message || ""))) {
      break;
    }
    if (!r.ok) continue;
    if (!models.length) continue;
    addModels(models, entry.path);
    if ((entry.stop_on_priced && pricedModels.length) || (entry.stop_on_models && models.length && family !== "new_api")) {
      break;
    }
    if (family === "new_api" && entry.path === "/api/models" && merged.size) {
      continue;
    }
  }

  const items = Array.from(merged.values());
  return {
    source: sources.join(" + "),
    diagnostics,
    items,
    byId: new Map(items.map((m) => [m.id, m])),
  };
}

function toModelViewItem(model) {
  const pricing = model?.pricing || {};
  const effectiveText = formatPricingText(pricing);
  const priceInfo = classifyPriceSource(model.source_fields || [], pricing);
  return {
    id: model.id,
    name: model.name || model.id,
    platform: String(model.platform || ""),
    billing_mode: String(pricing.billing_mode || pricing.mode || ""),
    model_ratio: pricing.model_ratio == null ? null : pricing.model_ratio,
    group_ratio: pricing.group_ratio == null ? null : pricing.group_ratio,
    user_group_ratio: pricing.user_group_ratio == null ? null : pricing.user_group_ratio,
    completion_ratio: pricing.completion_ratio == null ? null : pricing.completion_ratio,
    cache_ratio: pricing.cache_ratio == null ? null : pricing.cache_ratio,
    fixed_price: pricing.model_price == null ? null : pricing.model_price,
    model_price_unit: pricing.model_price_unit || pricing.unit || "",
    quota_type: pricing.quota_type || "",
    input_price: pricing.input_price == null ? null : pricing.input_price,
    output_price: pricing.output_price == null ? null : pricing.output_price,
    cached_price: pricing.cached_price == null ? null : pricing.cached_price,
    cache_read_price: pricing.cache_read_price == null ? null : pricing.cache_read_price,
    cache_write_price: pricing.cache_write_price == null ? null : pricing.cache_write_price,
    per_request_price: pricing.per_request_price == null ? null : pricing.per_request_price,
    price: pricing.price == null ? null : pricing.price,
    price_text: effectiveText,
    effective_price_text: effectiveText === "-" ? "未提供" : effectiveText,
    source_fields: model.source_fields || [],
    source_level:
      (model.source_fields || []).some((x) => String(x).includes("frontend-confirmed"))
        ? "frontend-confirmed"
        : (model.source_fields || []).some((x) => String(x).includes("pricing"))
          ? "official-api"
          : (model.source_fields || []).some((x) => String(x).includes("channel:"))
            ? "bundle-derived"
            : "compat-probe",
    price_confidence: priceInfo.price_confidence,
    price_source: priceInfo.price_source,
    missing_price_reason: priceInfo.missing_price_reason,
    price_rank:
      priceInfo.price_confidence === "high"
        ? 1
        : priceInfo.price_confidence === "medium"
          ? 2
          : priceInfo.price_confidence === "mapping_only"
            ? 4
            : 5,
    diagnostic_reason: priceInfo.missing_price_reason || priceInfo.price_source,
    diagnostic_sources: model.source_fields || [],
    pricing,
  };
}

async function getSiteModelsView(env, workspaceId, site) {
  const catalog = await fetchModelCatalog(env, workspaceId, site);
  return {
    source: catalog.source,
    family: resolveSiteFamily(site),
    cached_at: nowIso(),
    cache_status: "fresh",
    diagnostics: catalog.diagnostics || [],
    items: catalog.items.map((item) => toModelViewItem(item)),
  };
}

function summarizeModelCache(modelsView) {
  const items = modelsView?.items || [];
  return {
    cached_at: modelsView?.cached_at || nowIso(),
    cache_status: modelsView?.cache_status || "fresh",
    source: modelsView?.source || "",
    model_count: items.length,
    priced_count: items.filter((x) => hasPricingValue(x.pricing || x)).length,
    missing_count: items.filter((x) => !hasPricingValue(x.pricing || x)).length,
    diagnostics: (modelsView?.diagnostics || []).slice(0, 20),
  };
}

function attachGroupModels(group, catalogById) {
  const pricingMap = group.model_price_map || {};
  let modelSet = new Set([...(group.model_ids || []), ...Object.keys(pricingMap)]);
  const hasOnlyNumericIds = modelSet.size > 0 && Array.from(modelSet).every((x) => /^\d+$/.test(String(x || "")));
  const mappingType = hasOnlyNumericIds ? "channel" : "model";
  const mappingIds = Array.from(modelSet).map((x) => String(x || "")).filter(Boolean);
  if (mappingType !== "model" && catalogById.size) {
    modelSet = new Set(catalogById.keys());
  }
  if (!modelSet.size && catalogById.size) {
    for (const modelId of catalogById.keys()) modelSet.add(modelId);
  }
  const models = Array.from(modelSet)
    .map((modelId) => {
      const id = String(modelId || "").trim();
      if (!id) return null;
      const catalog = catalogById.get(id);
      const directPricing = normalizePriceEntry(pricingMap[id]);
      const pricing =
        mappingType !== "model"
          ? {
              ...mergePricing(catalog?.pricing || {}, directPricing),
              quota_type: directPricing.quota_type || catalog?.pricing?.quota_type || mappingType,
            }
          :
        directPricing.price != null ||
        directPricing.model_ratio != null ||
        directPricing.group_ratio != null ||
        directPricing.user_group_ratio != null ||
        directPricing.completion_ratio != null ||
        directPricing.cache_ratio != null ||
        directPricing.model_price != null ||
        directPricing.input_price != null ||
        directPricing.output_price != null ||
        directPricing.cached_price != null
          ? directPricing
          : catalog?.pricing || {};
      const effectiveText = formatPricingText(pricing);
      const sourceFields = [
        ...(catalog?.source_fields || []),
        ...(Object.keys(pricingMap).length ? ["group_price_map"] : []),
        mappingType !== "model" ? `${mappingType}_mapping` : "",
      ].filter(Boolean);
      const priceInfo = classifyPriceSource(sourceFields, pricing);
      return {
        id,
        name: mappingType === "model" ? catalog?.name || id : `映射 ${id}`,
        mapping_type: mappingType,
        platform: catalog?.platform || "",
        billing_mode: String((pricing && (pricing.billing_mode || pricing.mode)) || ""),
        model_ratio: pricing.model_ratio == null ? null : pricing.model_ratio,
        group_ratio: pricing.group_ratio == null ? null : pricing.group_ratio,
        user_group_ratio: pricing.user_group_ratio == null ? null : pricing.user_group_ratio,
        completion_ratio: pricing.completion_ratio == null ? null : pricing.completion_ratio,
        cache_ratio: pricing.cache_ratio == null ? null : pricing.cache_ratio,
        fixed_price: pricing.model_price == null ? null : pricing.model_price,
        model_price_unit: pricing.model_price_unit || pricing.unit || "",
        quota_type: pricing.quota_type || "",
        input_price: pricing.input_price == null ? null : pricing.input_price,
        output_price: pricing.output_price == null ? null : pricing.output_price,
        cached_price: pricing.cached_price == null ? null : pricing.cached_price,
        cache_read_price: pricing.cache_read_price == null ? null : pricing.cache_read_price,
        cache_write_price: pricing.cache_write_price == null ? null : pricing.cache_write_price,
        per_request_price: pricing.per_request_price == null ? null : pricing.per_request_price,
        price: pricing.price == null ? null : pricing.price,
        pricing,
        price_text: effectiveText,
        effective_price_text: mappingType === "model" ? (effectiveText === "-" ? "未提供" : effectiveText) : "渠道/账号映射，模型由目录补全",
        source_fields: sourceFields,
        price_confidence: mappingType === "model" ? priceInfo.price_confidence : "mapping_only",
        price_source: mappingType === "model" ? priceInfo.price_source : "渠道映射",
        missing_price_reason: mappingType === "model" ? priceInfo.missing_price_reason : "该分组只返回数字渠道/账号 ID，不是模型计价字段",
        price_rank: mappingType === "model" ? (priceInfo.price_confidence === "high" ? 1 : priceInfo.price_confidence === "medium" ? 2 : 5) : 4,
        diagnostic_reason: mappingType === "model" ? priceInfo.missing_price_reason || priceInfo.price_source : "渠道/账号映射由模型目录补全",
        mapping_ids: mappingIds.slice(0, 30),
      };
    })
    .filter(Boolean);

  return {
    id: group.id,
    name: group.name,
    mapping_type: mappingType,
    group_ratio: group.group_ratio == null ? null : group.group_ratio,
    group_desc: group.group_desc || "",
    mapping_ids: mappingIds.slice(0, 30),
    supported_models: Array.isArray(group.supported_models) ? group.supported_models.slice(0, 200) : [],
    pricing_source: group.pricing_source || "",
    model_count: models.length,
    models,
  };
}

async function getKeyGroups(env, workspaceId, site) {
  const family = resolveSiteFamily(site);
  const candidates =
    family === "new_api"
      ? ["/api/group/?p=1&size=200", "/api/group", "/api/groups", "/api/user/group", "/api/user/groups"]
      : family === "qingyi"
        ? ["/groups/available", "/groups/rates", "/api/v1/groups", "/api/v1/group", "/api/group", "/api/groups"]
        : ["/api/v1/groups", "/api/v1/group", "/api/group", "/api/groups"];

  const catalog = await fetchModelCatalog(env, workspaceId, site);

  for (const p of candidates) {
    const r = await siteRequest(env, workspaceId, site, "GET", p, { timeout_ms: 3500 });
    if (!r.ok) continue;
    const groups = normalizeGroupItems(r.payload);
    if (!groups.length) continue;
    return {
      source: p,
      model_source: catalog.source,
      items: groups.map((g) => attachGroupModels(g, catalog.byId)),
    };
  }

  try {
    const keyItems = await listKeys(env, workspaceId, site, 4000);
    const groupSet = new Set(
      keyItems
        .map((k) => String(k.group || "").trim())
        .filter(Boolean)
    );
    if (!groupSet.size && family === "new_api") groupSet.add("default");
    const inferred = Array.from(groupSet).map((g) =>
      attachGroupModels(
        {
          id: g,
          name: g,
          model_ids: [],
          model_price_map: {},
        },
        catalog.byId
      )
    );
    if (inferred.length) {
      return {
        source: "inferred-from-keys",
        model_source: catalog.source,
        items: inferred,
      };
    }
  } catch (_) {
    // ignore fallback failure
  }

  if (family === "new_api" && catalog.items.length) {
    return {
      source: "catalog-default",
      model_source: catalog.source,
      items: [
        attachGroupModels(
          {
            id: "default",
            name: "default",
            model_ids: [],
            model_price_map: {},
          },
          catalog.byId
        ),
      ],
    };
  }

  return {
    source: "",
    model_source: catalog.source,
    items: [],
  };
}

function pickBestKey(items, preferred) {
  if (!items.length) return null;
  const wanted = String(preferred || "").trim().toLowerCase();
  if (wanted) {
    const matched = items.find((x) => String(x.name || "").toLowerCase().includes(wanted));
    if (matched) return matched;
  }
  const active = items.find((x) => [1, "1", true, "enabled", "active", "on"].includes(String(x.status || "").toLowerCase()));
  return active || items[0];
}

async function listKeys(env, workspaceId, site, timeoutMs = 10000) {
  const family = resolveSiteFamily(site);
  if (family === "onetoken") {
    const r = await siteRequest(env, workspaceId, site, "GET", "/api/v1/users/me/token-key", { timeout_ms: timeoutMs });
    if (!r.ok) {
      throw new Error(r.message || "获取 OneToken Key 失败");
    }
    const data = (r.payload && (r.payload.data || r.payload)) || {};
    const key = String(data.key || data.token_key || data.token || data.api_key || "").trim();
    return key
      ? [
          {
            id: "onetoken-router",
            name: "OneToken Router Key",
            status: "active",
            group: "router",
            key_masked: maskSecret(key),
            key_revealable: true,
            raw_key: key,
            created_at: null,
          },
        ]
      : [];
  }

  if (family === "qingyi") {
    const r = await siteRequest(env, workspaceId, site, "GET", "/keys", { timeout_ms: timeoutMs });
    if (!r.ok) {
      throw new Error(r.message || "获取 API Key 列表失败");
    }
    const items = parseDataItems(r.payload).map((x) => ({
      id: x.id,
      name: String(x.name || ""),
      status: x.status,
      group: String(x.group || x.group_name || ""),
      key_masked: maskSecret(String(x.key || "")),
      key_revealable: Boolean(String(x.key || "").trim()),
      raw_key: String(x.key || ""),
      created_at: x.created_at || x.create_time || null,
    }));
    return items;
  }

  const r = await siteRequest(env, workspaceId, site, "GET", "/api/token/?p=1&size=100", { timeout_ms: timeoutMs });
  if (!r.ok) {
    throw new Error(r.message || "获取 Token 列表失败");
  }
  const items = parseDataItems(r.payload).map((x) => ({
    id: x.id,
    name: String(x.name || ""),
    status: x.status,
    group: String(x.group || x.role || ""),
    key_masked: String(x.key || ""),
    key_revealable: Number.isInteger(x.id),
    raw_key: "",
    created_at: x.created_at || x.accessed_time || null,
  }));
  return items;
}

async function extractExistingKey(env, workspaceId, site, preferredName = "") {
  const items = await listKeys(env, workspaceId, site);
  if (!items.length) throw new Error("当前站点没有可用 Key");
  const picked = pickBestKey(items, preferredName);
  if (!picked) throw new Error("未找到可用 Key");

  const family = resolveSiteFamily(site);
  if (family === "onetoken") {
    if (!picked.raw_key || picked.raw_key.includes("*")) {
      throw new Error("site returned masked OneToken key only, cannot reveal full key");
    }
    return {
      source: "existing",
      id: picked.id,
      name: picked.name,
      group: picked.group,
      key: picked.raw_key,
      key_masked: maskSecret(picked.raw_key),
    };
  }

  if (family === "qingyi") {
    if (!picked.raw_key || picked.raw_key.includes("*")) {
      throw new Error("site returned masked key only, cannot reveal full key");
    }
    return {
      source: "existing",
      id: picked.id,
      name: picked.name,
      group: picked.group,
      key: picked.raw_key,
      key_masked: maskSecret(picked.raw_key),
    };
  }

  if (!Number.isInteger(picked.id)) throw new Error("invalid token id, cannot extract full key");
  const r = await siteRequest(env, workspaceId, site, "GET", `/api/token/${picked.id}/key`, { timeout_ms: 10000 });
  if (!(r.status >= 200 && r.status < 300)) {
    throw new Error(r.message || "提取 Key 失败");
  }
  const data = r.payload && (r.payload.data || r.payload);
  const key = String((data && data.key) || "").trim();
  if (!key) throw new Error("服务端未返回明文 Key");

  return {
    source: "existing",
    id: picked.id,
    name: picked.name,
    group: picked.group,
    key,
    key_masked: maskSecret(key),
  };
}

async function createNewKey(env, workspaceId, site, name, group) {
  const keyName = String(name || `checkin-${Date.now()}`).trim() || `checkin-${Date.now()}`;

  const family = resolveSiteFamily(site);
  if (family === "onetoken") {
    throw new Error("OneToken 使用用户级 Router Key，暂不支持创建多个站内 Key；请使用提取Key");
  }

  if (family === "qingyi") {
    const body = group ? { name: keyName, group } : { name: keyName };
    const r = await siteRequest(env, workspaceId, site, "POST", "/keys", { json_body: body, timeout_ms: 12000 });
    if (!(r.status >= 200 && r.status < 300)) {
      throw new Error(r.message || "创建 Key 失败");
    }
    const data = (r.payload && (r.payload.data || r.payload)) || {};
    const key = String(data.key || "").trim();
    if (!key) throw new Error("创建成功但未返回明文 Key");
    return {
      source: "created",
      id: data.id || null,
      name: String(data.name || keyName),
      group: String(data.group || group || ""),
      key,
      key_masked: maskSecret(key),
    };
  }

  const createBody = group ? { name: keyName, group } : { name: keyName };
  const created = await siteRequest(env, workspaceId, site, "POST", "/api/token/", {
    json_body: createBody,
    timeout_ms: 12000,
  });
  if (!(created.status >= 200 && created.status < 300)) {
    throw new Error(created.message || "创建 Key 失败");
  }

  let tokenId = null;
  const cData = (created.payload && (created.payload.data || created.payload)) || {};
  if (Number.isInteger(cData.id)) tokenId = cData.id;

  if (!tokenId) {
    const listed = await listKeys(env, workspaceId, site);
    const match = listed.find((x) => x.name === keyName) || listed[0];
    tokenId = match && Number.isInteger(match.id) ? match.id : null;
  }
  if (!tokenId) throw new Error("创建成功但未拿到 token id");

  const r = await siteRequest(env, workspaceId, site, "GET", `/api/token/${tokenId}/key`, { timeout_ms: 10000 });
  if (!(r.status >= 200 && r.status < 300)) {
    throw new Error(r.message || "创建后提取 Key 失败");
  }
  const data = r.payload && (r.payload.data || r.payload);
  const key = String((data && data.key) || "").trim();
  if (!key) throw new Error("创建成功但未返回明文 Key");

  return {
    source: "created",
    id: tokenId,
    name: keyName,
    group: group || "",
    key,
    key_masked: maskSecret(key),
  };
}

async function probeCapabilities(env, workspaceId, site) {
  const family = resolveSiteFamily(site);
  const now = nowIso();
  const cap = {
    family,
    can_checkin: false,
    can_manage_token: false,
    can_manage_channel: false,
    can_read_quota: false,
    can_read_models: false,
    can_read_usage: false,
    api_base_url_guess: `${site.base_url}/v1`,
    reason: "",
    last_probe_at: now,
    probe_errors: [],
  };
  const probeMeta = {};
  const capabilityVerdicts = {};
  let quotaSnapshot = null;
  let profileResult = { profile: {}, profile_source: "", profile_errors: [], shell_detection: null };
  let requestsUsed = 0;
  let budgetExhausted = false;
  const requestProbe = async (path, options = {}) => {
    if (requestsUsed >= PROBE_REQUEST_BUDGET) {
      budgetExhausted = true;
      return {
        status: null,
        payload: null,
        message: "probe budget exhausted",
        ok: false,
        text: "",
        trace_id: "",
        auth_refreshed: false,
        budget_exhausted: true,
      };
    }
    requestsUsed += 1;
    const r = await siteRequest(env, workspaceId, site, "GET", path, options);
    if (isProbeBudgetErrorMessage(r.message)) budgetExhausted = true;
    return r;
  };

  if (family === "auth_shell") {
    try {
      profileResult = await fetchSiteProfile(env, workspaceId, site);
    } catch (err) {
      cap.probe_errors.push(`profile: ${String(err?.message || err)}`);
    }
    const shellDetection = profileResult.shell_detection || {
      shell_type: detectSiteShellType(site),
      title: "",
      canonical: "",
      console_entrypoints: [],
      has_login_overlay: false,
    };
    const entryCandidates = Array.from(new Set([...(shellDetection.console_entrypoints || []), "/console", "/dashboard"])).slice(0, 4);
    const consoleHits = [];
    for (const path of entryCandidates) {
      const r = await requestProbe(path, { timeout_ms: 4000 });
      probeMeta[path] = { status: r.status, ok: r.ok, message: r.message, auth_refreshed: Boolean(r.auth_refreshed), source_level: "frontend-confirmed" };
      if (r.status && r.status < 500) {
        consoleHits.push({ path, status: r.status, message: r.message });
      }
    }
    cap.can_manage_token = hasAuthMaterial(site);
    const adapterVerdict = consoleHits.length
      ? {
          verdict: "supported",
          evidence_path: consoleHits[0].path,
          http_status: consoleHits[0].status,
          auth_refreshed: false,
          parse_count: consoleHits.length,
          confidence: "high",
          next_action: "控制台入口可达，继续使用 Edge 登录态桥接识别真实 API 能力",
          source_level: "frontend-confirmed",
          title: "控制台入口",
        }
      : {
          verdict: "adapter_gap",
          evidence_path: "",
          http_status: null,
          auth_refreshed: false,
          parse_count: 0,
          confidence: "medium",
          next_action: "先在 Edge 中完成登录和授权回跳，再重新执行轻量探测",
          source_level: "frontend-confirmed",
          title: "控制台入口",
        };
    capabilityVerdicts.can_manage_token = {
      ...adapterVerdict,
      title: "登录态材料",
      verdict: hasAuthMaterial(site) ? "supported" : "auth_failed",
      next_action: hasAuthMaterial(site) ? "已提取浏览器会话，可继续验证控制台/API能力" : "需要先从 Edge 中提取 cookie/token/session",
    };
    capabilityVerdicts.can_manage_channel = adapterVerdict;
    capabilityVerdicts.can_read_models = { ...adapterVerdict, title: "模型能力", verdict: "adapter_gap", next_action: "当前先识别站内控制台，再确认是否开放模型/API目录" };
    capabilityVerdicts.can_read_usage = { ...adapterVerdict, title: "Usage 能力", verdict: "adapter_gap", next_action: "先确认控制台后端协议，再决定是否支持 Usage 接口" };
    capabilityVerdicts.can_checkin = { ...adapterVerdict, title: "签到能力", verdict: "adapter_gap", next_action: "这类站点优先确认控制台/API能力，签到能力需后续验证" };
    capabilityVerdicts.can_read_quota = { ...adapterVerdict, title: "额度能力", verdict: "adapter_gap", next_action: "先确认是否存在额度接口；当前不再直接按 new_api 误探" };
    probeMeta.shell_detection = shellDetection;
    probeMeta.console_entrypoints = entryCandidates;
    probeMeta.transport_chain = {
      state: shellDetection.shell_type === "oidc_console" ? "oidc_pending_callback" : "console_session_detected",
      title: shellDetection.title || "",
      canonical: shellDetection.canonical || "",
      console_entrypoints: entryCandidates,
    };
  } else {
    const matrix =
      family === "qingyi"
        ? {
            can_checkin: [{ path: "/api/v1/checkin/status", source_level: "compat-probe", title: "签到状态" }],
            can_manage_token: [{ path: "/keys", source_level: "frontend-confirmed", title: "Key 管理" }],
            can_manage_channel: [{ path: "/channels/available", source_level: "frontend-confirmed", title: "渠道列表" }],
            can_read_models: [
              { path: "/channels/available", source_level: "frontend-confirmed", title: "可用渠道" },
              { path: "/groups/available", source_level: "frontend-confirmed", title: "可用分组" },
            ],
            can_read_usage: [
              { path: "/usage", source_level: "frontend-confirmed", title: "Usage 列表" },
              { path: "/usage/stats", source_level: "frontend-confirmed", title: "Usage 统计" },
            ],
          }
        : family === "onetoken"
          ? {
              can_checkin: [],
              can_manage_token: [{ path: "/api/v1/users/me/token-key", source_level: "official-api", title: "Router Key" }],
              can_manage_channel: [],
              can_read_models: [{ path: "https://router.onetoken.sh/v1/models", source_level: "official-api", title: "Router 模型目录" }],
              can_read_usage: [{ path: "/api/v1/token/usage", source_level: "official-api", title: "Token 用量" }],
            }
          : {
              can_checkin: [{ path: `/api/user/checkin?month=${monthNow()}`, source_level: "official-api", title: "签到状态" }],
              can_manage_token: [{ path: "/api/token/?p=1&size=1", source_level: "official-api", title: "Token 管理" }],
              can_manage_channel: [{ path: "/api/channel/?p=1&size=1", source_level: "official-api", title: "渠道管理" }],
              can_read_models: [
                { path: "/api/pricing", source_level: "official-api", title: "价格接口" },
                { path: "/api/models", source_level: "official-api", title: "模型目录" },
              ],
              can_read_usage: [{ path: "/api/log/self?p=1&size=1", source_level: "official-api", title: "个人日志" }],
            };

    for (const [key, paths] of Object.entries(matrix)) {
      if (!paths.length) {
        cap[key] = false;
        capabilityVerdicts[key] = {
          verdict: "not_exposed",
          evidence_path: "",
          http_status: null,
          auth_refreshed: false,
          parse_count: 0,
          confidence: "low",
          next_action: "该协议当前未提供此能力",
          source_level: "compat-probe",
          title: key,
        };
        continue;
      }
      let supported = false;
      let bestVerdict = {
        verdict: "not_exposed",
        evidence_path: "",
        http_status: null,
        auth_refreshed: false,
        parse_count: 0,
        confidence: "low",
        next_action: "查看系统日志与协议报告",
        source_level: "compat-probe",
        title: key,
      };
      for (const entry of paths) {
        const path = typeof entry === "string" ? entry : entry.path;
        const sourceLevel = typeof entry === "string" ? "compat-probe" : entry.source_level || "compat-probe";
        const title = typeof entry === "string" ? key : entry.title || key;
        const r = await requestProbe(path, { timeout_ms: 3500 });
        const parseCount = parseDataItems(r.payload).length;
        probeMeta[path] = { status: r.status, ok: r.ok, message: r.message, auth_refreshed: Boolean(r.auth_refreshed), source_level: sourceLevel };
        if (r.ok) {
          supported = true;
          if (!cap.reason) cap.reason = pickMessage(r.payload, r.message);
          bestVerdict = {
            verdict: "supported",
            evidence_path: path,
            http_status: r.status,
            auth_refreshed: Boolean(r.auth_refreshed),
            parse_count: parseCount,
            confidence: sourceLevel === "frontend-confirmed" || sourceLevel === "official-api" ? "high" : "medium",
            next_action: "能力已验证，可继续执行站点任务",
            source_level: sourceLevel,
            title,
          };
          break;
        }
        if ([401, 403].includes(Number(r.status)) && !cap.reason) cap.reason = pickMessage(r.payload, r.message);
        if (!r.status || r.status >= 500 || isProbeBudgetErrorMessage(r.message)) {
          cap.probe_errors.push(`${path}: ${r.message || `status=${r.status}`}`);
        }
        if (isProbeBudgetErrorMessage(r.message)) {
          bestVerdict = {
            verdict: "adapter_gap",
            evidence_path: path,
            http_status: r.status,
            auth_refreshed: Boolean(r.auth_refreshed),
            parse_count: parseCount,
            confidence: "medium",
            next_action: "本次探测预算已耗尽，请改用轻量探测或单项验证",
            source_level: sourceLevel,
            title,
          };
        } else if (/html|challenge|expected json/i.test(String(r.message || ""))) {
          cap.probe_errors.push(`${path}: ${r.message}`);
          bestVerdict = {
            verdict: "auth_failed",
            evidence_path: path,
            http_status: r.status,
            auth_refreshed: Boolean(r.auth_refreshed),
            parse_count: parseCount,
            confidence: sourceLevel === "frontend-confirmed" ? "high" : "medium",
            next_action: "站点返回挑战页/HTML，请在浏览器完成挑战并修复登录态",
            source_level: sourceLevel,
            title,
          };
        } else if ([401, 403].includes(Number(r.status))) {
          bestVerdict = {
            verdict: family === "onetoken" && key === "can_read_models" ? "key_limited" : "auth_failed",
            evidence_path: path,
            http_status: r.status,
            auth_refreshed: Boolean(r.auth_refreshed),
            parse_count: parseCount,
            confidence: sourceLevel === "frontend-confirmed" ? "high" : "medium",
            next_action: "先修复登录态或确认当前账号 / Key 权限",
            source_level: sourceLevel,
            title,
          };
        } else if (Number(r.status) === 404 && bestVerdict.verdict !== "auth_failed") {
          bestVerdict = {
            verdict: sourceLevel === "frontend-confirmed" ? "not_exposed" : "adapter_gap",
            evidence_path: path,
            http_status: r.status,
            auth_refreshed: Boolean(r.auth_refreshed),
            parse_count: parseCount,
            confidence: sourceLevel === "frontend-confirmed" ? "high" : "low",
            next_action: sourceLevel === "frontend-confirmed" ? "站点当前未开放该接口，可按可忽略缺口处理" : "兼容路径失效，查看协议报告确认真实接口",
            source_level: sourceLevel,
            title,
          };
        }
      }
      cap[key] = supported;
      capabilityVerdicts[key] = bestVerdict;
    }

    try {
      quotaSnapshot = await refreshQuota(env, workspaceId, site);
      cap.can_read_quota = quotaSnapshot.quota_status === "available";
      capabilityVerdicts.can_read_quota = {
        verdict: cap.can_read_quota ? "supported" : "not_exposed",
        evidence_path: quotaSnapshot?.quota_source || quotaSnapshot?.source || "",
        http_status: 200,
        auth_refreshed: false,
        parse_count: quotaSnapshot?.balance != null || quotaSnapshot?.display_balance != null ? 1 : 0,
        confidence: "high",
        next_action: cap.can_read_quota ? "额度解析成功，可查看余额换算说明" : "执行检测额度并查看来源接口",
        source_level: family === "qingyi" ? "frontend-confirmed" : "official-api",
        title: "额度读取",
      };
    } catch (err) {
      cap.can_read_quota = false;
      cap.probe_errors.push(`quota: ${String(err?.message || err)}`);
      probeMeta.quota_error_code = err?.code || "";
      capabilityVerdicts.can_read_quota = {
        verdict: err?.code === "auth_failed" ? "auth_failed" : isProbeBudgetErrorMessage(err?.message) ? "adapter_gap" : "not_exposed",
        evidence_path: "",
        http_status: err?.status || null,
        auth_refreshed: false,
        parse_count: 0,
        confidence: "medium",
        next_action: err?.code === "auth_failed" ? "修复登录态后重新检测额度" : "查看额度来源诊断和原始字段",
        source_level: family === "qingyi" ? "frontend-confirmed" : "official-api",
        title: "额度读取",
      };
    }

    try {
      profileResult = await fetchSiteProfile(env, workspaceId, site);
    } catch (err) {
      cap.probe_errors.push(`profile: ${String(err?.message || err)}`);
    }
  }

  probeMeta.probe_budget = {
    limit: PROBE_REQUEST_BUDGET,
    used: requestsUsed,
    status: budgetExhausted ? "probe_budget_exhausted" : "ok",
  };
  probeMeta.shell_detection = probeMeta.shell_detection || profileResult.shell_detection || null;
  probeMeta.console_entrypoints = probeMeta.console_entrypoints || profileResult?.shell_detection?.console_entrypoints || [];
  probeMeta.transport_chain = probeMeta.transport_chain || {
    state: family === "auth_shell" ? detectSiteShellType(site, { probe_meta: { shell_detection: profileResult.shell_detection } }) || "console_session_detected" : "api_direct",
  };
  probeMeta.profile = profileResult.profile || {};
  probeMeta.profile_source = profileResult.profile_source || "";
  probeMeta.profile_errors = profileResult.profile_errors || [];
  probeMeta.quota_snapshot = quotaSnapshot;
  probeMeta.capability_verdicts = capabilityVerdicts;
  probeMeta.frontend_confirmed_endpoints =
    family === "qingyi"
      ? ["/user/profile", "/usage", "/usage/stats", "/groups/available", "/groups/rates", "/channels/available", "/keys", "/auth/refresh"]
      : family === "onetoken"
        ? ["/api/v1/token/usage", "/api/v1/token/logs", "/api/v1/wallet/balance", "/api/v1/wallet/logs", "https://router.onetoken.sh/v1/models"]
        : family === "auth_shell"
          ? probeMeta.console_entrypoints
          : ["/api/pricing", "/api/models", "/api/user/groups", "/api/log/self"];
  probeMeta.credential_materials = buildCredentialMaterials(site);
  probeMeta.adapter_recommendation = family === "auth_shell" ? "keep-auth-shell-then-detect-downstream" : family;
  probeMeta.repair_mode = inferRepairMode(site, { capabilities: cap, probe_meta: probeMeta, probe_errors: cap.probe_errors });
  probeMeta.bridge_status = {
    browser: "edge",
    preferred: true,
    has_materials: buildCredentialMaterials(site).length > 0,
  };
  probeMeta.repair_steps = buildRepairSteps(site, { capabilities: cap, probe_meta: probeMeta, probe_errors: cap.probe_errors });
  probeMeta.support_status = inferSupportStatus(site, { capabilities: cap, probe_meta: probeMeta, probe_errors: cap.probe_errors });

  await dbSaveSiteProfile(env, workspaceId, site.id, {
    family,
    capabilities: cap,
    last_probe_at: now,
    probe_errors: cap.probe_errors,
    probe_meta: probeMeta,
  });

  return cap;
}

async function createChannel(env, workspaceId, site, payload) {
  if (resolveSiteFamily(site) !== "new_api") {
    throw new Error("当前适配器不支持渠道创建");
  }
  const cap = await probeCapabilities(env, workspaceId, site);
  if (!cap.can_manage_channel) {
    throw new Error("permission denied: current account cannot create channel");
  }
  const body = {
    name: String(payload.name || `channel-${Date.now()}`),
    key: String(payload.key || ""),
    type: payload.type == null ? 1 : payload.type,
    models: Array.isArray(payload.models) ? payload.models : [],
    group: String(payload.group || "default"),
    status: payload.status == null ? 1 : payload.status,
  };
  const r = await siteRequest(env, workspaceId, site, "POST", "/api/channel/", {
    json_body: body,
    timeout_ms: 12000,
  });
  if (!(r.status >= 200 && r.status < 300)) {
    throw new Error(r.message || "创建渠道失败");
  }
  return (r.payload && (r.payload.data || r.payload)) || {};
}

function hasAuthMaterial(site) {
  const creds = site.credentials || {};
  const family = resolveSiteFamily(site);
  if (family === "qingyi") return Boolean(String(creds.auth_token || creds.token || creds.cookie || creds.refresh_token || "").trim());
  if (family === "onetoken") return Boolean(String(creds.token || creds.auth_token || creds.cookie || "").trim());
  if (family === "auth_shell") return Boolean(String(creds.token || creds.auth_token || creds.cookie || creds.session || "").trim());
  return Boolean(String(creds.token || creds.cookie || "").trim());
}

function summarizeCredentialStatus(site, profile = null) {
  const family = resolveSiteFamily(site);
  const cap = profile?.capabilities || {};
  const meta = profile?.probe_meta || {};
  const errors = Array.isArray(profile?.probe_errors) ? profile.probe_errors.join(" | ") : "";
  const reason = String(cap.reason || errors || "").toLowerCase();
  if (!hasAuthMaterial(site)) {
    return {
      status: "missing",
      label: "缺少登录态",
      hint: "需要重新提取 cookie/token，否则无法签到和读取额度",
    };
  }
  if (family === "qingyi" && (reason.includes("token has expired") || reason.includes("invalid refresh") || reason.includes("expired"))) {
    return {
      status: "expired",
      label: "登录态过期",
      hint: "auth_token/refresh_token 已失效，需要重新打开站点并提取登录态",
    };
  }
  if (family === "auth_shell" && String(meta?.transport_chain?.state || "").includes("oidc")) {
    return {
      status: "auth_warning",
      label: "等待授权回跳",
      hint: "请在 Edge 中完成 OIDC 授权回跳后，再回到控制台点击修复登录态",
    };
  }
  if (reason.includes("unexpected html") || reason.includes("expected json") || reason.includes("site challenge")) {
    return {
      status: "auth_warning",
      label: "接口返回HTML",
      hint: "目标站点返回了页面/挑战/登录页，不是 JSON API；需要检查协议类型或重新登录",
    };
  }
  const coreTaskWorks = Boolean(cap.can_checkin || cap.can_read_quota);
  if (
    !coreTaskWorks &&
    (reason.includes("未登录") ||
      reason.includes("unauthorized") ||
      reason.includes("permission") ||
      reason.includes("无权") ||
      reason.includes("validate credentials") ||
      reason.includes("invalid token") ||
      reason.includes("鉴权"))
  ) {
    return {
      status: "auth_warning",
      label: "鉴权异常",
      hint: "站点返回鉴权/权限异常；若签到或额度失败，请重新提取登录态",
    };
  }
  return {
    status: "ok",
    label: "登录态可用",
    hint: "已保存 cookie/token，可执行站点任务",
  };
}

function summarizeSourceConfidence(meta = {}) {
  const verdicts = meta.capability_verdicts && typeof meta.capability_verdicts === "object" ? meta.capability_verdicts : {};
  const summary = {
    "frontend-confirmed": 0,
    "official-api": 0,
    "compat-probe": 0,
    "bundle-derived": 0,
  };
  Object.values(verdicts).forEach((value) => {
    const level = String(value?.source_level || "");
    if (summary[level] != null) summary[level] += 1;
  });
  return summary;
}

function inferSupportStatus(site, profile = null) {
  const credential = summarizeCredentialStatus(site, profile ? { capabilities: profile.capabilities || {}, probe_errors: profile.probe_errors || [], probe_meta: profile.probe_meta || {} } : null);
  const family = resolveSiteFamily(site);
  const verdicts = profile?.probe_meta?.capability_verdicts || {};
  const allEvidence = [
    ...(Array.isArray(profile?.probe_errors) ? profile.probe_errors : []),
    ...Object.values(verdicts).map((x) => `${x?.message || ""} ${x?.evidence || ""} ${x?.status || ""}`),
  ].join(" | ");
  if (/error code:\s*1016|status[=: ]*530|network error|timeout|dns|fetch failed/i.test(allEvidence)) return "network_failed";
  if (profile?.probe_meta?.probe_budget?.status === "probe_budget_exhausted") return "adapter_gap";
  if (credential.status === "expired") return "supported_but_auth_expired";
  if (Object.values(verdicts).some((x) => String(x?.verdict || "") === "auth_failed")) return "supported_but_auth_expired";
  if (family === "auth_shell") {
    const hasConsole = Array.isArray(profile?.probe_meta?.console_entrypoints) && profile.probe_meta.console_entrypoints.length > 0;
    if (credential.status === "ok" && hasConsole) return "supported";
    return "adapter_gap";
  }
  if (family === "onetoken" && ["key_limited", "auth_failed"].includes(String(verdicts.can_read_models?.verdict || ""))) {
    return "key_limited";
  }
  if (Object.values(verdicts).some((x) => String(x?.verdict || "") === "adapter_gap")) return "adapter_gap";
  if (Object.values(verdicts).some((x) => String(x?.verdict || "") === "not_exposed")) return "not_exposed";
  return "supported";
}

function describeAuthState(site, profile = null) {
  const status = summarizeCredentialStatus(site, profile);
  const creds = site.credentials || {};
  return {
    ...status,
    has_auth_token: Boolean(String(creds.auth_token || creds.token || "").trim()),
    has_refresh_token: Boolean(String(creds.refresh_token || "").trim()),
    token_expires_at: String(creds.token_expires_at || "").trim(),
    has_cookie: Boolean(String(creds.cookie || "").trim()),
    has_session: Boolean(String(creds.session || "").trim()),
  };
}

function compactProfile(data = {}, fallback = {}) {
  const user = data.user && typeof data.user === "object" ? data.user : {};
  const profile = data.profile && typeof data.profile === "object" ? data.profile : {};
  const account = data.account && typeof data.account === "object" ? data.account : {};
  const settings = data.settings && typeof data.settings === "object" ? data.settings : {};
  const source = { ...settings, ...account, ...profile, ...user, ...data };
  const displayName = String(
    source.site_title ||
      source.system_name ||
      source.app_name ||
      source.title ||
      source.name ||
      source.display_name ||
      source.username ||
      source.email ||
      fallback.display_name ||
      ""
  ).trim();
  return {
    display_name: displayName,
    username: String(source.username || source.user_name || user.name || "").trim(),
    email: String(source.email || user.email || "").trim(),
    site_title: String(source.site_title || source.system_name || source.app_name || source.title || fallback.site_title || "").trim(),
    plan: String(source.plan || source.group || source.group_name || source.role || "").trim(),
  };
}

async function fetchSiteProfile(env, workspaceId, site) {
  const family = resolveSiteFamily(site);
  if (family === "auth_shell") {
    const errors = [];
    try {
      const resp = await fetch(site.base_url, { headers: siteHeaders(site) });
      const text = await resp.text();
      const title = extractHtmlTitle(text);
      const canonical = extractCanonicalHref(text);
      const consoleEntrypoints = extractConsoleEntrypoints(text);
      return {
        profile: compactProfile({}, { site_title: title, display_name: title || site.name || site.id }),
        profile_source: "/ (html)",
        profile_errors: errors,
        shell_detection: {
          shell_type: detectSiteShellType(site),
          title,
          canonical,
          console_entrypoints: consoleEntrypoints,
          has_login_overlay: /sign in|wechat sign in|登录|authorize/i.test(text),
        },
      };
    } catch (err) {
      errors.push(`/: ${String(err?.message || err)}`);
      return {
        profile: {},
        profile_source: "",
        profile_errors: errors,
        shell_detection: {
          shell_type: detectSiteShellType(site),
          title: "",
          canonical: "",
          console_entrypoints: [],
          has_login_overlay: false,
        },
      };
    }
  }
  const paths =
    family === "qingyi"
      ? ["/user/profile", "/auth/me", "/keys", "/groups/available", "/groups/rates"]
      : family === "onetoken"
        ? ["/api/v1/users/me", "/api/v1/wallet/balance"]
      : ["/api/user/self", "/api/user/profile", "/api/status", "/api/user/status"];
  let best = {};
  let source = "";
  const errors = [];

  for (const path of paths) {
    const r = await siteRequest(env, workspaceId, site, "GET", path, { timeout_ms: 8000 });
    if (!(r.status >= 200 && r.status < 300) || !r.payload) {
      errors.push(`${path}: ${r.status || "network"}`);
      continue;
    }
    const data = (r.payload && (r.payload.data || r.payload)) || {};
    const profile = compactProfile(data, best);
    if (profile.display_name || profile.site_title || profile.username || profile.email) {
      best = profile;
      source = path;
      break;
    }
  }

  if (!best.site_title) {
    try {
      const resp = await fetch(site.base_url, { headers: siteHeaders(site) });
      const text = await resp.text();
      const m = text.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
      if (m && m[1]) {
        best = compactProfile({}, { ...best, site_title: m[1].replace(/\s+/g, " ").trim() });
        source = source || "/";
      }
    } catch (err) {
      errors.push(`/: ${String(err?.message || err)}`);
    }
  }

  return {
    profile: best,
    profile_source: source,
    profile_errors: errors.slice(0, 5),
    shell_detection: null,
  };
}

function chooseDisplayName(site, profile) {
  const p = profile || {};
  if (p.site_title) return { display_name: p.site_title, name_source: "site_title" };
  if (p.display_name) return { display_name: p.display_name, name_source: "profile" };
  if (site.name && site.name !== site.id) return { display_name: site.name, name_source: "manual" };
  return { display_name: site.name || site.id, name_source: "saved" };
}

function buildProtocolReportItem(site, profile = null, authHistory = []) {
  const meta = profile?.probe_meta || {};
  const capabilityVerdicts = meta.capability_verdicts || {};
  const endpointMatrix = Object.entries(meta)
    .filter(([key, value]) => key.startsWith("/") || key.startsWith("http"))
    .map(([path, value]) => ({
      path,
      status: value?.status ?? null,
      ok: Boolean(value?.ok),
      message: String(value?.message || ""),
      auth_refreshed: Boolean(value?.auth_refreshed),
      source_level: value?.source_level || "compat-probe",
      is_json: !/html/i.test(String(value?.message || "")),
    }));
  const familyCandidates = Array.from(new Set([resolveSiteFamily(site), site.adapter || "new_api"].filter(Boolean)));
  return {
    site_id: site.id,
    family: resolveSiteFamily(site),
    family_candidates: familyCandidates,
    support_status: inferSupportStatus(site, profile),
    auth_state: describeAuthState(site, profile ? { capabilities: profile.capabilities || {}, probe_errors: profile.probe_errors || [], probe_meta: profile.probe_meta || {} } : null),
    shell_detection: meta.shell_detection || null,
    console_entrypoints: meta.console_entrypoints || meta.shell_detection?.console_entrypoints || [],
    frontend_confirmed_endpoints: meta.frontend_confirmed_endpoints || [],
    capability_verdicts: capabilityVerdicts,
    endpoint_matrix: endpointMatrix,
    credential_materials: meta.credential_materials || buildCredentialMaterials(site),
    adapter_recommendation: meta.adapter_recommendation || resolveSiteFamily(site),
    repair_steps: meta.repair_steps || buildRepairSteps(site, profile),
    transport_chain: meta.transport_chain || { state: "api_direct" },
    probe_budget: meta.probe_budget || { limit: PROBE_REQUEST_BUDGET, used: 0, status: "ok" },
    bridge_status: meta.bridge_status || { browser: "edge", preferred: true, has_materials: buildCredentialMaterials(site).length > 0 },
    profile_source: meta.profile_source || "",
    quota_snapshot: meta.quota_snapshot || null,
    recent_auth_refresh: authHistory,
    probe_errors: profile?.probe_errors || [],
    generated_at: nowIso(),
  };
}

function normalizeQuotaCurrency(data, fallback = "") {
  const raw = String(data.currency || data.unit || data.quota_unit || fallback || "").trim();
  if (!raw) return "";
  if (/usd|dollar/i.test(raw)) return "USD";
  if (/cny|rmb|yuan|¥/i.test(raw)) return "CNY";
  return raw.toUpperCase();
}

function parseQuotaInfoFromData(data = {}) {
  const candidates = [data];
  ["user", "profile", "account", "quota", "billing", "usage", "stats", "subscription", "credit_grants", "data"].forEach((key) => {
    const v = data && data[key];
    if (v && typeof v === "object" && !Array.isArray(v)) candidates.push(v);
  });
  const pick = (...keys) => {
    for (const obj of candidates) {
      for (const key of keys) {
        const n = toNumber(obj[key]);
        if (n != null) return n;
      }
    }
    return null;
  };
  const balanceRaw =
    pick("balance", "available_balance", "remaining_balance", "remain", "remaining", "amount", "credit", "balance_amount", "token_balance", "tokens");
  const todaySpend = pick("today_spend", "today_cost", "today_used", "daily_cost", "daily_spend", "today_tokens", "daily_tokens");
  const totalSpend = pick("total_spend", "total_cost", "used", "used_quota", "cost", "total_used", "used_tokens", "total_tokens");
  const quota = pick("quota", "total_quota", "total_available", "total_granted", "credit_granted", "total_amount", "token_quota");
  const usedQuota = pick("used_quota", "total_used", "used", "used_amount", "used_tokens");

  let balance = balanceRaw;
  const rawTotalSpend = totalSpend;

  let note = "";
  if (balance == null && quota != null && usedQuota != null) {
    balance = quota - usedQuota;
    note = "由 quota-used 推导余额";
  }

  const info = {
    balance,
    today_spend: todaySpend,
    total_spend: totalSpend,
    currency: normalizeQuotaCurrency(data),
    note,
    raw_balance: balance,
    raw_quota: quota,
    raw_total_spend: rawTotalSpend,
    total_quota: quota,
    used_quota: usedQuota,
    normalized_unit: Math.abs(quota || totalSpend || balance || 0) >= 1_000_000 ? "quota/500000" : "",
  };
  return decorateQuotaDisplay(info);
}

async function refreshQuota(env, workspaceId, site) {
  if (!hasAuthMaterial(site)) {
    const err = new Error("auth_failed: missing credentials");
    err.code = "auth_failed";
    throw err;
  }
  const family = resolveSiteFamily(site);
  const routes =
    family === "qingyi"
      ? [
          "/user/profile",
          "/usage/stats",
          "/usage",
          "/api/v1/user/profile",
        ]
      : family === "onetoken"
        ? [
            "/api/v1/wallet/balance",
            "/api/v1/token/usage",
            "/api/v1/users/me",
          ]
      : family === "auth_shell"
        ? []
      : [
          "/api/user/self",
          "/api/user/profile",
          "/api/user/status",
          "/v1/dashboard/billing/subscription",
          "/v1/dashboard/billing/credit_grants",
        ];

  let lastMsg = "";
  let lastStatus = null;
  if (family === "auth_shell") {
    const err = new Error("当前站点已识别为控制台外壳，需先完成 Edge 会话桥接与协议识别后再验证额度");
    err.code = "parse_failed";
    throw err;
  }
  for (const p of routes) {
    const r = await siteRequest(env, workspaceId, site, "GET", p, { timeout_ms: 10000 });
    lastStatus = r.status;
    if (!(r.status >= 200 && r.status < 300) || !r.payload) {
      lastMsg = r.message || `status ${r.status}`;
      continue;
    }
    const data = (r.payload && (r.payload.data || r.payload)) || {};
    const info = parseQuotaInfoFromData(data);
    if (family === "qingyi" && p === "/usage/stats") {
      info.currency = normalizeQuotaCurrency(data, info.currency || "");
      if (!info.note) info.note = "来自 qingyi usage/stats";
    }
    if (p.includes("/v1/dashboard/billing")) {
      info.currency = "USD";
      if (!info.note) info.note = "来自 OpenAI billing 兼容接口";
    }
    if (info.balance == null && info.today_spend == null && info.total_spend == null) {
      lastMsg = `path ${p} 未识别出额度字段`;
      continue;
    }
    const quotaResult = {
      quota_status: "available",
      balance: info.balance,
      today_spend: info.today_spend,
      total_spend: info.total_spend,
      raw_balance: info.raw_balance,
      raw_quota: info.raw_quota,
      raw_total_spend: info.raw_total_spend,
      total_quota: info.total_quota,
      used_quota: info.used_quota,
      display_balance: info.display_balance,
      display_today_spend: info.display_today_spend,
      display_total_spend: info.display_total_spend,
      display_total_quota: info.display_total_quota,
      display_used_quota: info.display_used_quota,
      display_unit: info.display_unit,
      billing_style: info.billing_style,
      conversion_rate: info.conversion_rate,
      conversion_note: info.conversion_note,
      normalized_unit: info.normalized_unit,
      currency: info.currency,
      note: info.note || "",
      quota_parse_note: info.note || "解析成功",
      raw: data,
      source: p,
      quota_source: p,
    };
    try {
      await saveQuotaSnapshot(env, workspaceId, site.id, quotaResult);
    } catch (_) {
      // Snapshot failures must never block live quota reads.
    }
    return quotaResult;
  }

  const err = new Error(lastMsg || "读取额度失败：站点未返回可识别数据");
  err.code = lastStatus === 401 || lastStatus === 403 ? "auth_failed" : lastStatus ? "parse_failed" : "network_failed";
  throw err;
}

async function runCheckinOne(env, workspaceId, site, dryRun = false, runtime = {}) {
  const timeoutMs = Number(runtime.timeout_ms || API_TIMEOUT_MS);
  const family = resolveSiteFamily(site);
  let authRefreshed = false;
  if (!hasAuthMaterial(site)) {
    return { status: "skipped", ok: true, message: "跳过：缺少 cookie/token 凭据", http_status: null, reason: "missing-credentials", support_status: "supported_but_auth_expired", auth_refreshed: false };
  }
  if (family === "onetoken") {
    return { status: "skipped", ok: true, message: "跳过：OneToken 未发现站内签到接口", http_status: null, reason: "unsupported-checkin", support_status: "not_exposed", auth_refreshed: false };
  }
  if (family === "auth_shell") {
    return {
      status: "skipped",
      ok: true,
      message: "跳过：控制台外壳站点尚未确认站内签到接口",
      http_status: null,
      reason: "unsupported-checkin-auth-shell",
      support_status: "adapter_gap",
      auth_refreshed: false,
    };
  }
  if (family === "qingyi") {
    let statusResp = await siteRequest(env, workspaceId, site, "GET", "/api/v1/checkin/status", { timeout_ms: timeoutMs });
    authRefreshed = Boolean(statusResp.auth_refreshed);

    if (statusResp.status === 401) {
      const refreshed = await tryRefreshQingyiAuth(env, workspaceId, site, { reason: "/api/v1/checkin/status" });
      if (!refreshed.ok) {
        return {
          status: "skipped",
          ok: true,
          message: `跳过：登录已过期且刷新失败 ${refreshed.message || ""}`.trim(),
          http_status: 401,
          reason: "auth-expired",
          support_status: "supported_but_auth_expired",
          auth_refreshed: false,
          source_endpoint: "/api/v1/checkin/status",
        };
      }
      authRefreshed = true;
      statusResp = await siteRequest(env, workspaceId, site, "GET", "/api/v1/checkin/status", { timeout_ms: timeoutMs });
      authRefreshed = authRefreshed || Boolean(statusResp.auth_refreshed);
    }

    const message = pickMessage(statusResp.payload, statusResp.message);
    if (likeChecked(message)) return { status: "already_checked_in", ok: true, message: "already checked in today", http_status: statusResp.status, auth_refreshed: authRefreshed, source_endpoint: "/api/v1/checkin/status", support_status: "supported" };
    if ([401, 403].includes(Number(statusResp.status))) {
      return { status: "skipped", ok: true, message: `跳过：鉴权失败 ${message || ""}`.trim(), http_status: statusResp.status, reason: message || "auth-failed", auth_refreshed: authRefreshed, source_endpoint: "/api/v1/checkin/status", support_status: "supported_but_auth_expired" };
    }
    if (Number(statusResp.status) === 404) {
      return { status: "skipped", ok: true, message: "跳过：站点未提供签到接口", http_status: 404, reason: message || "unsupported", auth_refreshed: authRefreshed, source_endpoint: "/api/v1/checkin/status", support_status: "not_exposed" };
    }
    if (dryRun) return { status: "dry_run_pending", ok: true, message: "dry-run: will check in", http_status: statusResp.status, auth_refreshed: authRefreshed, source_endpoint: "/api/v1/checkin/status", support_status: "supported" };

    const post = await siteRequest(env, workspaceId, site, "POST", "/api/v1/checkin", { timeout_ms: timeoutMs });
    const pMsg = pickMessage(post.payload, post.message);
    if (post.status >= 200 && post.status < 300 && (likeSuccess(pMsg) || likeChecked(pMsg) || !pMsg)) {
      return {
        status: likeChecked(pMsg) ? "already_checked_in" : "checked_in",
        ok: true,
        message: pMsg || "checkin success",
        http_status: post.status,
        auth_refreshed: authRefreshed,
        source_endpoint: "/api/v1/checkin",
        support_status: "supported",
      };
    }
    return { status: "failed", ok: false, message: pMsg || "checkin failed", http_status: post.status, reason: post.message || pMsg, auth_refreshed: authRefreshed, source_endpoint: "/api/v1/checkin", support_status: "supported" };
  }

  const statusResp = await siteRequest(env, workspaceId, site, "GET", `/api/user/checkin?month=${monthNow()}`, { timeout_ms: timeoutMs });
  const msg = pickMessage(statusResp.payload, statusResp.message);
  const payloadText = JSON.stringify(statusResp.payload || {});
  const already = likeChecked(msg) || /\"checked\"\\s*:\\s*true/i.test(payloadText);

  if (already) return { status: "already_checked_in", ok: true, message: "already checked in today", http_status: statusResp.status, auth_refreshed: false, source_endpoint: `/api/user/checkin?month=${monthNow()}`, support_status: "supported" };
  if ([401, 403].includes(Number(statusResp.status))) {
    return { status: "skipped", ok: true, message: `跳过：鉴权失败 ${msg || ""}`.trim(), http_status: statusResp.status, reason: msg || "auth-failed", auth_refreshed: false, source_endpoint: `/api/user/checkin?month=${monthNow()}`, support_status: "supported_but_auth_expired" };
  }
  if (Number(statusResp.status) === 404) {
    return { status: "skipped", ok: true, message: "跳过：站点未提供签到接口", http_status: 404, reason: msg || "unsupported", auth_refreshed: false, source_endpoint: `/api/user/checkin?month=${monthNow()}`, support_status: "not_exposed" };
  }
  if (dryRun) return { status: "dry_run_pending", ok: true, message: "dry-run: will check in", http_status: statusResp.status, auth_refreshed: false, source_endpoint: `/api/user/checkin?month=${monthNow()}`, support_status: "supported" };

  const post = await siteRequest(env, workspaceId, site, "POST", "/api/user/checkin", { timeout_ms: timeoutMs });
  const postMsg = pickMessage(post.payload, post.message);
  if (post.status >= 200 && post.status < 300 && (likeSuccess(postMsg) || likeChecked(postMsg) || !postMsg)) {
    return {
      status: likeChecked(postMsg) ? "already_checked_in" : "checked_in",
      ok: true,
      message: postMsg || "checkin success",
      http_status: post.status,
      auth_refreshed: false,
      source_endpoint: "/api/user/checkin",
      support_status: "supported",
    };
  }
  return { status: "failed", ok: false, message: postMsg || "checkin failed", http_status: post.status, reason: post.message || postMsg, auth_refreshed: false, source_endpoint: "/api/user/checkin", support_status: "supported" };
}

async function appendJobEvent(env, workspaceId, jobId, step, status, message, elapsedMs = null) {
  await env.DB.prepare(
    "INSERT INTO job_events (job_id, workspace_id, step, status, message, elapsed_ms, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
  )
    .bind(jobId, workspaceId, step, status, message || "", elapsedMs == null ? null : Number(elapsedMs), nowIso())
    .run();
}

async function updateJob(env, jobId, status, result = null) {
  await env.DB.prepare("UPDATE jobs SET status = ?1, result_json = ?2, updated_at = ?3 WHERE id = ?4")
    .bind(status, result ? JSON.stringify(result) : null, nowIso(), jobId)
    .run();
}

async function acquireWorkspaceLock(env, workspaceId, jobId) {
  const id = env.WORKSPACE_LOCK.idFromName(workspaceId);
  const stub = env.WORKSPACE_LOCK.get(id);
  const acquire = () => stub.fetch("https://lock/acquire", {
    method: "POST",
    body: JSON.stringify({ job_id: jobId }),
  });
  let r = await acquire();
  const data = await r.json();
  if (data.ok !== true && data.holder) {
    const holder = String(data.holder || "");
    const row = await env.DB.prepare("SELECT status, updated_at FROM jobs WHERE workspace_id = ?1 AND id = ?2")
      .bind(workspaceId, holder)
      .first();
    const updatedMs = row?.updated_at ? Date.parse(row.updated_at) : 0;
    const staleRunning = row?.status === "running" && updatedMs && Date.now() - updatedMs > 5 * 60 * 1000;
    if (!row || row.status !== "running" || staleRunning) {
      await stub.fetch("https://lock/release", {
        method: "POST",
        body: JSON.stringify({ job_id: holder }),
      });
      r = await acquire();
      const retry = await r.json();
      return retry.ok === true;
    }
  }
  return data.ok === true;
}

async function releaseWorkspaceLock(env, workspaceId, jobId) {
  const id = env.WORKSPACE_LOCK.idFromName(workspaceId);
  const stub = env.WORKSPACE_LOCK.get(id);
  await stub.fetch("https://lock/release", {
    method: "POST",
    body: JSON.stringify({ job_id: jobId }),
  });
}

function explainCheckinResult(site, result, attempts = 1) {
  const family = resolveSiteFamily(site);
  const httpStatus = result?.http_status == null ? "-" : String(result.http_status);
  const evidence = {
    http_status: result?.http_status || null,
    message: result?.message || "",
    reason: result?.reason || "",
    attempts,
    source_endpoint: result?.source_endpoint || "",
    auth_refreshed: Boolean(result?.auth_refreshed),
  };
  if (result?.status === "checked_in") {
    return {
      result_level: "success",
      result_title: result?.auth_refreshed ? "自动刷新后签到成功" : "签到成功",
      result_reason: result?.auth_refreshed ? "系统先自动刷新了过期登录态，然后重新发起签到并成功完成。" : "目标站点接受了签到请求，今日任务已完成。",
      evidence,
      next_action: "保持每日自动任务即可",
      auth_refreshed: Boolean(result?.auth_refreshed),
      source_endpoint: result?.source_endpoint || "",
      support_status: result?.support_status || "supported",
    };
  }
  if (result?.status === "already_checked_in") {
    return {
      result_level: "info",
      result_title: "今日已签到",
      result_reason: "目标站点返回已签到或重复签到提示，无需再次操作。",
      evidence,
      next_action: "无需处理，等待明天自动任务",
      auth_refreshed: Boolean(result?.auth_refreshed),
      source_endpoint: result?.source_endpoint || "",
      support_status: result?.support_status || "supported",
    };
  }
  if (result?.status === "dry_run_pending") {
    return {
      result_level: "info",
      result_title: "仅检查通过",
      result_reason: "dry-run 模式没有真正签到，但接口显示可以执行签到。",
      evidence,
      next_action: "需要真实签到时点击全站签到或单站签到",
      auth_refreshed: Boolean(result?.auth_refreshed),
      source_endpoint: result?.source_endpoint || "",
      support_status: result?.support_status || "supported",
    };
  }
  if (result?.status === "skipped" && family === "onetoken") {
    return {
      result_level: "info",
      result_title: "协议无签到接口",
      result_reason: "OneToken/Router 类站点通常没有站内签到入口，按 API、额度和模型健康验收即可。",
      evidence,
      next_action: "不用把跳过当失败；可刷新额度和模型确认站点健康",
      auth_refreshed: false,
      source_endpoint: result?.source_endpoint || "",
      support_status: result?.support_status || "not_exposed",
    };
  }
  if (result?.status === "skipped" && family === "auth_shell") {
    return {
      result_level: "info",
      result_title: "无需签到接口",
      result_reason: "该站点目前被识别为控制台外壳 / 授权跳转型站点，尚未确认有独立站内签到 API；这不计为签到失败。",
      evidence,
      next_action: "先完成 Edge 登录态桥接和协议识别，再按额度/API 健康验收",
      auth_refreshed: false,
      source_endpoint: result?.source_endpoint || "",
      support_status: result?.support_status || "adapter_gap",
    };
  }
  if (result?.status === "skipped" && /missing|credential|cookie|token|凭据/i.test(String(result.reason || result.message || ""))) {
    return {
      result_level: "warning",
      result_title: "需要修复登录态",
      result_reason: "当前站点缺少可用于签到的 cookie/token 凭据。请先在 Edge 登录目标站点，再回到控制台执行修复登录态。",
      evidence,
      next_action: "在 Edge 登录目标站点并点击修复登录态",
      auth_refreshed: false,
      source_endpoint: result?.source_endpoint || "",
      support_status: result?.support_status || "supported_but_auth_expired",
    };
  }
  if (result?.status === "skipped" && /unsupported|404|未提供签到接口/i.test(String(result.reason || result.message || ""))) {
    return {
      result_level: "info",
      result_title: "站点未开放签到接口",
      result_reason: "该站点协议或当前版本没有可用签到 API，因此跳过是正常降级。",
      evidence,
      next_action: "按额度/API 健康验收；如站点前端有签到按钮，可重新修复登录态后再测",
      auth_refreshed: Boolean(result?.auth_refreshed),
      source_endpoint: result?.source_endpoint || "",
      support_status: result?.support_status || "not_exposed",
    };
  }
  if (result?.status === "skipped" && /auth|401|403|登录|鉴权/i.test(String(result.reason || result.message || ""))) {
    return {
      result_level: "warning",
      result_title: result?.auth_refreshed ? "自动刷新失败" : "登录态失效",
      result_reason: result?.auth_refreshed
        ? `系统尝试自动刷新登录态后仍未完成签到（HTTP ${httpStatus}）。`
        : `接口返回鉴权相关状态（HTTP ${httpStatus}），当前凭据不足以完成签到。`,
      evidence,
      next_action: "重新登录目标站点，并执行修复登录态",
      auth_refreshed: Boolean(result?.auth_refreshed),
      source_endpoint: result?.source_endpoint || "",
      support_status: result?.support_status || "supported_but_auth_expired",
    };
  }
  if (result?.status === "skipped") {
    return {
      result_level: "info",
      result_title: "已跳过",
      result_reason: result?.message || "当前站点不需要或无法执行签到。",
      evidence,
      next_action: "查看诊断矩阵判断是否需要处理",
      auth_refreshed: Boolean(result?.auth_refreshed),
      source_endpoint: result?.source_endpoint || "",
      support_status: result?.support_status || "supported",
    };
  }
  return {
    result_level: "error",
    result_title: "请求失败",
    result_reason: result?.message || "签到请求没有成功完成。",
    evidence,
    next_action: Number(result?.http_status) === 401 || Number(result?.http_status) === 403 ? "重新登录并修复登录态" : "查看系统日志和重试轨迹",
    auth_refreshed: Boolean(result?.auth_refreshed),
    source_endpoint: result?.source_endpoint || "",
    support_status: result?.support_status || "supported",
  };
}

async function upsertAlertEvent(env, workspaceId, siteId, payload) {
  const now = nowIso();
  const row = await env.DB.prepare(
    "SELECT id, status FROM alert_events WHERE workspace_id = ?1 AND ifnull(site_id,'') = ifnull(?2,'') AND rule_key = ?3 AND status IN ('open','acked') ORDER BY id DESC LIMIT 1"
  )
    .bind(workspaceId, siteId || null, payload.rule_key)
    .first();
  if (payload.triggered) {
    if (row) {
      const keepStatus = row.status === "acked" ? "acked" : "open";
      await env.DB.prepare(
        `UPDATE alert_events
         SET level = ?1, title = ?2, detail = ?3, metric_value = ?4, threshold_value = ?5, sample_size = ?6, status = ?7, last_triggered_at = ?8, updated_at = ?8
         WHERE id = ?9`
      )
        .bind(
          payload.level,
          payload.title,
          payload.detail || "",
          payload.metric_value == null ? null : Number(payload.metric_value),
          payload.threshold_value == null ? null : Number(payload.threshold_value),
          payload.sample_size == null ? null : Number(payload.sample_size),
          keepStatus,
          now,
          row.id
        )
        .run();
      return { changed: false, status: keepStatus, id: row.id };
    }
    const inserted = await env.DB.prepare(
      `INSERT INTO alert_events (
          workspace_id, site_id, level, rule_key, status, title, detail, metric_value, threshold_value, sample_size,
          first_triggered_at, last_triggered_at, acked_at, resolved_at, created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, 'open', ?5, ?6, ?7, ?8, ?9, ?10, ?10, NULL, NULL, ?10, ?10)`
    )
      .bind(
        workspaceId,
        siteId || null,
        payload.level,
        payload.rule_key,
        payload.title,
        payload.detail || "",
        payload.metric_value == null ? null : Number(payload.metric_value),
        payload.threshold_value == null ? null : Number(payload.threshold_value),
        payload.sample_size == null ? null : Number(payload.sample_size),
        now
      )
      .run();
    return { changed: true, status: "open", id: inserted.meta?.last_row_id || null };
  }

  if (row) {
    await env.DB.prepare("UPDATE alert_events SET status = 'resolved', resolved_at = ?1, updated_at = ?1 WHERE id = ?2")
      .bind(now, row.id)
      .run();
    return { changed: true, status: "resolved", id: row.id };
  }
  return { changed: false, status: "resolved", id: null };
}

async function buildUsageSummaryMap(env, workspaceId, startIso, endIso = nowIso()) {
  const rows = await env.DB.prepare(
    `SELECT site_id, SUM(COALESCE(token_count,0)) AS tokens, SUM(COALESCE(cost,0)) AS cost, COUNT(*) AS count
       FROM usage_logs
      WHERE workspace_id = ?1 AND source_ts >= ?2 AND source_ts <= ?3
   GROUP BY site_id`
  )
    .bind(workspaceId, startIso, endIso)
    .all();
  const out = new Map();
  (rows.results || []).forEach((r) => {
    out.set(String(r.site_id || ""), {
      tokens: Number(r.tokens || 0),
      cost: Number(r.cost || 0),
      count: Number(r.count || 0),
    });
  });
  return out;
}

async function buildFailure15mMap(env, workspaceId, sinceIso) {
  const rows = await env.DB.prepare(
    `SELECT site_id,
            SUM(CASE WHEN ok = 0 THEN 1 ELSE 0 END) AS failed,
            COUNT(*) AS total
       FROM system_logs
      WHERE workspace_id = ?1 AND created_at >= ?2
   GROUP BY site_id`
  )
    .bind(workspaceId, sinceIso)
    .all();
  const out = new Map();
  (rows.results || []).forEach((r) => {
    const total = Number(r.total || 0);
    const failed = Number(r.failed || 0);
    out.set(String(r.site_id || ""), {
      total,
      failed,
      failure_rate: total > 0 ? failed / total : 0,
    });
  });
  return out;
}

async function countRecentConsecutiveFailures(env, workspaceId, siteId, maxScan = 30) {
  const rows = await env.DB.prepare(
    `SELECT status
       FROM job_events
      WHERE workspace_id = ?1 AND step = ?2
   ORDER BY id DESC
      LIMIT ?3`
  )
    .bind(workspaceId, `site:${siteId}`, maxScan)
    .all();
  let count = 0;
  for (const row of rows.results || []) {
    if (row.status === "failed") count += 1;
    else break;
  }
  return count;
}

async function evaluateAlerts(env, workspaceId, sites, alertPolicy) {
  const startToday = startOfDayUtcIso();
  const usageMap = await buildUsageSummaryMap(env, workspaceId, startToday);
  const failMap = await buildFailure15mMap(env, workspaceId, minutesAgoIso(15));
  const siteList = Array.isArray(sites) ? sites : [];

  for (const site of siteList) {
    const siteId = site.id;
    const usage = usageMap.get(siteId) || { tokens: 0, cost: 0, count: 0 };
    const failure = failMap.get(siteId) || { total: 0, failed: 0, failure_rate: 0 };
    const consecutive = await countRecentConsecutiveFailures(env, workspaceId, siteId, Math.max(alertPolicy.consecutive_failures * 3, 30));

    await upsertAlertEvent(env, workspaceId, siteId, {
      triggered: usage.cost >= alertPolicy.daily_cost,
      level: usage.cost >= alertPolicy.daily_cost * 2 ? "critical" : "warn",
      rule_key: "daily_cost",
      title: "日成本达到阈值",
      detail: `site=${siteId} cost=${usage.cost.toFixed(6)} threshold=${alertPolicy.daily_cost}`,
      metric_value: usage.cost,
      threshold_value: alertPolicy.daily_cost,
      sample_size: usage.count,
    });
    await upsertAlertEvent(env, workspaceId, siteId, {
      triggered: usage.tokens >= alertPolicy.daily_tokens,
      level: usage.tokens >= alertPolicy.daily_tokens * 2 ? "critical" : "warn",
      rule_key: "daily_tokens",
      title: "日 Token 消耗达到阈值",
      detail: `site=${siteId} tokens=${usage.tokens} threshold=${alertPolicy.daily_tokens}`,
      metric_value: usage.tokens,
      threshold_value: alertPolicy.daily_tokens,
      sample_size: usage.count,
    });
    await upsertAlertEvent(env, workspaceId, siteId, {
      triggered:
        failure.total >= alertPolicy.failure_rate_15m_min_samples && failure.failure_rate >= alertPolicy.failure_rate_15m,
      level: "critical",
      rule_key: "failure_rate_15m",
      title: "15 分钟失败率过高",
      detail: `site=${siteId} failed=${failure.failed}/${failure.total} rate=${(failure.failure_rate * 100).toFixed(2)}%`,
      metric_value: failure.failure_rate,
      threshold_value: alertPolicy.failure_rate_15m,
      sample_size: failure.total,
    });
    await upsertAlertEvent(env, workspaceId, siteId, {
      triggered: consecutive >= alertPolicy.consecutive_failures,
      level: "critical",
      rule_key: "consecutive_failures",
      title: "连续失败次数达到阈值",
      detail: `site=${siteId} consecutive_failures=${consecutive}`,
      metric_value: consecutive,
      threshold_value: alertPolicy.consecutive_failures,
      sample_size: consecutive,
    });
  }
}

async function runCheckinJob(env, workspaceId, triggerType, params) {
  const jobId = randomId();
  const createdAt = nowIso();
  await env.DB.prepare(
    "INSERT INTO jobs (id, workspace_id, trigger_type, status, params_json, result_json, created_at, updated_at) VALUES (?1, ?2, ?3, 'running', ?4, NULL, ?5, ?5)"
  )
    .bind(jobId, workspaceId, triggerType, JSON.stringify(params || {}), createdAt)
    .run();

  const lockOk = await acquireWorkspaceLock(env, workspaceId, jobId);
  if (!lockOk) {
    const report = {
      generated_at: nowIso(),
      dry_run: Boolean(params?.dry_run),
      selected_sites: Array.isArray(params?.site_ids) ? params.site_ids : [],
      summary: { ok: 0, failed: 0, skipped: 0, checked_in: 0, already_checked_in: 0, dry_run_pending: 0 },
      checkin_summary_by_level: summarizeCheckinByLevel({ results: [] }),
      human_summary: "已有签到任务正在执行，本次请求已进入等待提示，不会记为失败。",
      results: [],
    };
    await appendJobEvent(env, workspaceId, jobId, "lock", "skipped", "同一工作区已有任务在执行，请等待当前任务完成");
    await updateJob(env, jobId, "completed", { code: "job_already_running", report, exit_code: 0 });
    return {
      job_id: jobId,
      status: "waiting",
      code: "job_already_running",
      message: "已有签到任务运行中，请等待当前任务完成",
      report,
      exit_code: 0,
    };
  }

  try {
    await appendJobEvent(env, workspaceId, jobId, "start", "running", "job started");
    const workspaceSettings = await getWorkspaceSettings(env, workspaceId);
    const sites = await dbListSites(env, workspaceId);
    const selectedIds = Array.isArray(params.site_ids) ? params.site_ids : [];
    const target = sites.filter((s) => {
      if (params.enabled_only && !s.enabled) return false;
      if (selectedIds.length && !selectedIds.includes(s.id)) return false;
      return true;
    });

    await appendJobEvent(env, workspaceId, jobId, "select", "running", `selected ${target.length} sites`);

    const dryRun = Boolean(params.dry_run);
    const workspaceRetryPolicy = normalizeRetryPolicy({
      ...workspaceSettings.retry_policy,
      ...(Number.isFinite(params.retry) ? { max_attempts: Number(params.retry) + 1 } : {}),
      ...(Number.isFinite(params.retry_delay) ? { base_delay_s: Number(params.retry_delay) } : {}),
    });

    const results = [];
    const summary = {
      ok: 0,
      failed: 0,
      skipped: 0,
      checked_in: 0,
      already_checked_in: 0,
      dry_run_pending: 0,
    };

    for (const site of target) {
      const siteStart = Date.now();
      await appendJobEvent(env, workspaceId, jobId, `site:${site.id}`, "running", `开始处理 ${site.id}`);
      const retryResolved = resolveRetryPolicyForSite(workspaceRetryPolicy, site);
      await appendJobEvent(
        env,
        workspaceId,
        jobId,
        `site:${site.id}`,
        "running",
        `重试策略来源=${retryResolved.source}; max_attempts=${retryResolved.policy.max_attempts}; base=${retryResolved.policy.base_delay_s}s; multiplier=${retryResolved.policy.multiplier}; max_delay=${retryResolved.policy.max_delay_s}s; jitter=${Math.round(retryResolved.policy.jitter_ratio * 100)}%; timeout=${retryResolved.policy.timeout_ms}ms`
      );
      let result = null;
      let attempts = 0;
      while (attempts < retryResolved.policy.max_attempts) {
        attempts += 1;
        result = await runCheckinOne(env, workspaceId, site, dryRun, { timeout_ms: retryResolved.policy.timeout_ms });
        if (result.ok) break;

        const retryable = shouldRetryCheckin(result);
        if (!retryable || attempts >= retryResolved.policy.max_attempts) {
          await appendJobEvent(
            env,
            workspaceId,
            jobId,
            `site:${site.id}`,
            "running",
            `停止重试 attempt=${attempts}/${retryResolved.policy.max_attempts}; retryable=${retryable}; status=${
              result.http_status == null ? "-" : result.http_status
            }`
          );
          break;
        }
        const waitMs = computeRetryDelayMs(retryResolved.policy, attempts);
        await appendJobEvent(
          env,
          workspaceId,
          jobId,
          `site:${site.id}`,
          "running",
          `重试 ${attempts}/${retryResolved.policy.max_attempts - 1} | wait=${waitMs}ms | status=${
            result.http_status == null ? "-" : result.http_status
          } | reason=${result.reason || result.message || ""}`
        );
        await new Promise((resolve) => setTimeout(resolve, waitMs));
      }

      const explained = explainCheckinResult(site, result, attempts);
      const item = {
        site: site.id,
        base_url: site.base_url,
        status: result.status,
        ok: result.ok,
        message: result.message,
        http_status: result.http_status || null,
        retry_policy_source: retryResolved.source,
        attempts,
        timestamp: nowIso(),
        result_level: explained.result_level,
        result_title: explained.result_title,
        result_reason: explained.result_reason,
        evidence: explained.evidence,
        next_action: explained.next_action,
        auth_refreshed: explained.auth_refreshed,
        source_endpoint: explained.source_endpoint,
        support_status: explained.support_status,
      };
      results.push(item);
      if (result.status === "skipped") summary.skipped += 1;
      else if (result.ok) summary.ok += 1;
      else summary.failed += 1;
      if (result.status !== "skipped" && summary[result.status] != null) summary[result.status] += 1;

      await appendJobEvent(
        env,
        workspaceId,
        jobId,
        `site:${site.id}`,
        result.status === "skipped" ? "skipped" : result.ok ? "ok" : "failed",
        `${explained.result_title} | ${explained.result_reason} | ${result.message || ""}`,
        Date.now() - siteStart
      );
    }
    const byLevel = summarizeCheckinByLevel({ results });
    const hardFailures = (byLevel.request_failed || 0) + (byLevel.network_error || 0);
    const humanSummary = `签到完成：成功 ${summary.checked_in || 0}，今日已签到 ${summary.already_checked_in || 0}，无需接口 ${byLevel.no_interface || 0}，需修复登录态 ${byLevel.need_auth || 0}，失败 ${hardFailures}。${
      hardFailures ? "请优先处理网络异常或请求失败站点。" : byLevel.need_auth ? "本轮没有硬失败，但仍有站点需要修复登录态。" : "没有阻塞性失败。"
    }`;

    const report = {
      generated_at: nowIso(),
      dry_run: dryRun,
      retry_policy: workspaceRetryPolicy,
      selected_sites: target.map((s) => s.id),
      summary,
      checkin_summary_by_level: byLevel,
      human_summary: humanSummary,
      results,
    };

    await evaluateAlerts(env, workspaceId, sites, workspaceSettings.alert_policy);

    const exitCode = summary.failed > 0 ? 1 : 0;
    await appendJobEvent(
      env,
      workspaceId,
      jobId,
      "finish",
      exitCode === 0 ? "ok" : "failed",
      `${humanSummary} 退出码 ${exitCode}`
    );
    await updateJob(env, jobId, exitCode === 0 ? "completed" : "failed", { report, exit_code: exitCode });
    return {
      job_id: jobId,
      status: exitCode === 0 ? "completed" : "failed",
      report,
      exit_code: exitCode,
    };
  } finally {
    await releaseWorkspaceLock(env, workspaceId, jobId);
  }
}

async function listSystemLogs(env, workspaceId, query) {
  const limit = Math.min(Number(query.get("limit") || 100), 500);
  const siteId = query.get("site_id") || "";
  const keyword = query.get("q") || "";

  let sql = "SELECT * FROM system_logs WHERE workspace_id = ?1";
  const args = [workspaceId];
  if (siteId) {
    sql += " AND site_id = ?2";
    args.push(siteId);
  }
  if (keyword) {
    sql += ` AND (message LIKE ?${args.length + 1} OR path LIKE ?${args.length + 1})`;
    args.push(`%${keyword}%`);
  }
  sql += ` ORDER BY id DESC LIMIT ?${args.length + 1}`;
  args.push(limit);

  const rows = await env.DB.prepare(sql).bind(...args).all();
  return rows.results || [];
}

function normalizeUsage(raw, siteId) {
  const reqTypeRaw = raw.type ?? raw.request_type ?? raw.channel_type ?? raw.request_method ?? "";
  const endpointRaw = raw.endpoint || raw.path || raw.route || raw.url || raw.api_path || "";
  const contentText = String(raw.content || raw.message || "");
  const usageObj = raw.usage && typeof raw.usage === "object" ? raw.usage : {};

  const promptTokens = toNumber(
    raw.prompt_tokens ?? raw.input_tokens ?? raw.prompt_token ?? usageObj.prompt_tokens ?? usageObj.input_tokens
  );
  const completionTokens = toNumber(
    raw.completion_tokens ??
      raw.output_tokens ??
      raw.completion_token ??
      usageObj.completion_tokens ??
      usageObj.output_tokens
  );
  const totalTokens = toNumber(raw.total_tokens ?? raw.token_count ?? raw.tokens ?? usageObj.total_tokens);

  let tokenCount = null;
  let parseNote = "";
  if (promptTokens != null || completionTokens != null) {
    tokenCount = (promptTokens || 0) + (completionTokens || 0);
    parseNote = "token 来自 prompt/completion";
  } else if (totalTokens != null) {
    tokenCount = totalTokens;
    parseNote = "token 来自 total_tokens";
  } else {
    tokenCount = sumTokens(raw);
    parseNote = tokenCount == null ? "未识别 token 字段" : "token 来自兼容映射";
  }

  let cost = toNumber(raw.cost ?? raw.amount ?? raw.price ?? raw.fee ?? usageObj.cost ?? usageObj.amount);
  if (cost == null) {
    const quotaDerived = toNumber(raw.quota ?? raw.used_quota ?? usageObj.quota ?? usageObj.used_quota);
    if (quotaDerived != null) {
      cost = scaleQuotaNumber(quotaDerived);
      parseNote = parseNote ? `${parseNote}; cost 来自 quota 推导` : "cost 来自 quota 推导";
    }
  }

  let parseStatus = "success";
  if (tokenCount == null && cost == null) parseStatus = "failed";
  else if (tokenCount == null || cost == null) parseStatus = "partial";

  return {
    site_id: siteId,
    api_key: String(raw.key || raw.api_key || raw.token_name || raw.token_id || raw.channel || ""),
    model: String(raw.model || raw.model_name || raw.model_name_cn || raw.model_id || ""),
    endpoint: String(endpointRaw || (contentText.length > 80 ? `${contentText.slice(0, 80)}...` : contentText)),
    req_type: String(reqTypeRaw),
    billing_mode: String(raw.billing_mode || raw.mode || raw.charge_mode || raw.bill_mode || ""),
    prompt_tokens: promptTokens,
    completion_tokens: completionTokens,
    token_count: tokenCount,
    cost,
    first_token_ms: toNumber(raw.first_token_ms || raw.first_latency || raw.first_token_latency),
    elapsed_ms: toNumber(raw.elapsed_ms || raw.latency || raw.duration_ms || raw.use_time || raw.elapsed),
    user_agent: String(raw.user_agent || raw.ua || raw.ip || ""),
    source_ts: toIsoTimestamp(raw.created_at ?? raw.time ?? raw.timestamp),
    parse_status: parseStatus,
    parse_note: parseNote,
    raw_json: raw,
  };
}

async function refreshUsageForSite(env, workspaceId, site) {
  const family = resolveSiteFamily(site);
  const paths =
    family === "qingyi"
      ? ["/usage/dashboard/models", "/usage", "/usage/stats", "/usage/dashboard/stats", "/api/v1/log/self?p=1&size=50"]
      : family === "onetoken"
        ? ["/api/v1/token/logs?limit=50", "/api/v1/token/usage", "/api/v1/wallet/logs"]
      : [
          "/api/log/self?p=1&size=50",
          "/api/log/?p=1&size=50",
          "/api/log/personal?p=1&size=50",
          "/api/logs?p=1&size=50",
          "/api/log/self",
        ];

  for (const p of paths) {
    const r = await siteRequest(env, workspaceId, site, "GET", p, { timeout_ms: 10000 });
    if (!r.ok) continue;
    const items = parseDataItems(r.payload);
    if (!items.length) {
      if (family === "onetoken" && p === "/api/v1/token/usage") {
        return { inserted: 0, path: p, message: "站点返回的是统计摘要接口，不是逐条 Usage 日志" };
      }
      continue;
    }

    const stmt = env.DB.prepare(
      `INSERT INTO usage_logs (
          workspace_id, site_id, api_key, model, endpoint, req_type, billing_mode,
          prompt_tokens, completion_tokens, token_count, cost, first_token_ms, elapsed_ms,
          user_agent, source_ts, parse_status, parse_note, created_at, raw_json
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)`
    );

    const now = nowIso();
    const batches = items.slice(0, 50).map((row) => {
      const n = normalizeUsage(row, site.id);
      return stmt.bind(
        workspaceId,
        site.id,
        n.api_key,
        n.model,
        n.endpoint,
        n.req_type,
        n.billing_mode,
        n.prompt_tokens,
        n.completion_tokens,
        n.token_count,
        n.cost,
        n.first_token_ms,
        n.elapsed_ms,
        n.user_agent,
        n.source_ts,
        n.parse_status,
        n.parse_note,
        now,
        JSON.stringify(n.raw_json)
      );
    });

    if (batches.length) {
      await env.DB.batch(batches);
      return { inserted: batches.length, path: p };
    }
  }

  return {
    inserted: 0,
    path: "",
    message:
      family === "qingyi"
        ? "站点未开放用户 Usage 明细接口或当前账号无日志权限"
        : family === "onetoken"
          ? "站点只返回 Usage 摘要，未返回逐条日志"
          : "接口不支持/未返回数据",
  };
}

async function listUsageLogs(env, workspaceId, query) {
  const limit = Math.min(Number(query.get("limit") || 100), 500);
  const siteId = query.get("site_id") || "";
  const keyword = query.get("q") || "";
  const parseStatus = query.get("parse_status") || "";
  const startAt = query.get("start") || "";
  const endAt = query.get("end") || "";
  const alertLevel = query.get("alert_level") || "";

  let sql = "SELECT * FROM usage_logs WHERE workspace_id = ?1";
  const args = [workspaceId];
  if (siteId) {
    sql += " AND site_id = ?2";
    args.push(siteId);
  }
  if (keyword) {
    sql += ` AND (model LIKE ?${args.length + 1} OR endpoint LIKE ?${args.length + 1} OR api_key LIKE ?${args.length + 1})`;
    args.push(`%${keyword}%`);
  }
  if (parseStatus) {
    sql += ` AND parse_status = ?${args.length + 1}`;
    args.push(parseStatus);
  }
  if (startAt) {
    sql += ` AND source_ts >= ?${args.length + 1}`;
    args.push(toIsoTimestamp(startAt));
  }
  if (endAt) {
    sql += ` AND source_ts <= ?${args.length + 1}`;
    args.push(toIsoTimestamp(endAt));
  }
  if (alertLevel) {
    const levelRows = await env.DB.prepare(
      "SELECT DISTINCT site_id FROM alert_events WHERE workspace_id = ?1 AND level = ?2 AND status IN ('open','acked')"
    )
      .bind(workspaceId, alertLevel)
      .all();
    const siteIds = (levelRows.results || []).map((x) => String(x.site_id || "")).filter(Boolean);
    if (!siteIds.length) return [];
    const placeholders = siteIds.map((_, idx) => `?${args.length + idx + 1}`).join(", ");
    sql += ` AND site_id IN (${placeholders})`;
    args.push(...siteIds);
  }
  sql += ` ORDER BY id DESC LIMIT ?${args.length + 1}`;
  args.push(limit);

  const rows = await env.DB.prepare(sql).bind(...args).all();
  return rows.results || [];
}

async function getUsageSummary(env, workspaceId, query) {
  const startAt = query.get("start") ? toIsoTimestamp(query.get("start")) : startOfDayUtcIso();
  const endAt = query.get("end") ? toIsoTimestamp(query.get("end")) : nowIso();
  const siteId = query.get("site_id") || "";

  let usageSql =
    "SELECT site_id, SUM(COALESCE(token_count,0)) AS token_total, SUM(COALESCE(cost,0)) AS cost_total, COUNT(*) AS usage_count FROM usage_logs WHERE workspace_id = ?1 AND source_ts >= ?2 AND source_ts <= ?3";
  const usageArgs = [workspaceId, startAt, endAt];
  if (siteId) {
    usageSql += ` AND site_id = ?${usageArgs.length + 1}`;
    usageArgs.push(siteId);
  }
  usageSql += " GROUP BY site_id ORDER BY cost_total DESC";

  let errSql =
    "SELECT site_id, SUM(CASE WHEN ok = 0 THEN 1 ELSE 0 END) AS failed_count, COUNT(*) AS total_count FROM system_logs WHERE workspace_id = ?1 AND created_at >= ?2 AND created_at <= ?3";
  const errArgs = [workspaceId, startAt, endAt];
  if (siteId) {
    errSql += ` AND site_id = ?${errArgs.length + 1}`;
    errArgs.push(siteId);
  }
  errSql += " GROUP BY site_id";

  const [usageRows, errRows] = await Promise.all([
    env.DB.prepare(usageSql).bind(...usageArgs).all(),
    env.DB.prepare(errSql).bind(...errArgs).all(),
  ]);
  const errMap = new Map();
  (errRows.results || []).forEach((row) => {
    const total = Number(row.total_count || 0);
    const failed = Number(row.failed_count || 0);
    errMap.set(String(row.site_id || ""), {
      failed_count: failed,
      total_count: total,
      error_rate: total > 0 ? failed / total : 0,
    });
  });

  const items = (usageRows.results || []).map((row) => {
    const key = String(row.site_id || "");
    const err = errMap.get(key) || { failed_count: 0, total_count: 0, error_rate: 0 };
    return {
      site_id: key,
      token_total: Number(row.token_total || 0),
      cost_total: Number(row.cost_total || 0),
      usage_count: Number(row.usage_count || 0),
      failed_count: err.failed_count,
      total_count: err.total_count,
      error_rate: err.error_rate,
    };
  });

  return {
    start: startAt,
    end: endAt,
    items,
  };
}

async function listAlerts(env, workspaceId, query) {
  const limit = Math.min(Number(query.get("limit") || 200), 1000);
  const siteId = query.get("site_id") || "";
  const level = query.get("level") || "";
  const ruleKey = query.get("rule_key") || "";
  const status = query.get("status") || "";
  const keyword = query.get("q") || "";
  const start = query.get("start") || "";
  const end = query.get("end") || "";

  let sql = "SELECT * FROM alert_events WHERE workspace_id = ?1";
  const args = [workspaceId];
  if (siteId) {
    sql += ` AND site_id = ?${args.length + 1}`;
    args.push(siteId);
  }
  if (level) {
    sql += ` AND level = ?${args.length + 1}`;
    args.push(level);
  }
  if (ruleKey) {
    sql += ` AND rule_key = ?${args.length + 1}`;
    args.push(ruleKey);
  }
  if (status) {
    sql += ` AND status = ?${args.length + 1}`;
    args.push(status);
  }
  if (keyword) {
    sql += ` AND (title LIKE ?${args.length + 1} OR detail LIKE ?${args.length + 1})`;
    args.push(`%${keyword}%`);
  }
  if (start) {
    sql += ` AND created_at >= ?${args.length + 1}`;
    args.push(toIsoTimestamp(start));
  }
  if (end) {
    sql += ` AND created_at <= ?${args.length + 1}`;
    args.push(toIsoTimestamp(end));
  }
  sql += ` ORDER BY id DESC LIMIT ?${args.length + 1}`;
  args.push(limit);

  const rows = await env.DB.prepare(sql).bind(...args).all();
  return rows.results || [];
}

function defaultRangeFromQuery(query, fallbackHours = 24) {
  const end = query.get("end") ? toIsoTimestamp(query.get("end")) : nowIso();
  const start = query.get("start") ? toIsoTimestamp(query.get("start")) : new Date(Date.now() - fallbackHours * 3600 * 1000).toISOString();
  return { start, end };
}

async function getMetricsOverview(env, workspaceId, query) {
  const { start, end } = defaultRangeFromQuery(query, 24);
  const sites = await dbListSites(env, workspaceId);
  const profileMap = await loadSiteProfileMap(env, workspaceId);
  const latestCheckinMap = await loadLatestCheckinResultMap(env, workspaceId);
  const health = sites.map((site) => buildSiteHealth(site, profileMap.get(site.id), latestCheckinMap.get(site.id)));
  const summary = {
    total_sites: health.length,
    enabled_sites: health.filter((x) => x.enabled).length,
    healthy: health.filter((x) => x.status === "healthy").length,
    warning: health.filter((x) => x.status === "warning").length,
    critical: health.filter((x) => x.status === "critical").length,
    avg_score: health.length ? Math.round(health.reduce((a, b) => a + b.score, 0) / health.length) : 0,
  };
  const usageRows = await env.DB.prepare(
    `SELECT site_id,
            SUM(COALESCE(token_count,0)) AS token_total,
            SUM(COALESCE(cost,0)) AS cost_total,
            COUNT(*) AS usage_count,
            SUM(CASE WHEN parse_status = 'failed' THEN 1 ELSE 0 END) AS parse_failed
       FROM usage_logs
      WHERE workspace_id = ?1 AND COALESCE(source_ts, created_at) >= ?2 AND COALESCE(source_ts, created_at) <= ?3
      GROUP BY site_id
      ORDER BY cost_total DESC`
  )
    .bind(workspaceId, start, end)
    .all();
  const usage = usageRows.results || [];
  const modelRows = await env.DB.prepare(
    `SELECT model,
            SUM(COALESCE(token_count,0)) AS token_total,
            SUM(COALESCE(cost,0)) AS cost_total,
            COUNT(*) AS usage_count
       FROM usage_logs
      WHERE workspace_id = ?1 AND COALESCE(source_ts, created_at) >= ?2 AND COALESCE(source_ts, created_at) <= ?3
      GROUP BY model
      ORDER BY cost_total DESC
      LIMIT 10`
  )
    .bind(workspaceId, start, end)
    .all();
  const systemRows = await env.DB.prepare(
    `SELECT site_id,
            COUNT(*) AS total,
            SUM(CASE WHEN ok = 0 THEN 1 ELSE 0 END) AS failed,
            AVG(COALESCE(elapsed_ms,0)) AS avg_elapsed_ms
       FROM system_logs
      WHERE workspace_id = ?1 AND created_at >= ?2 AND created_at <= ?3
      GROUP BY site_id
      ORDER BY failed DESC, total DESC`
  )
    .bind(workspaceId, start, end)
    .all();
  const alerts = await env.DB.prepare(
    "SELECT status, level, COUNT(*) AS count FROM alert_events WHERE workspace_id = ?1 GROUP BY status, level"
  )
    .bind(workspaceId)
    .all();
  return {
    range: { start, end },
    summary: {
      ...summary,
      token_total: usage.reduce((a, b) => a + Number(b.token_total || 0), 0),
      cost_total: usage.reduce((a, b) => a + Number(b.cost_total || 0), 0),
      usage_count: usage.reduce((a, b) => a + Number(b.usage_count || 0), 0),
    },
    health,
    top_sites: usage.slice(0, 10),
    top_models: modelRows.results || [],
    failure_sites: systemRows.results || [],
    price_missing_sites: health.filter((x) => x.issue_codes.includes("model_price_missing")).slice(0, 10),
    alerts: alerts.results || [],
  };
}

async function getMetricsTrends(env, workspaceId, query) {
  const { start, end } = defaultRangeFromQuery(query, 24 * 7);
  const group = ["hour", "day", "site", "model"].includes(query.get("group")) ? query.get("group") : "day";
  const siteId = query.get("site_id") || "";
  const model = query.get("model") || "";
  const bucketExpr =
    group === "hour"
      ? "substr(COALESCE(source_ts, created_at),1,13) || ':00:00Z'"
      : group === "site"
        ? "site_id"
        : group === "model"
          ? "model"
          : "substr(COALESCE(source_ts, created_at),1,10)";
  let usageSql = `SELECT ${bucketExpr} AS bucket,
                         SUM(COALESCE(token_count,0)) AS token_total,
                         SUM(COALESCE(cost,0)) AS cost_total,
                         COUNT(*) AS usage_count,
                         SUM(CASE WHEN parse_status = 'failed' THEN 1 ELSE 0 END) AS parse_failed
                    FROM usage_logs
                   WHERE workspace_id = ?1 AND COALESCE(source_ts, created_at) >= ?2 AND COALESCE(source_ts, created_at) <= ?3`;
  const args = [workspaceId, start, end];
  if (siteId) {
    usageSql += ` AND site_id = ?${args.length + 1}`;
    args.push(siteId);
  }
  if (model) {
    usageSql += ` AND model = ?${args.length + 1}`;
    args.push(model);
  }
  usageSql += " GROUP BY bucket ORDER BY bucket ASC";
  const usageRows = await env.DB.prepare(usageSql).bind(...args).all();
  let quotaSql = `SELECT site_id, substr(created_at,1,13) || ':00:00Z' AS bucket,
                         AVG(display_balance) AS display_balance,
                         MAX(display_unit) AS display_unit,
                         MAX(source) AS source
                    FROM quota_snapshots
                   WHERE workspace_id = ?1 AND created_at >= ?2 AND created_at <= ?3`;
  const qArgs = [workspaceId, start, end];
  if (siteId) {
    quotaSql += ` AND site_id = ?${qArgs.length + 1}`;
    qArgs.push(siteId);
  }
  quotaSql += " GROUP BY site_id, bucket ORDER BY bucket ASC";
  const quotaRows = await env.DB.prepare(quotaSql).bind(...qArgs).all();
  const sysRows = await env.DB.prepare(
    `SELECT substr(created_at,1,13) || ':00:00Z' AS bucket,
            COUNT(*) AS total,
            SUM(CASE WHEN ok = 0 THEN 1 ELSE 0 END) AS failed
       FROM system_logs
      WHERE workspace_id = ?1 AND created_at >= ?2 AND created_at <= ?3
      GROUP BY bucket
      ORDER BY bucket ASC`
  )
    .bind(workspaceId, start, end)
    .all();
  return {
    range: { start, end },
    group,
    usage: usageRows.results || [],
    quota: quotaRows.results || [],
    failures: (sysRows.results || []).map((r) => ({
      ...r,
      failure_rate: Number(r.total || 0) ? Number(r.failed || 0) / Number(r.total || 1) : 0,
    })),
  };
}

function classifyBulkFailureMessage(message = "", site = null) {
  const text = String(message || "");
  const family = site ? resolveSiteFamily(site) : "";
  if (isProbeBudgetErrorMessage(text)) return "预算耗尽";
  if (/html|challenge|expected json|挑战页/i.test(text)) return "HTML挑战页";
  if (/401|403|token|登录态|未登录|unauthorized|forbidden|无效的令牌|权限/i.test(text)) return "登录态失效";
  if (/Router Key|key_limited|Key 权限|权限限制/i.test(text)) return "Key权限受限";
  if (/530|1016|network|timeout|dns|fetch failed/i.test(text)) return "站点网络异常";
  if (family === "auth_shell" || /adapter_gap|协议待确认|控制台外壳/i.test(text)) return "协议待确认";
  if (/not.?exposed|unsupported|未开放|不支持|404/i.test(text)) return "接口未开放";
  return "其它失败";
}

function isBenignBulkStep(step = {}, site = null) {
  const family = site ? resolveSiteFamily(site) : "";
  const msg = String(step.message || "");
  if (step.skipped) return true;
  if (family === "auth_shell" && ["quota", "models", "usage"].includes(step.step)) return true;
  if (family === "onetoken" && /Router Key|权限限制|key_limited|协议无签到接口|未公开模型目录/i.test(msg)) return true;
  if (/usage.*未开放|Usage.*未开放|接口未开放|not.?exposed|unsupported|不支持/i.test(msg)) return true;
  if (/协议待确认|控制台外壳/i.test(msg)) return true;
  return false;
}

async function runBulkSiteAction(env, workspaceId, body = {}) {
  const action = String(body.action || "").trim();
  const allowed = new Set(["inspect", "light-inspect", "quota", "models", "usage", "repair-config", "disable", "repair-auth", "repair-browser-auth", "full-heal", "rebuild-model-cache", "export-diagnostics"]);
  if (!allowed.has(action)) throw new Error("unsupported bulk action");
  if (action === "repair-config") {
    const repaired = await repairSiteConfigurations(env, workspaceId);
    return {
      action,
      ...repaired,
      summary_text: repaired.changed
        ? `已修复 ${repaired.changed} 项配置问题，旧重复站点已自动禁用。`
        : "没有发现需要修复的重复导入或适配器配置问题。",
      success_sites: repaired.actions || [],
      failed_sites: [],
      skipped_sites: [],
      next_actions: repaired.changed ? ["刷新站点列表并重新计算健康分"] : ["保持监控"],
    };
  }

  const allSites = await dbListSites(env, workspaceId);
  const ids = Array.isArray(body.site_ids) ? body.site_ids.map((x) => String(x || "").trim()).filter(Boolean) : [];
  const selected = ids.length ? allSites.filter((s) => ids.includes(s.id)) : allSites.filter((s) => s.enabled);
  const heavyActions = new Set(["full-heal", "rebuild-model-cache", "models", "usage", "quota"]);
  if (heavyActions.has(action) && selected.length > 1) {
    return {
      action,
      total: selected.length,
      ok: 0,
      failed: 0,
      skipped: 0,
      needs_client_queue: true,
      remaining_site_ids: selected.map((s) => s.id),
      budget_status: "client_queue_required",
      summary_text: "该动作会触发较多目标站点请求，已要求前端改用逐站队列执行，避免 Worker 子请求预算耗尽。",
      success_sites: [],
      failed_sites: [],
      skipped_sites: [],
      phase_results: [],
      failure_categories: {},
      next_actions: ["前端将自动逐站执行；若你直接调用 API，请每次只传 1 个 site_id"],
      items: [],
    };
  }
  const items = [];
  for (const site of selected) {
    try {
      if (action === "inspect" || action === "light-inspect") {
        const cap = await probeCapabilities(env, workspaceId, site);
        items.push({ site_id: site.id, ok: true, action, capabilities: cap });
      } else if (action === "quota") {
        const quota = await refreshQuota(env, workspaceId, site);
        await patchSiteProbeMeta(env, workspaceId, site.id, { quota_snapshot: quota });
        items.push({ site_id: site.id, ok: true, action, quota_status: quota.quota_status, balance: quota.display_balance ?? quota.balance });
      } else if (action === "models" || action === "rebuild-model-cache") {
        if (resolveSiteFamily(site) === "auth_shell") {
          items.push({ site_id: site.id, ok: true, skipped: true, action, model_count: 0, priced_count: 0, message: "协议待确认：auth_shell 站点需先完成 Edge 登录态桥接和控制台入口识别" });
          continue;
        }
        const models = await getSiteModelsView(env, workspaceId, site);
        await patchSiteProbeMeta(env, workspaceId, site.id, { model_catalog_cache: summarizeModelCache(models) });
        items.push({ site_id: site.id, ok: true, action, model_count: models.items.length, priced_count: models.items.filter((x) => hasPricingValue(x.pricing || x)).length });
      } else if (action === "usage") {
        const result = await refreshUsageForSite(env, workspaceId, site);
        items.push({ site_id: site.id, ok: true, action, ...result });
      } else if (action === "repair-auth" || action === "repair-browser-auth") {
        if (resolveSiteFamily(site) !== "qingyi") {
          items.push({ site_id: site.id, ok: true, skipped: true, action, message: "当前站点优先使用 Edge 浏览器桥接修复登录态" });
        } else {
          const refreshed = await tryRefreshQingyiAuth(env, workspaceId, site, { reason: "bulk-repair-auth" });
          items.push({ site_id: site.id, ok: refreshed.ok, action, auth_refreshed: refreshed.auth_refreshed, message: refreshed.message });
        }
      } else if (action === "full-heal") {
        const steps = [];
        const family = resolveSiteFamily(site);
        if (family === "qingyi") {
          const refreshed = await tryRefreshQingyiAuth(env, workspaceId, site, { reason: "bulk-full-heal" });
          steps.push({ step: "repair-auth", ok: refreshed.ok, message: refreshed.message });
        }
        try {
          const cap = await probeCapabilities(env, workspaceId, site);
          steps.push({ step: "inspect", ok: true, message: cap.reason || "ok" });
        } catch (err) {
          steps.push({ step: "inspect", ok: false, message: String(err?.message || err) });
        }
        try {
          if (family === "auth_shell") {
            steps.push({ step: "quota", ok: true, skipped: true, message: "协议待确认：先完成控制台入口识别后再验证额度" });
          } else {
            const quota = await refreshQuota(env, workspaceId, site);
            await patchSiteProbeMeta(env, workspaceId, site.id, { quota_snapshot: quota });
            steps.push({ step: "quota", ok: true, message: quota.quota_parse_note || quota.note || "ok" });
          }
        } catch (err) {
          steps.push({ step: "quota", ok: false, message: String(err?.message || err) });
        }
        try {
          if (family === "auth_shell") {
            steps.push({ step: "models", ok: true, skipped: true, message: "协议待确认：auth_shell 不执行 new_api 模型探测链" });
          } else {
            const models = await getSiteModelsView(env, workspaceId, site);
            await patchSiteProbeMeta(env, workspaceId, site.id, { model_catalog_cache: summarizeModelCache(models) });
            const note = models.items.length ? `models=${models.items.length}` : (models.diagnostics || []).map((x) => x.message).filter(Boolean)[0] || "模型目录未返回数据";
            steps.push({ step: "models", ok: true, message: note });
          }
        } catch (err) {
          steps.push({ step: "models", ok: false, message: String(err?.message || err) });
        }
        try {
          if (family === "auth_shell") {
            steps.push({ step: "usage", ok: true, skipped: true, message: "协议待确认：先完成控制台入口识别后再判断 Usage" });
          } else {
            const usage = await refreshUsageForSite(env, workspaceId, site);
            steps.push({ step: "usage", ok: true, message: usage.message || `inserted=${usage.inserted || 0}` });
          }
        } catch (err) {
          steps.push({ step: "usage", ok: false, message: String(err?.message || err) });
        }
        const effectiveOk = steps
          .filter((x) => x.step !== "repair-auth")
          .every((x) => x.ok !== false || isBenignBulkStep(x, site));
        items.push({
          site_id: site.id,
          ok: effectiveOk,
          action,
          steps,
          phase_results: steps,
          failure_category: effectiveOk ? "" : classifyBulkFailureMessage(steps.find((x) => x.ok === false)?.message || "", site),
          summary: steps.map((x) => `${x.step}:${x.ok === false ? "failed" : "ok"}`).join(" | "),
        });
      } else if (action === "export-diagnostics") {
        const profile = await dbGetSiteProfile(env, workspaceId, site.id);
        const authHistory = await listAuthRefreshHistory(env, workspaceId, site.id, 20);
        items.push({
          site_id: site.id,
          ok: true,
          action,
          support_status: inferSupportStatus(site, profile),
          capability_verdicts: profile?.probe_meta?.capability_verdicts || {},
          auth_history: authHistory,
        });
      } else if (action === "disable") {
        await dbSaveSite(env, workspaceId, { ...site, enabled: 0 });
        items.push({ site_id: site.id, ok: true, action, disabled: true });
      }
    } catch (err) {
      const message = String(err?.message || err);
      items.push({ site_id: site.id, ok: false, action, message, failure_category: classifyBulkFailureMessage(message, site) });
    }
  }
  const successSites = items.filter((x) => x.ok);
  const failedSites = items.filter((x) => !x.ok);
  const skippedSites = items.filter((x) => x.skipped);
  const phaseResults = items.flatMap((x) => (x.phase_results || x.steps || []).map((step) => ({ site_id: x.site_id, ...step })));
  const failureCategories = {};
  for (const item of failedSites) {
    const category = item.failure_category || classifyBulkFailureMessage(item.message || item.summary || "", allSites.find((s) => s.id === item.site_id));
    failureCategories[category] = (failureCategories[category] || 0) + 1;
  }
  const budgetStatus = items.some((x) => isProbeBudgetErrorMessage(x.message || x.summary || "") || (x.steps || []).some((s) => isProbeBudgetErrorMessage(s.message))) ? "probe_budget_exhausted" : "ok";
  const actionName = {
    inspect: "批量检测",
    "light-inspect": "轻量探测",
    quota: "刷新额度",
    models: "刷新模型/价格缓存",
    "rebuild-model-cache": "重建模型/价格缓存",
    usage: "拉取 Usage",
    "repair-auth": "修复过期登录态",
    "repair-browser-auth": "修复浏览器登录态",
    "full-heal": "一键体检并修复",
    "export-diagnostics": "导出协议诊断",
    disable: "禁用异常站点",
  }[action] || action;
  const nextActions = [];
  if (failedSites.length) nextActions.push("打开失败站点详情，查看诊断矩阵和系统日志");
  if (action === "models" || action === "rebuild-model-cache") nextActions.push("进入模型页按价格可信度排序，检查未开放价格接口的站点");
  if (action === "quota") nextActions.push("查看余额趋势和额度换算说明");
  if (action === "usage") nextActions.push("进入日志中心查看 token/cost 趋势与错误聚类");
  if (action === "repair-auth") nextActions.push("刷新健康中心，确认 supported_but_auth_expired 是否已恢复");
  if (action === "repair-browser-auth") nextActions.push("在 Edge 中保持目标站点已登录，再进入站点详情执行登录态修复向导");
  if (action === "full-heal") nextActions.push("检查站点详情中的结论、证据和下一步建议是否收敛");
  if (action === "export-diagnostics") nextActions.push("可将返回结果下载为协议报告，交叉核对接口支持状态");
  if (!nextActions.length) nextActions.push("刷新健康中心确认分数变化");
  return {
    action,
    total: selected.length,
    ok: successSites.length,
    failed: failedSites.length,
    skipped: skippedSites.length,
    summary_text: `${actionName}完成：成功 ${successSites.length} 个，失败 ${failedSites.length} 个，跳过 ${skippedSites.length} 个。`,
    success_sites: successSites,
    failed_sites: failedSites,
    skipped_sites: skippedSites,
    phase_results: phaseResults,
    failure_categories: failureCategories,
    needs_client_queue: false,
    remaining_site_ids: [],
    budget_status: budgetStatus,
    next_actions: nextActions,
    items,
  };
}

async function ackAlerts(env, workspaceId, ids = []) {
  const clean = Array.isArray(ids) ? ids.map((x) => Number(x)).filter((x) => Number.isInteger(x) && x > 0) : [];
  if (!clean.length) return { updated: 0 };
  const now = nowIso();
  const placeholders = clean.map((_, i) => `?${i + 3}`).join(", ");
  const res = await env.DB.prepare(
    `UPDATE alert_events
        SET status = 'acked', acked_at = COALESCE(acked_at, ?1), updated_at = ?1
      WHERE workspace_id = ?2
        AND id IN (${placeholders})
        AND status = 'open'`
  )
    .bind(now, workspaceId, ...clean)
    .run();
  return { updated: Number(res.meta?.changes || 0) };
}

async function ackAllAlerts(env, workspaceId, filter = {}) {
  const now = nowIso();
  let sql = "UPDATE alert_events SET status = 'acked', acked_at = COALESCE(acked_at, ?1), updated_at = ?1 WHERE workspace_id = ?2 AND status = 'open'";
  const args = [now, workspaceId];
  if (filter.site_id) {
    sql += ` AND site_id = ?${args.length + 1}`;
    args.push(String(filter.site_id));
  }
  if (filter.level) {
    sql += ` AND level = ?${args.length + 1}`;
    args.push(String(filter.level));
  }
  if (filter.rule_key) {
    sql += ` AND rule_key = ?${args.length + 1}`;
    args.push(String(filter.rule_key));
  }
  if (filter.start) {
    sql += ` AND created_at >= ?${args.length + 1}`;
    args.push(toIsoTimestamp(filter.start));
  }
  if (filter.end) {
    sql += ` AND created_at <= ?${args.length + 1}`;
    args.push(toIsoTimestamp(filter.end));
  }
  const res = await env.DB.prepare(sql).bind(...args).run();
  return { updated: Number(res.meta?.changes || 0) };
}

function toCsv(rows) {
  const headers = [
    "site_id",
    "api_key",
    "model",
    "endpoint",
    "req_type",
    "billing_mode",
    "prompt_tokens",
    "completion_tokens",
    "token_count",
    "cost",
    "parse_status",
    "parse_note",
    "first_token_ms",
    "elapsed_ms",
    "user_agent",
    "source_ts",
    "created_at",
  ];
  const esc = (v) => `"${String(v == null ? "" : v).replace(/"/g, "\"\"")}"`;
  const lines = [headers.join(",")];
  rows.forEach((r) => {
    lines.push(headers.map((h) => esc(r[h])).join(","));
  });
  return `\uFEFF${lines.join("\n")}`;
}

async function ensureSchedule(env, workspaceId) {
  let row = await env.DB.prepare("SELECT workspace_id, enabled, time_hhmm, timezone, last_run_date FROM schedules WHERE workspace_id = ?1")
    .bind(workspaceId)
    .first();
  if (!row) {
    await env.DB.prepare(
      "INSERT INTO schedules (workspace_id, enabled, time_hhmm, timezone, last_run_date) VALUES (?1, 1, '09:05', 'Asia/Shanghai', NULL)"
    )
      .bind(workspaceId)
      .run();
    row = await env.DB.prepare("SELECT workspace_id, enabled, time_hhmm, timezone, last_run_date FROM schedules WHERE workspace_id = ?1")
      .bind(workspaceId)
      .first();
  }
  return {
    workspace_id: row.workspace_id,
    enabled: Number(row.enabled) === 1,
    time: row.time_hhmm,
    timezone: row.timezone,
    last_run_date: row.last_run_date,
  };
}

async function streamJobEvents(env, workspaceId, jobId) {
  let lastId = 0;
  const stream = new ReadableStream({
    async start(controller) {
      const encoder = new TextEncoder();
      const send = (event, data) => {
        controller.enqueue(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
      };
      send("hello", { job_id: jobId, started_at: nowIso() });

      for (let i = 0; i < 120; i += 1) {
        const rows = await env.DB.prepare(
          "SELECT id, step, status, message, elapsed_ms, created_at FROM job_events WHERE workspace_id = ?1 AND job_id = ?2 AND id > ?3 ORDER BY id ASC"
        )
          .bind(workspaceId, jobId, lastId)
          .all();
        const items = rows.results || [];
        for (const item of items) {
          lastId = item.id;
          send("step", item);
        }

        const job = await env.DB.prepare("SELECT status, result_json, updated_at FROM jobs WHERE workspace_id = ?1 AND id = ?2")
          .bind(workspaceId, jobId)
          .first();
        if (!job) {
          send("end", { status: "missing" });
          break;
        }
        if (["completed", "failed"].includes(job.status)) {
          send("end", { status: job.status, result: job.result_json ? JSON.parse(job.result_json) : null, updated_at: job.updated_at });
          break;
        }

        await new Promise((resolve) => setTimeout(resolve, 1000));
      }

      controller.close();
    },
  });

  return new Response(stream, {
    headers: {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache",
      connection: "keep-alive",
    },
  });
}

function routeParams(pathname, regex) {
  const m = pathname.match(regex);
  return m ? m.slice(1) : null;
}

function sessionCookieForRequest(request, token, maxAgeSec) {
  const isHttps = String(request.url || "").startsWith("https://");
  const secure = isHttps ? "; Secure" : "";
  return `cf_session=${encodeURIComponent(token)}; HttpOnly${secure}; Path=/; SameSite=Lax; Max-Age=${maxAgeSec}`;
}

async function handleApi(env, request, user) {
  const url = new URL(request.url);
  const { pathname } = url;
  const method = request.method.toUpperCase();

  if (pathname === "/api/health" && method === "GET") {
    return ok({ status: "ok", now: nowIso() });
  }

  if (pathname === "/api/auth/login/request" && method === "POST") {
    const body = await parseBody(request);
    const username = String(body.username || "").trim();
    const password = String(body.password || "");
    if (!username || !password) return fail("请输入账号和密码", 400);

    const row = await env.DB.prepare("SELECT id, password_hash FROM users WHERE username = ?1").bind(username).first();
    if (!row) return fail("invalid username or password", 401);
    const passOk = await verifyPassword(password, row.password_hash);
    if (!passOk) return fail("invalid username or password", 401);

    const challengeId = randomId();
    const now = new Date();
    const exp = new Date(now.getTime() + LOGIN_CHALLENGE_TTL_MIN * 60 * 1000).toISOString();
    await env.DB.prepare("INSERT INTO login_challenges (id, user_id, expires_at, created_at) VALUES (?1, ?2, ?3, ?4)")
      .bind(challengeId, row.id, exp, now.toISOString())
      .run();

    return ok({ challenge_id: challengeId, need_2fa: true, hint: "请输入二次验证码" });
  }

  if (pathname === "/api/auth/login/verify" && method === "POST") {
    const body = await parseBody(request);
    const challengeId = String(body.challenge_id || "").trim();
    const code = String(body.code || "").trim();
    if (!challengeId || !code) return fail("缺少 challenge_id 或验证码", 400);

    const row = await env.DB.prepare(
      "SELECT lc.id, lc.user_id, lc.expires_at, u.username FROM login_challenges lc JOIN users u ON u.id = lc.user_id WHERE lc.id = ?1"
    )
      .bind(challengeId)
      .first();
    if (!row) return fail("验证码会话不存在", 400);
    if (row.expires_at <= nowIso()) return fail("验证码已过期", 400);

    const expected = String(env.WEB_UI_OTP_CODE || DEFAULT_2FA_CODE);
    if (code !== expected) return fail("invalid otp code", 401);

    await env.DB.prepare("DELETE FROM login_challenges WHERE id = ?1").bind(challengeId).run();
    const session = await createSession(env, row.user_id);
    return json(
      { ok: true, item: { username: row.username } },
      200,
      { "set-cookie": sessionCookieForRequest(request, session.token, SESSION_TTL_HOURS * 3600) }
    );
  }

  if (pathname === "/api/auth/me" && method === "GET") {
    if (!user) return fail("unauthorized", 401);
    return ok({ username: user.username, workspace_id: user.workspace_id });
  }

  if (pathname === "/api/auth/logout" && method === "POST") {
    if (!user) return fail("unauthorized", 401);
    const cookies = parseCookie(request.headers.get("cookie") || "");
    if (cookies.cf_session) {
      await env.DB.prepare("DELETE FROM sessions WHERE token = ?1").bind(cookies.cf_session).run();
    }
    return new Response(JSON.stringify({ ok: true }), {
      headers: {
        "content-type": "application/json; charset=utf-8",
        "set-cookie": sessionCookieForRequest(request, "", 0),
      },
    });
  }

  if (!user) return fail("unauthorized", 401);

  if (pathname === "/api/policies/retry" && method === "GET") {
    const settings = await getWorkspaceSettings(env, user.workspace_id);
    return ok(settings.retry_policy);
  }

  if (pathname === "/api/policies/retry" && method === "PUT") {
    const body = await parseBody(request);
    const saved = await saveWorkspacePolicies(env, user.workspace_id, { retry_policy: body || {} });
    return ok(saved.retry_policy);
  }

  if (pathname === "/api/policies/alerts" && method === "GET") {
    const settings = await getWorkspaceSettings(env, user.workspace_id);
    return ok(settings.alert_policy);
  }

  if (pathname === "/api/policies/alerts" && method === "PUT") {
    const body = await parseBody(request);
    const saved = await saveWorkspacePolicies(env, user.workspace_id, { alert_policy: body || {} });
    return ok(saved.alert_policy);
  }

  if (pathname === "/api/alerts" && method === "GET") {
    const items = await listAlerts(env, user.workspace_id, url.searchParams);
    return ok({ items });
  }

  if (pathname === "/api/alerts/ack" && method === "POST") {
    const body = await parseBody(request);
    const ids = Array.isArray(body.ids) ? body.ids : body.id != null ? [body.id] : [];
    const result = await ackAlerts(env, user.workspace_id, ids);
    return ok(result);
  }

  if (pathname === "/api/alerts/ack-all" && method === "POST") {
    const body = await parseBody(request);
    const result = await ackAllAlerts(env, user.workspace_id, body || {});
    return ok(result);
  }

  if (pathname === "/api/metrics/overview" && method === "GET") {
    return ok(await getMetricsOverview(env, user.workspace_id, url.searchParams));
  }

  if (pathname === "/api/metrics/trends" && method === "GET") {
    return ok(await getMetricsTrends(env, user.workspace_id, url.searchParams));
  }

  if (pathname === "/api/sites/health" && method === "GET") {
    const sites = await dbListSites(env, user.workspace_id);
    const profileMap = await loadSiteProfileMap(env, user.workspace_id);
    const latestCheckinMap = await loadLatestCheckinResultMap(env, user.workspace_id);
    const items = sites.map((site) => buildSiteHealth(site, profileMap.get(site.id), latestCheckinMap.get(site.id)));
    try {
      await saveHealthSnapshots(env, user.workspace_id, items);
    } catch (_) {
      // Health history is helpful, but UI health must not depend on snapshot writes.
    }
    return ok({
      summary: {
        total: items.length,
        active: items.filter((x) => x.enabled).length,
        archived: items.filter((x) => x.human_status === "已归档").length,
        healthy: items.filter((x) => x.status === "healthy").length,
        warning: items.filter((x) => x.status === "warning").length,
        critical: items.filter((x) => x.status === "critical").length,
        must_fix: items.reduce((n, x) => n + (x.must_fix_issues || []).length, 0),
        optional: items.reduce((n, x) => n + (x.optional_issues || []).length, 0),
        avg_score: items.length ? Math.round(items.reduce((a, b) => a + b.score, 0) / items.length) : 0,
      },
      items,
    });
  }

  if (pathname === "/api/sites/actions/bulk" && method === "POST") {
    const body = await parseBody(request);
    return ok(await runBulkSiteAction(env, user.workspace_id, body || {}));
  }

  const siteDiagnosticsRoute = routeParams(pathname, /^\/api\/sites\/([A-Za-z0-9_-]{1,64})\/diagnostics$/);
  if (siteDiagnosticsRoute && method === "GET") {
    const site = await dbGetSite(env, user.workspace_id, siteDiagnosticsRoute[0]);
    if (!site) return fail("site not found", 404);
    const profileMap = await loadSiteProfileMap(env, user.workspace_id);
    const profile = profileMap.get(site.id) || null;
    const latestCheckinMap = await loadLatestCheckinResultMap(env, user.workspace_id);
    const latestCheckin = latestCheckinMap.get(site.id);
    const health = buildSiteHealth(site, profile, latestCheckin);
    const logs = await env.DB.prepare(
      "SELECT created_at, method, path, status, ok, elapsed_ms, message FROM system_logs WHERE workspace_id = ?1 AND site_id = ?2 ORDER BY id DESC LIMIT 40"
    )
      .bind(user.workspace_id, site.id)
      .all();
    const quotaRows = await env.DB.prepare(
      "SELECT display_balance, display_unit, raw_balance, raw_quota, source, billing_style, created_at FROM quota_snapshots WHERE workspace_id = ?1 AND site_id = ?2 ORDER BY id DESC LIMIT 30"
    )
      .bind(user.workspace_id, site.id)
      .all();
    const authHistory = await listAuthRefreshHistory(env, user.workspace_id, site.id, 40);
    const protocolReport = buildProtocolReportItem(site, profile, authHistory);
    return ok({
      site: publicSiteWithProfile(site, profile),
      health,
      diagnostic_matrix: health.diagnostic_matrix || [],
      capability_matrix: Object.entries(profile?.probe_meta?.capability_verdicts || {}).map(([area, row]) => ({
        area,
        ...row,
      })),
      protocol_family_evidence: {
        family: resolveSiteFamily(site),
        support_status: inferSupportStatus(site, profile),
      },
      auth_refresh_history: authHistory,
      frontend_confirmed_endpoints: profile?.probe_meta?.frontend_confirmed_endpoints || [],
      repair_guide: protocolReport.repair_steps || [],
      transport_chain: protocolReport.transport_chain || { state: "api_direct" },
      probe_budget: protocolReport.probe_budget || { limit: PROBE_REQUEST_BUDGET, used: 0, status: "ok" },
      bridge_status: protocolReport.bridge_status || { browser: "edge", preferred: true, has_materials: false },
      checkin_diagnostic: buildCheckinDiagnostic(site, latestCheckin, logs.results || []),
      recent_logs: logs.results || [],
      quota_history: quotaRows.results || [],
      generated_at: nowIso(),
    });
  }

  const siteAuthHistoryRoute = routeParams(pathname, /^\/api\/sites\/([A-Za-z0-9_-]{1,64})\/auth-history$/);
  if (siteAuthHistoryRoute && method === "GET") {
    const site = await dbGetSite(env, user.workspace_id, siteAuthHistoryRoute[0]);
    if (!site) return fail("site not found", 404);
    return ok({
      site_id: site.id,
      items: await listAuthRefreshHistory(env, user.workspace_id, site.id, Number(url.searchParams.get("limit") || 40)),
    });
  }

  const siteProtocolReportRoute = routeParams(pathname, /^\/api\/sites\/([A-Za-z0-9_-]{1,64})\/protocol-report$/);
  if (siteProtocolReportRoute && method === "GET") {
    const site = await dbGetSite(env, user.workspace_id, siteProtocolReportRoute[0]);
    if (!site) return fail("site not found", 404);
    const profile = await dbGetSiteProfile(env, user.workspace_id, site.id);
    const authHistory = await listAuthRefreshHistory(env, user.workspace_id, site.id, 10);
    return ok(buildProtocolReportItem(site, profile, authHistory));
  }

  const siteHealthHistoryRoute = routeParams(pathname, /^\/api\/sites\/([A-Za-z0-9_-]{1,64})\/health-history$/);
  if (siteHealthHistoryRoute && method === "GET") {
    const siteId = siteHealthHistoryRoute[0];
    const healthRows = await env.DB.prepare(
      "SELECT score, status, human_status, issue_codes, created_at FROM health_snapshots WHERE workspace_id = ?1 AND site_id = ?2 ORDER BY id DESC LIMIT 120"
    )
      .bind(user.workspace_id, siteId)
      .all();
    const quotaRows = await env.DB.prepare(
      "SELECT display_balance, display_unit, raw_balance, raw_quota, source, billing_style, created_at FROM quota_snapshots WHERE workspace_id = ?1 AND site_id = ?2 ORDER BY id DESC LIMIT 120"
    )
      .bind(user.workspace_id, siteId)
      .all();
    return ok({
      site_id: siteId,
      health: (healthRows.results || []).map((row) => ({
        ...row,
        issue_codes: parseJsonSafe(row.issue_codes, []),
      })),
      quota: quotaRows.results || [],
    });
  }

  if (pathname === "/api/sites" && method === "GET") {
    const sites = await dbListSites(env, user.workspace_id);
    const profileMap = await loadSiteProfileMap(env, user.workspace_id);
    return ok({
      items: sites.map((site) => publicSiteWithProfile(site, profileMap.get(site.id))),
    });
  }

  if (pathname === "/api/sites/readiness" && method === "GET") {
    const sites = await dbListSites(env, user.workspace_id);
    const profileMap = await loadSiteProfileMap(env, user.workspace_id);
    const latestCheckinMap = await loadLatestCheckinResultMap(env, user.workspace_id);
    const items = sites.map((site) => readinessForSite(site, profileMap.get(site.id), latestCheckinMap.get(site.id)));
    const summary = {
      total: items.length,
      enabled: items.filter((x) => x.enabled).length,
      ready: items.filter((x) => x.enabled && x.ready).length,
      blocked: items.filter((x) => x.enabled && !x.ready).length,
      missing_credentials: items.filter((x) => x.blockers.some((b) => b.code === "missing_credentials")).length,
      expired_credentials: items.filter((x) => x.blockers.some((b) => b.code === "expired_credentials")).length,
      quota_available: items.filter((x) => x.quota_status === "available").length,
      checkin_ready: items.filter((x) => x.can_checkin).length,
    };
    const completed = summary.enabled > 0 && items.filter((x) => x.enabled).every((x) => x.ready);
    return ok({
      completed,
      summary,
      items,
      next_actions: items
        .filter((x) => !x.ready)
        .map((x) => ({
          site_id: x.site_id,
          display_name: x.display_name,
          action: x.blockers[0]?.action || "重新检测站点",
          blockers: x.blockers.map((b) => b.label),
        })),
    });
  }

  if (pathname === "/api/sites/maintenance/repair" && method === "POST") {
    const result = await repairSiteConfigurations(env, user.workspace_id);
    return ok(result);
  }

  if (pathname === "/api/sites" && method === "POST") {
    const body = await parseBody(request);
    const site = validateSitePayload(body);
    await dbSaveSite(env, user.workspace_id, site);
    const replaced = await disableDuplicateSitesForImport(env, user.workspace_id, site);
    return ok({ ...publicSite(site), replaced_duplicates: replaced }, 201);
  }

  const sitePut = routeParams(pathname, /^\/api\/sites\/([A-Za-z0-9_-]{1,64})$/);
  if (sitePut && method === "PUT") {
    const siteId = sitePut[0];
    const existing = await dbGetSite(env, user.workspace_id, siteId);
    if (!existing) return fail("site not found", 404);
    const body = await parseBody(request);
    const patch = validateSitePayload({
      ...body,
      id: siteId,
      credentials: Object.prototype.hasOwnProperty.call(body, "credentials") ? body.credentials : existing.credentials,
      extra_headers: Object.prototype.hasOwnProperty.call(body, "extra_headers") ? body.extra_headers : existing.extra_headers,
      duplicate_replaced_by: Object.prototype.hasOwnProperty.call(body, "duplicate_replaced_by") ? body.duplicate_replaced_by : existing.duplicate_replaced_by,
    });
    await dbSaveSite(env, user.workspace_id, patch);
    return ok(publicSite(patch));
  }

  const siteCredentialsRoute = routeParams(pathname, /^\/api\/sites\/([A-Za-z0-9_-]{1,64})\/credentials$/);
  if (siteCredentialsRoute && method === "POST") {
    const siteId = siteCredentialsRoute[0];
    const site = await dbGetSite(env, user.workspace_id, siteId);
    if (!site) return fail("site not found", 404);
    const body = await parseBody(request);
    const adapter = ["new_api", "qingyi", "onetoken", "auth_shell"].includes(body.adapter) ? body.adapter : site.adapter;
    const extract = normalizeExtract(adapter, body.extract_result || body.extract || body.credentials || {});
    if (!hasAuthMaterial({ ...site, adapter, credentials: extract })) {
      return fail("本次提取结果里没有可用的 cookie/token，请先在目标站点登录后重新提取", 400);
    }
    const mergedCredentials = { ...(site.credentials || {}) };
    for (const [key, value] of Object.entries(extract)) {
      if (value !== undefined && value !== null && String(value).trim() !== "") mergedCredentials[key] = value;
    }
    const patched = {
      ...site,
      adapter,
      credentials: mergedCredentials,
      updated_at: nowIso(),
    };
    const validation = await validateCredentialsForSite(env, user.workspace_id, patched);
    if (!validation.ok) {
      return fail(
        `登录态验证失败：${validation.message}。请确认浏览器当前打开并登录的是 ${patched.base_url}，OneToken 需要提取 localStorage.openclaw_auth.accessToken。`,
        401,
        { validation }
      );
    }
    await dbSaveSite(env, user.workspace_id, patched);
    let inspect = null;
    try {
      const [capRes, quotaRes] = await Promise.allSettled([
        withTimeout(probeCapabilities(env, user.workspace_id, patched), 25000, "network_failed", "能力探测超时"),
        withTimeout(refreshQuota(env, user.workspace_id, patched), 30000, "network_failed", "额度读取超时"),
      ]);
      inspect = {
        capabilities: capRes.status === "fulfilled" ? capRes.value : null,
        quota: quotaRes.status === "fulfilled" ? quotaRes.value : null,
        quota_status: quotaRes.status === "fulfilled" ? "available" : quotaRes.reason?.code || "parse_failed",
        quota_note: quotaRes.status === "fulfilled" ? quotaRes.value.quota_parse_note || quotaRes.value.note || "" : String(quotaRes.reason?.message || quotaRes.reason || ""),
      };
    } catch (err) {
      inspect = { error: String(err?.message || err) };
    }
    const safeSite = {
      ...publicSite(patched),
      family: resolveSiteFamily(patched),
    };
    return ok({
      site: safeSite,
      credential_status: summarizeCredentialStatus(patched, inspect ? { capabilities: inspect.capabilities || {}, probe_errors: [] } : null),
      inspect,
      validation,
    });
  }

  const siteDel = routeParams(pathname, /^\/api\/sites\/([A-Za-z0-9_-]{1,64})$/);
  if (siteDel && method === "DELETE") {
    await dbDeleteSite(env, user.workspace_id, siteDel[0]);
    return ok({ deleted: siteDel[0] });
  }

  if (pathname === "/api/onboarding/probe" && method === "POST") {
    const body = await parseBody(request);
    const target = String(body.base_url || body.url || "").trim();
    if (!target) return fail("请输入站点 URL", 400);
    const result = await probeSite(target);
    return ok(result);
  }

  if (pathname === "/api/onboarding/extract" && method === "POST") {
    const body = await parseBody(request);
    const baseUrl = normalizeBaseUrl(body.base_url || body.url || "");
    const adapter = ["new_api", "qingyi", "onetoken"].includes(body.adapter) ? body.adapter : "new_api";
    const extract = normalizeExtract(adapter, body.extract_result || body.extract || {});
    const sites = await dbListSites(env, user.workspace_id);
    const used = new Set(sites.map((s) => s.id));
    const siteId = suggestSiteId(baseUrl, used);

    const draft = {
      id: siteId,
      name: siteId,
      adapter,
      base_url: baseUrl,
      enabled: true,
      credentials: extract,
      extra_headers: {},
      retry_override: null,
    };
    return ok(draft);
  }

  if (pathname === "/api/onboarding/extract-credentials" && method === "POST") {
    const body = await parseBody(request);
    const baseUrl = normalizeBaseUrl(body.base_url || body.url || "");
    const adapter = ["new_api", "qingyi", "onetoken"].includes(body.adapter) ? body.adapter : "new_api";
    const extract = normalizeExtract(adapter, body.extract_result || body.extract || {});
    const sites = await dbListSites(env, user.workspace_id);
    const used = new Set(sites.map((s) => s.id));
    const siteId = suggestSiteId(baseUrl, used);
    const draft = {
      id: siteId,
      name: siteId,
      adapter,
      base_url: baseUrl,
      enabled: true,
      credentials: extract,
      extra_headers: {},
      retry_override: null,
    };
    return ok(draft);
  }

  if (pathname === "/api/onboarding/auto" && method === "POST") {
    const body = await parseBody(request);
    const probe = await probeSite(body.base_url || body.url || "");
    const adapter = ["new_api", "qingyi", "onetoken"].includes(body.adapter) ? body.adapter : probe.adapter_guess;
    if (!["new_api", "qingyi", "onetoken"].includes(adapter)) return fail("auto extract currently supports only new_api / qingyi / onetoken", 400, { probe });

    const extract = normalizeExtract(adapter, body.extract_result || body.extract || {});
    const sites = await dbListSites(env, user.workspace_id);
    const used = new Set(sites.map((s) => s.id));
    const siteId = suggestSiteId(probe.base_url, used);

    const draft = {
      id: siteId,
      name: siteId,
      adapter,
      base_url: probe.base_url,
      enabled: true,
      credentials: extract,
      extra_headers: {},
      retry_override: null,
    };
    await dbSaveSite(env, user.workspace_id, draft);
    const replaced = await disableDuplicateSitesForImport(env, user.workspace_id, draft);
    return ok({ probe, site: draft, replaced_duplicates: replaced }, 201);
  }

  if (pathname === "/api/onboarding/save-site" && method === "POST") {
    const body = await parseBody(request);
    const site = validateSitePayload(body);
    await dbSaveSite(env, user.workspace_id, site);
    const replaced = await disableDuplicateSitesForImport(env, user.workspace_id, site);
    return ok({ site, replaced_duplicates: replaced }, 201);
  }

  const capRoute = routeParams(pathname, /^\/api\/site-capabilities\/([A-Za-z0-9_-]{1,64})$/);
  if (capRoute && method === "GET") {
    const site = await dbGetSite(env, user.workspace_id, capRoute[0]);
    if (!site) return fail("site not found", 404);
    const cap = await probeCapabilities(env, user.workspace_id, site);
    return ok({
      ...cap,
      last_probe_at: cap.last_probe_at || nowIso(),
      probe_errors: Array.isArray(cap.probe_errors) ? cap.probe_errors : [],
    });
  }

  const inspectRoute = routeParams(pathname, /^\/api\/sites\/([A-Za-z0-9_-]{1,64})\/inspect$/);
  if (inspectRoute && method === "GET") {
    const site = await dbGetSite(env, user.workspace_id, inspectRoute[0]);
    if (!site) return fail("site not found", 404);

    const [capRes, quotaRes] = await Promise.allSettled([
      withTimeout(probeCapabilities(env, user.workspace_id, site), 25000, "network_failed", "能力探测超时"),
      withTimeout(refreshQuota(env, user.workspace_id, site), 30000, "network_failed", "额度读取超时"),
    ]);
    const profile = await dbGetSiteProfile(env, user.workspace_id, site.id);
    const meta = profile?.probe_meta || {};
    const profileInfo = meta.profile || {};
    const cachedQuota = meta.quota_snapshot || null;
    const quotaError = quotaRes.status === "rejected" ? quotaRes.reason : null;
    const quotaValue = quotaRes.status === "fulfilled" ? quotaRes.value : cachedQuota?.quota_status === "available" ? cachedQuota : null;
    const quotaStatus =
      quotaValue
        ? "available"
        : quotaError?.code || (String(quotaError?.message || "").includes("missing credentials") ? "auth_failed" : "parse_failed");
    return ok({
      family: resolveSiteFamily(site),
      capabilities: capRes.status === "fulfilled" ? capRes.value : profile?.capabilities || null,
      quota: quotaValue,
      quota_status: quotaStatus,
      quota_source: quotaValue ? quotaValue.quota_source || quotaValue.source || "" : "",
      quota_parse_note: quotaValue
        ? `${quotaValue.quota_parse_note || quotaValue.note || "解析成功"}${quotaRes.status === "rejected" ? "（使用最近一次有效快照）" : ""}`
        : String(quotaError?.message || ""),
      credential_status: summarizeCredentialStatus(site, {
        capabilities: capRes.status === "fulfilled" ? capRes.value : profile?.capabilities || {},
        probe_errors: profile?.probe_errors || [],
      }),
      auth_state: describeAuthState(site, {
        capabilities: capRes.status === "fulfilled" ? capRes.value : profile?.capabilities || {},
        probe_errors: profile?.probe_errors || [],
      }),
      support_status: inferSupportStatus(site, profile),
      source_confidence_summary: summarizeSourceConfidence(meta),
      capability_verdicts: meta.capability_verdicts || {},
      profile: profileInfo,
      profile_source: meta.profile_source || "",
      last_probe_at: profile?.last_probe_at || (capRes.status === "fulfilled" ? capRes.value.last_probe_at : null),
      probe_errors: profile?.probe_errors || (capRes.status === "fulfilled" ? capRes.value.probe_errors : []),
      capability_error: capRes.status === "rejected" ? String(capRes.reason?.message || capRes.reason || "") : "",
      quota_error: quotaRes.status === "rejected" ? String(quotaRes.reason?.message || quotaRes.reason || "") : "",
    });
  }

  const profileModelCache = async (site, modelsView) => {
    await patchSiteProbeMeta(env, user.workspace_id, site.id, {
      model_catalog_cache: summarizeModelCache(modelsView),
    });
  };

  const keyListRoute = routeParams(pathname, /^\/api\/sites\/([A-Za-z0-9_-]{1,64})\/keys$/);
  if (keyListRoute && method === "GET") {
    const site = await dbGetSite(env, user.workspace_id, keyListRoute[0]);
    if (!site) return fail("site not found", 404);
    const items = await listKeys(env, user.workspace_id, site);
    return ok({ items: items.map((x) => ({ ...x, raw_key: undefined })) });
  }

  const keyExtractRoute = routeParams(pathname, /^\/api\/sites\/([A-Za-z0-9_-]{1,64})\/keys\/extract$/);
  if (keyExtractRoute && method === "POST") {
    const site = await dbGetSite(env, user.workspace_id, keyExtractRoute[0]);
    if (!site) return fail("site not found", 404);
    const body = await parseBody(request);
    const preferred = String(body.preferred_name || "");
    const data = await extractExistingKey(env, user.workspace_id, site, preferred);
    return ok(data);
  }

  const keyCreateRoute = routeParams(pathname, /^\/api\/sites\/([A-Za-z0-9_-]{1,64})\/keys\/create$/);
  if (keyCreateRoute && method === "POST") {
    const site = await dbGetSite(env, user.workspace_id, keyCreateRoute[0]);
    if (!site) return fail("site not found", 404);
    const body = await parseBody(request);
    const name = String(body.name || "");
    const group = String(body.group || "");
    const data = await createNewKey(env, user.workspace_id, site, name, group);
    return ok(data, 201);
  }

  const groupRoute = routeParams(pathname, /^\/api\/sites\/([A-Za-z0-9_-]{1,64})\/key-groups$/);
  if (groupRoute && method === "GET") {
    const site = await dbGetSite(env, user.workspace_id, groupRoute[0]);
    if (!site) return fail("site not found", 404);
    const groups = await getKeyGroups(env, user.workspace_id, site);
    return ok(groups);
  }

  const modelDiagRoute = routeParams(pathname, /^\/api\/sites\/([A-Za-z0-9_-]{1,64})\/models\/diagnostics$/);
  if (modelDiagRoute && method === "GET") {
    const site = await dbGetSite(env, user.workspace_id, modelDiagRoute[0]);
    if (!site) return fail("site not found", 404);
    const catalog = await fetchModelCatalog(env, user.workspace_id, site);
    const priced = catalog.items.filter((m) => hasPricingValue(m.pricing || {})).length;
    const hasHtmlChallenge = (catalog.diagnostics || []).some((row) => /html|challenge|expected json/i.test(String(row.message || "")));
    await patchSiteProbeMeta(env, user.workspace_id, site.id, {
      model_catalog_cache: summarizeModelCache({
        source: catalog.source,
        diagnostics: catalog.diagnostics,
        items: catalog.items.map((item) => toModelViewItem(item)),
      }),
    });
    return ok({
      family: resolveSiteFamily(site),
      model_count: catalog.items.length,
      priced_count: priced,
      source: catalog.source,
      diagnostics: catalog.diagnostics || [],
      diagnostic_matrix: (catalog.diagnostics || []).map((row) => ({
        area: row.type,
        title: row.ok ? "接口已响应" : "接口不可用",
        status: row.ok && Number(row.parsed_count || 0) > 0 ? "ok" : row.ok ? "info" : "warn",
        evidence: `${row.path} | HTTP ${row.status == null ? "-" : row.status} | 解析 ${row.parsed_count || 0} | 有价 ${row.priced_count || 0}`,
        next_action:
          row.ok && Number(row.parsed_count || 0) > 0
            ? "检查模型表中的价格可信度"
            : "若全部为空，通常是站点未开放该接口或当前账号权限不足",
      })),
      support_status:
        hasHtmlChallenge
          ? "supported_but_auth_expired"
          : resolveSiteFamily(site) === "onetoken" && !catalog.items.length
          ? "key_limited"
          : catalog.items.length
            ? "supported"
            : "not_exposed",
      note:
        catalog.items.length && !priced
          ? "已拿到模型目录，但站点未在已知接口返回倍率/固定价字段"
          : catalog.items.length
            ? "已解析模型目录与部分计价字段"
            : "未能从已知模型接口解析出模型目录",
    });
  }

  const modelsRoute = routeParams(pathname, /^\/api\/sites\/([A-Za-z0-9_-]{1,64})\/models$/);
  if (modelsRoute && method === "GET") {
    const site = await dbGetSite(env, user.workspace_id, modelsRoute[0]);
    if (!site) return fail("site not found", 404);
    const models = await getSiteModelsView(env, user.workspace_id, site);
    const hasHtmlChallenge = (models.diagnostics || []).some((row) => /html|challenge|expected json/i.test(String(row.message || "")));
    await profileModelCache(site, models);
    return ok({
      ...models,
      support_status:
        hasHtmlChallenge
          ? "supported_but_auth_expired"
          : resolveSiteFamily(site) === "onetoken" && !models.items.length
          ? "key_limited"
          : models.items.length
            ? "supported"
            : "not_exposed",
    });
  }

  const groupsModelsRoute = routeParams(pathname, /^\/api\/sites\/([A-Za-z0-9_-]{1,64})\/groups-models$/);
  if (groupsModelsRoute && method === "GET") {
    const site = await dbGetSite(env, user.workspace_id, groupsModelsRoute[0]);
    if (!site) return fail("site not found", 404);
    const groups = await getKeyGroups(env, user.workspace_id, site);
    if (!groups.items.length) {
      const catalog = await getSiteModelsView(env, user.workspace_id, site);
      await profileModelCache(site, catalog);
      return ok({
        source: groups.source || "",
        model_source: catalog.source,
        family: resolveSiteFamily(site),
        fallback: "catalog-only",
        items: [
          {
            id: "all",
            name: "全模型目录",
            model_count: catalog.items.length,
            models: catalog.items,
          },
        ],
      });
    }
    return ok({
      ...groups,
      family: resolveSiteFamily(site),
      fallback: "",
    });
  }

  const quotaRoute = routeParams(pathname, /^\/api\/sites\/([A-Za-z0-9_-]{1,64})\/quota$/);
  if (quotaRoute && method === "GET") {
    const site = await dbGetSite(env, user.workspace_id, quotaRoute[0]);
    if (!site) return fail("site not found", 404);
    try {
      const data = await refreshQuota(env, user.workspace_id, site);
      return ok(data);
    } catch (err) {
      const code = err?.code || (String(err?.message || "").includes("missing credentials") ? "auth_failed" : "parse_failed");
      return ok({
        quota_status: code,
        balance: null,
        today_spend: null,
        total_spend: null,
        raw_quota: null,
        total_quota: null,
        used_quota: null,
        normalized_unit: "",
        currency: "",
        note: "",
        quota_parse_note: String(err?.message || err || "读取额度失败"),
        source: "",
        quota_source: "",
      });
    }
  }

  const apiUrlRoute = routeParams(pathname, /^\/api\/api-url\/([A-Za-z0-9_-]{1,64})$/);
  if (apiUrlRoute && method === "GET") {
    const site = await dbGetSite(env, user.workspace_id, apiUrlRoute[0]);
    if (!site) return fail("site not found", 404);
    const apiBase = resolveSiteFamily(site) === "onetoken" ? "https://router.onetoken.sh/v1" : `${site.base_url}/v1`;
    return ok({
      base_url: site.base_url,
      base_url_v1: apiBase,
      paths: {
        chat_completions: `${apiBase}/chat/completions`,
        responses: `${apiBase}/responses`,
        embeddings: `${apiBase}/embeddings`,
      },
    });
  }

  const channelCreateRoute = routeParams(pathname, /^\/api\/channel\/([A-Za-z0-9_-]{1,64})\/create$/);
  if (channelCreateRoute && method === "POST") {
    const site = await dbGetSite(env, user.workspace_id, channelCreateRoute[0]);
    if (!site) return fail("site not found", 404);
    const body = await parseBody(request);
    const created = await createChannel(env, user.workspace_id, site, body);
    return ok(created, 201);
  }

  const tokenListCompat = routeParams(pathname, /^\/api\/token\/([A-Za-z0-9_-]{1,64})$/);
  if (tokenListCompat && method === "GET") {
    const site = await dbGetSite(env, user.workspace_id, tokenListCompat[0]);
    if (!site) return fail("site not found", 404);
    const items = await listKeys(env, user.workspace_id, site);
    return ok({ items: items.map((x) => ({ ...x, raw_key: undefined })) });
  }

  const tokenCreateCompat = routeParams(pathname, /^\/api\/token\/([A-Za-z0-9_-]{1,64})\/create$/);
  if (tokenCreateCompat && method === "POST") {
    const site = await dbGetSite(env, user.workspace_id, tokenCreateCompat[0]);
    if (!site) return fail("site not found", 404);
    const body = await parseBody(request);
    const name = String(body.name || "");
    const group = String(body.group || "");
    const data = await createNewKey(env, user.workspace_id, site, name, group);
    return ok(data, 201);
  }

  const tokenEnsureCompat = routeParams(pathname, /^\/api\/token\/([A-Za-z0-9_-]{1,64})\/ensure$/);
  if (tokenEnsureCompat && method === "POST") {
    const site = await dbGetSite(env, user.workspace_id, tokenEnsureCompat[0]);
    if (!site) return fail("site not found", 404);
    const body = await parseBody(request);
    const preferred = String(body.preferred_name || body.name || "");
    try {
      const existing = await extractExistingKey(env, user.workspace_id, site, preferred);
      return ok(existing);
    } catch (_) {
      const created = await createNewKey(env, user.workspace_id, site, preferred, String(body.group || ""));
      return ok(created, 201);
    }
  }

  if (pathname === "/api/checkin/run" && method === "POST") {
    const body = await parseBody(request);
    const params = {
      site_ids: Array.isArray(body.site_ids) ? body.site_ids : [],
      dry_run: Boolean(body.dry_run),
      retry: body.retry == null ? null : Number(body.retry),
      retry_delay: body.retry_delay == null ? null : Number(body.retry_delay),
      enabled_only: body.enabled_only !== false,
    };
    const res = await runCheckinJob(env, user.workspace_id, "manual", params);
    return ok(res);
  }

  const eventsRoute = routeParams(pathname, /^\/api\/jobs\/([A-Za-z0-9]+)\/events$/);
  if (eventsRoute && method === "GET") {
    return streamJobEvents(env, user.workspace_id, eventsRoute[0]);
  }

  if (pathname === "/api/checkin/history" && method === "GET") {
    const rows = await env.DB.prepare("SELECT id, trigger_type, status, result_json, created_at, updated_at FROM jobs WHERE workspace_id = ?1 ORDER BY created_at DESC LIMIT 50")
      .bind(user.workspace_id)
      .all();
    const items = (rows.results || []).map((x) => {
      const result = x.result_json ? JSON.parse(x.result_json) : null;
      const summary = summarizeCheckinByLevel(result?.report || null);
      return {
        ...x,
        result: result && result.report ? { ...result, report: { ...result.report, checkin_summary_by_level: result.report.checkin_summary_by_level || summary } } : result,
        checkin_summary_by_level: summary,
      };
    });
    return ok({ items, latest_summary: items[0]?.checkin_summary_by_level || summarizeCheckinByLevel(null) });
  }

  if (pathname === "/api/logs/system" && method === "GET") {
    const items = await listSystemLogs(env, user.workspace_id, url.searchParams);
    return ok({ items });
  }

  if (pathname === "/api/request-log" && method === "GET") {
    const items = await listSystemLogs(env, user.workspace_id, url.searchParams);
    return ok({ items });
  }

  if (pathname === "/api/logs/usage" && method === "GET") {
    const items = await listUsageLogs(env, user.workspace_id, url.searchParams);
    return ok({ items });
  }

  if (pathname === "/api/logs/usage/summary" && method === "GET") {
    const summary = await getUsageSummary(env, user.workspace_id, url.searchParams);
    return ok(summary);
  }

  if (pathname === "/api/logs/usage/refresh" && method === "POST") {
    const body = await parseBody(request);
    const siteIds = Array.isArray(body.site_ids) ? body.site_ids.map((x) => String(x || "").trim()).filter(Boolean) : [];
    const sites = await dbListSites(env, user.workspace_id);
    const enabledSites = sites.filter((s) => s.enabled && (!siteIds.length || siteIds.includes(s.id)));
    const out = [];
    for (const s of enabledSites) {
      out.push({ site_id: s.id, ...(await refreshUsageForSite(env, user.workspace_id, s)) });
    }
    const settings = await getWorkspaceSettings(env, user.workspace_id);
    await evaluateAlerts(env, user.workspace_id, sites, settings.alert_policy);
    return ok({ items: out, selected_site_count: enabledSites.length });
  }

  if (pathname === "/api/logs/usage/export.csv" && method === "GET") {
    const rows = await listUsageLogs(env, user.workspace_id, url.searchParams);
    const csv = toCsv(rows);
    return new Response(csv, {
      headers: {
        "content-type": "text/csv; charset=utf-8",
        "content-disposition": `attachment; filename=\"usage-logs-${Date.now()}.csv\"`,
      },
    });
  }

  if (pathname === "/api/schedule" && method === "GET") {
    const row = await ensureSchedule(env, user.workspace_id);
    return ok(row);
  }

  if (pathname === "/api/schedule" && method === "PUT") {
    const body = await parseBody(request);
    const enabled = body.enabled === false ? 0 : 1;
    const time = String(body.time || "09:05").trim();
    if (!/^\d{2}:\d{2}$/.test(time)) return fail("time 必须是 HH:MM", 400);
    const timezone = String(body.timezone || "Asia/Shanghai").trim() || "Asia/Shanghai";

    await env.DB.prepare(
      "INSERT INTO schedules (workspace_id, enabled, time_hhmm, timezone, last_run_date) VALUES (?1, ?2, ?3, ?4, NULL) ON CONFLICT(workspace_id) DO UPDATE SET enabled=excluded.enabled, time_hhmm=excluded.time_hhmm, timezone=excluded.timezone"
    )
      .bind(user.workspace_id, enabled, time, timezone)
      .run();
    const row = await ensureSchedule(env, user.workspace_id);
    return ok(row);
  }

  if (pathname === "/api/schedule/run-now" && method === "POST") {
    const res = await runCheckinJob(env, user.workspace_id, "schedule-manual", {
      site_ids: [],
      dry_run: false,
      retry: null,
      retry_delay: null,
      enabled_only: true,
    });
    return ok(res);
  }

  return fail("api not found", 404);
}

async function handleScheduled(controller, env) {
  await ensureExtendedSchema(env);
  await ensureBootstrapUser(env);
  const { date, time } = shanghaiDateTime();
  const rows = await env.DB.prepare("SELECT workspace_id, enabled, time_hhmm, last_run_date FROM schedules WHERE enabled = 1").all();
  const items = rows.results || [];

  for (const row of items) {
    if (row.time_hhmm !== time) continue;
    if (row.last_run_date === date) continue;
    const workspaceId = row.workspace_id;
    controller.waitUntil(
      (async () => {
        await runCheckinJob(env, workspaceId, "schedule", {
          site_ids: [],
          dry_run: false,
          retry: null,
          retry_delay: null,
          enabled_only: true,
        });
        await env.DB.prepare("UPDATE schedules SET last_run_date = ?1 WHERE workspace_id = ?2").bind(date, workspaceId).run();
      })()
    );
  }
}

async function routeFetch(request, env) {
  await ensureExtendedSchema(env);
  await ensureBootstrapUser(env);
  const url = new URL(request.url);
  const path = url.pathname;

  if (!path.startsWith("/api/")) {
    return env.ASSETS.fetch(request);
  }

  const user = await getUserBySession(env, request);
  return handleApi(env, request, user);
}

export default {
  async fetch(request, env) {
    try {
      return await routeFetch(request, env);
    } catch (err) {
      return fail(String((err && err.message) || err), 500);
    }
  },
  async scheduled(controller, env) {
    await handleScheduled(controller, env);
  },
};

export class WorkspaceLock {
  constructor(state) {
    this.state = state;
    this.lock = null;
  }

  async ensureLoaded() {
    if (this.lock !== null) return;
    this.lock = (await this.state.storage.get("lock")) || null;
  }

  async fetch(request) {
    await this.ensureLoaded();
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/acquire" && request.method.toUpperCase() === "POST") {
      const body = await request.json();
      const jobId = String(body.job_id || "");
      const now = Date.now();
      const expireMs = 30 * 60 * 1000;

      if (this.lock && this.lock.job_id !== jobId && now - Number(this.lock.ts || 0) < expireMs) {
        return json({ ok: false, holder: this.lock.job_id }, 409);
      }

      this.lock = { job_id: jobId, ts: now };
      await this.state.storage.put("lock", this.lock);
      return json({ ok: true });
    }

    if (path === "/release" && request.method.toUpperCase() === "POST") {
      const body = await request.json();
      const jobId = String(body.job_id || "");
      if (!this.lock || this.lock.job_id === jobId) {
        this.lock = null;
        await this.state.storage.delete("lock");
        return json({ ok: true });
      }
      return json({ ok: false, holder: this.lock.job_id }, 409);
    }

    if (path === "/status") {
      return json({ ok: true, lock: this.lock });
    }

    return json({ ok: false, message: "not found" }, 404);
  }
}


