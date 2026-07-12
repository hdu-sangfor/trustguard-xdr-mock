/**
 * Sangfor XDR Mock - Apifox 前置签名脚本
 *
 * 环境变量：
 *   xdr_ak = test_ak_0001
 *   xdr_sk = test_sk_0001_secret
 *
 * 脚本会先请求同一服务的 /health，以服务端返回的 signDate 生成签名，
 * 自动兼容 Windows、Docker、WSL 和不同时区。/health 失败时回退到客户端本地时间。
 */

const CryptoJS = require("crypto-js");
const { Buffer } = require("buffer");
const urlLib = require("url");

const ak = pm.environment.get("xdr_ak") || pm.variables.get("xdr_ak");
const sk = pm.environment.get("xdr_sk") || pm.variables.get("xdr_sk");

if (!ak || !sk) {
  throw new Error("缺少环境变量 xdr_ak 或 xdr_sk");
}

function pad2(value) {
  return String(value).padStart(2, "0");
}

function createLocalSignDate() {
  const now = new Date();
  return (
    now.getFullYear() +
    pad2(now.getMonth() + 1) +
    pad2(now.getDate()) +
    "T" +
    pad2(now.getHours()) +
    pad2(now.getMinutes()) +
    pad2(now.getSeconds()) +
    "Z"
  );
}

function encodePath(path) {
  return encodeURIComponent(path)
    .replace(/%2F/gi, "/")
    .replace(/[!'()*]/g, function (char) {
      return "%" + char.charCodeAt(0).toString(16).toUpperCase();
    });
}

function quotePlus(value) {
  return encodeURIComponent(value)
    .replace(/[!'()*]/g, function (char) {
      return "%" + char.charCodeAt(0).toString(16).toUpperCase();
    })
    .replace(/%20/g, "+");
}

function canonicalQuery(rawQuery) {
  if (!rawQuery) {
    return "";
  }
  return rawQuery
    .split("&")
    .filter(function (token) {
      return token !== "";
    })
    .sort()
    .map(function (token) {
      if (!token.includes("=")) {
        token += "=";
      }
      const equalIndex = token.indexOf("=");
      const key = token.substring(0, equalIndex);
      const value = token.substring(equalIndex + 1);
      return quotePlus(key) + "=" + quotePlus(value);
    })
    .join("&");
}

function wordArrayFromBytes(bytes) {
  const words = [];
  for (let i = 0; i < bytes.length; i++) {
    const wordIndex = i >>> 2;
    const bitOffset = 24 - (i % 4) * 8;
    words[wordIndex] = (words[wordIndex] || 0) | (bytes[i] << bitOffset);
  }
  return CryptoJS.lib.WordArray.create(words, bytes.length);
}

function sha256Upper(value) {
  return CryptoJS.SHA256(value).toString(CryptoJS.enc.Hex).toUpperCase();
}

function payloadHash(payload) {
  const text = payload === null || payload === undefined ? "" : String(payload);
  if (text.length === 0) {
    return sha256Upper(CryptoJS.lib.WordArray.create([], 0));
  }

  const utf8Bytes = Buffer.from(text, "utf8");
  const signedBytes = Array.from(utf8Bytes).map(function (value) {
    return value > 127 ? value - 256 : value;
  });
  signedBytes.sort(function (a, b) {
    return a - b;
  });

  const sortedBytes = signedBytes
    .map(function (value) {
      return value & 0xff;
    })
    .filter(function (value) {
      return value !== 0x20;
    });
  return sha256Upper(wordArrayFromBytes(sortedBytes));
}

function upsertHeader(key, value) {
  pm.request.headers.upsert({ key: key, value: String(value) });
}

function getRawBody(method) {
  if (!["POST", "PUT", "PATCH"].includes(method)) {
    return "";
  }
  if (!pm.request.body || pm.request.body.raw === null || pm.request.body.raw === undefined) {
    return "";
  }
  return pm.variables.replaceIn(String(pm.request.body.raw));
}

const requestUrl = pm.variables.replaceIn(pm.request.url.toString());
if (!requestUrl) {
  throw new Error("请求 URL 为空");
}
if (requestUrl.includes("{") || requestUrl.includes("}")) {
  throw new Error("请求 URL 仍包含未替换的路径参数: " + requestUrl);
}

const parsedUrl = urlLib.parse(requestUrl);
if (!parsedUrl.protocol || !parsedUrl.host) {
  throw new Error("无法解析请求 URL: " + requestUrl);
}

const method = String(pm.request.method || "GET").toUpperCase();
let path = parsedUrl.pathname || "/";
if (!path.endsWith("/")) {
  path += "/";
}
const encodedPath = encodePath(path);
const query = canonicalQuery(parsedUrl.query || "");

function applyXdrSignature(signDate, timeSource) {
  if (!/^\d{8}T\d{6}Z$/.test(signDate)) {
    throw new Error("signDate 格式非法: " + signDate);
  }

  const sdkHost = parsedUrl.host;
  const contentType = "application/json";
  const body = getRawBody(method);

  upsertHeader("content-type", contentType);
  upsertHeader("sdk-content-type", contentType);
  upsertHeader("sdk-host", sdkHost);
  upsertHeader("sign-date", signDate);

  const signedHeaders = "content-type;sdk-content-type;sdk-host;sign-date";
  const headerBlock =
    "content-type:" + contentType + "\n" +
    "sdk-content-type:" + contentType + "\n" +
    "sdk-host:" + sdkHost + "\n" +
    "sign-date:" + signDate + "\n";

  const bodyHash = payloadHash(body);
  const canonicalRequest =
    method + "\n" +
    encodedPath + "\n" +
    query + "\n" +
    headerBlock +
    signedHeaders + "\n" +
    bodyHash;
  const canonicalHash = sha256Upper(CryptoJS.enc.Utf8.parse(canonicalRequest));
  const totalString = "HMAC-SHA256\n" + signDate + "\n" + canonicalHash;
  const signature = CryptoJS.HmacSHA256(totalString, sk)
    .toString(CryptoJS.enc.Hex)
    .toUpperCase();
  const authorization =
    "algorithm=HMAC-SHA256, " +
    "Access=" + ak + ", " +
    "SignedHeaders=" + signedHeaders + ", " +
    "Signature=" + signature;

  upsertHeader("Authorization", authorization);

  console.log("========== XDR SIGN DEBUG ==========");
  console.log("Time source:", timeSource);
  console.log("Request URL:", requestUrl);
  console.log("Method:", method);
  console.log("Path:", path);
  console.log("Canonical Query:", query);
  console.log("sign-date:", signDate);
  console.log("Body Hash:", bodyHash);
  console.log("Canonical Request:\n" + canonicalRequest);
  console.log("Canonical Hash:", canonicalHash);
  console.log("Signature:", signature);
  console.log("Authorization:", authorization);
  console.log("====================================");
}

const healthUrl = parsedUrl.protocol + "//" + parsedUrl.host + "/health";

pm.sendRequest(
  {
    url: healthUrl,
    method: "GET",
    header: { "Cache-Control": "no-cache" },
  },
  function (error, response) {
    if (error) {
      console.warn("获取服务端时间失败，回退到客户端本地时间:", error);
      applyXdrSignature(createLocalSignDate(), "client-local-fallback");
      return;
    }

    try {
      const payload = response.json();
      if (response.code !== 200 || !payload || !payload.signDate) {
        throw new Error("/health 未返回有效 signDate");
      }
      applyXdrSignature(String(payload.signDate), "server-health");
    } catch (healthError) {
      console.warn("解析服务端时间失败，回退到客户端本地时间:", healthError);
      applyXdrSignature(createLocalSignDate(), "client-local-fallback");
    }
  }
);
