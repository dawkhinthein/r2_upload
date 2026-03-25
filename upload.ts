import { crypto } from "https://deno.land/std@0.224.0/crypto/mod.ts";
import { encodeHex } from "https://deno.land/std@0.224.0/encoding/hex.ts";

// ============ R2 Account 1 ============
const R2_ACC1_ACCOUNT_ID = Deno.env.get("R2_ACC1_ACCOUNT_ID")!;
const R2_ACC1_ACCESS_KEY_ID = Deno.env.get("R2_ACC1_ACCESS_KEY_ID")!;
const R2_ACC1_SECRET_ACCESS_KEY = Deno.env.get("R2_ACC1_SECRET_ACCESS_KEY")!;
const R2_ACC1_BUCKET_NAME = Deno.env.get("R2_ACC1_BUCKET_NAME")!;

// ============ R2 Account 2 ============
const R2_ACC2_ACCOUNT_ID = Deno.env.get("R2_ACC2_ACCOUNT_ID")!;
const R2_ACC2_ACCESS_KEY_ID = Deno.env.get("R2_ACC2_ACCESS_KEY_ID")!;
const R2_ACC2_SECRET_ACCESS_KEY = Deno.env.get("R2_ACC2_SECRET_ACCESS_KEY")!;
const R2_ACC2_BUCKET_NAME = Deno.env.get("R2_ACC2_BUCKET_NAME")!;

// R2 Account configs array
interface R2Account {
  accountId: string;
  accessKeyId: string;
  secretAccessKey: string;
  bucketName: string;
  label: string;
}

const R2_ACCOUNTS: R2Account[] = [
  {
    accountId: R2_ACC1_ACCOUNT_ID,
    accessKeyId: R2_ACC1_ACCESS_KEY_ID,
    secretAccessKey: R2_ACC1_SECRET_ACCESS_KEY,
    bucketName: R2_ACC1_BUCKET_NAME,
    label: "Account-1",
  },
  {
    accountId: R2_ACC2_ACCOUNT_ID,
    accessKeyId: R2_ACC2_ACCESS_KEY_ID,
    secretAccessKey: R2_ACC2_SECRET_ACCESS_KEY,
    bucketName: R2_ACC2_BUCKET_NAME,
    label: "Account-2",
  },
];

// Download link bases — Account 1 links first, Account 2 links next
const DOWNLOAD_LINKS_MAP: Record<string, string[]> = {
  "Account-1": [
    "https://kajarling.kajarling.ooguy.com/download",
    "https://pub-9c8bcd6f32434fe08628852555cc2e5c.r2.dev",
  ],
  "Account-2": [
    "https://lugyiappreel.carton-lugyiapp.gleeze.com/download",
    "https://pub-cbf23f7a9f914d1a88f8f1cf741716db.r2.dev",
  ],
};

// ============ Utility Functions ============

function generateUniqueFilename(extension: string): string {
  const timestamp = Date.now();
  const randomBytes = crypto.getRandomValues(new Uint8Array(8));
  const randomHex = encodeHex(randomBytes);
  return `${timestamp}_${randomHex}${extension}`;
}

function getExtension(filename: string, contentType?: string): string {
  const match = filename.match(/\.([a-zA-Z0-9]+)(\?.*)?$/);
  if (match) return `.${match[1].toLowerCase()}`;

  const mimeMap: Record<string, string> = {
    "video/mp4": ".mp4",
    "video/webm": ".webm",
    "video/x-matroska": ".mkv",
    "video/quicktime": ".mov",
    "video/x-msvideo": ".avi",
    "video/x-flv": ".flv",
    "audio/mpeg": ".mp3",
    "audio/mp4": ".m4a",
    "audio/ogg": ".ogg",
    "audio/wav": ".wav",
    "audio/flac": ".flac",
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "image/svg+xml": ".svg",
    "application/pdf": ".pdf",
    "application/zip": ".zip",
    "application/x-rar-compressed": ".rar",
    "application/x-7z-compressed": ".7z",
    "application/gzip": ".gz",
    "application/json": ".json",
    "text/plain": ".txt",
    "text/html": ".html",
    "application/octet-stream": ".bin",
  };

  if (contentType) {
    const base = contentType.split(";")[0].trim().toLowerCase();
    if (mimeMap[base]) return mimeMap[base];
  }

  return ".mp4";
}

function buildDownloadLinks(filename: string): string[] {
  const links: string[] = [];
  for (const account of R2_ACCOUNTS) {
    const bases = DOWNLOAD_LINKS_MAP[account.label] || [];
    for (const base of bases) {
      links.push(`${base}/${filename}`);
    }
  }
  return links;
}

// ============ AWS Signature V4 ============

async function hmacSHA256(key: ArrayBuffer | Uint8Array, message: string): Promise<ArrayBuffer> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(message));
}

async function sha256(data: Uint8Array | string): Promise<string> {
  const encoded = typeof data === "string" ? new TextEncoder().encode(data) : data;
  const hash = await crypto.subtle.digest("SHA-256", encoded);
  return encodeHex(new Uint8Array(hash));
}

async function getSignatureKey(
  key: string,
  dateStamp: string,
  region: string,
  service: string
): Promise<ArrayBuffer> {
  const kDate = await hmacSHA256(new TextEncoder().encode("AWS4" + key), dateStamp);
  const kRegion = await hmacSHA256(kDate, region);
  const kService = await hmacSHA256(kRegion, service);
  return await hmacSHA256(kService, "aws4_request");
}

async function uploadToR2(
  account: R2Account,
  objectKey: string,
  body: Uint8Array,
  contentType: string
): Promise<void> {
  const endpoint = `https://${account.accountId}.r2.cloudflarestorage.com`;
  const url = new URL(`/${account.bucketName}/${objectKey}`, endpoint);
  const region = "auto";
  const service = "s3";

  const now = new Date();
  const amzDate = now.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const dateStamp = amzDate.substring(0, 8);

  const payloadHash = await sha256(body);
  const canonicalUri = `/${account.bucketName}/${encodeURIComponent(objectKey).replace(/%2F/g, "/")}`;

  const host = url.host;
  const headers: Record<string, string> = {
    "content-length": body.byteLength.toString(),
    "content-type": contentType,
    host: host,
    "x-amz-content-sha256": payloadHash,
    "x-amz-date": amzDate,
  };

  const signedHeaderKeys = Object.keys(headers).sort();
  const signedHeadersStr = signedHeaderKeys.join(";");
  const canonicalHeaders = signedHeaderKeys.map((k) => `${k}:${headers[k]}\n`).join("");

  const canonicalRequest = [
    "PUT",
    canonicalUri,
    "",
    canonicalHeaders,
    signedHeadersStr,
    payloadHash,
  ].join("\n");

  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    await sha256(canonicalRequest),
  ].join("\n");

  const signingKey = await getSignatureKey(account.secretAccessKey, dateStamp, region, service);
  const signatureBuffer = await hmacSHA256(signingKey, stringToSign);
  const signature = encodeHex(new Uint8Array(signatureBuffer));

  const authorization = `AWS4-HMAC-SHA256 Credential=${account.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeadersStr}, Signature=${signature}`;

  const res = await fetch(url.toString(), {
    method: "PUT",
    headers: {
      ...headers,
      Authorization: authorization,
    },
    body,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`R2 [${account.label}] upload failed: ${res.status} ${text}`);
  }
  await res.text();
}

// Upload to BOTH accounts in parallel
async function uploadToBothR2(
  objectKey: string,
  body: Uint8Array,
  contentType: string
): Promise<{ results: string[] }> {
  const results = await Promise.allSettled(
    R2_ACCOUNTS.map((acc) => uploadToR2(acc, objectKey, body, contentType))
  );

  const successes: string[] = [];
  const errors: string[] = [];

  results.forEach((result, i) => {
    if (result.status === "fulfilled") {
      successes.push(R2_ACCOUNTS[i].label);
    } else {
      errors.push(`${R2_ACCOUNTS[i].label}: ${result.reason?.message}`);
    }
  });

  if (successes.length === 0) {
    throw new Error(`All R2 uploads failed: ${errors.join("; ")}`);
  }

  return { results: successes };
}

// ============ Handle Direct File Upload ============
export async function handleUpload(req: Request): Promise<{
  filename: string;
  size: number;
  links: string[];
  uploadedTo: string[];
}> {
  const contentType = req.headers.get("content-type") || "";

  if (!contentType.includes("multipart/form-data")) {
    throw new Error("Unsupported content type");
  }

  const formData = await req.formData();
  const file = formData.get("file") as File | null;
  if (!file) throw new Error("No file provided");

  const ext = getExtension(file.name, file.type);
  const uniqueName = generateUniqueFilename(ext);
  const buffer = new Uint8Array(await file.arrayBuffer());
  const mime = file.type || "application/octet-stream";

  const { results } = await uploadToBothR2(uniqueName, buffer, mime);

  return {
    filename: uniqueName,
    size: buffer.byteLength,
    links: buildDownloadLinks(uniqueName),
    uploadedTo: results,
  };
}

// ============ Handle Remote URL Upload (Stream + Progress) ============
export async function handleRemoteUpload(
  remoteUrl: string,
  onProgress?: (progress: { loaded: number; total: number; percent: number; phase: string }) => void
): Promise<{
  filename: string;
  size: number;
  links: string[];
  uploadedTo: string[];
}> {
  // Phase 1: Download from remote
  if (onProgress) onProgress({ loaded: 0, total: 0, percent: 0, phase: "connecting" });

  const response = await fetch(remoteUrl, {
    headers: {
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    },
    redirect: "follow",
  });

  if (!response.ok) {
    throw new Error(`Remote fetch failed: ${response.status} ${response.statusText}`);
  }

  const contentType = response.headers.get("content-type") || "application/octet-stream";
  const contentLength = parseInt(response.headers.get("content-length") || "0", 10);

  let urlPath = "";
  try {
    urlPath = new URL(remoteUrl).pathname;
  } catch { /* ignore */ }
  const ext = getExtension(urlPath || "file", contentType);
  const uniqueName = generateUniqueFilename(ext);

  // Stream-read with progress
  const reader = response.body!.getReader();
  const chunks: Uint8Array[] = [];
  let loaded = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    chunks.push(value);
    loaded += value.byteLength;

    if (onProgress) {
      const percent = contentLength > 0 ? Math.round((loaded / contentLength) * 100) : 0;
      onProgress({
        loaded,
        total: contentLength,
        percent,
        phase: "downloading",
      });
    }
  }

  // Combine chunks
  const combined = new Uint8Array(loaded);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }

  // Phase 2: Upload to both R2 accounts
  if (onProgress) {
    onProgress({ loaded, total: loaded, percent: 100, phase: "uploading_to_r2" });
  }

  const { results } = await uploadToBothR2(uniqueName, combined, contentType);

  return {
    filename: uniqueName,
    size: loaded,
    links: buildDownloadLinks(uniqueName),
    uploadedTo: results,
  };
}
