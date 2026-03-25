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

// Download link bases
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

// ============ Config ============
const MULTIPART_THRESHOLD = 50 * 1024 * 1024; // 50MB — ဒီထက်ကြီးရင် multipart သုံးမယ်
const PART_SIZE = 10 * 1024 * 1024; // 10MB per part
const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 1000; // retry ကြားခံ delay
const INTER_ACCOUNT_DELAY_MS = 500; // Account-1 ပြီးမှ Account-2 မတင်ခင် delay

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

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ============ AWS Signature V4 ============

async function hmacSHA256(
  key: ArrayBuffer | Uint8Array,
  message: string
): Promise<ArrayBuffer> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return await crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    new TextEncoder().encode(message)
  );
}

async function sha256(data: Uint8Array | string): Promise<string> {
  const encoded =
    typeof data === "string" ? new TextEncoder().encode(data) : data;
  const hash = await crypto.subtle.digest("SHA-256", encoded);
  return encodeHex(new Uint8Array(hash));
}

async function getSignatureKey(
  key: string,
  dateStamp: string,
  region: string,
  service: string
): Promise<ArrayBuffer> {
  const kDate = await hmacSHA256(
    new TextEncoder().encode("AWS4" + key),
    dateStamp
  );
  const kRegion = await hmacSHA256(kDate, region);
  const kService = await hmacSHA256(kRegion, service);
  return await hmacSHA256(kService, "aws4_request");
}

// ============ Signed request helper ============

async function signedR2Request(
  account: R2Account,
  method: string,
  objectKey: string,
  queryParams: string,
  headers: Record<string, string>,
  payloadHash: string
): Promise<{ url: string; headers: Record<string, string> }> {
  const endpoint = `https://${account.accountId}.r2.cloudflarestorage.com`;
  const region = "auto";
  const service = "s3";

  const now = new Date();
  const amzDate = now.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const dateStamp = amzDate.substring(0, 8);

  const canonicalUri = `/${account.bucketName}/${encodeURIComponent(objectKey).replace(/%2F/g, "/")}`;
  const host = `${account.accountId}.r2.cloudflarestorage.com`;

  const allHeaders: Record<string, string> = {
    ...headers,
    host,
    "x-amz-content-sha256": payloadHash,
    "x-amz-date": amzDate,
  };

  const signedHeaderKeys = Object.keys(allHeaders).sort();
  const signedHeadersStr = signedHeaderKeys.join(";");
  const canonicalHeaders = signedHeaderKeys
    .map((k) => `${k}:${allHeaders[k]}\n`)
    .join("");

  const canonicalRequest = [
    method,
    canonicalUri,
    queryParams,
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

  const signingKey = await getSignatureKey(
    account.secretAccessKey,
    dateStamp,
    region,
    service
  );
  const signatureBuffer = await hmacSHA256(signingKey, stringToSign);
  const signature = encodeHex(new Uint8Array(signatureBuffer));

  const authorization = `AWS4-HMAC-SHA256 Credential=${account.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeadersStr}, Signature=${signature}`;

  const fullUrl = `${endpoint}${canonicalUri}${queryParams ? "?" + queryParams : ""}`;

  return {
    url: fullUrl,
    headers: {
      ...allHeaders,
      Authorization: authorization,
    },
  };
}

// ============ Simple PUT upload (with retry) ============

async function uploadToR2Simple(
  account: R2Account,
  objectKey: string,
  body: Uint8Array,
  contentType: string
): Promise<void> {
  const payloadHash = await sha256(body);

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      const { url, headers } = await signedR2Request(
        account,
        "PUT",
        objectKey,
        "",
        {
          "content-length": body.byteLength.toString(),
          "content-type": contentType,
        },
        payloadHash
      );

      const res = await fetch(url, {
        method: "PUT",
        headers,
        body,
      });

      if (!res.ok) {
        const text = await res.text();
        throw new Error(
          `R2 [${account.label}] upload failed: ${res.status} ${text}`
        );
      }
      await res.body?.cancel(); // drain response
      return; // success
    } catch (err) {
      console.error(
        `[${account.label}] Simple upload attempt ${attempt}/${MAX_RETRIES} failed:`,
        (err as Error).message
      );
      if (attempt < MAX_RETRIES) {
        await delay(RETRY_DELAY_MS * attempt); // exponential-ish backoff
      } else {
        throw err;
      }
    }
  }
}

// ============ Multipart Upload (for large files, with retry) ============

async function initiateMultipartUpload(
  account: R2Account,
  objectKey: string,
  contentType: string
): Promise<string> {
  const { url, headers } = await signedR2Request(
    account,
    "POST",
    objectKey,
    "uploads=",
    { "content-type": contentType },
    await sha256("")
  );

  const res = await fetch(url, { method: "POST", headers });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(
      `[${account.label}] Initiate multipart failed: ${res.status} ${text}`
    );
  }

  const xml = await res.text();
  const match = xml.match(/<UploadId>(.+?)<\/UploadId>/);
  if (!match) throw new Error(`[${account.label}] No UploadId in response`);
  return match[1];
}

async function uploadPart(
  account: R2Account,
  objectKey: string,
  uploadId: string,
  partNumber: number,
  partData: Uint8Array
): Promise<string> {
  const payloadHash = await sha256(partData);
  const queryParams = `partNumber=${partNumber}&uploadId=${encodeURIComponent(uploadId)}`;

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      const { url, headers } = await signedR2Request(
        account,
        "PUT",
        objectKey,
        queryParams,
        { "content-length": partData.byteLength.toString() },
        payloadHash
      );

      const res = await fetch(url, { method: "PUT", headers, body: partData });

      if (!res.ok) {
        const text = await res.text();
        throw new Error(
          `[${account.label}] Part ${partNumber} upload failed: ${res.status} ${text}`
        );
      }

      const etag = res.headers.get("etag") || "";
      await res.body?.cancel();
      return etag;
    } catch (err) {
      console.error(
        `[${account.label}] Part ${partNumber} attempt ${attempt}/${MAX_RETRIES} failed:`,
        (err as Error).message
      );
      if (attempt < MAX_RETRIES) {
        await delay(RETRY_DELAY_MS * attempt);
      } else {
        throw err;
      }
    }
  }
  throw new Error("Unreachable");
}

async function completeMultipartUpload(
  account: R2Account,
  objectKey: string,
  uploadId: string,
  parts: { partNumber: number; etag: string }[]
): Promise<void> {
  const xmlParts = parts
    .map(
      (p) =>
        `<Part><PartNumber>${p.partNumber}</PartNumber><ETag>${p.etag}</ETag></Part>`
    )
    .join("");
  const body = `<CompleteMultipartUpload>${xmlParts}</CompleteMultipartUpload>`;
  const bodyBytes = new TextEncoder().encode(body);
  const payloadHash = await sha256(bodyBytes);

  const queryParams = `uploadId=${encodeURIComponent(uploadId)}`;

  const { url, headers } = await signedR2Request(
    account,
    "POST",
    objectKey,
    queryParams,
    {
      "content-length": bodyBytes.byteLength.toString(),
      "content-type": "application/xml",
    },
    payloadHash
  );

  const res = await fetch(url, { method: "POST", headers, body: bodyBytes });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(
      `[${account.label}] Complete multipart failed: ${res.status} ${text}`
    );
  }
  await res.body?.cancel();
}

async function abortMultipartUpload(
  account: R2Account,
  objectKey: string,
  uploadId: string
): Promise<void> {
  try {
    const queryParams = `uploadId=${encodeURIComponent(uploadId)}`;
    const { url, headers } = await signedR2Request(
      account,
      "DELETE",
      objectKey,
      queryParams,
      {},
      await sha256("")
    );
    const res = await fetch(url, { method: "DELETE", headers });
    await res.body?.cancel();
  } catch {
    // best-effort abort
  }
}

async function uploadToR2Multipart(
  account: R2Account,
  objectKey: string,
  body: Uint8Array,
  contentType: string,
  onPartProgress?: (uploaded: number, total: number) => void
): Promise<void> {
  const uploadId = await initiateMultipartUpload(account, objectKey, contentType);

  try {
    const totalParts = Math.ceil(body.byteLength / PART_SIZE);
    const parts: { partNumber: number; etag: string }[] = [];
    let uploadedBytes = 0;

    // Upload parts SEQUENTIALLY to reduce bandwidth pressure
    for (let i = 0; i < totalParts; i++) {
      const start = i * PART_SIZE;
      const end = Math.min(start + PART_SIZE, body.byteLength);
      const partData = body.subarray(start, end);
      const partNumber = i + 1;

      const etag = await uploadPart(
        account,
        objectKey,
        uploadId,
        partNumber,
        partData
      );
      parts.push({ partNumber, etag });

      uploadedBytes += partData.byteLength;
      if (onPartProgress) {
        onPartProgress(uploadedBytes, body.byteLength);
      }
    }

    await completeMultipartUpload(account, objectKey, uploadId, parts);
  } catch (err) {
    await abortMultipartUpload(account, objectKey, uploadId);
    throw err;
  }
}

// ============ Smart upload — auto-select simple vs multipart ============

async function uploadToR2Smart(
  account: R2Account,
  objectKey: string,
  body: Uint8Array,
  contentType: string,
  onPartProgress?: (uploaded: number, total: number) => void
): Promise<void> {
  if (body.byteLength > MULTIPART_THRESHOLD) {
    console.log(
      `[${account.label}] Using multipart upload (${(body.byteLength / 1024 / 1024).toFixed(1)} MB)`
    );
    await uploadToR2Multipart(account, objectKey, body, contentType, onPartProgress);
  } else {
    console.log(
      `[${account.label}] Using simple PUT upload (${(body.byteLength / 1024 / 1024).toFixed(1)} MB)`
    );
    await uploadToR2Simple(account, objectKey, body, contentType);
  }
}

// ============ Upload to BOTH accounts SEQUENTIALLY (key change!) ============

async function uploadToBothR2(
  objectKey: string,
  body: Uint8Array,
  contentType: string,
  onProgress?: (info: { account: string; phase: string; uploaded?: number; total?: number }) => void
): Promise<{ results: string[] }> {
  const successes: string[] = [];
  const errors: string[] = [];

  // SEQUENTIAL upload — Account-1 ပြီးမှ Account-2
  for (const account of R2_ACCOUNTS) {
    try {
      if (onProgress) {
        onProgress({ account: account.label, phase: "uploading" });
      }

      await uploadToR2Smart(account, objectKey, body, contentType, (uploaded, total) => {
        if (onProgress) {
          onProgress({
            account: account.label,
            phase: "uploading_part",
            uploaded,
            total,
          });
        }
      });

      successes.push(account.label);
      console.log(`[${account.label}] Upload succeeded`);

      // Account တစ်ခုပြီးတိုင်း delay ထည့် — rate limit ရှောင်
      if (account !== R2_ACCOUNTS[R2_ACCOUNTS.length - 1]) {
        console.log(
          `Waiting ${INTER_ACCOUNT_DELAY_MS}ms before next account upload...`
        );
        await delay(INTER_ACCOUNT_DELAY_MS);
      }
    } catch (err) {
      const msg = (err as Error).message;
      console.error(`[${account.label}] Upload failed after retries: ${msg}`);
      errors.push(`${account.label}: ${msg}`);
    }
  }

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
  onProgress?: (progress: {
    loaded: number;
    total: number;
    percent: number;
    phase: string;
  }) => void
): Promise<{
  filename: string;
  size: number;
  links: string[];
  uploadedTo: string[];
}> {
  // Phase 1: Download from remote
  if (onProgress)
    onProgress({ loaded: 0, total: 0, percent: 0, phase: "connecting" });

  const response = await fetch(remoteUrl, {
    headers: {
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    },
    redirect: "follow",
  });

  if (!response.ok) {
    throw new Error(
      `Remote fetch failed: ${response.status} ${response.statusText}`
    );
  }

  const remoteContentType =
    response.headers.get("content-type") || "application/octet-stream";
  const contentLength = parseInt(
    response.headers.get("content-length") || "0",
    10
  );

  let urlPath = "";
  try {
    urlPath = new URL(remoteUrl).pathname;
  } catch {
    /* ignore */
  }
  const ext = getExtension(urlPath || "file", remoteContentType);
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
      const percent =
        contentLength > 0 ? Math.round((loaded / contentLength) * 100) : 0;
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

  // Phase 2: Upload to both R2 accounts (sequentially with progress)
  if (onProgress) {
    onProgress({
      loaded,
      total: loaded,
      percent: 100,
      phase: "uploading_to_r2",
    });
  }

  const { results } = await uploadToBothR2(
    uniqueName,
    combined,
    remoteContentType,
    (info) => {
      if (onProgress) {
        onProgress({
          loaded: info.uploaded ?? loaded,
          total: info.total ?? loaded,
          percent: info.uploaded && info.total
            ? Math.round((info.uploaded / info.total) * 100)
            : 100,
          phase: `${info.phase}_${info.account}`,
        });
      }
    }
  );

  return {
    filename: uniqueName,
    size: loaded,
    links: buildDownloadLinks(uniqueName),
    uploadedTo: results,
  };
}
