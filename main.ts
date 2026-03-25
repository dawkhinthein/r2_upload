import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { handleUpload, handleRemoteUpload } from "./upload.ts";

const htmlContent = await Deno.readTextFile("./static/index.html");
const cssContent = await Deno.readTextFile("./static/style.css");
const jsContent = await Deno.readTextFile("./static/app.js");

serve(async (req: Request) => {
  const url = new URL(req.url);
  const path = url.pathname;

  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };

  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  // Static files
  if (path === "/" || path === "/index.html") {
    return new Response(htmlContent, {
      headers: { ...corsHeaders, "Content-Type": "text/html; charset=utf-8" },
    });
  }
  if (path === "/style.css") {
    return new Response(cssContent, {
      headers: { ...corsHeaders, "Content-Type": "text/css; charset=utf-8" },
    });
  }
  if (path === "/app.js") {
    return new Response(jsContent, {
      headers: { ...corsHeaders, "Content-Type": "application/javascript; charset=utf-8" },
    });
  }

  // Direct file upload
  if (path === "/api/upload" && req.method === "POST") {
    try {
      const result = await handleUpload(req);
      return new Response(JSON.stringify(result), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    } catch (e) {
      return new Response(JSON.stringify({ error: (e as Error).message }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
  }

  // Remote URL upload with SSE progress
  if (path === "/api/remote-upload-stream" && req.method === "POST") {
    try {
      const { url: remoteUrl } = await req.json();
      if (!remoteUrl) {
        return new Response(JSON.stringify({ error: "URL is required" }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      const stream = new ReadableStream({
        async start(controller) {
          const encoder = new TextEncoder();
          const send = (data: Record<string, unknown>) => {
            controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`));
          };
          try {
            const result = await handleRemoteUpload(remoteUrl, (progress) => {
              send({ type: "progress", ...progress });
            });
            send({ type: "done", ...result });
          } catch (e) {
            send({ type: "error", error: (e as Error).message });
          } finally {
            controller.close();
          }
        },
      });

      return new Response(stream, {
        headers: {
          ...corsHeaders,
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          "Connection": "keep-alive",
        },
      });
    } catch (e) {
      return new Response(JSON.stringify({ error: (e as Error).message }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
  }

  return new Response("Not Found", { status: 404, headers: corsHeaders });
}, { port: 8000 });

console.log("🚀 Server running on http://localhost:8000");
