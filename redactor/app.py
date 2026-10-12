"""FastAPI app + ASGI middleware that redacts PII/secrets from every JSON/text response body.
POST /v1/chat proxies to an upstream LLM (Ollama if REDACTOR_UPSTREAM=ollama, else an echo mock that leaks on purpose)."""
import json, logging, os, time, urllib.request
from fastapi import FastAPI
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from .detectors import redact

log = logging.getLogger("redactor")


class RedactMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        resp = await call_next(request)
        ctype = resp.headers.get("content-type", "")
        if not (ctype.startswith("application/json") or ctype.startswith("text/")):
            return resp
        body = b"".join([c async for c in resp.body_iterator])
        t0 = time.perf_counter()
        text, hits = redact(body.decode("utf-8", "replace"))
        if ctype.startswith("application/json"):  # keep JSON valid: redact string values, not raw bytes
            try:
                obj = json.loads(body); hits = []
                def walk(o):
                    if isinstance(o, str):
                        r, h = redact(o); hits.extend(h); return r
                    if isinstance(o, list): return [walk(x) for x in o]
                    if isinstance(o, dict): return {k: walk(v) for k, v in o.items()}
                    return o
                text = json.dumps(walk(obj), ensure_ascii=False)
            except ValueError:
                pass
        headers = {k: v for k, v in resp.headers.items() if k.lower() != "content-length"}
        headers["x-redactions"] = str(len(hits))
        headers["x-redact-ms"] = f"{(time.perf_counter() - t0) * 1000:.2f}"
        if hits:  # audit log: types and counts only, never the values
            log.warning("redacted %s", sorted({h["type"] for h in hits}))
        return Response(text, status_code=resp.status_code, headers=headers, media_type=ctype.split(";")[0])


app = FastAPI(title="LLM PII/secret redactor")
app.add_middleware(RedactMiddleware)


class Chat(BaseModel):
    prompt: str


def upstream(prompt: str) -> str:
    if os.environ.get("REDACTOR_UPSTREAM") == "ollama":
        body = json.dumps({"model": os.environ.get("OLLAMA_MODEL", "qwen2.5:1.5b"), "prompt": prompt, "stream": False,
                           "options": {"temperature": 0, "num_predict": 200}}).encode()
        req = urllib.request.Request(os.environ.get("OLLAMA_HOST", "http://localhost:11434") + "/api/generate", body,
                                     {"Content-Type": "application/json"})
        return json.loads(urllib.request.urlopen(req, timeout=120).read())["response"]
    return f"Sure! Here is what you asked about: {prompt}"  # echo mock: worst case, model repeats sensitive input


@app.post("/v1/chat")
def chat(c: Chat):
    return {"completion": upstream(c.prompt)}


@app.post("/v1/redact")
def redact_only(c: Chat):
    return {"text": c.prompt}  # middleware does the work; useful as a standalone redaction service


@app.get("/healthz")
def health():
    return {"ok": True}
