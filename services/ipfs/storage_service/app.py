"""IPFS 第五方的 HTTP 壳（storage-service）。

★ 这个服务**没有 crypto_client 目录**，也不 import crypto.sdk。
  这不是遗漏，是它的身份：第五方不持有任何密钥，也不该有能力接触密码学。
  如果哪天有人给它加了一个 crypto_client，那说明"平台不拥有内容"这句话已经不成立了。

★ 它也就没有"解密"端点。它收到的永远是密文，取出去的也永远是密文。
  契约里连明文的类型都没有，想传明文得先改契约 —— 那一步会被看见。

★ `GET /v1/objects/{cid}` 每次都会留痕（红线 18：取用必须可举证）。
  这条日志独立于 TP 的日志 —— 两边各自记录，才能在争议时互相印证。
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from .storage_service import StorageService


class PutIn(BaseModel):
    payloadB64: str = Field(min_length=1, description="密文的 base64；本服务不解释内容")
    requester: str = Field(min_length=1)


class PutOut(BaseModel):
    cid: str


class PinOut(BaseModel):
    cid: str
    pinned: bool


class AccessOut(BaseModel):
    cid: str
    requester: str
    action: str
    at: str
    ok: bool


def create_app(*, storage: StorageService | None = None) -> FastAPI:
    store = storage or StorageService()
    app = FastAPI(title="storage-service", version="0.2.0")
    app.state.domain = "ipfs"
    app.state.storage = store

    @app.get("/healthz")
    def healthz():
        checks = store.self_check()
        return {"status": "ok", "service": "storage-service", "domain": "ipfs",
                "objects": checks["objects"], "pinned": checks["pinned"],
                "holdsKeys": checks["holds_keys"]}

    @app.post("/v1/objects", response_model=PutOut)
    def put(body: PutIn):
        import base64
        import binascii

        try:
            blob = base64.b64decode(body.payloadB64, validate=True)
        except (binascii.Error, ValueError):
            return JSONResponse(status_code=400,
                                content={"code": 400, "message": "payloadB64 不是合法 base64",
                                         "detail": None})
        cid = store.put(blob, requester=body.requester)
        return PutOut(cid=cid)

    @app.get("/v1/objects/{cid}")
    def get(cid: str, requester: str = "unknown"):
        blob = store.get(cid, requester=requester)
        if blob is None:
            return JSONResponse(status_code=404,
                                content={"code": 404, "message": "对象不存在",
                                         "detail": None})
        return Response(content=blob, media_type="application/octet-stream")

    @app.post("/v1/objects/{cid}/pin", response_model=PinOut)
    def pin(cid: str, requester: str = "unknown"):
        return PinOut(cid=cid, pinned=store.pin(cid, requester=requester))

    @app.get("/v1/access/{cid}", response_model=list[AccessOut])
    def access_log(cid: str):
        return [AccessOut(cid=r.cid, requester=r.requester, action=r.action,
                          at=r.at, ok=r.ok) for r in store.log_of(cid)]

    @app.get("/v1/self-check")
    def self_check():
        """把"我不持密钥"变成一个可被外部核对的断言，而不是一句声明。"""
        checks = store.self_check()
        checks["note"] = ("本服务只在内存/对象存储里保存密文字节；"
                          "没有任何密钥字段，也不解析内容")
        return checks

    @app.exception_handler(Exception)
    async def _boom(_: Request, exc: Exception):    # pragma: no cover
        return JSONResponse(status_code=500,
                            content={"code": 500, "message": "内部错误", "detail": None})

    return app


app = create_app()

__all__ = ["create_app", "app"]
