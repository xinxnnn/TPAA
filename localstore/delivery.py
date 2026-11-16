"""Receive and verify a simple issued agent in the local user executor.

Files from AP are data, not trusted Python modules. Verification happens before
publishing a directory; the local preview runner never imports bundle code.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path, PurePosixPath

import crypto.sdk
from packages.tpaa_runtime.manifest import manifest_digest_of

v1 = crypto.sdk.v1
FORMAT = "tpaa-local-agent-v1"
_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")


def _json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _digest(files: dict[str, bytes]) -> str:
    h = hashlib.sha256()
    for name in sorted(files):
        h.update(name.encode("utf-8") + b"\0" + files[name] + b"\0")
    return h.hexdigest()


def _allowed_path(name: str) -> bool:
    if "\\" in name or name.startswith("/"):
        return False
    parts = PurePosixPath(name).parts
    return (name in {"agent.yaml", "integrity.json", "run.py"} or
            (len(parts) == 4 and parts[0] == "bundle" and
             parts[3] == "__init__.py" and
             all(_SEGMENT.fullmatch(seg) for seg in parts[1:3])))


def _verified_files(publication: dict, phc_doc: dict, *, owner: str,
                    application_id: str, did: str, record_id: str,
                    tp_pk, ap_pk) -> dict[str, bytes]:
    if not isinstance(publication, dict) or not isinstance(phc_doc, dict):
        raise ValueError("颁发制品或 PHC 格式无效")
    proof, manifest = publication.get("proof"), publication.get("manifest")
    modules, files = publication.get("modules"), publication.get("files")
    if (not isinstance(proof, dict) or set(proof) != {"body", "sig"}
            or not isinstance(proof["body"], dict) or not isinstance(proof["sig"], str)
            or not isinstance(manifest, dict) or not isinstance(modules, list)
            or not isinstance(files, dict)):
        raise ValueError("发布证明、manifest 或文件清单缺失")
    body = proof["body"]
    v1.check_sig(ap_pk, proof["sig"], "AG2Publication", v1.json_digest(body),
                 what="AP 发布证明")
    phc = v1.from_jsonld(phc_doc)
    if v1.verify_public(phc, tp_pk=tp_pk, ap_pk=ap_pk):
        raise ValueError("最终 PHC 公开验证失败")
    if phc.version < 3 or not phc.tpm.cdid or not phc.apm.cmi:
        raise ValueError("凭证尚未完成最终身份绑定")
    if (type(application_id) is not str or not application_id
            or type(record_id) is not str or not record_id
            or type(did) is not str or not did.startswith("did:wba:")
            or publication.get("status") != "ACTIVE"
            or publication.get("owner") != owner
            or publication.get("recordId") != record_id
            or publication.get("did") != did
            or body.get("kind") != "tpaa/ag2-publication"
            or body.get("owner") != owner or body.get("recordId") != record_id
            or body.get("did") != did
            or body.get("phcDigest") != v1.phc_digest(phc)
            or publication.get("phcDigest") != body["phcDigest"]
            or body.get("cmi") != phc.apm.cmi
            or publication.get("cmi") != body["cmi"]
            or body.get("modulesDigest") != v1.json_digest(modules)
            or body.get("buildDigest") != publication.get("buildDigest")
            or body.get("manifestDigest") != manifest_digest_of(manifest)
            or manifest.get("audit", {}).get("manifestDigest") != body["manifestDigest"]
            or body.get("publishedAt") != publication.get("publishedAt")):
        raise ValueError("AP 证明、最终 PHC 与本申请绑定不一致")
    if (manifest.get("did") != did
            or manifest.get("phc", {}).get("credentialDigest") != body["phcDigest"]
            or manifest.get("ownerBinding", {}).get("afRef") != phc.apm.af_ref
            or manifest.get("build", {}).get("cmi") != body["cmi"]
            or manifest.get("build", {}).get("buildDigest") != body["buildDigest"]
            or type(phc.apm.modules) is not list or phc.apm.modules != modules
            or manifest.get("build", {}).get("modules") != [
                {"id": m["moduleId"], "version": m["version"], "digest": m["digest"]}
                for m in modules]):
        raise ValueError("manifest、PHC 与能力清单不一致")
    if (not files or len(files) > 50 or "agent.yaml" not in files
            or "integrity.json" not in files or "run.py" not in files
            or any(type(k) is not str or not _allowed_path(k) or type(v) is not str
                   for k, v in files.items())):
        raise ValueError("颁发文件路径或内容无效")
    encoded = {k: v.encode("utf-8") for k, v in files.items()}
    if sum(map(len, encoded.values())) > 1024 * 1024 or _digest(encoded) != body["buildDigest"]:
        raise ValueError("颁发代码摘要不匹配或文件超限")
    integrity = json.loads(files["integrity.json"])
    if integrity.get("did") != did or integrity.get("cmi") != body["cmi"]:
        raise ValueError("构建完整性记录不匹配")
    return encoded


def directory(root: Path, application_id: str) -> Path:
    if type(application_id) is not str or not application_id:
        raise ValueError("申请编号无效")
    return Path(root) / "agent" / hashlib.sha256(application_id.encode()).hexdigest()[:32]


def _read(root: Path, application_id: str, *, tp_pk, ap_pk) -> dict:
    target = directory(root, application_id)
    binding = json.loads((target / "delivery.json").read_text(encoding="utf-8"))
    publication = json.loads((target / "publication.json").read_text(encoding="utf-8"))
    phc = json.loads((target / "phc.json").read_text(encoding="utf-8"))
    if (binding.get("format") != FORMAT or binding.get("applicationId") != application_id
            or not isinstance(binding.get("owner"), str) or not binding["owner"]):
        raise ValueError("本地颁发绑定信息无效")
    files = _verified_files(publication, phc, owner=binding["owner"],
                            application_id=application_id, did=binding["did"],
                            record_id=binding["recordId"], tp_pk=tp_pk, ap_pk=ap_pk)
    base = target / "files"
    present = {p.relative_to(base).as_posix() for p in base.rglob("*") if p.is_file()}
    if present != set(files) or any((base / name).read_bytes() != content
                                   for name, content in files.items()):
        raise ValueError("本地智能体代码已被篡改")
    return {"binding": binding, "publication": publication, "phc": phc}


def deliver(root: Path, publication: dict, phc: dict, *, owner: str,
            application_id: str, did: str, record_id: str,
            tp_pk, ap_pk) -> dict:
    files = _verified_files(publication, phc, owner=owner,
                            application_id=application_id, did=did,
                            record_id=record_id, tp_pk=tp_pk, ap_pk=ap_pk)
    target = directory(root, application_id)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        existing = _read(root, application_id, tp_pk=tp_pk, ap_pk=ap_pk)
        if existing["publication"] != publication or existing["phc"] != phc:
            raise FileExistsError("本申请已颁发不同的智能体，不允许覆盖")
        return receipt(root, application_id, tp_pk=tp_pk, ap_pk=ap_pk)
    stage = Path(tempfile.mkdtemp(dir=target.parent, prefix=".agent-pending-"))
    try:
        for name, content in files.items():
            file = stage / "files" / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(content)
        (stage / "publication.json").write_bytes(_json(publication))
        (stage / "phc.json").write_bytes(_json(phc))
        (stage / "delivery.json").write_bytes(_json({
            "format": FORMAT, "owner": owner, "applicationId": application_id,
            "recordId": record_id, "did": did}))
        for file in stage.rglob("*"):
            if file.is_file():
                with file.open("rb+") as saved:
                    os.fsync(saved.fileno())
        os.rename(stage, target)
    except BaseException:
        if stage.exists():
            shutil.rmtree(stage)
        raise
    return receipt(root, application_id, tp_pk=tp_pk, ap_pk=ap_pk)


def receipt(root: Path, application_id: str, *, tp_pk, ap_pk) -> dict:
    data = _read(root, application_id, tp_pk=tp_pk, ap_pk=ap_pk)
    pub = data["publication"]
    return {"applicationId": application_id, "recordId": pub["recordId"],
            "did": pub["did"], "phcDigest": pub["phcDigest"],
            "manifestDigest": pub["manifest"]["audit"]["manifestDigest"],
            "buildDigest": pub["buildDigest"], "status": "delivered-local-test-adapter",
            "localPath": str(directory(root, application_id))}


def load(root: Path, application_id: str, *, tp_pk, ap_pk) -> dict:
    """Read a locally delivered agent only after revalidating all artifacts."""
    return _read(root, application_id, tp_pk=tp_pk, ap_pk=ap_pk)
