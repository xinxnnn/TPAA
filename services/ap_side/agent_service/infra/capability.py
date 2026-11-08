"""CapabilityPort 的本地演练实现 —— 把「TP 侧的动作」真做出来，但**不在本服务里做**。

这个文件叫 Adapter 而不是 TpService，是有意的：
    它是**边界上的转接件**，把 AP 侧「我要什么」翻译成 TP 侧能做的动作。
    本地演练时转给同一进程里的 `LocalTpAuthority`（模拟 TP 的 HSM），
    生产时换成 gRPC/HTTP 客户端，**用例代码一行不改**。

★ 本文件最重要的性质：它**没有 AP 的任何私钥**。
  它能签发、能验签，但改写不了 AP 那一半 —— 手里只有 `PublicChameleon`。
  这不是靠约定，而是因为它拿到的入参就是 `PublicKeyMaterial`（一串十六进制）。
  于是「TP 不持有 AP 陷门」在这里是个**类型事实**，不是一句注释。

★ 第二个性质：`seal_did` 必须给出**唯一** DID。
  DID 一重复，追溯链就有两个根，级联吊销会吊销错人。
  所以用只增不减的发号器，而不是"取哈希前缀"那种会撞的写法。

★ 关于 PHC 的编解码为何走 `crypto.sdk.phc_json`：
  PHC 的 JSON-LD 形态是**跨域交换的唯一形态**，读写它属于密码层的职责，
  业务侧不该自己拼字段（拼错一个字段就是验签失败，而失败现场很难查）。
  sdk 因此提供 `phc_json_to_obj / phc_obj_to_json / phc_verify` 三个入口，
  业务侧只经它们，不 import crypto.phc。
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import crypto.sdk
from localstore.paths import write_atomic

from ..domain.ports import (
    IssueRequest,
    IssueResult,
    PhcVerifyResult,
    SealDidRequest,
    SealDidResult,
    WriteCmiRequest,
)

# 内容对象的定位串：IPFS 侧按 CID 取，这里只是"内容在哪"的语义化写法
_CONTENT_URI = "tpaa://{did}/bundle"


class CapabilityError(RuntimeError):
    """TP 侧拒绝了这次请求（不是网络错误，是对方说"不"）。"""


class LocalTpAuthority:
    """本地演练用的 TP。私钥只在这里，且只以 HSM 句柄形态存在。

    ★ 这是**演练替身**，不是 TP 的生产实现。生产上 TP 的 HSM 在 TP 的机房，
      本类会被换成 `RemoteCapabilityAdapter`（同签名、同语义）。
      保留它的意义：端到端测试能真跑一遍「TP 签发 → AP 验签」，
      而不是整条链路都活在 mock 里 —— 那样测出来的只是 mock 之间的默契。
    """

    def __init__(self, *, tp_hsm, ap_pk, ap_ch, ecid_key: bytes,
                 did_prefix: str = "did:tpaa",
                 state_dir: str | Path | None = None) -> None:
        if getattr(tp_hsm, "domain", None) != "TP":
            raise CapabilityError("LocalTpAuthority 必须持有 TP 域的 HSM 句柄")
        if getattr(ap_ch, "domain", None) is not None:
            # 传进来的是 HSM 本体而不是公钥句柄 —— 正是要堵住的那种误用
            raise CapabilityError(
                "LocalTpAuthority 只接受 AP 的公钥材料（ap_pk + ap_hsm.public_chameleon()），"
                "不接受 AP 的 HSM 句柄")
        if not isinstance(ecid_key, (bytes, bytearray)) or len(ecid_key) < 32:
            raise CapabilityError("ECID 加封密钥至少 32 字节")
        self._hsm = tp_hsm
        # ★ 只拿 AP 的**公钥**：带陷门的句柄在这里当场 PermissionError（require_public）。
        #   于是"TP 不持有 AP 陷门"在构造这一刻就被检查，而不是靠注释。
        self._ap_pk = ap_pk
        if callable(getattr(ap_ch, "has_trapdoor", None)) and ap_ch.has_trapdoor():
            raise PermissionError(
                "红线 1：LocalTpAuthority 收到了 AP 的**含陷门**句柄。"
                "TP 一侧只能持有 ap_hsm.public_chameleon()")
        self._ap_ch = crypto.sdk.as_public(ap_ch)
        self._ecid_key = bytes(ecid_key)
        self._prefix = did_prefix
        self._ecid_to_did: dict[str, str] = {}
        # ★ 发号状态必须落盘：只在内存里计数，重启后会从 000001 重来，
        #   与库里既有 DID 撞号 —— 追溯链从此有两个根。
        self._seq_lock = threading.Lock()
        self._seq_path = Path(state_dir) / "did-seq.json" if state_dir else None
        self._seq = self._load_seq()

    # ---- 对外的三个动作（由 Adapter 调用）----

    def issue(self, req: IssueRequest) -> dict:
        """签发 PHC。此刻既没有 DID、也没有 ECID —— 这两样都要等 `seal`。

        为什么内容标识符不在这一步封：
          签发时内容还没有进 IPFS，此时封出来的 ECID 解出来是个不存在的地址。
          一个"解出来取不到件"的 ECID 比空值更坏 —— 它看起来完成了，实际是错的。
          所以刻意留空，让"必须封 DID 才算完成"成为数据层面的约束（D6）。
        """
        phc = crypto.sdk.issue_phc(
            tp_hsm=self._hsm,
            ap_ch=crypto.sdk.public_from_hex(req.ap.ap_chameleon_cpk_hex),
            identity_hash=req.identity_hash,
            tau=req.tau,
            crf=req.crf,
            tpm_time=req.requested_at,
            tpm_ecid="",
            apid=bytes.fromhex(req.apid_hex),
            parent_did=req.parent_did,
        )
        return crypto.sdk.phc_obj_to_json(phc)

    def seal(self, req: SealDidRequest) -> SealDidResult:
        """写 DID、封 ECID，再重签一次。DID 唯一性在这里保证。

        ★ 顺序很关键：CDID / Time / ECID 三个字段都进 TPM，而 TPM 决定了 TPCH。
          必须先把它们**一起定稿**，再封印一次。分两次封印会多签一版
          "马上要作废"的 TPCH —— 结果虽然一样，但审计日志里会多出一条
          真实存在过的签发记录，事后追溯时无法判断哪条才是最终态。
          所以：先写字段（这一步 TPCH 已是旧值、暂时不自洽），
          再调一次 update_by_tp 让它重新自洽并签名。
        """
        phc = crypto.sdk.phc_json_to_obj(req.phc_json)
        did = self._allocate(req.did_namespace)
        ecid = crypto.sdk.protect_cid(_CONTENT_URI.format(did=did), self._ecid_key)
        self._ecid_to_did[ecid] = did

        # 先把 TP 那半的三个字段一次写定（此时 TPCH 尚未重算，属中间态）
        phc.tpm_cdid = did
        phc.tpm_time = req.requested_at
        phc.tpm_ecid = ecid
        if req.parent_did:
            phc.parent_did = req.parent_did

        # ★ 核对 APid 是否已由 issue_phc 落定。
        #   APA.APid 属于 AP 那半（APCH 覆盖 APA），必须在签发那一刻就定好；
        #   事后再补等于 APCH 变了、AF 锚定的对象变了，整张凭证作废。
        #   所以这里不接受"空着待补"，而是明确拒绝，让问题在这里暴露，
        #   而不是留到验签时表现成一条莫名其妙的"APCH 不一致"。
        if not phc.apa_apid:
            raise CapabilityError(
                "PHC 缺少 APA.APid —— 签发时必须带上 AP 公钥，事后补会让 APCH/AF 全部失效")

        sealed = crypto.sdk.update_by_tp(
            phc, tp_hsm=self._hsm, did=did, tpm_time=req.requested_at,
            parent_did=req.parent_did or None,
        )
        return SealDidResult(
            did=did, phc_json=crypto.sdk.phc_obj_to_json(sealed),
            lineage_proof={"parentDid": req.parent_did, "namespace": req.did_namespace},
        )

    def verify(self, phc_json: dict, *, identity_hash: int,
               tau: int, crf: int) -> PhcVerifyResult:
        """完整校验。

        ★ 为什么用**自己这一侧**的句柄，而不是从 PHC 里取：
          PHC 没有单独的"AP 变色龙公钥"字段（APCH 只需算得出、不必公开 cpk）。
          本方法在 AP 侧运行，AP 手上就有自己的 `public_chameleon()`。
          用自己那份比"读对方说的那个"更强：验的是"我本来就是谁"。
        """
        out = crypto.sdk.phc_verify(
            phc_json,
            tp_pk=self._hsm.pubkey(),
            ap_pk=self._ap_pk,
            tp_ch=self._hsm.public_chameleon(),
            ap_ch=self._ap_ch,
            identity_hash=identity_hash, tau=tau, crf=crf,
        )
        # sdk 不反向依赖 backend，所以它返回自己的轻量结果对象；在这里转成端口类型，
        # 让"这个服务承诺的返回形态"在适配层显式可见，而不是靠鸭子类型蒙过去。
        return PhcVerifyResult(ok=out.ok, errors=list(out.errors))

    # ------------------------------------------------------------------

    def _allocate(self, namespace: str) -> str:
        """发号：namespace + 单调序号。序号永不复用，所以不存在"撞了再改"。

        ★ 先落盘、再返回：返回之后才落盘的话，崩在中间就会把同一个号发两次。
        """
        with self._seq_lock:
            self._seq += 1
            if self._seq_path is not None:
                write_atomic(self._seq_path, json.dumps({"seq": self._seq}).encode())
            return f"{self._prefix}:{namespace or 'agent'}:{self._seq:06d}"

    def _load_seq(self) -> int:
        if self._seq_path is None or not self._seq_path.exists():
            return 0
        try:
            return int(json.loads(self._seq_path.read_text(encoding="utf-8"))["seq"])
        except (ValueError, KeyError, TypeError) as exc:
            # 发号状态坏了就拒绝启动：猜一个值继续发，等于赌它不撞号
            raise CapabilityError(f"DID 发号状态损坏：{self._seq_path}") from exc


class LocalCapabilityAdapter:
    """CapabilityPort 的本地实现：把端口调用翻译成具体动作。

    生产替换为 `RemoteCapabilityAdapter(base_url=...)`：
        issue/seal/verify  → HTTP 调 TP 的 phc-service / did-service
        write_cmi          → **仍在本进程做**（它要用 AP 的陷门，远端拿不到）

    ★ 所以这个适配器持有两样东西：一个"对方"（TP 的转接件）、一个"自己"（AP 的 HSM）。
      把它们分开存，是为了让 `write_cmi` 的实现里**根本没有 TP 可调用** ——
      "算法1 不需要 TP"就成了一个类型事实，而不是一句注释。
    """

    def __init__(self, authority: LocalTpAuthority, *, ap_hsm) -> None:
        if getattr(ap_hsm, "domain", None) != "AP":
            raise CapabilityError("LocalCapabilityAdapter 必须持有 AP 域的 HSM 句柄")
        self._tp = authority
        self._ap_hsm = ap_hsm

    def issue_phc(self, req: IssueRequest) -> IssueResult:
        if req.identity_hash <= 0:
            raise CapabilityError("身份哈希必须为正整数（由 identity-service 核验后给出）")
        try:
            apid = bytes.fromhex(req.apid_hex)
        except ValueError as e:
            raise CapabilityError(f"APid 不是合法十六进制：{e}") from e
        if len(apid) != 33:
            raise CapabilityError("APid 必须是 33 字节压缩点 —— 不收裸哈希、不收私钥")
        phc_json = self._tp.issue(req)
        return IssueResult(phc_json=phc_json, ecid="", phi_ref="")

    def seal_did(self, req: SealDidRequest) -> SealDidResult:
        return self._tp.seal(req)

    def verify_phc(self, phc_json: dict, *, identity_hash: int,
                   tau: int, crf: int) -> PhcVerifyResult:
        return self._tp.verify(phc_json, identity_hash=identity_hash, tau=tau, crf=crf)

    # ------------------------------------------------------------------
    # 算法1：由 **AP 自己**做，不经 TP
    # ------------------------------------------------------------------
    def write_cmi(self, req: WriteCmiRequest) -> dict:
        """把 CMI 写进 APM —— APCH 取值不变，所以 TP 的签名继续有效。

        ★ 这里不转给 `LocalTpAuthority`，因为 TP 手上没有 AP 的陷门，
          压根做不了这件事。转过去只会得到一句"我没有权限"。
          这行代码本身就是「算法1 不需要 TP」那句话的证明。

        ★ 落地后**立刻自证三项不变**（APCH / TPCH / AF）。不自证的话，
          若哪天引擎改动让 APCH 变了，本函数仍会"成功返回"，
          而问题要等到用户取件时验签失败才暴露 —— 那时已经离现场很远了。
        """
        before = crypto.sdk.phc_json_to_obj(req.phc_json)
        snap = (before.proof_apch, before.proof_tpch, before.tpm_af)
        version_before = before.version

        updated = crypto.sdk.update_by_ap(
            before, ap_hsm=self._ap_hsm, cmi=req.cmi, apm_time=req.apm_time)
        if (updated.proof_apch, updated.proof_tpch, updated.tpm_af) != snap:
            raise CapabilityError(
                "算法1 破坏了 APCH/TPCH/AF 的不变性 —— 拒绝落盘（这会让 TP 签名失效）")
        if updated.version != version_before + 1:
            raise CapabilityError("算法1 未推进版本号 —— 引擎行为异常")

        return crypto.sdk.phc_obj_to_json(updated)


__all__ = ["LocalCapabilityAdapter", "LocalTpAuthority", "CapabilityError"]
