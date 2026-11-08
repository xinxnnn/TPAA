"""初始化阶段展示：生成 pp、三方密钥、Paillier，并输出可审计摘要。

    python demos/phc/demo_initialization.py

默认 Paillier 使用 2048 bit 以便演示快速完成；生产初始化使用 3072 bit。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import crypto.sdk  # noqa: E402


def main() -> int:
    pp, user, ap, tp, paillier = crypto.sdk.v1.initialization.initialize_system(
        paillier_bits=2048)
    errors = crypto.sdk.v1.initialization.verify_initialization(pp, user, ap, tp, paillier)
    if errors:
        print("初始化失败：")
        for error in errors:
            print(f"  - {error}")
        return 1

    public = {
        "pp": pp.to_public_json(),
        "user": {"pk": user.public_bundle()["pk"]},
        "ap": ap.public_bundle(),
        "tp": {"pk": tp.public_bundle()["pk"], "cpk": tp.public_bundle()["cpk"]},
        "paillier": paillier.public.to_public_json(),
    }
    print("=" * 72)
    print("TPAA v1 · 初始化阶段")
    print("=" * 72)
    print(f"profile       : {public['pp']['profile']}")
    print(f"DL 参数       : {public['pp']['paramsId']}")
    print(f"p             : {pp.p.bit_length()} bits")
    print(f"q             : {pp.dl_q.bit_length()} bits")
    print(f"g             : {public['pp']['g']}")
    print(f"椭圆曲线      : {public['pp']['E']['name']}")
    print(f"Paillier n     : {len(public['pp']['n']) * 4} bits")
    print(f"User pk       : {public['user']['pk'][:32]}…")
    print(f"AP pk         : {public['ap']['pk'][:32]}…")
    print(f"AP cpk        : {public['ap']['cpk'][:32]}…")
    print(f"TP pk         : {public['tp']['pk'][:32]}…")
    print(f"TP cpk        : {public['tp']['cpk'][:32]}…")
    print(f"Paillier g1    : {public['paillier']['g1'][:32]}…")
    print("自检          : PASS")
    print("私钥输出      : 禁止（只进入对应 HSM/KMS）")
    print("=" * 72)
    print("公开参数 JSON：")
    print(json.dumps(public, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
