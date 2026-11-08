"""Prepare persistent local test-adapter files without exposing secrets."""

from __future__ import annotations

import argparse
import json
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import crypto.sdk

v1 = crypto.sdk.v1


def _write_once(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", type=Path, default=Path(".tpaa-local"))
    args = parser.parse_args()
    root = args.state_root.resolve()
    root.mkdir(parents=True, exist_ok=True)

    seed_path = root / "v1-hsm-seed.json"
    seed_names = ("tp", "ap", "auth", "ap_auth", "review")
    _write_once(seed_path, {
        **{name: v1.new_hsm_seed() for name in seed_names},
        "supervision": secrets.token_hex(32),
    })
    seed = json.loads(seed_path.read_text(encoding="utf-8"))
    if not set(seed_names).issubset(seed):
        raise RuntimeError("incomplete HSM seed file; inspect it or choose a new state root")
    if "supervision" not in seed:
        seed["supervision"] = secrets.token_hex(32)
        seed_path.write_text(json.dumps(seed, indent=2), encoding="utf-8")
    if set(seed) != {*seed_names, "supervision"}:
        raise RuntimeError("unexpected local HSM seed file fields; inspect it or choose a new state root")

    user_auth_path = root / "user-auth-seed.json"
    _write_once(user_auth_path, {"auth": v1.new_hsm_seed()})

    staff_seeds_path = root / "staff-hsms.json"
    if not staff_seeds_path.exists():
        _write_once(staff_seeds_path, {name: v1.new_hsm_seed() for name in
                                       ("reviewer-a", "operator", "supervisor-a",
                                        "supervisor-b")})
    staff_seeds = json.loads(staff_seeds_path.read_text(encoding="utf-8"))
    for name in ("supervisor-a", "supervisor-b"):
        if name not in staff_seeds:
            staff_seeds[name] = v1.new_hsm_seed()
    staff_seeds_path.write_text(json.dumps(staff_seeds, indent=2), encoding="utf-8")
    directory = {}
    for name, role in (("reviewer-a", "reviewer"), ("operator", "tp-operator"),
                       ("supervisor-a", "supervisor"), ("supervisor-b", "supervisor")):
        hsm = v1.hsm_from_seed(domain="STAFF", seed=staff_seeds[name])
        directory[v1.pk_hex(hsm.pubkey())] = {
            "id": name, "role": role, "encPub": format(hsm.enc_pub(), "x")}
    staff_path = root / "tp-staff.json"
    if staff_path.exists():
        saved_directory = json.loads(staff_path.read_text(encoding="utf-8"))
        for public_key, member in directory.items():
            saved = saved_directory.get(public_key)
            if saved is not None and saved != member:
                raise RuntimeError("staff key/directory mismatch; inspect local state")
            saved_directory[public_key] = member
        staff_path.write_text(json.dumps(saved_directory, indent=2), encoding="utf-8")
    else:
        _write_once(staff_path, directory)

    config_path = root / "local-config.json"
    config = {
        "TPAA_LOCAL_STATE_ROOT": str(root / "services"),
        "TPAA_V1_HSM_SEED": str(seed_path),
        "TPAA_USER_AUTH_HSM_SEED": str(user_auth_path),
        "TPAA_TP_STAFF": str(staff_path),
        "TPAA_LOCAL_REVIEWER_HSM_SEED": str(staff_seeds_path),
        "TPAA_STORE_ROOT": str(root / "services" / "ap-store"),
        "TPAA_INDEX_KEY": secrets.token_bytes(32).hex(),
        "TPAA_ECID_KEY": secrets.token_bytes(32).hex(),
        "TPAA_IDENTITY_DB": str(root / "services" / "identity.json"),
    }
    _write_once(config_path, config)
    saved = json.loads(config_path.read_text(encoding="utf-8"))
    if "TPAA_LOCAL_REVIEWER_HSM_SEED" not in saved:
        saved["TPAA_LOCAL_REVIEWER_HSM_SEED"] = str(staff_seeds_path)
        config_path.write_text(json.dumps(saved, indent=2), encoding="utf-8")
    for key, expected in config.items():
        if not saved.get(key):
            raise RuntimeError(f"local configuration is incomplete: {key}")
        if key not in {"TPAA_INDEX_KEY", "TPAA_ECID_KEY"} and saved[key] != expected:
            raise RuntimeError(f"local configuration path mismatch: {key}")
    for key in ("TPAA_INDEX_KEY", "TPAA_ECID_KEY"):
        if len(bytes.fromhex(saved[key])) < 32:
            raise RuntimeError(f"invalid persistent AP key: {key}")
    print(f"Local test-adapter state prepared at {root}")
    print("Seed/config files contain local demo keys; never share them or commit them.")


if __name__ == "__main__":
    main()
