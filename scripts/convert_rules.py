#!/usr/bin/env python3
"""Convert Clash-style .list files into sing-box rule-set JSON and SRS files.

The converter is intentionally strict: unsupported rule types, malformed rows,
empty values, invalid CIDRs, or empty generated rule sets fail the build instead
of being silently dropped.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import shutil
import subprocess
import sys
from collections import OrderedDict
from pathlib import Path

SUPPORTED_TYPES = {
    "DOMAIN-SUFFIX": "domain_suffix",
    "DOMAIN-KEYWORD": "domain_keyword",
    "DOMAIN": "domain",
    "IP-CIDR": "ip_cidr",
    "IP-CIDR6": "ip_cidr",
    "IP-ASN": "ip_asn",
}

# Keep version 1 for broad compatibility with existing clients. Bump only after
# confirming every consuming sing-box client supports newer rule-set versions.
RULE_SET_VERSION = 1
DOMAIN_RE = re.compile(r"^[A-Za-z0-9_*.-]+$")
DNS_SAFE_KEYS = {
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
}
DNS_DERIVED_RULE_SETS = {
    "my_direct": "my_direct_dns",
}


def fail(message: str) -> None:
    raise ValueError(message)


def validate_domain(value: str, source: Path, line_no: int) -> None:
    if "://" in value or "/" in value or any(ch.isspace() for ch in value):
        fail(f"{source}:{line_no}: invalid domain value: {value!r}")
    if not DOMAIN_RE.match(value):
        fail(f"{source}:{line_no}: invalid domain characters: {value!r}")


def parse_line(source: Path, line_no: int, raw_line: str) -> tuple[str, str] | None:
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return None

    parts = [part.strip() for part in line.split(",")]
    if len(parts) < 2:
        fail(f"{source}:{line_no}: malformed rule, expected TYPE,VALUE: {raw_line!r}")
    if len(parts) > 3:
        fail(f"{source}:{line_no}: too many fields: {raw_line!r}")

    rule_type = parts[0].upper()
    value = parts[1]
    option = parts[2].lower() if len(parts) == 3 else ""

    if rule_type not in SUPPORTED_TYPES:
        fail(
            f"{source}:{line_no}: unsupported rule type {rule_type!r}; "
            "move this rule to the sing-box config layer or add an explicit converter mapping"
        )
    if not value:
        fail(f"{source}:{line_no}: empty rule value: {raw_line!r}")
    if option and option != "no-resolve":
        fail(f"{source}:{line_no}: unsupported third field {option!r}: {raw_line!r}")

    key = SUPPORTED_TYPES[rule_type]
    if rule_type in {"IP-CIDR", "IP-CIDR6"}:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            fail(f"{source}:{line_no}: invalid CIDR {value!r}: {exc}")
        if rule_type == "IP-CIDR6" and network.version != 6:
            fail(f"{source}:{line_no}: IP-CIDR6 expects IPv6 CIDR, got {value!r}")
        if rule_type == "IP-CIDR" and network.version != 4:
            fail(f"{source}:{line_no}: IP-CIDR expects IPv4 CIDR, got {value!r}")
    elif rule_type == "IP-ASN":
        if not value.isdigit() or int(value) <= 0:
            fail(f"{source}:{line_no}: invalid ASN {value!r}")
    elif rule_type in {"DOMAIN", "DOMAIN-SUFFIX"}:
        validate_domain(value, source, line_no)

    return key, value


def convert_list_file(source: Path) -> dict[str, list[str]]:
    grouped: dict[str, OrderedDict[str, None]] = {}
    duplicate_count = 0

    with source.open("r", encoding="utf-8-sig") as handle:
        for line_no, raw_line in enumerate(handle, 1):
            parsed = parse_line(source, line_no, raw_line)
            if parsed is None:
                continue
            key, value = parsed
            grouped.setdefault(key, OrderedDict())
            if value in grouped[key]:
                duplicate_count += 1
                print(f"⚠️  Duplicate skipped: {source}:{line_no}: {key}={value}")
                continue
            grouped[key][value] = None

    if not grouped:
        fail(f"{source}: no valid rules generated")

    if duplicate_count:
        print(f"⚠️  {source}: skipped {duplicate_count} duplicate rule(s)")

    return {key: list(values.keys()) for key, values in grouped.items()}


def compile_srs(sing_box: str, json_path: Path, srs_path: Path) -> None:
    subprocess.run(
        [sing_box, "rule-set", "compile", str(json_path), "-o", str(srs_path)],
        check=True,
        text=True,
    )


def write_rule_set(
    name: str,
    rule: dict[str, list[str]],
    json_dir: Path,
    srs_dir: Path,
    sing_box: str,
    skip_compile: bool,
) -> None:
    json_path = json_dir / f"{name}.json"
    srs_path = srs_dir / f"{name}.srs"

    with json_path.open("w", encoding="utf-8") as handle:
        json.dump({"version": RULE_SET_VERSION, "rules": [rule]}, handle, indent=2)
        handle.write("\n")
    print(f"✅ JSON generated: {json_path}")

    if not skip_compile:
        compile_srs(sing_box, json_path, srs_path)
        print(f"✅ SRS compiled: {srs_path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert src/*.list to sing-box JSON/SRS rule sets")
    parser.add_argument("--src-dir", type=Path, default=Path("src"))
    parser.add_argument("--json-dir", type=Path, default=Path("rule_json"))
    parser.add_argument("--srs-dir", type=Path, default=Path("rule_srs"))
    parser.add_argument("--sing-box", default="sing-box")
    parser.add_argument("--skip-compile", action="store_true", help="Only generate JSON files")
    args = parser.parse_args(argv)

    list_files = sorted(args.src_dir.glob("*.list"))
    if not list_files:
        print(f"❌ No .list files found under {args.src_dir}", file=sys.stderr)
        return 1

    args.json_dir.mkdir(parents=True, exist_ok=True)
    args.srs_dir.mkdir(parents=True, exist_ok=True)

    if not args.skip_compile and shutil.which(args.sing_box) is None:
        print(f"❌ sing-box executable not found: {args.sing_box}", file=sys.stderr)
        return 1

    for list_file in list_files:
        name = list_file.stem
        print(f"Processing {list_file}...")
        final_rule = convert_list_file(list_file)
        write_rule_set(
            name,
            final_rule,
            args.json_dir,
            args.srs_dir,
            args.sing_box,
            args.skip_compile,
        )

        derived_name = DNS_DERIVED_RULE_SETS.get(name)
        if derived_name:
            dns_rule = {
                key: values
                for key, values in final_rule.items()
                if key in DNS_SAFE_KEYS
            }
            if not dns_rule:
                fail(f"{list_file}: no DNS-safe domain rules generated")
            write_rule_set(
                derived_name,
                dns_rule,
                args.json_dir,
                args.srs_dir,
                args.sing_box,
                args.skip_compile,
            )

    print("🎉 All rule sets processed successfully.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as exc:
        print(f"❌ sing-box compilation failed: {exc}", file=sys.stderr)
        raise SystemExit(exc.returncode)
    except ValueError as exc:
        print(f"❌ {exc}", file=sys.stderr)
        raise SystemExit(1)
