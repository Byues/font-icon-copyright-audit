#!/usr/bin/env python3
"""Local, read-only audit helpers. Inventory and structural checks are not a completed audit."""
from __future__ import annotations

import argparse
import collections
import csv
import datetime as dt
import hashlib
import html
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import urllib.parse
import uuid

RISKS = ("严重风险", "高风险", "中风险", "低风险", "待核查", "不适用")
RANK = {name: i for i, name in enumerate(RISKS)}
ARCHIVES = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"}
IMAGES = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"}
PATH_FIELDS = ("evidence_path", "preview")


def csv_cell(value):
    """Keep untrusted filenames/paths from becoming formulas when a CSV is opened."""
    if isinstance(value, str) and value.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def now():
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def read_json(path):
    with Path(path).open("r", encoding="utf-8-sig") as stream:
        return json.load(stream)


def new_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def is_within(path, root):
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except ValueError:
        return False


def is_reparse(path):
    info = Path(path).lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def local_path(value, base):
    """Resolve only filesystem paths, without fetching URLs or opening links."""
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    if value.startswith(("\\\\", "//")):
        return None
    if re.match(r"^[A-Za-z]:[\\/]", value):
        return Path(value).resolve()
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme:
        if parsed.scheme != "file" or parsed.netloc not in ("", "localhost"):
            return None
        value = urllib.parse.unquote(parsed.path)
        if os.name == "nt" and re.match(r"^/[A-Za-z]:/", value):
            value = value[1:]
    if value.startswith(("\\\\", "//")):
        return None
    path = Path(value)
    return (path if path.is_absolute() else Path(base) / path).resolve()


def exists_file(value, base):
    path = local_path(value, base)
    return bool(path and path.is_file())


def protected_output(out, inputs, data=None):
    if str(out).startswith(("\\\\", "//")):
        raise ValueError("离线工具不访问 UNC 或网络共享路径")
    out = Path(out).resolve()
    if any(out == Path(item).resolve() for item in inputs):
        raise ValueError("输出不能覆盖输入文件")
    if out.exists():
        raise ValueError("输出已存在，请选新文件名：" + str(out))
    project = (data or {}).get("project", {})
    for key in ("source", "source_root", "source_path"):
        source = project.get(key)
        if source and str(source).startswith(("\\\\", "//")):
            raise ValueError("离线工具不访问 UNC 或网络共享路径")
        if source and is_within(out, source):
            raise ValueError("输出不能写入源资料目录")
    return out


def schema(data):
    if not isinstance(data, dict) or not isinstance(data.get("project"), dict):
        raise ValueError("数据需要 project 对象")
    for name in ("files", "uses"):
        if not isinstance(data.get(name), list):
            raise ValueError("数据需要 " + name + " 数组")
        if any(not isinstance(item, dict) for item in data[name]):
            raise ValueError(name + " 中每条记录必须是对象")


def header_hint(head):
    if head.startswith(b"%PDF-"):
        return "PDF 文件头"
    if head.startswith(b"PK\x03\x04"):
        return "ZIP 容器；内部尚未解析"
    if head.startswith(b"RIFF"):
        return "RIFF 容器；内部尚未解析"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "OLE 复合容器；内部尚未解析"
    if head.startswith(b"Rar!\x1a\x07"):
        return "RAR 文件头；成员尚未读取"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7Z 文件头；成员尚未读取"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG 文件头；图中文字尚未审阅"
    if head.startswith(b"\xff\xd8\xff"):
        return "JPEG 文件头；图中文字尚未审阅"
    return "未解析；文件头仅作线索"


def inventory(args):
    source, out = Path(args.source).resolve(), Path(args.out).resolve()
    if not source.is_dir():
        raise ValueError("源目录不存在")
    if is_reparse(Path(args.source)):
        raise ValueError("源目录不能是链接或重解析点")
    if is_within(out, source) or is_within(source, out):
        raise ValueError("源目录和输出目录必须独立，不能相同或互相包含")
    manifest, csv_path = out / "扫描日志" / "资产清单.json", out / "扫描日志" / "资产清单.csv"
    old = None
    if manifest.exists():
        if not args.append:
            raise ValueError("资产清单已存在；追加扫描请使用 --append")
        old = read_json(manifest)
        if Path(old.get("project", {}).get("source", "")).resolve() != source:
            raise ValueError("--append 必须使用相同源目录")
    elif csv_path.exists():
        raise ValueError("存在孤立的 CSV，拒绝覆盖，请使用新输出目录")
    old_by_path = {f["relative_path"]: f for f in (old or {}).get("files", [])}
    registry = dict((old or {}).get("path_id_registry", {}))
    registry.update({path: item["id"] for path, item in old_by_path.items()})
    last_id = max([int(re.sub(r"\D", "", value) or 0) for value in registry.values()]
                  + [int((old or {}).get("next_sequence", 1)) - 1, 0])
    files, issues = [], []
    pending = [source]
    while pending:
        folder = pending.pop()
        try:
            with os.scandir(folder) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name.casefold())
        except OSError as exc:
            issues.append({"path": str(folder.relative_to(source)), "kind": "目录读取失败", "reason": str(exc)})
            continue
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(source).as_posix()
            try:
                if is_reparse(path):
                    issues.append({"path": relative, "kind": "链接或重解析点未跟随", "reason": "只读扫描不跟随链接、junction 或其他重解析点"})
                    continue
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    issues.append({"path": relative, "kind": "非普通文件未读取"})
                    continue
            except OSError as exc:
                issues.append({"path": relative, "kind": "目录项检查失败", "reason": str(exc)})
                continue
            previous = old_by_path.get(relative)
            if relative in registry:
                file_id = registry[relative]
            else:
                last_id += 1
                file_id = "F%06d" % last_id
                registry[relative] = file_id
            item = {"id": file_id, "name": path.name, "relative_path": relative,
                    "extension": path.suffix.lower(), "sha256": "", "status": "仅完成文件登记；字体与图标尚未检测"}
            try:
                before = path.stat()
                digest = hashlib.sha256()
                with path.open("rb") as stream:
                    head = stream.read(32)
                    digest.update(head)
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
                after = path.stat()
                item.update(size=before.st_size, modified_ns=before.st_mtime_ns,
                            sha256=digest.hexdigest(), header_hint=header_hint(head))
                if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                    item.update(status="读取期间文件发生变化；哈希待重新核验", sha256="")
                elif path.suffix.lower() in ARCHIVES or "RAR 文件头" in item["header_hint"] or "7Z 文件头" in item["header_hint"]:
                    item["status"] = "压缩包仅登记；成员未展开，待检查"
            except OSError as exc:
                item.update(status="文件读取失败", error=str(exc))
            files.append(item)
    files.sort(key=lambda f: f["relative_path"].casefold())
    first_hash = {}
    for item in files:
        digest = item.get("sha256")
        if digest:
            if digest in first_hash:
                item["duplicate_of"] = first_hash[digest]
            else:
                first_hash[digest] = item["id"]
    current = {f["relative_path"]: f for f in files}
    changes = {"added": [f["id"] for p, f in current.items() if p not in old_by_path],
               "removed": [{"id": f["id"], "relative_path": p} for p, f in old_by_path.items() if p not in current],
               "changed": [f["id"] for p, f in current.items() if p in old_by_path and
                           (f.get("sha256"), f.get("size"), f.get("status")) !=
                           (old_by_path[p].get("sha256"), old_by_path[p].get("size"), old_by_path[p].get("status"))]}
    data = {"project": {"company": "待填写", "scope": "仅文件资产登记，未完成字体、图标或授权审计", "date": now(), "source": str(source)},
            "files": files, "uses": [], "directory_issues": issues, "changes": changes,
            "next_sequence": last_id + 1, "path_id_registry": registry,
            "inventory_summary": {"files_registered": len(files), "hashes_read": sum(bool(f.get("sha256")) for f in files),
                                  "file_read_failures": sum(f["status"] == "文件读取失败" for f in files),
                                  "duplicates": sum("duplicate_of" in f for f in files), "directory_issues": len(issues),
                                  "font_icon_detection_completed": 0, "audit_completed": False}}
    manifest.parent.mkdir(parents=True, exist_ok=True)
    if old:
        archive = manifest.parent / ("历史资产清单_" + dt.datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:8])
        archive.mkdir()
        shutil.copy2(manifest, archive / manifest.name)
        if csv_path.exists():
            shutil.copy2(csv_path, archive / csv_path.name)
    temp_json, temp_csv = manifest.with_name("资产清单_" + uuid.uuid4().hex + ".json"), csv_path.with_name("资产清单_" + uuid.uuid4().hex + ".csv")
    new_json(temp_json, data)
    columns = ["id", "name", "relative_path", "extension", "size", "sha256", "status", "header_hint", "duplicate_of", "error"]
    with temp_csv.open("x", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows({key: csv_cell(value) for key, value in item.items()} for item in files)
    # These are generated manifests only; source files are never written.
    os.replace(temp_json, manifest)
    os.replace(temp_csv, csv_path)
    print(json.dumps({"manifest": str(manifest), **data["inventory_summary"], "notice": "资产登记已执行；尚未完成字体、图标、压缩包成员及授权核查"}, ensure_ascii=False, indent=2))


def normalize_paths(data, base):
    """Keep evidence references valid when the rated JSON is saved elsewhere."""
    for item in data["files"] + data["uses"]:
        for field in PATH_FIELDS:
            value = item.get(field)
            path = local_path(value, base)
            if path:
                item[field] = str(path)
        auth = item.get("authorization")
        if isinstance(auth, dict) and local_path(auth.get("evidence_path"), base):
            auth["evidence_path"] = str(local_path(auth["evidence_path"], base))


def norm_name(value):
    return " ".join(str(value or "").split()).casefold()


def policy_match(use, policy):
    name = norm_name(use.get("font_read"))
    if not name:
        return "", False
    verified = use.get("vendor_verified") is True
    for rule in policy.get("force_high", []):
        for token in rule.get("contains", []):
            # ASCII initials alone never identify a foundry.
            if token and not str(token).isascii() and norm_name(token) in name:
                return str(rule.get("vendor", "指定字库")), False
        for prefix in rule.get("prefixes", []):
            if prefix and name.startswith(norm_name(prefix)) and verified:
                return str(rule.get("vendor", "指定字库")), False
    if name in {norm_name(n) for n in policy.get("western_monotype_names", [])}:
        return "西文蒙纳（用户规则列名）", False
    if name in {norm_name(n) for n in policy.get("western_monotype_candidates", [])}:
        return ("西文蒙纳（归属已核对）", False) if verified else ("", True)
    return "", False


def classify(args):
    source = Path(args.data).resolve()
    data, policy = read_json(source), read_json(args.policy)
    schema(data)
    out = protected_output(args.out, [source, args.policy], data)
    normalize_paths(data, source.parent)
    counts = collections.Counter()
    for use in data["uses"]:
        auth = use.get("authorization") if isinstance(use.get("authorization"), dict) else {}
        evidence = exists_file(use.get("evidence_path"), source.parent)
        auth_evidence = exists_file(auth.get("evidence_path"), source.parent)
        is_font = use.get("asset_kind") == "font"
        identity = use.get("font_identity") if is_font else use.get("icon_identity")
        substitute = is_font and (use.get("font_read_role") == "substitute" or use.get("substitution_status") == "confirmed")
        technical = identity == "confirmed" and evidence and not substitute
        covered = auth_evidence and all(auth.get(key) is True for key in ("coverage_verified", "checks_complete", "scope_match"))
        gap = technical and auth_evidence and all(auth.get(key) is True for key in ("rights_verified", "explicit_gap", "review_complete", "checks_complete")) and bool(str(auth.get("gap_reason") or "").strip())
        vendor, candidate = policy_match(use, policy) if is_font else ("", False)
        state = "已核实授权覆盖" if covered and technical else ("授权待核实" if technical else "证据不足")
        if use.get("in_scope") is False or use.get("actual_use") is False:
            risk, state, reason = "不适用", "不适用", "已明确排除审查范围或并非实际使用；不参与字体内部风险分级"
        elif use.get("in_scope") is not True or use.get("actual_use") is not True:
            risk, state, reason = "待核查", "证据不足", "实际使用或成品范围尚未确认"
        elif substitute:
            risk, state, reason = "待核查", "证据不足", "读取名称已确认只是替代字体，不能据此确定原始成品字体或触发原字体高风险规则"
        elif gap:
            risk, state, reason = "严重风险", "已确认存在授权缺口", "技术使用与权利证据、完整授权核查均有记录，且存在具体缺口：" + str(auth["gap_reason"]) + "；最终法律定性须法务确认"
        elif vendor:
            risk, reason = "高风险", "按企业指定规则提高内部核查优先级：" + vendor + "；高风险不等于侵权事实"
            if not technical:
                reason += "；原始字体身份或技术证据仍待确认"
        elif candidate:
            risk, reason = "待核查", "该西文字体仅在候选清单，厂商归属尚未核验，不能自动标为蒙纳字体"
            if not covered:
                state = "证据不足"
        elif covered and technical:
            risk, reason = "低风险", "技术证据与已核实的适用授权覆盖相符；本次记录未发现具体缺口"
        elif technical:
            risk, reason = "中风险", "实际使用具有技术证据，但尚未核实覆盖本主体及用途的授权；缺证不等于未购买或已侵权"
        else:
            risk, reason = "待核查", "原始字体或图标身份缺乏足够技术证据；名称、图片近似和安装清单不能替代确认"
        use.update(risk=risk, check_status=state, risk_reason=reason,
                   policy_id=str(policy.get("id", "未命名规则")) if vendor and risk == "高风险" else "",
                   policy_vendor=vendor if risk == "高风险" else "", technical_confirmed=bool(technical))
        counts[risk] += 1
    data["classification"] = {"date": now(), "policy_id": policy.get("id", ""), "risk_counts": dict(counts),
                              "notice": "内部核查优先级；未代替人工识别、授权核对及法律定性；本工具不会给出疑似未授权结论"}
    new_json(out, data)
    print(json.dumps({"output": str(out), "uses": len(data["uses"]), "risk_counts": dict(counts)}, ensure_ascii=False, indent=2))


def esc(value):
    return html.escape(str(value if value is not None else ""), quote=True)


def local_href(value, base, out):
    path = local_path(value, base)
    if not path or not path.is_file():
        return ""
    try:
        return urllib.parse.quote(os.path.relpath(path, Path(out).parent).replace("\\", "/"), safe="/:")
    except ValueError:  # Different Windows drives.
        return path.as_uri()


def evidence_link(value, label, base, out):
    href = local_href(value, base, out)
    return ('<a href="' + esc(href) + '">' + esc(label) + "</a>") if href else ("未提供可访问的" + esc(label))


STYLE = """
:root{--blue:#164e73;--line:#dce6ee;--muted:#586c7e}*{box-sizing:border-box}body{margin:0;background:#f3f7fb;color:#193247;font:15px/1.65 'Microsoft YaHei',Arial,sans-serif}header{background:var(--blue);color:white;padding:28px max(4vw,20px)}h1{margin:0 0 8px;font-size:28px}h2{font-size:22px}h3{margin:0 0 6px;font-size:20px;word-break:break-all}main{max-width:1440px;margin:24px auto;padding:0 20px}a{color:#135b91}header p{margin:0;opacity:.9}.notice,.toolbar,.card{background:white;border:1px solid var(--line);border-radius:12px;padding:20px;margin:16px 0}.notice{border-left:5px solid #3984b0}.toolbar{position:sticky;top:0;z-index:2;box-shadow:0 3px 12px #14364c10}.search{display:flex;gap:10px}.search input{min-width:0;flex:1;border:1px solid #a8bccd;border-radius:7px;padding:12px;font:inherit}button{cursor:pointer;border:1px solid #adc2d3;background:#fff;color:#164e73;padding:10px 17px;border-radius:7px;font:inherit}button.primary,button[aria-pressed=true]{background:#164e73;color:#fff;border-color:#164e73}button:focus-visible,input:focus-visible,a:focus-visible{outline:3px solid #ffa93b;outline-offset:2px}.filters{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px}.muted,small{color:var(--muted)}.badge{display:inline-block;border-radius:5px;padding:3px 10px;background:#eaf1f7;font-weight:bold;margin-right:7px}.badge.high,.badge.severe{background:#ffe8e9;color:#a91f31}.badge.medium{background:#fff1d6;color:#8c5600}.badge.low{background:#e4f4ec;color:#176844}.badge.pending{background:#edf0f4;color:#515f70}.meta{font-size:13px;color:var(--muted);word-break:break-all;margin:6px 0}.preview{max-width:100%;max-height:540px;object-fit:contain;border:1px solid var(--line);background:#f5f7fa}table{border-collapse:collapse;width:100%;font-size:13px;table-layout:fixed}th,td{padding:10px;border:1px solid var(--line);text-align:left;vertical-align:top;overflow-wrap:anywhere;white-space:pre-wrap}th{background:#e8f1f8}td .badge{font-size:12px}.table-wrap{overflow-x:auto}details{margin-top:14px}summary{cursor:pointer;font-weight:bold}tr:target{background:#fff5cf}.empty{background:#fff;padding:30px;text-align:center;border:1px solid var(--line);border-radius:10px}.group{margin-top:32px}.group>h2{border-bottom:2px solid #c6d9e8;padding-bottom:10px}footer{margin:30px 0;color:var(--muted);font-size:13px}[hidden]{display:none!important}@media(max-width:760px){h1{font-size:23px}.toolbar{position:static}.search{flex-wrap:wrap}.search input{flex-basis:100%}.card{padding:14px}.table-wrap table{min-width:950px}main{padding:0 12px}}
"""
SCRIPT = """
(()=>{const q=document.getElementById('q'),cards=[...document.querySelectorAll('[data-search-item]')],buttons=[...document.querySelectorAll('[data-filter]')];let selected='all';
const riskNames=['严重风险','高风险','中低风险','中风险','低风险','待核查','不适用'];
function words(){return q.value.trim().toLowerCase().replace(/中(?:风险)?[、/]+低风险/g,'中低风险').split(/\\s+/).filter(Boolean);}
function riskWord(t){const k=t.replace(/(?:类型)?文件$/,'').replace(/类型$/,'');return riskNames.includes(k)?k:null;}
function matches(value,wanted){return wanted==='all'||(wanted==='中低风险'?['中风险','低风险'].includes(value):value===wanted);}
function apply(){let searchRisk=null;const tokens=words().filter(t=>{let r=riskWord(t);if(r){searchRisk=r;return false}return true});let shown=0;for(const c of cards){const risk=c.dataset.risk,matchRisk=matches(risk,selected)&&(!searchRisk||matches(risk,searchRisk));const corpus=c.dataset.search.toLowerCase();c.hidden=!(matchRisk&&tokens.every(t=>corpus.includes(t)));if(!c.hidden)shown++;}for(const g of document.querySelectorAll('[data-group]'))g.hidden=![...g.querySelectorAll('[data-search-item]')].some(c=>!c.hidden);document.getElementById('result-count').textContent=`显示 ${shown} / ${cards.length} 个文件`;document.getElementById('empty').hidden=shown!==0;for(const b of buttons)b.setAttribute('aria-pressed',String(b.dataset.filter===selected));}
document.getElementById('search-form').addEventListener('submit',e=>{e.preventDefault();apply()});q.addEventListener('input',apply);q.addEventListener('keydown',e=>{if(e.key==='Escape'){q.value='';selected='all';apply()}});document.getElementById('clear').addEventListener('click',()=>{q.value='';selected='all';apply();q.focus()});for(const b of buttons)b.addEventListener('click',()=>{selected=b.dataset.filter;q.value=words().filter(t=>!riskWord(t)).join(' ');apply()});apply();})();
"""


def file_risk(uses, scope_status=None):
    active = [u.get("risk", "待核查") for u in uses if u.get("risk") != "不适用"]
    return min(active, key=lambda risk: RANK[risk]) if active else ("不适用" if uses or scope_status == "not_applicable" else "待核查")


def badge(risk):
    category = dict(zip(RISKS, ("severe", "high", "medium", "low", "pending", "na")))[risk]
    return '<span class="badge ' + category + '">' + esc(risk) + "</span>"


def site(args):
    source = Path(args.data).resolve()
    data = read_json(source)
    schema(data)
    out = protected_output(args.out, [source], data)
    if out.suffix.lower() not in (".html", ".htm"):
        raise ValueError("网站输出需要 .html 后缀")
    ids = [f.get("id") for f in data["files"]]
    if not all(isinstance(value, str) and value for value in ids) or len(set(ids)) != len(ids):
        raise ValueError("文件 ID 缺失或重复")
    uses_by_file = collections.defaultdict(list)
    use_ids = set()
    for use in data["uses"]:
        if use.get("file_id") not in ids:
            raise ValueError("使用记录引用了不存在的文件：" + str(use.get("id")))
        if not isinstance(use.get("id"), str) or not use["id"] or use["id"] in use_ids:
            raise ValueError("使用 ID 缺失或重复")
        use_ids.add(use["id"])
        if use.get("risk") not in RISKS or not use.get("check_status"):
            raise ValueError("存在未评级使用记录；请先执行 classify：" + use["id"])
        uses_by_file[use["file_id"]].append(use)
    grouping = [(risk, [f for f in data["files"] if file_risk(uses_by_file[f["id"]], f.get("scope_status")) == risk]) for risk in RISKS]
    company = data["project"].get("company", "企业")
    chunks = ['<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">',
              '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; img-src \'self\' file:; style-src \'unsafe-inline\'; script-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">',
              '<title>' + esc(company) + ' · 字体与图标核查索引</title><style>' + STYLE + '</style></head><body><header id="top"><h1>' + esc(company) + ' · 字体与图标核查索引</h1><p>本地证据 · 使用位置 · 授权核对 · 内部风险优先级</p></header><main>',
              '<div class="notice"><strong>风险等级不等于侵权事实。</strong> 本页仅汇总输入的真实记录；高风险可来自企业指定核查规则。保留原始字体身份和授权核查状态。文件按最高已分级风险归组；没有使用记录的文件列为待核查。<br><span class="muted">范围：' + esc(data["project"].get("scope", "待确认")) + ' · 数据日期：' + esc(data["project"].get("date", "待确认")) + '</span></div>',
              '<section class="toolbar" aria-label="搜索和风险筛选"><form class="search" id="search-form"><input id="q" type="search" aria-label="搜索文件、字体、文字或风险类型" placeholder="搜索文件名、编号、字体、正文，或输入：高风险 / 中低风险"><button class="primary" type="submit">搜索</button><button id="clear" type="button">清除</button></form><div class="filters">']
    for risk in ("all", "严重风险", "高风险", "中低风险", "中风险", "低风险", "待核查", "不适用"):
        count = len(data["files"]) if risk == "all" else sum(len(fs) for r, fs in grouping if r in (("中风险", "低风险") if risk == "中低风险" else (risk,)))
        chunks.append('<button type="button" data-filter="' + esc(risk) + '" aria-pressed="false">' + esc("全部" if risk == "all" else risk) + ' ' + str(count) + '</button>')
    chunks.append('</div><p id="result-count" role="status" class="muted"></p><small>支持回车搜索、空格组合关键词、Esc 清空。高风险与中低风险分别筛选；待核查不等于低风险。</small></section><div id="empty" class="empty" hidden>没有匹配文件，请调整风险筛选或清除关键词。</div>')
    for risk, files in grouping:
        if not files:
            continue
        chunks.append('<section class="group" data-group="' + esc(risk) + '"><h2>' + esc(risk) + ' · ' + str(len(files)) + ' 个文件</h2>')
        for file in files:
            uses = uses_by_file[file["id"]]
            terms = [file.get("id"), file.get("name"), file.get("relative_path"), risk]
            if risk in ("中风险", "低风险"):
                terms.append("中低风险")
            for use in uses:
                terms.extend(use.get(k, "") for k in ("id", "font_read", "font_original", "text", "location", "policy_vendor"))
            chunks.append('<article class="card" id="file-' + esc(file["id"]) + '" data-search-item="true" data-file-id="' + esc(file["id"]) + '" data-risk="' + esc(risk) + '" data-search="' + esc(" ".join(str(v or "") for v in terms)) + '"><h3>' + esc(file["id"]) + ' · ' + esc(file.get("name", "未命名")) + '</h3><p>' + badge(risk) + '<strong>' + str(len(uses)) + ' 条使用记录</strong></p><p class="meta">路径：' + esc(file.get("relative_path", "待确认")) + '<br>SHA-256：' + esc(file.get("sha256", "未提取")) + '<br>检测状态：' + esc(file.get("status", "待确认")) + '</p>')
            if file.get("preview"):
                path = local_path(file["preview"], source.parent)
                href = local_href(file["preview"], source.parent, out)
                if path and path.suffix.lower() in IMAGES and href:
                    chunks.append('<a href="' + esc(href) + '"><img class="preview" loading="lazy" src="' + esc(href) + '" alt="' + esc(file.get("name", file["id"])) + '的真实预览"></a>')
                else:
                    chunks.append('<p class="muted">预览未提供、不可访问或不是允许的本地位图；本页未生成替代图片。</p>')
            if file.get("evidence_path"):
                chunks.append('<p>' + evidence_link(file["evidence_path"], "文件级证据", source.parent, out) + '</p>')
            if not uses:
                chunks.append('<p>' + ('已明确标记为不适用；具体范围判断请以文件级证据及人工复核为准。' if risk == '不适用' else '尚无可追溯的成品使用记录，需继续解析或人工复核，不能据此判断无风险。') + '</p>')
            else:
                chunks.append('<details open><summary>字体与图标使用记录</summary><div class="table-wrap"><table><thead><tr><th style="width:14%">编号与位置</th><th style="width:20%">对象与文字</th><th style="width:22%">字体身份及证据</th><th style="width:20%">授权核查</th><th style="width:24%">风险与下一步</th></tr></thead><tbody>')
                for use in uses:
                    auth = use.get("authorization") if isinstance(use.get("authorization"), dict) else {}
                    chunks.append('<tr id="use-' + esc(use["id"]) + '" data-use-id="' + esc(use["id"]) + '"><td><strong>' + esc(use["id"]) + '</strong><br>' + esc(use.get("location", "位置待确认")) + '<br>范围：' + esc({True: "成品内", False: "范围外", None: "待确认"}.get(use.get("in_scope"), "待确认")) + '</td><td>' + esc(use.get("asset_kind", "待确认")) + '<br><strong>' + esc(use.get("font_read", "未识别名称")) + '</strong><br>' + esc(use.get("text", "")) + '</td><td>原始字体：' + esc(use.get("font_original", "待确认")) + '<br>身份：' + esc(use.get("font_identity" if use.get("asset_kind") == "font" else "icon_identity", "unknown")) + '<br>证据等级：' + esc(use.get("evidence_grade", "待确认")) + '<br>' + evidence_link(use.get("evidence_path"), "技术证据", source.parent, out) + '<br>局限：' + esc(use.get("limitation", "尚未补充说明")) + '</td><td><strong>' + esc(use["check_status"]) + '</strong><br>原授权记录：' + esc(auth.get("state", "未提供")) + '<br>' + evidence_link(auth.get("evidence_path"), "授权证据", source.parent, out) + '</td><td>' + badge(use["risk"]) + '<br>' + esc(use.get("risk_reason", "待补评级依据")) + '</td></tr>')
                chunks.append('</tbody></table></div></details>')
            chunks.append('<p><a href="#top">回到搜索</a></p></article>')
        chunks.append('</section>')
    chunks.append('<footer>本页离线运行，不上传文件，不加载外部脚本或商业字体。此工具不执行字体识别、合同判断或法律定性；结构检查通过也不代表全量审计完成。</footer></main><script>' + SCRIPT + '</script></body></html>')
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write("".join(chunks))
    print(json.dumps({"output": str(out), "files": len(data["files"]), "uses": len(data["uses"]), "notice": "本地网页已生成，需另做实际浏览和证据内容复核"}, ensure_ascii=False, indent=2))


class IndexParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ids, self.files, self.uses, self.links, self.risks = [], [], [], [], []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if values.get("id"):
            self.ids.append(values["id"])
        if "data-search-item" in values:
            self.files.append(values.get("data-file-id"))
            self.risks.append(values.get("data-risk"))
        if values.get("data-use-id"):
            self.uses.append(values["data-use-id"])
        for field in ("href", "src"):
            if values.get(field):
                self.links.append(values[field])


def duplicates(values):
    return [key for key, count in collections.Counter(values).items() if count > 1]


def verify(args):
    source, webpage = Path(args.data).resolve(), Path(args.html).resolve()
    data = read_json(source)
    schema(data)
    errors, warnings = [], []
    file_ids, use_ids = [f.get("id") for f in data["files"]], [u.get("id") for u in data["uses"]]
    for name, ids in (("文件", file_ids), ("使用", use_ids)):
        if any(not isinstance(value, str) or not value for value in ids):
            errors.append(name + " ID 缺失或无效")
        if duplicates(ids):
            errors.append(name + " ID 重复：" + str(duplicates(ids)))
    for use in data["uses"]:
        if use.get("file_id") not in file_ids:
            errors.append("无效文件引用：" + str(use.get("id")))
        if use.get("risk") not in RISKS or not use.get("check_status"):
            errors.append("未评级记录：" + str(use.get("id")))
    for item in data["files"] + data["uses"]:
        paths = [(field, item.get(field)) for field in PATH_FIELDS]
        auth = item.get("authorization")
        if isinstance(auth, dict):
            paths.append(("authorization.evidence_path", auth.get("evidence_path")))
        for field, value in paths:
            if value and not exists_file(value, source.parent):
                errors.append(str(item.get("id")) + " 的本地证据不可访问：" + field)
    parser = IndexParser()
    parser.feed(webpage.read_text(encoding="utf-8-sig"))
    if duplicates(parser.ids):
        errors.append("HTML 锚点 ID 重复")
    if collections.Counter(parser.files) != collections.Counter(file_ids):
        errors.append("HTML 文件卡片与数据文件 ID 或条数不一致")
    if collections.Counter(parser.uses) != collections.Counter(use_ids):
        errors.append("HTML 使用记录与数据使用 ID 或条数不一致")
    if any(value not in RISKS for value in parser.risks):
        errors.append("HTML 含未知风险等级")
    for link in parser.links:
        parsed = urllib.parse.urlsplit(link)
        if parsed.scheme not in ("", "file") or parsed.netloc not in ("", "localhost"):
            errors.append("HTML 含非本地链接：" + link)
            continue
        # HTML hrefs are URL-encoded, whereas raw JSON paths are filesystem strings.
        target_value = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", "")) if parsed.scheme else urllib.parse.unquote(parsed.path)
        target = local_path(target_value, webpage.parent) if parsed.path else webpage
        if not target or not target.is_file():
            errors.append("HTML 链接目标不存在：" + link)
        elif parsed.fragment:
            anchor = urllib.parse.unquote(parsed.fragment)
            if target == webpage:
                anchors = parser.ids
            elif target.suffix.lower() in (".html", ".htm"):
                other = IndexParser()
                other.feed(target.read_text(encoding="utf-8-sig"))
                anchors = other.ids
            else:
                warnings.append("非 HTML 目标的片段无法核验：" + link)
                continue
            if anchor not in anchors:
                errors.append("HTML 锚点不存在：" + link)
    report = {"passed": not errors, "files": len(file_ids), "uses": len(use_ids), "html_files": len(parser.files),
              "html_uses": len(parser.uses), "local_links_checked": len(parser.links), "errors": errors, "warnings": warnings,
              "notice": "仅完成数据结构、ID、文件路径及 HTML 锚点验证；未验证字体事实、授权内容、截图正确性或全量审计完成情况"}
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if not errors else 1


def main():
    parser = argparse.ArgumentParser(description="离线版权审计辅助工具：只读资产登记、保守内部风险分级、本地图文索引和结构验证；不代替字体解析或法律判断。")
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("inventory", help="只读递归登记、哈希及重复关系；不解析字体或压缩包成员")
    p.add_argument("--source", required=True)
    p.add_argument("--out", required=True, help="独立输出目录，不能与源目录互相包含")
    p.add_argument("--append", action="store_true", help="同源增量重扫，复用路径 ID 并归档旧清单")
    p.set_defaults(run=inventory)
    p = commands.add_parser("classify", help="按真实技术、授权及用户规则分级，写入新 JSON")
    p.add_argument("--data", required=True)
    p.add_argument("--policy", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(run=classify)
    p = commands.add_parser("site", help="从已评级 JSON 生成单文件离线中文图文索引")
    p.add_argument("--data", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(run=site)
    p = commands.add_parser("verify", help="检查结构、记录 ID、本地链接和锚点；不代表审计完成")
    p.add_argument("--data", required=True)
    p.add_argument("--html", required=True)
    p.set_defaults(run=verify)
    args = parser.parse_args()
    try:
        for key in ("source", "data", "policy", "out", "html"):
            if str(getattr(args, key, "")).startswith(("\\\\", "//")):
                raise ValueError("离线工具不访问 UNC 或网络共享路径")
        result = args.run(args)
        return result if isinstance(result, int) else 0
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc), "audit_completed": False}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
