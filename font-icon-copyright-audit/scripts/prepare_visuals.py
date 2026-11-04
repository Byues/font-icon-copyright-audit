#!/usr/bin/env python3
"""Prepare real local page/frame previews. No OCR, font recognition, or network access."""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import html
import json
import os
from pathlib import Path
import stat
import sys
import urllib.parse
import warnings

MAX_SOURCE_PIXELS = 80_000_000
MAX_FRAME_PIXELS_PER_FILE = 500_000_000
MAX_INPUT_BYTES = 2 * 1024 * 1024 * 1024
BLOCKED = {".svg", ".svgz", ".eps", ".ps", ".ai", ".ttf", ".otf", ".woff", ".woff2", ".eot"}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp", ".gif", ".ico", ".pcx", ".ppm", ".pgm", ".pbm", ".pnm", ".tga", ".dds", ".icns", ".avif", ".heic", ".heif"}


def timestamp():
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def within(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def is_reparse(path):
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def dependency_report():
    fitz = Image = ImageOps = None
    info = {}
    try:
        try:
            import pymupdf as fitz_module
        except ImportError:
            import fitz as fitz_module
        if not hasattr(fitz_module, "open") or not hasattr(fitz_module, "Matrix"):
            raise ImportError("已安装的 fitz 不是支持所需接口的 PyMuPDF")
        fitz = fitz_module
        info["pymupdf"] = {"available": True, "version": str(getattr(fitz, "VersionBind", "未知"))}
    except (ImportError, OSError, RuntimeError) as exc:
        info["pymupdf"] = {"available": False, "reason": str(exc)}
    try:
        from PIL import Image as image_module, ImageOps as image_ops
        import PIL
        Image, ImageOps = image_module, image_ops
        info["pillow"] = {"available": True, "version": str(PIL.__version__)}
    except (ImportError, OSError, RuntimeError) as exc:
        info["pillow"] = {"available": False, "reason": str(exc)}
    return fitz, Image, ImageOps, info


def collect(source):
    files, issues = [], []
    if source.is_file():
        return [source], issues
    pending = [source]
    while pending:
        folder = pending.pop()
        try:
            with os.scandir(folder) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name.casefold())
        except OSError as exc:
            issues.append({"path": str(folder.relative_to(source)), "status": "目录无法读取", "reason": str(exc)})
            continue
        for entry in entries:
            path = Path(entry.path)
            try:
                if is_reparse(path):
                    issues.append({"path": str(path.relative_to(source)), "status": "链接或重解析点未跟随", "reason": "不跟随 symlink、junction 或其他重解析点"})
                elif entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                elif entry.is_file(follow_symlinks=False):
                    files.append(path)
                else:
                    issues.append({"path": str(path.relative_to(source)), "status": "非普通文件未读取"})
            except OSError as exc:
                issues.append({"path": str(path.relative_to(source)), "status": "目录项无法检查", "reason": str(exc)})
    return sorted(files, key=lambda p: str(p).casefold()), issues


def mark_status(item):
    total, done = item.get("units_total"), item.get("units_processed", 0)
    if total is not None:
        item["units_uncovered"] = max(0, total - done)
        if total > 0 and done == total:
            item["status"] = "success"
        elif done:
            item["status"] = "partial"
        elif item.get("status") not in ("pending", "unsupported"):
            item["status"] = "failed"
    else:
        item["units_uncovered"] = None


def add_preview(item, path, unit, source_width, source_height, width, height, source_unit="px", **extra):
    item["previews"].append({"id": item["id"] + "_" + unit[0] + str(unit[1]).zfill(5),
                             unit[0]: unit[1], "source_width": source_width, "source_height": source_height,
                             "source_unit": source_unit, "preview_width": width, "preview_height": height,
                             "scale_x": width / source_width, "scale_y": height / source_height,
                             "path": "预览图/" + path.name, "sha256": digest(path), "status": "success", **extra})
    item["units_processed"] += 1


def pdf_previews(path, item, image_dir, fitz, max_edge, max_pages):
    item["kind"] = "PDF"
    if fitz is None:
        item.update(status="failed", reason="缺少可用的 PyMuPDF；未安装依赖，PDF 页数及页面均未读取")
        return
    with fitz.open(str(path)) as document:
        if not document.is_pdf:
            item.update(status="failed", reason="扩展名为 PDF，但实际容器不是 PDF，未处理其他容器")
            return
        item["units_total"] = len(document)
        item["unit_kind"] = "page"
        if document.needs_pass:
            item.update(status="failed", reason="PDF 已加密且需要密码；未尝试破解或绕过密码")
            item["uncovered"].append({"all_pages": True, "reason": item["reason"]})
            return
        if not len(document):
            item.update(status="failed", reason="PDF 没有页面")
            return
        limit = min(len(document), max_pages) if max_pages else len(document)
        if limit < len(document):
            item["uncovered"].append({"pages_from": limit + 1, "pages_to": len(document), "reason": "由 --max-pages 限制，尚未渲染；不得声称全页覆盖"})
        for index in range(limit):
            try:
                page = document.load_page(index)
                width, height = float(page.rect.width), float(page.rect.height)
                if width <= 0 or height <= 0 or max(width, height) > 1_000_000:
                    raise ValueError("页面尺寸无效或超过安全边界")
                scale = min(2.0, max_edge / max(width, height))
                pixmap = page.get_pixmap(matrix=fitz.Matrix(scale, scale), alpha=False, colorspace=fitz.csRGB)
                if pixmap.width * pixmap.height > (max_edge + 2) ** 2:
                    raise ValueError("渲染尺寸超出限制")
                dest = image_dir / (item["id"] + "_page" + str(index + 1).zfill(5) + ".png")
                pixmap.save(str(dest))
                add_preview(item, dest, ("page", index + 1), width, height, pixmap.width, pixmap.height, "pt", rotation=int(page.rotation))
            except Exception as exc:
                item["uncovered"].append({"page": index + 1, "reason": type(exc).__name__ + ": " + str(exc)})


def image_previews(path, item, image_dir, Image, ImageOps, max_edge):
    item["kind"] = "image"
    if Image is None:
        item.update(status="failed", reason="缺少可用的 Pillow；未安装依赖，图像及帧数均未读取")
        return
    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        with Image.open(path) as image:
            image_format = str(image.format or "unknown")
            if image_format.upper() in {"EPS", "PS", "PDF", "SVG"}:
                item.update(status="unsupported", reason="不调用图像解码器的外部渲染程序或执行矢量/脚本格式")
                return
            total = int(getattr(image, "n_frames", 1))
            item.update(units_total=total, unit_kind="frame", image_format=image_format)
            decoded_pixels = 0
            for index in range(total):
                try:
                    image.seek(index)
                    raw_width, raw_height = image.size
                    if raw_width <= 0 or raw_height <= 0 or raw_width * raw_height > MAX_SOURCE_PIXELS:
                        raise ValueError("原图/帧像素数超过安全上限 " + str(MAX_SOURCE_PIXELS))
                    if decoded_pixels + raw_width * raw_height > MAX_FRAME_PIXELS_PER_FILE:
                        item["uncovered"].append({"frames_from": index + 1, "frames_to": total, "reason": "超过单文件累计解码像素预算 " + str(MAX_FRAME_PIXELS_PER_FILE) + "，余下帧未处理"})
                        break
                    decoded_pixels += raw_width * raw_height
                    duration = image.info.get("duration")
                    # Copying decodes the actual frame; EXIF orientation is explicitly recorded.
                    frame = ImageOps.exif_transpose(image.copy())
                    oriented_width, oriented_height = frame.size
                    frame.thumbnail((max_edge, max_edge), Image.Resampling.LANCZOS)
                    if frame.mode in ("RGBA", "LA") or (frame.mode == "P" and "transparency" in frame.info):
                        frame = frame.convert("RGBA")
                    else:
                        frame = frame.convert("RGB")
                    dest = image_dir / (item["id"] + "_frame" + str(index + 1).zfill(5) + ".png")
                    frame.save(dest, format="PNG")
                    add_preview(item, dest, ("frame", index + 1), oriented_width, oriented_height, frame.width, frame.height,
                                original_width=raw_width, original_height=raw_height,
                                transform="按 EXIF 方向显示；等比例缩放；保留透明通道，联系表以棋盘底显示；没有改写图中文字", duration_ms=duration)
                except (Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
                    item["uncovered"].append({"frames_from": index + 1, "frames_to": total, "reason": "图像炸弹保护：" + str(exc)})
                    break
                except Exception as exc:
                    item["uncovered"].append({"frame": index + 1, "reason": type(exc).__name__ + ": " + str(exc)})


def prepare_file(path, item, image_dir, fitz, Image, ImageOps, args):
    try:
        info = path.stat()
        item.update(bytes=info.st_size, modified_ns=info.st_mtime_ns)
        if info.st_size > MAX_INPUT_BYTES:
            item.update(status="pending", reason="文件大于 2 GiB 安全上限，未读取内容，哈希及页面/帧待补")
            return
        item["sha256"] = digest(path)
        with path.open("rb") as stream:
            head = stream.read(16)
        extension = path.suffix.lower()
        if extension == ".cdr":
            item.update(kind="CDR", status="pending", reason="CDR 需在已获授权的企业远程桌面使用正规 CorelDRAW 只读打开工作副本，导出真实 PDF/位图后再运行本预览流程；本脚本不解析 CDR")
        elif extension in BLOCKED or head.lstrip().startswith((b"<svg", b"<?xml")):
            item.update(kind="blocked", status="unsupported", reason="不加载 SVG、PostScript、AI 脚本/矢量容器或字体文件；未提取字体，也未调用外部渲染程序")
        elif extension == ".pdf" or head.startswith(b"%PDF-"):
            pdf_previews(path, item, image_dir, fitz, args.max_edge, args.max_pages)
        else:
            # Pillow sniffs the real format. Unknown extensions can be valid images.
            if Image is None and extension not in IMAGE_EXTENSIONS:
                item.update(status="unsupported", reason="未识别为支持的 PDF/图像，且 Pillow 不可用；没有按扩展名推定已审阅")
            else:
                image_previews(path, item, image_dir, Image, ImageOps, args.max_edge)
        after_hash = digest(path)
        item["sha256_after"] = after_hash
        item["source_unchanged"] = after_hash == item["sha256"]
        if not item["source_unchanged"]:
            item.update(status="partial" if item["units_processed"] else "failed", reason="源文件内容在处理期间发生变化，生成预览不能作为稳定原件的证据，需重新取证")
            item["units_uncovered"] = item.get("units_total")
            item["evidence_valid"] = False
            item["uncovered"].append({"all_units_require_recheck": True, "reason": item["reason"]})
        else:
            mark_status(item)
    except Exception as exc:
        item.update(status="partial" if item["units_processed"] else "failed", reason=type(exc).__name__ + ": " + str(exc))
        mark_status(item)


def esc(value):
    return html.escape(str(value if value is not None else ""), quote=True)


def contact_sheet(data):
    status_names = {"success": "预览已生成", "partial": "部分覆盖", "failed": "读取/渲染失败", "pending": "待补处理", "unsupported": "不支持或未处理"}
    chunks = ['<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">',
              '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; img-src \'self\' file:; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">',
              '<title>真实页面与图片预览联系表</title><style>body{margin:0;background:#f2f6fa;color:#1a3247;font:15px/1.65 Arial,"Microsoft YaHei",sans-serif}header{background:#164e73;color:white;padding:26px 4vw}h1{margin:0;font-size:27px}main{max-width:1480px;margin:22px auto;padding:0 20px}.notice,.file{background:white;border:1px solid #d4e0ea;border-radius:10px;padding:20px;margin:18px 0}.notice{border-left:5px solid #367fa7}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}figure{margin:0;border:1px solid #d8e2ea;background:#f9fbfd;padding:10px}img{display:block;width:100%;height:330px;object-fit:contain;background-color:#fafafa;background-image:linear-gradient(45deg,#c7c7c7 25%,transparent 25%),linear-gradient(-45deg,#c7c7c7 25%,transparent 25%),linear-gradient(45deg,transparent 75%,#c7c7c7 75%),linear-gradient(-45deg,transparent 75%,#c7c7c7 75%);background-size:20px 20px;background-position:0 0,0 10px,10px -10px,-10px 0}figcaption{font-size:13px;overflow-wrap:anywhere;margin-top:8px}.meta{color:#526a7c;font-size:13px;overflow-wrap:anywhere}h2{font-size:20px;overflow-wrap:anywhere}.status{font-weight:bold;color:#164e73}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.6 inherit}a{color:#145d93}footer{padding:20px;color:#526a7c}@media(max-width:640px){main{padding:0 10px}.file{padding:14px}h1{font-size:22px}img{height:280px}}</style></head><body><header><h1>真实页面与图片预览联系表</h1><div>仅本地预览 · 不做 OCR、字体识别或侵权判断</div></header><main>',
              '<section class="notice"><strong>这些 PNG 来自实际文件的页面或帧，不能凭预览直接确认字体及侵权。</strong><br>源资料只读，预览未标注候选字体；联系表不加载外部脚本或字体。点击图片可打开真实 PNG。<br>来源：' + esc(data["source"]) + '<br>时间：' + esc(data["created_at"]) + '<br>完整记录见同目录 <a href="manifest.json">manifest.json</a>。<pre>' + esc(json.dumps(data["summary"], ensure_ascii=False, indent=2)) + '</pre></section>']
    for item in data["files"]:
        chunks.append('<article class="file" id="' + esc(item["id"]) + '"><h2>' + esc(item["id"]) + ' · ' + esc(item["name"]) + '</h2><p class="status">' + esc(status_names[item["status"]]) + '</p><p class="meta">路径：' + esc(item["relative_path"]) + '<br>源 SHA-256：' + esc(item.get("sha256") or "尚未取得") + '<br>单位总数：' + esc(item.get("units_total") if item.get("units_total") is not None else "未知") + '；已生成：' + str(item["units_processed"]) + '；未覆盖：' + esc(item.get("units_uncovered") if item.get("units_uncovered") is not None else "数量未知") + '</p>')
        if item.get("reason"):
            chunks.append('<p>' + esc(item["reason"]) + '</p>')
        if item["previews"]:
            chunks.append('<div class="grid">')
            for preview in item["previews"]:
                label = "第 " + str(preview["page"]) + " 页" if "page" in preview else "第 " + str(preview["frame"]) + " 帧"
                href = urllib.parse.quote(preview["path"], safe="/")
                caption = label + ' · 原尺寸 ' + str(preview["source_width"]) + ' × ' + str(preview["source_height"]) + ' ' + preview["source_unit"] + ' → PNG ' + str(preview["preview_width"]) + ' × ' + str(preview["preview_height"]) + ' px；比例 ' + format(preview["scale_x"], '.5g') + ' / ' + format(preview["scale_y"], '.5g')
                chunks.append('<figure id="' + esc(preview["id"]) + '"><a href="' + href + '"><img loading="lazy" src="' + href + '" alt="' + esc(item["name"] + ' ' + label) + '"></a><figcaption><strong>' + esc(label) + '</strong><br>' + esc(caption) + '<br>编号：' + esc(preview["id"]) + '<br>PNG SHA-256：' + esc(preview["sha256"]) + '</figcaption></figure>')
            chunks.append('</div>')
        if item["uncovered"]:
            chunks.append('<details open><summary>未覆盖及失败记录</summary><pre>' + esc(json.dumps(item["uncovered"], ensure_ascii=False, indent=2)) + '</pre></details>')
        chunks.append('</article>')
    if data["directory_issues"]:
        chunks.append('<section class="file"><h2>目录与链接覆盖限制</h2><pre>' + esc(json.dumps(data["directory_issues"], ensure_ascii=False, indent=2)) + '</pre></section>')
    chunks.append('<footer>' + '<br>'.join(esc(line) for line in data["limitations"]) + '</footer></main></body></html>')
    return "".join(chunks)


def positive(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("必须是正整数")
    return number


def main():
    parser = argparse.ArgumentParser(description="用已有 PyMuPDF/Pillow 离线生成真实 PDF 全页和图像全帧 PNG 及联系表；不安装依赖、不做 OCR/字体识别或法律结论。")
    parser.add_argument("--source", required=True, help="单个本地文件或递归目录；不跟随链接/junction")
    parser.add_argument("--out", required=True, help="独立的新输出目录；不能与源目录互相包含，拒绝覆盖")
    parser.add_argument("--max-pages", type=positive, help="可选：每份 PDF 只渲染前 N 页，余下页面明确标记未覆盖；默认全部页面")
    parser.add_argument("--max-edge", type=positive, default=2400, help="PNG 最长边像素，默认 2400，允许 256–8192；PDF 最大 2 px/pt，图片不放大")
    args = parser.parse_args()
    try:
        if any(str(value).startswith(("\\\\", "//")) for value in (args.source, args.out)):
            raise ValueError("只接受本地磁盘路径，不访问 UNC 或网络共享")
        raw_source, raw_out = Path(args.source), Path(args.out)
        if is_reparse(raw_source):
            raise ValueError("源路径不能是链接或重解析点")
        source, out = raw_source.resolve(), raw_out.resolve()
        if not source.is_file() and not source.is_dir():
            raise ValueError("源路径必须是存在的普通文件或目录")
        if out.exists() or os.path.lexists(raw_out):
            raise ValueError("输出路径已存在，拒绝覆盖，请指定新的独立目录")
        if within(out, source) or within(source, out):
            raise ValueError("源与输出不能相同或互相包含")
        if not 256 <= args.max_edge <= 8192:
            raise ValueError("--max-edge 允许范围为 256–8192")
        fitz, Image, ImageOps, dependencies = dependency_report()
        files, issues = collect(source)
        out.mkdir(parents=True, exist_ok=False)
        image_dir = out / "预览图"
        image_dir.mkdir()
        records = [{"id": "V%06d" % (index + 1), "name": path.name,
                    "relative_path": path.name if source.is_file() else path.relative_to(source).as_posix(),
                    "source_path": str(path), "extension": path.suffix.lower(), "sha256": "", "status": "pending",
                    "kind": "unknown", "units_total": None, "units_processed": 0, "units_uncovered": None, "previews": [], "uncovered": []}
                   for index, path in enumerate(files)]
        interrupted = False
        try:
            for path, item in zip(files, records):
                prepare_file(path, item, image_dir, fitz, Image, ImageOps, args)
        except KeyboardInterrupt:
            interrupted = True
            for item in records:
                if item["status"] == "pending" and not item.get("reason"):
                    item["reason"] = "运行被中断，尚未处理或未完成"
        counts = collections.Counter(item["status"] for item in records)
        data = {"schema_version": 1, "created_at": timestamp(), "source": str(source), "output": str(out),
                "options": {"max_pages": args.max_pages, "max_edge": args.max_edge, "max_source_pixels": MAX_SOURCE_PIXELS,
                            "max_frame_pixels_per_file": MAX_FRAME_PIXELS_PER_FILE, "max_input_bytes": MAX_INPUT_BYTES},
                "dependencies": dependencies, "files": records, "directory_issues": issues,
                "summary": {"files_registered": len(records), "file_status_counts": dict(counts),
                            "previews_generated": sum(item["units_processed"] for item in records),
                            "known_uncovered_units": sum(item["units_uncovered"] or 0 for item in records),
                            "uncovered_unit_count_unknown_files": sum(item["units_total"] is None for item in records),
                            "files_not_fully_covered": sum(item["status"] != "success" for item in records),
                            "directory_issues": len(issues), "interrupted": interrupted, "audit_completed": False},
                "limitations": ["仅准备真实本地页面/帧预览及来源哈希，不做 OCR、图中文字识别、字体确认、许可证审查或侵权判断。",
                                "CDR 本体不处理，需在已获授权的企业远程 CorelDRAW 只读工作副本中导出真实 PDF/位图后再处理。",
                                "默认尝试全部 PDF 页面和图片帧；--max-pages、文件/像素安全上限、缺依赖、加密、损坏及异常均会产生明确未覆盖记录。",
                                "安全上限：单输入 2 GiB；单图/帧 8000 万像素；单图像文件累计解码 5 亿像素；保留 Pillow 自带图像炸弹保护。",
                                "PDF 按页面边界渲染；不保证图像型 PDF 内部超大压缩资源能够安全解码，渲染错误逐页登记。",
                                "图像按 EXIF 方向显示、等比例缩小、保留透明通道；联系表使用棋盘底便于查看浅色字标。这些预览不改变原件内容。",
                                "PNG 是整页/整帧可视化，没有构造字体区域框或识别结果；需要在后续审阅中定位包装、标签、说明书及彩页范围。",
                                "预览成功或来源哈希一致不等于全量版权审计完成；目录访问失败和未跟随链接亦属于覆盖限制。"]}
        with (out / "manifest.json").open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        with (out / "图片与页面预览联系表.html").open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(contact_sheet(data))
        print(json.dumps({"output": str(out), "manifest": str(out / "manifest.json"), **data["summary"]}, ensure_ascii=False, indent=2))
        return 130 if interrupted else (1 if data["summary"]["files_not_fully_covered"] or issues else 0)
    except (OSError, ValueError, TypeError) as exc:
        print(json.dumps({"error": str(exc), "audit_completed": False}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
