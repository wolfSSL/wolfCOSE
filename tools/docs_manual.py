#!/usr/bin/env python3
"""Build the wolfCOSE manual with wolfSSL/documentation's shared tooling."""

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path

import yaml
from markdown.extensions.toc import slugify


MANUAL = "wolfCOSE"
PDF = "wolfCOSE-Manual.pdf"
HEADING = re.compile(r"^(#{1,6})[ \t]+(.+?)[ \t]*#*[ \t]*$")
LINK = re.compile(r"\]\((?:([^)#]+\.md))?(?:#([^)]+))?\)")


def pages_from_nav(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from pages_from_nav(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from pages_from_nav(item)


def page_key(filename):
    return "wc-" + slugify(Path(filename).stem, "-")


def heading_slug(title):
    title = re.sub(r"[`*]", "", title)
    title = re.sub(r"\[([^]]+)\]\([^)]+\)", r"\1", title)
    return slugify(title, "-")


def stage(documentation_root, source_root):
    manual = documentation_root / MANUAL
    source_docs = source_root / "docs"
    shared = documentation_root / "common" / "common.am"
    if not source_docs.is_dir() or not shared.is_file():
        raise RuntimeError("wolfCOSE docs or documentation/common.am is missing")

    config = yaml.safe_load((source_root / "mkdocs.yml").read_text())
    pages = list(pages_from_nav(config["nav"]))
    if not pages or pages[0] != "index.md" or len(set(pages)) != len(pages):
        raise RuntimeError("manual navigation must start at index.md and contain unique pages")
    source_pages = {path.name for path in source_docs.glob("*.md")}
    if set(pages) != source_pages:
        raise RuntimeError(
            f"manual navigation mismatch: missing={sorted(source_pages - set(pages))}, "
            f"unknown={sorted(set(pages) - source_pages)}"
        )

    manual.mkdir(exist_ok=True)
    for name in ("src", "build", "html"):
        path = manual / name
        if path.exists():
            shutil.rmtree(path)
    shutil.copytree(source_docs, manual / "src", ignore=shutil.ignore_patterns("dev"))
    shutil.copyfile(manual / "src" / "index.md", manual / "src" / "Home.md")
    (manual / "build").mkdir()
    ordered_sources = ["Home.md" if page == "index.md" else page for page in pages]
    (manual / "build" / "order.mk").write_text(
        "SOURCES := " + " ".join(ordered_sources) + "\nAPPENDIX :=\n"
    )
    (manual / "build" / "order.json").write_text(json.dumps(pages) + "\n")
    shutil.copyfile(source_root / "tools" / "docs-manual" / "Makefile", manual / "manual.generated.mk")

    config["docs_dir"] = "build/html"
    config["site_dir"] = "html"
    config["theme"] = {
        "name": None,
        "custom_dir": "../mkdocs-material/material",
        "language": "en",
        "palette": {"primary": "indigo", "accent": "indigo"},
        "font": {"text": "Roboto", "code": "Roboto Mono"},
        "icon": "logo.png",
        "logo": "logo.png",
        "favicon": "logo.png",
        "feature": {"tabs": True},
    }
    config["extra_css"] = ["skin.css"]
    config["markdown_extensions"] = ["tables", "fenced_code", "toc"]
    config["plugins"] = ["search"]
    config["use_directory_urls"] = False
    (manual / "mkdocs.yml").write_text(yaml.safe_dump(config, sort_keys=False))

    header = (documentation_root / "wolfBoot" / "header.txt").read_text()
    header = header.replace("wolfBoot Documentation", "wolfCOSE Manual")
    header = re.sub(r"(\\copyright\s+)\d{4}", r"\g<1>2026", header)
    (manual / "header.txt").write_text(header)
    return manual


def prepare_pdf(documentation_root):
    manual = documentation_root / MANUAL
    pdf_dir = manual / "build" / "pdf"
    pages = json.loads((manual / "build" / "order.json").read_text())
    headers = {}
    for page in pages:
        staged = pdf_dir / ("Home.md" if page == "index.md" else page)
        found = set()
        in_fence = False
        for line in staged.read_text().splitlines():
            if line.lstrip().startswith(("```", "~~~")):
                in_fence = not in_fence
            if not in_fence:
                match = HEADING.match(line)
                if match:
                    found.add(heading_slug(match.group(2)))
        headers[page] = found

    for page in pages:
        staged = pdf_dir / ("Home.md" if page == "index.md" else page)
        output = [f"[]{{#{page_key(page)}}}\n\n"]
        in_fence = False
        seen = set()
        for line in staged.read_text().splitlines(keepends=True):
            anchor = ""
            if line.lstrip().startswith(("```", "~~~")):
                in_fence = not in_fence
            if not in_fence:
                match = HEADING.match(line.rstrip("\n"))
                if match:
                    slug = heading_slug(match.group(2))
                    unique = slug
                    counter = 1
                    while unique in seen:
                        counter += 1
                        unique = f"{slug}-{counter}"
                    seen.add(unique)
                    anchor = f"[]{{#{page_key(page)}-{unique}}}\n\n"

                def rewrite(link):
                    md = link.group(1)
                    fragment = link.group(2)
                    if md is None and fragment is None:
                        return link.group(0)
                    target = page if md is None else Path(md).name
                    if target not in headers:
                        return link.group(0)
                    if fragment and fragment not in headers[target]:
                        raise RuntimeError(f"unresolved PDF link: {page} -> {target}#{fragment}")
                    anchor = page_key(target) + (f"-{fragment}" if fragment else "")
                    return f"](#{anchor})"

                line = LINK.sub(rewrite, line)
            output.append(anchor + line)
        staged.write_text("".join(output))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build", "pdf-links"))
    parser.add_argument("--documentation-root", required=True, type=Path)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--target", choices=("all", "html", "pdf"), default="all")
    args = parser.parse_args()
    documentation_root = args.documentation_root.resolve()
    if args.command == "pdf-links":
        prepare_pdf(documentation_root)
        return
    if args.source_root is None:
        parser.error("build requires --source-root")
    source_root = args.source_root.resolve()
    manual = stage(documentation_root, source_root)
    subprocess.run(
        ["make", "-C", str(manual), "-f", "manual.generated.mk", args.target,
         f"WC_SOURCE={source_root}"],
        check=True,
    )


if __name__ == "__main__":
    main()
