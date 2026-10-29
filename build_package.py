#!/usr/bin/env python3
"""Build the installable package zip.

    python3 build_package.py [output_dir]      (default: ./dist)

Each extension folder named in pkg_colorpack_shield.xml becomes its own zip under packages/,
and the manifest inside the package points at those zips (Joomla installs a package from its
packages/ files). Tests, notes and .DS_Store files are left out.
"""
import io
import re
import sys
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parent
out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else root / "dist"
manifest = (root / "pkg_colorpack_shield.xml").read_text(encoding="utf-8")
version = re.search(r"<version>([^<]+)</version>", manifest).group(1)

SKIP = {".DS_Store"}


def zip_dir(src: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(src.rglob("*")):
            if f.is_file() and f.name not in SKIP:
                z.write(f, f.relative_to(src).as_posix())
    return buf.getvalue()


names = {}


def rewrite(m: re.Match) -> str:
    attrs, folder = m.group(1), m.group(2)
    typ = re.search(r'type="([^"]+)"', attrs).group(1)
    ident = re.search(r'id="([^"]+)"', attrs).group(1)
    group = re.search(r'group="([^"]+)"', attrs)
    name = f"{'plg_' + group.group(1) + '_' + ident if group else ident}.zip"
    names[name] = zip_dir(root / folder)
    return f"<file {attrs}>packages/{name}</file>"


packaged = re.sub(r"<file ([^>]*)>([^<]+)</file>", rewrite, manifest)
out_dir.mkdir(parents=True, exist_ok=True)
target = out_dir / f"pkg_colorpack_shield-{version}.zip"

with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("pkg_colorpack_shield.xml", packaged)
    z.write(root / "script.php", "script.php")
    for name, data in names.items():
        z.writestr(f"packages/{name}", data)

print(target)
