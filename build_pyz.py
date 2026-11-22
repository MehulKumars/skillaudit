"""Build dist/skillaudit.pyz - a single-file, dependency-free executable archive.

    python build_pyz.py
    python dist/skillaudit.pyz <path>
"""
import os
import shutil
import tempfile
import zipapp

ROOT = os.path.dirname(os.path.abspath(__file__))


def main() -> str:
    out_dir = os.path.join(ROOT, "dist")
    os.makedirs(out_dir, exist_ok=True)
    target = os.path.join(out_dir, "skillaudit.pyz")
    with tempfile.TemporaryDirectory() as tmp:
        shutil.copytree(os.path.join(ROOT, "skillaudit"), os.path.join(tmp, "skillaudit"),
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        with open(os.path.join(tmp, "__main__.py"), "w", encoding="utf-8") as fh:
            fh.write("import sys\nfrom skillaudit.cli import main\nsys.exit(main())\n")
        zipapp.create_archive(tmp, target, interpreter="/usr/bin/env python3", compressed=True)
    print("built %s (%d KB)" % (target, os.path.getsize(target) // 1024))
    return target


if __name__ == "__main__":
    main()
