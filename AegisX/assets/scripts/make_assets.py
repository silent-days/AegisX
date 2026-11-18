#!/usr/bin/env python3
"""AegisX — brand asset generator (logo + icon PNGs) rendered offscreen."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT / "src"), str(ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QRectF  # noqa: E402
from PySide6.QtGui import QColor, QPainter, QPixmap, QLinearGradient  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from aegisx.ui.logo import paint_shield  # noqa: E402

app = QApplication(["assetgen"])

# Transparent icon (used by desktop entry)
for size, name in ((256, "aegisx.png"), (128, "aegisx-128.png"), (64, "aegisx-64.png")):
    pix = QPixmap(size, size)
    pix.fill(QColor(0, 0, 0, 0))
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    paint_shield(p, QRectF(8, 8, size - 16, size - 16), size=size - 16)
    p.end()
    out = ROOT / "assets" / "icons" / name
    pix.save(str(out), "PNG")
    print("saved", out)

# Larger logo with subtle radial glow for README/hero
pix = QPixmap(512, 512)
pix.fill(QColor(0, 0, 0, 0))
p = QPainter(pix)
p.setRenderHint(QPainter.RenderHint.Antialiasing)
glow = QLinearGradient(60, 60, 452, 452)
glow.setColorAt(0.0, QColor(239, 68, 68, 42))
glow.setColorAt(1.0, QColor(185, 28, 28, 10))
p.setBrush(glow)
p.setPen(QColor(0, 0, 0, 0))
p.drawEllipse(QRectF(26, 26, 460, 460))
paint_shield(p, QRectF(96, 66, 320, 380), size=380)
p.end()
out = ROOT / "assets" / "logos" / "aegisx-logo.png"
pix.save(str(out), "PNG")
print("saved", out)
