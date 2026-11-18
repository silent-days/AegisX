"""
AegisX — stylesheet engine.

Loads light.qss + components.qss, substitutes @design tokens from theme.py
(single source of truth) and applies the result to the QApplication.
"""

from __future__ import annotations

from pathlib import Path

from . import theme


def _qss_tokens() -> dict[str, str]:
    tokens = {f"@{k}": v for k, v in theme.COLORS.items()}
    tokens.update(
        {
            "@font_family": theme.FONT_FAMILY,
            "@mono_family": theme.MONO_FAMILY,
            "@radius_card": f"{theme.RADIUS_CARD}px",
            "@radius_input": f"{theme.RADIUS_INPUT}px",
            "@radius_button": f"{theme.RADIUS_BUTTON}px",
        }
    )
    return tokens


def build_stylesheet() -> str:
    """Compose the complete application stylesheet."""
    base = Path(__file__).resolve().parent
    qss = ""
    for name in ("light.qss", "components.qss"):
        p = base / name
        if p.is_file():
            qss += p.read_text(encoding="utf-8") + "\n"
    # Longest tokens first so @text does not clobber @text_secondary, etc.
    for token, value in sorted(_qss_tokens().items(), key=lambda kv: -len(kv[0])):
        qss = qss.replace(token, value)
    return qss


def apply(app) -> None:
    """Apply theme + fonts to a QApplication."""
    from PySide6.QtGui import QFont

    font = QFont("Inter")
    fallbacks = ["Segoe UI", "Noto Sans", "Cantarell", "DejaVu Sans", "Liberation Sans"]
    for f in fallbacks:
        font.insertSubstitution("Inter", f)
    font.setPointSizeF(9.5)
    font.setStyleHint(QFont.StyleHint.SansSerif)
    app.setFont(font)
    app.setStyleSheet(build_stylesheet())
