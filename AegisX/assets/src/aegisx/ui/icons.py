"""
AegisX — icon system.

Stroke-based SVG icon set (24x24 grid, 2px strokes, round caps — consistent
with the premium light theme). Icons are recoloured at load time and cached
as QIcon instances at multiple sizes so every surface (sidebar, buttons,
cards) stays crisp on HiDPI displays.
"""

from __future__ import annotations

from functools import lru_cache

from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import QIcon, QImage, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

# 24x24 stroke icon path data (feather-style)
_SVGS: dict[str, str] = {
    "dashboard": '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/>',
    "globe": '<circle cx="12" cy="12" r="9"/><line x1="3" y1="12" x2="21" y2="12"/><path d="M12 3a14.5 14.5 0 0 1 3.8 9 14.5 14.5 0 0 1-3.8 9 14.5 14.5 0 0 1-3.8-9A14.5 14.5 0 0 1 12 3z"/>',
    "radar": '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4.5"/><line x1="12" y1="12" x2="19" y2="5"/><line x1="12" y1="3" x2="12" y2="5"/>',
    "target": '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.4"/>',
    "domain": '<path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/>',
    "server": '<rect x="2.5" y="3" width="19" height="7.5" rx="2"/><rect x="2.5" y="13.5" width="19" height="7.5" rx="2"/><line x1="6.5" y1="6.7" x2="6.6" y2="6.7"/><line x1="6.5" y1="17.2" x2="6.6" y2="17.2"/>',
    "share": '<circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.6" y1="10.6" x2="15.4" y2="6.5"/><line x1="8.6" y1="13.4" x2="15.4" y2="17.5"/>',
    "flag": '<path d="M4 15.5s1-1 4-1 5 2 8 2 4-1 4-1V4.5s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15.5"/>',
    "analytics": '<line x1="18" y1="20" x2="18" y2="9"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="13"/>',
    "briefcase": '<rect x="2.5" y="7" width="19" height="13" rx="2.5"/><path d="M16 7V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v2"/><path d="M2.5 13h19"/>',
    "database": '<ellipse cx="12" cy="5.5" rx="9" ry="3"/><path d="M21 5.5v6c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 11.5v7c0 1.66 4 3 9 3s9-1.34 9-3v-7"/>',
    "report": '<path d="M14 2.5H6a2 2 0 0 0-2 2v15a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8.5z"/><polyline points="14 2.5 14 8.5 20 8.5"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="13" y2="17"/>',
    "settings": '<line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/>',
    "info": '<circle cx="12" cy="12" r="9"/><line x1="12" y1="16" x2="12" y2="11"/><line x1="12" y1="7.5" x2="12.01" y2="7.5"/>',
    "search": '<circle cx="11" cy="11" r="7.5"/><line x1="21" y1="21" x2="16.5" y2="16.5"/>',
    "x": '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
    "plus": '<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>',
    "minus": '<line x1="5" y1="12" x2="19" y2="12"/>',
    "square": '<rect x="5" y="5" width="14" height="14" rx="2"/>',
    "refresh": '<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.5 9a9 9 0 0 1 14.9-3.4L23 10M1 14l4.6 4.4A9 9 0 0 0 20.5 15"/>',
    "download": '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>',
    "upload": '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>',
    "trash": '<polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/>',
    "alert": '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h16.9a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><line x1="12" y1="9" x2="12" y2="13.5"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    "check": '<path d="M22 11.1V12a10 10 0 1 1-5.9-9.1"/><polyline points="22 4 12 14.1 9 11.1"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><polyline points="12 6.5 12 12 16 14"/>',
    "zap": '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    "map-pin": '<path d="M21 10c0 7-9 12.5-9 12.5S3 17 3 10a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/>',
    "external": '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>',
    "eye": '<path d="M1 12s4-7.5 11-7.5S23 12 23 12s-4 7.5-11 7.5S1 12 1 12z"/><circle cx="12" cy="12" r="3"/>',
    "edit": '<path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4z"/>',
    "link": '<path d="M15 7h3a5 5 0 0 1 0 10h-3m-6 0H6A5 5 0 0 1 6 7h3"/><line x1="8" y1="12" x2="16" y2="12"/>',
    "filter": '<polygon points="22 3 2 3 10 12.5 10 19 14 21 14 12.5 22 3"/>',
    "folder": '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>',
    "key": '<path d="M21 2l-2 2m-7.6 7.6a5.5 5.5 0 1 1-7.8 7.8 5.5 5.5 0 0 1 7.8-7.8zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3-3.5 3.5z"/>',
    "lock": '<rect x="3.5" y="11" width="17" height="10" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    "bell": '<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.7 21a2 2 0 0 1-3.4 0"/>',
    "chevron-right": '<polyline points="9 6 15 12 9 18"/>',
    "chevron-left": '<polyline points="15 6 9 12 15 18"/>',
    "chevron-down": '<polyline points="6 9 12 15 18 9"/>',
    "play": '<polygon points="6 4 20 12 6 20 6 4"/>',
    "activity": '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
    "crosshair": '<circle cx="12" cy="12" r="9"/><line x1="22" y1="12" x2="18" y2="12"/><line x1="6" y1="12" x2="2" y2="12"/><line x1="12" y1="6" x2="12" y2="2"/><line x1="12" y1="22" x2="12" y2="18"/>',
    "cpu": '<rect x="4.5" y="4.5" width="15" height="15" rx="2"/><rect x="9.5" y="9.5" width="5" height="5"/><line x1="9" y1="2" x2="9" y2="4.5"/><line x1="15" y1="2" x2="15" y2="4.5"/><line x1="9" y1="19.5" x2="9" y2="22"/><line x1="15" y1="19.5" x2="15" y2="22"/><line x1="2" y1="9" x2="4.5" y2="9"/><line x1="2" y1="15" x2="4.5" y2="15"/><line x1="19.5" y1="9" x2="22" y2="9"/><line x1="19.5" y1="15" x2="22" y2="15"/>',
    "wifi-off": '<line x1="2" y1="2" x2="22" y2="22"/><path d="M8.5 16.4a5 5 0 0 1 7 0"/><path d="M5 12.9a10 10 0 0 1 5.2-2.8M18.6 13.5a10 10 0 0 0-2.1-1.5"/><path d="M2 8.8a15 15 0 0 1 5-3.1M19 8.8a15 15 0 0 0-4.4-2.6"/>',
    "users": '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
    "save": '<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>',
    "file": '<path d="M14 2.5H6a2 2 0 0 0-2 2v15a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8.5z"/><polyline points="14 2.5 14 8.5 20 8.5"/>',
    "list": '<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>',
    "gauge": '<path d="M12 15l3.5-5.5"/><path d="M20.5 15.5a9 9 0 1 0-17 0"/>',
    "network": '<rect x="9" y="2.5" width="6" height="6" rx="1.5"/><rect x="2.5" y="15.5" width="6" height="6" rx="1.5"/><rect x="15.5" y="15.5" width="6" height="6" rx="1.5"/><line x1="12" y1="8.5" x2="12" y2="12"/><line x1="5.5" y1="15.5" x2="5.5" y2="12"/><line x1="12" y1="12" x2="18.5" y2="12"/><line x1="18.5" y1="12" x2="18.5" y2="15.5"/><line x1="5.5" y1="12" x2="12" y2="12"/>',
    "maximize": '<path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3"/>',
}


def _svg_for(name: str, color: str) -> str:
    body = _SVGS.get(name, _SVGS["info"])
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" '
        f'viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="2" '
        f'stroke-linecap="round" stroke-linejoin="round">{body}</svg>'
    )


def icon_names() -> list[str]:
    return sorted(_SVGS.keys())


@lru_cache(maxsize=512)
def _render(name: str, color: str, size: int) -> QIcon:
    renderer = QSvgRenderer(QByteArray(_svg_for(name, color).encode("utf-8")))
    icon = QIcon()
    for s in {size, 16, 20, 24, 32, 48}:
        img = QImage(s, s, QImage.Format.Format_ARGB32_Premultiplied)
        img.fill(Qt.GlobalColor.transparent)
        painter = QPainter(img)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        renderer.render(painter, QRectF(0, 0, s, s))
        painter.end()
        icon.addPixmap(QPixmap.fromImage(img))
    return icon


def icon(name: str, color: str = "#64748B", size: int = 24) -> QIcon:
    """Cached, recoloured application icon."""
    return _render(name, color, size)


def pixmap(name: str, color: str, size: int = 24) -> QPixmap:
    return icon(name, color, size).pixmap(size, size)
