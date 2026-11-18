"""
AegisX — design tokens.

Single source of truth for the AEGISX premium light theme:
white surfaces, soft cool-gray background and a decisive cybersecurity red.

These tokens are consumed by:
  * the QSS stylesheets (via @token substitution in styles/__init__.py)
  * every custom painted widget (map, graphs, gauges, splash …)
"""

from __future__ import annotations

# ---------------------------------------------------------------- palette --
COLORS = {
    # Surfaces
    "bg":            "#F5F7FA",   # main application background
    "sidebar":       "#FFFFFF",
    "surface":       "#FFFFFF",   # cards
    "surface_alt":   "#F8FAFC",   # subtle wells / table stripes
    "hover":         "#FEF2F2",   # light red hover wash
    "selected":      "#FEF2F2",
    # Brand reds
    "primary":       "#DC2626",   # primary red
    "primary_light": "#EF4444",   # secondary red
    "primary_dark":  "#B91C1C",
    "primary_soft":  "#FEE2E2",   # red tint backgrounds
    # Text
    "text":          "#111827",
    "text_secondary":"#64748B",
    "text_muted":    "#94A3B8",
    "text_on_primary":"#FFFFFF",
    # Lines
    "border":        "#E5E7EB",
    "border_strong": "#D6DCE5",
    "divider":       "#EEF1F5",
    # Status
    "success":       "#16A34A",
    "success_soft":  "#DCFCE7",
    "warning":       "#F59E0B",
    "warning_soft":  "#FEF3C7",
    "critical":      "#DC2626",
    "critical_soft": "#FEE2E2",
    "info":          "#3B82F6",
    "info_soft":     "#DBEAFE",
    # Severity ladder
    "sev_critical":  "#DC2626",
    "sev_high":      "#F97316",
    "sev_medium":    "#F59E0B",
    "sev_low":       "#3B82F6",
    "sev_info":      "#64748B",
    # Map / viz
    "land_dot":      "#CBD5E1",
    "land_fill":     "#E2E8F0",
    "graticule":     "#EDF1F6",
    "ocean":         "#FFFFFF",
    "graph_edge":    "#D8DEE8",
}

SEVERITY_COLORS = {
    "critical": COLORS["sev_critical"],
    "high":     COLORS["sev_high"],
    "medium":   COLORS["sev_medium"],
    "low":      COLORS["sev_low"],
    "info":     COLORS["sev_info"],
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

INDICATOR_TYPE_COLORS = {
    "ip":     "#DC2626",
    "ipv6":   "#B91C1C",
    "domain": "#F97316",
    "url":    "#F59E0B",
    "hash":   "#8B5CF6",
    "asn":    "#3B82F6",
    "campaign": "#DC2626",
}

# ------------------------------------------------------------ typography --
FONT_FAMILY = (
    "Inter, 'Segoe UI', 'Noto Sans', 'Cantarell', 'DejaVu Sans', "
    "'Liberation Sans', sans-serif"
)
MONO_FAMILY = "'JetBrains Mono', 'Fira Code', 'DejaVu Sans Mono', 'Liberation Mono', monospace"

# ------------------------------------------------------------- dimensions --
RADIUS_CARD = 14
RADIUS_INPUT = 9
RADIUS_BUTTON = 9
RADIUS_BADGE = 999

def color(name: str, default: str = "#000000") -> str:
    return COLORS.get(name, default)


def qcolor(name: str):
    """QColor for a token (Qt imported lazily so core stays GUI-free)."""
    from PySide6.QtGui import QColor
    return QColor(COLORS.get(name, "#000000"))


def rgba(name: str, alpha: float) -> str:
    """'rgba(r, g, b, a)' string for inline styles."""
    hexv = COLORS.get(name, "#000000").lstrip("#")
    r, g, b = int(hexv[0:2], 16), int(hexv[2:4], 16), int(hexv[4:6], 16)
    return f"rgba({r}, {g}, {b}, {alpha})"


def rgba_hex(hex_color: str, alpha: float) -> str:
    """'rgba(r, g, b, a)' string from an arbitrary #RRGGBB value."""
    hexv = hex_color.lstrip("#")
    r, g, b = int(hexv[0:2], 16), int(hexv[2:4], 16), int(hexv[4:6], 16)
    return f"rgba({r}, {g}, {b}, {alpha})"
