"""
AegisX — chart factory (PyQtGraph).

Consistent light-theme styling for all analytical charts: area timelines,
bar charts and multi-series lines. Backgrounds are transparent so charts
sit naturally on white cards.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pyqtgraph as pg
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor

from ..styles import theme

pg.setConfigOptions(antialias=True, background="w", foreground="k", leftButtonPan=False)

_AXIS_COLOR = theme.COLORS["text_secondary"]
_GRID = theme.COLORS["divider"]


def _style_axes(plot: pg.PlotWidget) -> None:
    f = pg.QtGui.QFont()
    f.setPointSizeF(8.5)
    for axis in ("left", "bottom"):
        ax = plot.getAxis(axis)
        ax.setPen(pg.mkPen(QColor(_AXIS_COLOR), width=1))
        ax.setTextPen(pg.mkPen(QColor(_AXIS_COLOR)))
        ax.setTickFont(f)


def _base_plot(min_height: int = 200, parent=None) -> pg.PlotWidget:
    plot = pg.PlotWidget(parent=parent)
    plot.setBackground(None)
    plot.getPlotItem().showGrid(x=False, y=True, alpha=0.18)
    plot.getPlotItem().ctrlMenu = None
    vb = plot.getPlotItem().vb
    vb.setBackgroundColor(QColor("#FFFFFF"))
    _style_axes(plot)
    plot.setMinimumHeight(min_height)
    return plot


def timeline_chart(points: list[dict], *, label: str = "Indicators",
                   color: str | None = None, min_height: int = 210,
                   parent=None) -> pg.PlotWidget:
    """
    Filled area timeline. points: [{day: 'YYYY-MM-DD', count: int}].
    """
    plot = _base_plot(min_height, parent)
    color = color or theme.COLORS["primary"]

    xs: list[float] = []
    ys: list[float] = []
    for i, p in enumerate(points):
        try:
            dt = datetime.strptime(p["day"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except (ValueError, KeyError, TypeError):
            continue
        xs.append(dt.timestamp())
        ys.append(p.get("count", 0))
    if not xs:
        xs, ys = [0.0], [0]

    pen = pg.mkPen(QColor(color), width=2.4)
    fill = QColor(color)
    fill.setAlpha(46)
    brush = pg.mkBrush(fill)
    item = pg.PlotDataItem(x=xs, y=ys, pen=pen, brush=brush, fillLevel=0, stepMode=False)
    plot.addItem(item)

    # symbol dots on hover-capable line
    scatter = pg.ScatterPlotItem(x=xs, y=ys, size=6,
                                 pen=pg.mkPen(QColor("#FFFFFF"), width=1.2),
                                 brush=pg.mkBrush(QColor(color)))
    plot.addItem(scatter)

    axis = plot.getAxis("bottom")
    axis.setLabel("")
    ticks = [(x, datetime.fromtimestamp(x, tz=timezone.utc).strftime("%b %d")) for x in xs[:: max(1, len(xs) // 7)]]
    axis.setTicks([ticks])
    plot.getAxis("left").setLabel(label)
    plot.setMouseEnabled(x=True, y=True)
    plot.hideButtons()
    return plot


def bar_chart(categories: list[str], values: list[float], *,
              color: str | None = None, horizontal: bool = False,
              min_height: int = 210, label: str = "", parent=None) -> pg.PlotWidget:
    """Styled bar chart with rotated category labels."""
    color = color or theme.COLORS["primary"]
    plot = _base_plot(min_height, parent)

    n = max(1, len(values))
    width = 0.62
    xs = list(range(n))
    brush = pg.mkBrush(QColor(color))
    border = pg.mkPen(QColor(color).darker(118), width=1)
    bg = pg.BarGraphItem(x0=[x - width / 2 for x in xs], x1=[x + width / 2 for x in xs],
                         y0=[0] * n, y1=list(values), brush=brush, pen=border)
    if horizontal:
        bg = pg.BarGraphItem(y0=[x - width / 2 for x in xs], y1=[x + width / 2 for x in xs],
                             x0=[0] * n, x1=list(values), brush=brush, pen=border)
    plot.addItem(bg)

    # keep y-axis starting at zero for honest bar proportions
    plot.getPlotItem().vb.setLimits(yMin=0 if not horizontal else -1e9)

    ticks = [(i, str(c)) for i, c in enumerate(categories)]
    value_axis = "left" if not horizontal else "bottom"
    cat_axis = "bottom" if not horizontal else "left"
    ax = plot.getAxis(cat_axis)
    ax.setTicks([ticks])

    f = pg.QtGui.QFont()
    f.setPointSizeF(8.5)
    ax.setTickFont(f)
    if len(categories) and max(len(str(c)) for c in categories) > 12 and not horizontal:
        ax.setStyle(tickTextOffset=2)
        ax.setHeight(70)

    if label:
        plot.getAxis(value_axis).setLabel(label)
    plot.hideButtons()
    plot.setMouseEnabled(x=False, y=True) if not horizontal else plot.setMouseEnabled(x=True, y=False)
    return plot


def line_chart(series: dict[str, list[tuple[float, float]]], *,
               colors: dict[str, str] | None = None,
               min_height: int = 210, parent=None) -> pg.PlotWidget:
    """Multi-series line chart for comparisons."""
    plot = _base_plot(min_height, parent)
    colors = colors or {}
    palette = [theme.COLORS["primary"], theme.COLORS["info"], theme.COLORS["success"],
               theme.COLORS["warning"], theme.COLORS["sev_info"]]
    for i, (name, pts) in enumerate(series.items()):
        if not pts:
            continue
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        color = colors.get(name) or palette[i % len(palette)]
        plot.addItem(pg.PlotDataItem(x=xs, y=ys, pen=pg.mkPen(QColor(color), width=2.2),
                                     name=name))
    plot.addLegend(offset=(10, 10), labelTextSize="9px")
    plot.hideButtons()
    return plot
