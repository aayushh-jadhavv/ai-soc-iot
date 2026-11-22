"""Render the two release comparisons from the verified results (ReportLab 4.4.9)."""

import argparse
import json
from pathlib import Path

from reportlab.graphics import renderSVG
from reportlab.graphics.charts.barcharts import HorizontalBarChart
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib.colors import HexColor


def draw(results):
    models = results["models"]
    rows = [
        ("GA compact 3 (release)", "ga_3"), ("GA compact 2", "ga_2"), ("GA compact 1", "ga_1"),
        ("Direct small  /  31415", "direct_small_seed_31415"),
        ("Direct small  /  2718", "direct_small_seed_2718"),
        ("Direct small  /  1729", "direct_small_seed_1729"), ("Unpruned", "unpruned"),
    ]
    ink, line = HexColor("#193348"), HexColor("#ccd5d9")
    colors = [HexColor("#006b73"), HexColor("#dd9b41")]
    fig = Drawing(820, 358)
    fig.add(Rect(0, 0, 820, 358, fillColor=HexColor("#ffffff"), strokeColor=None))
    def label(x, y, value, size=11, bold=False):
        fig.add(String(x, y, value, fontName="Helvetica-Bold" if bold else "Helvetica",
                       fontSize=size, fillColor=ink))

    label(20, 327, "Frozen model comparisons", 22, True)
    label(20, 306, "UNSW-NB15  /  One chronological test block  /  2,513 histories  /  Comparison threshold 0.5")
    for i, name in enumerate(("Float32", "Diagnostic INT8")):
        x = 591 + i * 85
        fig.add(Rect(x, 331, 10, 9, strokeColor=None, fillColor=colors[i]))
        label(x + 15, 331, name, 10)

    for x, title, key, maximum, step in [
        (154, "Macro-F1", "macro_f1", 1, 0.25),
        (497, "False positives among 2,501 benign histories", "fp", 60, 10),
    ]:
        label(x, 268, title, 13, True)
        chart = HorizontalBarChart()
        chart.x, chart.y, chart.width, chart.height = x, 39, 277, 213
        chart.data = [[models[f"{name}/{precision}"][key] for _, name in rows]
                      for precision in ("float32", "int8")]
        chart.categoryAxis.categoryNames = [name for name, _ in rows]
        chart.categoryAxis.visibleLabels = key == "macro_f1"
        chart.categoryAxis.labels.fontName = "Helvetica"
        chart.categoryAxis.labels.fontSize = 11
        chart.categoryAxis.labels.fillColor = ink
        chart.categoryAxis.labels.dx = -7
        chart.categoryAxis.strokeColor = line
        chart.categoryAxis.tickLeft = 0
        chart.valueAxis.valueMin, chart.valueAxis.valueMax, chart.valueAxis.valueStep = 0, maximum, step
        chart.valueAxis.strokeColor = line
        chart.valueAxis.visibleGrid = True
        chart.valueAxis.gridStrokeColor = line
        chart.valueAxis.gridStrokeWidth = 0.4
        chart.valueAxis.labels.fillColor = ink
        chart.valueAxis.labels.fontName = "Helvetica"
        chart.valueAxis.labels.fontSize = 10
        for i, color in enumerate(colors):
            chart.bars[i].fillColor = color
            chart.bars[i].strokeColor = None
        fig.add(chart)
    return fig


if __name__ == "__main__":
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results", type=Path, default=here / "results.json")
    ap.add_argument("--output", type=Path, default=here / "comparison.svg")
    args = ap.parse_args()
    svg = renderSVG.drawToString(draw(json.loads(args.results.read_bytes())))
    svg = svg.replace("<title>...</title>", "<title>Frozen model comparisons</title>", 1)
    svg = svg.replace("<desc>...</desc>", "<desc>Macro-F1 and false positives on the UNSW-NB15 "
                      "chronological test block for seven float32 and INT8 model pairs.</desc>", 1)
    args.output.write_bytes(svg.encode("utf-8"))
