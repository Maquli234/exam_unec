"""Парсер вопросов из PDF/TXT. Текст берётся дословно (без исправления опечаток).

Поддерживаются маркеры верного ответа:
  1) символ в тексте: «√» / «✓» / «✔» (неверные — «•»);
  2) векторная радиокнопка: у выбранной есть лишняя чёрная заливка.
Сомнительные вопросы получают флаг needs_review для проверки в админке.
"""
import re
from dataclasses import dataclass, field, asdict
import pymupdf

CHECK = "√✓✔☑"
BULLET = "•●○◯·"
Q_RE = re.compile(r"^\s*(\d+)\s*[.)]?\s+(.*\S)\s*$")
Q_EMPTY_RE = re.compile(r"^\s*(\d+)\s*[.)]\s*$")
FOOTER_RE = re.compile(r"^\s*\d+\s*/\s*\d+\s*$")


@dataclass
class Question:
    number: int
    text: str
    options: list = field(default_factory=list)  # [{"text": str, "correct": bool}]
    needs_review: bool = False
    notes: list = field(default_factory=list)


def _page_lines(page):
    """Строки страницы: (y_center, x0, text), + центры «выбранных» радиокнопок."""
    lines = []
    for b in page.get_text("dict")["blocks"]:
        for l in b.get("lines", []):
            txt = "".join(s["text"] for s in l["spans"])
            if txt.strip():
                x0, y0, x1, y1 = l["bbox"]
                lines.append(((y0 + y1) / 2, x0, txt))
    lines.sort(key=lambda t: (round(t[0]), t[1]))
    shapes = [d for d in page.get_drawings()
              if d["type"] == "f" and d["rect"].x0 < 60 and d["rect"].width < 12]
    radios = [d["rect"] for d in shapes if d.get("fill") and tuple(d["fill"]) != (1, 1, 1)
              and d["rect"].width > 3]
    # группируем фигуры в кружки по близости y
    radios.sort(key=lambda r: r.y0)
    groups = []
    for r in radios:
        if groups and r.y0 - groups[-1][0].y0 < 5:
            groups[-1].append(r)
        else:
            groups.append([r])
    all_y = [(sum((r.y0 + r.y1) / 2 for r in g) / len(g), g) for g in groups]
    return lines, all_y, page


def _radio_marks(page):
    """-> (список y всех кружков, множество y выбранных). Выбранный = есть чёрная заливка."""
    ys, checked = [], []
    shapes = [d for d in page.get_drawings()
              if d["type"] == "f" and d["rect"].x0 < 60 and d["rect"].width < 12]
    shapes.sort(key=lambda d: d["rect"].y0)
    groups = []
    for d in shapes:
        if groups and d["rect"].y0 - groups[-1][0]["rect"].y0 < 5:
            groups[-1].append(d)
        else:
            groups.append([d])
    for g in groups:
        if len(g) < 4:  # не радиокнопка
            continue
        yc = sum((d["rect"].y0 + d["rect"].y1) / 2 for d in g) / len(g)
        ys.append(yc)
        if any(tuple(d["fill"] or ()) == (0.0, 0.0, 0.0) for d in g):
            checked.append(yc)
    return ys, checked


def _merge_rows(lines, tol=2.5):
    """Склеивает фрагменты одной визуальной строки (номер/маркер + текст)."""
    lines = sorted(lines, key=lambda t: t[0])
    rows = []
    for yc, x0, txt in lines:
        if rows and abs(rows[-1][0] - yc) <= tol:
            rows[-1][2].append((x0, txt))
        else:
            rows.append([yc, x0, [(x0, txt)]])
    out = []
    for yc, _, parts in rows:
        parts.sort()
        out.append((yc, parts[0][0], " ".join(t.strip() for _, t in parts)))
    return out


def parse_pdf(path):
    doc = pymupdf.open(path)
    items = []  # (kind, text, correct)  kind: line | option
    for page in doc:
        lines = []
        for b in page.get_text("dict")["blocks"]:
            for l in b.get("lines", []):
                txt = "".join(s["text"] for s in l["spans"])
                if txt.strip():
                    x0, y0, x1, y1 = l["bbox"]
                    lines.append(((y0 + y1) / 2, x0, txt))
        lines = _merge_rows(lines)
        radio_ys, checked_ys = _radio_marks(page)
        prev = None  # (y, x0, index в items) последней обычной строки
        for yc, x0, txt in lines:
            if FOOTER_RE.match(txt):
                continue
            s = txt.strip()
            if s[0] in CHECK + BULLET:
                body = s[1:].strip()
                if not body and prev and prev[1] > x0 + 5 and abs(prev[0] - yc) <= 8 \
                        and not Q_RE.match(items[prev[2]][1]):
                    # маркер по центру многострочного варианта: первая строка над ним
                    body = items.pop(prev[2])[1]
                    prev = None
                items.append(("option", body, s[0] in CHECK))
                prev = None
            elif any(abs(yc - ry) < 4 for ry in radio_ys):
                items.append(("option", s, any(abs(yc - cy) < 4 for cy in checked_ys)))
                prev = None
            else:
                qm = Q_RE.match(s) or Q_EMPTY_RE.match(s)
                if qm and prev and prev[1] > x0 + 5 and abs(prev[0] - yc) <= 8:
                    # номер по центру многострочного вопроса: строка над ним — начало текста
                    above = items.pop(prev[2])[1]
                    body = qm.group(2) if qm.lastindex == 2 else ""
                    s = f"{qm.group(1)}. {above} {body}".rstrip()
                items.append(("line", s, False))
                prev = (yc, x0, len(items) - 1)
    return flag_option_count_outliers(_assemble(items))


def parse_text(content: str):
    items = []
    for raw in content.splitlines():
        s = raw.strip()
        if not s:
            continue
        if s[0] in CHECK + BULLET:
            items.append(("option", s[1:].strip(), s[0] in CHECK))
        else:
            items.append(("line", s, False))
    return _assemble(items)


def _assemble(items):
    qs, cur, expected = [], None, 1
    for kind, text, correct in items:
        if kind == "option":
            if cur is None:
                continue
            cur.options.append({"text": text, "correct": correct})
            continue
        m = Q_RE.match(text) or Q_EMPTY_RE.match(text)
        if m and int(m.group(1)) == expected:
            cur = Question(number=int(m.group(1)), text=(m.group(2) if m.lastindex == 2 else ""))
            qs.append(cur)
            expected = cur.number + 1
        elif cur is not None:  # перенос строки
            if cur.options:
                cur.options[-1]["text"] += " " + text
            else:
                cur.text = (cur.text + " " + text) if cur.text else text
    for q in qs:
        n_ok = sum(o["correct"] for o in q.options)
        if n_ok != 1:
            q.needs_review = True
            q.notes.append(f"верных ответов: {n_ok}")
        if len(q.options) < 2:
            q.needs_review = True
            q.notes.append(f"вариантов: {len(q.options)}")
    return qs


def flag_option_count_outliers(qs):
    """Вопросы, у которых число вариантов отличается от типичного для файла."""
    from collections import Counter
    if not qs:
        return qs
    common = Counter(len(q.options) for q in qs).most_common(1)[0][0]
    for q in qs:
        if len(q.options) != common:
            q.needs_review = True
            q.notes.append(f"вариантов {len(q.options)}, обычно {common}")
    return qs


def to_dicts(qs):
    return [asdict(q) for q in qs]
