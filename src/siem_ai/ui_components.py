"""Shared, purely presentational SOC UI primitives for DA005 Sentinel Lab.

All helpers in this module format or render escaped HTML/Plotly layouts only;
they never alter AI predictions, thresholds, SQLite persistence, or policy rules.
"""
from __future__ import annotations

import html
import math
from typing import Iterable

import streamlit as st

_FLOW_FIELD_SPECS: tuple[tuple[str, str], ...] = (
    ("flow_ref", "Flow Ref"),
    ("uid", "Zeek UID"),
    ("event_time_utc", "Timestamp (UTC)"),
    ("src_ip", "Source IP"),
    ("src_port", "Source Port"),
    ("dst_ip", "Dest IP"),
    ("dst_port", "Dest Port"),
    ("proto", "Protocol"),
    ("service", "Service"),
    ("state", "Conn State"),
    ("conn_state", "Zeek State"),
    ("dur", "Duration (s)"),
    ("duration_s", "Duration (s)"),
    ("sbytes", "Src Bytes"),
    ("orig_bytes", "Orig Bytes"),
    ("dbytes", "Dst Bytes"),
    ("resp_bytes", "Resp Bytes"),
    ("spkts", "Src Pkts"),
    ("orig_pkts", "Orig Pkts"),
    ("dpkts", "Dst Pkts"),
    ("resp_pkts", "Resp Pkts"),
    ("rate", "Flow Rate"),
    ("sttl", "Src TTL"),
    ("dttl", "Dst TTL"),
    ("ct_srv_src", "ct_srv_src"),
    ("ct_state_ttl", "ct_state_ttl"),
    ("AI_verdict", "AI Verdict"),
    ("AI_attack_probability", "P(Attack)"),
    ("origin", "Data Origin"),
    ("source_sha256", "Source SHA-256"),
)


def style_chart(fig, *, height: int = 310, legend: bool = False):
    """Apply consistent enterprise light-surface Plotly styling across all pages."""
    fig.update_layout(
        template="plotly_white",
        height=height,
        paper_bgcolor="#ffffff",
        plot_bgcolor="#ffffff",
        font=dict(
            family="Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif",
            color="#283d5a",
            size=12,
        ),
        margin=dict(l=18, r=16, t=18, b=38),
        showlegend=legend,
        hoverlabel=dict(bgcolor="#14253f", font_color="#ffffff"),
    )
    fig.update_xaxes(showgrid=False, linecolor="#dbe4ee", tickfont=dict(color="#52637b"))
    fig.update_yaxes(gridcolor="#e8eef6", zeroline=False, tickfont=dict(color="#52637b"))
    return fig


def priority_band_from_probability(probability: float | None) -> dict[str, str | int]:
    """Map an AI Attack probability to a colorblind-safe priority band.

    Note: This ranks review priority by model score only; it is NOT an incident
    severity claim or confirmed security compromise.
    """
    if probability is None or not isinstance(probability, (int, float)) or not math.isfinite(float(probability)):
        return {
            "code": "INFO",
            "label": "[INFO] N/A",
            "badge_class": "soc-badge--info",
            "rank": 0,
        }
    value = float(probability)
    if value >= 0.90:
        return {"code": "CRIT", "label": "[CRIT] >= 0.90", "badge_class": "soc-badge--critical", "rank": 4}
    if value >= 0.80:
        return {"code": "HIGH", "label": "[HIGH] 0.80–0.89", "badge_class": "soc-badge--high", "rank": 3}
    if value >= 0.65:
        return {"code": "MED", "label": "[MED] 0.65–0.79", "badge_class": "soc-badge--medium", "rank": 2}
    if value >= 0.50:
        return {"code": "LOW", "label": "[LOW] 0.50–0.64", "badge_class": "soc-badge--low", "rank": 1}
    return {"code": "INFO", "label": "[INFO] Normal (<0.50)", "badge_class": "soc-badge--info", "rank": 0}


def render_sidebar_brand(
    *,
    workspace_title: str,
    workspace_mode: str,
    mode_variant: str = "dataset",
) -> None:
    """Render unified SENTINEL LAB sidebar branding and 4-workspace map."""
    mark_cls = "soc-brand__mark"
    if mode_variant == "blue":
        mark_cls += " soc-brand__mark--blue"
    elif mode_variant == "red":
        mark_cls += " soc-brand__mark--red"

    st.sidebar.markdown(
        '<div class="soc-brand">'
        f'<span class="{mark_cls}" aria-hidden="true">S</span>'
        '<span class="soc-brand__name">SENTINEL LAB</span>'
        '<p class="soc-brand__subtitle">DA005 / TDTU<br>Security Operations · Research Console</p>'
        f'<div class="soc-brand__workspace">{html.escape(workspace_title)} · {html.escape(workspace_mode)}</div>'
        '</div>',
        unsafe_allow_html=True,
    )

    workspaces = (
        ("dataset", "Dataset SOC (app.py)", "UNSW-NB15 benchmark & triage"),
        ("cyber_lab", "Cyber Lab", "Zeek conn.log offline preview"),
        ("red_team", "Red Team Lab", "Scenario planner (Execution OFF)"),
        ("new_log", "New Log Review", "Pinned Zeek AI review & audit"),
    )
    active_key = {
        "Dataset Mode": "dataset",
        "Blue Team · Telemetry": "cyber_lab",
        "Red Team · Simulation": "red_team",
        "Blue Team · NEW-Log": "new_log",
    }.get(workspace_title, "")

    rows = []
    for key, name, desc in workspaces:
        cls = "soc-sidebar-nav-item soc-sidebar-nav-item--active" if key == active_key else "soc-sidebar-nav-item"
        prefix = "&rsaquo; " if key == active_key else "&middot; "
        rows.append(
            f'<div class="{cls}">{prefix}<strong>{html.escape(name)}:</strong> {html.escape(desc)}</div>'
        )
    st.sidebar.markdown(
        '<div class="soc-sidebar-nav-guide">'
        '<div class="soc-sidebar-nav-guide__title">Phân hệ trong DA005</div>'
        + "".join(rows)
        + '</div>',
        unsafe_allow_html=True,
    )


def render_mode_banner(tag: str, title: str, detail: str, *, variant: str = "dataset") -> str:
    """Build an escaped operational mode banner separating Detection vs Simulation."""
    cls = "soc-mode-banner"
    if variant == "blue":
        cls += " soc-mode-banner--blue"
    elif variant == "red":
        cls += " soc-mode-banner--red"
    return (
        f'<div class="{cls}">'
        f'<div><strong>{html.escape(title)}</strong><br><span>{html.escape(detail)}</span></div>'
        f'<span class="soc-mode-banner__tag">{html.escape(tag)}</span>'
        '</div>'
    )


def render_provenance_strip(items: Iterable[tuple[str, str]]) -> str:
    """Build a responsive grid of provenance metadata items."""
    cards = []
    for label, value in items:
        cards.append(
            '<div class="soc-provenance-item">'
            f'<div class="soc-provenance-label">{html.escape(str(label))}</div>'
            f'<div class="soc-provenance-val">{html.escape(str(value))}</div>'
            '</div>'
        )
    return '<div class="soc-provenance-strip">' + "".join(cards) + '</div>'


def render_confusion_matrix_html(
    cm: list[list[int]],
    *,
    average_precision: float | None = None,
    train_size: int | None = None,
    test_size: int | None = None,
) -> str:
    """Render a readable 2x2 Confusion Matrix card instead of raw JSON."""
    tn, fp = int(cm[0][0]), int(cm[0][1])
    fn, tp = int(cm[1][0]), int(cm[1][1])
    total = tn + fp + fn + tp

    def _pct(val: int, denom: int) -> str:
        return f"{(val / denom * 100):.1f}%" if denom else "0.0%"

    footer_parts = []
    if average_precision is not None:
        footer_parts.append(f"Average Precision (Attack): {average_precision:.4f}")
    if train_size is not None and test_size is not None:
        footer_parts.append(f"Train: {train_size:,} · Official Test: {test_size:,}")
    footer_text = " · ".join(footer_parts)

    return (
        '<div class="soc-card">'
        '<div class="soc-card__header">'
        '<div><div class="soc-card__title">Ma trận nhầm lẫn (Confusion Matrix · Official Test)</div>'
        f'<div class="soc-card__sub">{html.escape(footer_text)}</div></div>'
        '<span class="soc-badge soc-badge--info">Ngưỡng mặc định 0,50</span>'
        '</div>'
        '<table class="soc-cm-table">'
        '<thead><tr>'
        '<th>Thực tế \\ Dự đoán</th>'
        '<th>Dự đoán Normal (0)</th>'
        '<th>Dự đoán Attack (1)</th>'
        '</tr></thead>'
        '<tbody>'
        '<tr>'
        '<th>Thực tế Normal (0)</th>'
        f'<td class="soc-cm-cell--tn"><span class="soc-cm-num">{tn:,}</span>'
        f'<span class="soc-cm-tag">TN · {_pct(tn, tn + fp)} Normal đúng</span></td>'
        f'<td class="soc-cm-cell--fp"><span class="soc-cm-num">{fp:,}</span>'
        f'<span class="soc-cm-tag">FP (Báo nhầm) · {_pct(fp, tn + fp)} FPR</span></td>'
        '</tr>'
        '<tr>'
        '<th>Thực tế Attack (1)</th>'
        f'<td class="soc-cm-cell--fn"><span class="soc-cm-num">{fn:,}</span>'
        f'<span class="soc-cm-tag">FN (Bỏ sót) · {_pct(fn, fn + tp)} FNR</span></td>'
        f'<td class="soc-cm-cell--tp"><span class="soc-cm-num">{tp:,}</span>'
        f'<span class="soc-cm-tag">TP · {_pct(tp, fn + tp)} Recall</span></td>'
        '</tr>'
        '</tbody>'
        '</table>'
        f'<div class="soc-card__sub" style="margin-top:9px;">Tổng mẫu kiểm thử: {total:,} flows. '
        'FP là gánh nặng cảnh báo giả cho SOC; FN là tấn công không được phát hiện ở ngưỡng 0,50.</div>'
        '</div>'
    )


def render_flow_evidence_card(
    row: dict,
    *,
    title: str = "Tóm tắt đặc trưng luồng mạng (Flow Evidence)",
    subtitle: str = "",
    badge_text: str = "",
    badge_class: str = "soc-badge--info",
) -> str:
    """Render key telemetry fields of a flow or Zeek record in a clean monospace grid."""
    items = []
    seen_keys: set[str] = set()
    for key, label in _FLOW_FIELD_SPECS:
        if key not in row:
            continue
        val = row.get(key)
        if val is None or str(val).strip() == "":
            continue
        seen_keys.add(key)
        if key == "AI_attack_probability":
            try:
                formatted = f"{float(val):.2%}"
            except (TypeError, ValueError):
                formatted = str(val)
        elif key == "source_sha256" and len(str(val)) > 20:
            s = str(val)
            formatted = f"{s[:12]}…{s[-8:]}"
        elif isinstance(val, float):
            formatted = f"{val:,.4f}".rstrip("0").rstrip(".")
        else:
            formatted = str(val)
        items.append(
            '<div class="soc-kv-item">'
            f'<div class="soc-kv-label">{html.escape(label)}</div>'
            f'<div class="soc-kv-value">{html.escape(formatted)}</div>'
            '</div>'
        )

    badge_html = (
        f'<span class="soc-badge {html.escape(badge_class)}">{html.escape(badge_text)}</span>'
        if badge_text
        else ""
    )
    sub_html = f'<div class="soc-card__sub">{html.escape(subtitle)}</div>' if subtitle else ""
    grid_html = (
        '<div class="soc-kv-grid">' + "".join(items) + '</div>'
        if items
        else '<div class="soc-card__sub">Không có thuộc tính hiển thị tóm tắt.</div>'
    )

    return (
        '<div class="soc-card">'
        '<div class="soc-card__header">'
        f'<div><div class="soc-card__title">{html.escape(title)}</div>{sub_html}</div>'
        f'{badge_html}'
        '</div>'
        f'{grid_html}'
        '</div>'
    )


def render_empty_state(title: str, description: str, hint: str = "") -> str:
    """Render a structured empty-state card with actionable next step."""
    hint_html = f'<div class="soc-empty-state__hint">{html.escape(hint)}</div>' if hint else ""
    return (
        '<div class="soc-empty-state">'
        f'<div class="soc-empty-state__title">{html.escape(title)}</div>'
        f'<div class="soc-empty-state__desc">{html.escape(description)}</div>'
        f'{hint_html}'
        '</div>'
    )


def render_footer() -> str:
    """Return consistent footer HTML across all Sentinel Lab pages."""
    return (
        '<footer class="soc-footer">DA005 · Dự án CNTT — Tôn Đức Thắng University<br>'
        'Nguyễn Văn Thiên Bảo / Đặng Triệu Vỹ · GVHD: Trương Đình Tú · '
        'Phiên bản nghiên cứu/học tập ngoại tuyến, không dùng để giám sát mạng sản xuất.</footer>'
    )
