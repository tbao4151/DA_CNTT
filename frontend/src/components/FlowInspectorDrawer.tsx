"use client";

import React, { useState } from "react";
import { Check, ChevronDown, ChevronRight, Copy, FolderPlus, X } from "lucide-react";
import { PriorityBadge } from "./ui";

export interface InspectorPayload {
  title: string;
  subtitle?: string;
  badgeCode?: string;
  badgeLabel?: string;
  signalScore?: number;
  signalReasons?: string[];
  evidence: Record<string, unknown>;
  canCreateCase?: boolean;
  onCreateCase?: () => Promise<void> | void;
}

export function FlowInspectorDrawer({
  payload,
  onClose,
}: {
  payload: InspectorPayload | null;
  onClose: () => void;
}) {
  const [showRawJson, setShowRawJson] = useState(false);
  const [copied, setCopied] = useState(false);
  const [creating, setCreating] = useState(false);

  if (!payload) return null;

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(payload.evidence, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // clipboard blocked
    }
  };

  const entries = Object.entries(payload.evidence).filter(
    ([, val]) => val !== null && val !== undefined && String(val).trim() !== ""
  );

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/70"
      role="dialog"
      aria-modal="true"
      aria-label={payload.title}
    >
      <div className="flex h-full w-full max-w-xl flex-col border-l border-slate-800 bg-surface shadow-2xl">
        <div className="flex items-start justify-between gap-3 border-b border-slate-800 px-5 py-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="truncate text-base font-bold text-slate-100">{payload.title}</h2>
              {payload.badgeCode ? (
                <PriorityBadge code={payload.badgeCode} label={payload.badgeLabel} />
              ) : null}
            </div>
            {payload.subtitle ? (
              <p className="mt-1 truncate font-mono text-xs text-slate-400">{payload.subtitle}</p>
            ) : null}
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Đóng ngăn chi tiết"
            className="rounded-lg border border-slate-700 p-1.5 text-slate-400 hover:bg-slate-800 hover:text-slate-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="flex-1 space-y-4 overflow-y-auto p-5">
          {typeof payload.signalScore === "number" && (
            <div className="rounded-xl border border-slate-800 bg-subtle p-3.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-slate-200">
                  Tín hiệu quy tắc phụ trợ (Heuristics)
                </span>
                <span className="font-mono font-bold text-amber-300 tabular-nums">
                  {payload.signalScore}/100
                </span>
              </div>
              <p className="mt-1.5 text-xs text-slate-400">
                {payload.signalReasons && payload.signalReasons.length > 0
                  ? payload.signalReasons.join("; ")
                  : "Không kích hoạt quy tắc mẫu bổ sung (chỉ là tín hiệu phụ trợ, không phải kết luận)."}
              </p>
            </div>
          )}

          <div>
            <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
              Thuộc tính kỹ thuật ({entries.length} trường)
            </div>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
              {entries.map(([key, val]) => (
                <div
                  key={key}
                  className="rounded-lg border border-slate-800 bg-canvas/80 px-2.5 py-2"
                >
                  <div className="truncate font-mono text-[10px] uppercase text-slate-500">
                    {key}
                  </div>
                  <div className="mt-0.5 break-all font-mono text-xs font-semibold text-slate-200 tabular-nums">
                    {String(val)}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-canvas/70">
            <div className="flex items-center justify-between px-3.5 py-2.5">
              <button
                type="button"
                onClick={() => setShowRawJson((v) => !v)}
                className="flex items-center gap-1.5 text-xs font-semibold text-slate-300 hover:text-white"
              >
                {showRawJson ? (
                  <ChevronDown className="h-3.5 w-3.5" />
                ) : (
                  <ChevronRight className="h-3.5 w-3.5" />
                )}
                Dữ liệu JSON nguyên bản (Raw Evidence)
              </button>
              <button
                type="button"
                onClick={() => void handleCopy()}
                className="inline-flex items-center gap-1 rounded border border-slate-700 px-2 py-1 font-mono text-[11px] text-slate-300 hover:bg-slate-800"
              >
                {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                {copied ? "Đã chép" : "Chép JSON"}
              </button>
            </div>
            {showRawJson && (
              <pre className="max-h-72 overflow-auto border-t border-slate-800 p-3 font-mono text-[11px] text-slate-300">
                {JSON.stringify(payload.evidence, null, 2)}
              </pre>
            )}
          </div>
        </div>

        <div className="flex items-center justify-between gap-3 border-t border-slate-800 bg-subtle px-5 py-3.5">
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-slate-700 px-3.5 py-2 text-xs font-medium text-slate-300 hover:bg-slate-800"
          >
            Đóng
          </button>
          {payload.canCreateCase && payload.onCreateCase ? (
            <button
              type="button"
              disabled={creating}
              onClick={async () => {
                setCreating(true);
                try {
                  await payload.onCreateCase?.();
                } finally {
                  setCreating(false);
                }
              }}
              className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-500 disabled:opacity-50"
            >
              <FolderPlus className="h-3.5 w-3.5" />
              {creating ? "Đang lập hồ sơ..." : "Tạo SOC case từ flow này"}
            </button>
          ) : null}
        </div>
      </div>
    </div>
  );
}
