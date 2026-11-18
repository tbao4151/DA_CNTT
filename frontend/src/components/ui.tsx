import React from "react";
import { AlertCircle, CheckCircle2, Info, RefreshCw, ShieldAlert } from "lucide-react";
import { cn } from "@/lib/utils";

export function Panel({
  className,
  children,
}: {
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <section
      className={cn(
        "rounded-xl border border-slate-800 bg-surface p-4 shadow-sm",
        className
      )}
    >
      {children}
    </section>
  );
}

export function PriorityBadge({
  code,
  label,
}: {
  code: string;
  label?: string;
}) {
  const styles: Record<string, string> = {
    CRIT: "border-red-500/40 bg-red-950/60 text-red-300",
    HIGH: "border-orange-500/40 bg-orange-950/60 text-orange-300",
    MED: "border-amber-500/40 bg-amber-950/60 text-amber-300",
    LOW: "border-sky-500/40 bg-sky-950/60 text-sky-300",
    INFO: "border-slate-700 bg-slate-800/80 text-slate-300",
    RED: "border-red-500/50 bg-red-950/70 text-red-200",
    BLUE: "border-teal-500/40 bg-teal-950/60 text-teal-200",
  };
  const cls = styles[code] ?? styles.INFO;
  return (
    <span
      className={cn(
        "inline-flex items-center whitespace-nowrap rounded-md border px-2 py-0.5 font-mono text-xs font-semibold tabular-nums",
        cls
      )}
    >
      {label ?? `[${code}]`}
    </span>
  );
}

export function KpiCard({
  label,
  value,
  sublabel,
  accent = "default",
}: {
  label: string;
  value: string;
  sublabel?: string;
  accent?: "default" | "blue" | "teal" | "red" | "amber";
}) {
  const borderAccent: Record<string, string> = {
    default: "border-slate-800",
    blue: "border-l-2 border-l-blue-500 border-slate-800",
    teal: "border-l-2 border-l-teal-500 border-slate-800",
    red: "border-l-2 border-l-red-500 border-slate-800",
    amber: "border-l-2 border-l-amber-500 border-slate-800",
  };
  return (
    <div
      className={cn(
        "rounded-xl border bg-surface px-4 py-3.5",
        borderAccent[accent] ?? borderAccent.default
      )}
    >
      <div className="text-xs font-medium uppercase tracking-wider text-slate-400">
        {label}
      </div>
      <div className="mt-1.5 font-mono text-2xl font-bold tracking-tight text-slate-100 tabular-nums">
        {value}
      </div>
      {sublabel ? (
        <div className="mt-1 text-xs text-slate-400">{sublabel}</div>
      ) : null}
    </div>
  );
}

export function ModeBanner({
  variant,
  tag,
  title,
  description,
}: {
  variant: "dataset" | "blue" | "red";
  tag: string;
  title: string;
  description: string;
}) {
  const styles = {
    dataset: "border-blue-500/30 bg-blue-950/30 text-blue-100",
    blue: "border-teal-500/30 bg-teal-950/30 text-teal-100",
    red: "border-red-500/40 bg-red-950/35 text-red-100",
  };
  const tagStyles = {
    dataset: "border-blue-400/40 bg-blue-900/50 text-blue-200",
    blue: "border-teal-400/40 bg-teal-900/50 text-teal-200",
    red: "border-red-400/50 bg-red-900/60 text-red-200",
  };
  const Icon = variant === "red" ? ShieldAlert : Info;
  return (
    <div
      className={cn(
        "flex flex-col gap-2 rounded-xl border px-4 py-3 sm:flex-row sm:items-center sm:justify-between",
        styles[variant]
      )}
    >
      <div className="flex items-start gap-2.5">
        <Icon className="mt-0.5 h-4 w-4 shrink-0 opacity-90" />
        <div className="text-xs leading-relaxed">
          <div className="font-semibold text-slate-100">{title}</div>
          <div className="text-slate-300">{description}</div>
        </div>
      </div>
      <span
        className={cn(
          "inline-flex w-fit shrink-0 items-center rounded-md border px-2.5 py-1 font-mono text-[11px] font-bold tracking-wide",
          tagStyles[variant]
        )}
      >
        {tag}
      </span>
    </div>
  );
}

export function EmptyState({
  title,
  description,
  hint,
  action,
}: {
  title: string;
  description: string;
  hint?: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="rounded-xl border border-dashed border-slate-700 bg-surface/70 p-6 text-left">
      <div className="text-sm font-semibold text-slate-100">{title}</div>
      <p className="mt-1 text-xs leading-relaxed text-slate-400">{description}</p>
      {hint ? (
        <p className="mt-2 text-xs font-medium text-sky-400">{hint}</p>
      ) : null}
      {action ? <div className="mt-3">{action}</div> : null}
    </div>
  );
}

export function ErrorBanner({
  message,
  onRetry,
}: {
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div
      role="alert"
      className="flex flex-col gap-3 rounded-xl border border-red-500/40 bg-red-950/40 px-4 py-3 text-xs text-red-200 sm:flex-row sm:items-center sm:justify-between"
    >
      <div className="flex items-start gap-2.5">
        <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-red-400" />
        <span className="leading-relaxed">{message}</span>
      </div>
      {onRetry ? (
        <button
          type="button"
          onClick={onRetry}
          className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-red-400/40 bg-red-900/50 px-3 py-1.5 font-medium text-red-100 hover:bg-red-800/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-400"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Thử lại
        </button>
      ) : null}
    </div>
  );
}

export function SuccessBanner({ message }: { message: string }) {
  return (
    <div className="flex items-start gap-2.5 rounded-xl border border-emerald-500/40 bg-emerald-950/35 px-4 py-3 text-xs text-emerald-200">
      <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />
      <span className="leading-relaxed">{message}</span>
    </div>
  );
}

export function LoadingRows({ count = 4 }: { count?: number }) {
  return (
    <div className="space-y-2.5" aria-busy="true" aria-label="Đang tải dữ liệu">
      {Array.from({ length: count }).map((_, idx) => (
        <div
          key={idx}
          className="h-10 w-full animate-pulse rounded-lg border border-slate-800 bg-slate-900/70"
        />
      ))}
    </div>
  );
}
