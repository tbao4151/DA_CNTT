"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  ChevronLeft,
  ChevronRight,
  Database,
  FileSearch,
  FlaskConical,
  Menu,
  RefreshCw,
  Shield,
  ShieldAlert,
  X,
} from "lucide-react";
import { api } from "@/lib/api";
import type { SystemStatus } from "@/lib/types";
import { cn } from "@/lib/utils";

interface NavItem {
  href: string;
  label: string;
  subtitle: string;
  group: "blue" | "red";
  icon: React.ComponentType<{ className?: string }>;
}

const NAV_ITEMS: NavItem[] = [
  {
    href: "/",
    label: "Dataset SOC",
    subtitle: "UNSW-NB15 & Triage",
    group: "blue",
    icon: Database,
  },
  {
    href: "/cyber-lab",
    label: "Cyber Lab · Zeek",
    subtitle: "Offline conn.log Explorer",
    group: "blue",
    icon: Activity,
  },
  {
    href: "/new-log-review",
    label: "New Log Review",
    subtitle: "Pinned SHA-256 AI Review",
    group: "blue",
    icon: FileSearch,
  },
  {
    href: "/red-team-lab",
    label: "Red Team Lab",
    subtitle: "EXECUTION OFF · Planner",
    group: "red",
    icon: FlaskConical,
  },
  {
    href: "/automated-lab",
    label: "Dual-AI Live Monitor",
    subtitle: "SYNTHETIC REPLAY · SSE",
    group: "red",
    icon: Activity,
  },
];

export function AppShell({
  title,
  breadcrumb,
  provenanceTag,
  actions,
  children,
}: {
  title: string;
  breadcrumb: string;
  provenanceTag: string;
  actions?: React.ReactNode;
  children: React.ReactNode;
}) {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [apiError, setApiError] = useState<string | null>(null);
  const [checking, setChecking] = useState(true);

  const loadStatus = async () => {
    setChecking(true);
    try {
      const data = await api.getSystemStatus();
      setStatus(data);
      setApiError(null);
    } catch (err) {
      setStatus(null);
      setApiError(err instanceof Error ? err.message : "Mất kết nối Backend API");
    } finally {
      setChecking(false);
    }
  };

  useEffect(() => {
    void loadStatus();
  }, []);

  const renderSidebarContent = (isMobile = false) => (
    <div className="flex h-full flex-col justify-between">
      <div>
        <div className="flex items-center justify-between border-b border-slate-800 px-3.5 py-4">
          <Link href="/" className="flex items-center gap-2.5 overflow-hidden">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-blue-600 text-white shadow-sm">
              <Shield className="h-4 w-4" />
            </div>
            {(!collapsed || isMobile) && (
              <div className="min-w-0">
                <div className="truncate text-sm font-bold tracking-wide text-slate-100">
                  SENTINEL LAB
                </div>
                <div className="truncate font-mono text-[10px] text-slate-400">
                  DA005 · TDTU CONSOLE
                </div>
              </div>
            )}
          </Link>
          {!isMobile ? (
            <button
              type="button"
              onClick={() => setCollapsed((v) => !v)}
              aria-label={collapsed ? "Mở rộng thanh điều hướng" : "Thu gọn thanh điều hướng"}
              className="rounded-md p-1 text-slate-400 hover:bg-slate-800 hover:text-slate-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
            >
              {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
            </button>
          ) : (
            <button
              type="button"
              onClick={() => setMobileOpen(false)}
              aria-label="Đóng menu"
              className="rounded-md p-1 text-slate-400 hover:bg-slate-800 hover:text-slate-100"
            >
              <X className="h-5 w-5" />
            </button>
          )}
        </div>

        <nav aria-label="Điều hướng phân hệ" className="space-y-5 px-2.5 py-4">
          <div>
            {(!collapsed || isMobile) && (
              <div className="px-2 pb-1.5 font-mono text-[10px] font-semibold uppercase tracking-widest text-slate-500">
                Blue Team · Detection
              </div>
            )}
            <div className="space-y-1">
              {NAV_ITEMS.filter((i) => i.group === "blue").map((item) => {
                const active = pathname === item.href;
                const Icon = item.icon;
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    onClick={() => setMobileOpen(false)}
                    title={item.label}
                    className={cn(
                      "flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-xs transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500",
                      active
                        ? "bg-blue-600/20 text-blue-200 ring-1 ring-inset ring-blue-500/40"
                        : "text-slate-300 hover:bg-slate-800/70 hover:text-white"
                    )}
                  >
                    <Icon className={cn("h-4 w-4 shrink-0", active ? "text-blue-400" : "text-slate-400")} />
                    {(!collapsed || isMobile) && (
                      <div className="min-w-0">
                        <div className="truncate font-semibold">{item.label}</div>
                        <div className="truncate text-[11px] text-slate-400">{item.subtitle}</div>
                      </div>
                    )}
                  </Link>
                );
              })}
            </div>
          </div>

          <div>
            {(!collapsed || isMobile) && (
              <div className="px-2 pb-1.5 font-mono text-[10px] font-semibold uppercase tracking-widest text-red-400/80">
                Red Team · Simulation
              </div>
            )}
            <div className="space-y-1">
              {NAV_ITEMS.filter((i) => i.group === "red").map((item) => {
                const active = pathname === item.href;
                const Icon = item.icon;
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    onClick={() => setMobileOpen(false)}
                    title={item.label}
                    className={cn(
                      "flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-xs transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500",
                      active
                        ? "bg-red-950/70 text-red-200 ring-1 ring-inset ring-red-500/50"
                        : "text-slate-300 hover:bg-slate-800/70 hover:text-white"
                    )}
                  >
                    <Icon className={cn("h-4 w-4 shrink-0", active ? "text-red-400" : "text-red-400/70")} />
                    {(!collapsed || isMobile) && (
                      <div className="min-w-0">
                        <div className="truncate font-semibold">{item.label}</div>
                        <div className="truncate font-mono text-[10px] text-red-300/80">
                          {item.subtitle}
                        </div>
                      </div>
                    )}
                  </Link>
                );
              })}
            </div>
          </div>
        </nav>
      </div>

      {/* Live system status footer inside sidebar */}
      <div className="border-t border-slate-800 p-3">
        {(!collapsed || isMobile) ? (
          <div className="space-y-2 rounded-lg border border-slate-800 bg-canvas/80 p-2.5 text-[11px]">
            <div className="flex items-center justify-between">
              <span className="font-medium text-slate-400">FastAPI Backend</span>
              <button
                type="button"
                onClick={() => void loadStatus()}
                title="Kiểm tra lại kết nối"
                className="rounded p-0.5 text-slate-400 hover:text-slate-100"
              >
                <RefreshCw className={cn("h-3 w-3", checking && "animate-spin")} />
              </button>
            </div>
            {apiError ? (
              <div className="flex items-center gap-1.5 font-mono text-red-300">
                <span className="h-2 w-2 rounded-full bg-red-500" />
                DISCONNECTED
              </div>
            ) : status ? (
              <div className="space-y-1 font-mono text-[10px]">
                <div className="flex items-center gap-1.5 text-emerald-300">
                  <span className="h-2 w-2 rounded-full bg-emerald-400" />
                  API CONNECTED (:8000)
                </div>
                <div className="text-slate-300">
                  AI Model:{" "}
                  {status.model.trained_local_artifact_available ? (
                    <span className="text-emerald-300">READY</span>
                  ) : (
                    <span className="text-amber-300">EXPLORATION ONLY</span>
                  )}
                </div>
                <div className="text-slate-400">Live Capture: OFF</div>
                <div className="text-red-300/90">Red Execution: OFF</div>
              </div>
            ) : (
              <div className="font-mono text-[10px] text-slate-400">CHECKING...</div>
            )}
          </div>
        ) : (
          <div className="flex justify-center">
            <span
              title={apiError ? "Backend Disconnected" : "Backend Connected"}
              className={cn(
                "h-2.5 w-2.5 rounded-full",
                apiError ? "bg-red-500" : status ? "bg-emerald-400" : "bg-amber-400"
              )}
            />
          </div>
        )}
      </div>
    </div>
  );

  return (
    <div className="flex min-h-screen bg-canvas text-slate-100">
      {/* Desktop Sidebar */}
      <aside
        className={cn(
          "hidden shrink-0 border-r border-slate-800 bg-surface transition-[width] duration-150 lg:block",
          collapsed ? "w-16" : "w-64"
        )}
      >
        <div className="sticky top-0 h-screen">{renderSidebarContent(false)}</div>
      </aside>

      {/* Mobile Drawer */}
      {mobileOpen && (
        <div className="fixed inset-0 z-50 flex lg:hidden">
          <div
            className="fixed inset-0 bg-black/70"
            onClick={() => setMobileOpen(false)}
            aria-hidden="true"
          />
          <aside className="relative z-10 w-64 border-r border-slate-800 bg-surface">
            {renderSidebarContent(true)}
          </aside>
        </div>
      )}

      {/* Main Content */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 border-b border-slate-800 bg-canvas/95 backdrop-blur">
          <div className="mx-auto flex max-w-[1480px] flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6">
            <div className="flex min-w-0 items-center gap-3">
              <button
                type="button"
                onClick={() => setMobileOpen(true)}
                aria-label="Mở menu điều hướng"
                className="rounded-lg border border-slate-700 bg-surface p-1.5 text-slate-300 hover:bg-slate-800 lg:hidden"
              >
                <Menu className="h-4 w-4" />
              </button>
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] text-slate-400">
                  <span>{breadcrumb}</span>
                  <span>/</span>
                  <span className="rounded border border-slate-700 bg-surface px-1.5 py-0.5 text-[10px] text-slate-300">
                    {provenanceTag}
                  </span>
                </div>
                <h1 className="truncate text-base font-bold tracking-tight text-slate-100 sm:text-lg">
                  {title}
                </h1>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {actions}
              {status && !status.model.trained_local_artifact_available && (
                <span className="inline-flex items-center gap-1.5 rounded-md border border-amber-500/40 bg-amber-950/40 px-2.5 py-1 font-mono text-[11px] text-amber-200">
                  <ShieldAlert className="h-3.5 w-3.5" />
                  Chưa có model cục bộ
                </span>
              )}
            </div>
          </div>
        </header>

        <main className="mx-auto w-full max-w-[1480px] flex-1 space-y-4 px-4 py-5 sm:px-6">
          {apiError && (
            <div className="rounded-xl border border-red-500/50 bg-red-950/50 px-4 py-3 text-xs text-red-200">
              <strong>Backend API không khả dụng:</strong> {apiError} Hãy chạy{" "}
              <code className="rounded bg-black/40 px-1.5 py-0.5 font-mono">
                .\start_backend.ps1
              </code>{" "}
              hoặc kiểm tra tiến trình Uvicorn cổng 8000.
            </div>
          )}
          {children}
        </main>

        <footer className="border-t border-slate-800/80 bg-surface/40 px-4 py-3 text-xs text-slate-500 sm:px-6">
          <div className="mx-auto flex max-w-[1480px] flex-col justify-between gap-1 sm:flex-row sm:items-center">
            <span>
              DA005 · Ứng dụng AI trong phân tích nhật ký hệ thống và phát hiện tấn công — Tôn Đức Thắng University
            </span>
            <span className="font-mono text-[11px]">
              Phân tích ngoại tuyến · Không thay thế SIEM sản xuất
            </span>
          </div>
        </footer>
      </div>
    </div>
  );
}
