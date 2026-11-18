"use client";

import React, { useMemo } from "react";
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  useReactTable,
} from "@tanstack/react-table";
import { ArrowDownUp, Download, FilterX, Search } from "lucide-react";
import { EmptyState, LoadingRows, Panel, PriorityBadge } from "@/components/ui";
import type { DatasetHuntingResponse, FlowRow } from "@/lib/types";
import { formatNumber, formatPercent } from "@/lib/utils";

const columnHelper = createColumnHelper<FlowRow>();

export interface HuntingFilters {
  protocols: string[];
  services: string[];
  states: string[];
  onlyAiAttacks: boolean;
  minProbEnabled: boolean;
  minProb: number;
  search: string;
  sortBy: string;
  sortDir: "asc" | "desc";
  page: number;
  pageSize: number;
}

export function HuntingTab({
  data,
  loading,
  filterOptions,
  filters,
  predictionsAvailable,
  onChangeFilters,
  onResetFilters,
  onExportCsv,
  onInspectRow,
}: {
  data: DatasetHuntingResponse | null;
  loading: boolean;
  filterOptions: { protocols: string[]; services: string[]; states: string[] };
  filters: HuntingFilters;
  predictionsAvailable: boolean;
  onChangeFilters: (next: Partial<HuntingFilters>) => void;
  onResetFilters: () => void;
  onExportCsv: () => void;
  onInspectRow: (row: FlowRow) => void;
}) {
  const toggleSort = (field: string) => {
    if (filters.sortBy === field) {
      onChangeFilters({
        sortDir: filters.sortDir === "asc" ? "desc" : "asc",
        page: 1,
      });
    } else {
      onChangeFilters({ sortBy: field, sortDir: "desc", page: 1 });
    }
  };

  const columns = useMemo(
    () => [
      columnHelper.accessor("flow_ref", {
        header: "Flow Ref",
        cell: (info) => (
          <span className="font-mono font-semibold text-sky-300">{info.getValue()}</span>
        ),
      }),
      columnHelper.accessor("proto", {
        header: "Proto",
        cell: (info) => <span className="font-mono text-slate-200">{info.getValue() ?? "—"}</span>,
      }),
      columnHelper.accessor("service", {
        header: "Service",
        cell: (info) => <span className="font-mono text-slate-300">{info.getValue() ?? "—"}</span>,
      }),
      columnHelper.accessor("state", {
        header: "State",
        cell: (info) => <span className="font-mono text-slate-300">{info.getValue() ?? "—"}</span>,
      }),
      columnHelper.accessor("dur", {
        header: "Dur (s)",
        cell: (info) => {
          const val = info.getValue();
          return <span className="font-mono tabular-nums text-slate-300">{val !== null ? val.toFixed(3) : "—"}</span>;
        },
      }),
      columnHelper.accessor("sbytes", {
        header: "Src Bytes",
        cell: (info) => (
          <span className="font-mono tabular-nums text-slate-200">{formatNumber(info.getValue())}</span>
        ),
      }),
      columnHelper.accessor("dbytes", {
        header: "Dst Bytes",
        cell: (info) => (
          <span className="font-mono tabular-nums text-slate-200">{formatNumber(info.getValue())}</span>
        ),
      }),
      columnHelper.accessor("AI_attack_probability", {
        header: "AI P(Attack)",
        cell: (info) => (
          <span className="font-mono tabular-nums text-slate-100">
            {formatPercent(info.getValue(), 1)}
          </span>
        ),
      }),
      columnHelper.accessor("priority_band", {
        header: "Mức ưu tiên",
        cell: (info) => {
          const b = info.getValue();
          return <PriorityBadge code={b.code} label={b.label} />;
        },
      }),
      columnHelper.accessor("attack_cat", {
        header: "Nhãn gốc",
        cell: (info) => (
          <span className="font-mono text-xs text-slate-400">{info.getValue() ?? "—"}</span>
        ),
      }),
    ],
    []
  );

  const table = useReactTable({
    data: data?.rows ?? [],
    columns,
    getCoreRowModel: getCoreRowModel(),
  });

  const activeFilterCount =
    filters.protocols.length +
    filters.services.length +
    filters.states.length +
    (filters.onlyAiAttacks ? 1 : 0) +
    (filters.minProbEnabled ? 1 : 0) +
    (filters.search.trim() ? 1 : 0);

  return (
    <div className="space-y-4">
      <Panel>
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">
              Threat hunting · Lọc đa chiều trên mẫu đang tải
            </h2>
            <p className="text-xs text-slate-400">
              Chọn trong cùng một nhóm là OR; kết hợp giữa các nhóm là AND. Bộ lọc không thay đổi kết quả dự đoán AI.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {activeFilterCount > 0 && (
              <button
                type="button"
                onClick={onResetFilters}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-subtle px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-800"
              >
                <FilterX className="h-3.5 w-3.5" />
                Xóa bộ lọc ({activeFilterCount})
              </button>
            )}
            <button
              type="button"
              onClick={onExportCsv}
              className="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/40 bg-blue-600/20 px-3 py-1.5 text-xs font-semibold text-blue-200 hover:bg-blue-600/30"
            >
              <Download className="h-3.5 w-3.5" />
              Xuất CSV an toàn
            </button>
          </div>
        </div>

        {/* Filter Controls */}
        <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
          <div>
            <label className="mb-1 block text-xs font-medium text-slate-300" htmlFor="hunt-search">
              Tìm kiếm (Flow Ref / Proto / Service)
            </label>
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-500" />
              <input
                id="hunt-search"
                type="text"
                value={filters.search}
                onChange={(e) => onChangeFilters({ search: e.target.value, page: 1 })}
                placeholder="VD: tcp, dns, 8f3a..."
                className="w-full rounded-lg border border-slate-700 bg-canvas py-1.5 pl-8 pr-3 text-xs text-slate-100 placeholder:text-slate-500 focus:border-blue-500 focus:outline-none"
              />
            </div>
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-slate-300" htmlFor="hunt-proto">
              Giao thức (proto)
            </label>
            <select
              id="hunt-proto"
              value={filters.protocols[0] ?? ""}
              onChange={(e) =>
                onChangeFilters({
                  protocols: e.target.value ? [e.target.value] : [],
                  page: 1,
                })
              }
              className="w-full rounded-lg border border-slate-700 bg-canvas px-2.5 py-1.5 text-xs text-slate-100 focus:border-blue-500 focus:outline-none"
            >
              <option value="">Tất cả ({filterOptions.protocols.length})</option>
              {filterOptions.protocols.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-slate-300" htmlFor="hunt-service">
              Dịch vụ (service)
            </label>
            <select
              id="hunt-service"
              value={filters.services[0] ?? ""}
              onChange={(e) =>
                onChangeFilters({
                  services: e.target.value ? [e.target.value] : [],
                  page: 1,
                })
              }
              className="w-full rounded-lg border border-slate-700 bg-canvas px-2.5 py-1.5 text-xs text-slate-100 focus:border-blue-500 focus:outline-none"
            >
              <option value="">Tất cả ({filterOptions.services.length})</option>
              {filterOptions.services.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-slate-300" htmlFor="hunt-state">
              Trạng thái kết nối (state)
            </label>
            <select
              id="hunt-state"
              value={filters.states[0] ?? ""}
              onChange={(e) =>
                onChangeFilters({
                  states: e.target.value ? [e.target.value] : [],
                  page: 1,
                })
              }
              className="w-full rounded-lg border border-slate-700 bg-canvas px-2.5 py-1.5 text-xs text-slate-100 focus:border-blue-500 focus:outline-none"
            >
              <option value="">Tất cả ({filterOptions.states.length})</option>
              {filterOptions.states.map((st) => (
                <option key={st} value={st}>
                  {st}
                </option>
              ))}
            </select>
          </div>
        </div>

        {predictionsAvailable && (
          <div className="mt-3 flex flex-wrap items-center gap-4 border-t border-slate-800 pt-3 text-xs">
            <label className="flex cursor-pointer items-center gap-2 text-slate-200">
              <input
                type="checkbox"
                checked={filters.onlyAiAttacks}
                onChange={(e) =>
                  onChangeFilters({ onlyAiAttacks: e.target.checked, page: 1 })
                }
                className="h-3.5 w-3.5 rounded border-slate-600 bg-canvas text-blue-500"
              />
              Chỉ các flow AI dự đoán Attack
            </label>
            <label className="flex cursor-pointer items-center gap-2 text-slate-200">
              <input
                type="checkbox"
                checked={filters.minProbEnabled}
                onChange={(e) =>
                  onChangeFilters({ minProbEnabled: e.target.checked, page: 1 })
                }
                className="h-3.5 w-3.5 rounded border-slate-600 bg-canvas text-blue-500"
              />
              Lọc theo xác suất tối thiểu
            </label>
            {filters.minProbEnabled && (
              <div className="flex items-center gap-2">
                <input
                  type="range"
                  min={0.5}
                  max={0.99}
                  step={0.05}
                  value={filters.minProb}
                  onChange={(e) =>
                    onChangeFilters({ minProb: Number(e.target.value), page: 1 })
                  }
                  aria-label="Xác suất Attack tối thiểu"
                  className="accent-blue-500"
                />
                <span className="font-mono text-sky-300 tabular-nums">
                  &ge; {(filters.minProb * 100).toFixed(0)}%
                </span>
              </div>
            )}
          </div>
        )}
      </Panel>

      {/* Table */}
      <Panel>
        {loading && !data ? (
          <LoadingRows count={6} />
        ) : !data || data.rows.length === 0 ? (
          <EmptyState
            title="Không có flow nào khớp điều kiện lọc"
            description="Kết quả 0 dòng chỉ phản ánh phạm vi bộ lọc trên mẫu dữ liệu đang tải, KHÔNG đồng nghĩa mạng an toàn."
            hint="Hãy xóa bớt bộ lọc hoặc tăng số dòng mẫu đọc."
          />
        ) : (
          <>
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400">
              <span className="font-mono tabular-nums">
                Hiển thị {formatNumber(data.rows.length)} trên {formatNumber(data.total_filtered)} flow khớp (tổng mẫu {formatNumber(data.total_loaded)}). Nhấp vào một dòng để mở ngăn kiểm tra chi tiết.
              </span>
              <div className="flex items-center gap-2">
                <span>Sắp xếp theo:</span>
                {[
                  { key: "row_index", label: "Thứ tự" },
                  ...(predictionsAvailable
                    ? [{ key: "AI_attack_probability", label: "P(Attack)" }]
                    : []),
                  { key: "sbytes", label: "Src Bytes" },
                  { key: "dur", label: "Duration" },
                ].map((opt) => (
                  <button
                    key={opt.key}
                    type="button"
                    onClick={() => toggleSort(opt.key)}
                    className={`inline-flex items-center gap-1 rounded border px-2 py-1 font-mono text-[11px] ${
                      filters.sortBy === opt.key
                        ? "border-blue-500/50 bg-blue-950/50 text-blue-200"
                        : "border-slate-700 bg-subtle text-slate-300 hover:bg-slate-800"
                    }`}
                  >
                    <ArrowDownUp className="h-3 w-3" />
                    {opt.label}
                    {filters.sortBy === opt.key ? (filters.sortDir === "asc" ? "↑" : "↓") : ""}
                  </button>
                ))}
              </div>
            </div>

            <div className="overflow-x-auto rounded-lg border border-slate-800">
              <table className="w-full min-w-[820px] border-collapse text-left text-xs">
                <thead className="bg-subtle">
                  {table.getHeaderGroups().map((hg) => (
                    <tr key={hg.id} className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-400">
                      {hg.headers.map((header) => (
                        <th key={header.id} className="px-3 py-2.5 font-semibold">
                          {header.isPlaceholder
                            ? null
                            : flexRender(header.column.columnDef.header, header.getContext())}
                        </th>
                      ))}
                    </tr>
                  ))}
                </thead>
                <tbody className="divide-y divide-slate-800/80">
                  {table.getRowModel().rows.map((row) => (
                    <tr
                      key={row.id}
                      onClick={() => onInspectRow(row.original)}
                      className="cursor-pointer transition-colors hover:bg-slate-800/50"
                    >
                      {row.getVisibleCells().map((cell) => (
                        <td key={cell.id} className="px-3 py-2">
                          {flexRender(cell.column.columnDef.cell, cell.getContext())}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400">
              <span className="font-mono tabular-nums">
                Trang {data.page} / {data.total_pages}
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={data.page <= 1}
                  onClick={() => onChangeFilters({ page: data.page - 1 })}
                  className="rounded-lg border border-slate-700 bg-subtle px-3 py-1 text-slate-200 hover:bg-slate-800 disabled:opacity-40"
                >
                  Trang trước
                </button>
                <button
                  type="button"
                  disabled={data.page >= data.total_pages}
                  onClick={() => onChangeFilters({ page: data.page + 1 })}
                  className="rounded-lg border border-slate-700 bg-subtle px-3 py-1 text-slate-200 hover:bg-slate-800 disabled:opacity-40"
                >
                  Trang sau
                </button>
              </div>
            </div>
          </>
        )}
      </Panel>
    </div>
  );
}
