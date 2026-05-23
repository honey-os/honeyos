'use client';

import React, { useEffect, useState, useCallback } from 'react';
import {
  Globe,
  Plus,
  Scan,
  AlertTriangle,
  CheckCircle,
  ChevronDown,
  ChevronUp,
  ChevronLeft,
  ChevronRight,
  Clock,
} from 'lucide-react';
import { useStore } from '@/stores/useStore';
import {
  createNetworkScan,
  getNetworkScanChanges,
} from '@/lib/api';
import type { NetworkScan } from '@/lib/api';
import { formatDate, formatRelativeTime } from '@/utils/formatters';
import clsx from 'clsx';

export default function NetworkPage() {
  const {
    networkScans,
    networkScansTotal,
    networkScansLoading,
    networkScansError,
    fetchNetworkScans,
  } = useStore();

  const [targetHost, setTargetHost] = useState('');
  const [scanType, setScanType] = useState('tcp');
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [expandedScan, setExpandedScan] = useState<string | null>(null);
  const [changes, setChanges] = useState<Record<string, {
    added_ports: number[];
    removed_ports: number[];
    unchanged_ports: number[];
  }>>({});
  const [page, setPage] = useState(1);

  const loadScans = useCallback(
    (p: number = 1) => {
      fetchNetworkScans({ page: p, per_page: 20 });
      setPage(p);
    },
    [fetchNetworkScans]
  );

  useEffect(() => {
    loadScans(1);
  }, [loadScans]);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetHost.trim()) return;

    setScanning(true);
    setScanError(null);
    try {
      await createNetworkScan({
        target_host: targetHost.trim(),
        scan_type: scanType,
      });
      setTargetHost('');
      await loadScans(1);
    } catch (err) {
      setScanError(
        err instanceof Error ? err.message : 'Scan failed'
      );
    } finally {
      setScanning(false);
    }
  };

  const handleExpandScan = async (scan: NetworkScan) => {
    const newId = expandedScan === scan.id ? null : scan.id;
    setExpandedScan(newId);

    if (newId && scan.changes_detected && !changes[scan.id]) {
      try {
        const data = await getNetworkScanChanges(scan.id);
        setChanges((prev) => ({ ...prev, [scan.id]: data }));
      } catch {
        // Silently fail, changes will just not be shown
      }
    }
  };

  const totalPages = Math.ceil(networkScansTotal / 20);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-100">Network</h1>
        <p className="text-sm text-gray-500 mt-1">
          Monitor your network perimeter and detect changes
        </p>
      </div>

      {/* Scan form */}
      <div className="card p-5">
        <h3 className="text-sm font-semibold text-gray-200 mb-4 flex items-center gap-2">
          <Scan className="w-4 h-4 text-amber-500" />
          New Scan
        </h3>
        <form onSubmit={handleScan} className="flex items-end gap-3">
          <div className="flex-1">
            <label className="label-text">Target Host</label>
            <input
              type="text"
              value={targetHost}
              onChange={(e) => setTargetHost(e.target.value)}
              className="input-field w-full"
              placeholder="192.168.1.1 or hostname"
              required
            />
          </div>
          <div className="w-40">
            <label className="label-text">Scan Type</label>
            <select
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
              className="select-field w-full"
            >
              <option value="tcp">TCP</option>
              <option value="syn">SYN</option>
              <option value="udp">UDP</option>
            </select>
          </div>
          <button
            type="submit"
            disabled={scanning}
            className="btn-primary flex items-center gap-2 text-sm disabled:opacity-50"
          >
            {scanning ? (
              <>
                <div className="w-4 h-4 border-2 border-gray-900/30 border-t-gray-900 rounded-full animate-spin" />
                Scanning...
              </>
            ) : (
              <>
                <Plus className="w-4 h-4" />
                Start Scan
              </>
            )}
          </button>
        </form>

        {scanError && (
          <div className="mt-3 text-sm text-red-400 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" />
            {scanError}
          </div>
        )}
      </div>

      {/* Error */}
      {networkScansError && (
        <div className="card p-4 border-red-500/30 bg-red-500/5 text-red-400 text-sm">
          {networkScansError}
        </div>
      )}

      {/* Scan results */}
      {networkScansLoading && networkScans.length === 0 ? (
        <div className="card p-12 text-center">
          <div className="inline-block w-6 h-6 border-2 border-amber-500/30 border-t-amber-500 rounded-full animate-spin" />
          <p className="mt-3 text-sm text-gray-500">Loading scans...</p>
        </div>
      ) : networkScans.length === 0 ? (
        <div className="card p-12 text-center">
          <Globe className="w-12 h-12 text-gray-700 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-400 mb-2">
            No scans recorded
          </h3>
          <p className="text-sm text-gray-600">
            Enter a target host above to perform your first network scan.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {networkScans.map((scan) => {
            const isExpanded = expandedScan === scan.id;
            const scanChanges = changes[scan.id];
            const ports = scan.discovered_ports || [];

            return (
              <div key={scan.id} className="card overflow-hidden">
                {/* Scan header */}
                <div
                  className="px-5 py-4 flex items-center justify-between cursor-pointer hover:bg-[#1c1c28] transition-colors"
                  onClick={() => handleExpandScan(scan)}
                >
                  <div className="flex items-center gap-4">
                    <div
                      className={clsx(
                        'w-10 h-10 rounded-lg flex items-center justify-center',
                        scan.changes_detected
                          ? 'bg-red-500/10 text-red-400'
                          : 'bg-green-500/10 text-green-400'
                      )}
                    >
                      {scan.changes_detected ? (
                        <AlertTriangle className="w-5 h-5" />
                      ) : (
                        <CheckCircle className="w-5 h-5" />
                      )}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm text-gray-200">
                          {scan.target_host}
                        </span>
                        <span className="px-2 py-0.5 rounded-md text-xs font-mono bg-[#1c1c28] text-gray-500 border border-[#2a2a3a] uppercase">
                          {scan.scan_type}
                        </span>
                        {scan.changes_detected && (
                          <span className="px-2 py-0.5 rounded-md text-xs bg-red-500/10 text-red-400 border border-red-500/20">
                            Changes Detected
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-4 mt-1 text-xs text-gray-500">
                        <span className="flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          {formatRelativeTime(scan.timestamp)}
                        </span>
                        <span>{ports.length} ports discovered</span>
                        {scan.scan_duration_ms && (
                          <span>{scan.scan_duration_ms}ms</span>
                        )}
                      </div>
                    </div>
                  </div>
                  {isExpanded ? (
                    <ChevronUp className="w-5 h-5 text-gray-600" />
                  ) : (
                    <ChevronDown className="w-5 h-5 text-gray-600" />
                  )}
                </div>

                {/* Expanded details */}
                {isExpanded && (
                  <div className="border-t border-[#2a2a3a] p-5 bg-[#111118]">
                    {/* Discovered ports */}
                    {ports.length > 0 ? (
                      <div className="mb-4">
                        <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-3">
                          Discovered Ports
                        </h4>
                        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
                          {ports.map((portInfo, idx) => (
                            <div
                              key={idx}
                              className="flex items-center justify-between px-3 py-2 rounded-md bg-[#0a0a0f] border border-[#2a2a3a]"
                            >
                              <span className="font-mono text-sm text-amber-400">
                                {portInfo.port}
                              </span>
                              <span className="text-xs text-gray-500">
                                {portInfo.service || 'unknown'}
                              </span>
                              <span
                                className={clsx(
                                  'w-2 h-2 rounded-full',
                                  portInfo.state === 'open'
                                    ? 'bg-green-500'
                                    : 'bg-gray-600'
                                )}
                              />
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : (
                      <p className="text-sm text-gray-600 mb-4">
                        No open ports discovered
                      </p>
                    )}

                    {/* Changes */}
                    {scan.changes_detected && scanChanges && (
                      <div>
                        <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-3">
                          Changes from Previous Scan
                        </h4>
                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                          {scanChanges.added_ports.length > 0 && (
                            <div className="p-3 rounded-md bg-red-500/5 border border-red-500/20">
                              <span className="text-xs font-medium text-red-400 uppercase">
                                New Ports
                              </span>
                              <div className="mt-2 flex flex-wrap gap-1">
                                {scanChanges.added_ports.map((p) => (
                                  <span
                                    key={p}
                                    className="px-2 py-0.5 rounded text-xs font-mono bg-red-500/10 text-red-400"
                                  >
                                    {p}
                                  </span>
                                ))}
                              </div>
                            </div>
                          )}
                          {scanChanges.removed_ports.length > 0 && (
                            <div className="p-3 rounded-md bg-green-500/5 border border-green-500/20">
                              <span className="text-xs font-medium text-green-400 uppercase">
                                Closed Ports
                              </span>
                              <div className="mt-2 flex flex-wrap gap-1">
                                {scanChanges.removed_ports.map((p) => (
                                  <span
                                    key={p}
                                    className="px-2 py-0.5 rounded text-xs font-mono bg-green-500/10 text-green-400"
                                  >
                                    {p}
                                  </span>
                                ))}
                              </div>
                            </div>
                          )}
                          {scanChanges.unchanged_ports.length > 0 && (
                            <div className="p-3 rounded-md bg-gray-500/5 border border-gray-500/20">
                              <span className="text-xs font-medium text-gray-400 uppercase">
                                Unchanged ({scanChanges.unchanged_ports.length})
                              </span>
                              <div className="mt-2 flex flex-wrap gap-1">
                                {scanChanges.unchanged_ports.slice(0, 10).map((p) => (
                                  <span
                                    key={p}
                                    className="px-2 py-0.5 rounded text-xs font-mono bg-gray-500/10 text-gray-500"
                                  >
                                    {p}
                                  </span>
                                ))}
                                {scanChanges.unchanged_ports.length > 10 && (
                                  <span className="text-xs text-gray-600">
                                    +{scanChanges.unchanged_ports.length - 10} more
                                  </span>
                                )}
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    <div className="mt-4 text-xs text-gray-600 font-mono">
                      Scan ID: {scan.id}
                      {scan.previous_scan_id && (
                        <span className="ml-4">
                          Previous: {scan.previous_scan_id}
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-gray-500">
            Page {page} of {totalPages} ({networkScansTotal} total)
          </p>
          <div className="flex items-center gap-2">
            <button
              onClick={() => loadScans(page - 1)}
              disabled={page <= 1}
              className="btn-secondary flex items-center gap-1 text-sm disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <ChevronLeft className="w-4 h-4" />
              Previous
            </button>
            <button
              onClick={() => loadScans(page + 1)}
              disabled={page >= totalPages}
              className="btn-secondary flex items-center gap-1 text-sm disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Next
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
