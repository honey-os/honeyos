'use client';

import React, { useEffect, useState, useCallback } from 'react';
import {
  Globe,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Eye,
  Plus,
  Trash2,
  RefreshCw,
  CheckCircle,
  XCircle,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Tag,
  Server,
  Clock,
} from 'lucide-react';
import { useStore } from '@/stores/useStore';
import {
  addDeclaredPort,
  removeDeclaredPort,
  syncDeclaredPorts,
  triggerPerimeterScan,
  getPerimeterScans,
  getBannerComparison,
} from '@/lib/api';
import type {
  DeclaredPort,
  PerimeterScan,
  BannerComparison,
} from '@/lib/api';
import { formatDate, formatRelativeTime } from '@/utils/formatters';
import clsx from 'clsx';

export default function NetworkPage() {
  const {
    perimeterStatus,
    perimeterStatusLoading,
    declaredPorts,
    declaredPortsLoading,
    censysSnapshot,
    censysLoading,
    fetchPerimeterStatus,
    fetchDeclaredPorts,
    fetchCensysSnapshot,
  } = useStore();

  // Port management
  const [newPort, setNewPort] = useState('');
  const [newLabel, setNewLabel] = useState('');
  const [addingPort, setAddingPort] = useState(false);
  const [syncing, setSyncing] = useState(false);

  // Scan state
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<PerimeterScan | null>(null);
  const [scanHistory, setScanHistory] = useState<PerimeterScan[]>([]);
  const [historyOpen, setHistoryOpen] = useState(false);

  // Exposure state
  const [banners, setBanners] = useState<BannerComparison[]>([]);
  const [expandedBanner, setExpandedBanner] = useState<number | null>(null);

  const loadInitialData = useCallback(() => {
    fetchPerimeterStatus();
    fetchDeclaredPorts();
    fetchCensysSnapshot();
    getBannerComparison()
      .then((data) => setBanners(data.items || []))
      .catch(() => {});
  }, [fetchPerimeterStatus, fetchDeclaredPorts, fetchCensysSnapshot]);

  useEffect(() => {
    loadInitialData();
  }, [loadInitialData]);

  // Load latest scan result and history
  useEffect(() => {
    getPerimeterScans({ page: 1, per_page: 11 })
      .then((data) => {
        if (data.items.length > 0) {
          setScanResult(data.items[0]);
          setScanHistory(data.items.slice(1));
        }
      })
      .catch(() => {});
  }, []);

  const handleAddPort = async (e: React.FormEvent) => {
    e.preventDefault();
    const portNum = parseInt(newPort, 10);
    if (!portNum || !newLabel.trim()) return;

    setAddingPort(true);
    try {
      await addDeclaredPort({ port: portNum, label: newLabel.trim() });
      setNewPort('');
      setNewLabel('');
      fetchDeclaredPorts();
      fetchPerimeterStatus();
    } catch {
      // handled by UI
    } finally {
      setAddingPort(false);
    }
  };

  const handleRemovePort = async (id: number) => {
    try {
      await removeDeclaredPort(id);
      fetchDeclaredPorts();
      fetchPerimeterStatus();
    } catch {
      // handled by UI
    }
  };

  const handleSync = async () => {
    setSyncing(true);
    try {
      await syncDeclaredPorts();
      fetchDeclaredPorts();
      fetchPerimeterStatus();
    } finally {
      setSyncing(false);
    }
  };

  const handleScan = async () => {
    setScanning(true);
    setScanError(null);
    try {
      const result = await triggerPerimeterScan();
      setScanResult(result);
      fetchPerimeterStatus();
      // Refresh exposure data (snapshot + banners) since the scan fetched fresh Censys data
      fetchCensysSnapshot();
      getBannerComparison()
        .then((data) => setBanners(data.items || []))
        .catch(() => {});
      // Refresh history
      const data = await getPerimeterScans({ page: 1, per_page: 11 });
      if (data.items.length > 1) {
        setScanHistory(data.items.slice(1));
      }
    } catch (err) {
      setScanError(err instanceof Error ? err.message : 'Scan failed');
    } finally {
      setScanning(false);
    }
  };

  const snapshot = censysSnapshot;
  const portsData = snapshot?.ports_data || [];
  const tags = snapshot?.tags || [];
  const vulns = snapshot?.vulns || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">Network</h1>
          <p className="text-sm text-gray-500 mt-1">
            Perimeter drift detection and external exposure monitoring
          </p>
        </div>
        <button
          onClick={handleScan}
          disabled={scanning}
          className="btn-primary flex items-center gap-1.5 text-sm disabled:opacity-50"
        >
          {scanning ? (
            <>
              <div className="w-3.5 h-3.5 border-2 border-gray-900/30 border-t-gray-900 rounded-full animate-spin" />
              Scanning...
            </>
          ) : (
            <>
              <RefreshCw className="w-3.5 h-3.5" />
              Check Now
            </>
          )}
        </button>
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Public IP */}
        <div className="card p-5">
          <div className="flex items-center gap-2 mb-2">
            <Globe className="w-4 h-4 text-amber-500" />
            <span className="text-xs font-medium text-gray-500 uppercase tracking-wider">Public IP</span>
          </div>
          {perimeterStatusLoading ? (
            <div className="h-8 bg-[#1c1c28] rounded animate-pulse" />
          ) : (
            <p className="text-xl font-mono text-amber-400">
              {perimeterStatus?.public_ip || 'Not detected'}
            </p>
          )}
        </div>

        {/* Declared Ports count */}
        <div className="card p-5">
          <div className="flex items-center gap-2 mb-2">
            <Server className="w-4 h-4 text-blue-400" />
            <span className="text-xs font-medium text-gray-500 uppercase tracking-wider">Declared Ports</span>
          </div>
          <p className="text-xl font-bold text-gray-100">
            {perimeterStatus?.declared_count ?? 0}
          </p>
        </div>

        {/* Drift Status */}
        <div className="card p-5">
          <div className="flex items-center gap-2 mb-2">
            <Shield className="w-4 h-4 text-gray-400" />
            <span className="text-xs font-medium text-gray-500 uppercase tracking-wider">Drift Status</span>
          </div>
          {perimeterStatus?.drift_detected ? (
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-red-400" />
              <span className="text-lg font-semibold text-red-400">Drift Detected</span>
              <span className="text-xs text-gray-500 ml-2">
                {perimeterStatus.unexpected_count > 0 && `${perimeterStatus.unexpected_count} unexpected`}
                {perimeterStatus.unexpected_count > 0 && perimeterStatus.missing_count > 0 && ', '}
                {perimeterStatus.missing_count > 0 && `${perimeterStatus.missing_count} missing`}
              </span>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-green-400" />
              <span className="text-lg font-semibold text-green-400">No Drift</span>
            </div>
          )}
        </div>
      </div>

      {/* Honeypot Fingerprint Alert */}
      {snapshot?.honeypot_flagged && (
        <div className="card p-5 border-red-500/30 bg-red-500/5">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-6 h-6 text-red-400 flex-shrink-0 mt-0.5" />
            <div>
              <h3 className="text-sm font-semibold text-red-400">
                Your honeypot has been fingerprinted
              </h3>
              <p className="text-sm text-gray-400 mt-1">
                Censys has tagged your IP with <code className="px-1 py-0.5 bg-red-500/10 rounded text-red-400 text-xs">honeypot</code>.
                Attackers using Censys will know this is a honeypot. Consider adjusting your service banners.
              </p>
              <div className="flex flex-wrap gap-1.5 mt-3">
                {tags.map((tag) => (
                  <span
                    key={tag}
                    className={clsx(
                      'px-2 py-0.5 rounded-md text-xs font-medium border',
                      tag === 'honeypot'
                        ? 'bg-red-500/10 text-red-400 border-red-500/20'
                        : 'bg-gray-500/10 text-gray-400 border-gray-500/20'
                    )}
                  >
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Drift Results */}
      <div className="card">
        <div className="px-5 py-4 border-b border-[#2a2a3a]">
          <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
            <Eye className="w-4 h-4 text-amber-500" />
            Drift Results
          </h3>
        </div>

        <div className="p-5">
          {scanError && (
            <div className="mb-4 p-3 rounded-lg bg-red-500/5 border border-red-500/20 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
              <p className="text-sm text-red-400">{scanError}</p>
            </div>
          )}
          {!scanResult ? (
            <div className="text-center py-8">
              <Shield className="w-12 h-12 text-gray-700 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-400 mb-2">No drift checks yet</h3>
              <p className="text-sm text-gray-600">
                Click Check Now to compare your declared ports against what is visible externally via Censys.
              </p>
            </div>
          ) : !scanResult.drift_detected ? (
            <div className="space-y-3">
              <div className="flex items-center gap-3 py-4">
                <CheckCircle className="w-6 h-6 text-green-400" />
                <div>
                  <p className="text-sm font-medium text-green-400">Perimeter matches declaration</p>
                  <p className="text-xs text-gray-500 mt-0.5">
                    Last checked {formatRelativeTime(scanResult.timestamp)}
                  </p>
                </div>
              </div>
              <CensysStatusBanner status={scanResult.censys_status} source={scanResult.scan_source} />
            </div>
          ) : (
            <div className="space-y-4">
              <div className="flex items-center gap-2 text-xs text-gray-500">
                <Clock className="w-3 h-3" />
                Last checked {formatRelativeTime(scanResult.timestamp)}
              </div>

              <CensysStatusBanner status={scanResult.censys_status} source={scanResult.scan_source} />

              {/* Unexpected ports */}
              {scanResult.unexpected_ports.length > 0 && (
                <div className="p-4 rounded-lg bg-red-500/5 border border-red-500/20">
                  <h4 className="text-xs font-medium text-red-400 uppercase tracking-wider mb-3">
                    Unexpected Ports ({scanResult.unexpected_ports.length})
                  </h4>
                  <p className="text-xs text-gray-500 mb-3">
                    Found externally but not declared — may indicate unauthorized services.
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {scanResult.unexpected_ports.map((p) => (
                      <span
                        key={p}
                        className="px-2.5 py-1 rounded-md text-sm font-mono bg-red-500/10 text-red-400 border border-red-500/20"
                      >
                        {p}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Missing ports */}
              {scanResult.missing_ports.length > 0 && (
                <div className="p-4 rounded-lg bg-amber-500/5 border border-amber-500/20">
                  <h4 className="text-xs font-medium text-amber-400 uppercase tracking-wider mb-3">
                    Missing Ports ({scanResult.missing_ports.length})
                  </h4>
                  <p className="text-xs text-gray-500 mb-3">
                    Declared but not found externally — may be closed or not forwarded.
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {scanResult.missing_ports.map((p) => (
                      <span
                        key={p}
                        className="px-2.5 py-1 rounded-md text-sm font-mono bg-amber-500/10 text-amber-400 border border-amber-500/20"
                      >
                        {p}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Host Overview — only shown when snapshot exists */}
      {snapshot && (
        <div className="card">
          <div className="px-5 py-4 border-b border-[#2a2a3a]">
            <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
              <Globe className="w-4 h-4 text-amber-500" />
              Host Overview
            </h3>
          </div>

          <div className="p-5">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div>
                <span className="text-xs text-gray-500">IP Address</span>
                <p className="text-sm font-mono text-amber-400 mt-0.5">{snapshot.ip}</p>
              </div>
              <div>
                <span className="text-xs text-gray-500">Organization</span>
                <p className="text-sm text-gray-200 mt-0.5">{snapshot.org || 'N/A'}</p>
              </div>
              <div>
                <span className="text-xs text-gray-500">ISP</span>
                <p className="text-sm text-gray-200 mt-0.5">{snapshot.isp || 'N/A'}</p>
              </div>
              <div>
                <span className="text-xs text-gray-500">OS</span>
                <p className="text-sm text-gray-200 mt-0.5">{snapshot.os_name || 'N/A'}</p>
              </div>
            </div>

            {(snapshot.hostnames?.length ?? 0) > 0 && (
              <div className="mt-4">
                <span className="text-xs text-gray-500">Hostnames</span>
                <div className="flex flex-wrap gap-1.5 mt-1">
                  {snapshot.hostnames.map((h) => (
                    <span key={h} className="px-2 py-0.5 rounded-md text-xs font-mono bg-[#1c1c28] text-gray-300 border border-[#2a2a3a]">
                      {h}
                    </span>
                  ))}
                </div>
              </div>
            )}

            <div className="mt-4 text-xs text-gray-600">
              Censys last updated: {snapshot.censys_updated || 'N/A'}
              <span className="mx-2">|</span>
              Fetched: {formatRelativeTime(snapshot.timestamp)}
            </div>
          </div>
        </div>
      )}

      {/* Open Ports from Censys */}
      {portsData.length > 0 && (
        <div className="card">
          <div className="px-5 py-4 border-b border-[#2a2a3a]">
            <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
              <Server className="w-4 h-4 text-amber-500" />
              Externally Visible Ports ({portsData.length})
            </h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-xs text-gray-500 uppercase tracking-wider border-b border-[#2a2a3a]">
                  <th className="text-left px-5 py-2.5 font-medium">Port</th>
                  <th className="text-left py-2.5 font-medium">Transport</th>
                  <th className="text-left py-2.5 font-medium">Service</th>
                  <th className="text-left py-2.5 font-medium">Product</th>
                  <th className="text-left py-2.5 font-medium">Version</th>
                  <th className="text-left py-2.5 pr-5 font-medium">Banner</th>
                </tr>
              </thead>
              <tbody>
                {portsData.map((p, idx) => (
                  <tr key={idx} className="border-b border-[#1c1c28] last:border-0 hover:bg-[#1c1c28]/50">
                    <td className="px-5 py-2.5 font-mono text-amber-400">{p.port}</td>
                    <td className="py-2.5 text-gray-400 uppercase text-xs">{p.transport}</td>
                    <td className="py-2.5 text-gray-300">{p.service || '-'}</td>
                    <td className="py-2.5 text-gray-300">{p.product || '-'}</td>
                    <td className="py-2.5 text-gray-400">{p.version || '-'}</td>
                    <td className="py-2.5 pr-5">
                      {p.banner ? (
                        <button
                          onClick={() => setExpandedBanner(expandedBanner === idx ? null : idx)}
                          className="text-xs text-gray-500 hover:text-gray-300 transition-colors font-mono truncate max-w-xs block"
                          title="Click to expand"
                        >
                          {expandedBanner === idx
                            ? p.banner
                            : p.banner.length > 60
                              ? p.banner.slice(0, 60) + '...'
                              : p.banner}
                        </button>
                      ) : (
                        <span className="text-xs text-gray-600">-</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Banner Comparison */}
      {banners.length > 0 && (
        <div className="card">
          <div className="px-5 py-4 border-b border-[#2a2a3a]">
            <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
              <Eye className="w-4 h-4 text-amber-500" />
              Banner Comparison
            </h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-xs text-gray-500 uppercase tracking-wider border-b border-[#2a2a3a]">
                  <th className="text-left px-5 py-2.5 font-medium">Port</th>
                  <th className="text-left py-2.5 font-medium">Protocol</th>
                  <th className="text-left py-2.5 font-medium">Configured Banner</th>
                  <th className="text-left py-2.5 font-medium">Censys Banner</th>
                  <th className="text-center py-2.5 pr-5 font-medium">Match</th>
                </tr>
              </thead>
              <tbody>
                {banners.map((b) => (
                  <tr key={b.port} className="border-b border-[#1c1c28] last:border-0">
                    <td className="px-5 py-2.5 font-mono text-amber-400">{b.port}</td>
                    <td className="py-2.5 text-gray-300 uppercase text-xs">{b.protocol}</td>
                    <td className="py-2.5 font-mono text-xs text-gray-400 max-w-xs truncate">
                      {b.configured_banner || <span className="text-gray-600 italic">not set</span>}
                    </td>
                    <td className="py-2.5 font-mono text-xs text-gray-400 max-w-xs truncate">
                      {b.censys_banner
                        ? b.censys_banner.length > 80
                          ? b.censys_banner.slice(0, 80) + '...'
                          : b.censys_banner
                        : <span className="text-gray-600 italic">not captured</span>}
                    </td>
                    <td className="py-2.5 pr-5 text-center">
                      {b.match ? (
                        <CheckCircle className="w-4 h-4 text-green-400 mx-auto" />
                      ) : (
                        <XCircle className="w-4 h-4 text-red-400 mx-auto" />
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tags + Vulns — only shown when snapshot has data */}
      {(tags.length > 0 || vulns.length > 0) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Tags */}
          <div className="card p-5">
            <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2 mb-3">
              <Tag className="w-4 h-4 text-amber-500" />
              Tags
            </h3>
            {tags.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {tags.map((tag) => (
                  <span
                    key={tag}
                    className={clsx(
                      'px-2 py-0.5 rounded-md text-xs font-medium border',
                      tag === 'honeypot'
                        ? 'bg-red-500/10 text-red-400 border-red-500/20'
                        : 'bg-[#1c1c28] text-gray-300 border-[#2a2a3a]'
                    )}
                  >
                    {tag}
                  </span>
                ))}
              </div>
            ) : (
              <p className="text-sm text-gray-600">No tags detected</p>
            )}
          </div>

          {/* Vulns */}
          <div className="card p-5">
            <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2 mb-3">
              <AlertTriangle className="w-4 h-4 text-amber-500" />
              Vulnerabilities
            </h3>
            {vulns.length > 0 ? (
              <div className="space-y-1">
                {vulns.map((v) => (
                  <div key={v} className="flex items-center gap-2">
                    <XCircle className="w-3 h-3 text-red-400 flex-shrink-0" />
                    <span className="text-sm font-mono text-gray-300">{v}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-gray-600">None detected</p>
            )}
          </div>
        </div>
      )}

      {/* Declared Ports */}
      <div className="card">
        <div className="px-5 py-4 border-b border-[#2a2a3a] flex items-center justify-between">
          <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
            <Server className="w-4 h-4 text-amber-500" />
            Declared Ports
          </h3>
          <button
            onClick={handleSync}
            disabled={syncing}
            className="btn-secondary flex items-center gap-1.5 text-xs"
          >
            <RefreshCw className={clsx('w-3.5 h-3.5', syncing && 'animate-spin')} />
            Sync from Honeypots
          </button>
        </div>

        <div className="p-5">
          {declaredPortsLoading && declaredPorts.length === 0 ? (
            <div className="text-center py-6">
              <div className="inline-block w-5 h-5 border-2 border-amber-500/30 border-t-amber-500 rounded-full animate-spin" />
            </div>
          ) : declaredPorts.length === 0 ? (
            <p className="text-sm text-gray-500 text-center py-4">
              No ports declared. Sync from honeypots or add manually below.
            </p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-xs text-gray-500 uppercase tracking-wider border-b border-[#2a2a3a]">
                  <th className="text-left pb-2 font-medium">Port</th>
                  <th className="text-left pb-2 font-medium">Transport</th>
                  <th className="text-left pb-2 font-medium">Label</th>
                  <th className="text-left pb-2 font-medium">Source</th>
                  <th className="text-right pb-2 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {declaredPorts.map((dp) => (
                  <tr key={dp.id} className="border-b border-[#1c1c28] last:border-0">
                    <td className="py-2.5 font-mono text-amber-400">{dp.port}</td>
                    <td className="py-2.5 text-gray-400 uppercase text-xs">{dp.transport}</td>
                    <td className="py-2.5 text-gray-200">{dp.label}</td>
                    <td className="py-2.5">
                      <span
                        className={clsx(
                          'px-2 py-0.5 rounded-md text-xs font-medium',
                          dp.source === 'honeypot'
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                            : 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                        )}
                      >
                        {dp.source}
                      </span>
                    </td>
                    <td className="py-2.5 text-right">
                      {dp.source === 'user' && (
                        <button
                          onClick={() => handleRemovePort(dp.id)}
                          className="text-gray-600 hover:text-red-400 transition-colors"
                          title="Remove"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {/* Add port form */}
          <form onSubmit={handleAddPort} className="flex items-end gap-3 mt-4 pt-4 border-t border-[#2a2a3a]">
            <div className="w-28">
              <label className="label-text">Port</label>
              <input
                type="number"
                value={newPort}
                onChange={(e) => setNewPort(e.target.value)}
                className="input-field w-full"
                placeholder="443"
                min="1"
                max="65535"
                required
              />
            </div>
            <div className="flex-1">
              <label className="label-text">Label</label>
              <input
                type="text"
                value={newLabel}
                onChange={(e) => setNewLabel(e.target.value)}
                className="input-field w-full"
                placeholder="HTTPS reverse proxy"
                required
              />
            </div>
            <button
              type="submit"
              disabled={addingPort}
              className="btn-primary flex items-center gap-1.5 text-sm disabled:opacity-50"
            >
              <Plus className="w-4 h-4" />
              Add
            </button>
          </form>
        </div>
      </div>

      {/* Scan history */}
      {scanHistory.length > 0 && (
        <div className="card">
          <div className="px-5 py-4">
            <button
              onClick={() => setHistoryOpen(!historyOpen)}
              className="flex items-center gap-2 text-sm text-gray-400 hover:text-gray-200 transition-colors w-full"
            >
              {historyOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              <span className="font-medium">Scan History ({scanHistory.length})</span>
            </button>
            {historyOpen && (
              <div className="mt-3 space-y-2">
                {scanHistory.map((s) => (
                  <div
                    key={s.id}
                    className="flex items-center justify-between px-3 py-2 rounded-md bg-[#0a0a0f] border border-[#2a2a3a] text-xs"
                  >
                    <div className="flex items-center gap-2">
                      {s.drift_detected ? (
                        <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
                      ) : (
                        <ShieldCheck className="w-3.5 h-3.5 text-green-400" />
                      )}
                      <span className="text-gray-400">{formatDate(s.timestamp)}</span>
                    </div>
                    <div className="flex items-center gap-3 text-gray-500">
                      {s.unexpected_ports.length > 0 && (
                        <span className="text-red-400">{s.unexpected_ports.length} unexpected</span>
                      )}
                      {s.missing_ports.length > 0 && (
                        <span className="text-amber-400">{s.missing_ports.length} missing</span>
                      )}
                      {!s.drift_detected && <span className="text-green-400">clean</span>}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Censys Status Banner
// ---------------------------------------------------------------------------

const CENSYS_STATUS_MESSAGES: Record<string, { color: string; message: string }> = {
  ok: { color: 'green', message: 'Censys data retrieved successfully.' },
  not_configured: { color: 'amber', message: 'CENSYS_API_TOKEN is not configured. Add it to your .env file to enable external lookups.' },
  no_data: { color: 'amber', message: 'Censys has no data for this IP address.' },
  auth_error: { color: 'red', message: 'Censys API token is invalid or lacks permissions. Check your CENSYS_API_TOKEN.' },
};

function CensysStatusBanner({ status, source }: { status?: string; source: string }) {
  const key = status || (source === 'censys' ? 'ok' : 'not_configured');
  const info = CENSYS_STATUS_MESSAGES[key];
  if (!info) return null;

  const colorMap: Record<string, string> = {
    green: 'bg-green-500/5 border-green-500/20 text-green-400',
    amber: 'bg-amber-500/5 border-amber-500/20 text-amber-400',
    red: 'bg-red-500/5 border-red-500/20 text-red-400',
  };

  return (
    <div className={`p-3 rounded-lg border flex items-start gap-2 ${colorMap[info.color]}`}>
      {info.color === 'green' ? (
        <CheckCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
      ) : info.color === 'red' ? (
        <XCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
      ) : (
        <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
      )}
      <p className="text-sm">{info.message}</p>
    </div>
  );
}
