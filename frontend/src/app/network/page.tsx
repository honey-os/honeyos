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
  ExternalLink,
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
  refreshShodan,
  getBannerComparison,
} from '@/lib/api';
import type {
  DeclaredPort,
  PerimeterScan,
  ShodanSnapshot,
  BannerComparison,
} from '@/lib/api';
import { formatDate, formatRelativeTime } from '@/utils/formatters';
import clsx from 'clsx';

type Tab = 'drift' | 'exposure';

export default function NetworkPage() {
  const {
    perimeterStatus,
    perimeterStatusLoading,
    declaredPorts,
    declaredPortsLoading,
    shodanSnapshot,
    shodanLoading,
    fetchPerimeterStatus,
    fetchDeclaredPorts,
    fetchShodanSnapshot,
  } = useStore();

  const [activeTab, setActiveTab] = useState<Tab>('drift');

  // Drift tab state
  const [newPort, setNewPort] = useState('');
  const [newLabel, setNewLabel] = useState('');
  const [addingPort, setAddingPort] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<PerimeterScan | null>(null);
  const [scanHistory, setScanHistory] = useState<PerimeterScan[]>([]);
  const [historyOpen, setHistoryOpen] = useState(false);

  // Exposure tab state
  const [refreshing, setRefreshing] = useState(false);
  const [banners, setBanners] = useState<BannerComparison[]>([]);
  const [expandedBanner, setExpandedBanner] = useState<number | null>(null);

  const loadInitialData = useCallback(() => {
    fetchPerimeterStatus();
    fetchDeclaredPorts();
    fetchShodanSnapshot();
  }, [fetchPerimeterStatus, fetchDeclaredPorts, fetchShodanSnapshot]);

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

  // Load banners when exposure tab is active
  useEffect(() => {
    if (activeTab === 'exposure' && perimeterStatus?.shodan_configured) {
      getBannerComparison()
        .then((data) => setBanners(data.items || []))
        .catch(() => {});
    }
  }, [activeTab, perimeterStatus?.shodan_configured]);

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
    try {
      const result = await triggerPerimeterScan();
      setScanResult(result);
      fetchPerimeterStatus();
      // Refresh history
      const data = await getPerimeterScans({ page: 1, per_page: 11 });
      if (data.items.length > 1) {
        setScanHistory(data.items.slice(1));
      }
    } catch {
      // handled by UI
    } finally {
      setScanning(false);
    }
  };

  const handleRefreshShodan = async () => {
    setRefreshing(true);
    try {
      await refreshShodan();
      fetchShodanSnapshot();
      fetchPerimeterStatus();
      const data = await getBannerComparison();
      setBanners(data.items || []);
    } catch {
      // handled by UI
    } finally {
      setRefreshing(false);
    }
  };

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
        <div className="flex items-center gap-2 text-sm">
          {(['drift', 'exposure'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={
                activeTab === tab
                  ? 'px-3 py-1 rounded-md bg-amber-500/20 text-amber-400 border border-amber-500/30 font-medium'
                  : 'px-3 py-1 rounded-md text-gray-500 hover:text-gray-300 transition-colors'
              }
            >
              {tab === 'drift' ? 'Perimeter Drift' : 'External Exposure'}
            </button>
          ))}
        </div>
      </div>

      {activeTab === 'drift' ? (
        <DriftTab
          status={perimeterStatus}
          statusLoading={perimeterStatusLoading}
          declaredPorts={declaredPorts}
          declaredPortsLoading={declaredPortsLoading}
          scanResult={scanResult}
          scanHistory={scanHistory}
          historyOpen={historyOpen}
          setHistoryOpen={setHistoryOpen}
          scanning={scanning}
          syncing={syncing}
          addingPort={addingPort}
          newPort={newPort}
          newLabel={newLabel}
          setNewPort={setNewPort}
          setNewLabel={setNewLabel}
          onAddPort={handleAddPort}
          onRemovePort={handleRemovePort}
          onSync={handleSync}
          onScan={handleScan}
        />
      ) : (
        <ExposureTab
          status={perimeterStatus}
          snapshot={shodanSnapshot}
          shodanLoading={shodanLoading}
          refreshing={refreshing}
          banners={banners}
          expandedBanner={expandedBanner}
          setExpandedBanner={setExpandedBanner}
          onRefresh={handleRefreshShodan}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Drift Tab
// ---------------------------------------------------------------------------

function DriftTab({
  status,
  statusLoading,
  declaredPorts,
  declaredPortsLoading,
  scanResult,
  scanHistory,
  historyOpen,
  setHistoryOpen,
  scanning,
  syncing,
  addingPort,
  newPort,
  newLabel,
  setNewPort,
  setNewLabel,
  onAddPort,
  onRemovePort,
  onSync,
  onScan,
}: {
  status: ReturnType<typeof useStore.getState>['perimeterStatus'];
  statusLoading: boolean;
  declaredPorts: DeclaredPort[];
  declaredPortsLoading: boolean;
  scanResult: PerimeterScan | null;
  scanHistory: PerimeterScan[];
  historyOpen: boolean;
  setHistoryOpen: (v: boolean) => void;
  scanning: boolean;
  syncing: boolean;
  addingPort: boolean;
  newPort: string;
  newLabel: string;
  setNewPort: (v: string) => void;
  setNewLabel: (v: string) => void;
  onAddPort: (e: React.FormEvent) => void;
  onRemovePort: (id: number) => void;
  onSync: () => void;
  onScan: () => void;
}) {
  return (
    <div className="space-y-6">
      {/* Metric cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Public IP */}
        <div className="card p-5">
          <div className="flex items-center gap-2 mb-2">
            <Globe className="w-4 h-4 text-amber-500" />
            <span className="text-xs font-medium text-gray-500 uppercase tracking-wider">Public IP</span>
          </div>
          {statusLoading ? (
            <div className="h-8 bg-[#1c1c28] rounded animate-pulse" />
          ) : (
            <p className="text-xl font-mono text-amber-400">
              {status?.public_ip || 'Not detected'}
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
            {status?.declared_count ?? 0}
          </p>
        </div>

        {/* Drift Status */}
        <div className="card p-5">
          <div className="flex items-center gap-2 mb-2">
            <Shield className="w-4 h-4 text-gray-400" />
            <span className="text-xs font-medium text-gray-500 uppercase tracking-wider">Drift Status</span>
          </div>
          {status?.drift_detected ? (
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-red-400" />
              <span className="text-lg font-semibold text-red-400">Drift Detected</span>
              <span className="text-xs text-gray-500 ml-2">
                {status.unexpected_count > 0 && `${status.unexpected_count} unexpected`}
                {status.unexpected_count > 0 && status.missing_count > 0 && ', '}
                {status.missing_count > 0 && `${status.missing_count} missing`}
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

      {/* Declared Ports */}
      <div className="card">
        <div className="px-5 py-4 border-b border-[#2a2a3a] flex items-center justify-between">
          <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
            <Server className="w-4 h-4 text-amber-500" />
            Declared Ports
          </h3>
          <button
            onClick={onSync}
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
                          onClick={() => onRemovePort(dp.id)}
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
          <form onSubmit={onAddPort} className="flex items-end gap-3 mt-4 pt-4 border-t border-[#2a2a3a]">
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

      {/* Drift Results */}
      <div className="card">
        <div className="px-5 py-4 border-b border-[#2a2a3a] flex items-center justify-between">
          <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
            <Eye className="w-4 h-4 text-amber-500" />
            Drift Results
          </h3>
          <button
            onClick={onScan}
            disabled={scanning}
            className="btn-primary flex items-center gap-1.5 text-sm disabled:opacity-50"
          >
            {scanning ? (
              <>
                <div className="w-3.5 h-3.5 border-2 border-gray-900/30 border-t-gray-900 rounded-full animate-spin" />
                Checking...
              </>
            ) : (
              <>
                <RefreshCw className="w-3.5 h-3.5" />
                Check Now
              </>
            )}
          </button>
        </div>

        <div className="p-5">
          {!scanResult ? (
            <div className="text-center py-8">
              <Shield className="w-12 h-12 text-gray-700 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-400 mb-2">No drift checks yet</h3>
              <p className="text-sm text-gray-600">
                Run a check to compare your declared ports against what is visible externally via Shodan.
              </p>
            </div>
          ) : !scanResult.drift_detected ? (
            <div className="flex items-center gap-3 py-4">
              <CheckCircle className="w-6 h-6 text-green-400" />
              <div>
                <p className="text-sm font-medium text-green-400">Perimeter matches declaration</p>
                <p className="text-xs text-gray-500 mt-0.5">
                  Last checked {formatRelativeTime(scanResult.timestamp)}
                </p>
              </div>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="flex items-center gap-2 text-xs text-gray-500">
                <Clock className="w-3 h-3" />
                Last checked {formatRelativeTime(scanResult.timestamp)}
              </div>

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

          {/* Scan history */}
          {scanHistory.length > 0 && (
            <div className="mt-6 pt-4 border-t border-[#2a2a3a]">
              <button
                onClick={() => setHistoryOpen(!historyOpen)}
                className="flex items-center gap-2 text-xs text-gray-500 hover:text-gray-300 transition-colors"
              >
                {historyOpen ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                Scan History ({scanHistory.length})
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
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Exposure Tab
// ---------------------------------------------------------------------------

function ExposureTab({
  status,
  snapshot,
  shodanLoading,
  refreshing,
  banners,
  expandedBanner,
  setExpandedBanner,
  onRefresh,
}: {
  status: ReturnType<typeof useStore.getState>['perimeterStatus'];
  snapshot: ShodanSnapshot | null;
  shodanLoading: boolean;
  refreshing: boolean;
  banners: BannerComparison[];
  expandedBanner: number | null;
  setExpandedBanner: (v: number | null) => void;
  onRefresh: () => void;
}) {
  // Not configured
  if (!status?.shodan_configured) {
    return (
      <div className="card p-8 text-center">
        <Eye className="w-12 h-12 text-gray-700 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-400 mb-2">
          Shodan API Not Configured
        </h3>
        <p className="text-sm text-gray-500 max-w-md mx-auto mb-4">
          Add <code className="px-1.5 py-0.5 bg-[#1c1c28] rounded text-amber-400 text-xs">SHODAN_API_KEY</code> to
          your <code className="px-1.5 py-0.5 bg-[#1c1c28] rounded text-amber-400 text-xs">.env</code> file
          to enable external exposure monitoring.
        </p>
        <p className="text-xs text-gray-600">
          Get a free API key at{' '}
          <span className="text-amber-400">shodan.io</span>
        </p>
      </div>
    );
  }

  if (shodanLoading && !snapshot) {
    return (
      <div className="card p-12 text-center">
        <div className="inline-block w-6 h-6 border-2 border-amber-500/30 border-t-amber-500 rounded-full animate-spin" />
        <p className="mt-3 text-sm text-gray-500">Loading Shodan data...</p>
      </div>
    );
  }

  const portsData = snapshot?.ports_data || [];
  const tags = snapshot?.tags || [];
  const vulns = snapshot?.vulns || [];

  return (
    <div className="space-y-6">
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
                Shodan has tagged your IP with <code className="px-1 py-0.5 bg-red-500/10 rounded text-red-400 text-xs">honeypot</code>.
                Attackers using Shodan will know this is a honeypot. Consider adjusting your service banners.
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

      {/* Host Overview */}
      <div className="card">
        <div className="px-5 py-4 border-b border-[#2a2a3a] flex items-center justify-between">
          <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
            <Globe className="w-4 h-4 text-amber-500" />
            Host Overview
          </h3>
          <button
            onClick={onRefresh}
            disabled={refreshing}
            className="btn-secondary flex items-center gap-1.5 text-xs"
          >
            <RefreshCw className={clsx('w-3.5 h-3.5', refreshing && 'animate-spin')} />
            Refresh
          </button>
        </div>

        {snapshot ? (
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
              Shodan last updated: {snapshot.shodan_updated || 'N/A'}
              <span className="mx-2">|</span>
              Fetched: {formatRelativeTime(snapshot.timestamp)}
            </div>
          </div>
        ) : (
          <div className="p-5 text-center py-8">
            <p className="text-sm text-gray-500">
              No Shodan data available. Click Refresh to fetch.
            </p>
          </div>
        )}
      </div>

      {/* Open Ports */}
      {portsData.length > 0 && (
        <div className="card">
          <div className="px-5 py-4 border-b border-[#2a2a3a]">
            <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
              <Server className="w-4 h-4 text-amber-500" />
              Open Ports ({portsData.length})
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
                  <th className="text-left py-2.5 font-medium">Shodan Banner</th>
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
                      {b.shodan_banner
                        ? b.shodan_banner.length > 80
                          ? b.shodan_banner.slice(0, 80) + '...'
                          : b.shodan_banner
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

      {/* Tags + Vulns */}
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
    </div>
  );
}
