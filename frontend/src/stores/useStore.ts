import { create } from 'zustand';
import {
  type Event,
  type Session,
  type Honeypot,
  type Alert,
  type DashboardSummary,
  type TimelinePoint,
  type NetworkScan,
  type SystemConfigItem,
  getEvents,
  getSessions,
  getHoneypots,
  getAlerts,
  getDashboardSummary,
  getDashboardTimeline,
  getNetworkScans,
  getConfig,
} from '@/lib/api';

// ---------------------------------------------------------------------------
// Store shape
// ---------------------------------------------------------------------------

interface HoneyStore {
  // Sidebar
  sidebarOpen: boolean;
  setSidebarOpen: (open: boolean) => void;
  toggleSidebar: () => void;

  // Events
  events: Event[];
  eventsTotal: number;
  eventsPage: number;
  eventsPages: number;
  eventsLoading: boolean;
  eventsError: string | null;
  fetchEvents: (params?: Record<string, unknown>) => Promise<void>;

  // Sessions
  sessions: Session[];
  sessionsTotal: number;
  sessionsPage: number;
  sessionsPages: number;
  sessionsLoading: boolean;
  sessionsError: string | null;
  selectedSession: Session | null;
  setSelectedSession: (session: Session | null) => void;
  fetchSessions: (params?: Record<string, unknown>) => Promise<void>;

  // Honeypots
  honeypots: Honeypot[];
  honeypotsLoading: boolean;
  honeypotsError: string | null;
  fetchHoneypots: () => Promise<void>;

  // Alerts
  alerts: Alert[];
  alertsLoading: boolean;
  alertsError: string | null;
  fetchAlerts: () => Promise<void>;

  // Dashboard
  dashboardSummary: DashboardSummary | null;
  dashboardTimeline: TimelinePoint[];
  dashboardLoading: boolean;
  dashboardError: string | null;
  fetchDashboard: (timelineHours?: number) => Promise<void>;

  // Network
  networkScans: NetworkScan[];
  networkScansTotal: number;
  networkScansLoading: boolean;
  networkScansError: string | null;
  fetchNetworkScans: (params?: Record<string, unknown>) => Promise<void>;

  // Config
  config: SystemConfigItem[];
  configLoading: boolean;
  configError: string | null;
  fetchConfig: () => Promise<void>;
}

// ---------------------------------------------------------------------------
// Store implementation
// ---------------------------------------------------------------------------

export const useStore = create<HoneyStore>((set) => ({
  // Sidebar
  sidebarOpen: true,
  setSidebarOpen: (open) => set({ sidebarOpen: open }),
  toggleSidebar: () => set((s) => ({ sidebarOpen: !s.sidebarOpen })),

  // Events
  events: [],
  eventsTotal: 0,
  eventsPage: 1,
  eventsPages: 1,
  eventsLoading: false,
  eventsError: null,
  fetchEvents: async (params = {}) => {
    set({ eventsLoading: true, eventsError: null });
    try {
      const data = await getEvents(params as Parameters<typeof getEvents>[0]);
      set({
        events: data.items || [],
        eventsTotal: data.total || 0,
        eventsPage: data.page || 1,
        eventsPages: data.pages || 1,
        eventsLoading: false,
      });
    } catch (err) {
      set({
        eventsLoading: false,
        eventsError: err instanceof Error ? err.message : 'Failed to fetch events',
      });
    }
  },

  // Sessions
  sessions: [],
  sessionsTotal: 0,
  sessionsPage: 1,
  sessionsPages: 1,
  sessionsLoading: false,
  sessionsError: null,
  selectedSession: null,
  setSelectedSession: (session) => set({ selectedSession: session }),
  fetchSessions: async (params = {}) => {
    set({ sessionsLoading: true, sessionsError: null });
    try {
      const data = await getSessions(params as Parameters<typeof getSessions>[0]);
      set({
        sessions: data.items || [],
        sessionsTotal: data.total || 0,
        sessionsPage: data.page || 1,
        sessionsPages: data.pages || 1,
        sessionsLoading: false,
      });
    } catch (err) {
      set({
        sessionsLoading: false,
        sessionsError: err instanceof Error ? err.message : 'Failed to fetch sessions',
      });
    }
  },

  // Honeypots
  honeypots: [],
  honeypotsLoading: false,
  honeypotsError: null,
  fetchHoneypots: async () => {
    set({ honeypotsLoading: true, honeypotsError: null });
    try {
      const data = await getHoneypots();
      set({ honeypots: Array.isArray(data) ? data : [], honeypotsLoading: false });
    } catch (err) {
      set({
        honeypotsLoading: false,
        honeypotsError: err instanceof Error ? err.message : 'Failed to fetch honeypots',
      });
    }
  },

  // Alerts
  alerts: [],
  alertsLoading: false,
  alertsError: null,
  fetchAlerts: async () => {
    set({ alertsLoading: true, alertsError: null });
    try {
      const data = await getAlerts();
      set({ alerts: Array.isArray(data) ? data : [], alertsLoading: false });
    } catch (err) {
      set({
        alertsLoading: false,
        alertsError: err instanceof Error ? err.message : 'Failed to fetch alerts',
      });
    }
  },

  // Dashboard
  dashboardSummary: null,
  dashboardTimeline: [],
  dashboardLoading: false,
  dashboardError: null,
  fetchDashboard: async (timelineHours = 24) => {
    set({ dashboardLoading: true, dashboardError: null });
    try {
      const [summary, timeline] = await Promise.all([
        getDashboardSummary(),
        getDashboardTimeline(timelineHours),
      ]);
      set({
        dashboardSummary: summary,
        dashboardTimeline: timeline,
        dashboardLoading: false,
      });
    } catch (err) {
      set({
        dashboardLoading: false,
        dashboardError: err instanceof Error ? err.message : 'Failed to fetch dashboard',
      });
    }
  },

  // Network
  networkScans: [],
  networkScansTotal: 0,
  networkScansLoading: false,
  networkScansError: null,
  fetchNetworkScans: async (params = {}) => {
    set({ networkScansLoading: true, networkScansError: null });
    try {
      const data = await getNetworkScans(params as Parameters<typeof getNetworkScans>[0]);
      set({
        networkScans: data.items,
        networkScansTotal: data.total,
        networkScansLoading: false,
      });
    } catch (err) {
      set({
        networkScansLoading: false,
        networkScansError: err instanceof Error ? err.message : 'Failed to fetch scans',
      });
    }
  },

  // Config
  config: [],
  configLoading: false,
  configError: null,
  fetchConfig: async () => {
    set({ configLoading: true, configError: null });
    try {
      const data = await getConfig();
      set({ config: Array.isArray(data) ? data : [], configLoading: false });
    } catch (err) {
      set({
        configLoading: false,
        configError: err instanceof Error ? err.message : 'Failed to fetch config',
      });
    }
  },
}));
