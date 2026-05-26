/**
 * HoneyOS API Client
 *
 * Communicates with the Flask backend API. Base URL is determined by
 * the NEXT_PUBLIC_API_URL environment variable or defaults to the
 * current origin (which uses Next.js rewrites to proxy /api/* requests).
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface Event {
  id: string;
  event_type: string;
  protocol: string;
  source_ip: string;
  source_port: number | null;
  destination_port: number | null;
  timestamp: string | null;
  severity: string;
  details: Record<string, unknown> | null;
  session_id: string | null;
  user_agent: string | null;
  raw_payload: string | null;
  geolocation: Record<string, unknown> | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface Session {
  id: string;
  source_ip: string;
  protocol: string;
  start_time: string | null;
  end_time: string | null;
  duration_seconds: number | null;
  commands_count: number;
  keystrokes: string[] | null;
  commands: Array<{ timestamp: string; command: string; output?: string }> | null;
  file_transfers: Array<{ filename: string; direction: string; size: number }> | null;
  status: string;
}

export interface Honeypot {
  id: string;
  name: string;
  protocol: string;
  port: number;
  enabled: boolean;
  description: string | null;
  config: Record<string, unknown> | null;
  last_activity: string | null;
  total_interactions: number;
}

export interface Alert {
  id: string;
  name: string;
  enabled: boolean;
  alert_type: string;
  config: Record<string, unknown> | null;
  conditions: Record<string, unknown> | null;
  last_sent: string | null;
  send_count: number;
}

export interface NetworkScan {
  id: string;
  target_host: string;
  scan_type: string;
  discovered_ports: Array<{ port: number; service: string; state: string }> | null;
  scan_duration_ms: number | null;
  timestamp: string | null;
  changes_detected: boolean;
  previous_scan_id: string | null;
}

export interface ThreatLevel {
  level: string;
  score: number;
  recent_events: number;
  high_severity_events: number;
  unique_attackers: number;
  unique_protocols: number;
}

export interface DashboardSummary {
  total_events: number;
  active_sessions: number;
  active_honeypots: number;
  threat_level: ThreatLevel;
  top_attackers: Array<{ ip: string; count: number; last_seen: string; country?: string; country_code?: string; org?: string }>;
  protocol_breakdown: Array<{ protocol: string; count: number }>;
  recent_events: Event[];
  events_today: number;
  events_this_week: number;
}

export interface TimelinePoint {
  timestamp: string;
  count: number;
}

export interface SettingItem {
  key: string;
  label: string;
  value: string;
  type: string;
}

export interface SettingsSection {
  id: string;
  label: string;
  settings: SettingItem[];
}

export interface SettingsSystem {
  version: string;
  database: string;
  uptime_seconds: number;
}

export interface SettingsResponse {
  sections: SettingsSection[];
  system: SettingsSystem;
}

export interface Attacker {
  ip: string;
  event_count: number;
  first_seen: string | null;
  last_seen: string | null;
  protocols: string[];
  country: string | null;
  country_code: string | null;
  city: string | null;
  org: string | null;
  isp: string | null;
  lat: number | null;
  lon: number | null;
}

export interface AttackerParams {
  page?: number;
  per_page?: number;
  protocol?: string;
  country_code?: string;
  search?: string;
  sort_by?: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
  pages: number;
}

export interface TopUsername {
  username: string;
  count: number;
  protocols: string[];
}

export interface TopPassword {
  password: string;
  count: number;
}

export interface TopCombo {
  username: string;
  password: string;
  count: number;
  protocols: string[];
}

export interface CredentialsData {
  total_attempts: number;
  top_usernames: TopUsername[];
  top_passwords: TopPassword[];
  top_combos: TopCombo[];
}

export interface CredentialsParams {
  protocol?: string;
  limit?: number;
}

export interface ApiError {
  error: string;
  message: string;
}

export interface AuthStatus {
  has_admin: boolean;
  authenticated: boolean;
}

// ---------------------------------------------------------------------------
// Base URL & fetch helper
// ---------------------------------------------------------------------------

function getBaseUrl(): string {
  if (typeof window !== 'undefined') {
    return window.location.origin;
  }
  return process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000';
}

async function fetchApi<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${getBaseUrl()}/api${endpoint}`;

  const defaultHeaders: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  const response = await fetch(url, {
    ...options,
    headers: {
      ...defaultHeaders,
      ...options.headers,
    },
  });

  if (!response.ok) {
    if (response.status === 401 && typeof window !== 'undefined') {
      window.location.reload();
      throw new Error('Session expired');
    }
    let errorData: ApiError;
    try {
      errorData = await response.json();
    } catch {
      errorData = {
        error: 'request_failed',
        message: `HTTP ${response.status}: ${response.statusText}`,
      };
    }
    throw new Error(errorData.message || `API Error: ${response.status}`);
  }

  // Handle 204 No Content
  if (response.status === 204) {
    return {} as T;
  }

  return response.json();
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

export interface EventParams {
  page?: number;
  per_page?: number;
  event_type?: string;
  protocol?: string;
  severity?: string;
  source_ip?: string;
  start_date?: string;
  end_date?: string;
}

export async function getEvents(params: EventParams = {}): Promise<PaginatedResponse<Event>> {
  const searchParams = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== '' && value !== null) {
      searchParams.append(key, String(value));
    }
  });
  const query = searchParams.toString();
  return fetchApi<PaginatedResponse<Event>>(`/events${query ? `?${query}` : ''}`);
}

export async function getEvent(id: string): Promise<Event> {
  return fetchApi<Event>(`/events/${id}`);
}

export async function createEvent(data: Partial<Event>): Promise<Event> {
  return fetchApi<Event>('/events', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

// ---------------------------------------------------------------------------
// Attackers
// ---------------------------------------------------------------------------

export async function getAttackers(params: AttackerParams = {}): Promise<PaginatedResponse<Attacker>> {
  const searchParams = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== '' && value !== null) {
      searchParams.append(key, String(value));
    }
  });
  const query = searchParams.toString();
  return fetchApi<PaginatedResponse<Attacker>>(`/attackers${query ? `?${query}` : ''}`);
}

export async function getAttackerEvents(ip: string, params: EventParams = {}): Promise<PaginatedResponse<Event>> {
  return getEvents({ source_ip: ip, ...params });
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

export async function getCredentials(params: CredentialsParams = {}): Promise<CredentialsData> {
  const searchParams = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== '' && value !== null) {
      searchParams.append(key, String(value));
    }
  });
  const query = searchParams.toString();
  return fetchApi<CredentialsData>(`/credentials${query ? `?${query}` : ''}`);
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

export interface SessionParams {
  page?: number;
  per_page?: number;
  protocol?: string;
  status?: string;
  source_ip?: string;
}

export async function getSessions(params: SessionParams = {}): Promise<PaginatedResponse<Session>> {
  const searchParams = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== '' && value !== null) {
      searchParams.append(key, String(value));
    }
  });
  const query = searchParams.toString();
  return fetchApi<PaginatedResponse<Session>>(`/sessions${query ? `?${query}` : ''}`);
}

export async function getSession(id: string): Promise<Session> {
  return fetchApi<Session>(`/sessions/${id}`);
}

export async function getSessionReplay(id: string): Promise<{ commands: Session['commands'] }> {
  return fetchApi<{ commands: Session['commands'] }>(`/sessions/${id}/replay`);
}

// ---------------------------------------------------------------------------
// Honeypots
// ---------------------------------------------------------------------------

export async function getHoneypots(): Promise<Honeypot[]> {
  return fetchApi<Honeypot[]>('/honeypots');
}

export async function createHoneypot(data: Partial<Honeypot>): Promise<Honeypot> {
  return fetchApi<Honeypot>('/honeypots', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function updateHoneypot(id: string, data: Partial<Honeypot>): Promise<Honeypot> {
  return fetchApi<Honeypot>(`/honeypots/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });
}

export async function deleteHoneypot(id: string): Promise<void> {
  await fetchApi<void>(`/honeypots/${id}`, {
    method: 'DELETE',
  });
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------

export async function getAlerts(): Promise<Alert[]> {
  return fetchApi<Alert[]>('/alerts');
}

export async function createAlert(data: Partial<Alert>): Promise<Alert> {
  return fetchApi<Alert>('/alerts', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function updateAlert(id: string, data: Partial<Alert>): Promise<Alert> {
  return fetchApi<Alert>(`/alerts/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });
}

export async function testAlert(id: string): Promise<{ success: boolean; message: string }> {
  return fetchApi<{ success: boolean; message: string }>(`/alerts/${id}/test`, {
    method: 'POST',
  });
}

// ---------------------------------------------------------------------------
// Network Scans
// ---------------------------------------------------------------------------

export interface NetworkScanParams {
  page?: number;
  per_page?: number;
  target_host?: string;
}

export async function getNetworkScans(params: NetworkScanParams = {}): Promise<PaginatedResponse<NetworkScan>> {
  const searchParams = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== '' && value !== null) {
      searchParams.append(key, String(value));
    }
  });
  const query = searchParams.toString();
  return fetchApi<PaginatedResponse<NetworkScan>>(`/network-scans${query ? `?${query}` : ''}`);
}

export async function createNetworkScan(data: { target_host: string; scan_type?: string }): Promise<NetworkScan> {
  return fetchApi<NetworkScan>('/network-scans', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function getNetworkScanChanges(id: string): Promise<{
  added_ports: number[];
  removed_ports: number[];
  unchanged_ports: number[];
}> {
  return fetchApi(`/network-scans/${id}/changes`);
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

export async function getDashboardSummary(): Promise<DashboardSummary> {
  return fetchApi<DashboardSummary>('/dashboard/summary');
}

export async function getDashboardTimeline(hours: number = 24): Promise<TimelinePoint[]> {
  return fetchApi<TimelinePoint[]>(`/dashboard/timeline?hours=${hours}`);
}

// ---------------------------------------------------------------------------
// Settings (read-only)
// ---------------------------------------------------------------------------

export async function getSettings(): Promise<SettingsResponse> {
  return fetchApi<SettingsResponse>('/settings');
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

export async function getAuthStatus(): Promise<AuthStatus> {
  const url = `${getBaseUrl()}/api/auth/status`;
  const res = await fetch(url, { credentials: 'same-origin' });
  return res.json();
}

export async function authSetup(password: string): Promise<void> {
  const url = `${getBaseUrl()}/api/auth/setup`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify({ password }),
  });
  if (!res.ok) {
    const data = await res.json();
    throw new Error(data.message || 'Setup failed');
  }
}

export async function authLogin(password: string): Promise<void> {
  const url = `${getBaseUrl()}/api/auth/login`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify({ password }),
  });
  if (!res.ok) {
    const data = await res.json();
    throw new Error(data.message || 'Login failed');
  }
}

export async function authLogout(): Promise<void> {
  const url = `${getBaseUrl()}/api/auth/logout`;
  await fetch(url, {
    method: 'POST',
    credentials: 'same-origin',
  });
}

export async function authChangePassword(
  currentPassword: string,
  newPassword: string
): Promise<void> {
  const url = `${getBaseUrl()}/api/auth/change-password`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  });
  if (!res.ok) {
    const data = await res.json();
    throw new Error(data.message || 'Password change failed');
  }
}
