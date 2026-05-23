import { format, formatDistanceToNow, parseISO } from 'date-fns';

/**
 * Format an ISO date string into a human-readable date/time.
 */
export function formatDate(dateStr: string | null | undefined, pattern: string = 'MMM d, yyyy HH:mm:ss'): string {
  if (!dateStr) return 'N/A';
  try {
    const date = parseISO(dateStr);
    return format(date, pattern);
  } catch {
    return 'Invalid date';
  }
}

/**
 * Format a date string as relative time (e.g., "5 minutes ago").
 */
export function formatRelativeTime(dateStr: string | null | undefined): string {
  if (!dateStr) return 'N/A';
  try {
    const date = parseISO(dateStr);
    return formatDistanceToNow(date, { addSuffix: true });
  } catch {
    return 'Invalid date';
  }
}

/**
 * Format a duration in seconds into a human-readable string.
 */
export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return 'N/A';

  if (seconds < 1) return '<1s';
  if (seconds < 60) return `${Math.round(seconds)}s`;

  const mins = Math.floor(seconds / 60);
  const secs = Math.round(seconds % 60);

  if (mins < 60) {
    return secs > 0 ? `${mins}m ${secs}s` : `${mins}m`;
  }

  const hours = Math.floor(mins / 60);
  const remainingMins = mins % 60;

  if (hours < 24) {
    return remainingMins > 0 ? `${hours}h ${remainingMins}m` : `${hours}h`;
  }

  const days = Math.floor(hours / 24);
  const remainingHours = hours % 24;
  return remainingHours > 0 ? `${days}d ${remainingHours}h` : `${days}d`;
}

/**
 * Format an IP address for display with monospace styling hint.
 */
export function formatIP(ip: string | null | undefined): string {
  if (!ip) return 'N/A';
  return ip;
}

/**
 * Truncate text to a maximum length with ellipsis.
 */
export function truncateText(text: string | null | undefined, maxLength: number = 50): string {
  if (!text) return '';
  if (text.length <= maxLength) return text;
  return text.slice(0, maxLength) + '...';
}

/**
 * Format bytes into a human-readable size string.
 */
export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return 'N/A';
  if (bytes === 0) return '0 B';

  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const k = 1024;
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  const value = bytes / Math.pow(k, i);

  return `${value.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

/**
 * Format a number with comma separators.
 */
export function formatNumber(num: number | null | undefined): string {
  if (num === null || num === undefined) return '0';
  return num.toLocaleString();
}

/**
 * Format a port number for display.
 */
export function formatPort(port: number | null | undefined): string {
  if (port === null || port === undefined) return 'N/A';
  return port.toString();
}
