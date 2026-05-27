'use client';

import { useSearchParams, useRouter, usePathname } from 'next/navigation';
import { useCallback } from 'react';

/**
 * Sync filter state with URL query parameters so filters
 * survive page reloads and are shareable via URL.
 */
export function useUrlFilters() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();

  /** Read a query param (returns '' if absent). */
  const getParam = useCallback(
    (key: string) => searchParams.get(key) || '',
    [searchParams]
  );

  /** Set a single query param (empty string removes it). */
  const setParam = useCallback(
    (key: string, value: string) => {
      const params = new URLSearchParams(searchParams.toString());
      if (value) {
        params.set(key, value);
      } else {
        params.delete(key);
      }
      const qs = params.toString();
      router.replace(qs ? `${pathname}?${qs}` : pathname);
    },
    [searchParams, router, pathname]
  );

  /** Remove all query params (or all except the listed keys). */
  const clearParams = useCallback(
    (...keep: string[]) => {
      if (keep.length === 0) {
        router.replace(pathname);
        return;
      }
      const params = new URLSearchParams();
      for (const key of keep) {
        const val = searchParams.get(key);
        if (val) params.set(key, val);
      }
      const qs = params.toString();
      router.replace(qs ? `${pathname}?${qs}` : pathname);
    },
    [searchParams, router, pathname]
  );

  return { searchParams, getParam, setParam, clearParams };
}
