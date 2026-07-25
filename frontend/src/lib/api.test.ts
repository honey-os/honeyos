import { describe, it, expect, vi, afterEach } from 'vitest';
import { fetchCanaryWebhook } from './api';

function mockFetch(body: unknown, ok = true, status = 200) {
  const fn = vi.fn().mockResolvedValue({
    ok,
    status,
    json: async () => body,
  });
  vi.stubGlobal('fetch', fn);
  return fn;
}

describe('fetchCanaryWebhook', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('calls the canarytokens webhook endpoint and returns the parsed info', async () => {
    const info = {
      enabled: true,
      port: 7779,
      webhook_url: 'http://host:7779/canarytokens/secret123',
    };
    const fetchFn = mockFetch(info);

    const result = await fetchCanaryWebhook();

    expect(result).toEqual(info);
    const calledUrl = fetchFn.mock.calls[0][0] as string;
    expect(calledUrl).toContain('/api/webhooks/canarytokens');
  });

  it('passes through a disabled-webhook response', async () => {
    mockFetch({ enabled: false, webhook_url: null });

    const result = await fetchCanaryWebhook();

    expect(result.enabled).toBe(false);
    expect(result.webhook_url).toBeNull();
  });

  it('throws when the API responds with an error status', async () => {
    mockFetch({ error: 'boom', message: 'server error' }, false, 500);

    await expect(fetchCanaryWebhook()).rejects.toThrow();
  });
});
