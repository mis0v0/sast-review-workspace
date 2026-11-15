import { readServerInstanceId } from './serverInstance';
import { parseHealth, parseOptions, parseScan, type Health, type Options, type ScanResponse } from './types';

export class ApiError extends Error {
  constructor(readonly status: number, readonly code: string, readonly serverInstanceId: string | null = null) { super(code); }
}

/** A parsed response body together with the server instance that produced it. */
export interface Attested<T> {
  readonly value: T;
  readonly serverInstanceId: string | null;
}

async function request(path: string, token?: string, body?: object): Promise<Attested<unknown>> {
  const headers = new Headers();
  if (token) headers.set('X-Local-API-Token', token);
  if (body) headers.set('Content-Type', 'application/json');
  let response: Response;
  try {
    response = await fetch(path, { method: body ? 'POST' : 'GET', headers, body: body ? JSON.stringify(body) : undefined, cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer' });
  } catch { throw new ApiError(0, 'connection_error'); }
  const serverInstanceId = readServerInstanceId(response);
  let value: unknown;
  try { value = await response.json(); } catch { throw new ApiError(response.status, 'invalid_api_response', serverInstanceId); }
  if (!response.ok) {
    const code = typeof value === 'object' && value !== null && 'error' in value && typeof value.error === 'string' && /^[a-z_]{1,64}$/.test(value.error) ? value.error : 'request_failed';
    throw new ApiError(response.status, code, serverInstanceId);
  }
  return { value, serverInstanceId };
}

export const api = {
  async health(): Promise<Health> { return parseHealth((await request('/api/v1/health')).value); },
  async options(): Promise<Attested<Options>> {
    const { value, serverInstanceId } = await request('/api/v1/options');
    return { value: parseOptions(value), serverInstanceId };
  },
  async scan(token: string, targetId: string, ruleProfileId: string): Promise<Attested<ScanResponse>> {
    const { value, serverInstanceId } = await request('/api/v1/scans', token, { target_id: targetId, rule_profile_id: ruleProfileId });
    return { value: parseScan(value), serverInstanceId };
  },
};
