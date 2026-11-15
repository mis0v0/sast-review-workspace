/**
 * Every API response names the server process that produced it in this header.
 * The value is random per process. It lets the page refuse to combine results
 * from two server runs; it does not identify a project and proves nothing about one.
 */
export const SERVER_INSTANCE_HEADER = 'X-Server-Instance';

const serverInstancePattern = /^[A-Za-z0-9_-]{16,64}$/;

export function isServerInstanceId(value: unknown): value is string {
  return typeof value === 'string' && serverInstancePattern.test(value);
}

/** Returns the identifier, or null when it is absent, repeated or malformed. */
export function readServerInstanceId(response: Pick<Response, 'headers'>): string | null {
  let raw: string | null;
  try { raw = response.headers.get(SERVER_INSTANCE_HEADER); } catch { return null; }
  return isServerInstanceId(raw) ? raw : null;
}
