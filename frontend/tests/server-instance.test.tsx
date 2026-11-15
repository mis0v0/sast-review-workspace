import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { api, ApiError } from '../src/api/client';
import { investigationApi } from '../src/api/investigation';
import { readServerInstanceId } from '../src/api/serverInstance';
import type { ApiFinding, ScanResponse } from '../src/api/types';
import { App } from '../src/app/App';
import { createAnalystReviewBackup } from '../src/features/scans/analystReviewBackup';
import { setAnalystReviewStatus, emptyAnalystReviewState } from '../src/features/scans/analystReview';
import { createComparisonMarkdown } from '../src/features/scans/comparisonMarkdownExport';
import { compareScanSnapshots, type ScanSnapshot } from '../src/features/scans/compare';
import { validateInvestigationRuns, type EvidenceBackedScan } from '../src/features/scans/investigationWorkflow';
import { createReviewMarkdown } from '../src/features/scans/markdownExport';
import { createSarifReport } from '../src/features/scans/sarifExport';

const SERVER_A = 'server-instance-aaaaaaa';
const SERVER_B = 'server-instance-bbbbbbb';

const finding = (name: string): ApiFinding => ({
  finding_id: `semgrep:${name.repeat(24).slice(0, 24)}`, rule_id: 'baseline.javascript-dynamic-eval', severity: 'high',
  verification_status: 'unverified', finding_kind: 'pattern', file_path: `src/${name}.js`, line_number: 2,
  evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [], validation_error_code: null,
});
const scan = (findings: ApiFinding[]): ScanResponse => ({
  scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: findings.length,
  displayed_finding_count: findings.length, omitted_finding_count: 0,
  severity_counts: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0 },
  issues: [], findings, limitations: ['scan_result_is_not_safety_proof'],
});
const snapshot = (instance: string | null | undefined, findings = [finding('a'), finding('b')], receivedAt = '2026-11-15T00:00:00.000Z'): ScanSnapshot => ({
  scan: scan(findings),
  context: { targetId: 'local-project', targetLabel: 'Local Project', ruleProfileId: 'baseline', ruleProfileLabel: 'Baseline', experimental: false,
    scanStatus: 'completed', receivedAt, ...(instance === undefined ? {} : { serverInstanceId: instance }) },
});

describe('reading the server instance header', () => {
  const read = (value: string | null) => readServerInstanceId({ headers: new Headers(value === null ? {} : { 'X-Server-Instance': value }) });
  it('accepts only one well-formed value', () => {
    expect(read(SERVER_A)).toBe(SERVER_A);
    for (const bad of [null, '', 'short', 'a'.repeat(65), 'has space inside here', `${SERVER_A}, ${SERVER_B}`, 'ünicode-ünicode-ünicode']) expect(read(bad)).toBeNull();
    const repeated = new Headers(); repeated.append('X-Server-Instance', SERVER_A); repeated.append('X-Server-Instance', SERVER_B);
    expect(readServerInstanceId({ headers: repeated })).toBeNull();
  });
});

describe('comparison requires one server run', () => {
  it('compares results from the same server run', () => {
    const result = compareScanSnapshots(snapshot(SERVER_A), snapshot(SERVER_A, [finding('a'), finding('c')], '2026-11-15T00:01:00.000Z'));
    expect(result.comparable).toBe(true);
    expect(result.groups?.shared).toHaveLength(1);
  });

  it('refuses results from two server runs, even when every finding is identical', () => {
    const result = compareScanSnapshots(snapshot(SERVER_A), snapshot(SERVER_B, undefined, '2026-11-15T00:01:00.000Z'));
    expect(result).toEqual({ comparable: false, reasons: ['server_instance_mismatch'], groups: null });
  });

  it.each([
    ['baseline missing', undefined, SERVER_A], ['current missing', SERVER_A, undefined],
    ['baseline null', null, SERVER_A], ['both null', null, null], ['malformed', 'bad', 'bad'],
  ] as const)('fails closed when the identity is unknown: %s', (_label, left, right) => {
    const result = compareScanSnapshots(snapshot(left), snapshot(right, undefined, '2026-11-15T00:01:00.000Z'));
    expect(result.comparable).toBe(false);
    expect(result.reasons).toContain('server_instance_unavailable');
    expect(result.groups).toBeNull();
  });

  it('never links investigation evidence across server runs', () => {
    const evidence = (instance: string | null, handle: string): EvidenceBackedScan => ({ snapshot: snapshot(instance), runHandle: handle.repeat(43) });
    expect(validateInvestigationRuns(evidence(SERVER_A, 'A'), evidence(SERVER_A, 'B'))).toEqual({ valid: true });
    expect(validateInvestigationRuns(evidence(SERVER_A, 'A'), evidence(SERVER_B, 'B'))).toEqual({ valid: false, reason: 'context_mismatch' });
    expect(validateInvestigationRuns(evidence(null, 'A'), evidence(null, 'B'))).toEqual({ valid: false, reason: 'context_mismatch' });
  });

  it('keeps the identifier out of every export', () => {
    const current = snapshot(SERVER_A, [finding('a'), finding('c')], '2026-11-15T00:01:00.000Z');
    const reviewed = setAnalystReviewStatus(emptyAnalystReviewState, current.scan.findings, current.scan.findings[0].finding_id, 'reviewed')!;
    const exported = [
      createReviewMarkdown(current.context, current.scan),
      JSON.stringify(createSarifReport(current.context, current.scan)),
      createAnalystReviewBackup(current.context, current.scan, reviewed, false),
      createComparisonMarkdown(snapshot(SERVER_A), current),
    ];
    for (const text of exported) {
      expect(text).not.toContain(SERVER_A);
      expect(text).not.toMatch(/server.?instance/i);
    }
  });
});

describe('API clients attach the instance to results and errors', () => {
  beforeEach(() => { vi.stubGlobal('fetch', vi.fn()); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it('reads it from v1 results, v1 errors and v2 scan results', async () => {
    const headers = { 'Content-Type': 'application/json', 'X-Server-Instance': SERVER_A };
    vi.mocked(fetch)
      .mockResolvedValueOnce(new Response(JSON.stringify(scan([finding('a')])), { status: 200, headers }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: 'unauthorized' }), { status: 401, headers }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ contract_version: 'investigation-scan/v1', run_handle: 'H'.repeat(43), scan: scan([]) }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
    expect((await api.scan('token', 'local-project', 'baseline')).serverInstanceId).toBe(SERVER_A);
    const failure = await api.scan('token', 'local-project', 'baseline').catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ApiError);
    expect((failure as ApiError).serverInstanceId).toBe(SERVER_A);
    expect((await investigationApi.scan('token', 'local-project', 'baseline')).serverInstanceId).toBeNull();
  });
});

describe('the dashboard across a server restart', () => {
  const options = { targets: [{ id: 'local-project', label: 'Local Project' }], rule_profiles: [{ id: 'baseline', label: 'Baseline', experimental: false }] };
  let instance = SERVER_A;
  let releases: string[] = [];
  let scansServed = 0;
  const reply = (value: unknown, status = 200, from = instance) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json', 'X-Server-Instance': from } });

  function install(scanResults: Array<() => Response>) {
    vi.mocked(fetch).mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.endsWith('/health')) return reply({ status: 'ok', service: 'ai-code-security-analyzer' });
      if (url.endsWith('/options')) return reply(options);
      if (url.endsWith('/api/v1/scans') || url.endsWith('/investigation-scans')) {
        scansServed += 1;
        const next = scanResults.shift();
        if (!next) throw new Error('unexpected scan request');
        return next();
      }
      if (url.endsWith('/investigation-release')) { releases.push(JSON.parse(String(init?.body)).handle); return new Response(null, { status: 204 }); }
      throw new Error(`unexpected request ${url}`);
    });
  }
  const optionsRequests = () => vi.mocked(fetch).mock.calls.filter(([input]) => String(input).endsWith('/options')).length;

  async function scanOnce(user: ReturnType<typeof userEvent.setup>) {
    const startView = screen.queryByRole('button', { name: '검사 시작' });
    if (startView) await user.click(startView);
    await user.click(screen.getByRole('button', { name: '검사 실행' }));
  }

  beforeEach(() => { vi.stubGlobal('fetch', vi.fn()); instance = SERVER_A; releases = []; scansServed = 0; });
  afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

  it('keeps the shown result and review work, discards the other server answer and reloads the options', async () => {
    const before = scan([finding('a'), finding('b')]);
    install([() => reply(before), () => { instance = SERVER_B; return reply(before); }, () => reply(scan([finding('a')]))]);
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    const user = userEvent.setup(); render(<App/>);
    await screen.findByText('API 연결됨');
    await user.type(screen.getByLabelText('로컬 API 토큰'), 'synthetic-restart-token');
    await scanOnce(user);
    await screen.findByRole('heading', { name: '정상 완료' });
    await user.click(screen.getByRole('button', { name: /비교 기준/ }));
    await user.click(within(screen.getByRole('region', { name: 'Finding 목록' })).getByRole('button', { name: /src\/a\.js/ }));
    await user.selectOptions(screen.getByLabelText('수동 검토 상태'), 'reviewed');
    expect(optionsRequests()).toBe(1);

    // The server restarted between scans: the next answer comes from another process.
    await scanOnce(user);
    expect(await screen.findAllByText(/검사 서버가 다시 시작된 것을 확인했습니다/)).not.toHaveLength(0);
    expect(document.querySelector('.retained-result-note')).not.toBeNull();
    await user.click(within(screen.getByRole('region', { name: 'Finding 목록' })).getByRole('button', { name: /src\/a\.js/ }));
    expect(screen.getByLabelText('수동 검토 상태')).toHaveValue('reviewed');
    await vi.waitFor(() => expect(optionsRequests()).toBe(2));

    // After reloading the options the next result is accepted, but never compared with the old baseline.
    await screen.findByText('API 연결됨');
    await scanOnce(user);
    await screen.findByRole('heading', { name: '정상 완료' });
    expect(screen.getByText(/서로 다른 서버 실행에서 만들어져 비교하지 않았습니다/)).toBeInTheDocument();
    expect(screen.queryByLabelText('Finding 관찰 차이')).not.toBeInTheDocument();
    expect(scansServed).toBe(3);
  });

  it('releases evidence issued by the other server and keeps none of it', async () => {
    install([() => { instance = SERVER_B; return reply({ contract_version: 'investigation-scan/v1', run_handle: 'N'.repeat(43), scan: scan([finding('a')]) }); }]);
    const user = userEvent.setup(); render(<App/>);
    await screen.findByText('API 연결됨');
    await user.type(screen.getByLabelText('로컬 API 토큰'), 'synthetic-restart-token');
    await user.click(screen.getByText('소멸 근거 조사 선택'));
    await user.click(screen.getByLabelText('소멸 근거 조사'));
    await scanOnce(user);
    expect(await screen.findAllByText(/검사 서버가 다시 시작된 것을 확인했습니다/)).not.toHaveLength(0);
    await vi.waitFor(() => expect(releases).toEqual(['N'.repeat(43)]));
    expect(screen.queryByRole('region', { name: 'Finding 목록' })).not.toBeInTheDocument();
    expect(screen.queryByText('현재 응답에 서버 조사 증거가 연결됐습니다.')).not.toBeInTheDocument();
  });

  it('shows a result without an instance but never compares it', async () => {
    install([
      () => new Response(JSON.stringify(scan([finding('a')])), { status: 200, headers: { 'Content-Type': 'application/json' } }),
      () => reply(scan([finding('a')])),
    ]);
    const user = userEvent.setup(); render(<App/>);
    await screen.findByText('API 연결됨');
    await user.type(screen.getByLabelText('로컬 API 토큰'), 'synthetic-restart-token');
    await scanOnce(user);
    await screen.findByRole('heading', { name: '정상 완료' });
    await user.click(screen.getByRole('button', { name: /비교 기준/ }));
    await scanOnce(user);
    await screen.findByRole('heading', { name: '정상 완료' });
    expect(screen.getByText(/서버 실행 식별 정보를 확인할 수 없어 비교하지 않았습니다/)).toBeInTheDocument();
    expect(screen.queryByLabelText('Finding 관찰 차이')).not.toBeInTheDocument();
  });

  it('says plainly that a backup is not checked against the project', async () => {
    const current = scan([finding('a')]);
    install([() => reply(current)]);
    const user = userEvent.setup(); render(<App/>);
    await screen.findByText('API 연결됨');
    await user.type(screen.getByLabelText('로컬 API 토큰'), 'synthetic-restart-token');
    await scanOnce(user);
    await screen.findByRole('heading', { name: '정상 완료' });
    const context = { targetId: 'local-project', targetLabel: 'Local Project', ruleProfileId: 'baseline', ruleProfileLabel: 'Baseline', experimental: false, scanStatus: 'completed' as const, receivedAt: '2026-11-15T00:00:00.000Z' };
    const backup = createAnalystReviewBackup(context, current, emptyAnalystReviewState, false);
    await user.upload(screen.getByLabelText('검토 기록 불러오기(JSON)'), new File([backup], 'backup.json', { type: 'application/json' }));
    const preview = await screen.findByRole('region', { name: '검토 기록 복원 미리보기' });
    expect(preview).toHaveTextContent('현재 프로젝트에서 만들어졌는지 확인하지 않습니다');
    expect(screen.getByText(/같은 프로젝트에서 만든 백업인지는 확인하지 않습니다/)).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/백업을 검증했습니다/);
  });
});
