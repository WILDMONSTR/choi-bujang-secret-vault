const SAMPLE_NOTE_ID = '00000000-0000-4000-8000-000000000001';

async function readResponse(response) {
  let body = null;
  try { body = await response.json(); } catch { body = null; }
  return { status: response.status, ok: response.ok, body };
}

function safeResponseSummary(result) {
  const body = result.body;
  if (body && typeof body === 'object' && typeof body.error === 'string') {
    return { httpStatus: result.status, error: body.error };
  }
  if (Array.isArray(body)) {
    return {
      httpStatus: result.status,
      responseType: 'array',
      itemCount: body.length,
      memoBodyIncluded: body.some((item) => item && (
        Object.hasOwn(item, 'body') || Object.hasOwn(item, 'content')
      )),
    };
  }
  if (body && typeof body === 'object') {
    return {
      httpStatus: result.status,
      responseType: 'object',
      keys: Object.keys(body).filter((key) => !['body', 'content', 'title', 'token'].includes(key)).sort(),
      memoBodyIncluded: Object.hasOwn(body, 'body') || Object.hasOwn(body, 'content'),
    };
  }
  return { httpStatus: result.status, responseType: body === null ? 'empty-or-non-json' : typeof body };
}

async function fetchJson(path, options = {}) {
  const response = await fetch(path, {
    cache: 'no-store',
    redirect: 'error',
    credentials: 'same-origin',
    headers: { Accept: 'application/json', ...(options.headers || {}) },
    ...options,
  });
  return readResponse(response);
}

export function mountOperationsRoom() {
  const root = document.querySelector('#operations-room');
  if (!root) return { setVisible() {}, refresh: async () => {} };

  const outputIds = [
    'ops-live-status', 'ops-decision-result', 'ops-detection-result',
    'ops-revoke-result', 'ops-recovery-result', 'ops-anonymous-result',
    'ops-owner-result', 'ops-zone-result', 'ops-deployment-source'
  ];
  const outputs = Object.fromEntries(outputIds.map((id) => [id, document.getElementById(id)]));
  const devicesList = document.querySelector('#ops-device-list');
  const refreshButton = document.querySelector('#ops-refresh');
  const decisionButton = document.querySelector('#ops-run-decision');
  const detectionButton = document.querySelector('#ops-run-detection');
  const recoveryButton = document.querySelector('#ops-run-recovery-preview');
  const anonymousButton = document.querySelector('#ops-run-anonymous');
  const ownerButton = document.querySelector('#ops-run-owner-check');
  const zoneButton = document.querySelector('#ops-run-zone-check');
  const ownerInput = document.querySelector('#ops-owner-note-id');
  const zoneInput = document.querySelector('#ops-zone-id');
  const resultState = new Map();
  let visible = false;
  let refreshing = false;

  function show(id, value) {
    if (outputs[id]) outputs[id].textContent = typeof value === 'string'
      ? value : JSON.stringify(value, null, 2);
  }

  function remember(id, value) {
    resultState.set(id, value);
    show(id, value);
  }

  function setBusy(button, busy, label) {
    button.disabled = busy;
    if (busy) button.dataset.originalLabel = button.textContent;
    button.textContent = busy ? label : (button.dataset.originalLabel || button.textContent);
  }

  function safePolicySummary(result) {
    const body = result.body;
    if (body && typeof body.error === 'string') {
      return { httpStatus: result.status, error: body.error, passed: false };
    }
    if (!body || typeof body !== 'object') {
      return { httpStatus: result.status, responseType: 'unknown', passed: false };
    }
    return {
      httpStatus: result.status,
      canRestore: body.canRestore === true,
      restoreVersion: typeof body.restoreVersion === 'string' ? body.restoreVersion : null,
      scope: typeof body.scope === 'string' ? body.scope : 'services.learning_notes',
      changeCount: Number.isInteger(body.changeCount) ? body.changeCount : null,
      truncated: body.truncated === true,
      snapshotVerified: body.snapshotVerified === true,
      passed: result.ok && typeof body.canRestore === 'boolean',
      note: '민감할 수 있는 정책 값 자체는 화면에 펼치지 않습니다.',
    };
  }

  function renderDevices(payload) {
    devicesList.replaceChildren();
    const items = payload?.devices?.items;
    if (!Array.isArray(items)) {
      const li = document.createElement('li');
      li.textContent = '실제 기기 목록을 읽지 못했습니다.';
      devicesList.append(li);
      return;
    }
    for (const device of items) {
      const li = document.createElement('li');
      li.className = 'ops-device';
      const summary = document.createElement('div');
      const name = document.createElement('strong');
      name.textContent = String(device.label || '이름 없는 기기') + ' · ' + String(device.status || 'unknown');
      const id = document.createElement('small');
      id.textContent = '기기 ID: ' + String(device.deviceId || 'unknown');
      summary.append(name, id);
      li.append(summary);

      if (device.status === 'approved'
          && device.deviceId !== payload?.authorization?.currentDeviceId) {
        const revoke = document.createElement('button');
        revoke.type = 'button';
        revoke.className = 'secondary';
        revoke.textContent = '이 기기 회수';
        revoke.addEventListener('click', async () => {
          if (!window.confirm('선택한 기기의 승인을 회수할까요? 회수된 기기는 보호 API에 다시 접근할 수 없습니다.')) return;
          revoke.disabled = true;
          revoke.textContent = '회수 요청 중…';
          try {
            const result = await fetchJson('/api/devices/revoke', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ deviceId: device.deviceId }),
            });
            const summaryResult = safeResponseSummary(result);
            remember('ops-revoke-result', {
              executed: true,
              expected: 'HTTP 200, status=revoked',
              actual: summaryResult,
              result: result.body && {
                revoked: result.body.revoked === true,
                status: result.body.status || null,
                revocationId: result.body.revocationId || null,
                revokedAt: result.body.revokedAt || null,
                source: result.body.source || null,
              },
              passed: result.status === 200 && result.body?.revoked === true
                && result.body?.status === 'revoked',
            });
            await refresh();
          } catch (error) {
            remember('ops-revoke-result', {
              executed: true,
              error: String(error?.message || 'NETWORK_ERROR'),
              passed: false,
            });
          } finally {
            revoke.disabled = false;
            revoke.textContent = '이 기기 회수';
          }
        });
        li.append(revoke);
      }
      devicesList.append(li);
    }
  }

  async function refresh() {
    if (refreshing || !visible) return;
    refreshing = true;
    setBusy(refreshButton, true, '실제 상태를 읽는 중…');
    try {
      const result = await fetchJson('/api/stage10/operations-status');
      if (!result.ok || !result.body || typeof result.body !== 'object') {
        remember('ops-live-status', {
          executed: true,
          httpStatus: result.status,
          actual: safeResponseSummary(result),
          state: '조회 실패 — 오류 응답을 성공으로 바꾸지 않았습니다.',
        });
        renderDevices(null);
        return;
      }
      const data = result.body;
      remember('ops-live-status', {
        executed: true,
        httpStatus: result.status,
        observedAt: data.observedAt,
        authenticated: data.authorization?.authenticated === true,
        currentDeviceStatus: data.authorization?.currentDeviceStatus || 'unknown',
        deviceCounts: data.devices?.counts || null,
        recoveryHistoryAvailable: data.recovery?.available === true,
        recoveryRecordsRead: Array.isArray(data.recovery?.records) ? data.recovery.records.length : null,
        revocationHistoryAvailable: data.revocation?.available === true,
        revocationRecordsRead: Array.isArray(data.revocation?.records) ? data.revocation.records.length : null,
        externalJudgeHistoryAvailable: data.providedEngine?.resultQueryAvailable === true,
        note: '서버 API 응답에서 읽은 상태입니다. 빈 기록은 통과 판정이 아닙니다.',
      });
      renderDevices(data);
      remember('ops-revoke-result', {
        source: data.revocation?.source || 'unknown',
        historyAvailable: data.revocation?.available === true,
        records: data.revocation?.records || [],
        status: data.revocation?.available ? 'DB 감사 기록 조회 완료' : (data.revocation?.errorCode || '조회 불가'),
      });
      remember('ops-recovery-result', {
        source: data.recovery?.source || 'unknown',
        historyAvailable: data.recovery?.available === true,
        records: data.recovery?.records || [],
        status: data.recovery?.available ? 'DB 복구 감사 기록 조회 완료' : (data.recovery?.errorCode || '조회 불가'),
      });
    } catch (error) {
      remember('ops-live-status', {
        executed: true,
        error: String(error?.message || 'NETWORK_ERROR'),
        state: '실제 상태를 읽지 못했습니다. 성공으로 처리하지 않았습니다.',
      });
    } finally {
      refreshing = false;
      setBusy(refreshButton, false, '새로고침');
    }
  }

  async function runStudentCheck(path, outputId, label) {
    const button = outputId === 'ops-decision-result' ? decisionButton : detectionButton;
    setBusy(button, true, '학생 코드 실행 중…');
    try {
      const result = await fetchJson(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      const body = result.body;
      const summary = {
        executed: true,
        httpStatus: result.status,
        source: body?.source || 'source unavailable',
        mode: body?.mode || null,
        executedAt: body?.executedAt || null,
        executedCount: body?.executedCount ?? body?.inputEventCount ?? null,
        actual: outputId === 'ops-decision-result'
          ? (body?.results || [])
          : (body?.actual || null),
        expected: outputId === 'ops-decision-result'
          ? (body?.results || []).map((item) => ({ id: item.id, expected: item.expected }))
          : (body?.expected || null),
        passed: body?.allPassed === true || body?.passed === true,
        revocationPerformed: body?.revocationPerformed === true,
        note: body?.note || label,
      };
      remember(outputId, summary);
    } catch (error) {
      remember(outputId, { executed: true, error: String(error?.message || 'NETWORK_ERROR'), passed: false });
    } finally {
      setBusy(button, false, '검사 실행');
    }
  }

  decisionButton.addEventListener('click', () =>
    void runStudentCheck('/api/stage10/decision-check', 'ops-decision-result',
      '판정 결과는 학생 코드의 가상 요청 결과이며 외부 심판 점수가 아닙니다.'));
  detectionButton.addEventListener('click', () =>
    void runStudentCheck('/api/stage10/detection-check', 'ops-detection-result',
      '탐지기는 회수 제안만 계산합니다. 이 검사는 실제 권한을 회수하지 않습니다.'));

  recoveryButton.addEventListener('click', async () => {
    setBusy(recoveryButton, true, '복구 미리보기 조회 중…');
    try {
      const result = await fetchJson('/api/stage10/policy-diff');
      remember('ops-recovery-result', {
        executed: true,
        preview: safePolicySummary(result),
        note: '복원 실행이 아닙니다. 실제 복구 성공은 감사 기록과 원본 대조로 확인해야 합니다.',
      });
    } catch (error) {
      remember('ops-recovery-result', { executed: true, error: String(error?.message || 'NETWORK_ERROR'), passed: false });
    } finally {
      setBusy(recoveryButton, false, '시험 정책 복구 미리보기');
    }
  });

  anonymousButton.addEventListener('click', async () => {
    setBusy(anonymousButton, true, '익명 요청 검사 중…');
    const probes = [
      { id: 'anonymous-note-list', method: 'GET', path: '/api/notes' },
      { id: 'anonymous-note-create', method: 'POST', path: '/api/notes', body: { title: 'stage12-anonymous-probe', body: 'synthetic test only' } },
      { id: 'anonymous-note-read', method: 'GET', path: '/api/notes/' + SAMPLE_NOTE_ID },
      { id: 'anonymous-note-update', method: 'PUT', path: '/api/notes/' + SAMPLE_NOTE_ID, body: { title: 'stage12-anonymous-probe', body: 'synthetic test only' } },
      { id: 'anonymous-note-delete', method: 'DELETE', path: '/api/notes/' + SAMPLE_NOTE_ID },
    ];
    const results = [];
    try {
      for (const probe of probes) {
        const headers = { Accept: 'application/json' };
        const options = {
          method: probe.method, cache: 'no-store', redirect: 'error',
          credentials: 'omit', headers,
        };
        if (probe.body) {
          headers['Content-Type'] = 'application/json';
          options.body = JSON.stringify(probe.body);
        }
        const result = await readResponse(await fetch(probe.path, options));
        const body = result.body;
        const hasMemoBody = body && typeof body === 'object'
          && (Object.hasOwn(body, 'body') || Object.hasOwn(body, 'content'));
        results.push({
          id: probe.id,
          executed: true,
          expected: 'HTTP 401 UNAUTHORIZED without memo data',
          actual: safeResponseSummary(result),
          passed: result.status === 401 && body?.error === 'UNAUTHORIZED' && !hasMemoBody,
        });
      }
      remember('ops-anonymous-result', {
        executed: true,
        expectedCount: probes.length,
        executedCount: results.length,
        passedCount: results.filter((item) => item.passed).length,
        results,
        note: '실제 배포 API에 쿠키/인증 헤더 없이 전송한 응답입니다.',
      });
    } catch (error) {
      remember('ops-anonymous-result', {
        executed: true,
        partialResults: results,
        error: String(error?.message || 'NETWORK_ERROR'),
        note: '중단된 나머지 요청은 미실행 상태입니다.',
      });
    } finally {
      setBusy(anonymousButton, false, '익명 조회·변경 5건 검사');
    }
  });

  ownerButton.addEventListener('click', async () => {
    const raw = ownerInput.value.trim();
    const normalized = raw.replace(/^memo:/iu, '');
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(normalized)) {
      remember('ops-owner-result', { executed: false, state: '미실행', reason: '시험 계정 A의 메모 UUID 또는 memo:UUID를 입력해 주세요.' });
      return;
    }
    setBusy(ownerButton, true, '타인 메모 조회 검사 중…');
    try {
      const result = await fetchJson('/api/notes/' + encodeURIComponent('memo:' + normalized), { method: 'GET' });
      const body = result.body;
      const containsMemoBody = body && typeof body === 'object'
        && (Object.hasOwn(body, 'body') || Object.hasOwn(body, 'content'));
      remember('ops-owner-result', {
        executed: true,
        expected: 'HTTP 404 NOT_FOUND with no memo body',
        actual: { httpStatus: result.status, error: body?.error || null, memoBodyIncluded: containsMemoBody },
        passed: result.status === 404 && body?.error === 'NOT_FOUND' && !containsMemoBody,
        note: '응답 본문 자체는 표시하지 않고 메모 본문 포함 여부만 확인합니다.',
      });
    } catch (error) {
      remember('ops-owner-result', { executed: true, error: String(error?.message || 'NETWORK_ERROR'), passed: false });
    } finally {
      setBusy(ownerButton, false, '타인 메모 ID 조회');
    }
  });

  zoneButton.addEventListener('click', async () => {
    const zoneId = zoneInput.value.trim();
    if (!/^[a-z0-9][a-z0-9_-]{0,63}$/u.test(zoneId)) {
      remember('ops-zone-result', { executed: false, state: '미실행', reason: '시험 계정에 속하지 않는 테스트 구역 ID를 입력해 주세요.' });
      return;
    }
    setBusy(zoneButton, true, '구역 경계 검사 중…');
    try {
      const result = await fetchJson('/api/notes?zoneId=' + encodeURIComponent(zoneId), { method: 'GET' });
      const body = result.body;
      remember('ops-zone-result', {
        executed: true,
        expected: 'HTTP 403 ZONE_ACCESS_DENIED',
        actual: safeResponseSummary(result),
        passed: result.status === 403 && body?.error === 'ZONE_ACCESS_DENIED',
        note: '응답에 메모 본문이 있더라도 결과 화면에는 노출하지 않습니다.',
      });
    } catch (error) {
      remember('ops-zone-result', { executed: true, error: String(error?.message || 'NETWORK_ERROR'), passed: false });
    } finally {
      setBusy(zoneButton, false, '구역 밖 메모 조회');
    }
  });

  refreshButton.addEventListener('click', () => void refresh());

  async function loadDeploymentSource() {
    try {
      const result = await fetchJson('/aleph.json', { method: 'GET' });
      const data = result.body;
      if (!result.ok || !data || typeof data !== 'object') {
        show('ops-deployment-source', {
          executed: true, httpStatus: result.status,
          status: '배포 식별자를 가져오지 못함; 커밋/단계는 추정하지 않음',
        });
        return;
      }
      show('ops-deployment-source', {
        executed: true,
        httpStatus: result.status,
        schema: data.schema || null,
        step: data.step ?? null,
        repoUrl: data.repoUrl || null,
        commit: data.commit || null,
        publicAppUrl: data.publicAppUrl || null,
        sampleMarker: data.sampleMarker || null,
        judgeIssuer: data.judgeIssuer || null,
        source: '/aleph.json from the current deployment',
      });
    } catch (error) {
      show('ops-deployment-source', { executed: true, error: String(error?.message || 'NETWORK_ERROR') });
    }
  }

  async function setVisible(next) {
    visible = Boolean(next);
    root.hidden = !visible;
    if (visible) {
      await Promise.all([refresh(), loadDeploymentSource()]);
    }
  }

  // A blank output is explicitly "not run"; it never defaults to success.
  for (const id of outputIds) {
    if (outputs[id]) outputs[id].textContent = '미실행 — 실행 버튼을 눌러 실제 응답을 확인하세요.';
  }
  show('ops-live-status', '미실행 — 서버 상태를 아직 조회하지 않았습니다.');
  show('ops-decision-result', '미실행 — 학생 판정기를 아직 실행하지 않았습니다.');
  show('ops-detection-result', '미실행 — 학생 탐지기를 아직 실행하지 않았습니다.');
  show('ops-anonymous-result', '미실행 — 실제 API 요청을 아직 전송하지 않았습니다.');
  show('ops-owner-result', '미실행 — 타인 메모 ID가 필요합니다.');
  show('ops-zone-result', '미실행 — 허용되지 않은 구역 ID가 필요합니다.');
  show('ops-deployment-source', '미실행 — 배포 출처를 아직 조회하지 않았습니다.');

  return { setVisible, refresh };
}
