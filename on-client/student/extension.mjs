// 이 파일은 학생이 같은 프로젝트에서 이어서 구현합니다.
// 제공 UI를 받은 것만으로 단계 완료를 인정하지 않습니다.

// ---- 13단계 renderIdentity 전용 도우미 ----
// 화면 문구만 한국어로 바꾸고, API 상태값(compliant·active 등)은 계약 그대로 괄호 안에 함께 보여 준다.
const IDENTITY_DEVICE_TEXT = { compliant: '보안 기준 충족', noncompliant: '보안 기준 미충족', unknown: '확인 불가' };
const IDENTITY_SESSION_TEXT = { active: '활성', expired: '만료', revoked: '철회됨', unknown: '확인 불가' };
// 정상처럼 보이면 안 되는 상태. 색뿐 아니라 "주의:" 글자로도 구분한다.
const IDENTITY_WARNING_STATUS = new Set(['noncompliant', 'expired', 'revoked']);

const identityIsRecord = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const identityText = value => (typeof value === 'string' ? value.trim() : '');

// document.createElement + textContent 만 사용한다. HTML 문자열은 만들지 않는다.
function identityNode(tagName, text, className) {
  const node = document.createElement(tagName);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

// 이름(label)과 ID 를 함께 보여 준다. 이름이 없으면 ID 만, 둘 다 없으면 확인 불가.
function identityNameWithId(item, idPrefix) {
  const label = identityText(item.label);
  const id = identityText(item.id);
  if (label && id && label !== id) return `${label} (ID: ${id})`;
  if (label) return label;
  if (id) return `${idPrefix}${id}`;
  return '이름·ID 확인 불가';
}

// 상태값을 글자로 보여 준다. 모르는 값은 정상으로 보이지 않게 "확인 불가" 로 처리한다.
function identityStatusNode(table, value) {
  const code = identityText(value).slice(0, 40) || 'unknown';
  const known = Object.hasOwn(table, code);
  const warning = IDENTITY_WARNING_STATUS.has(code);
  const label = known ? table[code] : '확인 불가';
  const tone = warning ? 'state-error' : known && code !== 'unknown' ? 'state-ok' : 'state-empty';
  return identityNode('span', `${warning ? '주의: ' : ''}${label}(${code})`, tone);
}

// 자료마다 전달받은 mode 안내. loading 중 아직 mode 를 받지 못한 경우에만 안내를 생략한다.
function identityModeNote(resource) {
  const mode = identityIsRecord(resource) ? resource.mode : undefined;
  const status = identityIsRecord(resource) ? resource.status : undefined;
  if (mode === 'demo') return { text: '예제 자료(demo)', className: 'tag tag-demo' };
  if (mode === 'disconnected') return { text: '연결 없음(disconnected)', className: 'tag' };
  if (mode === 'connected') return null;
  if (mode == null && status === 'loading') return null;
  return { text: '확인 불가(unknown)', className: 'tag' };
}

// 형식 불일치(확인 불가)와 요청 실패를 구분하고, 서버 message 를 글자로만 보여 준다.
function identityErrorText(error) {
  const message = identityText(identityIsRecord(error) ? error.message : '') || '서버가 사유를 알려 주지 않았습니다.';
  const code = identityIsRecord(error) ? error.code : undefined;
  const unverified = code === 'CONTRACT_MISMATCH' || code === 'ENGINE_RESULT_UNVERIFIED';
  return `${unverified ? '확인 불가' : '연결 실패'}: ${message}`;
}

// loading / ok / error 를 자료마다 따로 처리한다. error 일 때는 이전 값을 전혀 그리지 않는다.
function identitySection(title, resource, buildBody) {
  const section = identityNode('section');
  const heading = identityNode('h3', title);
  const note = identityModeNote(resource);
  if (note) heading.append(' ', identityNode('span', note.text, note.className));
  section.append(heading);
  const status = identityIsRecord(resource) ? resource.status : undefined;
  if (status === 'loading') {
    section.append(identityNode('p', '불러오는 중', 'state state-loading'));
  } else if (status === 'error') {
    section.append(identityNode('p', identityErrorText(resource.error), 'state state-error'));
  } else if (status === 'ok') {
    section.append(buildBody(resource.data)
      || identityNode('p', '확인 불가: 응답 형식이 맞지 않아 표시하지 않습니다.', 'state state-error'));
  } else {
    section.append(identityNode('p', '확인 불가: 이 자료의 상태를 알 수 없습니다.', 'state state-empty'));
  }
  return section;
}

// 현재 로그인한 사용자·기기·세션(me)
function identityMeBody(data) {
  if (!identityIsRecord(data) || !identityIsRecord(data.user) || !identityIsRecord(data.device) || !identityIsRecord(data.session)) return null;
  const list = identityNode('dl', undefined, 'identity');
  const deviceItem = identityNode('dd');
  deviceItem.append(`${identityNameWithId(data.device, '기기 ID: ')} · `, identityStatusNode(IDENTITY_DEVICE_TEXT, data.device.status));
  const sessionItem = identityNode('dd');
  sessionItem.append(`세션 ID: ${identityText(data.session.id) || '확인 불가'} · `, identityStatusNode(IDENTITY_SESSION_TEXT, data.session.status));
  list.append(
    identityNode('dt', '사용자'), identityNode('dd', identityNameWithId(data.user, '사용자 ID: ')),
    identityNode('dt', '현재 기기'), deviceItem,
    identityNode('dt', '현재 세션'), sessionItem,
  );
  return list;
}

// 내 기기 목록(devices) / 내 세션 목록(sessions)
function identityListBody(data, kind) {
  if (!Array.isArray(data)) return null;
  const isDevice = kind === 'device';
  if (data.length === 0) return identityNode('p', isDevice ? '표시할 기기가 없습니다.' : '표시할 세션이 없습니다.', 'state state-empty');
  const list = identityNode('ul', undefined, 'plain-list');
  for (const item of data) {
    const row = identityNode('li');
    if (!identityIsRecord(item)) {
      row.append(identityNode('span', '확인 불가: 항목 형식이 맞지 않습니다.'));
    } else if (isDevice) {
      row.append(identityNode('span', identityNameWithId(item, '기기 ID: ')), identityStatusNode(IDENTITY_DEVICE_TEXT, item.status));
    } else {
      row.append(identityNode('span', `세션 ID: ${identityText(item.id) || '확인 불가'}`), identityStatusNode(IDENTITY_SESSION_TEXT, item.status));
    }
    list.append(row);
  }
  return list;
}

// 14단계 renderDecision 전용 도우미. 서버가 보낸 문자열은 DOM 텍스트로만 표시한다.
const DECISION_PRESENTATION = Object.freeze({
  allow: {
    label: '접근 허용(allow)',
    className: 'decision-allow',
    note: '정책상 허용이라는 뜻이며, 실제 앱 접속 성공을 보장하지 않습니다.',
  },
  deny: {
    label: '접근 거부(deny)',
    className: 'decision-deny',
    note: '정책상 거부 판정입니다.',
  },
  challenge: {
    label: '추가 인증 또는 확인 필요(challenge)',
    className: 'decision-challenge',
    note: '추가 인증 또는 확인이 필요합니다. 이 화면은 추가 인증을 대신 수행하지 않으며, 허용 판정도 아닙니다.',
  },
  unknown: {
    label: '판정 확인 불가(unknown)',
    className: 'decision-unknown',
    note: '판정을 확인할 수 없습니다. 허용된 것으로 간주하지 마세요.',
  },
});

const decisionIsRecord = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const decisionText = (value, maxLength = 2000) =>
  typeof value === 'string' ? value.trim().slice(0, maxLength) : '';

function decisionNode(tagName, text, className) {
  const node = document.createElement(tagName);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function decisionModeNote(resource) {
  const mode = decisionIsRecord(resource) ? resource.mode : undefined;
  const status = decisionIsRecord(resource) ? resource.status : undefined;
  if (mode == null && (status === 'idle' || status === 'loading')) return null;
  if (mode === 'demo') return { text: '예제 자료(demo)', className: 'tag tag-demo' };
  if (mode === 'disconnected') return { text: '연결 없음(disconnected)', className: 'tag' };
  if (mode === 'connected') return null;
  return { text: '확인 불가(unknown)', className: 'tag' };
}

function decisionUnverified(view, message) {
  const detail = decisionText(message, 300) || '응답 형식을 확인할 수 없습니다.';
  view.append(
    decisionNode('p', `확인 불가: ${detail}`, 'decision decision-unknown'),
    decisionNode('p', '허용된 것으로 간주하지 마세요.', 'muted'),
  );
}

function decisionDetails(data) {
  const reason = decisionText(data.reason, 2000) || '사유 정보 없음';
  const checkedAt = typeof data.checkedAt === 'string' ? data.checkedAt : '시각 정보 없음';
  const details = decisionNode('dl', undefined, 'kv');
  details.append(
    decisionNode('dt', '판정 이유'), decisionNode('dd', reason),
    decisionNode('dt', '판정 시각'), decisionNode('dd', checkedAt),
    decisionNode('dt', '대상 앱'), decisionNode('dd', data.appId),
  );
  return details;
}

// ---- 15단계 renderEvents 전용 도우미 ----
// 원천 값은 textContent로만 표시한다. 목록·필터·상세 렌더링 과정에서 입력 기록을 수정하지 않는다.
const eventIsRecord = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const eventScalar = value => {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  if (typeof value === 'boolean') return String(value);
  return '';
};

function eventNode(tagName, text, className) {
  const node = document.createElement(tagName);
  if (text !== undefined) node.textContent = String(text);
  if (className) node.className = className;
  return node;
}

function eventStateText(kind, value) {
  const code = eventScalar(value) || 'unknown';
  const labels = {
    access: { allowed: '접근 허용', denied: '접근 거부', unknown: '확인 불가' },
    session: { active: '활성', expired: '만료', revoked: '철회됨', unknown: '확인 불가' },
    device: { compliant: '보안 기준 충족', noncompliant: '보안 기준 미충족', unknown: '확인 불가' },
  };
  const table = labels[kind] || {};
  return Object.hasOwn(table, code) ? table[code] + '(' + code + ')' : '확인 불가(' + code + ')';
}

function eventKindText(value) {
  const kind = eventScalar(value);
  if (kind === 'access') return '접속 기록 (access)';
  if (kind === 'xdr') return 'XDR 경보 (xdr)';
  return '기록 종류 확인 불가 (' + (kind || 'unknown') + ')';
}

function eventAppText(value) {
  const appId = eventScalar(value);
  return appId === '' ? '앱을 확인할 수 없음 (appId 없음)' : appId;
}

function eventFilterValue(event, field) {
  if (!eventIsRecord(event)) return '';
  if (field === 'kind') return eventScalar(event.kind);
  if (field === 'appId') return eventScalar(event.appId);
  const state = eventIsRecord(event.state) ? event.state : {};
  return eventScalar(state.access);
}

function eventFilterOptionText(field, value) {
  if (field === 'kind') return value === 'access' ? '접속 기록 (access)' : value === 'xdr' ? 'XDR 경보 (xdr)' : '확인 불가 (' + (value || 'unknown') + ')';
  if (field === 'appId') return value === '' ? '앱을 확인할 수 없음 (appId 없음)' : value;
  return eventStateText('access', value);
}

function eventTimestamp(event) {
  if (!eventIsRecord(event)) return NaN;
  if (typeof event.at === 'number') {
    const timestamp = new Date(event.at).getTime();
    return Number.isFinite(timestamp) ? timestamp : NaN;
  }
  if (typeof event.at === 'string' && event.at.trim() !== '') {
    const timestamp = Date.parse(event.at);
    return Number.isFinite(timestamp) ? timestamp : NaN;
  }
  return NaN;
}

function eventAppendRecordList(parent, title, items, emptyText) {
  const block = eventNode('section');
  block.appendChild(eventNode('h5', title));
  if (!Array.isArray(items) || items.length === 0) {
    block.appendChild(eventNode('p', emptyText, 'state state-empty'));
    parent.appendChild(block);
    return;
  }
  const list = eventNode('ul', undefined, 'plain-list');
  for (const item of items) {
    const record = eventIsRecord(item) ? item : {};
    const id = eventScalar(record.id) || '확인 불가';
    const text = eventScalar(record.text);
    list.appendChild(eventNode('li', 'ID: ' + id + ' · 내용: ' + (text || '내용 없음')));
  }
  block.appendChild(list);
  parent.appendChild(block);
}

function eventBuildDetail(event) {
  const record = eventIsRecord(event) ? event : {};
  const id = eventScalar(record.id) || '확인 불가';
  const detail = eventNode('section');
  detail.setAttribute('data-student-event-detail', id);
  detail.appendChild(eventNode('h4', id + ' 상세'));

  const metadata = eventNode('dl', undefined, 'kv');
  metadata.appendChild(eventNode('dt', '사건 ID'));
  metadata.appendChild(eventNode('dd', id));
  metadata.appendChild(eventNode('dt', '앱 ID'));
  metadata.appendChild(eventNode('dd', eventAppText(record.appId)));
  detail.appendChild(metadata);

  eventAppendRecordList(detail, '근거(evidence)', record.evidence, '표시할 근거가 없습니다.');
  eventAppendRecordList(detail, '규칙(rules)', record.rules, '표시할 규칙이 없습니다.');

  const state = eventIsRecord(record.state) ? record.state : {};
  const stateList = eventNode('dl', undefined, 'kv');
  const stateRows = [
    ['접속 상태(access)', eventStateText('access', state.access)],
    ['세션 상태(session)', eventStateText('session', state.session)],
    ['기기 상태(device)', eventStateText('device', state.device)],
  ];
  for (const entry of stateRows) {
    stateList.appendChild(eventNode('dt', entry[0]));
    stateList.appendChild(eventNode('dd', entry[1]));
  }
  const stateSection = eventNode('section');
  stateSection.appendChild(eventNode('h5', '상태(state)'));
  stateSection.appendChild(stateList);
  detail.appendChild(stateSection);

  const supportedActions = Array.isArray(record.supportedActions)
    ? record.supportedActions.filter(action => typeof action === 'string' && STATUS_SAFE_CODE.test(action))
    : [];
  if (supportedActions.length > 0) {
    const actionSection = eventNode('section');
    actionSection.appendChild(eventNode('h5', '지원되지 않는 조치'));
    actionSection.appendChild(eventNode('p', '조치 실행 연결은 준비 중입니다. 아래 버튼은 비활성 안내이며 요청을 전송하지 않습니다.', 'muted'));
    const actionList = eventNode('ul', undefined, 'plain-list');
    for (const action of supportedActions) {
      const item = eventNode('li');
      const unsupportedButton = eventNode('button', action + ' 미지원');
      unsupportedButton.type = 'button';
      unsupportedButton.disabled = true;
      item.appendChild(unsupportedButton);
      actionList.appendChild(item);
    }
    actionSection.appendChild(actionList);
    detail.appendChild(actionSection);
  }
  return detail;
}

// ---- 16단계 renderStatus 전용 도우미 ----
// 진단 결과는 허용 목록의 여섯 값만 표시·복사하고, 출처가 달라도 다른 필드는 전달하지 않는다.
const STATUS_SAFE_CODE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/;
const STATUS_SAFE_DIAGNOSTIC_VALUE = /^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,159}$/;
const STATUS_RESOURCE_LABELS = Object.freeze({
  me: '로그인 정보',
  apps: '업무 앱',
  events: '보안 기록',
  devices: '기기',
  sessions: '세션',
  access: '접속 판정',
  diagnostics: '도움정보',
  vulnerabilities: '설치 패키지 조회',
});

function statusSafeCode(value) {
  return typeof value === 'string' && STATUS_SAFE_CODE.test(value) ? value : '확인 불가';
}

function statusResourceText(value) {
  const code = statusSafeCode(value);
  if (code === '확인 불가') return '확인 불가';
  const label = STATUS_RESOURCE_LABELS[code];
  return label ? label + ' (' + code + ')' : code;
}

function statusErrorInfo(resource) {
  const error = eventIsRecord(resource && resource.error) ? resource.error : {};
  const code = statusSafeCode(error.code);
  const message = eventScalar(error.message).slice(0, 800) || '서버가 오류 메시지를 제공하지 않았습니다.';
  const timeout = (typeof error.code === 'string' && /TIMEOUT/i.test(error.code))
    || /시간\s*초과|초과됐|timeout/i.test(message);
  const unverified = ['CONTRACT_MISMATCH', 'ENGINE_RESULT_UNVERIFIED'].includes(error.code);
  return { code: code, message: message, timeout: timeout, unverified: unverified };
}

function statusRetryNote(resourceName) {
  if (resourceName === '도움정보') {
    return '다시 확인하려면 제공 화면의 「도움정보 불러오기」 버튼을 직접 누르세요.';
  }
  return '다시 시도하려면 위쪽 「다시 불러오기」 버튼을 직접 누르세요.';
}

function statusRenderResourceError(section, resourceName, resource) {
  const error = statusErrorInfo(resource);
  if (error.unverified) {
    section.appendChild(eventNode('p', '확인 불가: ' + resourceName + ' 응답을 검증할 수 없습니다.' + (error.message ? ' 세부 정보: ' + error.message : ''), 'state state-empty'));
  } else {
    const objectPhrase = { 기기: '기기를', 세션: '세션을', 도움정보: '도움정보를' }[resourceName] || resourceName;
    const timeoutNote = error.timeout ? ' (시간 초과)' : '';
    const codeNote = error.code !== '확인 불가' ? ' [' + error.code + ']' : '';
    section.appendChild(eventNode('p', objectPhrase + ' 불러오지 못했습니다' + timeoutNote + codeNote + ': ' + error.message, 'state state-error'));
  }
  section.appendChild(eventNode('p', statusRetryNote(resourceName), 'muted'));
}

function statusRenderDevices(resource) {
  const section = eventNode('section');
  section.appendChild(eventNode('h4', '내 기기'));
  if (!eventIsRecord(resource)) {
    section.appendChild(eventNode('p', '확인 불가: 기기 조회 상태를 확인할 수 없습니다.', 'state state-empty'));
  } else if (resource.status === 'loading') {
    section.appendChild(eventNode('p', '기기를 불러오는 중입니다.', 'state state-loading'));
  } else if (resource.status === 'error') {
    statusRenderResourceError(section, '기기', resource);
  } else if (resource.status === 'ok' && Array.isArray(resource.data)) {
    if (resource.data.length === 0) {
      section.appendChild(eventNode('p', '등록된 기기가 없습니다.', 'state state-empty'));
    } else {
      const list = eventNode('ul', undefined, 'plain-list');
      for (const value of resource.data) {
        const item = eventIsRecord(value) ? value : {};
        const label = eventScalar(item.label) || '이름 확인 불가';
        list.appendChild(eventNode('li', '기기: ' + label + ' · 상태: ' + eventStateText('device', item.status)));
      }
      section.appendChild(list);
    }
  } else {
    section.appendChild(eventNode('p', '확인 불가: 기기 응답 형식 또는 조회 상태가 올바르지 않습니다.', 'state state-empty'));
  }
  return section;
}

function statusRenderSessions(resource) {
  const section = eventNode('section');
  section.appendChild(eventNode('h4', '현재 세션'));
  section.appendChild(eventNode('p', '현재 검증된 연결 한 개만 표시합니다. 과거 세션 전체 목록은 아닙니다.', 'muted'));
  if (!eventIsRecord(resource)) {
    section.appendChild(eventNode('p', '확인 불가: 세션 조회 상태를 확인할 수 없습니다.', 'state state-empty'));
  } else if (resource.status === 'loading') {
    section.appendChild(eventNode('p', '세션 정보를 불러오는 중입니다.', 'state state-loading'));
  } else if (resource.status === 'error') {
    statusRenderResourceError(section, '세션', resource);
  } else if (resource.status === 'ok' && Array.isArray(resource.data)) {
    if (resource.data.length === 0) {
      section.appendChild(eventNode('p', '현재 연결이 없습니다.', 'state state-empty'));
    } else {
      const list = eventNode('ul', undefined, 'plain-list');
      for (const value of resource.data) {
        const item = eventIsRecord(value) ? value : {};
        const id = eventScalar(item.id) || '확인 불가';
        list.appendChild(eventNode('li', '세션 ID: ' + id + ' · 상태: ' + eventStateText('session', item.status)));
      }
      section.appendChild(list);
    }
  } else {
    section.appendChild(eventNode('p', '확인 불가: 세션 응답 형식 또는 조회 상태가 올바르지 않습니다.', 'state state-empty'));
  }
  return section;
}

function statusDiagnosticValue(value) {
  if (typeof value !== 'string' || !STATUS_SAFE_DIAGNOSTIC_VALUE.test(value)) {
    return { value: '확인 불가(안전하지 않은 값 생략)', safe: false };
  }
  return { value: value, safe: true };
}

function statusDiagnosticsSection(resource) {
  const section = eventNode('section');
  section.appendChild(eventNode('h4', '진단 정보'));
  const copyStatus = eventNode('p', '도움정보 복사는 허용된 진단 요약을 도움 요청에 사용할 수 있도록 클립보드에 복사합니다. 자동 전송하지 않습니다.', 'muted');
  let copyText = '';
  let canCopy = false;

  if (!eventIsRecord(resource)) {
    section.appendChild(eventNode('p', '확인 불가: 진단 조회 상태를 확인할 수 없습니다.', 'state state-empty'));
  } else if (resource.status === 'loading') {
    section.appendChild(eventNode('p', '도움정보를 불러오는 중입니다.', 'state state-loading'));
  } else if (resource.status === 'error') {
    statusRenderResourceError(section, '도움정보', resource);
  } else if (resource.status === 'idle') {
    section.appendChild(eventNode('p', '도움정보는 아직 조회되지 않았습니다. 필요할 때 제공 화면의 「도움정보 불러오기」 버튼을 직접 누르세요.', 'state state-empty'));
  } else if (resource.status === 'ok' && eventIsRecord(resource.data)) {
    const data = resource.data;
    const engine = eventIsRecord(data.engine) ? data.engine : {};
    const requestId = statusDiagnosticValue(data.requestId);
    const component = statusDiagnosticValue(data.component);
    const version = statusDiagnosticValue(data.version);
    const checkedAt = statusDiagnosticValue(data.checkedAt);
    const engineMode = statusDiagnosticValue(engine.mode);
    const engineCode = statusDiagnosticValue(engine.code);
    const entries = [
      ['요청 ID (requestId)', requestId],
      ['구성요소 (component)', component],
      ['버전 (version)', version],
      ['확인 시각 (checkedAt)', checkedAt],
      ['엔진 모드 (engine.mode)', engineMode],
      ['엔진 코드 (engine.code)', engineCode],
    ];
    const details = eventNode('dl', undefined, 'kv');
    let safeValueCount = 0;
    for (const entry of entries) {
      details.appendChild(eventNode('dt', entry[0]));
      details.appendChild(eventNode('dd', entry[1].value));
      if (entry[1].safe) safeValueCount += 1;
    }
    // 복사 자료는 허용한 필드만으로 새로 구성한다. ai, 설정, 인증정보 등 추가 필드는 복사하지 않는다.
    copyText = JSON.stringify({
      requestId: requestId.safe ? data.requestId : '확인 불가',
      component: component.safe ? data.component : '확인 불가',
      version: version.safe ? data.version : '확인 불가',
      checkedAt: checkedAt.safe ? data.checkedAt : '확인 불가',
      engine: {
        mode: engineMode.safe ? engine.mode : '확인 불가',
        code: engineCode.safe ? engine.code : '확인 불가',
      },
    }, null, 2);
    canCopy = safeValueCount > 0;
    section.appendChild(details);
    if (!canCopy) section.appendChild(eventNode('p', '확인 불가: 진단 응답 형식 또는 조회 상태가 올바르지 않습니다. 안전하게 복사할 수 있는 진단 값이 없어 복사가 비활성화되었습니다.', 'state state-empty'));
  } else {
    section.appendChild(eventNode('p', '확인 불가: 진단 응답 형식 또는 조회 상태가 올바르지 않습니다.', 'state state-empty'));
  }

  const copyButton = eventNode('button', '도움정보 복사');
  copyButton.type = 'button';
  copyButton.disabled = !canCopy;
  copyButton.addEventListener('click', async () => {
    if (!canCopy || !copyText) return;
    try {
      if (typeof navigator === 'undefined' || !navigator.clipboard || typeof navigator.clipboard.writeText !== 'function') {
        throw new Error('CLIPBOARD_UNAVAILABLE');
      }
      await navigator.clipboard.writeText(copyText);
      copyStatus.textContent = '허용된 진단 요약을 클립보드에 복사했습니다. 자동 전송하지 않았습니다.';
      copyStatus.className = 'state state-ok';
    } catch {
      copyStatus.textContent = '클립보드 복사에 실패했습니다. 브라우저의 클립보드 권한을 확인하세요.';
      copyStatus.className = 'state state-error';
    }
  });
  section.appendChild(copyStatus);
  section.appendChild(copyButton);
  return section;
}

function statusRenderNotifications(notifications) {
  const section = eventNode('section');
  section.appendChild(eventNode('h4', '알림'));
  if (!Array.isArray(notifications)) {
    section.appendChild(eventNode('p', '확인 불가: 알림 자료의 형식이 올바르지 않습니다.', 'state state-empty'));
    return section;
  }
  if (notifications.length === 0) {
    section.appendChild(eventNode('p', '주의할 알림이 없습니다.', 'state state-empty'));
    return section;
  }
  const list = eventNode('ul', undefined, 'plain-list');
  for (const value of notifications) {
    const item = eventIsRecord(value) ? value : {};
    const code = statusSafeCode(item.code);
    const message = eventScalar(item.message).slice(0, 1200) || '메시지 확인 불가';
    const row = eventNode('li');
    row.appendChild(eventNode('p', '자료(resource): ' + statusResourceText(item.resource)));
    row.appendChild(eventNode('p', '코드(code): ' + code));
    row.appendChild(eventNode('p', '메시지(message): ' + message));
    list.appendChild(row);
  }
  section.appendChild(list);
  return section;
}

export function createStudentView() {
  return {
    // 입력 { me, devices, sessions } 는 각각 { status, mode, data?, error? }. 호출할 때마다 새 DOM 요소 하나를 만들어
    // 돌려주므로(이전 값을 저장·재사용하지 않음) 다시 불러오면 이전 사용자·기기·세션 표시는 통째로 교체된다.
    renderIdentity(input) {
      const { me, devices, sessions } = identityIsRecord(input) ? input : {};
      const view = identityNode('div');
      view.append(
        identitySection('현재 로그인', me, identityMeBody),
        identitySection('내 기기 목록', devices, data => identityListBody(data, 'device')),
        identitySection('내 세션 목록', sessions, data => identityListBody(data, 'session')),
      );
      return view;
    },
    renderDecision(input) {
      const resource = decisionIsRecord(input) ? input : { status: 'unknown' };
      const view = decisionNode('div');
      const heading = decisionNode('h3', '접속 판정');
      const modeNote = decisionModeNote(resource);
      if (modeNote) heading.append(' ', decisionNode('span', modeNote.text, modeNote.className));
      view.append(heading);

      const status = resource.status;
      if (status === 'idle') {
        view.append(decisionNode('p', '앱을 골라 접속을 요청하세요', 'state state-empty'));
        return view;
      }
      if (status === 'loading') {
        const appId = decisionText(resource.appId, 80) || '확인 불가';
        view.append(
          decisionNode('p', '판정 확인 중', 'state state-loading'),
          decisionNode('p', `대상 앱 ID: ${appId}`, 'muted'),
        );
        return view;
      }
      if (status === 'error') {
        const error = decisionIsRecord(resource.error) ? resource.error : {};
        const code = typeof error.code === 'string' ? error.code : '';
        const message = decisionText(error.message, 300) || '요청 사유를 확인할 수 없습니다.';
        if (code === 'CONTRACT_MISMATCH' || code === 'ENGINE_RESULT_UNVERIFIED') {
          decisionUnverified(view, message);
        } else {
          view.append(
            decisionNode('p', `요청 실패: ${message}`, 'decision decision-failed'),
            decisionNode('p', '접근 거부 판정이 아니며 허용 판정도 아닙니다.', 'muted'),
          );
        }
        return view;
      }
      if (status !== 'ok') {
        decisionUnverified(view, '판정 상태를 알 수 없어 결과를 표시하지 않습니다.');
        return view;
      }

      const data = resource.data;
      const requestedAppId = typeof resource.appId === 'string' ? resource.appId : '';
      if (!decisionIsRecord(data) || !requestedAppId || data.appId !== requestedAppId) {
        decisionUnverified(view, '응답의 대상 앱 ID가 요청한 앱 ID와 일치하지 않습니다.');
        return view;
      }

      const value = typeof data.decision === 'string' ? data.decision : '';
      const known = Object.hasOwn(DECISION_PRESENTATION, value);
      const presentation = known ? DECISION_PRESENTATION[value] : DECISION_PRESENTATION.unknown;
      const result = decisionNode('p', undefined, `decision ${presentation.className}`);
      result.append(decisionNode('strong', presentation.label), ` · 대상 앱 ID: ${data.appId}`);
      view.append(result, decisionNode('p', presentation.note, 'muted'));

      if (!known) {
        const received = decisionText(value, 300) || '[형식 불일치]';
        view.append(decisionNode('p', `수신한 값: ${received}`, 'muted'));
      }
      view.append(decisionDetails(data));
      return view;
    },
    renderEvents(input) {
      const resource = eventIsRecord(input) ? input : { status: 'unknown' };
      const view = eventNode('div');
      const heading = eventNode('h3', '접속 기록·XDR 경보');
      const modeNote = identityModeNote(resource);
      if (modeNote) heading.appendChild(eventNode('span', ' ' + modeNote.text, modeNote.className));
      view.appendChild(heading);

      const status = resource.status;
      const error = eventIsRecord(resource.error) ? resource.error : {};
      const errorCode = eventScalar(error.code);
      const errorMessage = eventScalar(error.message) || (typeof resource.error === 'string' ? resource.error : '') || '서버가 오류 메시지를 제공하지 않았습니다.';

      if (status === 'loading') {
        view.appendChild(eventNode('p', '기록을 불러오는 중입니다.', 'state state-loading'));
        return view;
      }
      if (status === 'CONTRACT_MISMATCH' || errorCode === 'CONTRACT_MISMATCH') {
        const message = eventScalar(error.message);
        view.appendChild(eventNode('p', '확인 불가: 응답 형식이 맞지 않아 기록을 표시하지 않습니다.', 'state state-empty'));
        if (message) view.appendChild(eventNode('p', '세부 정보: ' + message.slice(0, 500), 'muted'));
        return view;
      }
      if (status === 'error') {
        view.appendChild(eventNode('p', '기록을 불러오지 못했습니다: ' + errorMessage.slice(0, 500), 'state state-error'));
        return view;
      }
      if (status === 'idle') {
        view.appendChild(eventNode('p', '기록 조회 대기 중입니다.', 'state state-empty'));
        return view;
      }
      if (status !== 'ok') {
        view.appendChild(eventNode('p', '확인 불가: 기록 조회 상태를 확인할 수 없습니다.', 'state state-empty'));
        return view;
      }
      if (!Array.isArray(resource.data)) {
        view.appendChild(eventNode('p', '확인 불가: 응답 형식이 맞지 않아 기록을 표시하지 않습니다.', 'state state-empty'));
        return view;
      }
      if (resource.data.length === 0) {
        view.appendChild(eventNode('p', '표시할 기록이 없습니다.', 'state state-empty'));
        return view;
      }

      // 입력 배열의 복사본을 정렬한다. 유효한 시각은 최신순, 시각을 해석할 수 없는 기록은 입력 순서를 유지해 뒤에 둔다.
      const events = resource.data.map((event, index) => ({
        event,
        index,
        timestamp: eventTimestamp(event),
      })).sort((left, right) => {
        const leftValid = Number.isFinite(left.timestamp);
        const rightValid = Number.isFinite(right.timestamp);
        if (leftValid && rightValid && left.timestamp !== right.timestamp) return right.timestamp - left.timestamp;
        if (leftValid !== rightValid) return leftValid ? -1 : 1;
        return left.index - right.index;
      }).map(entry => entry.event);

      const filterPanel = eventNode('div', undefined, 'event-filters');
      const resultArea = eventNode('div');
      const detailArea = eventNode('div');
      const filters = { kind: 'all', appId: 'all', access: 'all' };
      const filterSelects = {};

      function makeFilter(labelText, field) {
        const label = eventNode('label', labelText + ' ');
        const select = document.createElement('select');
        select.setAttribute('aria-label', labelText);
        const allOption = document.createElement('option');
        allOption.value = 'all';
        allOption.textContent = '전체';
        select.appendChild(allOption);

        const values = [];
        for (const event of events) {
          const value = eventFilterValue(event, field);
          if (!values.includes(value)) values.push(value);
        }
        for (const value of values) {
          const option = document.createElement('option');
          option.value = value;
          option.textContent = eventFilterOptionText(field, value);
          select.appendChild(option);
        }
        select.value = 'all';
        label.appendChild(select);
        filterSelects[field] = select;
        select.addEventListener('change', () => {
          filters[field] = select.value;
          renderFilteredRows();
        });
        filterPanel.appendChild(label);
      }

      makeFilter('기록 종류', 'kind');
      makeFilter('업무 앱', 'appId');
      makeFilter('접속 상태', 'access');

      function renderFilteredRows() {
        resultArea.textContent = '';
        detailArea.textContent = '';
        const visible = events.filter(event => {
          return (filters.kind === 'all' || eventFilterValue(event, 'kind') === filters.kind)
            && (filters.appId === 'all' || eventFilterValue(event, 'appId') === filters.appId)
            && (filters.access === 'all' || eventFilterValue(event, 'access') === filters.access);
        });

        if (visible.length === 0) {
          resultArea.appendChild(eventNode('p', '필터 조건에 맞는 기록이 없습니다.', 'state state-empty'));
          return;
        }

        const list = eventNode('ul', undefined, 'plain-list');
        for (const event of visible) {
          const record = eventIsRecord(event) ? event : {};
          const id = eventScalar(record.id) || '확인 불가';
          const time = eventScalar(record.at) || '시각 확인 불가';
          const appId = eventAppText(record.appId);
          const summary = eventScalar(record.summary) || '요약 없음';
          const row = eventNode('li');
          row.setAttribute('data-student-event-id', id);
          row.appendChild(eventNode('p', '사건 ID: ' + id + ' · 시각: ' + time + ' · 종류: ' + eventKindText(record.kind) + ' · 앱: ' + appId));
          row.appendChild(eventNode('p', '요약: ' + summary));

          const button = eventNode('button', id + ' 상세');
          button.type = 'button';
          button.addEventListener('click', () => {
            detailArea.textContent = '';
            detailArea.appendChild(eventBuildDetail(record));
          });
          row.appendChild(button);
          list.appendChild(row);
        }
        resultArea.appendChild(list);
      }

      view.appendChild(filterPanel);
      view.appendChild(resultArea);
      view.appendChild(detailArea);
      renderFilteredRows();
      return view;
    },
    renderStatus(input) {
      const resource = eventIsRecord(input) ? input : {};
      const view = eventNode('div');
      const heading = eventNode('h3', '상태·알림·진단 정보');
      const modeNote = identityModeNote({ mode: resource.mode, status: 'ok' });
      if (modeNote) heading.appendChild(eventNode('span', ' ' + modeNote.text, modeNote.className));
      view.appendChild(heading);
      view.appendChild(statusRenderDevices(resource.devices));
      view.appendChild(statusRenderSessions(resource.sessions));
      view.appendChild(statusRenderNotifications(resource.notifications));
      view.appendChild(statusDiagnosticsSection(resource.diagnostics));
      return view;
    },
    renderVulnerabilities(input) {
      const resource = eventIsRecord(input) ? input : {};
      const view = eventNode('div');
      view.setAttribute('aria-live', 'polite');
      view.appendChild(eventNode('h3', '설치 패키지 취약점 조회'));

      const mode = eventScalar(resource.mode).trim();
      if (mode === 'demo') {
        view.appendChild(eventNode('p', '예제 데이터(demo) · 실제 연결 아님', 'tag tag-demo'));
      } else if (mode === 'disconnected') {
        view.appendChild(eventNode('p', '연결 없음(disconnected)', 'tag'));
      } else if (mode !== '' && mode !== 'connected') {
        view.appendChild(eventNode('p', '연결 상태 확인 불가(unknown)', 'tag'));
      }

      const secretPattern = /(?:\bBearer\s+\S+|-----BEGIN [A-Z ]*PRIVATE KEY-----|\bsk-(?:proj-|ant-|svcacct-)?[A-Za-z0-9_-]{8,}|(?:api[_ -]?key|authorization|password|token|비밀번호|토큰)\s*[:=]\s*\S+)/i;
      const controlPattern = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;
      const safeText = (value, maxLength = 800) => {
        const text = eventScalar(value).trim();
        return text && text.length <= maxLength && !secretPattern.test(text) && !controlPattern.test(text) ? text : '';
      };
      const packageNamePattern = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
      const exactVersionPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;

      if (resource.status === 'idle') {
        view.appendChild(eventNode('p', '조회 전(idle)', 'state state-empty'));
        view.appendChild(eventNode('p', '아직 OSV 취약점 조회를 실행하지 않았습니다.', 'muted'));
        return view;
      }
      if (resource.status === 'loading') {
        view.appendChild(eventNode('p', '조회 중(loading)', 'state state-loading'));
        view.appendChild(eventNode('p', '조회가 끝날 때까지 이전 표를 현재 결과로 표시하지 않습니다.', 'muted'));
        return view;
      }
      if (resource.status === 'error') {
        const error = eventIsRecord(resource.error) ? resource.error : {};
        const rawMessage = eventScalar(error.message).trim();
        const message = safeText(rawMessage) || (rawMessage ? '오류 메시지를 안전하게 표시할 수 없습니다.' : '서버가 오류 메시지를 제공하지 않았습니다.');
        view.appendChild(eventNode('p', '조회 실패(error)', 'state state-error'));
        view.appendChild(eventNode('p', '조회 실패: ' + message, 'state state-error'));
        view.appendChild(eventNode('p', '이전 조회 결과는 현재 결과가 아닙니다. 필요하면 제공 화면에서 직접 다시 조회하세요.', 'muted'));
        return view;
      }
      if (resource.status !== 'ok') {
        view.appendChild(eventNode('p', '확인 불가: 조회 상태를 알 수 없습니다.', 'state state-empty'));
        return view;
      }

      const data = eventIsRecord(resource.data) ? resource.data : null;
      if (!data || !Array.isArray(data.packages)) {
        view.appendChild(eventNode('p', '확인 불가: 조회 응답 형식이 공식 입력 계약과 일치하지 않습니다.', 'state state-error'));
        return view;
      }

      const scanStatus = safeText(data.status, 80);
      const scanStatusLabels = {
        complete: '모두 조회',
        partial: '일부 조회 실패',
        not_checked: '아직 조회 안 함',
        not_configured: '조회 준비 미완료',
        unverifiable: '잠금 파일 확인 불가',
      };
      const scanStatusNotes = {
        complete: '허용된 조회 범위의 패키지 조회가 완료되었습니다.',
        partial: '일부 패키지 조회에 실패했습니다. 이미 받은 취약점 ID는 그대로 표시합니다.',
        not_checked: '승인된 공개 조회 대상이 없어 아직 조회하지 않았습니다.',
        not_configured: '조회 대상 프로젝트 설정이 필요합니다. 담당자에게 설정을 요청하세요.',
        unverifiable: 'package-lock.json을 확인할 수 없어 설치 목록과 정확한 버전을 검증하지 못했습니다.',
      };
      if (!Object.hasOwn(scanStatusLabels, scanStatus)) {
        view.appendChild(eventNode('p', '확인 불가: 전체 조회 상태를 해석할 수 없습니다(' + (scanStatus || 'unknown') + ').', 'state state-error'));
        return view;
      }

      const scanTone = scanStatus === 'complete' ? 'state state-ok'
        : scanStatus === 'partial' ? 'state state-error'
          : 'state state-empty';
      view.appendChild(eventNode('p', '전체 조회 상태: ' + scanStatusLabels[scanStatus] + '(' + scanStatus + ')', scanTone));
      view.appendChild(eventNode('p', scanStatusNotes[scanStatus], scanStatus === 'partial' ? 'state state-error' : 'muted'));

      const metadata = eventNode('dl', undefined, 'kv');
      let metadataCount = 0;
      const addMetadata = (label, value) => {
        if (value === undefined || value === null) return;
        const display = safeText(value, 300);
        if (!display) return;
        metadata.appendChild(eventNode('dt', label));
        metadata.appendChild(eventNode('dd', display));
        metadataCount += 1;
      };
      addMetadata('잠금 파일 버전(lockfileVersion)', data.lockfileVersion);
      addMetadata('잠금 파일 해시(lockfileHash)', data.lockfileHash);
      addMetadata('전체 조회 시각(checkedAt)', data.checkedAt);
      if (metadataCount > 0) view.appendChild(metadata);

      const packageStatusLabels = {
        known_vulnerabilities: '알려진 취약점 항목 있음',
        none_found: '조회 범위에서 알려진 취약점 항목 없음',
        unverifiable: '조회 확인 불가',
      };
      const table = eventNode('table');
      const head = eventNode('thead');
      const headerRow = eventNode('tr');
      for (const label of ['패키지', '정확한 설치 버전', '패키지 조회 상태', '출처(source)', '패키지 확인 시각(checkedAt)', '취약점 ID', '수정 시각(modified)']) {
        headerRow.appendChild(eventNode('th', label));
      }
      head.appendChild(headerRow);
      table.appendChild(head);
      const body = eventNode('tbody');

      for (const value of data.packages) {
        const pkg = eventIsRecord(value) ? value : {};
        const rawName = safeText(pkg.name, 214);
        const name = rawName && packageNamePattern.test(rawName) ? rawName : '';
        const rawVersion = safeText(pkg.version, 100);
        const version = rawVersion && exactVersionPattern.test(rawVersion) ? rawVersion : '';
        const packageStatus = safeText(pkg.status, 80);
        const source = safeText(pkg.source, 300) || '확인 불가';
        const packageCheckedAt = safeText(pkg.checkedAt, 120) || '확인 불가';
        const findings = Array.isArray(pkg.vulnerabilities) && pkg.vulnerabilities.length > 0
          ? pkg.vulnerabilities
          : [null];
        let statusText = Object.hasOwn(packageStatusLabels, packageStatus)
          ? packageStatusLabels[packageStatus] + '(' + packageStatus + ')'
          : '확인 불가(' + (packageStatus || 'unknown') + ')';
        if (packageStatus === 'unverifiable' && Array.isArray(pkg.vulnerabilities) && pkg.vulnerabilities.length > 0) {
          statusText = '일부 확인·전체 조회 확인 불가(unverifiable)';
        }

        for (const findingValue of findings) {
          const finding = eventIsRecord(findingValue) ? findingValue : null;
          const row = eventNode('tr');
          row.setAttribute('data-student-package-name', name);
          row.setAttribute('data-student-package-version', version);
          row.appendChild(eventNode('td', name || '확인 불가'));
          row.appendChild(eventNode('td', version || '확인 불가(정확한 설치 버전 아님)'));
          row.appendChild(eventNode('td', statusText));
          row.appendChild(eventNode('td', source));
          row.appendChild(eventNode('td', packageCheckedAt));
          row.appendChild(eventNode('td', finding ? safeText(finding.id, 160) : ''));
          row.appendChild(eventNode('td', finding ? (safeText(finding.modified, 120) || '확인 불가') : ''));
          body.appendChild(row);
        }
      }

      if (data.packages.length > 0) {
        table.appendChild(body);
        view.appendChild(table);
      } else {
        view.appendChild(eventNode('p', '표시할 패키지 조회 결과가 없습니다.', 'state state-empty'));
      }
      view.appendChild(eventNode('p', 'OSV는 알려진 취약점 데이터베이스입니다. 조회 범위에서 알려진 항목이 없더라도 해당 패키지나 앱 전체의 안전성을 보장하지 않습니다.', 'muted'));
      return view;
    },
    renderAiConnection(input) {
      const resource = eventIsRecord(input) ? input : {};
      const view = eventNode('div');
      view.appendChild(eventNode('h3', '앱 내부 AI 연결 점검'));

      if (resource.status === 'idle') {
        view.appendChild(eventNode('p', 'AI 연결 점검 전', 'state state-empty'));
        view.appendChild(eventNode('p', '다시 점검하려면 「현재 API 연결 점검」을 직접 누르세요. 자동 재점검은 하지 않습니다.', 'muted'));
        return view;
      }
      if (resource.status === 'loading') {
        view.appendChild(eventNode('p', 'AI 연결 점검 중', 'state state-loading'));
        view.appendChild(eventNode('p', '점검 중 취소할 수 있습니다. 취소되거나 오래된 응답은 현재 결과로 표시하지 않습니다.', 'muted'));
        return view;
      }
      if (resource.status === 'error') {
        const error = eventIsRecord(resource.error) ? resource.error : {};
        const rawCode = eventScalar(error.code);
        const code = /^[A-Z][A-Z0-9_]{0,79}$/.test(rawCode) ? rawCode : 'AI_REQUEST_UNVERIFIED';
        const rawMessage = eventScalar(error.message).trim().slice(0, 800);
        const secretPattern = /(?:\bBearer\s+\S+|-----BEGIN [A-Z ]*PRIVATE KEY-----|\bsk-(?:proj-|ant-|svcacct-)?[A-Za-z0-9_-]{8,}|(?:api[_ -]?key|authorization|password|비밀번호|토큰)\s*[:=]\s*\S+)/i;
        const message = rawMessage && !secretPattern.test(rawMessage) && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(rawMessage)
          ? rawMessage
          : '오류 메시지를 안전하게 표시할 수 없습니다.';

        const permissionCodes = new Set(['ON_AI_PROVISIONING_PENDING', 'ON_AI_AUTHORIZATION_CHANGED', 'SUBJECT_SCOPE_UNVERIFIED', 'AI_REQUEST_UNVERIFIED']);
        const authenticationCodes = new Set(['WB_CLCO_AUTH_REQUIRED', 'WB_CLCO_INVALID_TOKEN']);
        const accessCodes = new Set(['WB_CLCO_ACCESS_BLOCKED']);
        const limitCodes = new Set(['WB_CLCO_COHORT_BUDGET_EXHAUSTED', 'WB_CLCO_LIMIT_REACHED']);
        const timeCodes = new Set(['WB_CLCO_SESSION_CLOSED']);
        const retryCodes = new Set(['WB_CLCO_RATE_LIMITED', 'WB_CLCO_TIMEOUT', 'REQUEST_TIMEOUT', 'ENGINE_TIMEOUT', 'TIMEOUT', 'WB_CLCO_NETWORK_ERROR', 'WB_CLCO_SERVER_UNAVAILABLE']);
        const cancelCodes = new Set(['WB_CLCO_CANCELLED', 'CANCELLED', 'REQUEST_CANCELLED']);
        const modelCodes = new Set(['MODEL_NOT_CONFIGURED', 'ON_AI_MODEL_LIST_EMPTY']);
        let guidance = '오류 원인을 구분할 수 없습니다. 담당자에게 계정 연결과 앱 권한 확인을 요청하세요.';
        if (permissionCodes.has(code)) {
          guidance = '학생 계정 연결과 앱 이용 권한의 발급·준비 상태를 담당자에게 확인 요청하세요.';
        } else if (authenticationCodes.has(code)) {
          guidance = '계정 연결을 다시 확인하고, 담당자에게 앱 전용 인증 상태를 확인 요청하세요.';
        } else if (accessCodes.has(code)) {
          guidance = '담당자에게 학생 앱의 이용 권한과 접근 제한 상태를 확인 요청하세요.';
        } else if (limitCodes.has(code)) {
          guidance = '담당자에게 반 사용량과 이용 한도를 확인 요청하세요.';
        } else if (timeCodes.has(code)) {
          guidance = '허용된 AI 이용 시간을 확인하세요.';
        } else if (retryCodes.has(code)) {
          guidance = '잠시 뒤 「현재 API 연결 점검」을 직접 눌러 다시 점검하세요. 자동 재점검은 하지 않습니다.';
        } else if (cancelCodes.has(code)) {
          guidance = '요청이 취소되었습니다. 이전 결과는 현재 결과가 아닙니다. 필요하면 직접 다시 점검하세요.';
        } else if (modelCodes.has(code)) {
          guidance = '담당자에게 앱에서 허용된 AI 모델 설정을 확인 요청하세요.';
        }

        view.appendChild(eventNode('p', 'AI 연결 점검 실패', 'state state-error'));
        view.appendChild(eventNode('p', '오류 코드(code): ' + code));
        view.appendChild(eventNode('p', '오류 메시지(message): ' + message));
        view.appendChild(eventNode('p', '원인 및 조치: ' + guidance, 'muted'));
        return view;
      }
      if (resource.status !== 'ok') {
        view.appendChild(eventNode('p', '확인 불가: AI 연결 점검 상태를 알 수 없습니다.', 'state state-empty'));
        return view;
      }

      const data = resource.data;
      const checkedAt = eventScalar(resource.checkedAt).trim();
      if (!eventIsRecord(data) || data.transportChecked !== true
        || !['test', 'verified'].includes(data.audienceAuthorization)
        || !Number.isInteger(data.modelCount) || data.modelCount < 0 || data.modelCount > 10000
        || !eventIsRecord(data.help) || !checkedAt || !Number.isFinite(Date.parse(checkedAt))
        || resource.explanationAccepted !== false) {
        view.appendChild(eventNode('p', '확인 불가: AI 연결 점검 응답이 공식 입력 계약과 일치하지 않습니다.', 'state state-error'));
        return view;
      }

      const authorizationLabel = data.audienceAuthorization === 'test'
        ? '시험 연결 점검(test)'
        : '앱 권한 확인 후 점검(verified)';
      view.appendChild(eventNode('p', authorizationLabel, 'state state-ok'));
      if (resource.mode === 'demo') {
        view.appendChild(eventNode('p', '예제 응답(demo) · 실제 게이트 수용 아님', 'muted'));
      }
      view.appendChild(eventNode('p', '응답 모델 수(modelCount): ' + data.modelCount));
      view.appendChild(eventNode('p', '점검 시각(checkedAt): ' + checkedAt));
      view.appendChild(eventNode('p', '연결 경로와 모델 응답만 점검했습니다. 사건 설명은 아직 실행하지 않았습니다.', 'muted'));
      return view;
    },
    renderExplanation(input) {
      const resource = eventIsRecord(input) ? input : {};
      const event = eventIsRecord(resource.event) ? resource.event : null;
      const explanation = eventIsRecord(resource.explanation) ? resource.explanation : {};
      const view = eventNode('div');
      view.appendChild(eventNode('h3', 'AI 사건 설명'));

      const secretPattern = /(?:\bBearer\s+\S+|-----BEGIN [A-Z ]*PRIVATE KEY-----|\bsk-(?:proj-|ant-|svcacct-)?[A-Za-z0-9_-]{8,}|(?:api[_ -]?key|authorization|password|비밀번호|토큰)\s*[:=]\s*\S+)/i;
      const controlPattern = /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/;
      const idPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/;
      const safeText = (value, maxLength = 2000) => {
        const text = eventScalar(value).trim();
        return text && text.length <= maxLength && !secretPattern.test(text) && !controlPattern.test(text) ? text : '';
      };
      const safeCode = value => {
        const code = eventScalar(value).trim();
        return /^[A-Z][A-Z0-9_]{0,79}$/.test(code) ? code : '';
      };
      const appendErrorCode = () => {
        const error = eventIsRecord(explanation.error) ? explanation.error : {};
        const code = safeCode(error.code);
        if (code) view.appendChild(eventNode('p', '오류 코드(code): ' + code));
      };
      const failWithoutSuccess = reason => {
        view.appendChild(eventNode('p', reason, 'state state-error'));
        appendErrorCode();
        view.appendChild(eventNode('p', '기록은 그대로입니다.', 'muted'));
        return view;
      };

      // 실패는 event가 없어도 먼저 표시한다. raw 오류 문자열과 코드는 안전성 검사를 거친다.
      if (explanation.status === 'error') {
        const error = eventIsRecord(explanation.error) ? explanation.error : {};
        const code = safeCode(error.code) || 'AI_REQUEST_UNVERIFIED';
        const rawMessage = eventScalar(error.message).trim();
        const message = safeText(rawMessage, 800) || '오류 메시지를 안전하게 표시할 수 없습니다.';
        const evidenceFailure = /EVIDENCE|INSUFFICIENT/i.test(code)
          || /근거.{0,20}(부족|불일치|확인할 수 없)|evidence|insufficient/i.test(rawMessage);
        const contractFailure = /CONTRACT|INVALID_RESPONSE|UNVERIFIED/i.test(code);
        if (evidenceFailure) {
          view.appendChild(eventNode('p', '근거가 부족하거나 근거 ID가 일치하지 않아 AI 설명을 표시할 수 없습니다.', 'state state-error'));
        } else if (contractFailure) {
          view.appendChild(eventNode('p', '응답 계약을 검증할 수 없어 AI 설명을 표시하지 않습니다.', 'state state-error'));
        }
        view.appendChild(eventNode('p', 'AI 설명 실패', 'state state-error'));
        view.appendChild(eventNode('p', '오류 코드(code): ' + code));
        view.appendChild(eventNode('p', '오류 메시지(message): ' + message));
        view.appendChild(eventNode('p', '기록은 그대로입니다.', 'muted'));
        return view;
      }

      if (!event) {
        view.appendChild(eventNode('p', '보안 기록에서 기록을 먼저 고르세요.', 'state state-empty'));
        return view;
      }
      if (explanation.status === 'idle') {
        view.appendChild(eventNode('p', '선택한 기록의 AI 설명은 아직 요청하지 않았습니다.', 'state state-empty'));
        return view;
      }
      if (explanation.status === 'loading') {
        view.appendChild(eventNode('p', '선택한 기록의 AI 설명을 요청 중입니다.', 'state state-loading'));
        return view;
      }
      if (explanation.status !== 'ok') {
        view.appendChild(eventNode('p', 'AI 설명 결과를 확인할 수 없습니다. 기록은 그대로입니다.', 'state state-empty'));
        return view;
      }

      const data = explanation.data;
      if (!eventIsRecord(data)) return failWithoutSuccess('응답 자료의 형식이 올바르지 않아 AI 설명을 표시할 수 없습니다.');
      if (data.executed === true) {
        return failWithoutSuccess('AI가 이미 실행했다고 답한 설명은 표시할 수 없습니다. 실행 상태가 공식 계약과 일치하지 않습니다.');
      }
      if (data.requiresHumanConfirmation !== true || data.executed !== false) {
        return failWithoutSuccess('사람 확인 필요 여부 또는 미실행 상태가 공식 계약과 일치하지 않아 설명을 표시할 수 없습니다.');
      }

      const eventId = eventScalar(event.id).trim();
      if (!idPattern.test(eventId)) return failWithoutSuccess('선택한 보안 기록의 사건 ID가 올바르지 않습니다.');

      const evidence = Array.isArray(event.evidence) ? event.evidence : null;
      if (!evidence || evidence.length === 0) {
        return failWithoutSuccess('선택한 기록에 표시할 근거가 없어 AI 설명을 표시할 수 없습니다.');
      }
      const evidenceById = new Map();
      for (const item of evidence) {
        if (!eventIsRecord(item)) return failWithoutSuccess('기록의 근거 자료 형식이 올바르지 않습니다.');
        const id = eventScalar(item.id).trim();
        const text = safeText(item.text);
        if (!idPattern.test(id) || !text || evidenceById.has(id)) {
          return failWithoutSuccess('기록의 근거 ID 또는 근거 글을 확인할 수 없어 AI 설명을 표시할 수 없습니다.');
        }
        evidenceById.set(id, text);
      }

      const summary = safeText(data.summary);
      if (!summary) return failWithoutSuccess('AI 요약이 비어 있거나 안전하게 표시할 수 없어 설명을 표시하지 않습니다.');

      const evidenceIds = data.evidenceIds;
      if (!Array.isArray(evidenceIds) || evidenceIds.length !== evidenceById.size
        || new Set(evidenceIds).size !== evidenceIds.length
        || evidenceIds.some(id => typeof id !== 'string' || !idPattern.test(id) || !evidenceById.has(id))) {
        return failWithoutSuccess('근거 ID가 현재 기록의 근거와 일치하지 않아 AI 설명을 표시할 수 없습니다.');
      }

      if (!Array.isArray(event.rules)) return failWithoutSuccess('현재 기록의 규칙 자료를 확인할 수 없어 설명을 표시하지 않습니다.');
      const rules = [];
      const ruleIds = new Set();
      for (const rule of event.rules) {
        if (!eventIsRecord(rule)) return failWithoutSuccess('규칙 자료 형식이 올바르지 않아 설명을 표시하지 않습니다.');
        const id = eventScalar(rule.id).trim();
        const text = safeText(rule.text);
        if (!idPattern.test(id) || !text || ruleIds.has(id)) {
          return failWithoutSuccess('규칙 ID 또는 규칙 글을 확인할 수 없어 설명을 표시하지 않습니다.');
        }
        ruleIds.add(id);
        rules.push({ id, text });
      }

      if (!eventIsRecord(event.state)) return failWithoutSuccess('현재 상태 자료를 확인할 수 없어 설명을 표시하지 않습니다.');
      const unknownStates = [
        ['access', '접속'],
        ['session', '세션'],
        ['device', '기기'],
      ].filter(([key]) => event.state[key] === 'unknown');
      const otherStatesValid = ['access', 'session', 'device'].every(key =>
        typeof event.state[key] === 'string' && event.state[key].length > 0);
      if (!otherStatesValid) return failWithoutSuccess('접속·세션·기기 상태 형식이 올바르지 않아 설명을 표시하지 않습니다.');

      if (!Array.isArray(event.supportedActions)) {
        return failWithoutSuccess('연동 시스템의 지원 조치 목록을 확인할 수 없어 제안 여부를 판단할 수 없습니다.');
      }
      if (!Array.isArray(data.proposals)) return failWithoutSuccess('AI 제안 자료의 형식이 올바르지 않아 설명을 표시하지 않습니다.');
      const proposals = [];
      for (const proposal of data.proposals) {
        if (!eventIsRecord(proposal)) return failWithoutSuccess('AI 제안 자료의 형식이 올바르지 않아 설명을 표시하지 않습니다.');
        const action = eventScalar(proposal.action).trim();
        const reason = safeText(proposal.reason, 500);
        const proposalEvidenceIds = proposal.evidenceIds;
        if (!idPattern.test(action) || !event.supportedActions.includes(action) || !reason
          || !Array.isArray(proposalEvidenceIds) || proposalEvidenceIds.length === 0
          || new Set(proposalEvidenceIds).size !== proposalEvidenceIds.length
          || proposalEvidenceIds.some(id => typeof id !== 'string' || !idPattern.test(id) || !evidenceById.has(id))) {
          return failWithoutSuccess('AI 제안의 조치 또는 근거 ID가 현재 기록과 일치하지 않아 제안을 표시하지 않습니다.');
        }
        proposals.push({ action, reason, evidenceIds: proposalEvidenceIds });
      }

      // 모든 입력과 참조를 검사한 뒤 성공 DOM을 만든다. 실패 경로에는 성공 속성을 붙이지 않는다.
      const content = eventNode('section');
      content.appendChild(eventNode('p', '사건 ID: ' + eventId));
      content.appendChild(eventNode('h4', 'AI 설명(참고용)'));
      content.appendChild(eventNode('p', summary));
      content.appendChild(eventNode('p', 'AI 설명은 해석입니다. 사실 판단은 인용한 근거 글과 연동 시스템이 알려 준 현재 상태를 기준으로 하세요.', 'muted'));

      content.appendChild(eventNode('h4', '인용한 근거'));
      const evidenceList = eventNode('ul', undefined, 'plain-list');
      for (const id of evidenceIds) {
        evidenceList.appendChild(eventNode('li', id + ' — ' + evidenceById.get(id)));
      }
      content.appendChild(evidenceList);

      content.appendChild(eventNode('h4', '현재 규칙'));
      if (rules.length === 0) {
        content.appendChild(eventNode('p', '표시할 규칙이 없습니다.', 'state state-empty'));
      } else {
        const ruleList = eventNode('ul', undefined, 'plain-list');
        for (const rule of rules) ruleList.appendChild(eventNode('li', rule.id + ' — ' + rule.text));
        content.appendChild(ruleList);
      }

      content.appendChild(eventNode('h4', '확인 불가 상태'));
      if (unknownStates.length === 0) {
        content.appendChild(eventNode('p', '없음', 'state state-empty'));
      } else {
        const stateList = eventNode('ul', undefined, 'plain-list');
        for (const [key, label] of unknownStates) {
          stateList.appendChild(eventNode('li', label + ': 확인 불가(unknown)'));
        }
        content.appendChild(stateList);
      }

      content.appendChild(eventNode('h4', '조치 제안'));
      if (proposals.length === 0) {
        const noProposalText = event.supportedActions.length === 0
          ? '연동 시스템이 지원하는 조치가 없어 제안이 없습니다(정상).'
          : 'AI가 제안한 조치가 없습니다.';
        content.appendChild(eventNode('p', noProposalText, 'state state-empty'));
      } else {
        const proposalList = eventNode('ul', undefined, 'plain-list');
        for (const proposal of proposals) {
          const item = eventNode('li');
          item.appendChild(eventNode('p', '조치: ' + proposal.action));
          item.appendChild(eventNode('p', '사유: ' + proposal.reason));
          const refs = proposal.evidenceIds.map(id => id + ' — ' + evidenceById.get(id)).join(' / ');
          item.appendChild(eventNode('p', '근거: ' + refs));
          item.appendChild(eventNode('p', '사람 확인이 필요하며 아직 실행되지 않았습니다.', 'muted'));
          proposalList.appendChild(item);
        }
        content.appendChild(proposalList);
      }
      content.appendChild(eventNode('p', '이 AI 설명과 제안만으로 보안 조치는 실행되지 않습니다.', 'muted'));

      view.setAttribute('data-student-explanation-event', eventId);
      view.appendChild(content);
      return view;
    },
    renderAction(input) {
      const resource = eventIsRecord(input) ? input : {};
      const view = eventNode('div');
      view.setAttribute('aria-live', 'polite');
      view.appendChild(eventNode('h3', '조치 처리 상태'));

      const secretPattern = /(?:\bBearer\s+\S+|-----BEGIN [A-Z ]*PRIVATE KEY-----|\bsk-(?:proj-|ant-|svcacct-)?[A-Za-z0-9_-]{8,}|(?:api[_ -]?key|authorization|password|비밀번호|토큰)\s*[:=]\s*\S+)/i;
      const controlPattern = /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/;
      const safeText = (value, maxLength = 800) => {
        const text = eventScalar(value).trim();
        return text && text.length <= maxLength && !secretPattern.test(text) && !controlPattern.test(text) ? text : '';
      };
      const safeId = value => {
        const id = eventScalar(value).trim();
        return STATUS_SAFE_CODE.test(id) && !secretPattern.test(id) ? id : '';
      };
      const safeCode = value => {
        const code = eventScalar(value).trim();
        return /^[A-Z][A-Z0-9_]{0,79}$/.test(code) ? code : '';
      };
      const safeTime = value => {
        const text = safeText(value, 120);
        return text && Number.isFinite(Date.parse(text)) ? text : '';
      };

      const allowedStatuses = new Set(['idle', 'loading', 'prepared', 'executing', 'pending', 'succeeded', 'denied', 'failed', 'unknown', 'error', 'expired']);
      const rawStatus = safeId(resource.status);
      const status = allowedStatuses.has(rawStatus) ? rawStatus : 'unknown';
      const event = eventIsRecord(resource.event) ? resource.event : null;
      const target = eventIsRecord(resource.target) ? resource.target : null;
      const receipt = eventIsRecord(resource.receipt) ? resource.receipt : null;
      const observation = eventIsRecord(resource.observation) ? resource.observation : null;
      const error = eventIsRecord(resource.error) ? resource.error : null;
      const eventId = safeId(event?.id);
      const actionId = safeId(resource.actionId);
      const requestId = safeId(receipt?.requestId);
      const receiptId = safeId(receipt?.receiptId);
      const observedAt = safeTime(observation?.observedAt);
      const confirmationExpiresAt = safeTime(resource.confirmationExpiresAt);
      const message = safeText(resource.message);
      const errorCode = safeCode(error?.code);
      const errorMessage = safeText(error?.message) || '오류 메시지를 안전하게 표시할 수 없습니다.';
      const receiptEventId = safeId(receipt?.eventId);
      const receiptActionId = safeId(receipt?.actionId);
      const intentMismatch = Boolean(
        (receipt?.eventId != null && (!receiptEventId || !eventId || receiptEventId !== eventId)) ||
        (receipt?.actionId != null && (!receiptActionId || !actionId || receiptActionId !== actionId))
      );
      const cancelledIdle = status === 'idle' && /조치 화면을 취소했습니다/.test(message);

      let stateLabel = '';
      let stateClass = 'state state-empty';
      let stateNote = '';
      let effectConfirmed = false;

      if (intentMismatch) {
        stateLabel = '결과 불명(unknown)';
        stateNote = '영수증의 사건 ID 또는 조치 ID가 현재 화면의 값과 일치하지 않습니다. 성공이나 효과 없음으로 판단하지 말고 제공 화면에서 현재 요청의 결과만 재조회하세요.';
      } else if (cancelledIdle) {
        stateLabel = '조치 화면 취소(idle)';
        stateNote = '조치 화면 표시를 초기화한 상태입니다. 이미 서버에 전달된 조치 효과를 되돌리는 기능은 아닙니다.';
      } else {
        switch (status) {
          case 'idle':
            stateLabel = '아직 미실행(idle)';
            stateNote = '조치 준비 버튼은 제공 화면의 AI 제안 중 원천이 지원하는 조치에만 표시됩니다. 버튼이 보이지 않으면 현재 기록에 지원 조치가 없어 정상일 수 있습니다.';
            break;
          case 'loading':
            stateLabel = '조치 준비 또는 원천 결과 조회 중(loading)';
            stateNote = '요청 준비 또는 결과 조회가 진행 중입니다. 처리 결과는 아직 확인되지 않았습니다.';
            stateClass = 'state state-loading';
            break;
          case 'prepared':
            stateLabel = '준비됨·미실행(prepared)';
            stateNote = '조치 준비만 완료되었습니다. 서버 집행 요청은 아직 전송되지 않았습니다. 실제 대상과 확인 기한을 검토한 뒤 제공 화면의 확인 버튼을 사용하세요.';
            stateClass = 'state state-loading';
            break;
          case 'executing':
            stateLabel = '서버에 전달 중(executing)';
            stateNote = '서버 전달 중이며 결과는 아직 확인되지 않았습니다. 완료 또는 성공으로 간주하지 마세요.';
            stateClass = 'state state-loading';
            break;
          case 'pending':
            stateLabel = '서버 접수·처리 중(pending)';
            stateNote = '서버가 요청을 접수했습니다(ACK). 접수 응답은 실제 효과 확인이 아니며 결과는 아직 확인되지 않았습니다.';
            stateClass = 'state state-loading';
            break;
          case 'succeeded': {
            const receiptVersionValid = Number.isSafeInteger(receipt?.version) && receipt.version > 0;
            effectConfirmed = observation?.effectApplied === true
              && Boolean(observedAt)
              && Boolean(eventId && actionId && requestId && receiptId)
              && receiptEventId === eventId
              && receiptActionId === actionId
              && receipt?.status === 'succeeded'
              && receiptVersionValid;
            if (effectConfirmed) {
              stateLabel = '효과 확인(succeeded)';
              stateNote = '연동 시스템의 효과 관측이 확인되었습니다. 아래에 관측 시각, effectApplied: true, receiptId가 표시됩니다.';
              stateClass = 'state state-ok';
            } else {
              stateLabel = '결과 불명(unknown)';
              stateNote = '입력 status=succeeded만으로는 효과를 확정하지 않습니다. observation.effectApplied=true, 관측 시각, receiptId 및 현재 사건·조치·요청 연결을 모두 확인하지 못했습니다. 성공이나 효과 없음으로 단정하지 말고 제공 화면의 「원천 결과만 재조회」를 사용하세요.';
            }
            break;
          }
          case 'denied':
            stateLabel = '조치 거절(denied)';
            stateNote = message || '서버가 별도 메시지(message)를 전달하지 않았습니다.';
            stateClass = 'state state-error';
            break;
          case 'failed':
            stateLabel = '조치 실패(failed)';
            stateNote = message || '서버가 별도 메시지(message)를 전달하지 않았습니다.';
            stateClass = 'state state-error';
            break;
          case 'unknown':
            stateLabel = '결과 불명(unknown)';
            stateNote = '성공이나 효과 없음으로 판단하지 마세요. 새 집행을 시도하지 말고 제공 화면의 「원천 결과만 재조회」로 기존 요청 결과만 확인하세요.';
            break;
          case 'expired':
            stateLabel = '확인 기한 지남(expired)';
            stateNote = '이번 준비 정보로는 집행할 수 없습니다. 제공 화면에서 조치를 다시 준비하고 실제 대상과 새 확인 기한을 확인하세요.';
            stateClass = 'state state-error';
            break;
          case 'error':
            stateLabel = '요청 처리 안 됨(error)';
            stateNote = errorMessage;
            stateClass = 'state state-error';
            break;
          default:
            stateLabel = '결과 불명(unknown)';
            stateNote = '인식할 수 없는 상태값입니다. 성공이나 효과 없음으로 판단하지 말고 제공 화면에서 기존 요청 결과만 재조회하세요.';
        }
      }

      view.appendChild(eventNode('p', stateLabel, stateClass));
      if (stateNote) view.appendChild(eventNode('p', stateNote, 'muted'));

      // 상태만 전달된 unknown/error 응답에서도 안전한 오류 코드·메시지를 숨기지 않는다.
      if (error && status !== 'error' && errorCode) view.appendChild(eventNode('p', '오류 코드(code): ' + errorCode));
      if (error && status !== 'error' && safeText(error.message)) {
        view.appendChild(eventNode('p', '오류 메시지(message): ' + safeText(error.message), 'muted'));
      }
      if (status === 'error' && errorCode) view.appendChild(eventNode('p', '오류 코드(code): ' + errorCode));
      if (status === 'error') view.appendChild(eventNode('p', '오류 메시지(message): ' + errorMessage));

      const details = eventNode('dl', undefined, 'kv');
      let detailCount = 0;
      const addDetail = (label, value) => {
        if (value === '' || value == null) return;
        details.appendChild(eventNode('dt', label));
        details.appendChild(eventNode('dd', String(value)));
        detailCount += 1;
      };

      addDetail('사건 ID(event.id)', eventId);
      const evidenceIds = Array.isArray(event?.evidence)
        ? [...new Set(event.evidence.map(item => safeId(eventIsRecord(item) ? item.id : '')).filter(Boolean))]
        : [];
      addDetail('근거 ID(event.evidence.id)', evidenceIds.join(', '));
      addDetail('조치 ID(actionId)', actionId);
      addDetail('실제 대상(target.id)', safeId(target?.id));
      addDetail('대상 세대(target.generation)', Number.isSafeInteger(target?.generation) && target.generation > 0 ? target.generation : '');
      addDetail('요청 ID(receipt.requestId)', requestId);
      addDetail('영수증 ID(receipt.receiptId)', receiptId);
      addDetail('영수증 사건 ID(receipt.eventId)', receiptEventId);
      addDetail('영수증 조치 ID(receipt.actionId)', receiptActionId);
      addDetail('영수증 상태(receipt.status)', safeId(receipt?.status));
      addDetail('영수증 버전(receipt.version)', Number.isSafeInteger(receipt?.version) && receipt.version > 0 ? receipt.version : '');
      if (typeof receipt?.replayed === 'boolean') addDetail('기존 요청 결과 재사용(replayed)', receipt.replayed);
      addDetail('사람 확인 기한(confirmationExpiresAt)', confirmationExpiresAt);
      if (observedAt) addDetail('관측 시각(observation.observedAt)', observedAt);
      if (effectConfirmed) addDetail('effectApplied', 'true');
      if (receipt?.superseded === true) addDetail('이전 결과 상태', '최신 결과 아님(superseded)');
      if (detailCount > 0) view.appendChild(details);

      if (status === 'succeeded' && !effectConfirmed) {
        view.appendChild(eventNode('p', 'effectApplied: true를 확인할 수 없어 효과 확인으로 표시하지 않았습니다. 이는 효과 없음 판정도 아닙니다.', 'muted'));
      }
      if (receipt?.superseded === true) {
        view.appendChild(eventNode('p', '이전 조회 결과는 최신 결과를 대신하지 않습니다(superseded).', 'state state-empty'));
      }
      view.appendChild(eventNode('p', '이 화면은 상태 표시만 수행하며 조치 요청·확인 티켓 생성·자동 재시도를 하지 않습니다. 실제 대상 확인·집행·재조회는 제공 화면의 버튼을 사용하세요.', 'muted'));
      if (status === 'idle' && !cancelledIdle) {
        view.appendChild(eventNode('p', '「조치 화면 취소」는 화면 표시를 초기화할 뿐, 이미 서버에 전달된 조치 효과를 되돌리지 않습니다.', 'muted'));
      }

      if (eventId) view.setAttribute('data-student-action-event', eventId);
      if (requestId) view.setAttribute('data-student-action-request', requestId);
      return view;
    },
  };
}
