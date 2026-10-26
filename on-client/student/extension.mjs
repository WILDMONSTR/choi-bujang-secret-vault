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
  return detail;
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
    renderStatus() { return '학생 구현 대기: 기기·세션·알림과 연결 점검 상태를 구분하세요.'; },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation() { return '학생 구현 대기: 선택한 사건의 근거·규칙·현재 상태와 AI 설명을 연결하세요. 제안은 자동 실행하지 않습니다.'; },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
