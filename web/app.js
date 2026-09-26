/* Hacklipse 대시보드 표시 계층.
 *
 * 서버는 ProgressSnapshot과 ProgressEvent의 원본 값만 보낸다. 문구·색·심각도 라벨은
 * 전부 여기서 정한다 — application/progress.py 가 "문구·색·기호는 CLI나 웹 UI가
 * 정한다"고 규정한 경계를 그대로 지킨다.
 */
'use strict';

/* RunPhase 중 화면에 단계로 보여줄 다섯 개. init·done·failed 는 단계가 아니라 상태다. */
const STEPS = [
  { phase: 'recon', name: 'RECON' },
  { phase: 'route', name: 'ROUTER' },
  { phase: 'analyze', name: 'ANALYZE' },
  { phase: 'validate', name: 'VALIDATE' },
  { phase: 'report', name: 'REPORT' },
];

/* agent_type 원본값 → 화면 표기. 모르는 이름은 그대로 보여준다(조용히 숨기지 않는다). */
const AGENT_LABELS = {
  recon: 'Recon',
  xss_analyzer: 'XSS',
  browser_xss_analyzer: 'Browser XSS',
  sqli_analyzer: 'SQLi',
  access_control_analyzer: 'Access Control',
  path_traversal_analyzer: 'Path Traversal',
  ssti_analyzer: 'SSTI',
  validation: 'Validation',
  report: 'Report',
  evidence_collector: 'Evidence',
  session_authenticator: 'Auth',
};

/* CandidateStatus 원본값 → 표시 문구와 색 클래스. */
const STATUS_LABELS = {
  routed: ['Queued', ''],
  analyzed: ['In review', ''],
  confirmed: ['Confirmed', 'is-confirmed'],
  suspected: ['Suspected', ''],
  rejected: ['Rejected', 'is-rejected'],
  blocked: ['Blocked', 'is-blocked'],
  failed: ['Failed', 'is-blocked'],
  skipped_budget: ['Skipped (budget)', 'is-rejected'],
};

/* 심각도는 LASP 판정이 아니다. Finding.severity 기본값이 "unrated" 이므로, 서버가
 * 실제 등급을 주지 않는 한 취약점 유형에 대응하는 관행적 등급을 화면이 붙인다. */
const SEVERITY_BY_TYPE = {
  SQLi: 'critical',
  SSTI: 'critical',
  'Access Control': 'high',
  'Path Traversal': 'high',
  XSS: 'medium',
};

/* 정렬 우선순위. 확정된 것부터 위로 올린다. */
const STATUS_ORDER = {
  confirmed: 0,
  analyzed: 1,
  suspected: 2,
  blocked: 3,
  routed: 4,
  failed: 5,
  skipped_budget: 6,
  rejected: 7,
};

const MAX_ACTIVITY = 60;   // 보관 개수
const SHOWN_ACTIVITY = 12; // 화면에 그리는 개수

const $ = (id) => document.getElementById(id);

let config = {};
let lastSequence = 0;
const seenNotes = new Set();
let activity = [];
let running = false;
let timer = null;
const expandedFindingGroups = new Set();

/* ------------------------------------------------------------------ 포맷터 */

const pad2 = (value) => String(value).padStart(2, '0');

function agentLabel(agentType) {
  if (!agentType) return null;
  return `${AGENT_LABELS[agentType] || agentType} Agent`;
}

function severityOf(candidate) {
  /* 서버가 등급을 매긴 Finding 이면 그걸 쓰고, 아니면 유형별 관행 등급으로 보완한다. */
  if (candidate.severity && candidate.severity !== 'unrated') {
    return candidate.severity.toLowerCase();
  }
  return SEVERITY_BY_TYPE[candidate.vulnerability_type] || 'unrated';
}

function surfaceLabel(candidate) {
  const path = candidate.path || '/';
  const names = candidate.parameters || [];
  return names.length ? `${path}?${names.join('&')}=` : path;
}

/* ProgressEvent 하나를 한 줄 문구로 바꾼다. tone 은 원본 마크업의 클래스명과 맞춘다. */
function describe(event) {
  const agent = agentLabel(event.agent_type);
  const where = event.surface_path ? ` ${event.surface_path}` : '';
  const type = event.vulnerability_type || '';

  switch (event.kind) {
    case 'run_started':
      return ['Run started', 'active'];
    case 'phase_changed':
      return [`Phase → ${event.phase.toUpperCase()}`, 'active'];
    case 'candidate_queued':
      return [`Router queued ${type} candidate${where}`, ''];
    case 'orchestration_decided':
      return [event.detail || 'Orchestration decision recorded', ''];
    case 'budget_allocated':
      return [event.detail || 'Budget allocated', ''];
    case 'knowledge_retrieved':
      return [event.detail || 'Knowledge hints retrieved', ''];
    case 'knowledge_retrieval_failed':
      return [event.detail || 'Knowledge retrieval failed', 'alert'];
    case 'agent_started':
      return [`${agent || 'Agent'} started${where}`, 'active'];
    case 'agent_completed':
      return [`${agent || 'Agent'} completed${where}`, ''];
    case 'evidence_collected':
      return [`Evidence collected${where}`, ''];
    case 'finding_created':
      return [`Confirmed ${type}${where}`, 'alert'];
    case 'candidate_failed':
      return [`${type} candidate failed — ${event.detail || 'unknown reason'}`, 'alert'];
    case 'candidate_skipped':
      return [`${type} candidate skipped — ${event.detail || 'budget'}`, 'alert'];
    case 'run_completed':
      return ['Run completed', 'active'];
    default:
      return [event.detail || event.kind, ''];
  }
}

/* ------------------------------------------------------------------ 렌더링 */

function renderStatus(state) {
  const badge = $('run-status');
  const text = $('run-status-text');
  badge.classList.remove('idle', 'done', 'failed');

  if (state.status === 'running') {
    text.textContent = 'SCAN IN PROGRESS';
  } else if (state.status === 'done') {
    badge.classList.add('done');
    text.textContent = 'SCAN COMPLETE';
  } else if (state.status === 'failed') {
    badge.classList.add('failed');
    text.textContent = 'SCAN FAILED';
  } else {
    badge.classList.add('idle');
    text.textContent = 'IDLE';
  }

  const button = $('start-btn');
  const busy = state.status === 'running';
  button.disabled = busy;
  button.textContent = busy ? 'SCANNING…' : 'START SCAN';
  /* Run 중에 구성을 바꾸면 화면과 실제 실행이 어긋난다. 끝날 때까지 잠근다. */
  for (const id of ['target-input', 'mode-select', 'vuln-select', 'engine-select', 'budget-input'])
    $(id).disabled = busy;
  applyLocks(busy);

  const banner = $('error-banner');
  if (state.error) {
    banner.textContent = state.error;
    banner.classList.add('show');
  } else {
    banner.classList.remove('show');
  }
}

/* 판정까지 끝난 Candidate 상태. domain 의 CandidateStatus 와 같은 어휘를 쓴다. */
const VERDICT_STATUSES = ['confirmed', 'suspected', 'rejected', 'blocked'];
/* 검사를 시작조차 못 한 상태. 이것을 진행으로 세면 안 된다. */
const UNCHECKED_STATUSES = ['failed', 'skipped_budget'];

/* 진행률은 "단계가 지나갔는가"가 아니라 "표면이 실제로 검사됐는가"로 잰다.
 *
 * 왜 단계 기반이면 안 되는가 — 예산이 모자라 Candidate 36개가 전부 건너뛰어져도
 * RECON~REPORT 다섯 단계는 모두 지나간다. 그때 100%를 표시하면 "검사했는데 없었다"와
 * "검사하지 못했다"가 화면에서 같은 그림이 된다. LASP 가 Candidate 상태를 여덟 가지로
 * 쪼개 구분하는 이유가 바로 그 둘을 뭉치지 않기 위해서다. */
function verificationProgress(state) {
  const total = state.candidates.length;
  const verified = countByStatus(state, VERDICT_STATUSES);
  const unchecked = countByStatus(state, UNCHECKED_STATUSES);
  return {
    total,
    verified,
    unchecked,
    ratio: total ? verified / total : 0,
    /* 검사를 마친 것이 하나도 없는데 건너뛴 것은 있다 = 예산에 굶었다. */
    starved: total > 0 && verified === 0 && unchecked > 0,
  };
}

/* 단계 표시는 진행률과 별개 축이다. 어느 단계까지 갔는지는 그대로 보여준다. */
function phaseIndex(state) {
  if (state.phase === 'done') return STEPS.length;
  if (state.status === 'idle') return -1;
  return STEPS.findIndex((step) => step.phase === state.phase);
}

function countByStatus(state, statuses) {
  return state.candidates.filter((item) => statuses.includes(item.status)).length;
}

function stepCaption(state, stepIndex, currentIndex) {
  const snapshot = state.snapshot;
  if (stepIndex > currentIndex) return 'Queued';

  const isCurrent = stepIndex === currentIndex;
  const progress = verificationProgress(state);

  switch (STEPS[stepIndex].phase) {
    case 'recon':
      return isCurrent ? 'Crawling…' : `${snapshot.surface_count} surfaces found`;
    case 'route':
      return isCurrent ? 'Routing…' : `${progress.total} candidates`;
    case 'analyze': {
      if (isCurrent) return agentLabel(state.current_agent) || 'Analyzing…';
      const analyzed = countByStatus(state, ['analyzed', ...VERDICT_STATUSES]);
      return progress.unchecked
        ? `${analyzed} analyzed, ${progress.unchecked} skipped`
        : `${analyzed} analyzed`;
    }
    case 'validate':
      if (isCurrent) return 'Verifying…';
      return progress.verified ? `${progress.verified} verified` : 'Nothing verified';
    case 'report':
      return isCurrent ? 'Writing…' : `${state.findings_total} findings`;
    default:
      return '';
  }
}

/* 지나갔지만 실제로 한 일이 없는 단계인가. ANALYZE·VALIDATE 에만 해당한다 —
 * REPORT 의 findings 0 은 정상 결과일 수 있으므로 경고하지 않는다. */
function isStarvedStep(state, stepIndex, currentIndex) {
  if (stepIndex >= currentIndex) return false;
  const progress = verificationProgress(state);
  if (!progress.starved) return false;
  return ['analyze', 'validate'].includes(STEPS[stepIndex].phase);
}

function renderPipeline(state) {
  const index = phaseIndex(state);
  const progress = verificationProgress(state);
  const percent = Math.round(progress.ratio * 100);

  $('steps').innerHTML = STEPS.map((step, i) => {
    const done = i < index;
    const current = i === index;
    const starved = isStarvedStep(state, i, index);
    const mark = starved ? '!' : done ? '✓' : current ? '●' : '·';
    const klass = starved ? 'step done starved' : done ? 'step done' : current ? 'step current' : 'step';
    /* ANALYZE 칸만 현재 분석기 이름으로 바꿔 단다 — 목업의 "SQLi AGENT" 자리다. */
    const name =
      current && step.phase === 'analyze' && state.current_agent
        ? (AGENT_LABELS[state.current_agent] || state.current_agent).toUpperCase()
        : step.name;
    return (
      `<div class="${klass}">` +
      `<div class="step-top"><span>${pad2(i + 1)}</span><span class="step-check" aria-hidden="true">${mark}</span></div>` +
      `<div class="step-name">${escapeHtml(name)}</div>` +
      `<div class="step-caption">${escapeHtml(stepCaption(state, i, index))}</div>` +
      `</div>`
    );
  }).join('');

  const stage = Math.max(0, Math.min(index + 1, STEPS.length));
  $('step-counter').innerHTML = `${pad2(stage)} <small>/ 05</small>`;
  $('step-counter').setAttribute('aria-label', `Stage ${stage} of ${STEPS.length}`);

  const label = $('progress-label');
  label.textContent = progress.total ? `${progress.verified} / ${progress.total}` : '—';
  label.classList.toggle('starved', progress.starved);
  $('progress-caption').textContent = progress.starved
    ? 'Candidates verified — none reached a verdict'
    : 'Candidates verified';

  const fill = $('progress-fill');
  /* 굶은 Run 의 막대는 비어 있는 것이 맞다. 채우면 "다 했다"로 읽힌다. */
  fill.style.width = `${percent}%`;
  fill.classList.toggle('starved', progress.starved);
  $('progress-track').setAttribute('aria-valuenow', String(percent));
}

function renderMetrics(state) {
  const snapshot = state.snapshot;
  const progress = verificationProgress(state);

  const coverage = $('m-coverage');
  coverage.innerHTML = `${Math.round(progress.ratio * 100)}<small>%</small>`;
  coverage.classList.toggle('warn', progress.starved);
  $('m-stage').textContent =
    state.status === 'idle'
      ? 'Not started'
      : progress.unchecked
        ? `${progress.unchecked} never checked`
        : `${progress.verified} of ${progress.total} candidates`;
  $('m-surfaces').textContent = pad2(snapshot.surface_count);
  $('m-parameters').textContent = `${snapshot.parameter_count} parameters`;
  $('m-budget-used').textContent = pad2(snapshot.budget_used);
  $('m-budget-total').textContent = `${snapshot.budget_total} budget`;
  $('m-findings').textContent = pad2(state.findings_total);
  $('m-awaiting').textContent = String(countByStatus(state, ['routed', 'analyzed']));
  $('nav-findings-count').textContent = String(state.findings_total);
  $('run-id').textContent = state.run_id ? state.run_id.slice(0, 8) : '—';
  $('current-agent').textContent = agentLabel(state.current_agent) || '—';
}

function renderFindings(state) {
  const rows = [...state.candidates].sort(
    (a, b) =>
      (STATUS_ORDER[a.status] ?? 9) - (STATUS_ORDER[b.status] ?? 9) ||
      a.vulnerability_type.localeCompare(b.vulnerability_type)
  );

  const groups = $('findings-groups');
  if (!rows.length) {
    expandedFindingGroups.clear();
    groups.innerHTML = `<div class="findings-empty">${
      state.status === 'idle' ? 'No candidates yet.' : 'No candidates raised so far.'
    }</div>`;
  } else {
    const grouped = new Map();
    for (const item of rows) {
      const type = item.vulnerability_type || 'Unknown';
      if (!grouped.has(type)) grouped.set(type, []);
      grouped.get(type).push(item);
    }
    const entries = [...grouped.entries()];
    const activeTypes = new Set(grouped.keys());
    for (const type of expandedFindingGroups) {
      if (!activeTypes.has(type)) expandedFindingGroups.delete(type);
    }

    groups.innerHTML = entries
      .map(([type, items], index) => {
        const expanded = expandedFindingGroups.has(type);
        const statusCounts = new Map();
        for (const item of items) {
          statusCounts.set(item.status, (statusCounts.get(item.status) || 0) + 1);
        }
        const summary = Object.keys(STATUS_ORDER)
          .filter((status) => statusCounts.has(status))
          .map((status) => {
            const [label] = STATUS_LABELS[status] || [status];
            return `${statusCounts.get(status)} ${label}`;
          })
          .join(' · ');
        const buttonId = `finding-group-toggle-${index}`;
        const bodyId = `finding-group-body-${index}`;
        const itemRows = items
          .map((item) => {
            const severity = severityOf(item);
            const [label, klass] = STATUS_LABELS[item.status] || [item.status, ''];
            return (
              '<tr>' +
              `<td><span class="finding-name">${escapeHtml(type)}</span>` +
              `<span class="finding-path">${escapeHtml(surfaceLabel(item))}</span></td>` +
              `<td><span class="severity ${severity}">${severity[0].toUpperCase()}${severity.slice(1)}</span></td>` +
              `<td><span class="finding-status ${klass}">${escapeHtml(label)}</span></td>` +
              '</tr>'
            );
          })
          .join('');
        return (
          '<section class="finding-group">' +
          `<button class="finding-group-toggle" id="${buttonId}" type="button" ` +
          `data-group-index="${index}" aria-expanded="${expanded}" aria-controls="${bodyId}">` +
          `<span class="finding-group-name">${escapeHtml(type)} <span class="finding-group-count">${items.length}</span></span>` +
          `<span class="finding-group-summary">${escapeHtml(summary)}</span>` +
          '<span class="finding-group-chevron" aria-hidden="true">⌄</span></button>' +
          `<div class="finding-group-body" id="${bodyId}" role="region" aria-labelledby="${buttonId}"${expanded ? '' : ' hidden'}>` +
          '<table class="findings-table"><thead><tr><th scope="col">Finding</th><th scope="col">Severity</th><th scope="col">Status</th></tr></thead>' +
          `<tbody>${itemRows}</tbody></table></div></section>`
        );
      })
      .join('');

    for (const button of groups.querySelectorAll('.finding-group-toggle')) {
      button.addEventListener('click', () => {
        const [type] = entries[Number(button.dataset.groupIndex)];
        const expanded = button.getAttribute('aria-expanded') !== 'true';
        button.setAttribute('aria-expanded', String(expanded));
        document.getElementById(button.getAttribute('aria-controls')).hidden = !expanded;
        if (expanded) expandedFindingGroups.add(type);
        else expandedFindingGroups.delete(type);
      });
    }
  }

  const count = $('findings-count');
  count.textContent = pad2(state.findings_total);
  count.classList.toggle('none', state.findings_total === 0);
  $('findings-footer').textContent = rows.length
    ? `${rows.length} candidates grouped by ${new Set(rows.map((item) => item.vulnerability_type)).size} vulnerability types`
    : 'Waiting for the router to raise candidates';
}

function renderValidation(state) {
  const confirmed = countByStatus(state, ['confirmed']);
  const suspected = countByStatus(state, ['suspected']);
  const rejected = countByStatus(state, ['rejected']);
  const total = state.snapshot.validated_count;

  $('v-confirmed').textContent = pad2(confirmed);
  $('v-suspected').textContent = pad2(suspected);
  $('v-rejected').textContent = pad2(rejected);
  $('v-total').textContent = `${total} total`;

  const sum = confirmed + suspected + rejected;
  const share = (value) => (sum ? `${(value / sum) * 100}%` : '0%');
  $('v-bar-confirmed').style.width = share(confirmed);
  $('v-bar-suspected').style.width = share(suspected);
}

function renderActivity() {
  const list = $('activity-list');
  if (!activity.length) {
    list.innerHTML =
      '<li class="activity-item"><span class="activity-message">Idle — start a scan to see agent events.</span></li>';
    return;
  }
  list.innerHTML = activity
    .slice(0, SHOWN_ACTIVITY)
    .map((item, i) => {
      const tone = i === 0 && running ? 'active' : item.tone;
      return (
        `<li class="activity-item${tone ? ' ' + tone : ''}">` +
        `<time class="activity-time">${escapeHtml(item.time)}</time>` +
        `<span class="activity-message">${escapeHtml(item.message)}</span></li>`
      );
    })
    .join('');
}

function renderReport(state) {
  const body = $('report-body');
  const copy = $('copy-report');
  if (state.report) {
    body.textContent = state.report;
    copy.disabled = false;
  } else {
    body.textContent =
      state.status === 'running'
        ? 'REPORT 단계에서 생성된다…'
        : 'Run이 끝나면 생성된 보고서가 여기에 나온다.';
    copy.disabled = true;
  }
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[ch]);
}

/* ------------------------------------------------------------------ 폴링 */

function render(state) {
  running = state.status === 'running';
  renderStatus(state);
  renderMetrics(state);
  renderPipeline(state);
  renderFindings(state);
  renderValidation(state);
  renderReport(state);
  renderActivity();
}

function absorbEvents(events) {
  for (const event of events) {
    if (event.sequence < 0) {
      if (seenNotes.has(event.sequence)) continue;
      seenNotes.add(event.sequence);
    } else {
      if (event.sequence <= lastSequence) continue;
      lastSequence = event.sequence;
    }
    const [message, tone] = describe(event);
    activity.unshift({ time: event.time, message, tone });
  }
  activity = activity.slice(0, MAX_ACTIVITY);
}

async function poll() {
  try {
    const response = await fetch(`/api/state?since=${lastSequence}`, { cache: 'no-store' });
    if (!response.ok) throw new Error(`state request failed: ${response.status}`);
    const state = await response.json();
    absorbEvents(state.events || []);
    render(state);
    schedule(state.status === 'running' ? 800 : 3000);
  } catch (error) {
    $('error-banner').textContent = `대시보드 서버에 연결하지 못했다: ${error.message}`;
    $('error-banner').classList.add('show');
    schedule(3000);
  }
}

function schedule(delay) {
  clearTimeout(timer);
  timer = setTimeout(poll, delay);
}

async function start() {
  const target = $('target-input').value.trim();
  if (!target) return;
  $('start-btn').disabled = true;
  /* 새 Run 이므로 이전 Run 의 활동 로그와 순번을 버린다. */
  lastSequence = 0;
  seenNotes.clear();
  activity = [];
  expandedFindingGroups.clear();
  try {
    const payload = {
      target,
      mode: $('mode-select').value,
      vuln: $('vuln-select').value,
      engine: $('engine-select').value,
      budget: Number($('budget-input').value) || 0,
      access_accounts: {},
    };
    for (const select of document.querySelectorAll('#advanced-grid select')) {
      payload[select.dataset.field] = select.value;
    }
    for (const box of document.querySelectorAll('#boolean-grid input')) {
      payload[box.dataset.field] = box.checked;
    }
    for (const input of document.querySelectorAll('[data-llm-field]')) {
      const value = input.value.trim();
      if (!value) continue;
      payload[input.dataset.llmField] =
        input.dataset.llmField === 'llm_rpm_limit' ? Number(value) : value;
    }
    for (const input of document.querySelectorAll('[data-secret]')) {
      const name = input.dataset.secret;
      if (name.startsWith('actor_') || name.startsWith('owner_')) {
        payload.access_accounts[name] = input.value;
      } else {
        payload[name] = input.value;
      }
    }

    const response = await fetch('/api/run', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Hacklipse-CSRF': config.csrf_token || '',
      },
      body: JSON.stringify(payload),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `HTTP ${response.status}`);
    for (const input of document.querySelectorAll('[data-secret]')) {
      if (input.dataset.secret !== 'juice_shop_db') input.value = '';
    }
    markSetupNeeded();
  } catch (error) {
    $('error-banner').textContent = `Run을 시작하지 못했다: ${error.message}`;
    $('error-banner').classList.add('show');
    $('start-btn').disabled = false;
    /* 무엇을 채워야 하는지 바로 보여준다. 사유만 띄우고 칸을 숨겨두지 않는다. */
    const blank = [...document.querySelectorAll('[data-secret]')].find(
      (input) => !input.value.trim()
    );
    if (blank) {
      openSetup();
      blank.focus();
    }
    markSetupNeeded();
  }
  schedule(100);
}

function tickClock() {
  const now = new Date();
  const month = now.toLocaleString('en-GB', { month: 'short', timeZone: 'UTC' }).toUpperCase();
  const utc = `${pad2(now.getUTCDate())} ${month} ${now.getUTCFullYear()} · ${pad2(
    now.getUTCHours()
  )}:${pad2(now.getUTCMinutes())} UTC`;
  $('clock').textContent = utc;
}

/* 자격증명 입력은 실행 모드가 요구할 때만 만든다. 필요 없는 화면에 비밀 입력칸을
 * 띄워두지 않는다. type=password 는 어깨너머 노출과 브라우저 자동완성을 막는다. */
const CREDENTIAL_FIELDS = {
  access: [
    ['actor_email', 'ACTOR 이메일', 'text'],
    ['actor_password', 'ACTOR 비밀번호', 'password'],
    ['owner_email', 'OWNER 이메일', 'text'],
    ['owner_password', 'OWNER 비밀번호', 'password'],
  ],
  ssti: [['ssti_token', 'SSTI token Cookie', 'password']],
  db: [['juice_shop_db', 'juiceshop.sqlite 경로', 'text']],
};

function buildControls() {
  const fill = (select, items, selected) => {
    select.innerHTML = items
      .map(
        (item) =>
          `<option value="${escapeHtml(item.id)}"${item.available === false ? ' disabled' : ''}>${escapeHtml(
            item.available === false ? `${item.label} (키 없음)` : item.label
          )}</option>`
      )
      .join('');
    if (selected) select.value = selected;
  };

  $('target-input').value = config.default_target || '';
  $('target-input').title = `허용 호스트: ${(config.allowed_hosts || []).join(', ')}`;
  $('budget-input').max = config.max_budget;

  fill($('mode-select'), config.modes, 'generic');
  fill($('vuln-select'), config.vulns, 'all');
  fill($('engine-select'), config.engines, config.default_engine);
  $('engine-select').title = (config.engines || [])
    .filter((engine) => engine.key_env)
    .map((engine) => `${engine.label}: ${engine.available ? '사용 가능' : engine.key_env + ' 미설정'}`)
    .join('\n');

  $('advanced-grid').innerHTML = (config.advanced || [])
    .map(
      (spec) =>
        `<div class="field"><span class="meta-label">${escapeHtml(spec.label)}</span>` +
        `<select class="control-input" data-field="${escapeHtml(spec.field)}" data-llm-only="${spec.llm_only.join(',')}">` +
        spec.choices
          .map((choice) => `<option value="${escapeHtml(choice)}">${escapeHtml(choice)}</option>`)
          .join('') +
        `</select></div>`
    )
    .join('');
  $('llm-grid').innerHTML = (config.llm_fields || [])
    .map(
      (spec) =>
        `<div class="field"><span class="meta-label">${escapeHtml(spec.label)}</span>` +
        `<input class="control-input" data-llm-field="${escapeHtml(spec.field)}" ` +
        `placeholder="${escapeHtml(spec.placeholder)}" autocomplete="off" spellcheck="false"></div>`
    )
    .join('');
  $('boolean-grid').innerHTML = (config.booleans || [])
    .map(
      (spec) =>
        `<div class="field check" data-check="${escapeHtml(spec.field)}">` +
        `<input type="checkbox" id="chk-${escapeHtml(spec.field)}" data-field="${escapeHtml(spec.field)}" data-llm-only="${spec.llm_only}">` +
        `<label for="chk-${escapeHtml(spec.field)}">${escapeHtml(spec.label)}</label></div>`
    )
    .join('');

  $('credential-grid').addEventListener('input', markSetupNeeded);
  $('mode-select').addEventListener('change', syncMode);
  $('vuln-select').addEventListener('change', syncMode);
  $('engine-select').addEventListener('change', syncEngine);
  syncMode();
  syncEngine();
}

/* 모드에 따라 필요한 입력만 남긴다. 화면이 서버 규칙을 미리 반영해 400 을 줄인다. */
let credentialSignature = null;

function syncMode() {
  const juice = $('mode-select').value === 'juice-shop';
  const vuln = $('vuln-select').value;
  $('vuln-field').hidden = !juice;

  const needed = [];
  if (juice && ['access_control', 'all'].includes(vuln)) needed.push('access');
  if (juice && vuln === 'ssti') needed.push('ssti');
  if (juice && ['path_traversal', 'all'].includes(vuln)) needed.push('db');

  $('credential-block').hidden = needed.length === 0;
  applyBrowserRule(juice, vuln);
  /* 입력을 요구하면서 칸을 숨겨두지 않는다. 필요해지는 순간 패널을 연다. */
  if (needed.length) openSetup();
  markSetupNeeded();

  /* 이미 같은 구성이면 다시 그리지 않는다 — 입력해둔 값을 지우게 된다. */
  const signature = needed.join('|');
  if (signature === credentialSignature) return;
  credentialSignature = signature;

  const wanted = needed.flatMap((group) => CREDENTIAL_FIELDS[group]);
  $('credential-grid').innerHTML = wanted
    .map(
      ([name, label, type]) =>
        `<div class="field"><span class="meta-label">${escapeHtml(label)}</span>` +
        `<input class="control-input" type="${type}" data-secret="${escapeHtml(name)}" autocomplete="off" spellcheck="false"></div>`
    )
    .join('');
}

/* 브라우저 검증은 Juice Shop 모드에서 유형이 정한다(CLI 와 같은 규칙). 수동 선택을
 * 막아 화면 표시와 실제 배선을 일치시킨다. */
function setSetupExpanded(expanded) {
  $('setup-body').hidden = !expanded;
  for (const id of ['setup-toggle', 'setup-panel-toggle']) {
    $(id).setAttribute('aria-expanded', String(expanded));
  }
  $('setup-panel-toggle').setAttribute(
    'aria-label',
    expanded ? '실행 조건 접기' : '실행 조건 펼치기'
  );
}

function openSetup() {
  setSetupExpanded(true);
}

/* 비어 있는 필수 입력이 남아 있으면 SETUP 버튼에 표시한다. 패널을 닫아둔 채로도
 * 무엇이 막고 있는지 알 수 있어야 한다. */
function markSetupNeeded() {
  const pending = [...document.querySelectorAll('[data-secret]')].some(
    (input) => !input.value.trim()
  );
  $('setup-toggle').classList.toggle('needs-input', pending);
}

function applyBrowserRule(juice, vuln) {
  const box = document.querySelector('[data-field="browser"]');
  if (!box) return;
  box.dataset.ruleLocked = juice ? 'true' : 'false';
  if (juice) box.checked = ['xss', 'all'].includes(vuln);
  box.closest('.field').classList.toggle('disabled', juice);
}

/* LLM 이 필요한 선택지는 결정적 엔진에서 잠근다. 서버도 같은 규칙으로 거부한다. */
function syncEngine() {
  const llm = $('engine-select').value.startsWith('llm:');
  /* 결정적 엔진에서는 모델·호출 상한이 의미가 없다. 칸 자체를 숨긴다. */
  $('llm-grid').hidden = !llm;
  for (const select of document.querySelectorAll('#advanced-grid select')) {
    const llmOnly = (select.dataset.llmOnly || '').split(',').filter(Boolean);
    for (const option of select.options) option.disabled = !llm && llmOnly.includes(option.value);
    if (select.selectedOptions[0]?.disabled) select.selectedIndex = 0;
  }
  for (const box of document.querySelectorAll('#boolean-grid input')) {
    if (box.dataset.field === 'browser') continue;
    const locked = box.dataset.llmOnly === 'true' && !llm;
    box.dataset.ruleLocked = locked ? 'true' : 'false';
    if (locked) box.checked = false;
    box.closest('.field').classList.toggle('disabled', locked);
  }
  applyLocks(false);
}

/* 실행 중 잠금과 규칙 잠금을 함께 적용한다. 둘 중 하나라도 걸리면 잠근다. */
function applyLocks(busy) {
  for (const control of document.querySelectorAll('#setup-panel select, #setup-panel input')) {
    control.disabled = busy || control.dataset.ruleLocked === 'true';
  }
}

async function boot() {
  tickClock();
  setInterval(tickClock, 30000);
  $('start-btn').addEventListener('click', start);
  const toggleSetup = () => setSetupExpanded($('setup-body').hidden);
  $('setup-toggle').addEventListener('click', toggleSetup);
  $('setup-panel-toggle').addEventListener('click', toggleSetup);
  $('copy-report').addEventListener('click', async () => {
    await navigator.clipboard.writeText($('report-body').textContent);
    const button = $('copy-report');
    button.textContent = 'COPIED';
    setTimeout(() => (button.textContent = 'COPY'), 1500);
  });
  $('target-input').addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && !$('start-btn').disabled) start();
  });

  /* 허용 호스트·엔진·실행 조건 선택지는 서버가 안다. 화면이 값을 지어내지 않는다. */
  try {
    const response = await fetch('/api/config', { cache: 'no-store' });
    config = await response.json();
    buildControls();
  } catch (error) {
    $('error-banner').textContent = `설정을 읽지 못했다: ${error.message}`;
    $('error-banner').classList.add('show');
  }

  poll();
}

boot();
