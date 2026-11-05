// Run with: node .github/tests/handoff.test.cjs (no network or dependencies).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const workflow = fs.readFileSync(process.env.HANDOFF_WORKFLOW || path.join(__dirname, '../workflows/handoff.yml'), 'utf8');
const script = workflow.split('          script: |\n')[1].split('\n').map(line => line.slice(12)).join('\n');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const execute = new AsyncFunction('github', 'context', 'core', script);
const condition = workflow.match(/    if: >-\n([\s\S]*?)    # Job-level/)[1].trim();
const enabled = new Function('github', 'contains', `return (${condition});`);
const actors = ['bloclabs-io', 'bloclabs-britney', 'chatgpt-codex-connector[bot]', 'cursor[bot]'];
const sha = 'a'.repeat(40), nextSha = 'b'.repeat(40);
const date = n => `2026-01-01T00:00:0${n}Z`;
const markerBody = (head, phase = 'open') => `<!-- bloclabs-handoff-state:v1 ${head} ${phase} 0 -->`;

function fixture({ head = sha, draft = false, state = 'open', labels = ['ready-for-test', 'unrelated'], tracked = sha } = {}) {
  const model = {
    pr: { number: 7, state, draft, head: { sha: head, repo: { full_name: 'example/repo' } } },
    labels: new Set(labels),
    comments: tracked ? [{ id: 1, user: { login: 'github-actions[bot]' }, body: markerBody(tracked), updated_at: date(0) }] : [],
    calls: [], failed: [],
    events: [],
  };
  const issues = {
    listComments: async () => model.comments,
    listEvents: async () => model.events,
    getLabel: async () => { throw { status: 404 }; },
    createLabel: async () => {},
    updateLabel: async () => {},
    listLabelsOnIssue: async () => ({ data: [...model.labels].map(name => ({ name })) }),
    removeLabel: async ({ name }) => { model.calls.push('remove'); model.labels.delete(name); },
    addLabels: async ({ labels }) => { model.calls.push('add'); labels.forEach(name => model.labels.add(name)); },
    createComment: async ({ body }) => {
      model.calls.push('checkpoint');
      model.comments.push({ id: model.comments.length + 1, user: { login: 'github-actions[bot]' }, body, updated_at: date(2) });
    },
    updateComment: async ({ comment_id, body }) => {
      model.calls.push('checkpoint');
      Object.assign(model.comments.find(c => c.id === comment_id), { body, updated_at: date(2) });
    },
  };
  const github = {
    rest: { issues, pulls: { get: async () => { model.calls.push('getPR'); return { data: structuredClone(model.pr) }; } } },
    paginate: async (method, args) => method(args),
  };
  model.run = async ({ event = 'issue_comment', actor = actors[3], body = 'Handoff: test', at = date(1), action = 'synchronize', reviewHead = model.pr.head.sha, fork = false } = {}) => {
    const note = { user: { login: actor }, body, created_at: at, submitted_at: event === 'pull_request_review' ? at : undefined, commit_id: reviewHead };
    const payload = {
      action, repository: { full_name: 'example/repo' },
      // Real issue_comment issue objects have no draft field. Both payloads can be stale.
      issue: { number: 7, state: 'open', pull_request: {} },
      pull_request: { number: 7, state: 'open', draft: false, head: { sha, repo: { full_name: fork ? 'fork/repo' : 'example/repo' } } },
      comment: note, review: note,
    };
    if (!enabled({ event_name: event, event: payload }, (text, part) => (text || '').includes(part))) return;
    await execute(github, { repo: { owner: 'example', repo: 'repo' }, eventName: event, payload }, {
      info: () => {}, setFailed: message => model.failed.push(message),
    });
  };
  model.stages = () => [...model.labels].filter(name => name !== 'unrelated').sort();
  return model;
}

test('issue_comment fetches the live draft PR and clears stale stage labels', async () => {
  const f = fixture({ draft: true });
  await f.run();
  assert.deepEqual(f.stages(), []);
  assert.ok(f.calls.includes('getPR'));
  assert.ok(f.labels.has('unrelated'));
});

test('live closed state wins over the stale open issue payload', async () => {
  const f = fixture({ state: 'closed' });
  await f.run();
  assert.deepEqual(f.stages(), []);
});

for (const actor of [...actors, 'outsider']) {
  test(`a dropped synchronize is reconciled by the replacing comment from ${actor}`, async () => {
    // The synchronize job is deliberately never executed: a later comment replaced its pending slot.
    const f = fixture({ head: nextSha, tracked: sha });
    await f.run({ actor, body: 'Handoff: merge' });
    assert.deepEqual(f.stages(), ['needs-review']);
    assert.match(f.comments[0].body, new RegExp(nextSha));
    assert.ok(!f.comments[0].body.includes('Handoff:'));
  });
}

test('the next fresh handoffs work after the lost push reset is repaired', async () => {
  const f = fixture({ head: nextSha });
  await f.run({ actor: 'outsider' });
  await f.run({ at: date(3) });
  assert.deepEqual(f.stages(), ['ready-for-test']);
  await f.run({ actor: actors[1], body: 'Handoff: merge', at: date(4) });
  assert.deepEqual(f.stages(), ['tested']);
});

for (const event of ['reopened', 'ready_for_review']) {
  test(`a dropped ${event} resets review even when the head and live open state match`, async () => {
    const f = fixture();
    f.events.push({ id: 10, event });
    await f.run({ actor: 'outsider' });
    assert.deepEqual(f.stages(), ['needs-review']);
    assert.match(f.comments[0].body, /open 10 -->/);
  });
}

test('ordinary issue events do not invalidate a head checkpoint', async () => {
  const f = fixture();
  f.events.push({ id: 10, event: 'labeled' }, { id: 11, event: 'assigned' });
  await f.run();
  assert.deepEqual(f.stages(), ['ready-for-test']);
  assert.equal(f.calls.includes('checkpoint'), false);
});

test('a delayed old handoff cannot undo a new-head checkpoint', async () => {
  const f = fixture({ head: nextSha });
  await f.run({ event: 'pull_request' });
  await f.run({ actor: actors[1], body: 'Handoff: merge', at: date(1) });
  assert.deepEqual(f.stages(), ['needs-review']);
});

test('an old-head review cannot promote the current head, even if submitted later', async () => {
  const f = fixture({ head: nextSha, tracked: nextSha, labels: ['needs-review'] });
  await f.run({ event: 'pull_request_review', reviewHead: sha });
  assert.deepEqual(f.stages(), ['needs-review']);
});

test('first run on an existing PR establishes a checkpoint and requires a fresh handoff', async () => {
  const f = fixture({ tracked: null });
  await f.run({ actor: actors[1], body: 'Handoff: merge' });
  assert.deepEqual(f.stages(), ['needs-review']);
  assert.equal(f.comments.length, 1);
});

test('user-authored checkpoint copies cannot suppress a new-head reset', async () => {
  const f = fixture({ head: nextSha });
  f.comments.push({ id: 2, user: { login: actors[3] }, body: markerBody(nextSha), updated_at: date(0) });
  await f.run();
  assert.deepEqual(f.stages(), ['needs-review']);
});

for (const event of ['issue_comment', 'pull_request_review']) {
  for (const actor of actors) {
    for (const [command, target] of Object.entries({ review: 'needs-review', fix: 'needs-fix', test: 'ready-for-test' })) {
      test(`${event}: ${actor} can hand off ${command}`, async () => {
        const f = fixture();
        await f.run({ event, actor, body: `Handoff: ${command}` });
        assert.deepEqual(f.stages(), [target]);
      });
    }
    test(`${event}: merge is restricted to Britney`, async () => {
      const f = fixture();
      await f.run({ event, actor, body: 'Handoff: merge' });
      assert.deepEqual(f.stages(), [actor === actors[1] ? 'tested' : 'ready-for-test']);
      assert.equal(f.failed.length, actor === actors[1] ? 0 : 1);
    });
  }
  test(`${event}: Britney merge requires ready-for-test`, async () => {
    const f = fixture({ labels: ['needs-review'] });
    await f.run({ event, actor: actors[1], body: 'Handoff: merge' });
    assert.deepEqual(f.stages(), ['needs-review']);
    assert.equal(f.failed.length, 1);
  });
  test(`${event}: unauthorized actor cannot change an established head`, async () => {
    const f = fixture();
    await f.run({ event, actor: 'outsider', body: 'Handoff: fix' });
    assert.deepEqual(f.stages(), ['ready-for-test']);
    assert.deepEqual(f.calls, ['getPR']);
  });
  for (const body of ['prefix Handoff: fix', 'Handoff: fix suffix', '> Handoff: fix', '```\nHandoff: fix\n```', '~~~\nHandoff: fix\n~~~', '```\nHandoff: fix']) {
    test(`${event}: whole-line rule ignores ${JSON.stringify(body)}`, async () => {
      const f = fixture();
      await f.run({ event, body });
      assert.deepEqual(f.stages(), ['ready-for-test']);
    });
  }
  test(`${event}: last unfenced line wins`, async () => {
    const f = fixture();
    await f.run({ event, body: 'Handoff: review\nHandoff: fix\n```\nHandoff: test\n```' });
    assert.deepEqual(f.stages(), ['needs-fix']);
  });
  test(`${event}: a comment without Handoff skips the job entirely`, async () => {
    const f = fixture({ head: nextSha });
    await f.run({ event, body: 'Just a normal comment' });
    assert.deepEqual(f.calls, []);
  });
}

for (const action of ['opened', 'reopened', 'ready_for_review', 'synchronize']) {
  test(`${action} resets the stage and records the current head`, async () => {
    const f = fixture();
    await f.run({ event: 'pull_request', action });
    assert.deepEqual(f.stages(), ['needs-review']);
    assert.ok(f.calls.includes('checkpoint'));
  });
}

test('fork pull_request events keep the read-only token guard', async () => {
  const f = fixture();
  await f.run({ event: 'pull_request', fork: true });
  assert.deepEqual(f.calls, []);
});
