import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { assessJavaRollout } from './java-inventory.mjs';

const digest = char => 'sha256:' + char.repeat(64);
const now = Date.parse('2026-11-18T10:30:00.000Z');
const artifactDigest = digest('a');
const finding = {
  vendor: 'synthetic-vendor', package: 'demo-jdk', build: '21.0.0-demo+1',
  architecture: 'amd64', status: 'fixed', reference: 'https://example.invalid/errata/demo',
};
const policy = {
  schema: 'amqic-java-policy/v1', advisory: 'CVE-2026-114938', changeId: 'demo-change',
  changeStartedAt: '2026-11-18T10:00:00.000Z',
  expected: [{ workload: 'worker-a', previousInstance: 'old-a', artifactDigest }],
  vendorFindings: [finding],
};
const observation = {
  workload: 'worker-a', instance: 'new-a', startedAt: '2026-11-18T10:20:00.000Z',
  vendor: finding.vendor, package: finding.package, build: finding.build,
  architecture: finding.architecture, artifactDigest, evidenceDigest: digest('b'),
};
const inventory = {
  schema: 'amqic-java-inventory/v1', changeId: policy.changeId,
  observedAt: '2026-11-18T10:25:00.000Z', observations: [observation],
};

test('accept the newly running exact artifact and vendor-validated build', () => {
  const report = assessJavaRollout(policy, inventory, now);
  assert.equal(report.checkPassed, true);
  assert.deepEqual(report.results, [{
    workload: 'worker-a', outcome: 'accepted', vendorStatus: 'fixed',
    reference: finding.reference, evidenceDigest: observation.evidenceDigest,
  }]);
});

test('fail closed on older process, unknown vendor build, and wrong artifact', () => {
  for (const [update, outcome] of [
    [{ instance: 'old-a' }, 'restart-unverified'],
    [{ startedAt: '2026-11-18T09:59:59.999Z' }, 'restart-unverified'],
    [{ build: '21.0.999' }, 'vendor-status-unknown'],
    [{ architecture: 'arm64' }, 'vendor-status-unknown'],
    [{ artifactDigest: digest('c') }, 'artifact-mismatch'],
  ]) {
    const report = assessJavaRollout(policy, { ...inventory, observations: [{ ...observation, ...update }] }, now);
    assert.equal(report.checkPassed, false);
    assert.equal(report.results[0].outcome, outcome);
  }
});

test('affected entries and incomplete fleet coverage stop acceptance', () => {
  const vulnerable = { ...policy, vendorFindings: [{ ...finding, status: 'affected' }] };
  assert.equal(assessJavaRollout(vulnerable, inventory, now).results[0].outcome, 'affected');
  const larger = { ...policy, expected: [...policy.expected, { workload: 'worker-b', previousInstance: 'old-b', artifactDigest }] };
  const report = assessJavaRollout(larger, inventory, now);
  assert.equal(report.checkPassed, false);
  assert.equal(report.results[1].outcome, 'missing-observation');
  const reusedInstance = { ...inventory, observations: [{ ...observation, instance: 'old-b' }] };
  assert.equal(assessJavaRollout(larger, reusedInstance, now).results[0].outcome, 'restart-unverified');
});

test('reject duplicate, unexplained, stale, future and cross-change evidence', () => {
  for (const update of [
    { observations: [observation, observation] },
    { observations: [{ ...observation, workload: 'unreviewed-worker' }] },
    { observedAt: '2026-11-18T10:31:00.000Z' },
    { observedAt: '2026-11-18T10:10:00.000Z' },
    { changeId: 'another-change' },
  ]) {
    assert.throws(() => assessJavaRollout(policy, { ...inventory, ...update }, now));
  }
  assert.throws(() => assessJavaRollout(policy, inventory, now + 25 * 3600 * 1000));
  assert.throws(() => assessJavaRollout({ ...policy, vendorFindings: [finding, finding] }, inventory, now));
});

function fixture(path) {
  return readFileSync(new URL(path, import.meta.url), 'utf8');
}

test('shared Helm pod specification keeps restricted defaults and bounded storage', () => {
  const pod = JSON.parse(fixture('./helm/files/pod-spec.json'));
  assert.equal(pod.automountServiceAccountToken, false);
  assert.equal(pod.securityContext.runAsNonRoot, true);
  assert.ok(pod.securityContext.runAsUser > 0);
  assert.equal(pod.securityContext.seccompProfile.type, 'RuntimeDefault');
  assert.equal(pod.securityContext.appArmorProfile.type, 'RuntimeDefault');
  assert.deepEqual([pod.hostNetwork, pod.hostPID, pod.hostIPC], [false, false, false]);
  assert.equal(pod.nodeSelector['kubernetes.io/os'], 'linux');
  const app = pod.containers[0];
  assert.equal(pod.containers.length, 1);
  assert.equal(app.image, undefined);
  assert.equal(app.securityContext.privileged, false);
  assert.equal(app.securityContext.allowPrivilegeEscalation, false);
  assert.equal(app.securityContext.readOnlyRootFilesystem, true);
  assert.deepEqual(app.securityContext.capabilities.drop, ['ALL']);
  assert.deepEqual(pod.volumes, [{ name: 'tmp', emptyDir: { sizeLimit: '64Mi' } }]);
  assert.ok(app.resources.requests.cpu && app.resources.limits.memory);

  const deployment = fixture('./helm/templates/deployment.yaml');
  assert.match(deployment, /required .*approved digest-pinned image/);
  assert.match(deployment, /@sha256:\[0-9a-f\]\{64\}/);
  assert.match(deployment, /\.Files\.Get "files\/pod-spec\.json"/);
  const network = fixture('./helm/templates/networkpolicy.yaml');
  assert.match(network, /policyTypes: \[Ingress, Egress\]/);
  assert.match(network, /ingress: \[\]\s+egress: \[\]/);
  for (const text of [deployment, network]) {
    assert.match(text, /app\.kubernetes\.io\/name: amqic-java-workload/);
    assert.match(text, /app\.kubernetes\.io\/instance: \{\{ \.Release\.Name \| quote \}\}/);
  }
});

test('OpenTofu guardrails and Falco output have narrow statically checked scope', () => {
  const tofu = fixture('./tofu/main.tf');
  assert.match(tofu, /pod-security\.kubernetes\.io\/enforce"\s*= "restricted"/);
  assert.match(tofu, /pod_security_version/);
  assert.match(tofu, /pod_selector \{\}\s+policy_types = \["Ingress", "Egress"\]/);
  const falco = fixture('./profiles/java-shell.falco.yaml');
  assert.match(falco, /container\.id != host and proc\.pname = java/);
  const output = falco.split('\n').find(line => line.includes('output:'));
  assert.doesNotMatch(output, /cmdline|args|env|exepath/);
});

// Source checks only: no auditd, sshd, login, Falco, kernel or shell execution.
for (const [profile, parent] of [
  ['java', 'proc.pname = java'],
  ['nginx', 'proc.pname = nginx'],
  ['node', 'proc.pname in (node, nodejs)'],
  ['postgres', 'proc.pname = postgres'],
]) {
  test(`${profile} Falco starting rule keeps successful container exec and bounded output`, () => {
    const falco = fixture(`./profiles/${profile}-shell.falco.yaml`);
    assert.match(falco, /desc:.*successful shell exec/);
    assert.match(falco, /evt\.type in \(execve, execveat\) and evt\.dir = < and evt\.rawres >= 0/);
    assert.match(falco, /container\.id != host/);
    const condition = falco.split('condition:')[1].split('output:')[0];
    assert.equal(condition.match(/proc\.pname (?:= \w+|in \([^)]+\))/g)?.join(''), parent);
    assert.match(condition, /proc\.name in \(sh, bash, dash, ash, zsh, ksh\)/);
    assert.match(falco, /^  source: syscall$/m);
    assert.match(falco, /^  priority: WARNING$/m);
    const outputs = falco.split('\n').filter(line => /^\s*output:/.test(line));
    assert.equal(outputs.length, 1);
    assert.doesNotMatch(outputs[0], /cmdline|args|env|exepath/);
    assert.deepEqual(outputs[0].match(/%[a-zA-Z0-9_.]+/g), [
      '%container.id', '%proc.pname', '%proc.name', '%proc.pid',
    ]);
  });
}

test('SSH integrity watch template names the file class without live fingerprints', () => {
  const template = fixture('../../infra/ssh/authorized-keys-integrity.audit.rules.template');
  assert.match(template, /@@ADMIN_USER@@/);
  assert.match(template, /authorized_keys/);
  assert.match(template, /\.ssh/);
  assert.match(template, /sshd_config\.d\/00-security\.conf/);
  assert.doesNotMatch(template, /SHA256:[A-Za-z0-9+/]{20,}={0,2}|(?:[0-9a-f]{2}:){15}[0-9a-f]{2}/i);
});
