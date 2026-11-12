import { fixture } from './fixtures.mjs';

const example = fixture();
try {
  example.provision();
  example.core.seedSyntheticRecord('record-1', 'user-1');
  const session = example.login();
  example.advance(); // A used login TOTP code cannot authorize another operation.
  const action = 'records.remove';
  const args = { id: 'record-1' };
  const operation = 'operation-1';
  const { grant } = example.core.stepUp({ session, action, args, operation, code: example.code() });
  const body = { session, action, args, operation, grant };
  const first = example.core.dispatch(example.request(body));
  const retry = example.core.dispatch(example.request(body)); // Fresh signature/nonce, same operation.
  console.log(JSON.stringify({ login: 'completed', first, retry, sameResult: JSON.stringify(first) === JSON.stringify(retry) }));
} finally {
  example.core.close();
}
