const followingStep = new Map([
  ['login', 'password'],
  ['password', 'captcha'],
  ['captcha', 'totp'],
  ['totp', 'authenticated']
]);

// Headless presentation controller. The server remains the authorization owner.
export class LoginClient {
  #transport;
  #onState;
  #ticket;
  #generation = 0;
  #pending;
  #state = Object.freeze({ step: 'login', busy: false, error: null });

  constructor({ transport, onState }) {
    if (typeof transport !== 'function' || typeof onState !== 'function') throw new TypeError('Adapters required');
    this.#transport = transport;
    this.#onState = onState;
    this.#notify();
  }

  get state() { return this.#state; }

  #notify() {
    // Presentation failures must not change an authentication result or strand busy.
    try {
      const result = this.#onState(this.#state);
      if (result && typeof result.then === 'function') Promise.resolve(result).catch(() => {});
    } catch {}
  }

  #publish(step, busy, error = null) {
    this.#state = Object.freeze({ step, busy, error });
    this.#notify();
  }

  reset() {
    this.#generation++;
    this.#pending?.abort();
    this.#pending = undefined;
    this.#ticket = undefined;
    this.#publish('login', false);
  }

  async submit(value) {
    if (this.#state.busy) throw new Error('Submission already in progress');
    const step = this.#state.step;
    const next = followingStep.get(step);
    if (!next) throw new Error('Start a new login attempt first');
    const generation = this.#generation;
    const controller = new AbortController();
    this.#pending = controller;
    this.#publish(step, true);
    if (generation !== this.#generation) {
      value = undefined;
      return false;
    }
    try {
      const pending = this.#transport({ step, value, ticket: this.#ticket }, { signal: controller.signal });
      value = undefined;
      const response = await pending;
      if (generation !== this.#generation) return false;
      const validObject = response && Object.getPrototypeOf(response) === Object.prototype;
      if (next === 'authenticated') {
        if (!validObject || Object.keys(response).join(',') !== 'authenticated' || response.authenticated !== true) {
          throw new Error('Invalid authentication response');
        }
        this.#ticket = undefined;
      } else {
        if (!validObject || Object.keys(response).sort().join(',') !== 'next,ticket' || response.next !== next ||
            typeof response.ticket !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(response.ticket)) {
          throw new Error('Invalid authentication response');
        }
        this.#ticket = response.ticket;
      }
      this.#pending = undefined;
      this.#publish(next, false);
      return generation === this.#generation;
    } catch {
      value = undefined;
      if (generation !== this.#generation) return false;
      this.#ticket = undefined;
      this.#pending = undefined;
      this.#publish('login', false, 'request_failed');
      return false;
    }
  }
}
