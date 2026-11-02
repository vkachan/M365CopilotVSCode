/**
 * The few `vscode` APIs that ProfileStore and the local token server use, for
 * the tests that run them in plain Node (profileBridge.mts). Only resolved
 * when the real module is missing — that is, outside a VS Code host.
 */
export class EventEmitter {
  #listeners = new Set();
  event = (listener) => {
    this.#listeners.add(listener);
    return { dispose: () => this.#listeners.delete(listener) };
  };
  fire(value) {
    for (const listener of [...this.#listeners]) listener(value);
  }
  dispose() {
    this.#listeners.clear();
  }
}
