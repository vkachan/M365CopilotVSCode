import * as vscode from "vscode";
import {
  describeProfile,
  parsePastedProfile,
  chatEndpointDiagnostics,
  log,
  tokenFingerprint,
  tokenFormat,
  type CopilotProfile,
  debug,
} from "@m365copilot/core/bizchat";
import { t } from "./i18n";

const SECRET_KEY = "m365copilot.profile.v1";

/** A profile without its timestamp: what tells a repeated delivery from a change. */
const stable = (profile: CopilotProfile) => JSON.stringify({ ...profile, capturedAt: undefined });

/**
 * Stores the captured Copilot profile in VS Code SecretStorage (encrypted,
 * per-machine) and notifies listeners when it changes so the model picker can
 * refresh its warning state.
 */
export class ProfileStore {
  private cached: CopilotProfile | null | undefined;
  private readonly changeEmitter = new vscode.EventEmitter<void>();
  readonly onDidChange = this.changeEmitter.event;

  constructor(private readonly secrets: vscode.SecretStorage) {
    // Cross-window sync: another window writing the secret should refresh
    // this window's cache and picker.
    this.disposable = secrets.onDidChange((e) => {
      if (e.key === SECRET_KEY) {
        debug("profile", "the stored secret changed (this or another window); cache dropped");
        this.cached = undefined;
        this.changeEmitter.fire();
      }
    });
  }

  private readonly disposable: vscode.Disposable;

  async get(): Promise<CopilotProfile | null> {
    if (this.cached !== undefined) return this.cached;
    const raw = await this.secrets.get(SECRET_KEY);
    if (!raw) {
      this.cached = null;
      return null;
    }
    try {
      this.cached = JSON.parse(raw) as CopilotProfile;
    } catch {
      this.cached = null;
    }
    return this.cached;
  }

  async has(): Promise<boolean> {
    return (await this.get()) !== null;
  }

  /** Parse and store a pasted profile/token. Returns the normalized profile. */
  async setFromPaste(pasted: string): Promise<CopilotProfile> {
    return (await this.receive(pasted)).profile;
  }

  /**
   * Parse and store a profile delivered by the browser, saying what it was:
   * `tokenChanged` only for another token (a real renewal, by fingerprint),
   * `changed` when anything stored changed. The same delivery again writes
   * nothing — every write reaches every window — and the same token M365
   * already refused stays refused.
   */
  async receive(
    pasted: string,
  ): Promise<{ profile: CopilotProfile; tokenChanged: boolean; changed: boolean }> {
    const incoming = parsePastedProfile(pasted);
    const stored = await this.get();
    const sameToken =
      stored !== null &&
      tokenFingerprint(stored.accessToken) === tokenFingerprint(incoming.accessToken);
    const next =
      sameToken && stored?.rejectedAt ? { ...incoming, rejectedAt: stored.rejectedAt } : incoming;
    if (stored && sameToken && stable(stored) === stable(next))
      return { profile: stored, tokenChanged: false, changed: false };
    return { profile: await this.set(next), tokenChanged: !sameToken, changed: true };
  }

  /** Store an already parsed profile (see {@link parsePastedProfile}). */
  async set(profile: CopilotProfile): Promise<CopilotProfile> {
    await this.secrets.store(SECRET_KEY, JSON.stringify(profile));
    // A personal account connects through the chat endpoint it was captured
    // with: say what it has (never the token, the ids or the whole URL).
    if (tokenFormat(profile.accessToken) === "jwe")
      log(t("log.chatEndpoint", JSON.stringify(chatEndpointDiagnostics(profile))));
    debug("profile", "profile stored in SecretStorage", () => describeProfile(profile));
    this.cached = profile;
    this.changeEmitter.fire();
    return profile;
  }

  /**
   * M365 refused `token` (401/403): mark the stored profile so, if it is still
   * that token. A token whose expiry cannot be read (a JWE) only dies this way,
   * so from here it counts as not usable — the editor offers the fix and the
   * browser extension, which sees it in the health check, renews it.
   */
  async markRejected(token: string): Promise<void> {
    const profile = await this.get();
    if (!profile || profile.accessToken !== token || profile.rejectedAt) return;
    debug("profile", "M365 rejected the stored token; marked as not usable");
    await this.set({ ...profile, rejectedAt: new Date().toISOString() });
  }

  async clear(): Promise<void> {
    await this.secrets.delete(SECRET_KEY);
    debug("profile", "profile deleted from SecretStorage");
    this.cached = null;
    this.changeEmitter.fire();
  }

  dispose(): void {
    this.disposable.dispose();
    this.changeEmitter.dispose();
  }
}
