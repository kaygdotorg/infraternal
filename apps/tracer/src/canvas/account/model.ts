/**
 * What the person's card (D283) knows about the person, and the one interface it reads it through.
 *
 * The card never talks to a server itself. It reads an `AccountModel`: the product's model fills in what the server can
 * say: the signed-in identity first, then setup facts on open. The mock's test double fills in everything, so the
 * whole card can be seen and tested before the server can say it. A field the model does not know is `undefined` and its
 * row is not drawn at all (TASTE: no invented chrome); a field the model knows is shown as a plain fact, and as a
 * concern in its own value when there is one (words.ts).
 */
import type { HostPlatform } from "../../../../../packages/ui/src/host-icons";

/** One machine an account can log in to. `tags` are the tags it carries, in order: they colour it (TASTE: named things are chips). */
export interface LoginHost { name: string; platform: HostPlatform; tags: string[] }

/** One account the person can log in as, and the machines where that works (read-only: the access rules own the change). */
export interface Login { account: string; hosts: LoginHost[] }

/** The state of the recovery key. It is mandatory at setup (D24), so "not set up" is an exception, not a normal state. */
export interface Recovery {
  setUp: boolean;
  /** When the person last proved they still hold the key (epoch milliseconds); `null` = never; absent = verification history unavailable. */
  verifiedAt?: number | null | undefined;
}

export interface Person {
  /** Optional in the data (an imported person may have none): the card then shows the username as the name. */
  name: string;
  username: string;
  /** Optional (Q4), never part of sign-in; empty = none. `undefined` = this model cannot hold one. */
  email?: string | undefined;
  /** A picture the person uploaded, as a data URL; undefined = the initials. */
  picture?: string | undefined;
  /** Present only in a team (EE, Q5). */
  org?: { name: string; role: "Member" | "Admin" };
  /** The sign-in health. Each is undefined while the server cannot say it; the row is then not drawn. */
  loginAs?: Login[] | undefined;
  passkeys?: number | undefined;
  recovery?: Recovery | undefined;
  devices?: number | undefined;
}

export interface AccountModel {
  person(): Person;
  /** Refresh on open, never during idle preparation or first paint. */
  refresh?(): Promise<void>;
  onChange(run: () => void): () => void;
  /**
   * Saves a change of the name, the email or the picture. Absent when the server cannot store them yet: the card then
   * offers no pencil, no picture menu and no "add email", rather than controls that do nothing.
   */
  patch?(next: Partial<Pick<Person, "name" | "email" | "picture">>): void;
}

/** The signed-in identity; setup facts arrive only when the card or Settings opens. */
export function identityModel(identity: { name: string; username: string }, userId: string, incarnation?: string): AccountModel {
  const person: Person = { name: identity.name, username: identity.username };
  const listeners = new Set<() => void>();
  let pending: Promise<void> | undefined;
  return {
    person: () => person,
    onChange(run) { listeners.add(run); return () => { listeners.delete(run); }; },
    refresh() {
      return pending ??= import("../../auth").then((auth) => auth.readAccountSummary()).then((summary) => {
        // A shared cookie may have changed since this screen mounted. Never apply another lifetime's facts.
        if (summary.user_id !== userId || (incarnation && summary.session_incarnation !== incarnation)) return;
        person.passkeys = summary.passkeys;
        person.recovery = { setUp: summary.recovery_set_up };
        for (const listener of listeners) listener();
      }).catch(() => { /* Unknown stays unknown; reopening retries without inventing an empty account. */ })
        .finally(() => { pending = undefined; });
    },
  };
}
