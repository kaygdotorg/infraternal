/** Typed Mesh actions and revision-aware live snapshots over the multiplexed client transport [164,180,187]. */

export type MeshNodeId = number;

/** The Mesh API exposes only node and tag endpoints in this slice. */
export type MeshEndpoint = { Node: MeshNodeId } | { Tag: string };

/** Traffic policy shared with mesh-core's Arrow representation. */
export type MeshTrafficPolicy =
  | "None"
  | "All"
  | { Ports: readonly { protocol: "Tcp" | "Udp"; number: number }[] };

/** An enrolled node and its current control-plane liveness measurement. */
export interface MeshNode {
  node: {
    id: MeshNodeId;
    public_key: readonly number[];
    host: string;
    tags: readonly string[];
  };
  /** Whether this node's attached infraternal agent supports safe mesh key rotation. */
  key_rotation_supported?: boolean;
  live: boolean;
  last_seen: number | null;
  last_rtt_us: number | null;
}

/** A tag with members in stable node-ID order. */
export interface MeshTag {
  name: string;
  members: readonly MeshNodeId[];
}

/** A named grant carrying the validated mesh-core directional policy. */
export interface MeshGrant {
  name: string;
  arrow: {
    id: number;
    from: MeshEndpoint;
    to: MeshEndpoint;
    both_ways: boolean;
    ports: MeshTrafficPolicy;
  };
}

/** Permission-filtered Mesh inventory returned by list and subscription snapshots. */
export interface MeshSnapshot {
  revision: number;
  nodes: readonly MeshNode[];
  tags: readonly MeshTag[];
  grants: readonly MeshGrant[];
}

/** A continuation bound to one revision and the stable nodes/tags/grants order. */
export interface MeshCursor {
  revision: number;
  offset: number;
}

/** One bounded wire page; views receive the assembled MeshSnapshot instead. */
export interface MeshSnapshotPage extends MeshSnapshot {
  next_cursor?: MeshCursor;
}

/** Optional tag filter shared by list calls and live subscriptions. */
export interface MeshFilter {
  tag?: string;
}

/** Granular role actions; visibility follows an assigned action as required by D187. */
export type MeshRoleAction =
  | "mesh.manage_nodes"
  | "mesh.manage_tags"
  | "mesh.manage_grants"
  | "mesh.manage_roles";

/** Public action IDs handled by the current Mesh API. */
export type MeshActionId =
  | "mesh.list"
  | "mesh.node.enroll"
  | "mesh.node.observe"
  | "mesh.node.rename"
  | "mesh.node.delete"
  | "mesh.tag.create"
  | "mesh.tag.rename"
  | "mesh.tag.delete"
  | "mesh.tag.member.add"
  | "mesh.tag.member.remove"
  | "mesh.grant.create"
  | "mesh.grant.move"
  | "mesh.grant.delete"
  | "mesh.grant.rename"
  | "mesh.role.define"
  | "mesh.role.assign"
  | "mesh.default.get"
  | "mesh.default.preview"
  | "mesh.default.set";

/** Edition default or persisted owner choice for new Mesh connections [216]. */
export type MeshDefaultPolicy = "Allow" | "Deny";

/** One bounded page of directed pairs that would lose new-connection reach. */
export interface MeshDefaultPreview {
  default_policy: MeshDefaultPolicy;
  revision: number;
  loses_reach: readonly (readonly [MeshNodeId, MeshNodeId])[];
  total_pairs: number;
  /**
   * Nodes that would lose access to the server's own host: SSH and every
   * other service there follow Access, while control-plane reach to the
   * server is never lost (#221, D352). Sent on the first page only; later
   * pages carry an empty list.
   */
  loses_ssh_to_server: readonly MeshNodeId[];
  next_cursor: MeshCursor | null;
}

/** An invalidation or snapshot delivered by a `topic: mesh` subscription. */
export type MeshSubscriptionEvent =
  | { type: "snapshot"; snapshot: MeshSnapshotPage }
  | { type: "resync"; snapshot: MeshSnapshotPage }
  | { type: "changed"; revision: number }
  | { type: "error"; error: string };

/** A refreshed inventory or sanitized subscription failure exposed to a view. */
export type MeshClientEvent =
  | { type: "snapshot"; snapshot: MeshSnapshot }
  | { type: "error"; error: string; /** A failed refresh leaves its server watch installed. */ subscriptionActive?: boolean };

/** The action and subscription operations the existing multiplexed socket adapter must provide. */
export interface MeshTransport {
  call<TOutput>(action: MeshActionId, input: unknown): Promise<TOutput>;
  subscribe(
    filter: { topic: "mesh"; tag?: string },
    listener: (event: MeshSubscriptionEvent) => void,
  ): () => void;
}

/** A write result whose state change is identified by its committed revision. */
export interface MeshEditResult {
  revision: number;
}

/** The result returned when a node is enrolled. */
export interface MeshNodeEnrollResult extends MeshEditResult {
  node_id: MeshNodeId;
}

/** The result returned when a named grant is created. */
export interface MeshGrantCreateResult extends MeshEditResult {
  grant_id: number;
}

/** Internal cancellation marker: obsolete work is silent, not a service failure. */
class SnapshotSuperseded extends Error {}

/** Typed action and subscription client for the Mesh control plane. */
export class MeshClient {
  constructor(private readonly transport: MeshTransport) {}

  /** Read the current Mesh default; the server checks owner authority. */
  getDefault(): Promise<{ default_policy: MeshDefaultPolicy }> {
    return this.transport.call("mesh.default.get", {});
  }

  /** Preview one revision-bound page before applying a new default. */
  previewDefault(input: {
    default_policy: MeshDefaultPolicy;
    cursor?: MeshCursor;
  }): Promise<MeshDefaultPreview> {
    return this.transport.call("mesh.default.preview", input);
  }

  /** Apply the preview's revision; fresh authentication remains a server check. */
  setDefault(input: {
    default_policy: MeshDefaultPolicy;
    expected_revision: number;
  }): Promise<MeshEditResult> {
    return this.transport.call("mesh.default.set", input);
  }

  /** List the caller's authorized inventory, optionally restricted to one tag. */
  async list(filter: MeshFilter = {}): Promise<MeshSnapshot> {
    return this.fetchSnapshot(filter);
  }

  /** Carry watch lifetime and generation through the first list and every continuation. */
  private async fetchSnapshot(filter: MeshFilter, isCurrent?: () => boolean): Promise<MeshSnapshot> {
    const first = await this.transport.call<MeshSnapshotPage>("mesh.list", filter);
    return this.completeSnapshot(first, filter, isCurrent);
  }

  /** Assemble only one revision; a concurrent edit restarts the server's sequence. */
  private async completeSnapshot(
    first: MeshSnapshotPage, filter: MeshFilter, isCurrent?: () => boolean,
  ): Promise<MeshSnapshot> {
    if (isCurrent?.() === false) throw new SnapshotSuperseded("superseded");
    if (first.next_cursor === undefined) {
      return first;
    }
    let revision = first.revision;
    let nodes: MeshNode[] = [];
    let tags: MeshTag[] = [];
    let grants: MeshGrant[] = [];
    let page = first;
    let restarts = 0;
    // Bound work if inventory continuously changes or a peer never finishes.
    for (let count = 0; count < 128; count++) {
      if (isCurrent?.() === false) throw new SnapshotSuperseded("superseded");
      if (page.revision < revision) {
        throw new Error("mesh unavailable");
      }
      if (page.revision > revision) {
        if (++restarts > 3) {
          throw new Error("mesh unavailable");
        }
        revision = page.revision;
        nodes = [];
        tags = [];
        grants = [];
      }
      for (const node of page.nodes) nodes.push(node);
      for (const tag of page.tags) tags.push(tag);
      for (const grant of page.grants) grants.push(grant);
      const cursor = page.next_cursor;
      if (cursor === undefined) {
        return { revision, nodes, tags, grants };
      }
      const offset = nodes.length + tags.length + grants.length;
      if (!Number.isSafeInteger(cursor.offset) || cursor.offset <= 0
        || cursor.offset !== offset || cursor.revision !== revision) {
        throw new Error("mesh unavailable");
      }
      page = await this.transport.call<MeshSnapshotPage>("mesh.list", { ...filter, cursor });
    }
    throw new Error("mesh unavailable");
  }

  /** Enroll public inventory; host_id explicitly binds an authenticated remote host. */
  enrollNode(input: {
    name: string;
    public_key: readonly number[];
    host_id?: string;
  }): Promise<MeshNodeEnrollResult> {
    return this.transport.call("mesh.node.enroll", input);
  }

  /** Record the last successful observation and its optional measured RTT. */
  observeNode(input: {
    node_id: MeshNodeId;
    last_rtt_us?: number | null;
  }): Promise<MeshEditResult> {
    return this.transport.call("mesh.node.observe", input);
  }

  /** Change an enrolled node's readable host name. */
  renameNode(input: { node_id: MeshNodeId; name: string }): Promise<MeshEditResult> {
    return this.transport.call("mesh.node.rename", input);
  }

  /** Remove a node and its dependent grants. */
  deleteNode(node_id: MeshNodeId): Promise<MeshEditResult> {
    return this.transport.call("mesh.node.delete", { node_id });
  }

  /** Create an empty tag. */
  createTag(name: string): Promise<MeshEditResult> {
    return this.transport.call("mesh.tag.create", { name });
  }

  /** Rename a tag and all grant and role-scope references. */
  renameTag(name: string, new_name: string): Promise<MeshEditResult> {
    return this.transport.call("mesh.tag.rename", { name, new_name });
  }

  /** Delete an unreferenced tag. */
  deleteTag(name: string): Promise<MeshEditResult> {
    return this.transport.call("mesh.tag.delete", { name });
  }

  /** Add a node to a tag. */
  addTagMember(tag: string, node_id: MeshNodeId): Promise<MeshEditResult> {
    return this.transport.call("mesh.tag.member.add", { tag, node_id });
  }

  /** Remove a node from a tag. */
  removeTagMember(tag: string, node_id: MeshNodeId): Promise<MeshEditResult> {
    return this.transport.call("mesh.tag.member.remove", { tag, node_id });
  }

  /** Create a named, directional grant; an omitted port policy means all traffic. */
  createGrant(input: {
    name: string;
    from: MeshEndpoint;
    to: MeshEndpoint;
    both_ways: boolean;
    ports?: MeshTrafficPolicy;
  }): Promise<MeshGrantCreateResult> {
    return this.transport.call("mesh.grant.create", input);
  }

  /** Move one endpoint while retaining the grant's name and traffic policy. */
  moveGrant(input: {
    name: string;
    side: "from" | "to";
    endpoint: MeshEndpoint;
  }): Promise<MeshEditResult> {
    return this.transport.call("mesh.grant.move", input);
  }

  /** Delete a named grant. */
  deleteGrant(name: string): Promise<MeshEditResult> {
    return this.transport.call("mesh.grant.delete", { name });
  }

  /** Rename a grant while preserving its stable numeric identity. */
  renameGrant(name: string, new_name: string): Promise<MeshEditResult> {
    return this.transport.call("mesh.grant.rename", { name, new_name });
  }

  /** Define or replace a role's actions and optional tag scopes. */
  defineRole(input: {
    name: string;
    actions: readonly MeshRoleAction[];
    scopes?: readonly string[];
  }): Promise<MeshEditResult> {
    return this.transport.call("mesh.role.define", input);
  }

  /** Assign a defined role to an instance user. */
  assignRole(input: { user_id: string; role: string }): Promise<MeshEditResult> {
    return this.transport.call("mesh.role.assign", input);
  }

  /**
   * Subscribe to snapshots; change-only events refetch the filtered list.
   * Revisions advance monotonically so a late refresh cannot roll the view back.
   */
  watch(filter: MeshFilter, listener: (event: MeshClientEvent) => void): () => void {
    const wireFilter = filter.tag === undefined
      ? { topic: "mesh" as const }
      : { topic: "mesh" as const, tag: filter.tag };
    let stopped = false;
    let deliveredRevision = -1;
    let pendingRevision = -1;
    let refreshing = false;
    let snapshotGeneration = 0;
    let authoritativeRevision = -1;

    const publish = (snapshot: MeshSnapshot, authoritative = false): void => {
      // Liveness can expire without a database revision. Server snapshots are
      // authoritative at equality; delayed list replies cannot replace them.
      if (stopped || snapshot.revision < deliveredRevision
        || (!authoritative && snapshot.revision === deliveredRevision)) {
        return;
      }
      deliveredRevision = snapshot.revision;
      // A completed view supersedes earlier page work, including its errors and
      // equal-revision liveness. Advance before a listener can deliver reentrantly.
      snapshotGeneration += 1;
      listener({ type: "snapshot", snapshot });
    };

    const refreshLatest = async (): Promise<void> => {
      if (stopped || refreshing) {
        return;
      }
      refreshing = true;
      let refreshGeneration = snapshotGeneration;
      try {
        while (!stopped && pendingRevision > deliveredRevision) {
          const requestedRevision = pendingRevision;
          const generation = snapshotGeneration;
          refreshGeneration = generation;
          const snapshot = await this.fetchSnapshot(filter,
            () => !stopped && generation === snapshotGeneration);
          // Ownership can change between assembly and this parent await resuming.
          if (stopped || generation !== snapshotGeneration) {
            break;
          }
          if (snapshot.revision < requestedRevision) {
            if (pendingRevision > requestedRevision) {
              continue;
            }
            pendingRevision = deliveredRevision;
            listener({ type: "error", error: "mesh unavailable", subscriptionActive: true });
            break;
          }
          publish(snapshot);
        }
      } catch (error) {
        // A newer snapshot owns both inventory and error delivery.
        // Keep its pending revision intact when an obsolete request rejects.
        if (refreshGeneration === snapshotGeneration
          && !(error instanceof SnapshotSuperseded)) {
          pendingRevision = deliveredRevision;
          if (!stopped) {
            listener({ type: "error", error: "mesh unavailable", subscriptionActive: true });
          }
        }
      } finally {
        refreshing = false;
        if (!stopped && pendingRevision > deliveredRevision) {
          void refreshLatest();
        }
      }
    };

    let unsubscribe: (() => void) | undefined;
    const disconnect = (): void => {
      const release = unsubscribe;
      unsubscribe = undefined;
      release?.();
    };
    unsubscribe = this.transport.subscribe(wireFilter, (event) => {
      if (stopped) {
        return;
      }
      if (event.type === "snapshot" || event.type === "resync") {
        if (event.snapshot.revision < Math.max(deliveredRevision, authoritativeRevision)) {
          return;
        }
        authoritativeRevision = event.snapshot.revision;
        const generation = ++snapshotGeneration;
        if (event.snapshot.next_cursor === undefined) {
          publish(event.snapshot, true);
        } else {
          void this.completeSnapshot(event.snapshot, filter,
            () => !stopped && generation === snapshotGeneration).then((snapshot) => {
            if (generation === snapshotGeneration) publish(snapshot, true);
          }).catch(() => {
            if (!stopped && generation === snapshotGeneration) {
              listener({ type: "error", error: "mesh unavailable", subscriptionActive: true });
            }
          });
        }
      } else if (event.type === "error") {
        // The server withdraws this subscription on error. Stop before notifying
        // the view so pending replies and reentrant delivery cannot republish it.
        stopped = true;
        pendingRevision = deliveredRevision;
        disconnect();
        listener({ type: "error", error: event.error });
      } else if (event.revision > deliveredRevision) {
        pendingRevision = Math.max(pendingRevision, event.revision);
        void refreshLatest();
      }
    });

    // A transport may synchronously report a refusal during subscribe.
    if (stopped) {
      disconnect();
    }
    return () => {
      stopped = true;
      pendingRevision = deliveredRevision;
      disconnect();
    };
  }
}
