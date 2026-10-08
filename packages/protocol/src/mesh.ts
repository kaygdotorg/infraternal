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
  | "mesh.role.assign";

/** An invalidation or snapshot delivered by a `topic: mesh` subscription. */
export type MeshSubscriptionEvent =
  | { type: "snapshot"; snapshot: MeshSnapshot }
  | { type: "resync"; snapshot: MeshSnapshot }
  | { type: "changed"; revision: number }
  | { type: "error"; error: string };

/** A refreshed inventory or sanitized subscription failure exposed to a view. */
export type MeshClientEvent =
  | { type: "snapshot"; snapshot: MeshSnapshot }
  | { type: "error"; error: string };

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

/** Typed action and subscription client for the Mesh control plane. */
export class MeshClient {
  constructor(private readonly transport: MeshTransport) {}

  /** List the caller's authorized inventory, optionally restricted to one tag. */
  list(filter: MeshFilter = {}): Promise<MeshSnapshot> {
    return this.transport.call("mesh.list", filter);
  }

  /** Enroll a public-key identity. */
  enrollNode(input: { name: string; public_key: readonly number[] }): Promise<MeshNodeEnrollResult> {
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

    const publish = (snapshot: MeshSnapshot): void => {
      if (stopped || snapshot.revision <= deliveredRevision) {
        return;
      }
      deliveredRevision = snapshot.revision;
      listener({ type: "snapshot", snapshot });
    };

    const refreshLatest = async (): Promise<void> => {
      if (stopped || refreshing) {
        return;
      }
      refreshing = true;
      try {
        while (!stopped && pendingRevision > deliveredRevision) {
          const requestedRevision = pendingRevision;
          const snapshot = await this.list(filter);
          if (stopped) {
            break;
          }
          if (snapshot.revision < requestedRevision) {
            if (pendingRevision > requestedRevision) {
              continue;
            }
            pendingRevision = deliveredRevision;
            listener({ type: "error", error: "mesh unavailable" });
            break;
          }
          publish(snapshot);
        }
      } catch {
        pendingRevision = deliveredRevision;
        if (!stopped) {
          listener({ type: "error", error: "mesh unavailable" });
        }
      } finally {
        refreshing = false;
        if (!stopped && pendingRevision > deliveredRevision) {
          void refreshLatest();
        }
      }
    };

    const unsubscribe = this.transport.subscribe(wireFilter, (event) => {
      if (event.type === "snapshot" || event.type === "resync") {
        publish(event.snapshot);
      } else if (event.type === "error") {
        if (!stopped) {
          listener(event);
        }
      } else if (event.revision > deliveredRevision) {
        pendingRevision = Math.max(pendingRevision, event.revision);
        void refreshLatest();
      }
    });

    return () => {
      stopped = true;
      unsubscribe();
    };
  }
}
