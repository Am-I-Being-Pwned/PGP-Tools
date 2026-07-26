import type { Page } from "@playwright/test";

/**
 * Retainer-aware companion to `heap.ts`.
 *
 * `scanJsHeap` answers "do these bytes appear anywhere in a heap
 * snapshot?" -- the right question for key material, and the one
 * heap.spec.ts asks. But a hit doesn't say WHO is holding the string, and
 * a heap snapshot also lists strings that no JS object retains any more:
 * V8 records *external* strings (whose characters are owned by Blink --
 * a DOM node's `value`, for instance) under a synthetic
 * "(External strings)" root reached only by **weak** edges.
 *
 * That distinction matters when auditing app code, because only the
 * strongly-retained case is something the app's own objects are holding.
 * This module parses the raw snapshot, walks forward from the GC roots
 * across non-weak edges only, and reports which strings containing a
 * needle are reachable that way -- with the retaining path, so a failure
 * names the culprit instead of just its existence.
 *
 * Same needle rules as `heap.ts`: newline-free, and unique to the secret.
 */

interface RawSnapshot {
  snapshot: {
    meta: {
      node_fields: string[];
      node_types: (string[] | string)[];
      edge_fields: string[];
      edge_types: (string[] | string)[];
    };
  };
  nodes: number[];
  edges: number[];
  strings: string[];
}

/** One string in the heap whose value contains the needle. */
export interface RetainedString {
  /** The string's full value (truncated for readability). */
  value: string;
  /** True when a chain of non-weak edges reaches it from a GC root -- i.e.
   *  some live JS object is holding it. */
  stronglyRetained: boolean;
  /** Root → ... → string, one `type:"name"` step per hop. Only populated
   *  for strongly-retained strings. */
  path: string[];
}

async function takeRawSnapshot(page: Page): Promise<RawSnapshot> {
  const client = await page.context().newCDPSession(page);
  await client.send("HeapProfiler.enable");
  await client.send("HeapProfiler.collectGarbage");
  let text = "";
  const onChunk = (e: { chunk: string }) => {
    text += e.chunk;
  };
  client.on("HeapProfiler.addHeapSnapshotChunk", onChunk);
  await client.send("HeapProfiler.takeHeapSnapshot", { reportProgress: false });
  client.off("HeapProfiler.addHeapSnapshotChunk", onChunk);
  await client.send("HeapProfiler.disable");
  return JSON.parse(text) as RawSnapshot;
}

const STRING_TYPES = new Set([
  "string",
  "concatenated string",
  "sliced string",
  "thin string",
]);

/**
 * Every string in the page's heap whose value contains `needle`, each
 * classified by whether a live JS object retains it.
 */
export async function findStrings(
  page: Page,
  needle: string,
): Promise<RetainedString[]> {
  const snap = await takeRawSnapshot(page);
  const { node_fields, node_types, edge_fields, edge_types } =
    snap.snapshot.meta;
  const NF = node_fields.length;
  const EF = edge_fields.length;
  const nType = node_fields.indexOf("type");
  const nName = node_fields.indexOf("name");
  const nEdgeCount = node_fields.indexOf("edge_count");
  const eType = edge_fields.indexOf("type");
  const eName = edge_fields.indexOf("name_or_index");
  const eTo = edge_fields.indexOf("to_node");
  const nodeTypeNames = node_types[nType] as string[];
  const edgeTypeNames = edge_types[eType] as string[];
  const weakType = edgeTypeNames.indexOf("weak");

  const nodeCount = snap.nodes.length / NF;
  // Edges are a flat array laid out in node order; this gives each node's
  // slice of it.
  const firstEdge = new Uint32Array(nodeCount + 1);
  for (let i = 0; i < nodeCount; i++) {
    firstEdge[i + 1] = firstEdge[i] + snap.nodes[i * NF + nEdgeCount];
  }

  const describeNode = (n: number): string => {
    const t = nodeTypeNames[snap.nodes[n * NF + nType]];
    const name = snap.strings[snap.nodes[n * NF + nName]] ?? "";
    return `${t}:${JSON.stringify(name.length > 60 ? `${name.slice(0, 60)}…` : name)}`;
  };
  const describeEdge = (e: number): string => {
    const t = edgeTypeNames[snap.edges[e * EF + eType]];
    const raw = snap.edges[e * EF + eName];
    const name =
      t === "element" || t === "hidden" ? String(raw) : snap.strings[raw];
    return `${t}[${name}]`;
  };

  // Forward BFS from the root (node 0) over NON-weak edges, recording the
  // edge we arrived by so a path can be reconstructed.
  const cameFrom = new Int32Array(nodeCount).fill(-1);
  const viaEdge = new Int32Array(nodeCount).fill(-1);
  const seen = new Uint8Array(nodeCount);
  seen[0] = 1;
  let frontier = [0];
  while (frontier.length > 0) {
    const next: number[] = [];
    for (const n of frontier) {
      for (let e = firstEdge[n]; e < firstEdge[n + 1]; e++) {
        if (snap.edges[e * EF + eType] === weakType) continue;
        const to = snap.edges[e * EF + eTo] / NF;
        if (seen[to]) continue;
        seen[to] = 1;
        cameFrom[to] = n;
        viaEdge[to] = e;
        next.push(to);
      }
    }
    frontier = next;
  }

  const results: RetainedString[] = [];
  for (let i = 0; i < nodeCount; i++) {
    if (!STRING_TYPES.has(nodeTypeNames[snap.nodes[i * NF + nType]])) continue;
    const value = snap.strings[snap.nodes[i * NF + nName]] ?? "";
    if (!value.includes(needle)) continue;

    const stronglyRetained = seen[i] === 1;
    const path: string[] = [];
    if (stronglyRetained) {
      const chain: number[] = [];
      for (let n = i; n !== -1; n = cameFrom[n]) chain.push(n);
      chain.reverse();
      for (const n of chain) {
        const e = viaEdge[n];
        path.push(
          e === -1
            ? describeNode(n)
            : `${describeEdge(e)} → ${describeNode(n)}`,
        );
      }
    }
    results.push({
      value: value.length > 120 ? `${value.slice(0, 120)}…` : value,
      stronglyRetained,
      path,
    });
  }
  return results;
}

/** How many strings containing `needle` a live JS object is holding, and
 *  a printable summary of the retaining paths for assertion messages. */
export async function strongRetainers(
  page: Page,
  needle: string,
): Promise<{ count: number; report: string }> {
  const strings = (await findStrings(page, needle)).filter(
    (s) => s.stronglyRetained,
  );
  const report = strings
    .map((s) => `\n  ${s.value}\n    ${s.path.join("\n    ")}`)
    .join("");
  return { count: strings.length, report };
}
