"""Directed multigraph over resolved components with bounded, cycle-safe path search."""

from __future__ import annotations

import time
from collections import defaultdict, deque

from scradar.domain.models import ROOT_ID, Component, DependencyPath, DepType, Edge, PathSummary

_RUNTIME_TYPES = {DepType.RUNTIME, DepType.WORKSPACE, DepType.PEER, DepType.UNKNOWN}


class DependencyGraph:
    def __init__(self, components: dict[str, Component], edges: list[Edge]) -> None:
        self.components = components
        self.edges = edges
        self.children: dict[str, list[Edge]] = defaultdict(list)
        self.parents: dict[str, list[Edge]] = defaultdict(list)
        self.dangling: list[Edge] = []
        for e in edges:
            if e.parent not in components or e.child not in components:
                self.dangling.append(e)
                continue
            self.children[e.parent].append(e)
            self.parents[e.child].append(e)

    # -- reachability -------------------------------------------------------------------------

    def _bfs(self, start: str, allowed: set[DepType] | None = None) -> dict[str, int]:
        depth = {start: 0}
        q = deque([start])
        while q:
            n = q.popleft()
            for e in self.children.get(n, ()):
                if allowed is not None and e.type not in allowed:
                    continue
                if e.child not in depth:
                    depth[e.child] = depth[n] + 1
                    q.append(e.child)
        return depth

    def depths(self) -> dict[str, int]:
        return self._bfs(ROOT_ID)

    def compute_scopes(self) -> None:
        """Annotate components with graph-derived scope/dependency types (idempotent)."""

        runtime = self._bfs(ROOT_ID, _RUNTIME_TYPES)
        non_dev = self._bfs(ROOT_ID, _RUNTIME_TYPES | {DepType.OPTIONAL})
        everything = self._bfs(ROOT_ID)
        for cid, comp in self.components.items():
            if cid == ROOT_ID:
                continue
            types = {e.type for e in self.parents.get(cid, ())}
            comp.dep_types = sorted(types, key=lambda t: t.value)
            if cid in runtime:
                comp.scopes = ["runtime"]
            elif cid in non_dev:
                comp.scopes = ["optional"]
            elif cid in everything:
                comp.scopes = ["dev"]
            elif not comp.scopes:
                comp.scopes = ["unknown"]
            comp.direct = any(e.parent == ROOT_ID for e in self.parents.get(cid, ()))

    # -- paths --------------------------------------------------------------------------------

    def _can_reach(self, target: str) -> set[str]:
        seen = {target}
        q = deque([target])
        while q:
            n = q.popleft()
            for e in self.parents.get(n, ()):
                if e.parent not in seen:
                    seen.add(e.parent)
                    q.append(e.parent)
        return seen

    def _edge_between(self, a: str, b: str) -> Edge:
        best = None
        for e in self.children.get(a, ()):
            if e.child == b and (
                best is None or (best.confidence != "declared" and e.confidence == "declared")
            ):
                best = e
        assert best is not None
        return best

    def paths_to(
        self,
        target: str,
        *,
        max_paths: int = 20,
        max_depth: int = 64,
        max_expansions: int = 200_000,
        max_seconds: float = 5.0,
    ) -> PathSummary:
        if target not in self.components:
            return PathSummary(reachable_from_root=False, warning="component is not in the graph")
        if target == ROOT_ID:
            return PathSummary(
                paths=[DependencyPath(nodes=[ROOT_ID])], total_found=1, reachable_from_root=True
            )
        can_reach = self._can_reach(target)
        if ROOT_ID not in can_reach:
            no_edges = not self.edges
            return PathSummary(
                reachable_from_root=False,
                warning=(
                    "the imported file carries no dependency relationships, so no path can be shown"
                    if no_edges
                    else "no dependency path from the application root was found in the imported graph"
                ),
            )
        found: list[list[str]] = []
        truncated = False
        deadline = time.monotonic() + max_seconds

        # 1) Shortest paths first, always: BFS distances from the root and to the target, then walk only
        #    "tight" edges. Every tight node lies on a shortest path, so there are no dead ends and this
        #    stays cheap on large, heavily shared graphs.
        dist = self._bfs(ROOT_ID)
        rdist: dict[str, int] = {target: 0}
        rq = deque([target])
        while rq:
            n = rq.popleft()
            for e in self.parents.get(n, ()):
                if e.parent not in rdist:
                    rdist[e.parent] = rdist[n] + 1
                    rq.append(e.parent)
        shortest = dist[target]
        stack: list[tuple[str, tuple[str, ...]]] = [(ROOT_ID, (ROOT_ID,))]
        while stack and len(found) < max_paths:
            node, path = stack.pop()
            if node == target:
                found.append(list(path))
                continue
            for e in reversed(self.children.get(node, [])):
                c = e.child
                if c in rdist and dist.get(c) == dist[node] + 1 and dist[c] + rdist[c] == shortest:
                    stack.append((c, (*path, c)))
        if stack:
            truncated = True

        # 2) Longer alternative routes, bounded by node/time budgets (cycle-safe: no node repeats on a path).
        if len(found) < max_paths and not truncated:
            seen = {tuple(p) for p in found}
            expansions = 0
            q: deque[tuple[str, ...]] = deque([(ROOT_ID,)])
            while q:
                path = q.popleft()
                node = path[-1]
                if node == target:
                    if path not in seen:
                        found.append(list(path))
                        seen.add(path)
                        if len(found) >= max_paths:
                            truncated = bool(q)
                            break
                    continue
                if len(path) > max_depth:
                    truncated = True
                    continue
                for e in self.children.get(node, ()):
                    c = e.child
                    if c in can_reach and c not in path:
                        expansions += 1
                        q.append((*path, c))
                if expansions > max_expansions or time.monotonic() > deadline:
                    truncated = True
                    break
        paths = []
        for nodes in found:
            etypes, inferred = [], False
            for a, b in zip(nodes, nodes[1:], strict=False):
                e = self._edge_between(a, b)
                etypes.append(e.type.value)
                inferred = inferred or e.confidence != "declared"
            paths.append(DependencyPath(nodes=nodes, edge_types=etypes, inferred=inferred))
        return PathSummary(
            paths=paths,
            total_found=len(found),
            truncated=truncated,
            introducers=self.introducers(target, can_reach),
            reachable_from_root=True,
            warning=(
                f"path search stopped at its limits; {len(found)} path(s) shown, more may exist"
                if truncated
                else None
            ),
        )

    def introducers(self, target: str, can_reach: set[str] | None = None) -> list[str]:
        """Direct dependencies of the application (or workspace packages) that lead to ``target``."""

        can_reach = can_reach if can_reach is not None else self._can_reach(target)
        out: list[str] = []
        for e in self.children.get(ROOT_ID, ()):
            if e.child not in can_reach:
                continue
            comp = self.components[e.child]
            if e.type == DepType.WORKSPACE or comp.source == "workspace":
                for e2 in self.children.get(e.child, ()):
                    if e2.child in can_reach and e2.child not in out:
                        out.append(e2.child)
                if e.child == target and e.child not in out:
                    out.append(e.child)
            elif e.child not in out:
                out.append(e.child)
        return sorted(out)

    # -- structure checks ---------------------------------------------------------------------

    def analysis(self) -> dict:
        reach = self.depths()
        orphans = [cid for cid in self.components if cid != ROOT_ID and cid not in reach]
        return {
            "nodes": len(self.components),
            "edges": len(self.edges),
            "dangling_edges": len(self.dangling),
            "unreachable_components": len(orphans),
            "max_depth": max(reach.values()) if reach else 0,
            "has_cycles": self._has_cycle(),
        }

    def _has_cycle(self) -> bool:
        color: dict[str, int] = {}
        for start in list(self.components):
            if color.get(start):
                continue
            stack = [(start, iter(self.children.get(start, ())))]
            color[start] = 1
            while stack:
                node, it = stack[-1]
                nxt = next(it, None)
                if nxt is None:
                    color[node] = 2
                    stack.pop()
                    continue
                c = color.get(nxt.child, 0)
                if c == 1:
                    return True
                if c == 0:
                    color[nxt.child] = 1
                    stack.append((nxt.child, iter(self.children.get(nxt.child, ()))))
        return False

    def subgraph_for(self, targets: list[str], max_paths: int = 20) -> tuple[set[str], list[Edge]]:
        """Union of nodes/edges on shortest-first paths to the targets (for focused graph views)."""

        nodes: set[str] = set()
        used: dict[tuple[str, str, str], Edge] = {}
        for t in targets:
            summary = self.paths_to(t, max_paths=max_paths)
            for p in summary.paths:
                nodes.update(p.nodes)
                for a, b in zip(p.nodes, p.nodes[1:], strict=False):
                    e = self._edge_between(a, b)
                    used[(e.parent, e.child, e.type.value)] = e
        return nodes, list(used.values())
