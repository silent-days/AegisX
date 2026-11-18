"""
AegisX — correlation engine.

Derives infrastructure relationships between indicators from evidence
(shared ASN, shared campaign, DNS resolution, co-investigation, tag
similarity), clusters indicators into infrastructure groups, and exposes
facet analytics. Relationships always carry evidence strings and confidence.
"""

from __future__ import annotations

from collections import defaultdict

from ..database.repository import Repository


def jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


class CorrelationEngine:
    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    # -------------------------------------------------------- derivations
    def derive_for_indicator(self, indicator_id: int) -> int:
        """Derive & persist relationships for one indicator. Returns edges added."""
        ind = self.repo.get_indicator(indicator_id)
        if not ind:
            return 0
        added = 0

        # 1. Shared ASN (strong infrastructural relationship)
        if ind.get("asn"):
            peers = self.repo.search_indicators(limit=400)
            for peer in peers:
                if peer["id"] == indicator_id:
                    continue
                if peer.get("asn") == ind.get("asn"):
                    evidence = f"Both observed on {ind['asn']}"
                    if peer.get("asn_name"):
                        evidence += f" ({peer['asn_name']})"
                    if self.repo.add_relationship(indicator_id, peer["id"], "same-asn",
                                                  evidence, 0.75):
                        added += 1

        # 2. DNS resolution (domain -> ip)
        for finding in self.repo.findings_for_indicator(indicator_id):
            data = finding.get("data") or {}
            resolved = data.get("resolves_to") or []
            if isinstance(resolved, str):
                resolved = [resolved]
            for ip_value in resolved:
                peer = self.repo.get_indicator_by_value(ip_value)
                if peer and peer["id"] != indicator_id:
                    if self.repo.add_relationship(indicator_id, peer["id"], "resolves-to",
                                                  f"DNS: {ind['value']} -> {ip_value}", 0.95):
                        added += 1

        # 3. Shared campaign membership
        for camp in self.repo.list_campaigns():
            members = self.repo.campaign_indicators(camp["id"])
            ids = {m["id"] for m in members}
            if indicator_id in ids:
                for m in members:
                    if m["id"] != indicator_id:
                        if self.repo.add_relationship(indicator_id, m["id"], "campaign",
                                                      f"Campaign: {camp['name']}", 0.8):
                            added += 1

        # 4. Tag similarity within same type (weak link, needs 0.65+ overlap)
        if ind.get("tags"):
            base_tags = set(ind["tags"])
            for peer in self.repo.search_indicators(type_=ind["type"], limit=200):
                if peer["id"] == indicator_id or not peer.get("tags"):
                    continue
                sim = jaccard(base_tags, set(peer["tags"]))
                if sim >= 0.65:
                    shared = sorted(base_tags & set(peer["tags"]))
                    if self.repo.add_relationship(
                        indicator_id, peer["id"], "shared-tags",
                        f"Similar behaviour: {', '.join(shared[:4])} ({sim:.0%})", sim * 0.6,
                    ):
                        added += 1
        return added

    # ------------------------------------------------------------- graph view
    def build_graph(self, center_id: int, *, depth: int = 1, kinds: set[str] | None = None) -> dict:
        """Sub-graph around a center indicator: nodes + edges."""
        kinds = kinds or {"same-asn", "resolves-to", "campaign", "shared-tags", "co-investigation"}
        nodes: dict[int, dict] = {}
        edges: list[dict] = []
        frontier = [center_id]
        seen: set[int] = set()

        center = self.repo.get_indicator(center_id)
        if not center:
            return {"nodes": [], "edges": []}

        for _ in range(max(1, depth)):
            nxt: list[int] = []
            for nid in frontier:
                if nid in seen:
                    continue
                seen.add(nid)
                ind = self.repo.get_indicator(nid) or {}
                nodes[nid] = ind
                for rel in self.repo.relationships_for(nid):
                    if rel["kind"] not in kinds:
                        continue
                    other = rel["target_id"] if rel["source_id"] == nid else rel["source_id"]
                    edge_key = (min(rel["source_id"], rel["target_id"]),
                                max(rel["source_id"], rel["target_id"]), rel["kind"])
                    if all(e["key"] != edge_key for e in edges):
                        edges.append({
                            "key": edge_key,
                            "source": rel["source_id"],
                            "target": rel["target_id"],
                            "kind": rel["kind"],
                            "evidence": rel.get("evidence", ""),
                            "confidence": rel.get("confidence", 0),
                        })
                    if other not in seen and depth > 1:
                        nxt.append(other)
            frontier = nxt

        return {"nodes": list(nodes.values()), "edges": edges}

    # ------------------------------------------------------------- clustering
    def clusters(self) -> list[dict]:
        """Union-find over stored relationships -> infrastructure clusters."""
        parent: dict[int, int] = {}

        def find(x: int) -> int:
            while parent.setdefault(x, x) != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: int, b: int) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        for rel in self.repo._q("SELECT source_id, target_id FROM relationships"):
            union(rel["source_id"], rel["target_id"])

        groups: dict[int, list[int]] = defaultdict(list)
        for ind in self.repo.search_indicators(limit=2000):
            groups[find(ind["id"])].append(ind)

        out = []
        for members in groups.values():
            if len(members) < 2:
                continue
            tags: dict[str, int] = defaultdict(int)
            sev_sum = 0
            for m in members:
                for t in m.get("tags") or []:
                    tags[t] += 1
                sev_sum += m.get("risk_score") or 0
            dominant = sorted(tags.items(), key=lambda kv: -kv[1])[:5]
            out.append({
                "size": len(members),
                "avg_risk": round(sev_sum / len(members)),
                "members": [m["value"] for m in members[:12]],
                "member_ids": [m["id"] for m in members],
                "dominant_tags": [t for t, _ in dominant],
                "types": sorted({m["type"] for m in members}),
            })
        out.sort(key=lambda c: -c["size"])
        return out

    # -------------------------------------------------------------- facets
    def facet_analysis(self) -> dict:
        return {
            "countries": self.repo.top_field("country", 10),
            "asns": self.repo.top_field("asn", 10),
            "clusters": self.clusters(),
            "relationship_total": self.repo.relationship_count(),
        }
