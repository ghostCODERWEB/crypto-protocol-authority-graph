"""Trace role delegation, threshold controls, timelocks and compromised-principal paths through protocol permissions."""

from .validation import integer, identifier


def closure(principals, rules, now):
    reached = set(principals)
    trace = []
    changed = True
    while changed:
        changed = False
        for rule in rules:
            target = rule["target"]
            sources = rule["sources"]
            threshold = rule["threshold"]
            witnesses = [s for s in sources if s in reached]
            if (
                target not in reached
                and len(witnesses) >= threshold
                and rule["delay"] <= now
            ):
                reached.add(target)
                trace.append(
                    {
                        "target": target,
                        "rule": rule["id"],
                        "witnesses": witnesses[:threshold],
                        "delay": rule["delay"],
                    }
                )
                changed = True
    return reached, trace


def analyze(data):
    nodes = {identifier(n["id"]): n["kind"] for n in data["nodes"]}
    if len(nodes) != len(data["nodes"]):
        raise ValueError("duplicate authority node")
    rules = []
    ids = set()
    for rule in data["rules"]:
        key = identifier(rule["id"])
        sources = [identifier(s) for s in rule["sources"]]
        target = identifier(rule["target"])
        threshold = integer(rule["threshold"], minimum=1)
        delay = integer(rule.get("delay", 0))
        if (
            key in ids
            or target not in nodes
            or any(s not in nodes for s in sources)
            or len(set(sources)) != len(sources)
            or threshold > len(sources)
        ):
            raise ValueError("invalid authority rule")
        ids.add(key)
        rules.append(
            {
                "id": key,
                "sources": sources,
                "target": target,
                "threshold": threshold,
                "delay": delay,
            }
        )
    capabilities = [k for k, v in nodes.items() if v == "capability"]
    scenarios = []
    for scenario in data["scenarios"]:
        compromised = [identifier(p) for p in scenario["compromised"]]
        if any(p not in nodes or nodes[p] != "principal" for p in compromised):
            raise ValueError("compromise seeds must be principal nodes")
        horizon = integer(scenario.get("horizon", 0))
        reached, trace = closure(compromised, rules, horizon)
        exposed = sorted(set(capabilities) & reached)
        scenarios.append(
            {
                "name": identifier(scenario["name"]),
                "reachable_nodes": sorted(reached),
                "exposed_capabilities": exposed,
                "derivations": trace,
                "horizon": horizon,
            }
        )
    single = []
    for principal, kind in sorted(nodes.items()):
        if kind == "principal":
            reached, _ = closure(
                [principal], rules, integer(data.get("audit_horizon", 0))
            )
            single.append(
                {
                    "principal": principal,
                    "exposed_capabilities": sorted(reached & set(capabilities)),
                }
            )
    unused = sorted(
        k
        for k in nodes
        if k not in {s for r in rules for s in r["sources"]}
        and nodes[k] != "capability"
    )
    return {
        "scenarios": scenarios,
        "single_principal_blast_radius": single,
        "unused_nodes": unused,
        "rule_count": len(rules),
        "model": "threshold hypergraph closure with per-edge maturity",
    }
