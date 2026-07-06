#!/usr/bin/env python3
"""
Containment + graduated autonomy -- the runtime layer under the crypto layer.

The macaroon token bounds an agent's AUTHORITY (what it may do). This module bounds
its REACH (where it runs, and whether it can be reaped) and models how a child EARNS
autonomy over time. Two rules, in plain terms:

  1. A child is born inside the parent's isolation boundary ("same box"). The parent
     owns the child's lifecycle; tearing the parent down reaps the whole subtree. There
     are no orphan processes -- a child cannot outlive the box it was born in.
  2. A child starts in SHADOW (watch, don't act) and earns wider autonomy by building a
     verified track record. Trust is earned SLOWLY and revoked INSTANTLY. And -- the
     load-bearing safety invariant -- graduated trust only ever loosens REVERSIBLE
     reach. The irreversible floor (delete, spend, external commit) is ALWAYS gated,
     no matter how trusted the child looks. You never let a reputation gradient decide
     something you can't undo.

The autonomy ladder is Tesla shadow-mode made into a lifecycle:
  SHADOW -> CONTAINED -> SUPERVISED -> TRUSTED   (promotion to its own principal, i.e.
  leaving containment entirely, is a separate human-gated act, not a level here).

The runtime is pluggable (Runtime): Docker for a containerized fleet, a k8s pod, or a
cgroup / process-group for a non-containerized worker. The default SimRuntime models
the lifecycle in memory so the policy is testable without a real substrate.

Pure stdlib, deterministic.
"""

from dataclasses import dataclass, field
from enum import Enum, IntEnum

from seam7_delegation import Cap


class AutonomyLevel(IntEnum):
    SHADOW = 0        # watch only: actions are computed + audited, NOT executed
    CONTAINED = 1     # execute reversible actions, but authorize EVERY one; tight box
    SUPERVISED = 2    # reversible actions, a SAMPLE authorized; wider box, longer TTL
    TRUSTED = 3       # reversible actions run with audit-only; broadest box


class Gating(str, Enum):
    OBSERVE = "observe"       # don't execute -- record what it WOULD have done (shadow)
    GATE_EACH = "gate_each"   # route every action through the authorize() PDP
    SAMPLE = "sample"         # authorize a random sample; run the rest
    MINIMAL = "minimal"       # run; audit only


class Verdict(str, Enum):
    EXECUTE = "execute"           # allowed to run without a per-action gate
    OBSERVE_ONLY = "observe_only" # shadow: compute + audit, do not execute
    GATE = "gate"                 # must pass the authorize() PDP (or human co-sign) first
    DENY = "deny"                 # dead node


@dataclass(frozen=True)
class SandboxProfile:
    level: AutonomyLevel
    caps_ceiling: Cap        # the widest caps this level may hold (token attenuates within)
    ttl_seconds: int
    gating: Gating
    max_children: int

    # Deliberately, NO level grants DELETE / SPEND: those are irreversible-floor caps,
    # always gated per-action regardless of autonomy. Trust buys reversible reach only.


PROFILES = {
    AutonomyLevel.SHADOW:     SandboxProfile(AutonomyLevel.SHADOW,     Cap.READ,                          60,   Gating.OBSERVE,   0),
    AutonomyLevel.CONTAINED:  SandboxProfile(AutonomyLevel.CONTAINED,  Cap.READ | Cap.ENRICH,             120,  Gating.GATE_EACH, 1),
    AutonomyLevel.SUPERVISED: SandboxProfile(AutonomyLevel.SUPERVISED, Cap.READ | Cap.ENRICH | Cap.WRITE, 600,  Gating.SAMPLE,    3),
    AutonomyLevel.TRUSTED:    SandboxProfile(AutonomyLevel.TRUSTED,    Cap.READ | Cap.ENRICH | Cap.WRITE | Cap.SPAWN, 3600, Gating.MINIMAL, 8),
}

PROMOTE_AFTER = 5   # consecutive verified-good reversible outcomes to rise one level


@dataclass
class Contained:
    name: str
    spiffe_id: str                 # path mirrors the containment tree: parent-id/child
    parent: "Contained" = None
    level: AutonomyLevel = AutonomyLevel.SHADOW   # everyone is born in shadow
    children: list = field(default_factory=list)
    alive: bool = True
    streak: int = 0                # consecutive good reversible outcomes
    good: int = 0
    demotions: int = 0

    @property
    def profile(self) -> SandboxProfile:
        return PROFILES[self.level]


class Runtime:
    """Substrate-agnostic lifecycle backend: Docker / k8s pod / cgroup."""
    def spawn(self, node: Contained) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def kill(self, node: Contained) -> None:   # pragma: no cover - interface
        raise NotImplementedError


class SimRuntime(Runtime):
    """In-memory model of the runtime, so the policy is testable without a real box."""
    def __init__(self):
        self.running = set()
        self.killed = []

    def spawn(self, node):
        self.running.add(node.spiffe_id)

    def kill(self, node):
        self.running.discard(node.spiffe_id)
        self.killed.append(node.spiffe_id)


def verdict_for(node: Contained, *, reversible: bool, sampled: bool = False) -> Verdict:
    """The runtime verdict for an action, BEFORE the crypto/authorize() gate. Standalone
    so the gateway can call it without a manager. The irreversible floor is always gated;
    reversible reach follows the node's autonomy level."""
    if not node.alive:
        return Verdict.DENY
    if not reversible:
        return Verdict.GATE                           # the floor: trust is irrelevant
    g = node.profile.gating
    if g == Gating.OBSERVE:
        return Verdict.OBSERVE_ONLY                    # shadow mode
    if g == Gating.GATE_EACH:
        return Verdict.GATE
    if g == Gating.SAMPLE:
        return Verdict.GATE if sampled else Verdict.EXECUTE
    return Verdict.EXECUTE                             # MINIMAL


def attenuate_to_level(parent_token, node: Contained, now: float, holder: str = None):
    """Shape a child's capability TOKEN from its containment level: caps are narrowed to
    the level's ceiling and the TTL to the level's window. This is the crypto layer being
    shaped by the runtime layer -- as the child graduates, re-issue a wider token."""
    from seam7_delegation import attenuate
    prof = node.profile
    return attenuate(parent_token, caps=prof.caps_ceiling, exp=now + prof.ttl_seconds,
                     actor=node.spiffe_id, holder=holder)


class ContainmentManager:
    def __init__(self, runtime: Runtime = None):
        self.runtime = runtime or SimRuntime()

    def spawn(self, parent: Contained, name: str) -> Contained:
        """Create a child inside the parent's box. The child's SPIFFE id is the
        parent's path + /name, so identity proves it is within the parent's reach."""
        if not parent.alive:
            raise ValueError("cannot spawn under a reaped parent")
        if len(parent.children) >= parent.profile.max_children:
            raise ValueError(f"parent at {parent.level.name} may hold at most "
                             f"{parent.profile.max_children} children")
        child = Contained(name=name, spiffe_id=f"{parent.spiffe_id}/{name}", parent=parent)
        parent.children.append(child)
        self.runtime.spawn(child)
        return child

    def reap(self, node: Contained) -> None:
        """Tear down a node and its ENTIRE subtree (depth-first). This is 'no orphan
        processes': killing the box kills everything born inside it."""
        for c in list(node.children):
            self.reap(c)
        node.alive = False
        self.runtime.kill(node)

    def record_outcome(self, node: Contained, *, verified_good: bool,
                       floor_violation: bool = False) -> None:
        """Update a child's standing. Earn slowly (PROMOTE_AFTER good in a row to rise
        one level, capped at the parent's level -- a child can never out-rank its
        parent). Revoke instantly: any bad outcome drops to CONTAINED; any attempt to
        breach the irreversible floor drops to SHADOW."""
        if floor_violation:
            node.level = AutonomyLevel.SHADOW
            node.streak = 0
            node.demotions += 1
            return
        if not verified_good:
            node.level = AutonomyLevel.CONTAINED if node.level > AutonomyLevel.CONTAINED else node.level
            node.streak = 0
            node.demotions += 1
            return
        node.good += 1
        node.streak += 1
        if node.streak >= PROMOTE_AFTER and node.level < AutonomyLevel.TRUSTED:
            ceiling = node.parent.level if node.parent else AutonomyLevel.TRUSTED
            if node.level < ceiling:                      # never exceed the parent's reach
                node.level = AutonomyLevel(node.level + 1)
            node.streak = 0

    def may_execute(self, node: Contained, *, reversible: bool, sampled: bool = False) -> Verdict:
        return verdict_for(node, reversible=reversible, sampled=sampled)


# ----------------------------------------------------------------------------------
def _demo():
    print("=" * 76)
    print("CONTAINMENT DEMO -- a child earns reversible autonomy; the floor never opens")
    print("=" * 76)
    cm = ContainmentManager()
    parent = Contained(name="triage-manager",
                       spiffe_id="spiffe://axionaiapps.com/agent/triage-manager",
                       level=AutonomyLevel.TRUSTED)   # a trusted parent
    child = cm.spawn(parent, "parser")
    print(f"\n[spawn]  child = {child.spiffe_id}")
    print(f"         born at {child.level.name}: reversible verdict = "
          f"{cm.may_execute(child, reversible=True).value}  (watch, don't act)")
    print(f"         irreversible verdict = {cm.may_execute(child, reversible=False).value}\n")

    for i in range(15):
        cm.record_outcome(child, verified_good=True)
        if (i + 1) % 5 == 0:
            print(f"  after {i+1} good outcomes -> {child.level.name:11s} "
                  f"reversible={cm.may_execute(child, reversible=True).value:12s} "
                  f"irreversible={cm.may_execute(child, reversible=False).value}")

    print("\n  [floor breach] child attempts an irreversible action it shouldn't:")
    cm.record_outcome(child, verified_good=False, floor_violation=True)
    print(f"     -> instantly demoted to {child.level.name} (earn slowly, revoke instantly)\n")

    print("  [reap] tear down the parent's box:")
    cm.reap(parent)
    print(f"     parent alive={parent.alive}, child alive={child.alive}, "
          f"runtime killed={len(cm.runtime.killed)} nodes (no orphans)")


if __name__ == "__main__":
    _demo()
