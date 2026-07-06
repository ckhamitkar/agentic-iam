#!/usr/bin/env python3
"""Tests for containment + graduated autonomy. Pure stdlib unittest, deterministic."""

import unittest

from seam7_delegation import Cap
from containment import (
    AutonomyLevel, Gating, Verdict, ContainmentManager, Contained, SimRuntime,
    PROMOTE_AFTER, PROFILES,
)


def _root(level=AutonomyLevel.TRUSTED):
    return Contained(name="root", spiffe_id="spiffe://td/agent/root", level=level)


class TestBirthInShadow(unittest.TestCase):
    def test_child_is_born_in_shadow_and_only_watches(self):
        cm = ContainmentManager()
        child = cm.spawn(_root(), "c")
        self.assertEqual(child.level, AutonomyLevel.SHADOW)
        self.assertEqual(cm.may_execute(child, reversible=True), Verdict.OBSERVE_ONLY)

    def test_child_spiffe_id_is_nested_under_parent(self):
        cm = ContainmentManager()
        parent = _root()
        child = cm.spawn(parent, "parser")
        self.assertEqual(child.spiffe_id, "spiffe://td/agent/root/parser")


class TestGraduatedTrust(unittest.TestCase):
    def test_earns_a_level_after_a_streak(self):
        cm = ContainmentManager()
        child = cm.spawn(_root(), "c")
        for _ in range(PROMOTE_AFTER):
            cm.record_outcome(child, verified_good=True)
        self.assertEqual(child.level, AutonomyLevel.CONTAINED)

    def test_climbs_the_ladder(self):
        cm = ContainmentManager()
        child = cm.spawn(_root(), "c")
        for _ in range(PROMOTE_AFTER * 3):
            cm.record_outcome(child, verified_good=True)
        self.assertEqual(child.level, AutonomyLevel.TRUSTED)

    def test_earn_slowly_revoke_instantly(self):
        cm = ContainmentManager()
        child = cm.spawn(_root(), "c")
        for _ in range(PROMOTE_AFTER * 2):        # climb to SUPERVISED
            cm.record_outcome(child, verified_good=True)
        self.assertEqual(child.level, AutonomyLevel.SUPERVISED)
        cm.record_outcome(child, verified_good=False)   # one bad outcome
        self.assertEqual(child.level, AutonomyLevel.CONTAINED)   # instant drop

    def test_child_can_never_out_rank_parent(self):
        cm = ContainmentManager()
        parent = _root(level=AutonomyLevel.CONTAINED)   # a low-trust parent
        child = cm.spawn(parent, "c")
        for _ in range(PROMOTE_AFTER * 3):
            cm.record_outcome(child, verified_good=True)
        self.assertLessEqual(child.level, parent.level)   # capped at parent's reach


class TestIrreversibleFloor(unittest.TestCase):
    def test_floor_is_always_gated_regardless_of_trust(self):
        cm = ContainmentManager()
        child = cm.spawn(_root(), "c")
        for _ in range(PROMOTE_AFTER * 3):            # make it maximally TRUSTED
            cm.record_outcome(child, verified_good=True)
        self.assertEqual(child.level, AutonomyLevel.TRUSTED)
        # reversible runs with audit-only at TRUSTED...
        self.assertEqual(cm.may_execute(child, reversible=True), Verdict.EXECUTE)
        # ...but the irreversible floor is STILL gated. Trust never opens it.
        self.assertEqual(cm.may_execute(child, reversible=False), Verdict.GATE)

    def test_no_level_grants_delete_or_spend_in_its_ceiling(self):
        for prof in PROFILES.values():
            self.assertFalse(prof.caps_ceiling & Cap.DELETE)
            self.assertFalse(prof.caps_ceiling & Cap.SPEND)

    def test_floor_violation_drops_to_shadow(self):
        cm = ContainmentManager()
        child = cm.spawn(_root(), "c")
        for _ in range(PROMOTE_AFTER * 2):
            cm.record_outcome(child, verified_good=True)
        cm.record_outcome(child, verified_good=False, floor_violation=True)
        self.assertEqual(child.level, AutonomyLevel.SHADOW)


class TestReaping(unittest.TestCase):
    def test_reaping_parent_kills_the_whole_subtree(self):
        rt = SimRuntime()
        cm = ContainmentManager(rt)
        parent = _root()
        c1 = cm.spawn(parent, "c1")
        for _ in range(PROMOTE_AFTER):
            cm.record_outcome(c1, verified_good=True)   # c1 -> CONTAINED, may hold a child
        g1 = cm.spawn(c1, "g1")
        cm.reap(parent)
        self.assertFalse(parent.alive)
        self.assertFalse(c1.alive)
        self.assertFalse(g1.alive)
        self.assertEqual(set(rt.killed), {parent.spiffe_id, c1.spiffe_id, g1.spiffe_id})
        self.assertEqual(len(rt.running), 0)   # no orphans left running

    def test_cannot_spawn_under_a_reaped_parent(self):
        cm = ContainmentManager()
        parent = _root()
        cm.reap(parent)
        with self.assertRaises(ValueError):
            cm.spawn(parent, "c")

    def test_dead_node_denies_everything(self):
        cm = ContainmentManager()
        child = cm.spawn(_root(), "c")
        cm.reap(child)
        self.assertEqual(cm.may_execute(child, reversible=True), Verdict.DENY)


class TestChildBudgetOfBox(unittest.TestCase):
    def test_max_children_enforced_by_level(self):
        cm = ContainmentManager()
        parent = _root(level=AutonomyLevel.CONTAINED)   # may hold 1 child
        cm.spawn(parent, "a")
        with self.assertRaises(ValueError):
            cm.spawn(parent, "b")


if __name__ == "__main__":
    unittest.main(verbosity=2)
