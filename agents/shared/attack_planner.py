import math
import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from shared.redteam_knowledge import RedTeamKnowledgeService
from shared.payload_utils import build_payload_preview, hash_payload, short_payload_hash


TARGET_CONTEXT = {
    "agent-a": {"defense_hint": 0.9, "target_surface": "human_operator", "propagation_value": 1.0, "depth": 3},
    "agent-b": {"defense_hint": 0.55, "target_surface": "input_channel", "propagation_value": 0.65, "depth": 2},
    "agent-c": {"defense_hint": 0.2, "target_surface": "input_channel", "propagation_value": 0.2, "depth": 1},
}

OBJECTIVES = (
    "SPREAD_FAST",
    "REACH_DEEPEST_NODE",
    "MAXIMIZE_SUCCESS_RATE",
    "MAXIMIZE_MUTATION_DIVERSITY",
    "PRESSURE_HIGHEST_VALUE_TARGET",
)


def _normalize_objective(value: str) -> str:
    candidate = str(value or "").strip().upper()
    return candidate if candidate in OBJECTIVES else OBJECTIVES[0]

TARGET_SCORE_WEIGHTS = {
    "historical_success_rate": 0.45,
    "resistance_penalty": 0.55,
    "recent_block_ratio": 0.35,
    "propagation_value": 0.30,
    "exploration_bonus": 0.20,
    "state_bonus": 0.15,
    "objective_alignment": 0.20,
}

STRATEGY_SCORE_WEIGHTS = {
    "knowledge_base_strength": 0.42,
    "knowledge_stealth": 0.18,
    "target_resistance": 0.30,
    "recent_block_ratio": 0.22,
    "recent_success_ratio": 0.28,
    "objective_alignment": 0.22,
    "exploration_bonus": 0.12,
    "cooldown_penalty": 0.40,
}

MUTATION_SCORE_WEIGHTS = {
    "knowledge_preference": 0.35,
    "runtime_success": 0.35,
    "failure_penalty": 0.28,
    "cooldown_penalty": 0.18,
    "exploration_bonus": 0.10,
}

OBJECTIVE_STRATEGY_BIAS = {
    "SPREAD_FAST": {"DIRECT_OVERRIDE": 0.20, "ROLEPLAY_MANIPULATION": 0.05, "JAILBREAK_ESCALATION": -0.05, "RECON_PROBE": -0.15},
    "REACH_DEEPEST_NODE": {"DIRECT_OVERRIDE": 0.05, "ROLEPLAY_MANIPULATION": 0.10, "JAILBREAK_ESCALATION": 0.15, "RECON_PROBE": 0.02},
    "MAXIMIZE_SUCCESS_RATE": {"DIRECT_OVERRIDE": 0.12, "ROLEPLAY_MANIPULATION": 0.10, "JAILBREAK_ESCALATION": -0.04, "RECON_PROBE": 0.04},
    "MAXIMIZE_MUTATION_DIVERSITY": {"DIRECT_OVERRIDE": 0.03, "ROLEPLAY_MANIPULATION": 0.05, "JAILBREAK_ESCALATION": 0.08, "RECON_PROBE": 0.08},
    "PRESSURE_HIGHEST_VALUE_TARGET": {"DIRECT_OVERRIDE": -0.04, "ROLEPLAY_MANIPULATION": 0.15, "JAILBREAK_ESCALATION": 0.20, "RECON_PROBE": 0.12},
}


@dataclass
class TargetProfile:
    target_id: str
    attempts_sent: int = 0
    successes: int = 0
    blocks: int = 0
    last_seen_state: str = "unknown"
    avg_success_rate: float = 0.0
    avg_attack_strength_used: float = 0.0
    recent_mutation_successes: Dict[str, int] = field(default_factory=dict)
    last_success_ts: float = 0.0
    last_block_ts: float = 0.0
    inferred_resistance_score: float = 0.4
    target_surface: str = "input_channel"

    def recent_block_ratio(self) -> float:
        total = self.successes + self.blocks
        return self.blocks / total if total else 0.0


@dataclass
class StrategyHistoryItem:
    attack_type: str
    strategy_family: str
    technique: str
    target: str
    payload_hash: str
    mutation_v: int
    attack_strength: float
    outcome: str
    ts: float


@dataclass
class MutationHistoryItem:
    parent_payload_hash: str
    child_payload_hash: str
    mutation_type: str
    target: str
    success: bool
    ts: float


@dataclass
class CampaignState:
    campaign_id: str
    active_objective: str
    initial_source: str
    total_attempts: int = 0
    total_successes: int = 0
    current_preferred_strategy: str = ""
    current_preferred_mutation_family: str = ""
    started_at: float = field(default_factory=time.time)


@dataclass
class PlannedAttack:
    target: str
    strategy: Dict[str, Any]
    mutation_type: str
    mutation_profile: Dict[str, Any]
    payload: str
    payload_hash: str
    payload_hash_full: str
    parent_payload_hash: str
    parent_payload_hash_full: str
    payload_preview: str
    payload_length: int
    attack_strength: float
    confidence: float
    score_breakdown: Dict[str, Any]
    rationale: str
    hop_count: int
    semantic_family: str
    mutation_v: int


class AttackerMemory:
    def __init__(self, agent_id: str, seed: int, debug: bool = False, initial_objective: str = OBJECTIVES[0]):
        self.agent_id = agent_id
        self.debug = debug
        self.rng = random.Random(seed)
        self.seed = seed
        self.initial_objective = _normalize_objective(initial_objective)
        self.target_profiles: Dict[str, TargetProfile] = {}
        self.strategy_history: List[StrategyHistoryItem] = []
        self.mutation_history: List[MutationHistoryItem] = []
        self.attack_outcomes: List[Dict[str, Any]] = []
        self.strategy_weights: Dict[Tuple[str, str], float] = {}
        self.technique_weights: Dict[Tuple[str, str], float] = {}
        self.mutation_weights: Dict[Tuple[str, str], float] = {}
        self.strategy_cooldowns: Dict[str, float] = {}
        self.mutation_cooldowns: Dict[str, float] = {}
        self.active_attempts: Dict[str, Dict[str, Any]] = {}
        self.objective_index = 0
        self.campaign_state = CampaignState(
            campaign_id=f"cmp_{int(time.time())}_{agent_id}",
            active_objective=self.initial_objective,
            initial_source=agent_id,
        )

    def reset(self) -> None:
        self.target_profiles.clear()
        self.strategy_history.clear()
        self.mutation_history.clear()
        self.attack_outcomes.clear()
        self.strategy_weights.clear()
        self.technique_weights.clear()
        self.mutation_weights.clear()
        self.strategy_cooldowns.clear()
        self.mutation_cooldowns.clear()
        self.active_attempts.clear()
        self.objective_index = 0
        self.campaign_state = CampaignState(
            campaign_id=f"cmp_{int(time.time())}_{self.agent_id}",
            active_objective=self.initial_objective,
            initial_source=self.agent_id,
        )

    def get_target_profile(self, target: str) -> TargetProfile:
        if target not in self.target_profiles:
            context = TARGET_CONTEXT.get(target, TARGET_CONTEXT["agent-b"])
            self.target_profiles[target] = TargetProfile(
                target_id=target,
                inferred_resistance_score=float(context["defense_hint"]),
                target_surface=str(context["target_surface"]),
            )
        return self.target_profiles[target]

    def objective(self) -> str:
        return self.campaign_state.active_objective

    def rotate_objective(self, *, force: bool = False) -> Optional[Tuple[str, str]]:
        if not force and self.campaign_state.total_attempts < 3:
            return None
        previous = self.campaign_state.active_objective
        if self.campaign_state.total_attempts and self.campaign_state.total_successes == 0:
            next_objective = "MAXIMIZE_SUCCESS_RATE"
        elif any(profile.successes > 0 and TARGET_CONTEXT.get(profile.target_id, {}).get("depth", 0) < 3 for profile in self.target_profiles.values()):
            next_objective = "REACH_DEEPEST_NODE"
        elif len({item.mutation_type for item in self.mutation_history[-6:]}) < 2:
            next_objective = "MAXIMIZE_MUTATION_DIVERSITY"
        else:
            self.objective_index = (self.objective_index + 1) % len(OBJECTIVES)
            next_objective = OBJECTIVES[self.objective_index]
        if next_objective == previous:
            return None
        self.campaign_state.active_objective = next_objective
        return previous, next_objective


class KnowledgeAwareAttackPlanner:
    def __init__(
        self,
        *,
        agent_id: str,
        knowledge_service: RedTeamKnowledgeService,
        seed: int,
        debug: bool = False,
        initial_objective: str = OBJECTIVES[0],
        lock_objective: bool = False,
    ):
        self.agent_id = agent_id
        self.knowledge_service = knowledge_service
        self.debug = debug
        self.initial_objective = _normalize_objective(initial_objective)
        self.lock_objective = lock_objective
        self.memory = AttackerMemory(
            agent_id=agent_id,
            seed=seed,
            debug=debug,
            initial_objective=self.initial_objective,
        )
        self.max_attempts_per_window = 4
        self.window_seconds = 5.0
        self.strategy_cooldown_s = 1.25
        self.mutation_cooldown_s = 0.75
        self.max_concurrent_active_chains = 4
        self.max_hops = 4
        self.campaign_timeout_s = 120.0
        self.exploration_rate = 0.18

    def reset(self) -> None:
        self.memory.reset()

    def startup_summary(self) -> Dict[str, Any]:
        return {
            "attack_families": self.knowledge_service.get_attack_families(),
            "mutation_families": sorted(self.knowledge_service.mutation_profiles.keys()),
            "knowledge_source": self.knowledge_service.knowledge_source,
            "knowledge_version": self.knowledge_service.knowledge_version,
            "seed": self.memory.seed,
            "objective": self.memory.objective(),
            "objective_locked": self.lock_objective,
        }

    def _time_decay(self, timestamp: float) -> float:
        if not timestamp:
            return 0.0
        return math.exp(-(time.time() - timestamp) / 30.0)

    def _objective_alignment(self, target: str) -> float:
        context = TARGET_CONTEXT.get(target, TARGET_CONTEXT["agent-b"])
        objective = self.memory.objective()
        if objective == "SPREAD_FAST":
            return 1.0 - float(context["defense_hint"])
        if objective == "REACH_DEEPEST_NODE":
            return float(context["depth"]) / 3.0
        if objective == "MAXIMIZE_SUCCESS_RATE":
            profile = self.memory.get_target_profile(target)
            return profile.avg_success_rate or (1.0 - profile.inferred_resistance_score)
        if objective == "MAXIMIZE_MUTATION_DIVERSITY":
            return 0.5 + (0.1 * len({item.mutation_type for item in self.memory.mutation_history[-6:]}))
        if objective == "PRESSURE_HIGHEST_VALUE_TARGET":
            return float(context["depth"]) * float(context["defense_hint"]) / 3.0
        return 0.0

    def score_target(self, target: str) -> Dict[str, Any]:
        profile = self.memory.get_target_profile(target)
        context = TARGET_CONTEXT.get(target, TARGET_CONTEXT["agent-b"])
        historical_success_rate = profile.avg_success_rate
        inferred_resistance = profile.inferred_resistance_score
        recent_block_ratio = profile.recent_block_ratio()
        propagation_value = float(context["propagation_value"])
        exploration_bonus = 0.25 if profile.attempts_sent == 0 else 0.0
        state_bonus = 0.1 if profile.last_seen_state not in {"quarantined", "blocked"} else -0.15
        objective_alignment = self._objective_alignment(target)
        score = (
            TARGET_SCORE_WEIGHTS["historical_success_rate"] * historical_success_rate
            - TARGET_SCORE_WEIGHTS["resistance_penalty"] * inferred_resistance
            - TARGET_SCORE_WEIGHTS["recent_block_ratio"] * recent_block_ratio
            + TARGET_SCORE_WEIGHTS["propagation_value"] * propagation_value
            + TARGET_SCORE_WEIGHTS["exploration_bonus"] * exploration_bonus
            + TARGET_SCORE_WEIGHTS["state_bonus"] * state_bonus
            + TARGET_SCORE_WEIGHTS["objective_alignment"] * objective_alignment
        )
        return {
            "target": target,
            "score": round(score, 4),
            "score_breakdown": {
                "historical_success_rate": round(historical_success_rate, 4),
                "inferred_resistance_score": round(inferred_resistance, 4),
                "recent_block_ratio": round(recent_block_ratio, 4),
                "propagation_value": round(propagation_value, 4),
                "exploration_bonus": round(exploration_bonus, 4),
                "state_bonus": round(state_bonus, 4),
                "objective_alignment": round(objective_alignment, 4),
            },
            "profile": profile,
        }

    def choose_target(self, targets: List[str]) -> Dict[str, Any]:
        scored = [self.score_target(target) for target in targets]
        scored.sort(key=lambda item: (item["score"], item["target"]), reverse=True)
        return scored[0]

    def _strategy_recent_rates(self, target: str, strategy_family: str, technique: str) -> Tuple[float, float]:
        recent = [item for item in self.memory.strategy_history[-12:] if item.target == target and item.strategy_family == strategy_family]
        if not recent:
            return 0.0, 0.0
        successes = sum(1 for item in recent if item.outcome == "success")
        blocks = sum(1 for item in recent if item.outcome == "blocked")
        total = max(1, len(recent))
        technique_bonus = self.memory.technique_weights.get((target, technique), 0.0)
        return min(1.0, (successes / total) + technique_bonus), min(1.0, blocks / total)

    def choose_strategy(self, *, target_score: Dict[str, Any], strategy_override: Optional[str] = None) -> Dict[str, Any]:
        target = target_score["target"]
        profile = target_score["profile"]
        candidates = self.knowledge_service.get_candidate_strategies(
            {
                "target_id": target,
                "target_surface": profile.target_surface,
                "inferred_resistance_score": profile.inferred_resistance_score,
                "avg_success_rate": profile.avg_success_rate,
            },
            self.memory.objective(),
        )
        scored_candidates: List[Dict[str, Any]] = []
        now = time.time()
        for candidate in candidates:
            if strategy_override and candidate["strategy_family"] != strategy_override:
                continue
            success_rate, block_ratio = self._strategy_recent_rates(target, candidate["strategy_family"], candidate["technique"])
            cooldown_active = now < self.memory.strategy_cooldowns.get(candidate["strategy_family"], 0.0)
            exploration_bonus = self.exploration_rate if (target, candidate["technique"]) not in self.memory.technique_weights else 0.0
            objective_bias = OBJECTIVE_STRATEGY_BIAS.get(self.memory.objective(), {}).get(candidate["strategy_family"], 0.0)
            score = (
                STRATEGY_SCORE_WEIGHTS["knowledge_base_strength"] * candidate["base_strength"]
                + STRATEGY_SCORE_WEIGHTS["knowledge_stealth"] * candidate["stealth"]
                - STRATEGY_SCORE_WEIGHTS["target_resistance"] * profile.inferred_resistance_score
                - STRATEGY_SCORE_WEIGHTS["recent_block_ratio"] * block_ratio
                + STRATEGY_SCORE_WEIGHTS["recent_success_ratio"] * success_rate
                + STRATEGY_SCORE_WEIGHTS["objective_alignment"] * (candidate["objective_alignment"] + objective_bias)
                + STRATEGY_SCORE_WEIGHTS["exploration_bonus"] * exploration_bonus
                - STRATEGY_SCORE_WEIGHTS["cooldown_penalty"] * (1.0 if cooldown_active else 0.0)
                + self.memory.strategy_weights.get((target, candidate["strategy_family"]), 0.0)
            )
            scored_candidates.append(
                {
                    **candidate,
                    "score": round(score, 4),
                    "score_breakdown": {
                        "knowledge_base_strength": round(candidate["base_strength"], 4),
                        "knowledge_stealth": round(candidate["stealth"], 4),
                        "target_inferred_resistance": round(profile.inferred_resistance_score, 4),
                        "recent_block_ratio": round(block_ratio, 4),
                        "recent_success_ratio": round(success_rate, 4),
                        "objective_alignment": round(candidate["objective_alignment"] + objective_bias, 4),
                        "exploration_bonus": round(exploration_bonus, 4),
                        "cooldown_penalty": 1.0 if cooldown_active else 0.0,
                    },
                }
            )
        if not scored_candidates:
            raise ValueError("no candidate strategies available")
        scored_candidates.sort(
            key=lambda item: (item["score"], item["knowledge_confidence"], item["technique"]),
            reverse=True,
        )
        if len(scored_candidates) > 1 and self.memory.rng.random() < self.exploration_rate:
            return scored_candidates[1]
        return scored_candidates[0]

    def choose_mutation(self, *, strategy: Dict[str, Any], target: str) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        candidate_mutations = list(strategy.get("preferred_mutations", [])) or list(self.knowledge_service.mutation_profiles.keys())
        if "reframe" not in candidate_mutations:
            candidate_mutations.extend(["reframe"])
        scored: List[Dict[str, Any]] = []
        now = time.time()
        for mutation_type in dict.fromkeys(candidate_mutations):
            profile = self.knowledge_service.get_mutation_profile(mutation_type)
            runtime_weight = self.memory.mutation_weights.get((target, mutation_type), 0.0)
            successes = self.memory.get_target_profile(target).recent_mutation_successes.get(mutation_type, 0)
            failure_penalty = abs(min(0.0, runtime_weight))
            cooldown_active = now < self.memory.mutation_cooldowns.get(mutation_type, 0.0)
            knowledge_preference = 1.0 if mutation_type in strategy.get("preferred_mutations", []) else 0.4
            exploration_bonus = self.exploration_rate if (target, mutation_type) not in self.memory.mutation_weights else 0.0
            score = (
                MUTATION_SCORE_WEIGHTS["knowledge_preference"] * knowledge_preference
                + MUTATION_SCORE_WEIGHTS["runtime_success"] * min(1.0, successes * 0.25 + max(runtime_weight, 0.0))
                - MUTATION_SCORE_WEIGHTS["failure_penalty"] * failure_penalty
                - MUTATION_SCORE_WEIGHTS["cooldown_penalty"] * (1.0 if cooldown_active else 0.0)
                + MUTATION_SCORE_WEIGHTS["exploration_bonus"] * exploration_bonus
                + float(profile.get("retry_bias", 0.5)) * 0.10
            )
            scored.append(
                {
                    "mutation_type": mutation_type,
                    "mutation_profile": profile,
                    "score": round(score, 4),
                    "score_breakdown": {
                        "knowledge_preference": knowledge_preference,
                        "runtime_success": round(min(1.0, successes * 0.25 + max(runtime_weight, 0.0)), 4),
                        "failure_penalty": round(failure_penalty, 4),
                        "cooldown_penalty": 1.0 if cooldown_active else 0.0,
                        "exploration_bonus": round(exploration_bonus, 4),
                    },
                }
            )
        scored.sort(key=lambda item: (item["score"], item["mutation_type"]), reverse=True)
        winner = scored[0]
        return winner["mutation_type"], winner["mutation_profile"], {"candidates": scored, "selected": winner}

    def _bounded_strength(self, *, strategy: Dict[str, Any], mutation_profile: Dict[str, Any], target_profile: TargetProfile) -> float:
        objective_modifier = 0.08 if self.memory.objective() in {"SPREAD_FAST", "REACH_DEEPEST_NODE"} else 0.03
        resistance_penalty = target_profile.inferred_resistance_score * 0.18
        noise = self.memory.rng.uniform(-0.04, 0.04)
        strength = (
            float(strategy["base_strength"])
            + float(mutation_profile.get("strength_modifier", 0.0))
            + objective_modifier
            - resistance_penalty
            + noise
        )
        return round(max(0.15, min(1.75, strength)), 4)

    def plan_attack(
        self,
        *,
        source_payload: str,
        neighbors: List[str],
        current_hop_count: int,
        source_metadata: Dict[str, Any],
        strategy_override: Optional[str] = None,
    ) -> PlannedAttack:
        if not neighbors:
            raise ValueError("no neighbors to target")
        now = time.time()
        if current_hop_count >= self.max_hops:
            raise ValueError("max_hops_exceeded")
        if len(self.memory.active_attempts) >= self.max_concurrent_active_chains:
            raise ValueError("max_concurrent_active_chains_reached")
        recent_attempts = [item for item in self.memory.attack_outcomes if now - item["ts"] <= self.window_seconds]
        if len(recent_attempts) >= self.max_attempts_per_window:
            raise ValueError("max_attempts_per_window_reached")
        if now - self.memory.campaign_state.started_at > self.campaign_timeout_s:
            self.memory.rotate_objective(force=True)
            self.memory.campaign_state.started_at = now

        target_score = self.choose_target(neighbors)
        strategy = self.choose_strategy(target_score=target_score, strategy_override=strategy_override)
        mutation_type, mutation_profile, mutation_debug = self.choose_mutation(strategy=strategy, target=target_score["target"])
        target_profile = target_score["profile"]
        attack_strength = self._bounded_strength(strategy=strategy, mutation_profile=mutation_profile, target_profile=target_profile)
        semantic_family = str(strategy["knowledge_attack_type"])
        payload = f"SIM_ATTACK[{semantic_family}|technique={strategy['technique']}|mutation={mutation_type}|objective={self.memory.objective()}]"
        payload_hash_full = hash_payload(payload)
        parent_payload_hash_full = hash_payload(source_payload or "")
        rationale = (
            f"target={target_score['target']} scored highest; strategy={strategy['strategy_family']} "
            f"favored by knowledge strength {strategy['base_strength']:.2f} and objective {self.memory.objective()}"
        )
        confidence = round(min(0.99, 0.45 + strategy["knowledge_confidence"] * 0.4 + max(strategy["score"], 0.0) * 0.1), 3)
        return PlannedAttack(
            target=target_score["target"],
            strategy=strategy,
            mutation_type=mutation_type,
            mutation_profile=mutation_profile,
            payload=payload,
            payload_hash=short_payload_hash(payload_hash_full),
            payload_hash_full=payload_hash_full,
            parent_payload_hash=short_payload_hash(parent_payload_hash_full),
            parent_payload_hash_full=parent_payload_hash_full,
            payload_preview=build_payload_preview(payload),
            payload_length=len(payload),
            attack_strength=attack_strength,
            confidence=confidence,
            score_breakdown={
                "target": target_score["score_breakdown"],
                "strategy": strategy["score_breakdown"],
                "mutation": mutation_debug["selected"]["score_breakdown"],
            },
            rationale=rationale,
            hop_count=current_hop_count + 1,
            semantic_family=semantic_family,
            mutation_v=int(source_metadata.get("mutation_v", 0)) + 1,
        )

    def register_attempt(self, attempt_id: str, planned_attack: PlannedAttack, *, injection_id: str, reset_id: str, epoch: int) -> Dict[str, Any]:
        entry = {
            "attempt_id": attempt_id,
            "campaign_id": self.memory.campaign_state.campaign_id,
            "target": planned_attack.target,
            "strategy_family": planned_attack.strategy["strategy_family"],
            "attack_type": planned_attack.strategy["attack_type"],
            "knowledge_attack_type": planned_attack.strategy["knowledge_attack_type"],
            "technique": planned_attack.strategy["technique"],
            "mutation_type": planned_attack.mutation_type,
            "payload_hash": planned_attack.payload_hash,
            "payload_hash_full": planned_attack.payload_hash_full,
            "parent_payload_hash": planned_attack.parent_payload_hash,
            "parent_payload_hash_full": planned_attack.parent_payload_hash_full,
            "payload_preview": planned_attack.payload_preview,
            "payload_length": planned_attack.payload_length,
            "mutation_v": planned_attack.mutation_v,
            "attack_strength": planned_attack.attack_strength,
            "knowledge_confidence": planned_attack.strategy["knowledge_confidence"],
            "knowledge_source": planned_attack.strategy["knowledge_source"],
            "objective": self.memory.objective(),
            "ts": time.time(),
            "injection_id": injection_id,
            "reset_id": reset_id,
            "epoch": epoch,
        }
        self.memory.active_attempts[attempt_id] = entry
        self.memory.campaign_state.total_attempts += 1
        return entry

    def evaluate_feedback(self, feedback: Dict[str, Any]) -> Dict[str, Any]:
        attempt_id = str(feedback.get("attempt_id", ""))
        attempt = self.memory.active_attempts.pop(attempt_id, {})
        target = str(feedback.get("dst") or attempt.get("target") or "")
        profile = self.memory.get_target_profile(target)
        outcome = str(feedback.get("outcome", "unknown"))
        attack_strength = float(feedback.get("attack_strength", attempt.get("attack_strength", 0.5)) or 0.5)
        prior_profile = {
            "avg_success_rate": round(profile.avg_success_rate, 4),
            "inferred_resistance_score": round(profile.inferred_resistance_score, 4),
        }
        profile.attempts_sent += 1
        profile.avg_attack_strength_used = (
            ((profile.avg_attack_strength_used * max(profile.attempts_sent - 1, 0)) + attack_strength) / max(profile.attempts_sent, 1)
        )
        profile.last_seen_state = str(feedback.get("state_after") or profile.last_seen_state or "unknown")
        now = time.time()
        success = outcome == "success"
        if success:
            profile.successes += 1
            profile.last_success_ts = now
            mutation_key = str(feedback.get("mutation_type", ""))
            profile.recent_mutation_successes[mutation_key] = profile.recent_mutation_successes.get(mutation_key, 0) + 1
            self.memory.campaign_state.total_successes += 1
        else:
            profile.blocks += 1
            profile.last_block_ts = now
        profile.avg_success_rate = round(profile.successes / max(profile.attempts_sent, 1), 4)
        target_decay = self._time_decay(profile.last_success_ts if success else profile.last_block_ts)
        if success:
            profile.inferred_resistance_score = max(0.05, profile.inferred_resistance_score - (0.08 * target_decay))
        else:
            profile.inferred_resistance_score = min(0.98, profile.inferred_resistance_score + (0.10 * max(target_decay, 0.35)))

        strategy_family = str(feedback.get("strategy_family") or attempt.get("strategy_family") or "DIRECT_OVERRIDE")
        technique = str(feedback.get("technique") or attempt.get("technique") or "instruction_override")
        mutation_type = str(feedback.get("mutation_type") or attempt.get("mutation_type") or "reframe")
        delta = 0.12 if success else -0.10
        self.memory.strategy_weights[(target, strategy_family)] = max(-0.6, min(0.6, self.memory.strategy_weights.get((target, strategy_family), 0.0) + delta))
        self.memory.technique_weights[(target, technique)] = max(-0.6, min(0.6, self.memory.technique_weights.get((target, technique), 0.0) + (0.10 if success else -0.08)))
        self.memory.mutation_weights[(target, mutation_type)] = max(-0.6, min(0.6, self.memory.mutation_weights.get((target, mutation_type), 0.0) + (0.10 if success else -0.08)))
        self.memory.strategy_cooldowns[strategy_family] = now + (self.strategy_cooldown_s * (2.0 if not success else 0.6))
        self.memory.mutation_cooldowns[mutation_type] = now + (self.mutation_cooldown_s * (1.8 if not success else 0.5))
        self.memory.strategy_history.append(
            StrategyHistoryItem(
                attack_type=str(feedback.get("attack_type") or attempt.get("attack_type") or ""),
                strategy_family=strategy_family,
                technique=technique,
                target=target,
                payload_hash=str(feedback.get("payload_hash") or attempt.get("payload_hash") or ""),
                mutation_v=int(feedback.get("mutation_v", attempt.get("mutation_v", 0)) or 0),
                attack_strength=attack_strength,
                outcome=outcome,
                ts=now,
            )
        )
        self.memory.mutation_history.append(
            MutationHistoryItem(
                parent_payload_hash=str(feedback.get("parent_payload_hash") or attempt.get("parent_payload_hash") or ""),
                child_payload_hash=str(feedback.get("payload_hash") or attempt.get("payload_hash") or ""),
                mutation_type=mutation_type,
                target=target,
                success=success,
                ts=now,
            )
        )
        self.memory.attack_outcomes.append({"ts": now, "outcome": outcome, "target": target})
        rotated = None if self.lock_objective else self.memory.rotate_objective()
        preferred_strategy = max(
            {key[1]: value for key, value in self.memory.strategy_weights.items() if key[0] == target}.items(),
            key=lambda item: item[1],
            default=("", 0.0),
        )[0]
        preferred_mutation = max(
            {key[1]: value for key, value in self.memory.mutation_weights.items() if key[0] == target}.items(),
            key=lambda item: item[1],
            default=("", 0.0),
        )[0]
        self.memory.campaign_state.current_preferred_strategy = preferred_strategy
        self.memory.campaign_state.current_preferred_mutation_family = preferred_mutation
        return {
            "attempt": attempt,
            "target_profile_before": prior_profile,
            "target_profile_after": {
                "avg_success_rate": round(profile.avg_success_rate, 4),
                "inferred_resistance_score": round(profile.inferred_resistance_score, 4),
            },
            "strategy_weight_after": round(self.memory.strategy_weights[(target, strategy_family)], 4),
            "mutation_weight_after": round(self.memory.mutation_weights[(target, mutation_type)], 4),
            "rotated_objective": rotated,
        }
