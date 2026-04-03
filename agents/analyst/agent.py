"""
Analyst Agent — Medium-security compliance assessor with LLM-first hybrid decisions.

Architecture (Red Teaming AI, Ch.8 & Ch.11):
  The Analyst is the "gray zone" agent — neither naive like Courier
  nor hardened like Guardian. It represents the Confused Deputy Problem:
  a legitimate intermediary that can be socially engineered into
  forwarding malicious payloads upstream.

Decision Stack:
  Layer 1: LLM semantic compliance assessment (PRIMARY)
  Layer 2: Base probabilistic model (sigmoid bounds)
  Layer 3: Role calibration — wide uncertain band, most hybrid behavior

Role Calibration Profile:
  - No hard blocks (unlike Guardian) — Analyst can always be persuaded
  - No forced compliance (unlike Courier) — Analyst has moderate guardrails
  - Wide band: P ranges freely 0.15 – 0.85 based on LLM compliance verdict
  - High compliance (LLM persuaded) → defense DOWN by up to 0.25
  - Low compliance (LLM suspicious) → defense UP by up to 0.20
  - Forward-to-Guardian escalation: reduces own infection risk
"""

import asyncio
import json
import math
import os
import random
import time
from typing import Any, Dict

from shared.agent_base import AgentBase, AgentState, EventPayload
from shared.llm_service import LLMService, ComplianceVerdict


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def _clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


class AnalystAgent(AgentBase):
    """
    Medium-security analyzer — LLM-first compliance assessment.

    The Analyst sits between Courier (vulnerable) and Guardian (hardened).
    Its LLM decides whether to comply with, refuse, or escalate incoming
    messages. The compliance verdict modulates the probabilistic infection
    model rather than replacing it entirely.
    """

    def __init__(self):
        super().__init__()

        # Base defense — moderate (from docker-compose DEFENSE_LEVEL)
        self.defense_level = float(os.environ.get("DEFENSE_LEVEL", "0.50"))
        self.base_defense = self.defense_level

        # TEMPORAL SIMULATION: Medium processing (some analysis)
        self.base_delay_ms = 200      # Base: 200ms
        self.jitter_ms = 50           # Jitter: ±50ms

        # AUTONOMOUS PROPAGATION: Moderate spread rate
        self.propagation_interval_ms = 300
        self.max_broadcasts_per_second = 10

        # ─── LLM-FIRST COMPLIANCE ENGINE ──────────────────────────
        self.llm_service = LLMService(
            ollama_url=self.ollama_url,
            model=self.model,
            agent_id=self.agent_id,
        )

        # Role calibration: Analyst has a wide uncertainty band
        self.llm_compliance_weight = float(
            os.environ.get("LLM_COMPLIANCE_WEIGHT", "0.25")
        )
        # How much a high-compliance LLM verdict reduces defense
        self.max_defense_reduction = float(
            os.environ.get("ANALYST_MAX_DEFENSE_REDUCTION", "0.25")
        )
        # How much a low-compliance (suspicious) LLM verdict boosts defense
        self.max_defense_boost = float(
            os.environ.get("ANALYST_MAX_DEFENSE_BOOST", "0.20")
        )
        # Analyst role bounds — infection probability clamped to this band
        self.min_infection_probability = float(
            os.environ.get("ANALYST_MIN_INFECTION_P", "0.15")
        )
        self.max_infection_probability = float(
            os.environ.get("ANALYST_MAX_INFECTION_P", "0.85")
        )

    def get_system_prompt(self) -> str:
        with open("system_prompt.txt", "r") as f:
            return f.read()

    async def _on_reset_applied(self) -> None:
        """Reset LLM state and restore base defense on simulation reset."""
        self.defense_level = self.base_defense
        self.llm_service.reset()

    def _uncertainty_level(self, verdict: ComplianceVerdict) -> str:
        if verdict.model_status in ("fallback", "error"):
            return "high"
        if verdict.verdict == "uncertain" or verdict.recommended_action == "analyze":
            if verdict.confidence < 0.45:
                return "high"
            if verdict.confidence < 0.7:
                return "medium"
        if 0.4 <= verdict.compliance_score <= 0.6:
            return "medium"
        return "low"

    def _decision_rationale(self, verdict: ComplianceVerdict) -> str:
        rationale = (verdict.decision_rationale or verdict.summary or "").strip()
        if rationale:
            return rationale
        return f"Analyst classified the message as {verdict.verdict or 'uncertain'}."

    # ══════════════════════════════════════════════════════════════════
    # QUARANTINE ADVISORY HANDLING
    # ══════════════════════════════════════════════════════════════════

    async def _handle_quarantine_advisory(self, message: EventPayload) -> None:
        """Process quarantine feedback from Guardian — boost defense scrutiny."""
        threat_score = float(message.metadata.get("threat_score", 0.5) or 0.5)
        boost = _clamp(threat_score * 0.15, 0.02, 0.12)
        old_defense = self.defense_level
        self.defense_level = _clamp(self.defense_level + boost, 0.10, 0.90)
        print(
            f"[{self.agent_id}] Quarantine advisory from {message.src}: "
            f"defense {old_defense:.2f} -> {self.defense_level:.2f} (+{boost:.3f})"
        )
        await self._emit_event(
            "QUARANTINE_ADVISORY_RECEIVED",
            src=message.src, dst=self.agent_id,
            state_after=self.state.value,
            metadata={
                "advisory_type": message.metadata.get("advisory_type"),
                "threat_score": round(threat_score, 4),
                "defense_boost": round(boost, 4),
                "defense_before": round(old_defense, 4),
                "defense_after": round(self.defense_level, 4),
                "original_attempt_id": message.metadata.get("original_attempt_id"),
            },
        )

    # ══════════════════════════════════════════════════════════════════
    # LLM-FIRST HANDLE_MESSAGE
    # ══════════════════════════════════════════════════════════════════

    async def handle_message(self, message: EventPayload):
        # Handle quarantine advisories from Guardian
        if message.event_type == "quarantine_advisory":
            await self._handle_quarantine_advisory(message)
            return
        """
        LLM-FIRST ANALYST COMPLIANCE ENGINE

        Architecture (3-layer stack):
          Layer 1: LLM semantic compliance assessment (PRIMARY decision-maker)
          Layer 2: Base probabilistic model — sigmoid(attack - defense - immunity)
          Layer 3: Role calibration — wide band, hybrid blending

        LLM persuaded (high compliance)  → defense reduced → higher P(infect)
        LLM suspicious (low compliance)  → defense boosted → lower P(infect)
        LLM escalates to Guardian        → defense boost + reduced exposure
        LLM unavailable                  → pure probabilistic fallback
        """

        # Guard: skip if quarantined
        if self.state == AgentState.QUARANTINED:
            return

        self.last_message_metadata = dict(message.metadata)
        hop_count = int(message.metadata.get("hop_count", 0) or 0)
        injection_id = message.metadata.get("injection_id", "")
        attempt_id = str(
            message.metadata.get("attempt_id") or injection_id or message.id
        )
        message_epoch = int(
            message.metadata.get("epoch", self.current_epoch) or self.current_epoch
        )
        message_reset_id = str(
            message.metadata.get("reset_id", self.last_reset_id) or self.last_reset_id
        )
        attack_strength = float(message.metadata.get("attack_strength", 0.5) or 0.5)
        attack_type = str(message.metadata.get("attack_type", "unknown") or "unknown")

        print(f"[{self.agent_id}] ╔ LLM-FIRST Compliance analysis for message from {message.src}")

        # ─────────────────────────────────────────────────────────
        # PHASE 0: TRANSITION TO EXPOSED (analysis in progress)
        # ─────────────────────────────────────────────────────────
        if self.state in (AgentState.HEALTHY, AgentState.RESISTANT):
            self.state = AgentState.EXPOSED
            print(f"[{self.agent_id}] │ State → EXPOSED (analyzing)")

        # ═══════════════════════════════════════════════════════════
        # LAYER 1: LLM COMPLIANCE ASSESSMENT (concurrent with delay)
        # ═══════════════════════════════════════════════════════════
        metadata_context = (
            f"src={message.src} attack_type={attack_type} "
            f"hop_count={hop_count} mutation_v={message.metadata.get('mutation_v', 0)}"
        )
        llm_task = asyncio.create_task(
            self.llm_service.assess_compliance(
                message.payload,
                self.get_system_prompt(),
                source_agent=message.src,
                metadata_context=metadata_context,
            )
        )
        await self.inject_processing_delay()

        # Check for stale events after delay
        control_epoch, control_reset_id = await self._get_control_plane_epoch()
        if (
            message_epoch < control_epoch
            or (control_reset_id and message_reset_id
                and message_reset_id != control_reset_id)
        ):
            llm_task.cancel()
            await self._emit_event(
                "STALE_EVENT_DROPPED",
                src=message.src, dst=self.agent_id,
                payload=message.payload,
                state_after=self.state.value,
                metadata={
                    **message.metadata,
                    "attempt_id": attempt_id,
                    "reason": "post_delay_control_mismatch",
                },
            )
            return

        # Await LLM result
        llm_verdict: ComplianceVerdict
        try:
            llm_verdict = await llm_task
        except Exception:
            llm_verdict = ComplianceVerdict(
                model_status="error",
                summary="LLM task failed",
            )
        uncertainty_level = self._uncertainty_level(llm_verdict)
        decision_rationale = self._decision_rationale(llm_verdict)
        semantic_decision_path = (
            f"semantic_verdict={llm_verdict.verdict or 'uncertain'} "
            f"recommended_action={llm_verdict.recommended_action or 'analyze'}"
        )

        # Emit LLM compliance event
        await self._emit_event(
            "LLM_COMPLIANCE_ASSESSMENT",
            src=message.src, dst=self.agent_id,
            payload=message.payload,
            state_after=self.state.value,
            metadata={
                "attempt_id": attempt_id,
                "llm_verdict": llm_verdict.verdict,
                "llm_confidence": llm_verdict.confidence,
                "llm_compliance_score": llm_verdict.compliance_score,
                "llm_risk_score": llm_verdict.risk_score,
                "llm_reasoning_tags": llm_verdict.reasoning_tags,
                "llm_summary": llm_verdict.summary,
                "decision_rationale": decision_rationale,
                "uncertainty_reason": llm_verdict.uncertainty_reason,
                "uncertainty_level": uncertainty_level,
                "semantic_decision_path": semantic_decision_path,
                "llm_recommended_action": llm_verdict.recommended_action,
                "llm_model_status": llm_verdict.model_status,
                "llm_latency_ms": round(llm_verdict.latency_ms, 1),
                "llm_model": self.model,
                "decision_source": (
                    "llm" if llm_verdict.model_status == "ok"
                    else "fallback"
                ),
            },
        )

        print(
            f"[{self.agent_id}] │ LLM verdict: {llm_verdict.verdict} "
            f"(confidence={llm_verdict.confidence:.2f}, "
            f"compliance={llm_verdict.compliance_score:.2f}, "
            f"risk={llm_verdict.risk_score:.2f}, "
            f"status={llm_verdict.model_status})"
        )
        print(f"[{self.agent_id}] │ LLM tags: {llm_verdict.reasoning_tags}")
        print(f"[{self.agent_id}] │ LLM summary: {llm_verdict.summary}")

        # ═══════════════════════════════════════════════════════════
        # LAYER 2: PROBABILISTIC BASE (sigmoid infection model)
        # ═══════════════════════════════════════════════════════════
        base_p = self.compute_infection_probability(attack_strength, attack_type)

        # ═══════════════════════════════════════════════════════════
        # LAYER 3: HYBRID DECISION — LLM compliance modulates defense
        # ═══════════════════════════════════════════════════════════

        is_infected = False
        P_infect_noisy = 0.0
        infection_roll = 1.0
        decision_path = "unknown"

        if llm_verdict.model_status in ("fallback", "error"):
            # ──── LLM UNAVAILABLE → pure probabilistic fallback ────
            P_infect_noisy = _clamp(
                self.add_stochastic_noise(base_p),
                self.min_infection_probability,
                self.max_infection_probability,
            )
            infection_roll = random.random()
            is_infected = infection_roll < P_infect_noisy
            decision_path = "probabilistic_fallback"
            print(
                f"[{self.agent_id}] │ ⚠️ LLM fallback — pure probabilistic "
                f"P={P_infect_noisy:.2%}"
            )

        elif llm_verdict.is_persuaded:
            # ──── LLM PERSUADED (high compliance) → defense DOWN ────
            # The Analyst's LLM was convinced by the social engineering.
            # This is the Confused Deputy: compliance reduces defenses.
            # Red Teaming AI Ch.11: social engineering exploits trust.
            defense_reduction = self.max_defense_reduction * llm_verdict.compliance_score
            effective_defense = _clamp(
                self.defense_level - defense_reduction,
                0.10,  # floor — never fully undefended
                0.90,
            )
            self.defense_level = effective_defense
            net_attack = attack_strength - effective_defense
            adjusted_p = _sigmoid(net_attack)
            P_infect_noisy = _clamp(
                self.add_stochastic_noise(adjusted_p),
                self.min_infection_probability,
                self.max_infection_probability,
            )
            infection_roll = random.random()
            is_infected = infection_roll < P_infect_noisy
            decision_path = "llm_persuaded"
            print(
                f"[{self.agent_id}] │ 🟡 LLM PERSUADED — defense reduced by "
                f"{defense_reduction:.2f} → effective={effective_defense:.2f} "
                f"P={P_infect_noisy:.2%}"
            )

        elif llm_verdict.is_refusing:
            # ──── LLM REFUSING (low compliance) → defense UP ────
            # Analyst is suspicious. Boost defense, but no hard block
            # (that's Guardian-only). Analyst can still be infected
            # at reduced probability.
            defense_boost = self.max_defense_boost * llm_verdict.confidence
            effective_defense = _clamp(
                self.defense_level + defense_boost,
                0.10,
                0.90,
            )
            self.defense_level = effective_defense
            net_attack = attack_strength - effective_defense
            adjusted_p = _sigmoid(net_attack)
            P_infect_noisy = _clamp(
                self.add_stochastic_noise(adjusted_p),
                self.min_infection_probability,
                self.max_infection_probability,
            )
            infection_roll = random.random()
            is_infected = infection_roll < P_infect_noisy
            decision_path = "llm_refusing"
            print(
                f"[{self.agent_id}] │ 🟢 LLM REFUSING — defense boosted by "
                f"{defense_boost:.2f} → effective={effective_defense:.2f} "
                f"P={P_infect_noisy:.2%}"
            )

        elif llm_verdict.verdict == "forward_to_guardian":
            # ──── ESCALATION TO GUARDIAN → moderate defense boost ────
            # Analyst escalates uncertain messages. This gives a defense
            # bonus because the act of escalating shows awareness.
            # However, the message may still partially infect.
            defense_boost = self.max_defense_boost * 0.5
            effective_defense = _clamp(
                self.defense_level + defense_boost,
                0.10,
                0.90,
            )
            self.defense_level = effective_defense
            net_attack = attack_strength - effective_defense
            adjusted_p = _sigmoid(net_attack)
            P_infect_noisy = _clamp(
                self.add_stochastic_noise(adjusted_p),
                self.min_infection_probability,
                self.max_infection_probability,
            )
            infection_roll = random.random()
            is_infected = infection_roll < P_infect_noisy
            decision_path = "escalate_to_guardian"
            print(
                f"[{self.agent_id}] │ 🔵 ESCALATING to Guardian — "
                f"defense +{defense_boost:.2f} → effective={effective_defense:.2f} "
                f"P={P_infect_noisy:.2%}"
            )

        else:
            # ──── UNCERTAIN → pure hybrid blend ────
            # Most common Analyst path: moderate compliance, uncertain risk.
            # Blend LLM compliance into defense via weighted modifier.
            #   compliance > 0.5 → defense decreases (agent leaning toward comply)
            #   compliance < 0.5 → defense increases (agent leaning toward refuse)
            compliance_modifier = (
                self.llm_compliance_weight
                * (llm_verdict.compliance_score - 0.5)
                * 2.0
            )
            effective_defense = _clamp(
                self.defense_level - compliance_modifier,  # subtract: high compliance → lower defense
                0.15,
                0.85,
            )
            self.defense_level = effective_defense
            net_attack = attack_strength - effective_defense
            adjusted_p = _sigmoid(net_attack)
            P_infect_noisy = _clamp(
                self.add_stochastic_noise(adjusted_p),
                self.min_infection_probability,
                self.max_infection_probability,
            )
            infection_roll = random.random()
            is_infected = infection_roll < P_infect_noisy
            decision_path = "hybrid_uncertain"
            print(
                f"[{self.agent_id}] │ ⚪ UNCERTAIN — compliance modifier "
                f"{compliance_modifier:+.3f} → defense={effective_defense:.2f} "
                f"P={P_infect_noisy:.2%}"
            )

        print(
            f"[{self.agent_id}] │ Roll: {infection_roll:.2%} → "
            f"{'🔴 INFECTED' if is_infected else '✅ BLOCKED'}"
        )

        # Emit hybrid decision event
        await self._emit_event(
            "HYBRID_DECISION_MADE",
            src=message.src, dst=self.agent_id,
            payload=message.payload,
            attack_type=attack_type,
            attack_strength=attack_strength,
            state_after=self.state.value,
            metadata={
                **dict(message.metadata),
                "attempt_id": attempt_id,
                "decision_path": decision_path,
                "llm_verdict": llm_verdict.verdict,
                "llm_compliance_score": llm_verdict.compliance_score,
                "llm_risk_score": llm_verdict.risk_score,
                "llm_confidence": llm_verdict.confidence,
                "decision_rationale": decision_rationale,
                "uncertainty_reason": llm_verdict.uncertainty_reason,
                "uncertainty_level": uncertainty_level,
                "semantic_decision_path": f"{semantic_decision_path} hybrid_path={decision_path}",
                "llm_model_status": llm_verdict.model_status,
                "llm_latency_ms": round(llm_verdict.latency_ms, 1),
                "base_defense": round(self.base_defense, 4),
                "effective_defense": round(self.defense_level, 4),
                "base_p": round(base_p, 4),
                "P_infection_final": round(P_infect_noisy, 4),
                "infection_roll": round(infection_roll, 4),
                "result": "infected" if is_infected else "blocked",
                "analyst_band": f"[{self.min_infection_probability:.2f}, {self.max_infection_probability:.2f}]",
            },
        )

        # ═══════════════════════════════════════════════════════════
        # STATE TRANSITION & CONSEQUENCES
        # ═══════════════════════════════════════════════════════════
        if is_infected:
            await self._on_infection_succeeded(message, P_infect_noisy, infection_roll)
        else:
            await self._on_infection_blocked(message, P_infect_noisy, infection_roll)

        print(f"[{self.agent_id}] ╚")


async def main():
    agent = AnalystAgent()
    await agent.start()

if __name__ == "__main__":
    asyncio.run(main())
