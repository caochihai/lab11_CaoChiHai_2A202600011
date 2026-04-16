"""
Lab 11 - Part 4: Human-in-the-Loop Design
  TODO 12: Confidence Router
  TODO 13: Design 3 HITL decision points
"""
from dataclasses import dataclass


HIGH_RISK_ACTIONS = [
    "transfer_money",
    "close_account",
    "change_password",
    "delete_data",
    "update_personal_info",
]


@dataclass
class RoutingDecision:
    """Result of the confidence router."""
    action: str
    confidence: float
    reason: str
    priority: str
    requires_human: bool


class ConfidenceRouter:
    """Route agent responses based on confidence and risk level."""

    HIGH_THRESHOLD = 0.9
    MEDIUM_THRESHOLD = 0.7

    def route(self, response: str, confidence: float,
              action_type: str = "general") -> RoutingDecision:
        """Route a response based on confidence score and action type."""
        if action_type in HIGH_RISK_ACTIONS:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason=f"High-risk action: {action_type}",
                priority="high",
                requires_human=True,
            )

        if confidence >= self.HIGH_THRESHOLD:
            return RoutingDecision(
                action="auto_send",
                confidence=confidence,
                reason="High confidence",
                priority="low",
                requires_human=False,
            )

        if confidence >= self.MEDIUM_THRESHOLD:
            return RoutingDecision(
                action="queue_review",
                confidence=confidence,
                reason="Medium confidence - needs review",
                priority="normal",
                requires_human=True,
            )

        return RoutingDecision(
            action="escalate",
            confidence=confidence,
            reason="Low confidence - escalating",
            priority="high",
            requires_human=True,
        )


hitl_decision_points = [
    {
        "id": 1,
        "name": "Large transfer approval",
        "trigger": "Transfer request exceeds bank threshold or has unusual destination.",
        "hitl_model": "human-in-the-loop",
        "context_needed": "User identity, transfer amount, destination account history, fraud risk signals, model rationale.",
        "example": "Customer requests transfer of 500000000 VND to a first-time beneficiary at midnight.",
    },
    {
        "id": 2,
        "name": "Sensitive profile change review",
        "trigger": "Request includes change of phone, email, password reset path, or recovery contact.",
        "hitl_model": "human-on-the-loop",
        "context_needed": "Authenticated session details, device fingerprint, recent account events, requested profile diff.",
        "example": "Account asks to update both phone and email right after failed login attempts from new device.",
    },
    {
        "id": 3,
        "name": "Policy conflict adjudication",
        "trigger": "Guardrails disagree or confidence is borderline for refusal versus answer.",
        "hitl_model": "human-as-tiebreaker",
        "context_needed": "Original prompt, blocked rule IDs, safety judge verdict, proposed response variants.",
        "example": "User asks tax planning question that looks banking-related but includes instructions that resemble evasion.",
    },
]


def test_confidence_router():
    """Test ConfidenceRouter with sample scenarios."""
    router = ConfidenceRouter()

    test_cases = [
        ("Balance inquiry", 0.95, "general"),
        ("Interest rate question", 0.82, "general"),
        ("Ambiguous request", 0.55, "general"),
        ("Transfer $50,000", 0.98, "transfer_money"),
        ("Close my account", 0.91, "close_account"),
    ]

    print("Testing ConfidenceRouter:")
    print("=" * 80)
    print(f"{'Scenario':<25} {'Conf':<6} {'Action Type':<18} {'Decision':<15} {'Priority':<10} {'Human?'}")
    print("-" * 80)

    for scenario, conf, action_type in test_cases:
        decision = router.route(scenario, conf, action_type)
        print(
            f"{scenario:<25} {conf:<6.2f} {action_type:<18} "
            f"{decision.action:<15} {decision.priority:<10} "
            f"{'Yes' if decision.requires_human else 'No'}"
        )

    print("=" * 80)


def test_hitl_points():
    """Display HITL decision points."""
    print("\nHITL Decision Points:")
    print("=" * 60)
    for point in hitl_decision_points:
        print(f"\n  Decision Point #{point['id']}: {point['name']}")
        print(f"    Trigger:  {point['trigger']}")
        print(f"    Model:    {point['hitl_model']}")
        print(f"    Context:  {point['context_needed']}")
        print(f"    Example:  {point['example']}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_confidence_router()
    test_hitl_points()
