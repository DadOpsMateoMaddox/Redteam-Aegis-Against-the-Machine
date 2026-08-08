"""Tests for the interactive red-team evaluator interaction contract."""
import pytest

from src.agent.redteam_evaluator import RedTeamEvaluator
from src.agent.redteam_schemas import (
    AttackVector,
    EscalationStage,
    RedTeamArea,
    RedTeamConfig,
)


@pytest.fixture
def config():
    return RedTeamConfig(
        objective="test boundary pressure",
        attack_vectors=[
            AttackVector.SEQUENTIAL_DECOMPOSITION,
            AttackVector.CRESCENDO_ESCALATION,
        ],
        testing_area=RedTeamArea.VULNERABILITY_DISCOVERY,
        escalation_stages=[
            EscalationStage.SETUP_AND_BOUNDARY_PROBE,
            EscalationStage.LIGHT_PRESSURE,
        ],
    )


@pytest.fixture
def evaluator(config, tmp_path):
    return RedTeamEvaluator(config, audit_path=tmp_path / "audit.log")


def test_configuration_is_exposed(evaluator):
    summary = evaluator.display_configuration()
    assert "Sequential / decomposition" in summary
    assert "Crescendo / escalation" in summary
    assert "Vulnerability discovery" in summary
    assert "setup_and_boundary_probe" in summary


def test_start_evaluation_generates_only_first_prompt(evaluator):
    turn = evaluator.start_evaluation()
    assert turn.turn_number == 1
    assert turn.attack_vector == AttackVector.SEQUENTIAL_DECOMPOSITION
    assert turn.testing_area == RedTeamArea.VULNERABILITY_DISCOVERY
    assert turn.escalation_stage == EscalationStage.SETUP_AND_BOUNDARY_PROBE
    assert turn.prompt
    assert turn.response is None
    assert len(evaluator.state.turns) == 1
    assert evaluator.audit.entries()


def test_start_evaluation_cannot_be_called_twice(evaluator):
    evaluator.start_evaluation()
    with pytest.raises(RuntimeError):
        evaluator.start_evaluation()


def test_next_turn_requires_target_response(evaluator):
    evaluator.start_evaluation()
    with pytest.raises(ValueError, match="target model response is required"):
        evaluator.next_turn("")


def test_next_turn_advances_one_turn_at_a_time(evaluator):
    turn1 = evaluator.start_evaluation()
    turn2 = evaluator.next_turn("I cannot help with that.")

    assert turn2.turn_number == 2
    assert turn2.response is None
    assert turn1.response == "I cannot help with that."
    # Stage should advance within the first vector before rotating.
    assert turn2.escalation_stage == EscalationStage.LIGHT_PRESSURE
    assert turn2.attack_vector == AttackVector.SEQUENTIAL_DECOMPOSITION
    assert len(evaluator.state.turns) == 2


def test_next_turn_rotates_vector_after_exhausting_stages(evaluator):
    turn1 = evaluator.start_evaluation()
    turn2 = evaluator.next_turn("response-1")
    turn3 = evaluator.next_turn("response-2")

    assert turn3.turn_number == 3
    assert turn3.attack_vector == AttackVector.CRESCENDO_ESCALATION
    assert turn3.escalation_stage == EscalationStage.SETUP_AND_BOUNDARY_PROBE


def test_evaluator_stops_after_exhausting_vectors_and_stages(evaluator):
    evaluator.start_evaluation()
    evaluator.next_turn("r1")  # stage 1 of vector 0
    evaluator.next_turn("r2")  # stage 2 of vector 0 -> rotate
    evaluator.next_turn("r3")  # stage 1 of vector 1
    with pytest.raises(RuntimeError, match="evaluation has already ended"):
        evaluator.next_turn("r4")


def test_prompt_does_not_contain_invented_response(evaluator):
    turn = evaluator.start_evaluation()
    assert "I cannot help" not in turn.prompt
    assert "target model" not in turn.prompt.lower() or "target model's" not in turn.prompt


def test_config_requires_attack_vector():
    with pytest.raises(ValueError, match="at least one attack vector"):
        RedTeamConfig(attack_vectors=[], testing_area=RedTeamArea.KILL_CHAIN_DECOMPOSITION)


def test_config_requires_testing_area():
    with pytest.raises(ValueError, match="a red-team testing area must be selected"):
        RedTeamConfig(
            attack_vectors=[AttackVector.ROLEPLAY_NARRATIVE_INCEPTION],
            testing_area=None,
        )
