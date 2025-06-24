from gatox.enumerate.results.complexity import Complexity


def test_complexity_enum_values():
    """Test that all enum values are correctly defined with expected strings"""
    assert Complexity.ZERO_CLICK.value == "No Interaction"
    assert Complexity.PREVIOUS_CONTRIBUTOR.value == "Previous Contributor"
    assert Complexity.FOLLOW_UP.value == "Persistent Approval Gated"
    assert Complexity.TOCTOU.value == "Time-of-Check to Time-of-Use"
    assert Complexity.BROKEN_ACCESS.value == "Broken Access Control"


def test_complexity_string_representation():
    """Test string and repr representations of Complexity enum"""
    assert str(Complexity.ZERO_CLICK) == "No Interaction"
    assert repr(Complexity.ZERO_CLICK) == "No Interaction"
    assert str(Complexity.BROKEN_ACCESS) == "Broken Access Control"
    assert repr(Complexity.BROKEN_ACCESS) == "Broken Access Control"


def test_complexity_explain():
    """Test explain method returns correct descriptions"""
    explanations = {
        Complexity.ZERO_CLICK: "Exploit requires no user interaction, you must still confirm there are no custom permission checks that would prevent the attack.",
        Complexity.PREVIOUS_CONTRIBUTOR: "Exploit requires a previous contributor to the repository, and the repository must use the default pull-request approval setting.",
        Complexity.FOLLOW_UP: "Exploit requires a maintainer to perform some state changing action, such as labeling a PR, at that point the attacker can follow up with their payload.",
        Complexity.TOCTOU: "Exploit requires updating pull request quickly after the maintainer performs an approval action, make sure the approval action runs on forks for this to be feasible.",
        Complexity.BROKEN_ACCESS: "Exploit requires the attacker to have some access, but the access control mechanism is not properly implemented.",
    }

    for complexity, expected in explanations.items():
        assert complexity.explain() == expected


def test_complexity_members():
    """Test that Complexity enum has all expected members"""
    expected_members = [
        "ZERO_CLICK",
        "PREVIOUS_CONTRIBUTOR",
        "FOLLOW_UP",
        "TOCTOU",
        "BROKEN_ACCESS",
    ]

    actual_members = [member.name for member in Complexity]
    assert sorted(actual_members) == sorted(expected_members)
