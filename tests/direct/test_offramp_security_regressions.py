import json


TRAP = "backend/subscription-trap.py"
GEN = 10**18
PROOF = bytes(range(32))
VERIFIER_ADDRESS = "0x3333333333333333333333333333333333333333"
HTML_DARK = """
<html><body>
<button style='color:#f8f8f8'>cancel subscription</button>
<div>Before cancellation you must call support by phone.</div>
<div>Complete a survey gate before we continue.</div>
<div>Retention offer: click no thanks three times.</div>
<div>Your account may renew if final confirmation is not processed by support.</div>
</body></html>
"""
HTML_CLEAN = "<html><body><button>Cancel subscription</button><button>Confirm cancellation</button></body></html>"


def _addr_hex(value):
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if hasattr(value, "as_bytes"):
        return "0x" + bytes(value.as_bytes).hex()
    return str(value).lower()


def deploy_trap_with_mock_verifier(direct_vm, direct_deploy, owner):
    attestations = set()

    def hook(_vm, request):
        if "CallContract" in request:
            call = request["CallContract"]
            calldata_obj = call.get("calldata", {})
            ok = (
                getattr(_vm, "_offramp_last_submit_ok", False)
                and calldata_obj.get("method") == "verify_web_session"
            )
            from genlayer.py import calldata

            return bytes([0]) + calldata.encode(ok)
        if "PostMessage" in request:
            return {}
        return None

    direct_vm._offramp_attestations = attestations
    direct_vm._gl_call_hook = hook
    direct_vm.sender = owner
    trap = direct_deploy(TRAP, VERIFIER_ADDRESS)
    return trap


def mock_patterns(direct_vm, patterns):
    direct_vm.mock_llm(
        r".*authenticated subscription-cancellation HTML session bundle.*",
        json.dumps(
            {
                "patterns": patterns,
                "regulatory_concern": "FTC_ROSCA",
                "rationale": "Semantic pattern catalog matched visible cancellation-flow obstacles.",
            }
        ),
    )


def attest(direct_vm, subject, url, html, proof_id, proof=PROOF):
    direct_vm._offramp_attestations.add((_addr_hex(subject), url.strip(), html.strip(), proof_id.strip(), bytes(proof)))


def submit(direct_vm, trap, reporter, url, html, proof_id, bond=GEN, proof=PROOF):
    direct_vm.sender = reporter
    direct_vm.value = bond
    direct_vm._offramp_last_submit_ok = (_addr_hex(reporter), url.strip(), html.strip(), proof_id.strip(), bytes(proof)) in direct_vm._offramp_attestations
    trap.submit_flow(url, html, proof_id, proof)
    direct_vm._offramp_last_submit_ok = False
    direct_vm.value = 0


def test_submit_requires_verified_session_and_blocks_replay(direct_vm, direct_deploy, direct_owner, direct_alice):
    trap = deploy_trap_with_mock_verifier(direct_vm, direct_deploy, direct_owner)
    url = "https://service.example/account/cancel"
    pid = "proof-session-0001"

    with direct_vm.expect_revert("[EXPECTED] invalid web session proof"):
        submit(direct_vm, trap, direct_alice, url, HTML_DARK, pid)

    attest(direct_vm, direct_alice, url, HTML_DARK, pid)
    submit(direct_vm, trap, direct_alice, url, HTML_DARK, pid)
    assert trap.is_proof_used(pid) is True

    with direct_vm.expect_revert("[EXPECTED] session proof already used"):
        submit(direct_vm, trap, direct_alice, url, HTML_DARK, pid)


def test_semantic_pattern_matching_is_stored_not_text_only_count(direct_vm, direct_deploy, direct_owner, direct_alice):
    trap = deploy_trap_with_mock_verifier(direct_vm, direct_deploy, direct_owner)
    url = "https://dark.example/settings/cancel"
    pid = "proof-session-0002"
    attest(direct_vm, direct_alice, url, HTML_DARK, pid)
    submit(direct_vm, trap, direct_alice, url, HTML_DARK, pid)
    mock_patterns(
        direct_vm,
        [
            {"pattern": "FORCED_PHONE_CANCEL", "severity": 9, "evidence": "must call support by phone"},
            {"pattern": "SURVEY_GATE", "severity": 6, "evidence": "Complete a survey gate"},
            {"pattern": "RETENTION_GAUNTLET", "severity": 8, "evidence": "Retention offer"},
            {"pattern": "MISDIRECTION", "severity": 7, "evidence": "low-contrast cancel"},
        ],
    )
    direct_vm.sender = direct_alice
    trap.analyze(0)
    card = trap.get_case_card(0)
    assert card["evidence_verified"] is True
    assert card["obstacle_count"] == 4
    assert "FORCED_PHONE_CANCEL" in card["pattern_signature"]
    assert "SURVEY_GATE" in card["catalog_report"]
    trap.adjudicate(0)
    assert trap.get_case_card(0)["verdict"] == "DARK_PATTERN"


def test_clean_report_forfeits_bond_once_to_pool(direct_vm, direct_deploy, direct_owner, direct_alice):
    trap = deploy_trap_with_mock_verifier(direct_vm, direct_deploy, direct_owner)
    url = "https://clean.example/account/cancel"
    pid = "proof-session-0003"
    attest(direct_vm, direct_alice, url, HTML_CLEAN, pid)
    submit(direct_vm, trap, direct_alice, url, HTML_CLEAN, pid, bond=2 * GEN)
    mock_patterns(direct_vm, [])
    direct_vm.sender = direct_alice
    trap.analyze(0)
    trap.adjudicate(0)
    trap.flag_or_clear(0)
    card = trap.get_case_card(0)
    assert card["verdict"] == "CLEAN"
    assert card["bond"] == "0"
    assert trap.get_pool_balance() == str(2 * GEN)
    with direct_vm.expect_revert("[EXPECTED] case must be adjudicated first"):
        trap.flag_or_clear(0)


def test_dark_pattern_gets_bond_back_and_capped_bounty_not_double_pool_bond(direct_vm, direct_deploy, direct_owner, direct_alice):
    trap = deploy_trap_with_mock_verifier(direct_vm, direct_deploy, direct_owner)
    direct_vm.sender = direct_owner
    direct_vm.value = GEN
    trap.fund_pool()
    direct_vm.value = 0

    url = "https://dark.example/account/cancel"
    pid = "proof-session-0004"
    attest(direct_vm, direct_alice, url, HTML_DARK, pid)
    submit(direct_vm, trap, direct_alice, url, HTML_DARK, pid, bond=4 * GEN)
    mock_patterns(
        direct_vm,
        [
            {"pattern": "FORCED_PHONE_CANCEL", "severity": 9, "evidence": "phone only"},
            {"pattern": "SURVEY_GATE", "severity": 6, "evidence": "survey"},
            {"pattern": "RETENTION_GAUNTLET", "severity": 8, "evidence": "retention"},
            {"pattern": "MISDIRECTION", "severity": 7, "evidence": "hidden cancel"},
        ],
    )
    direct_vm.sender = direct_alice
    trap.analyze(0)
    trap.adjudicate(0)
    trap.flag_or_clear(0)
    card = trap.get_case_card(0)
    assert card["verdict"] == "DARK_PATTERN"
    assert card["bond"] == "0"
    assert card["bounty_paid"] == str(GEN)
    assert trap.get_pool_balance() == "0"
