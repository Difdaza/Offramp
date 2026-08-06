# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

import hashlib
from dataclasses import dataclass

from genlayer import *


ERROR_EXPECTED = "[EXPECTED]"


def _as_address(addr) -> Address:
    try:
        if hasattr(addr, "as_bytes"):
            return addr
    except Exception:
        pass
    try:
        if isinstance(addr, bytes):
            return Address(addr)
    except Exception:
        pass
    return Address(str(addr))


def _sender() -> Address:
    return _as_address(gl.message.sender_address)


def _addr_text(addr) -> str:
    try:
        return "0x" + bytes(addr.as_bytes).hex()
    except Exception:
        return str(addr)


def _bytes_text(data: bytes) -> str:
    try:
        return bytes(data).hex()
    except Exception:
        return str(data)


def _digest(subject: Address, target_url: str, html_bundle: str, proof_id: str, session_proof: bytes) -> str:
    html_hash = hashlib.sha256(html_bundle.encode("utf-8", "ignore")).hexdigest()
    proof_hash = hashlib.sha256(_bytes_text(session_proof).encode("utf-8", "ignore")).hexdigest()
    payload = (
        _addr_text(subject).lower()
        + "|"
        + target_url.strip()
        + "|"
        + html_hash
        + "|"
        + proof_id.strip()
        + "|"
        + proof_hash
    )
    return hashlib.sha256(payload.encode("utf-8", "ignore")).hexdigest()


@allow_storage
@dataclass
class SessionAttestation:
    subject: Address
    target_url: str
    html_hash: str
    proof_id: str
    proof_digest: str
    active: bool


class WebSessionVerifier(gl.Contract):
    owner: Address
    attestations: TreeMap[str, SessionAttestation]

    def __init__(self):
        self.owner = _sender()

    def _require_owner(self) -> None:
        if _sender() != self.owner:
            raise gl.vm.UserError(ERROR_EXPECTED + " verifier owner only")

    @gl.public.write
    def attest_session(
        self,
        subject: Address,
        target_url: str,
        html_bundle: str,
        proof_id: str,
        session_proof: bytes,
    ) -> None:
        self._require_owner()
        url = target_url.strip()
        pid = proof_id.strip()
        if not url.startswith("https://"):
            raise gl.vm.UserError(ERROR_EXPECTED + " https target required")
        if len(html_bundle.strip()) < 30:
            raise gl.vm.UserError(ERROR_EXPECTED + " html too short")
        if len(pid) < 16:
            raise gl.vm.UserError(ERROR_EXPECTED + " proof id too short")
        key = _digest(_as_address(subject), url, html_bundle.strip(), pid, session_proof)
        self.attestations[key] = SessionAttestation(
            subject=_as_address(subject),
            target_url=url,
            html_hash=hashlib.sha256(html_bundle.strip().encode("utf-8", "ignore")).hexdigest(),
            proof_id=pid,
            proof_digest=key,
            active=True,
        )

    @gl.public.view
    def verify_web_session(
        self,
        subject: Address,
        target_url: str,
        html_bundle: str,
        proof_id: str,
        session_proof: bytes,
    ) -> bool:
        key = _digest(_as_address(subject), target_url.strip(), html_bundle.strip(), proof_id.strip(), session_proof)
        att = self.attestations.get(key)
        return att is not None and bool(att.active)

    @gl.public.view
    def get_attestation(self, proof_digest: str) -> dict:
        att = self.attestations.get(proof_digest.strip())
        if att is None:
            return {"exists": False}
        return {
            "exists": True,
            "subject": _addr_text(att.subject),
            "target_url": att.target_url,
            "html_hash": att.html_hash,
            "proof_id": att.proof_id,
            "proof_digest": att.proof_digest,
            "active": bool(att.active),
        }
