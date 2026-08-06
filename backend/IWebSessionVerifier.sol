// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IWebSessionVerifier {
    function verify_web_session(
        address subject,
        string calldata targetUrl,
        string calldata htmlBundle,
        string calldata proofId,
        bytes calldata sessionProof
    ) external view returns (bool);
}
