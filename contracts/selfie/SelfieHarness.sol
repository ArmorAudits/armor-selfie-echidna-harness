// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.6.0;

import "@openzeppelin/contracts/token/ERC20/ERC20Snapshot.sol";
import "./SelfiePool.sol";

contract MockSnapshot is ERC20Snapshot {
    constructor() public ERC20("MOCK","MOCK") {}
}

contract SelfieHarness is SelfiePool {
    uint256 public lastQueuedActionId;
    bytes4 private constant DRAIN_SEL = bytes4(keccak256("drainAllFunds(address)"));

    constructor() public
        SelfiePool(address(new MockSnapshot()), address(0x000000000000000000000000000000000000dEaD))
    {}

    // pool balance never goes below its initial value
    bool private _inited;
    uint256 private _init;
    function echidna_pool_not_drained() public returns (bool) {
        if (!_inited) {
            _init = IERC20(address(token)).balanceOf(address(this));
            _inited = true;
        }
        return IERC20(address(token)).balanceOf(address(this)) >= _init;
    }

    // Let Echidna try queueing arbitrary calls against this pool
    function fuzz_queue(bytes calldata data) external {
        // SimpleGovernance signature in DVT: queueAction(address,bytes,uint256) -> uint256
        lastQueuedActionId = governance.queueAction(address(this), data, 0);
    }

    // Fail if a pending action targets drainAllFunds(address)
    function echidna_no_drain_action_queued() public view returns (bool) {
        uint256 id = lastQueuedActionId;
        if (id == 0) return true;

        // DVT SimpleGovernance.actions(id) returns:
        // (address receiver, uint256 weiAmount, bytes memory data, uint256 proposedAt, bool executed)
        (address receiver, bytes memory callData, uint256 _weiAmount, uint256 proposedAt, uint256 executedAt) =
            governance.actions(id);

        if (executedAt != 0) return true;
        if (receiver != address(this)) return true;
        if (callData.length < 4) return true;

        // First 4 bytes are the function selector
        bytes4 sel;
        assembly { sel := mload(add(callData, 32)) }

        return sel != DRAIN_SEL;
    }
}
