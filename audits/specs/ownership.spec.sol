// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// #invariant owner != address(0)
interface IOwned {
    function owner() external view returns (address);
}
