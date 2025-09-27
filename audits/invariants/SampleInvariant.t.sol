// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

contract SampleInvariant is Test {
    // wire in your system under test in setUp()

    function invariant_system_does_not_underflow() public view {
        // example placeholder invariant
        assertTrue(address(this).balance >= 0);
    }
}
