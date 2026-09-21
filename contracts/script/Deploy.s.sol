// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {ArcGuardRegistry} from "../src/ArcGuardRegistry.sol";

/**
 * Deploy ArcGuardRegistry to Arc.
 *
 *   export PRIVATE_KEY=0x...
 *   forge script script/Deploy.s.sol --rpc-url arc --broadcast
 *
 * Then copy the printed address into docs/config.js as `registryAddress`.
 * Gas is paid in USDC, so the deploying account needs a little USDC on Arc.
 */
contract Deploy is Script {
    function run() external returns (ArcGuardRegistry registry) {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerKey);
        registry = new ArcGuardRegistry();
        vm.stopBroadcast();

        console2.log("ArcGuardRegistry deployed at:", address(registry));
        console2.log("Paste this into docs/config.js -> registryAddress");
    }
}
