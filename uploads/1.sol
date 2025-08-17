pragma solidity ^0.8.0;

contract BadContract {
    address owner;

    function withdraw() public {
        if (tx.origin == owner) {   // bad
            payable(owner).call.value(1 ether)(""); // bad
        }
    }
}
