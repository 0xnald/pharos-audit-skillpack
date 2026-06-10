pragma solidity ^0.7.0;

contract VulnerableBank {
    address public owner;
    mapping(address => uint) public balances;
    
    constructor() {
        owner = msg.sender;
    }
    
    // Default visibility bug (public by default in older versions)
    function deposit() payable {
        balances[msg.sender] += msg.value;
    }
    
    // Reentrancy bug & tx.origin auth bug
    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        
        // External call before state variable change
        (bool success, ) = msg.sender.call{value: amount}("");
        
        // Vulnerable unchecked call return
        // require(success); is missing
        
        balances[msg.sender] -= amount;
    }
    
    // Unprotected state update & tx.origin auth modifier
    function changeOwner(address newOwner) public {
        require(tx.origin == owner); // tx.origin authorization
        owner = newOwner;
    }
}
