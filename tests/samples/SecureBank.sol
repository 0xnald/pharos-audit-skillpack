pragma solidity 0.8.20;

abstract contract ReentrancyGuard {
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status;

    constructor() {
        _status = _NOT_ENTERED;
    }

    modifier nonReentrant() {
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }
}

contract SecureBank is ReentrancyGuard {
    address public owner;
    mapping(address => uint256) public balances;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);
    
    constructor() {
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "SecureBank: caller is not the owner");
        _;
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    function withdraw(uint256 amount) public nonReentrant {
        require(balances[msg.sender] >= amount, "SecureBank: insufficient balance");
        
        // Checks-Effects-Interactions
        balances[msg.sender] -= amount;
        
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "SecureBank: transfer failed");
        
        emit Withdraw(msg.sender, amount);
    }
    
    function changeOwner(address newOwner) public onlyOwner {
        require(newOwner != address(0), "SecureBank: new owner is the zero address");
        owner = newOwner;
    }
}
