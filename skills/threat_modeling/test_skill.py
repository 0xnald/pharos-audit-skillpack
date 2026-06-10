import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import handler

def test_roles_and_privileged():
    code = """
    pragma solidity 0.8.20;
    contract Auth {
        address public owner;
        address public manager;
        
        modifier onlyOwner() {
            require(msg.sender == owner);
            _;
        }
        
        function setManager(address newManager) public onlyOwner {
            manager = newManager;
        }
    }
    """
    res = handler.analyze(code)
    assert "Owner" in res["roles"]
    assert any(pf["name"] == "setManager" and pf["modifier"] == "onlyOwner" for pf in res["privileged_functions"])

def test_unprotected_state_mutator():
    code = """
    pragma solidity 0.8.20;
    contract Vulnerable {
        address public owner;
        
        function changeOwner(address newOwner) public {
            owner = newOwner; // Vulnerable: missing onlyOwner modifier
        }
    }
    """
    res = handler.analyze(code)
    assert any(t["id"] == "THREAT-CTRL-001" for t in res["threats"])

def test_missing_safemath_pre_08():
    code = """
    pragma solidity ^0.7.0;
    contract Old {
        mapping(address => uint) balances;
        function transfer(address to, uint amount) public {
            balances[msg.sender] -= amount; // Vulnerable to underflow
            balances[to] += amount;         // Vulnerable to overflow
        }
    }
    """
    res = handler.analyze(code)
    assert any(t["id"] == "THREAT-MATH-001" for t in res["threats"])

def test_oracle_spot_price():
    code = """
    pragma solidity 0.8.20;
    contract OracleVulnerable {
        address pair;
        function getPrice() public view returns (uint) {
            uint reserve0 = IUniswap(pair).getReserves();
            uint balance = IERC20(token).balanceOf(pair);
            return reserve0 * 1e18 / balance; // spot price manipulation risk
        }
    }
    """
    res = handler.analyze(code)
    assert any(t["id"] == "THREAT-ORACLE-001" for t in res["threats"])

if __name__ == "__main__":
    test_roles_and_privileged()
    test_unprotected_state_mutator()
    test_missing_safemath_pre_08()
    test_oracle_spot_price()
    print("All threat modeling tests passed successfully!")
