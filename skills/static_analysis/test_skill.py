import sys
import os

# Include parent directory to import handler
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import handler

def test_analyze_vulnerable_pragma():
    code = """
    pragma solidity ^0.8.0;
    contract Test {}
    """
    res = handler.analyze(code)
    vulns = res["vulnerabilities"]
    assert any(v["id"] == "SOL-PRAGMA-001" for v in vulns)
    assert res["score"] < 100

def test_analyze_fixed_pragma():
    code = """
    pragma solidity 0.8.20;
    contract Test {}
    """
    res = handler.analyze(code)
    vulns = res["vulnerabilities"]
    assert not any(v["id"] == "SOL-PRAGMA-001" for v in vulns)
    assert res["score"] == 100

def test_analyze_default_visibility():
    code = """
    pragma solidity 0.8.20;
    contract Test {
        function withdraw() {
            // default visibility public
        }
    }
    """
    res = handler.analyze(code)
    vulns = res["vulnerabilities"]
    assert any(v["id"] == "SOL-VIS-001" for v in vulns)

def test_analyze_tx_origin():
    code = """
    pragma solidity 0.8.20;
    contract Test {
        address owner;
        function update(address newOwner) public {
            require(tx.origin == owner);
            owner = newOwner;
        }
    }
    """
    res = handler.analyze(code)
    vulns = res["vulnerabilities"]
    assert any(v["id"] == "SOL-AUTH-001" for v in vulns)

def test_analyze_unchecked_call():
    code = """
    pragma solidity 0.8.20;
    contract Test {
        function pay(address payable target) public {
            target.send(1 ether);
        }
    }
    """
    res = handler.analyze(code)
    vulns = res["vulnerabilities"]
    assert any(v["id"] == "SOL-CALL-001" for v in vulns)

def test_analyze_reentrancy():
    code = """
    pragma solidity 0.8.20;
    contract Vulnerable {
        mapping(address => uint) balances;
        function withdraw(uint amount) public {
            require(balances[msg.sender] >= amount);
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success);
            balances[msg.sender] -= amount;
        }
    }
    """
    res = handler.analyze(code)
    vulns = res["vulnerabilities"]
    assert any(v["id"] == "SOL-REENTRANCY-001" for v in vulns)

if __name__ == "__main__":
    test_analyze_vulnerable_pragma()
    test_analyze_fixed_pragma()
    test_analyze_default_visibility()
    test_analyze_tx_origin()
    test_analyze_unchecked_call()
    test_analyze_reentrancy()
    print("All static analysis tests passed successfully!")
