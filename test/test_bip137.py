import base64, pytest
from bitcoin_utils import BitcoinProofOfFunds as BPF

VECTORS = [

   #segwit standard signature
   ("tb1q3sl8k8vysfzehty2jkvgk980a6eqetv5uq66cm",
    "IDdrFMhwIRkBIvN//Zqjqb4dSYbOYBTLJX8mOCKzBQCmGCU1SgSgKKGkyCLL+4RYQAhv1WXZsoH58lOHSyekvhw="
    ),
    #segwit 137 signature
    ("tb1q3sl8k8vysfzehty2jkvgk980a6eqetv5uq66cm",
     "KDdrFMhwIRkBIvN//Zqjqb4dSYbOYBTLJX8mOCKzBQCmGCU1SgSgKKGkyCLL+4RYQAhv1WXZsoH58lOHSyekvhw="
    ),
     #taproot bip322 signature
    ("tb1ppyepzw6hvhqvgx7re5clqlcplqjcxmk3cwd9y62szzexhx98z7aqg0kxt7",
      "AUGx2USoXwH3yoZGm8UWbag4LmIu6JoJBsB3oMVGCUwZbd8XgBEW6H1TzbDlNRZZMvYdwpiC6v/7yizCC3zBG838AQ=="
    ),
      #p2pkh standard signature
    ("n13zS1jhzxe123hALq7S8i6ftECs3EaFBJ",
      "ICng6T6xCtzUy1BPbyfEzMGj2AjegHivNJCu+6uGuIg5P4JMHxwmurCdczBJW2D2fTijJfuXgu7H6YQpf0L5R8c="
    ),
      #nested segwit standard signature
    ("2Mtot6Cz59zCTh5b1cj1qY7hHtHdDeK3aDX",
      "IGmnHXiHeL1akAphqtFF71GG1wkpSYBwX4pnItnVfLeYCQRkKuj6pgViOVqJlKWFB+rmf4PQG3U7w/GJ+SgmZOI="
    ),
      #nested segwit 137 signature
    ("2Mtot6Cz59zCTh5b1cj1qY7hHtHdDeK3aDX",
      "JGmnHXiHeL1akAphqtFF71GG1wkpSYBwX4pnItnVfLeYCQRkKuj6pgViOVqJlKWFB+rmf4PQG3U7w/GJ+SgmZOI="
    )

]

@pytest.mark.parametrize("addr,sig", VECTORS)

def test_bip137(addr, sig):
    msg = f"Proof of Funds\nTimestamp: 2025-06-29T00:00:00Z\nTotal Amount: 1.00000000 BTC\nAddresses:\n- {addr}"
    assert BPF.verify_message_signature(addr, sig, msg) is True

def test_wrong_address_fails():
    # This signature is valid for "tb1q3sl8k8vysfzehty2jkvgk980a6eqetv5uq66cm"
    sig_for_addr1 = "IDdrFMhwIRkBIvN//Zqjqb4dSYbOYBTLJX8mOCKzBQCmGCU1SgSgKKGkyCLL+4RYQAhv1WXZsoH58lOHSyekvhw="
    
    # But we are testing it against the Taproot address
    addr2 = "tb1ppyepzw6hvhqvgx7re5clqlcplqjcxmk3cwd9y62szzexhx98z7aqg0kxt7"
    
    msg = f"Proof of Funds\nTimestamp: 2025-06-29T00:00:00Z\nTotal Amount: 1.00000000 BTC\nAddresses:\n- {addr2}"
    
    # The signature does not match the address, so this MUST be False
    assert BPF.verify_message_signature(addr2, sig_for_addr1, msg) is False

def test_wrong_message_fails():
    # This address and signature are a valid pair for the original message
    addr = "n13zS1jhzxe123hALq7S8i6ftECs3EaFBJ"
    sig = "ICng6T6xCtzUy1BPbyfEzMGj2AjegHivNJCu+6uGuIg5P4JMHxwmurCdczBJW2D2fTijJfuXgu7H6YQpf0L5R8c="
    
    # But we create a slightly different message (changed the timestamp)
    wrong_msg = f"Proof of Funds\nTimestamp: 2025-06-28T00:00:00Z\nTotal Amount: 1.00000000 BTC\nAddresses:\n- {addr}"
    
    # The signature was not created for this specific message, so this MUST be False
    assert BPF.verify_message_signature(addr, sig, wrong_msg) is False

def test_malformed_signature_fails():
    addr = "n13zS1jhzxe123hALq7S8i6ftECs3EaFBJ"
    malformed_sig = "this is not a valid base64 signature"
    msg = f"Proof of Funds\nTimestamp: 2025-06-29T00:00:00Z\nTotal Amount: 1.00000000 BTC\nAddresses:\n- {addr}"

    # The library should handle the error and return False
    assert BPF.verify_message_signature(addr, malformed_sig, msg) is False
