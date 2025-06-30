import hashlib
import requests
import base64
import struct
from datetime import datetime, timezone
from typing import Optional, Union, List
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    import ecdsa
    from ecdsa import VerifyingKey, SECP256k1
    from ecdsa.ellipticcurve import Point
    ECDSA_AVAILABLE = True
    logger.info("✅ ecdsa library loaded - full cryptographic verification available!")
except ImportError as e:
    ECDSA_AVAILABLE = False
    logger.error(f"❌ ecdsa not available: {e}")
    logger.error("Install with: pip install ecdsa")


class BitcoinProofOfFunds:
    """
    Bitcoin Proof of Funds utility class with full cryptographic verification.
    This version includes a correct Bech32/Bech32m implementation for SegWit/Taproot addresses.
    """

    # --- Bech32/Bech32m Implementation (BIP-173, BIP-350) ---

    _BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    _BECH32M_CONST = 0x2bc830a3
    
    @staticmethod
    def _parse_header_byte(h: int):                                                     
        """
        Break the 65-byte message-signature header into its BIP-137 fields.

        Returns (recid, is_compressed, is_segwit, is_taproot)
        """
        flags = h - 27
        recid         =  flags        & 0b11          # 0-3
        is_compressed = (flags >> 2)  & 0b1           # bit 2
        is_segwit     = (flags >> 3)  & 0b1           # bit 3
        is_taproot    = (flags >> 4)  & 0b1           # bit 4
        return recid, bool(is_compressed), bool(is_segwit), bool(is_taproot)                

    @staticmethod
    def _bech32_polymod(values: List[int]) -> int:
        """Internal function that computes the Bech32 checksum."""
        generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for value in values:
            top = chk >> 25
            chk = (chk & 0x1ffffff) << 5 ^ value
            for i in range(5):
                chk ^= generator[i] if ((top >> i) & 1) else 0
        return chk

    @staticmethod
    def _bech32_hrp_expand(hrp: str) -> List[int]:
        """Expand the HRP into values for checksum computation."""
        return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

    @staticmethod
    def _convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> Optional[List[int]]:
        """General power-of-2 base conversion."""
        acc = 0
        bits = 0
        ret = []
        maxv = (1 << tobits) - 1
        max_acc = (1 << (frombits + tobits - 1)) - 1
        for value in data:
            if value < 0 or (value >> frombits):
                return None
            acc = ((acc << frombits) | value) & max_acc
            bits += frombits
            while bits >= tobits:
                bits -= tobits
                ret.append((acc >> bits) & maxv)
        if pad:
            if bits:
                ret.append((acc << (tobits - bits)) & maxv)
        elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
            return None
        return ret

    @classmethod
    def _bech32_encode(cls, hrp: str, witver: int, witprog: bytes, bech32m: bool = False) -> str:
        """
        Encode a SegWit address using a correct Bech32 or Bech32m implementation.
        """
        const = cls._BECH32M_CONST if bech32m else 1
        converted_bits = cls._convertbits(witprog, 8, 5)
        if converted_bits is None:
            return ""
        data = [witver] + converted_bits
        polymod_data = cls._bech32_hrp_expand(hrp) + data
        checksum = cls._bech32_polymod(polymod_data + [0, 0, 0, 0, 0, 0]) ^ const
        
        encoded_data = ''.join([cls._BECH32_CHARSET[d] for d in data])
        encoded_checksum = ''.join([cls._BECH32_CHARSET[(checksum >> (5 * (5 - i))) & 31] for i in range(6)])
        
        return hrp + '1' + encoded_data + encoded_checksum

    # --- Core Verification Logic ---

    @staticmethod
    def verify_message_signature(address: str, signature: str, message: str) -> bool:
        """
        Verify a Bitcoin message signature using full ECDSA cryptographic verification.
        """
        if not ECDSA_AVAILABLE:
            logger.warning("⚠️ ecdsa library not available, falling back to format validation")
            return BitcoinProofOfFunds._verify_signature_fallback(address, signature, message)
        
        if not all([address, signature, message]):
            logger.warning("Missing required parameters for signature verification")
            return False
        
        if not BitcoinProofOfFunds._is_valid_address_format(address):
            logger.warning(f"Invalid address format: {address}")
            return False
        
        try:
            logger.info(f"🔐 Performing full cryptographic verification for {address[:10]}...")
            is_valid = BitcoinProofOfFunds._verify_bitcoin_message_signature(
                address, signature, message
            )
            logger.info(f"🔒 Cryptographic verification result for {address}: {is_valid}")
            return is_valid
        except Exception as e:
            logger.error(f"Cryptographic verification for {address} failed: {e}", exc_info=True)
            return False

    @staticmethod
    def _verify_bitcoin_message_signature(address: str,
                                        signature: str,
                                        message: str) -> bool:
        """Perform full Bitcoin message signature verification."""
        try:
            # 1️⃣  Hash the “Bitcoin Signed Message” payload
            formatted = BitcoinProofOfFunds._format_message_for_signing(message)
            msg_hash  = BitcoinProofOfFunds._double_sha256(formatted)

            # 2️⃣  Decode and sanity-check the compact signature
            try:
                sig_bytes = base64.b64decode(signature)
            except Exception as e:
                logger.warning(f"Invalid base64 signature: {e}")
                return False
            if len(sig_bytes) != 65:
                logger.warning(f"Invalid signature length: {len(sig_bytes)} (expected 65)")
                return False

            # 3️⃣  Split it into header, r, s
            header = sig_bytes[0]
            r = int.from_bytes(sig_bytes[1:33],  'big')
            s = int.from_bytes(sig_bytes[33:65], 'big')

            # 4️⃣  Recover the public key point
            recovered_pubkey = BitcoinProofOfFunds._recover_public_key(
                msg_hash, r, s, header
            )
            if not recovered_pubkey:
                logger.warning("❌ Public-key recovery failed.")
                return False

            # 5️⃣  Build every address that key can map to
            recovered_addresses_all = (
                BitcoinProofOfFunds._pubkey_to_addresses(recovered_pubkey, True)  +
                BitcoinProofOfFunds._pubkey_to_addresses(recovered_pubkey, False)
            )
            recovered_addresses_all = list(dict.fromkeys(recovered_addresses_all))  # dedupe

            # 6️⃣  Check for a match
            if address in recovered_addresses_all:
                logger.info(f"✅ Address match found! Signature for {address} is valid.")
                return True

            logger.warning(
                f"❌ No address match found for {address}. "
                f"Recovered addresses: {recovered_addresses_all}. Signature is invalid."
            )
            return False

        except Exception as e:
            logger.error(f"Bitcoin message verification error: {e}", exc_info=True)
            return False

    @staticmethod
    def _format_message_for_signing(message: str) -> bytes:
        """Format message with Bitcoin's magic prefix."""
        message_bytes = message.encode('utf-8')
        message_length = len(message_bytes)
        prefix = b"\x18Bitcoin Signed Message:\n"
        
        if message_length < 253:
            length_bytes = bytes([message_length])
        elif message_length < 65536:
            length_bytes = b'\xfd' + struct.pack('<H', message_length)
        elif message_length < 4294967296:
            length_bytes = b'\xfe' + struct.pack('<I', message_length)
        else:
            length_bytes = b'\xff' + struct.pack('<Q', message_length)
        
        return prefix + length_bytes + message_bytes

    @staticmethod
    def _double_sha256(data: bytes) -> bytes:
        """Perform double SHA256 hash."""
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

    @staticmethod
    def _recover_public_key(message_hash: bytes, r: int, s: int, recovery_flag: int) -> Optional[Point]:
        """Recovers the public key from an ECDSA signature."""
        if not (27 <= recovery_flag <= 42):
            logger.warning(f"Invalid recovery flag: {recovery_flag}")
            return None

        recid = (recovery_flag - 27) & 3      # 0-3

        
        curve = SECP256k1.curve
        p = curve.p()
        n = SECP256k1.order
        G = SECP256k1.generator
        
        x = r + (recid // 2) * n
        
        alpha = (pow(x, 3, p) + curve.b()) % p
        beta = pow(alpha, (p + 1) // 4, p)
        
        y = beta if (beta % 2 == recid % 2) else p - beta
        R = Point(curve, x, y)
        
        e = int.from_bytes(message_hash, byteorder='big')
        r_inv = pow(r, n - 2, n)
        
        Q = r_inv * (s * R + e * -G)
        
        pk = VerifyingKey.from_public_point(Q, curve=SECP256k1)
        sig_obj = ecdsa.ecdsa.Signature(r, s)
        
        message_hash_as_int = int.from_bytes(message_hash, 'big')
        if pk.pubkey.verifies(message_hash_as_int, sig_obj):
            return Q

        return None

    # --- Address Generation from Public Key ---
    
    @staticmethod
    def _pubkey_to_addresses(pubkey_point: Point, compressed: bool) -> List[str]:
        """
        Generates relevant Bitcoin addresses from a public key point,
        respecting the compressed flag from the signature.
        """
        addresses = []
        try:
            x = pubkey_point.x()
            y = pubkey_point.y()
            
            if compressed:
                # Modern addresses are derived from compressed keys
                compressed_pubkey = (b'\x02' if y % 2 == 0 else b'\x03') + x.to_bytes(32, 'big')
                pubkey_hash_comp = BitcoinProofOfFunds._hash160(compressed_pubkey)
                
                # P2PKH (compressed)
                addresses.append(BitcoinProofOfFunds._hash160_to_p2pkh_address(pubkey_hash_comp))
                # P2WPKH (Native SegWit)
                addresses.append(BitcoinProofOfFunds._hash160_to_p2wpkh_address(pubkey_hash_comp))
                # P2SH-P2WPKH (Wrapped SegWit)
                addresses.append(BitcoinProofOfFunds._hash160_to_p2sh_p2wpkh_address(pubkey_hash_comp))
                # P2TR (Taproot)
                addresses.append(BitcoinProofOfFunds._pubkey_to_p2tr_address(compressed_pubkey))
            else:
                # Legacy uncompressed addresses
                uncompressed_pubkey = b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
                pubkey_hash_uncomp = BitcoinProofOfFunds._hash160(uncompressed_pubkey)
                # P2PKH (uncompressed)
                addresses.append(BitcoinProofOfFunds._hash160_to_p2pkh_address(pubkey_hash_uncomp))
            
            return [addr for addr in addresses if addr]
        except Exception as e:
            logger.error(f"Address generation failed: {e}", exc_info=True)
            return []

    @staticmethod
    def _hash160(data: bytes) -> bytes:
        """Perform HASH160: SHA256 followed by RIPEMD160."""
        sha256_hash = hashlib.sha256(data).digest()
        return hashlib.new('ripemd160', sha256_hash).digest()

    @staticmethod
    def _base58_encode(data: bytes) -> str:
        """Encode bytes to Base58 (Bitcoin style)."""
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        num = int.from_bytes(data, 'big')
        encoded = ''
        while num > 0:
            num, remainder = divmod(num, 58)
            encoded = alphabet[remainder] + encoded
        
        pad = len(data) - len(data.lstrip(b'\0'))
        return '1' * pad + encoded

    @classmethod
    def _hash160_to_p2pkh_address(cls, pubkey_hash: bytes) -> str:
        """Convert HASH160 to P2PKH address (starts with 1)."""
        versioned_payload = b'\x00' + pubkey_hash
        checksum = cls._double_sha256(versioned_payload)[:4]
        return cls._base58_encode(versioned_payload + checksum)

    @classmethod
    def _hash160_to_p2wpkh_address(cls, pubkey_hash: bytes) -> Optional[str]:
        """Convert HASH160 to P2WPKH address (starts with bc1q)."""
        if len(pubkey_hash) != 20: return None
        return cls._bech32_encode('bc', 0, pubkey_hash)

    @classmethod
    def _hash160_to_p2sh_p2wpkh_address(cls, pubkey_hash: bytes) -> Optional[str]:
        """Convert HASH160 to P2SH-P2WPKH address (starts with 3)."""
        if len(pubkey_hash) != 20: return None
        p2wpkh_script = b'\x00\x14' + pubkey_hash
        script_hash = cls._hash160(p2wpkh_script)
        versioned_payload = b'\x05' + script_hash
        checksum = cls._double_sha256(versioned_payload)[:4]
        return cls._base58_encode(versioned_payload + checksum)
    
    @classmethod
    def _pubkey_to_p2tr_address(cls, compressed_pubkey: bytes) -> Optional[str]:
        """Convert compressed public key to P2TR address (starts with bc1p)."""
        if len(compressed_pubkey) != 33: return None
        x_coord = compressed_pubkey[1:33]
        return cls._bech32_encode('bc', 1, x_coord, bech32m=True)

    # --- Other Utility and API Methods ---
    
    @staticmethod
    def _verify_signature_fallback(address: str, signature: str, message: str) -> bool:
        """Fallback verification when ECDSA library is not available"""
        logger.warning("⚠️ Using format validation fallback - install 'ecdsa' for full verification")
        try:
            if not all([address, signature, message]): return False
            if len(base64.b64decode(signature)) != 65: return False
            if not message.startswith("Proof of Funds"): return False
            logger.info("✅ Format validation passed (fallback mode)")
            return True
        except Exception as e:
            logger.error(f"Fallback verification failed: {e}")
            return False

    @staticmethod
    def _is_valid_address_format(address: str) -> bool:
        """Comprehensive Bitcoin address format validation."""
        if not isinstance(address, str) or len(address) < 26: return False
        if address.startswith('1') and 26 <= len(address) <= 35: return True
        if address.startswith('3') and 26 <= len(address) <= 35: return True
        if address.startswith('bc1q') and 42 <= len(address) <= 62: return True
        if address.startswith('bc1p') and 42 <= len(address) <= 66: return True
        if address.startswith(('m', 'n', '2', 'tb1')): return True
        return False

    @staticmethod
    def create_proof_message(
        addresses: list, 
        amount: Union[int, float], 
        proof_name: Optional[str] = None, 
        timestamp: Optional[str] = None
    ) -> str:
        """Create a standardized proof of funds message, optionally including a proof name."""
        if timestamp is None:
            # Use timezone-aware UTC datetime to avoid DeprecationWarning
            timestamp = datetime.now(timezone.utc).isoformat()
        
        amount_str = f"{float(amount):.8f}"
        
        # Start with the purpose of the proof, making it more specific
        message_lines = []
        if proof_name and proof_name.strip():
            message_lines.append(f"Proof of Funds For: {proof_name.strip()}")
        else:
            message_lines.append("Proof of Funds")
            
        message_lines.extend([
            f"Timestamp: {timestamp}",
            f"Total Amount: {amount_str} BTC",
            "Addresses:"
        ] + [f"- {addr}" for addr in addresses])
        
        return "\n".join(message_lines)

    @staticmethod
    def get_address_balance(address: str, timeout: int = 10) -> float:
        """Get real balance for a Bitcoin address using multiple API sources."""
        if not BitcoinProofOfFunds._is_valid_address_format(address):
            logger.warning(f"Invalid address format for balance check: {address}")
            return 0.0
        
        apis = [
            {'name': 'Blockchain.info', 'url': f'https://blockchain.info/q/addressbalance/{address}', 'parser': BitcoinProofOfFunds._parse_blockchain_info_response},
            {'name': 'Blockstream', 'url': f'https://blockstream.info/api/address/{address}', 'parser': BitcoinProofOfFunds._parse_blockstream_response}
        ]
        
        for api in apis:
            try:
                logger.info(f"Fetching balance from {api['name']} for {address[:10]}...")
                response = requests.get(api['url'], timeout=timeout)
                if response.status_code == 200:
                    balance = api['parser'](response)
                    if balance is not None:
                        logger.info(f"Balance retrieved: {balance:.8f} BTC")
                        return balance
                else:
                    logger.warning(f"{api['name']} returned status {response.status_code}")
            except requests.RequestException as e:
                logger.warning(f"{api['name']} request failed: {e}")
            except Exception as e:
                logger.error(f"{api['name']} parsing failed: {e}")
        
        logger.error(f"All APIs failed for address {address[:10]}...")
        return 0.0

    @staticmethod
    def _parse_blockchain_info_response(response) -> Optional[float]:
        try:
            return int(response.text.strip()) / 100_000_000
        except (ValueError, AttributeError):
            return None

    @staticmethod
    def _parse_blockstream_response(response) -> Optional[float]:
        try:
            data = response.json()
            chain_stats = data.get('chain_stats', {})
            return (chain_stats.get('funded_txo_sum', 0) - chain_stats.get('spent_txo_sum', 0)) / 100_000_000
        except (ValueError, KeyError, AttributeError):
            return None
    
    @staticmethod
    def validate_proof_data(addresses: list, signatures: dict) -> dict: # <-- REMOVED message from arguments
        """
        Validate a complete proof submission. Each address object in the list
        is expected to contain its own 'message' key.
        """
        results = {}
        all_valid = True
        warnings = []
        if not ECDSA_AVAILABLE:
            warnings.append("⚠️ Using format validation only - install 'ecdsa' for full cryptographic verification")
        
        for addr_data in addresses:
            address = addr_data.get('address')
            message = addr_data.get('message') # <-- GET message from the address object
            if not address: continue
            
            signature = signatures.get(address, '').strip()
            
            if not signature:
                results[address] = {'valid': False, 'error': 'No signature provided'}
                all_valid = False
                continue
            
            if not message: # <-- ADDED check for message
                results[address] = {'valid': False, 'error': 'No message provided for this address'}
                all_valid = False
                continue

            is_valid = BitcoinProofOfFunds.verify_message_signature(address, signature, message)
            results[address] = {
                'valid': is_valid,
                'balance': addr_data.get('balance', 0),
                'address_type': BitcoinProofOfFunds._get_address_type(address),
                'verification_method': 'cryptographic' if ECDSA_AVAILABLE else 'format_only'
            }
            if not is_valid:
                all_valid = False
                results[address]['error'] = 'Cryptographic signature verification failed'
        
        return {
            'valid': all_valid,
            'results': results,
            'total_addresses': len(addresses),
            'valid_signatures': sum(1 for r in results.values() if r.get('valid')),
            'warnings': warnings,
            'verification_level': 'cryptographic' if ECDSA_AVAILABLE else 'format_only'
        }
    
    @staticmethod
    def _get_address_type(address: str) -> str:
        """Get human-readable address type"""
        if address.startswith('1'): return 'P2PKH (Legacy)'
        if address.startswith('3'): return 'P2SH (Script Hash)'
        if address.startswith('bc1q'): return 'P2WPKH (Native SegWit)'
        if address.startswith('bc1p'): return 'P2TR (Taproot)'
        if address.startswith(('m', 'n', '2', 'tb1')): return 'Testnet'
        return 'Unknown'

if __name__ == "__main__":
    # Legacy
    addr1     = "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
    message1  = "Proof of Funds\nTimestamp: 2025-06-28T20:00:00Z\nTotal Amount: 0.00100000 BTC\nAddresses:\n- " + addr1
    sig1      = "IFNGvXfgncT6tcNvFblj1miEE1tS7HmuRWXnpxj7BHvKtMNlG+pE9gpo5SYWIf2H6GoLxRhGDuvokeuQi+ZXrak="

    # bc1 SegWit v0
    addr2     = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
    message2  = message1.replace(addr1, addr2)
    sig2      = "H7CulS7v9QyMeC0qaVOzHxgTnLdJtm0ZgFWL1ZMrJmgIpIHbkqTYrBXuV1sQjr0DEiM0+uYRcBNybVw3+kCGeIA="

    for a, s, m in [(addr1, sig1, message1), (addr2, sig2, message2)]:
        print(a[:12], BitcoinProofOfFunds.verify_message_signature(a, s, m))