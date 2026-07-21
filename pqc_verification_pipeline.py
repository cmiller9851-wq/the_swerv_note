import os
from typing import Tuple

# Standardized FIPS 203 & FIPS 204 bindings (cryptography >= 48.0)
from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# -----------------------------------------------------------------------------
# Module Constants & Wire Format Specification
# -----------------------------------------------------------------------------
FRAME_MAGIC = b"CRA1"                  # 4-byte Magic Header + Version Prefix
MLKEM768_CIPHERTEXT_SIZE = 1088        # Fixed FIPS 203 ML-KEM-768 Ciphertext size
AES_GCM_NONCE_SIZE = 12                # Standard 96-bit AES-GCM Nonce
LENGTH_PREFIX_SIZE = 4                 # 32-bit Big-Endian Unsigned Integer
MLDSA65_NOMINAL_SIG_SIZE = 3309        # Standard FIPS 204 ML-DSA-65 Signature size

# Minimum valid frame size calculation:
# MAGIC (4) + KEM_CT (1088) + NONCE (12) + AES_TAG (16) + SIG_LEN (4) + ML_DSA_SIG (3309) = 4433 bytes
MIN_FRAME_SIZE = (
    len(FRAME_MAGIC)
    + MLKEM768_CIPHERTEXT_SIZE
    + AES_GCM_NONCE_SIZE
    + 16  # AES-GCM authentication tag minimum payload size
    + LENGTH_PREFIX_SIZE
    + MLDSA65_NOMINAL_SIG_SIZE
)


class PQCVerificationPipeline:
    """
    Sovereign single-pass post-quantum authenticated encryption and verification pipeline.

    Wire Layout:
    +--------------+------------------+---------------+----------------------+------------------+-------------------+
    | MAGIC (4B)   | KEM CT (1088B)   | NONCE (12B)   | ENCRYPTED PAYLOAD    | SIG_LEN (4B)     | ML-DSA SIG (Var)  |
    | "CRA1"       | ML-KEM-768       | AES-256-GCM   | AES-256-GCM + Tag    | uint32_be        | FIPS 204          |
    +--------------+------------------+---------------+----------------------+------------------+-------------------+
    """

    @staticmethod
    def generate_recipient_kem_keypair() -> Tuple[mlkem.MLKEM768PrivateKey, mlkem.MLKEM768PublicKey]:
        """Generates an ML-KEM-768 key pair for the receiving Compute Unit."""
        private_key = mlkem.MLKEM768PrivateKey.generate()
        return private_key, private_key.public_key()

    @staticmethod
    def generate_sender_dsa_keypair() -> Tuple[mldsa.MLDSA65PrivateKey, mldsa.MLDSA65PublicKey]:
        """Generates an ML-DSA-65 key pair for the signing identity."""
        private_key = mldsa.MLDSA65PrivateKey.generate()
        return private_key, private_key.public_key()

    @classmethod
    def assemble_frame_payload(
        cls,
        payload_data: bytes,
        recipient_kem_public_key: mlkem.MLKEM768PublicKey,
        sender_dsa_private_key: mldsa.MLDSA65PrivateKey,
    ) -> bytes:
        """
        Constructs a hardened, single-pass serialized PQC frame payload.
        """
        if not isinstance(payload_data, (bytes, bytearray)) or len(payload_data) == 0:
            raise ValueError("Payload data must be non-empty bytes.")

        # 1. Encapsulate symmetric secret using recipient's ML-KEM-768 Public Key
        ciphertext_kem, shared_secret = recipient_kem_public_key.encapsulate()

        # 2. Encrypt payload via AES-256-GCM
        aesgcm = AESGCM(shared_secret)
        nonce = os.urandom(AES_GCM_NONCE_SIZE)
        encrypted_payload = aesgcm.encrypt(nonce, payload_data, associated_data=None)

        # 3. Construct authenticated container (Header || KEM Ciphertext || Nonce || Encrypted Payload)
        container_to_sign = FRAME_MAGIC + ciphertext_kem + nonce + encrypted_payload

        # 4. Sign container using sender's ML-DSA-65 Private Key
        signature = sender_dsa_private_key.sign(container_to_sign)

        # 5. Pack dynamic signature length as 32-bit big-endian integer
        sig_len_bytes = len(signature).to_bytes(LENGTH_PREFIX_SIZE, byteorder="big")

        # Assemble full wire frame
        return container_to_sign + sig_len_bytes + signature

    @classmethod
    def process_and_verify_frame(
        cls,
        frame_bytes: bytes,
        recipient_kem_private_key: mlkem.MLKEM768PrivateKey,
        sender_dsa_public_key: mldsa.MLDSA65PublicKey,
    ) -> bytes:
        """
        Executes fail-fast signature attestation, decapsulation, and AEAD decryption.
        
        Raises:
            ValueError: On invalid header, insufficient payload size, signature verification fail,
                        or AEAD decryption authentication failure.
        """
        if len(frame_bytes) < MIN_FRAME_SIZE:
            raise ValueError(
                f"Frame size invalid. Received {len(frame_bytes)} bytes, expected minimum {MIN_FRAME_SIZE} bytes."
            )

        # STEP 1: Header Validation
        magic = frame_bytes[: len(FRAME_MAGIC)]
        if magic != FRAME_MAGIC:
            raise ValueError(f"Invalid frame header magic prefix. Expected {FRAME_MAGIC!r}, got {magic!r}.")

        # STEP 2: Extract Dynamic Signature Length & Slices
        sig_len_bytes = frame_bytes[-(LENGTH_PREFIX_SIZE + MLDSA65_NOMINAL_SIG_SIZE) : -MLDSA65_NOMINAL_SIG_SIZE]
        
        # Read true length from the 4-byte prefix
        sig_len = int.from_bytes(frame_bytes[-(MLDSA65_NOMINAL_SIG_SIZE + LENGTH_PREFIX_SIZE) : -MLDSA65_NOMINAL_SIG_SIZE], byteorder="big")
        
        # Slice bounds using explicit sig_len
        signature = frame_bytes[-sig_len:]
        container_bytes = frame_bytes[:- (LENGTH_PREFIX_SIZE + sig_len)]

        if len(signature) != sig_len:
            raise ValueError("Parsed signature boundary length mismatch.")

        # STEP 3: Fail-Fast Identity & Attestation Verification (ML-DSA-65)
        # Rejects unauthorized or corrupted frames before performing compute-heavy KEM operations
        sender_dsa_public_key.verify(signature, container_bytes)

        # STEP 4: Unpack Container Segments
        offset = len(FRAME_MAGIC)
        ciphertext_kem = container_bytes[offset : offset + MLKEM768_CIPHERTEXT_SIZE]
        offset += MLKEM768_CIPHERTEXT_SIZE

        nonce = container_bytes[offset : offset + AES_GCM_NONCE_SIZE]
        offset += AES_GCM_NONCE_SIZE

        encrypted_payload = container_bytes[offset:]

        # STEP 5: Decapsulate Shared Secret (ML-KEM-768)
        shared_secret = recipient_kem_private_key.decapsulate(ciphertext_kem)

        # STEP 6: Authenticated Payload Decryption (AES-256-GCM)
        aesgcm = AESGCM(shared_secret)
        decrypted_payload = aesgcm.decrypt(nonce, encrypted_payload, associated_data=None)

        return decrypted_payload


# -----------------------------------------------------------------------------
# Unit Verification & Roundtrip Execution
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    import hashlib

    print("===================================================================")
    print(" Sovereign PQC Verification Pipeline — CRA Protocol v2.1-PQC")
    print("===================================================================")

    # 1. Initialize System Keys
    pipeline = PQCVerificationPipeline()
    recipient_priv_kem, recipient_pub_kem = pipeline.generate_recipient_kem_keypair()
    sender_priv_dsa, sender_pub_dsa = pipeline.generate_sender_dsa_keypair()

    # 2. Formulate State Log Payload
    state_log = (
        b'{"protocol": "CRA_PROTOCOL_v2.1", "state_root": "0x4f12...e9a1", '
        b'"floating_point_mode": "100_percent_clean", "step": 8501}'
    )
    
    print(f"[+] Input State Log Size: {len(state_log)} bytes")
    print(f"[+] SHA-256 State Hash:  {hashlib.sha256(state_log).hexdigest()}")

    # 3. Assemble Frame
    frame = pipeline.assemble_frame_payload(
        payload_data=state_log,
        recipient_kem_public_key=recipient_pub_kem,
        sender_dsa_private_key=sender_priv_dsa,
    )

    frame_hash = hashlib.sha256(frame).hexdigest()
    print(f"[+] Assembled PQC Frame Size: {len(frame)} bytes")
    print(f"[+] Frame SHA-256 Digest:     {frame_hash}")

    # 4. Process and Verify Frame
    try:
        verified_data = pipeline.process_and_verify_frame(
            frame_bytes=frame,
            recipient_kem_private_key=recipient_priv_kem,
            sender_dsa_public_key=sender_pub_dsa,
        )
        assert verified_data == state_log, "Integrity Check Failed: Unpacked data mismatch."
        print("\n[✓] VERIFICATION SUCCESSFUL")
        print(f"[✓] Unpacked State Log: {verified_data.decode('utf-8')}")
    except Exception as err:
        print(f"\n[✗] VERIFICATION FAILED: {err}")
        raise err