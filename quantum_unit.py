import hashlib
import json
import logging
import math
import struct
import time
from typing import Any, Dict, List

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("QUANTUM_CU_PROTOCOL_v1.0")


class QuantumStateEvaluator:
    """
    Evaluates density matrix projections over 2-qubit statevectors (4-dim Hilbert space)
    using deterministic vector normalizations and quantum state fidelity metrics.
    """

    def __init__(self, dim: int = 4):
        self.dim = dim
        # Baseline state: Equal superposition |psi> = 1/sqrt(dim) * [1, 1, 1, 1]
        norm_factor = 1.0 / math.sqrt(dim)
        self.state_vector: List[float] = [norm_factor] * dim

    def apply_unitary_projection(self, payload_vector: List[float]) -> List[float]:
        """
        Applies a deterministic state transformation blending the current state vector
        with incoming phase data, maintaining unit norm (Sum of probabilities = 1.0).
        """
        # Truncate or zero-pad to match Hilbert space dimension
        padded = (payload_vector + [0.0] * self.dim)[: self.dim]
        
        # Calculate Euclidean norm for incoming vector
        p_norm = math.sqrt(sum(x * x for x in padded)) or 1.0
        normalized_payload = [x / p_norm for x in padded]

        # Inner product (Overlap fidelity)
        overlap = sum(s * p for s, p in zip(self.state_vector, normalized_payload))
        fidelity = max(0.0, min(1.0, overlap ** 2))

        # Convex projection based on state overlap fidelity
        updated = [
            (s * fidelity) + (p * (1.0 - fidelity))
            for s, p in zip(self.state_vector, normalized_payload)
        ]

        # Renormalize state vector
        u_norm = math.sqrt(sum(x * x for x in updated)) or 1.0
        self.state_vector = [x / u_norm for x in updated]
        return self.state_vector


class QuantumResistantComputeUnit:
    """
    Decentralized Compute Unit execution runner enforcing binary-packed 
    post-quantum hashing over snapshot states.
    """

    def __init__(self, process_id: str):
        self.process_id = process_id
        self.evaluator = QuantumStateEvaluator(dim=4)
        self.history_hashes: List[str] = []

    def compute_pq_canonical_hash(self, nonce: int, state: List[float]) -> str:
        """
        Packs floating point state vectors into IEEE 754 big-endian byte sequences 
        and computes SHA-256 state commitments resistant to architectural drift.
        """
        buffer = bytearray()
        buffer.extend(self.process_id.encode("utf-8"))
        buffer.extend(struct.pack(">Q", nonce))  # Unsigned 64-bit int

        for amplitude in state:
            # Rounding to 8 decimal places enforces strict IEEE-754 equivalence
            buffer.extend(struct.pack(">d", round(amplitude, 8)))

        return hashlib.sha256(buffer).hexdigest()

    def process_quantum_message(self, message_id: str, nonce: int, state_payload: List[float]) -> str:
        """
        Ingests a state measurement vector, updates internal Hilbert projection, 
        and records a deterministic state snapshot.
        """
        new_state = self.evaluator.apply_unitary_projection(state_payload)
        state_hash = self.compute_pq_canonical_hash(nonce, new_state)
        self.history_hashes.append(state_hash)

        logger.info(f"Msg ID: {message_id} | Nonce: {nonce} | State Hash: {state_hash[:16]}...")
        return state_hash

    def get_snapshot(self) -> Dict[str, Any]:
        return {
            "process_id": self.process_id,
            "quantum_state_vector": [round(x, 6) for x in self.evaluator.state_vector],
            "latest_state_hash": self.history_hashes[-1] if self.history_hashes else None
        }


if __name__ == "__main__":
    q_cu = QuantumResistantComputeUnit(process_id="q_process_node_01")

    # Quantum state measurement inputs (Simulated Bell-state telemetry)
    telemetry_stream = [
        {"id": "q_msg_101", "nonce": 1, "payload": [0.7071, 0.0, 0.0, 0.7071]},
        {"id": "q_msg_102", "nonce": 2, "payload": [0.5, 0.5, 0.5, 0.5]},
        {"id": "q_msg_103", "nonce": 3, "payload": [0.0, 0.7071, 0.7071, 0.0]},
    ]

    print("\n--- Processing Quantum State Telemetry ---")
    for item in telemetry_stream:
        q_cu.process_quantum_message(item["id"], item["nonce"], item["payload"])

    print("\n--- Final Quantum Compute Unit State Projection ---")
    print(json.dumps(q_cu.get_snapshot(), indent=2))
