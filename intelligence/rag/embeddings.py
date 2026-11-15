"""
SentinelAI - Stage 09: Vector Embedding Engine
==============================================
Encodes threat intelligence text chunks and real-time security queries into
dense semantic vector representations using state-of-the-art transformer embeddings.
"""

from typing import List, Union, Optional
import os
os.environ["HF_HUB_OFFLINE"] = "1"
os.environ["TRANSFORMERS_OFFLINE"] = "1"
import numpy as np


class SentinelEmbeddingEngine:
    """
    High-performance vector embedding wrapper optimized for cybersecurity
    threat intelligence texts and SOC investigation queries.
    """
    DEFAULT_MODEL = "all-MiniLM-L6-v2"
    # Alternative higher-capacity model: "BAAI/bge-small-en-v1.5"

    def __init__(self, model_name: Optional[str] = None, device: Optional[str] = None):
        self.model_name = model_name or self.DEFAULT_MODEL
        self.device = device
        self._model = None
        self._dimension = 384  # Standard dimension for MiniLM and BGE-small

    def _load_model(self):
        """Lazy loader for SentenceTransformer model."""
        if self._model is None:
            try:
                from sentence_transformers import SentenceTransformer
                import torch

                if self.device is None:
                    self.device = "cuda" if torch.cuda.is_available() else "cpu"

                print(f"[*] Loading SentinelEmbeddingEngine with '{self.model_name}' on {self.device.upper()}...", flush=True)
                try:
                    self._model = SentenceTransformer(self.model_name, device=self.device, local_files_only=True)
                except Exception:
                    self._model = SentenceTransformer(self.model_name, device=self.device)

                if hasattr(self._model, "get_embedding_dimension"):
                    self._dimension = self._model.get_embedding_dimension()
                else:
                    self._dimension = self._model.get_sentence_embedding_dimension()
                print(f"[+] Embedding model online (Dimension: {self._dimension}D).", flush=True)
            except ImportError as e:
                raise ImportError(
                    "sentence-transformers is not installed. Run: pip install sentence-transformers"
                ) from e

    @property
    def dimension(self) -> int:
        """Returns the embedding vector dimensionality."""
        return self._dimension

    def encode_text(self, text: str, normalize: bool = True) -> List[float]:
        """
        Embeds a single query or text string into a normalized dense vector.
        """
        self._load_model()
        embedding = self._model.encode(
            text,
            convert_to_numpy=True,
            normalize_embeddings=normalize,
            show_progress_bar=False
        )
        return embedding.tolist()

    def encode_batch(
        self,
        texts: List[str],
        batch_size: int = 64,
        normalize: bool = True,
        show_progress_bar: bool = True
    ) -> List[List[float]]:
        """
        Embeds a batch of threat intelligence texts efficiently.
        """
        self._load_model()
        embeddings = self._model.encode(
            texts,
            batch_size=batch_size,
            convert_to_numpy=True,
            normalize_embeddings=normalize,
            show_progress_bar=show_progress_bar
        )
        return embeddings.tolist()

    def similarity(self, vec1: Union[List[float], np.ndarray], vec2: Union[List[float], np.ndarray]) -> float:
        """
        Computes cosine similarity between two normalized embedding vectors.
        """
        a = np.asarray(vec1)
        b = np.asarray(vec2)
        norm_a = np.linalg.norm(a)
        norm_b = np.linalg.norm(b)
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return float(np.dot(a, b) / (norm_a * norm_b))


# Singleton instance accessor
_embedding_instance: Optional[SentinelEmbeddingEngine] = None

def get_embedding_engine(model_name: Optional[str] = None) -> SentinelEmbeddingEngine:
    global _embedding_instance
    if _embedding_instance is None or (model_name and _embedding_instance.model_name != model_name):
        _embedding_instance = SentinelEmbeddingEngine(model_name=model_name)
    return _embedding_instance


if __name__ == "__main__":
    engine = get_embedding_engine()
    test_queries = [
        "Adversary using SMB for lateral movement and remote code execution",
        "SQL injection exploit in web application login form",
        "DDoS volumetric UDP flood overwhelming network bandwidth"
    ]
    print(f"Testing embedding engine on {len(test_queries)} sample queries...")
    vectors = engine.encode_batch(test_queries, show_progress_bar=False)
    for q, v in zip(test_queries, vectors):
        print(f"  • Query: '{q[:45]}...' -> Vector Length: {len(v)} | First 3 dims: {[round(x, 4) for x in v[:3]]}")
    
    sim = engine.similarity(vectors[0], vectors[1])
    print(f"\nCosine Similarity between Query 1 (SMB/Infiltration) and Query 2 (SQLi/Web): {sim:.4f}")

