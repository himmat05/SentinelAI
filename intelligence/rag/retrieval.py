"""
SentinelAI - Stage 09: Threat Intelligence Vector Store & Retrieval Engine
==========================================================================
Manages persistent ChromaDB indexing, semantic similarity retrieval, and
metadata-filtered querying across MITRE ATT&CK, CISA KEV, NVD, and OWASP.
"""

from typing import List, Dict, Any, Optional
from pathlib import Path
import json
import os
import chromadb
from chromadb.config import Settings

from intelligence.rag.embeddings import get_embedding_engine, SentinelEmbeddingEngine
from intelligence.rag.ingestion import ThreatIntelChunk


class ThreatIntelRetriever:
    """
    Vector search and hybrid retrieval engine connecting ChromaDB vector store
    with SentinelAI's autonomous SOC investigation workflow.
    """
    COLLECTION_NAME = "sentinel_threat_intel"

    def __init__(
        self,
        persist_dir: Optional[Path] = None,
        embedding_engine: Optional[SentinelEmbeddingEngine] = None
    ):
        if persist_dir is None:
            project_root = Path(__file__).resolve().parent.parent.parent
            self.persist_dir = project_root / "intelligence" / "data" / "processed" / "chroma_db"
        else:
            self.persist_dir = Path(persist_dir)

        self.persist_dir.mkdir(parents=True, exist_ok=True)
        self.embedding_engine = embedding_engine or get_embedding_engine()

        # Initialize persistent Chroma client
        self.client = chromadb.PersistentClient(path=str(self.persist_dir))
        self.collection = self.client.get_or_create_collection(
            name=self.COLLECTION_NAME,
            metadata={"description": "SentinelAI Unified Threat Intelligence Vector Store (MITRE, CISA, NVD, OWASP)"}
        )

    def reset_collection(self):
        """Resets and recreates the ChromaDB collection to ensure a clean index."""
        try:
            self.client.delete_collection(self.COLLECTION_NAME)
        except Exception:
            pass
        self.collection = self.client.create_collection(
            name=self.COLLECTION_NAME,
            metadata={"description": "SentinelAI Unified Threat Intelligence Vector Store (MITRE, CISA, NVD, OWASP)"}
        )

    def count(self) -> int:
        """Returns total indexed vector documents in the collection."""
        return self.collection.count()

    def build_index(self, chunks_json_path: Optional[Path] = None, batch_size: int = 128) -> int:
        """
        Loads pre-processed chunks JSON, computes embeddings, and indexes them into ChromaDB.
        """
        if chunks_json_path is None:
            project_root = Path(__file__).resolve().parent.parent.parent
            chunks_json_path = project_root / "intelligence" / "data" / "processed" / "threat_intel_chunks.json"

        chunks_path = Path(chunks_json_path)
        if not chunks_path.exists():
            raise FileNotFoundError(f"Chunks file not found: {chunks_path}. Run ingestion.py first.")

        print(f"[*] Loading threat intel chunks from {chunks_path}...", flush=True)
        with open(chunks_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        total_chunks = len(raw_data)
        print(f"[+] Loaded {total_chunks:,} chunks. Preparing ChromaDB vectors...", flush=True)

        # Batch indexing
        for i in range(0, total_chunks, batch_size):
            batch = raw_data[i:i + batch_size]

            ids = [item["chunk_id"] for item in batch]
            documents = [item["text"] for item in batch]
            
            # Metadata flattening (ChromaDB requires primitives: str, int, float, bool)
            metadatas = []
            for item in batch:
                meta = {
                    "source": item.get("source", ""),
                    "category": item.get("category", ""),
                    "identifier": item.get("identifier", ""),
                    "title": item.get("title", ""),
                    "severity": item.get("severity", "MEDIUM")
                }
                # Include selected extra attributes
                extra = item.get("metadata", {})
                if "tactics" in extra and isinstance(extra["tactics"], list):
                    meta["tactics"] = ", ".join(extra["tactics"])
                if "ransomware_use" in extra:
                    meta["ransomware_use"] = bool(extra["ransomware_use"])
                if "cvss_score" in extra and extra["cvss_score"] is not None:
                    meta["cvss_score"] = float(extra["cvss_score"])
                if "section_type" in extra:
                    meta["section_type"] = str(extra["section_type"])

                metadatas.append(meta)

            # Compute embeddings
            embeddings = self.embedding_engine.encode_batch(documents, batch_size=batch_size, show_progress_bar=False)

            # Upsert into ChromaDB
            self.collection.upsert(
                ids=ids,
                documents=documents,
                embeddings=embeddings,
                metadatas=metadatas
            )
            print(f"    Indexed {min(i + batch_size, total_chunks):,}/{total_chunks:,} vectors...", flush=True)

        indexed_count = self.collection.count()
        print(f"[✓] ChromaDB indexing complete! Collection now holds {indexed_count:,} indexed vectors.", flush=True)
        return indexed_count

    def search(
        self,
        query: str,
        n_results: int = 5,
        category: Optional[str] = None,
        source: Optional[str] = None,
        severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Semantic similarity search across the threat intelligence base with optional metadata filtering.
        """
        # Formulate query embedding
        query_vector = self.embedding_engine.encode_text(query)

        # Build metadata filter where clause
        where_conditions = []
        if category:
            where_conditions.append({"category": category})
        if source:
            where_conditions.append({"source": source})
        if severity:
            where_conditions.append({"severity": severity})

        where_clause = None
        if len(where_conditions) == 1:
            where_clause = where_conditions[0]
        elif len(where_conditions) > 1:
            where_clause = {"$and": where_conditions}

        # Query ChromaDB
        results = self.collection.query(
            query_embeddings=[query_vector],
            n_results=n_results,
            where=where_clause
        )

        output: List[Dict[str, Any]] = []
        if not results or not results["ids"] or not results["ids"][0]:
            return output

        for i in range(len(results["ids"][0])):
            doc_id = results["ids"][0][i]
            doc_text = results["documents"][0][i] if results["documents"] else ""
            meta = results["metadatas"][0][i] if results["metadatas"] else {}
            distance = results["distances"][0][i] if results.get("distances") else 0.0

            # Convert distance to similarity score
            score = 1.0 - (distance / 2.0)

            output.append({
                "chunk_id": doc_id,
                "score": round(score, 4),
                "title": meta.get("title", ""),
                "source": meta.get("source", ""),
                "category": meta.get("category", ""),
                "identifier": meta.get("identifier", ""),
                "severity": meta.get("severity", ""),
                "text": doc_text,
                "metadata": meta
            })

        return output

    def get_mitigations_for_alert(self, attack_family: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """
        Specialized RAG query for SOC incident response:
        Retrieves authoritative defensive playbooks & mitigations for a detected attack family.
        """
        query = f"Defensive mitigations, prevention guidelines, and remediation playbooks for {attack_family} attacks"
        results = self.search(query, n_results=top_k * 2)

        # Prioritize mitigation playbooks and course-of-action chunks
        mitigations = []
        for r in results:
            text_lower = r["text"].lower()
            if any(term in text_lower for term in ["mitigation", "how to prevent", "remediation", "action", "defense"]):
                mitigations.append(r)
            if len(mitigations) >= top_k:
                break

        # Fallback to general results if no explicit mitigation keyword matched
        if not mitigations:
            mitigations = results[:top_k]

        return mitigations


if __name__ == "__main__":
    retriever = ThreatIntelRetriever()
    current_count = retriever.count()
    print(f"Current ChromaDB collection vectors: {current_count:,}")

    if current_count < 3774:
        print("[*] Collection incomplete or empty. Re-building vector index from threat_intel_chunks.json...")
        retriever.reset_collection()
        retriever.build_index()

    # Test Query
    print("\n" + "=" * 70)
    print("  TEST 1: SEMANTIC SEARCH (SQL Injection)")
    print("=" * 70)
    query = "Adversary exploiting SQL injection vulnerability on web login portal"
    hits = retriever.search(query, n_results=3)
    for idx, hit in enumerate(hits, 1):
        print(f"\n[Hit {idx}] Score: {hit['score']} | {hit['source'].upper()} | {hit['identifier']}: {hit['title']}")
        print("  Snippet:", hit['text'][:200].replace('\n', ' ') + "...")

    print("\n" + "=" * 70)
    print("  TEST 2: AUTONOMOUS MITIGATION RETRIEVAL FOR ML ALERT ('Infiltration')")
    print("=" * 70)
    mit_hits = retriever.get_mitigations_for_alert("Infiltration", top_k=2)
    for idx, hit in enumerate(mit_hits, 1):
        print(f"\n[Mitigation {idx}] {hit['identifier']}: {hit['title']} (Source: {hit['source']})")
        print("  Text:\n  " + hit['text'][:250].replace('\n', '\n  ') + "...")

