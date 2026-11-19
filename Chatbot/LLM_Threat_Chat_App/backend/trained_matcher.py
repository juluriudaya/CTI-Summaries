"""CTI Trained Matcher & Dual-Tier Vector Classifier

Trained on:
1. All 18 Curriculum Labs (Labs 1–18, plus 7.1 and 7.2)
2. All 57 Viva / Exam Common Questions
3. All 14 CTI Threat Entities across Windows, Linux, macOS, Android, and iOS
4. Threat Lifecycle Definitions & MITRE ATT&CK concepts
5. Conversational & Autonomous Mitigation Intents

Architecture:
- Character N-Gram TF-IDF (analyzer='char_wb', ngram_range=(2, 5)): Immune to typos, abbreviations, and informal phrasing.
- Word N-Gram TF-IDF (analyzer='word', ngram_range=(1, 3)): Captures exact multi-word technical terminology.
- Fast sub-millisecond inference using cosine distance over pre-fit matrices.
"""

import os
import re
import joblib
import numpy as np
from typing import List, Dict, Any, Optional
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import linear_kernel

MODEL_SAVE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "trained_model_weights.joblib")

class CTITrainedMatcher:
    def __init__(self, model_path: str = MODEL_SAVE_PATH):
        self.model_path = model_path
        self.char_vec: Optional[TfidfVectorizer] = None
        self.word_vec: Optional[TfidfVectorizer] = None
        self.char_matrix = None
        self.word_matrix = None
        self.targets: List[Dict[str, Any]] = []
        self.query_to_target_idx: List[int] = []
        self.training_queries: List[str] = []
        self.is_trained = False
        
        if os.path.exists(self.model_path):
            self.load()

    def train(self, dataset: List[Dict[str, Any]]):
        """Train character and word n-gram models on the unified dataset."""
        self.targets = []
        self.training_queries = []
        self.query_to_target_idx = []

        for target_idx, entry in enumerate(dataset):
            self.targets.append(entry)
            queries = entry.get("queries", [])
            # Also include title, concept, and keywords as query targets
            all_q = list(queries)
            if entry.get("title"):
                all_q.append(entry["title"])
            if entry.get("concept"):
                all_q.append(entry["concept"])
            if entry.get("lab_id"):
                all_q.append(entry["lab_id"])
                all_q.append(entry["lab_id"].lower())
                all_q.append(entry["lab_id"].replace("Lab ", "lab"))
                all_q.append(entry["lab_id"].replace("Lab ", "experiment "))

            for q in set(all_q):
                if q and q.strip():
                    self.training_queries.append(q.strip().lower())
                    self.query_to_target_idx.append(target_idx)

        # 1. Fit Character N-Gram Vectorizer (2-5 chars) - handles typos, word breaks
        self.char_vec = TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(2, 5),
            sublinear_tf=True,
            min_df=1
        )
        self.char_matrix = self.char_vec.fit_transform(self.training_queries)

        # 2. Fit Word N-Gram Vectorizer (1-3 words) - handles technical phrases
        self.word_vec = TfidfVectorizer(
            analyzer="word",
            ngram_range=(1, 3),
            sublinear_tf=True,
            min_df=1
        )
        self.word_matrix = self.word_vec.fit_transform(self.training_queries)
        self.is_trained = True

    def save(self, path: Optional[str] = None):
        """Serialize trained model weights to disk."""
        target_path = path or self.model_path
        payload = {
            "char_vec": self.char_vec,
            "word_vec": self.word_vec,
            "char_matrix": self.char_matrix,
            "word_matrix": self.word_matrix,
            "targets": self.targets,
            "query_to_target_idx": self.query_to_target_idx,
            "training_queries": self.training_queries
        }
        joblib.dump(payload, target_path, compress=3)

    def load(self, path: Optional[str] = None):
        """Load trained weights from disk."""
        target_path = path or self.model_path
        if not os.path.exists(target_path):
            return False
        payload = joblib.load(target_path)
        self.char_vec = payload["char_vec"]
        self.word_vec = payload["word_vec"]
        self.char_matrix = payload["char_matrix"]
        self.word_matrix = payload["word_matrix"]
        self.targets = payload["targets"]
        self.query_to_target_idx = payload["query_to_target_idx"]
        self.training_queries = payload.get("training_queries", [])
        self.is_trained = True
        return True

    def predict(
        self,
        query: str,
        top_k: int = 3,
        platform: Optional[str] = None,
        stage: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Predict best matching targets with confidence scores."""
        if not self.is_trained or not self.char_vec or not self.word_vec:
            return []

        q_clean = query.strip().lower()
        if not q_clean:
            return []

        # Transform query using both vectorizers
        q_char_vec = self.char_vec.transform([q_clean])
        q_word_vec = self.word_vec.transform([q_clean])

        # Cosine similarity over character and word spaces
        char_sims = linear_kernel(q_char_vec, self.char_matrix).ravel()
        word_sims = linear_kernel(q_word_vec, self.word_matrix).ravel()

        # Hybrid fusion score (char handles typos/substrings, word handles exact phrases)
        hybrid_scores = 0.55 * char_sims + 0.45 * word_sims

        # Detect lab number query boost
        lab_m = re.search(r"\b(?:lab|exp|experiment)\s*(1[0-8]|[1-9](\.[1-2])?)\b", q_clean)
        target_lab_id = f"Lab {lab_m.group(1)}" if lab_m else None

        # Filter and rank distinct targets
        target_best_scores: Dict[int, float] = {}
        for q_idx, score in enumerate(hybrid_scores):
            t_idx = self.query_to_target_idx[q_idx]
            target = self.targets[t_idx]

            # Boost exact lab matches
            if target_lab_id and target.get("lab_id") and target["lab_id"].lower() == target_lab_id.lower():
                score += 0.50

            # Boost platform match if specified
            if platform and platform.lower() not in ["all", "all platforms"]:
                if target.get("platform", "").lower() == platform.lower():
                    score += 0.15

            # Boost stage match if specified
            if stage and stage.lower() not in ["all", "all stages"]:
                if target.get("stage", "").lower() == stage.lower():
                    score += 0.15

            if t_idx not in target_best_scores or score > target_best_scores[t_idx]:
                target_best_scores[t_idx] = float(score)

        sorted_targets = sorted(target_best_scores.items(), key=lambda x: x[1], reverse=True)
        results = []
        for t_idx, score in sorted_targets[:top_k]:
            entry = dict(self.targets[t_idx])
            entry["score"] = round(score, 4)
            results.append(entry)

        return results


# Global singleton instance
_trained_matcher_instance = None

def get_trained_matcher() -> CTITrainedMatcher:
    global _trained_matcher_instance
    if _trained_matcher_instance is None:
        _trained_matcher_instance = CTITrainedMatcher()
    return _trained_matcher_instance
