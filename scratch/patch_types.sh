sed -i '' 's/def test_keyword_score():/def test_keyword_score() -> None:/' tests/integration/test_evaluation_baselines.py
sed -i '' 's/def test_mock_corpus_building():/def test_mock_corpus_building() -> None:/' tests/integration/test_evaluation_baselines.py
sed -i '' 's/def test_retrieval_strategies():/def test_retrieval_strategies() -> None:/' tests/integration/test_evaluation_baselines.py
sed -i '' 's/def test_ground_truth_not_injected():/def test_ground_truth_not_injected() -> None:/' tests/integration/test_evaluation_baselines.py

sed -i '' 's/self.corpus = {}/self.corpus: dict[str, ThreatChunk] = {}/' scripts/evaluate.py
sed -i '' 's/retrieval_results = {"keyword": \[\], "vector": \[\], "hybrid": \[\]}/retrieval_results: dict[str, list[list[str]]] = {"keyword": [], "vector": [], "hybrid": []}/' scripts/evaluate.py
