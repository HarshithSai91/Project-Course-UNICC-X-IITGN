from scripts.evaluate import MockRetrievalCorpus, _keyword_score, _vector_cosine_score


def test_keyword_score() -> None:
    query = "attacker used CVE-2024-1234"
    text1 = "attacker used CVE-2024-1234"
    text2 = "routine system logs"
    assert abs(_keyword_score(query, text1) - 1.0) < 0.001
    assert _keyword_score(query, text2) == 0.0

def test_vector_score() -> None:
    query = "malware attack"
    text1 = "malware attack on system"
    text2 = "system update routine"
    
    # Should independently compute semantic scores without any ground-truth mapping
    score1 = _vector_cosine_score(query, text1)
    score2 = _vector_cosine_score(query, text2)
    
    assert score1 > 0.0
    assert score2 == 0.0 # No shared 3-grams
    
def test_mock_corpus_building() -> None:
    dataset = [
        {
            "query": "q1",
            "candidates": [
                {"chunk_id": "c1", "text": "foo"},
                {"chunk_id": "c2", "text": "bar"}
            ]
        },
        {
            "query": "q2",
            "candidates": [
                {"chunk_id": "c2", "text": "bar"},
                {"chunk_id": "c3", "text": "baz"}
            ]
        }
    ]
    
    corpus = MockRetrievalCorpus(dataset)
    assert len(corpus.corpus) == 3
    assert "c1" in corpus.corpus
    assert "c2" in corpus.corpus
    assert "c3" in corpus.corpus
    
    # verify NO ground-truth labels are stored
    assert not hasattr(corpus, 'vector_scores')
    
def test_retrieval_strategies() -> None:
    dataset = [
        {
            "query": "q1 specific word",
            "candidates": [
                {"chunk_id": "c1", "text": "q1 specific word"},
                {"chunk_id": "c2", "text": "completely irrelevant"}
            ]
        }
    ]
    corpus = MockRetrievalCorpus(dataset)
    
    # 1. Keyword only
    kw_results = corpus.retrieve("q1 specific word", "keyword", top_k=2)
    assert kw_results[0].chunk.chunk_id == "c1"
    assert kw_results[0].bm25_score > 0
    assert kw_results[0].vector_score == 0.0
    
    # 2. Vector only
    vec_results = corpus.retrieve("q1 specific word", "vector", top_k=2)
    assert vec_results[0].chunk.chunk_id == "c1"
    assert vec_results[0].vector_score > 0
    assert vec_results[0].bm25_score == 0.0
    
    # 3. Hybrid
    hyb_results = corpus.retrieve("q1 specific word", "hybrid", top_k=2)
    assert hyb_results[0].chunk.chunk_id == "c1"
    assert hyb_results[0].bm25_score > 0
    assert hyb_results[0].vector_score > 0

def test_ground_truth_not_injected() -> None:
    # Verify that the retrieve method computes scores for ALL chunks in the corpus
    dataset = [
        {
            "query": "find matching text",
            "candidates": [
                {"chunk_id": "target", "text": "matching text here"},
            ]
        },
        {
            "query": "other query",
            "candidates": [
                {"chunk_id": "distractor", "text": "find matching text"} # High keyword overlap for query 1
            ]
        }
    ]
    corpus = MockRetrievalCorpus(dataset)
    
    kw_results = corpus.retrieve("find matching text", "keyword", top_k=5)
    chunk_ids = [r.chunk.chunk_id for r in kw_results]
    
    assert len(chunk_ids) == 2
    assert "target" in chunk_ids
    assert "distractor" in chunk_ids
    # "distractor" text is exactly the query, so its keyword score will be 1.0 and it will outrank the target
    assert chunk_ids[0] == "distractor"

def test_vector_distractor_outranks() -> None:
    # Prove vector baseline relies on independent score, and can be tricked by a distractor
    dataset = [
        {
            "query": "abcd efg",
            "candidates": [
                {"chunk_id": "target", "text": "abcd something else"},
            ]
        },
        {
            "query": "other",
            "candidates": [
                {"chunk_id": "distractor", "text": "abcd efg exactly"} 
            ]
        }
    ]
    corpus = MockRetrievalCorpus(dataset)
    vec_results = corpus.retrieve("abcd efg", "vector", top_k=5)
    chunk_ids = [r.chunk.chunk_id for r in vec_results]
    
    # Distractor perfectly matches the query's n-grams, so it outranks the target
    assert chunk_ids[0] == "distractor"
    
