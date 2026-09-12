import json

with open("data/golden_dataset.json") as f:
    dataset = json.load(f)

corpus = []
for case in dataset:
    for cand in case["candidates"]:
        if cand not in corpus:
            corpus.append(cand)

def get_words(text):
    return set(text.lower().split())

def get_3grams(text):
    text = text.lower()
    return set([text[i:i+3] for i in range(len(text)-2)])

for case in dataset:
    query = case["query"]
    print("Q:", query)
    qw = get_words(query)
    q3 = get_3grams(query)
    
    for cand in corpus:
        text = " ".join(cand["entities"].get("cves", [])) + " " + " ".join(cand["entities"].get("mitre_techniques", [])) + " " + " ".join(cand["entities"].get("ips", []))
        cw = get_words(text)
        c3 = get_3grams(text)
        
        # Word overlap
        w_inter = len(qw & cw)
        w_score = w_inter / (len(qw | cw) + 1e-6)
        
        # 3-gram overlap
        g_inter = len(q3 & c3)
        g_score = g_inter / (len(q3 | c3) + 1e-6)
        
        print(f"  Cand: {cand['chunk_id']} -> W: {w_score:.2f}, G: {g_score:.2f}")
