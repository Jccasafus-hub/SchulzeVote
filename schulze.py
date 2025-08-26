from collections import defaultdict

def schulze_method(ballots, candidates):
    # Inicializa matriz de preferências
    pairwise = { (a,b):0 for a in candidates for b in candidates if a != b }
    for ballot in ballots:
        for i,a in enumerate(ballot):
            for b in ballot[i+1:]:
                pairwise[(a,b)] += 1

    # Força
    strength = defaultdict(int)
    for a in candidates:
        for b in candidates:
            if a != b and pairwise.get((a,b),0) > pairwise.get((b,a),0):
                strength[(a,b)] = pairwise[(a,b)]

    # Caminho mais forte
    for i in candidates:
        for j in candidates:
            if i != j:
                for k in candidates:
                    if i!=k and j!=k:
                        strength[(j,k)] = max(strength[(j,k)],
                                              min(strength[(j,i)], strength[(i,k)]))

    # Ranking final
    ranking = sorted(candidates, key=lambda x: [
        sum(strength[(x,y)] > strength[(y,x)] for y in candidates if y!=x),
        -sum(strength[(y,x)] > strength[(x,y)] for y in candidates if y!=x)
    ], reverse=True)
    return ranking
