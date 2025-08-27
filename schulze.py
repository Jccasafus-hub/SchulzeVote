from collections import defaultdict

def schulze_method(ballots_with_weights, candidates):
    """
    ballots_with_weights: lista de itens {"ranking": [cand1, cand2, ...], "peso": int}
    candidates: lista de candidatos (incluindo "Voto em Branco" e "Voto Nulo", se usados)
    """
    # Matriz de preferências ponderada
    pairwise = { (a,b): 0 for a in candidates for b in candidates if a != b }

    for item in ballots_with_weights:
        ranking = item.get("ranking", [])
        w = int(item.get("peso", 1))
        # Para cada par (a,b) onde a precede b na cédula, soma w
        for i, a in enumerate(ranking):
            for b in ranking[i+1:]:
                if a != b and (a in candidates) and (b in candidates):
                    pairwise[(a,b)] += w

    # Força de preferência direta
    strength = defaultdict(int)
    for a in candidates:
        for b in candidates:
            if a != b:
                ab = pairwise.get((a,b), 0)
                ba = pairwise.get((b,a), 0)
                strength[(a,b)] = ab if ab > ba else 0

    # Caminhos mais fortes (algoritmo de Schulze)
    for i in candidates:
        for j in candidates:
            if i == j: 
                continue
            for k in candidates:
                if k == i or k == j:
                    continue
                strength[(j,k)] = max(
                    strength[(j,k)],
                    min(strength[(j,i)], strength[(i,k)])
                )

    # Ordenação final
    def score(x):
        wins = sum(strength[(x,y)] > strength[(y,x)] for y in candidates if y != x)
        losses = sum(strength[(y,x)] > strength[(x,y)] for y in candidates if y != x)
        return (wins, -losses)

    return sorted(candidates, key=score, reverse=True)
