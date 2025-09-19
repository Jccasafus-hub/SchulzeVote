#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Gera figuras PNG para o guia do método de Schulze.

Saída sugerida: colocar os PNGs gerados em static/img/
"""

import math
from textwrap import fill
from PIL import Image, ImageDraw, ImageFont

# ==========================
# CONFIG (ajuste aqui)
# ==========================
W, H = 1600, 900                 # tamanho base de cada figura (px)
MARGIN = 60                      # margem (px)
BG = (11, 13, 16)                # var(--bg)
FG = (229, 231, 235)             # var(--text)
MUTED = (152, 162, 179)          # var(--muted)
ACCENT = (249, 115, 22)          # var(--accent)
ACCENT2 = (245, 158, 11)         # var(--accent-2)
CARD = (17, 19, 23)              # var(--card)
BORDER = (31, 36, 44)            # var(--border)

# Fonte: troque o caminho se quiser outra (ex.: Roboto, Inter, etc.)
# Dica: no Linux/macOS normalmente "DejaVuSans" existe; no Windows, Arial.
FONT_BOLD_PATH = None  # ex.: "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
FONT_REG_PATH  = None  # ex.: "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"

TITLE_SIZE = 54
SUB_SIZE   = 30
BODY_SIZE  = 28
MONO_SIZE  = 26

# ==========================
# Utilitários de desenho
# ==========================
def load_font(path, size, fallback="Arial"):
    try:
        if path:
            return ImageFont.truetype(path, size=size)
        return ImageFont.truetype(fallback, size=size)
    except Exception:
        return ImageFont.load_default()

FB = load_font(FONT_BOLD_PATH, TITLE_SIZE)
FR = load_font(FONT_REG_PATH,  BODY_SIZE)
FS = load_font(FONT_REG_PATH,  SUB_SIZE)
FM = load_font(FONT_REG_PATH,  MONO_SIZE)

def draw_box(draw, xy, radius=18, fill=CARD, outline=BORDER, width=2):
    x1,y1,x2,y2 = xy
    draw.rounded_rectangle(xy, radius=radius, fill=fill, outline=outline, width=width)

def draw_wrapped(draw, text, xy, font, fill=FG, max_width_px=1000, line_spacing=6):
    x, y = xy
    # aproxima o wrap pelo número de chars por linha
    avg = font.getlength("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")/52
    max_chars = max(10, int(max_width_px / max(1, avg)))
    wrapped = fill_text(text, max_chars)
    for line in wrapped.split("\n"):
        draw.text((x,y), line, font=font, fill=fill)
        y += font.size + line_spacing
    return y

def fill_text(s, width):
    return fill(s, width=width, break_long_words=False, replace_whitespace=False)

def header(img, title, subtitle=None):
    draw = ImageDraw.Draw(img)
    x = MARGIN
    y = MARGIN
    draw.text((x, y), title, font=FB, fill=FG)
    y += TITLE_SIZE + 12
    if subtitle:
        draw.text((x, y), subtitle, font=FS, fill=MUTED)
        y += SUB_SIZE + 8
    return y + 10

def save(img, name):
    img.save(name, format="PNG", optimize=True)
    print("ok ->", name)

# ==========================
# Figura 1: Fluxo geral
# ==========================
def fig_flow_overview():
    img = Image.new("RGB", (W,H), BG)
    y = header(img, "Método de Schulze — visão geral",
               "Como o voto é dado e como a contagem funciona")
    draw = ImageDraw.Draw(img)

    # Caixinhas do fluxo
    col_w = (W - 2*MARGIN)
    box_h = 120
    gap = 20

    steps = [
        ("Eleitor informa um ranking", "1º, 2º, 3º… (pode deixar alguns sem número)"),
        ("Contagem par-a-par", "para cada par (A,B) contamos quantos preferem A>B"),
        ("Forças diretas", "A→B = d[A][B] se d[A][B] > d[B][A], senão 0"),
        ("Melhores caminhos", "p[A][B] = força do caminho mais forte de A até B"),
        ("Comparação final", "A não perde para B se p[A][B] ≥ p[B][A]"),
        ("Vencedor(es)", "quem não perde para ninguém"),
    ]

    cur_y = y + 10
    for title, sub in steps:
        draw_box(draw, (MARGIN, cur_y, MARGIN+col_w, cur_y+box_h))
        draw.text((MARGIN+20, cur_y+20), title, font=FS, fill=FG)
        draw.text((MARGIN+20, cur_y+60), sub,   font=FR, fill=MUTED)
        cur_y += box_h + gap

    save(img, "schulze_flow_overview.png")

# ==========================
# Figura 2: Definição formal
# ==========================
def fig_formal_definition():
    img = Image.new("RGB", (W,H), BG)
    y = header(img, "Definição formal (resumo técnico)")
    draw = ImageDraw.Draw(img)

    text = (
        "Para cada par distinto (a,b), d[a][b] é o número (ou soma de pesos) de eleitores que preferem a>b.\n"
        "Força direta: a→b = d[a][b], se d[a][b] > d[b][a]; caso contrário, 0.\n"
        "A força de um caminho a→…→b é o mínimo das forças diretas nesse caminho.\n"
        "p[a][b] é a máxima força dentre todos os caminhos a→…→b.\n"
        "Comparamos p par-a-par: a ‘não perde’ para b se p[a][b] ≥ p[b][a]."
    )
    draw_box(draw, (MARGIN, y, W-MARGIN, H-MARGIN))
    draw.text((MARGIN+20, y+20), "Resumo:", font=FS, fill=FG)
    draw_wrapped(draw, text, (MARGIN+20, y+70), FR, fill=FG, max_width_px=W-2*MARGIN-60)

    save(img, "schulze_formal_definition.png")

# ==========================
# Figura 3: Exemplo simples
# ==========================
def fig_example_simple():
    img = Image.new("RGB", (W,H), BG)
    y = header(img, "Exemplo simples (3 candidatos)",
               "Perfis ilustrativos e resultado")
    draw = ImageDraw.Draw(img)

    left_x = MARGIN
    mid_x  = W//2
    box_h  = (H - y - MARGIN - 20)
    draw_box(draw, (left_x, y, mid_x-10, y+box_h))
    draw_box(draw, (mid_x+10, y, W-MARGIN, y+box_h))

    # Votos
    draw.text((left_x+20, y+20), "Perfis (peso 1):", font=FS, fill=FG)
    lines = [
        "1) A > B > C",
        "2) A > C > B",
        "3) B > C > A",
        "4) C > B > A",
        "5) A > B > C",
        "",
        "Par-a-par:",
        "A×B: A=3, B=2  → A→B=3",
        "A×C: A=3, C=2  → A→C=3",
        "B×C: B=3, C=2  → B→C=3",
    ]
    yy = y+70
    for ln in lines:
        draw.text((left_x+24, yy), ln, font=FR, fill=FG if ln and ln[0].isdigit() else MUTED)
        yy += BODY_SIZE + 6

    # Conclusão
    txt = "A vence B e C diretamente; B vence C. Logo, A é vencedor de Schulze."
    draw.text((mid_x+30, y+30), "Conclusão:", font=FS, fill=FG)
    draw_wrapped(draw, txt, (mid_x+30, y+80), FR, fill=FG, max_width_px=(W - mid_x - MARGIN - 60))

    save(img, "schulze_example_simple.png")

# ==========================
# Figura 4: Exemplo com ciclo
# ==========================
def fig_example_cycle():
    img = Image.new("RGB", (W,H), BG)
    y = header(img, "Exemplo com ciclo", "A > B, B > C, C > A (ilustrativo)")
    draw = ImageDraw.Draw(img)

    draw_box(draw, (MARGIN, y, W-MARGIN, H-MARGIN))
    yy = y+20
    draw.text((MARGIN+20, yy), "Perfis:", font=FS, fill=FG); yy += SUB_SIZE + 10
    block = (
        "40 eleitores: A > B > C\n"
        "35 eleitores: B > C > A\n"
        "25 eleitores: C > A > B\n\n"
        "Par-a-par:\n"
        "A×B: A ganha (65 vs 35) → A→B = 65\n"
        "B×C: B ganha (75 vs 25) → B→C = 75\n"
        "C×A: C ganha (60 vs 40) → C→A = 60\n\n"
        "Há um ciclo. O Schulze compara os melhores caminhos p[a][b] e escolhe quem ‘não perde para ninguém’."
    )
    draw_wrapped(draw, block, (MARGIN+20, yy), FR, fill=FG, max_width_px=W-2*MARGIN-60)
    save(img, "schulze_example_cycle.png")

# ==========================
# Figura 5: Matriz d vs p (NOVO)
# ==========================
def fig_matrix_d_vs_p():
    img = Image.new("RGB", (W,H), BG)
    y = header(img, "Matrizes d[a][b] (par-a-par) vs p[a][b] (melhores caminhos)",
               "Exemplo ilustrativo com 3 candidatos")
    draw = ImageDraw.Draw(img)

    # Dados ilustrativos coerentes com o exemplo simples
    C = ["A","B","C"]
    d = {
        "A": {"B": 3, "C": 3},
        "B": {"A": 2, "C": 3},
        "C": {"A": 2, "B": 2},
    }
    # Força direta s = d> - filtrada
    s = {a:{b: (d[a][b] if d[a][b] > d[b][a] else 0) for b in C if b!=a} for a in C}
    # Floyd-Warshall para p (mutamos s como p)
    for i in C:
        for j in C:
            if i==j: continue
            for k in C:
                if i==k or j==k: continue
                s[j][k] = max(s[j][k], min(s[j][i], s[i][k]))

    # Desenha duas tabelas lado a lado
    gap = 30
    w_panel = (W - 2*MARGIN - gap) // 2
    panels = [
        ("d[a][b] (par-a-par)", d),
        ("p[a][b] (melhores caminhos)", s),
    ]
    px = [MARGIN, MARGIN + w_panel + gap]

    for pi, (title, mat) in enumerate(panels):
        x0 = px[pi]; y0 = y
        draw_box(draw, (x0, y0, x0+w_panel, H-MARGIN))
        draw.text((x0+20, y0+20), title, font=FS, fill=FG)

        # Tabela
        cell = 80
        tx = x0 + 40
        ty = y0 + 70

        # cabeçalho
        for j,b in enumerate([""]+C):
            text = b
            draw.text((tx + j*cell, ty), text, font=FM, fill=MUTED)
        ty += 36
        # linhas
        for i,a in enumerate(C):
            draw.text((tx, ty + i*cell), a, font=FM, fill=MUTED)
            for j,b in enumerate(C):
                if i==j:
                    val = ""
                else:
                    val = str(mat[a][b]) if (a in mat and b in mat[a]) else ""
                # célula
                cx = tx + (j+1)*cell
                cy = ty + i*cell
                draw.rectangle((cx-6, cy-4, cx+60, cy+36), fill=BG, outline=BORDER, width=1)
                draw.text((cx, cy), val, font=FM, fill=FG)

    save(img, "schulze_matrix_d_vs_p.png")

# ==========================
# main
# ==========================
if __name__ == "__main__":
    fig_flow_overview()
    fig_formal_definition()
    fig_example_simple()
    fig_example_cycle()
    fig_matrix_d_vs_p()
