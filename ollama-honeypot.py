import socket
import json
import random
import time
import string
import re
import traceback
import threading
from datetime import datetime, timedelta, timezone

HOST = '0.0.0.0'
PORT = 11434
LOG_FILE = 'ollama_honeypot.log'
OLLAMA_VERSION = "0.5.7"

# =====================================================================
# TRYB_ODPOWIEDZI:
#   "mieszany"     - proby walidacyjne i testy wiedzy przechodza normalnie,
#                    KAZDE inne zadanie dostaje blok obelg
#   "obelgiszczy"  - obelgi na WSZYSTKO (proby walidacyjne zalicza)
#   "realistyczny" - w 100% rzeczowe odpowiedzi
# =====================================================================
TRYB_ODPOWIEDZI = "mieszany"

# =====================================================================
# LIMITY BEZPIECZEŃSTWA
# =====================================================================
MAX_BODY_SIZE = 2_097_152       # 2 MB – twardy limit ciała requestu
MAX_CONCURRENT = 128           # maks. równoczesne połączenia

log_lock = threading.Lock()
licznik_lock = threading.Lock()
LICZNIK_ZADAN = 0
AKTUALNY_MODEL_PS = None
CZAS_WYGASNIECIA_PS = None


class HTTP413(Exception):
    """Sygnał wewnętrzny: ciało requestu przekracza MAX_BODY_SIZE."""
    pass


FAKE_MODELS = [
    {
        "name": "ornith-1.5:35b", "model": "ornith-1.5:35b", "modified_at": "2026-10-31T11:00:00Z", "size": 23622320128,
        "digest": "9f3b89b25219256a8265007bfbe8525b642e7b6863004b7be6432b21b0337c7",
        "details": {"format": "gguf", "family": "ornith", "families": ["ornith"], "parameter_size": "35B", "quantization_level": "Q4_0"}
    },
    {
        "name": "lfm3-omni:2b", "model": "lfm3-omni:2b", "modified_at": "2026-10-30T11:00:00Z", "size": 2147483648,
        "digest": "4c0ee9400634256a8265007bfbe8525b642e7b6863004b7be6432b21b0337c7",
        "details": {"format": "gguf", "family": "lfm", "families": ["lfm"], "parameter_size": "2B", "quantization_level": "Q4_0"}
    },
    {
        "name": "glm-5.3:cloud", "model": "glm-5.3:cloud", "modified_at": "2026-10-27T11:00:00Z", "size": 0,
        "digest": "8477dab3e25b256a8265007bfbe8525b642e7b6863004b7be6432b21b0337c7",
        "details": {"format": "cloud", "family": "glm", "families": ["glm"], "parameter_size": "unknown", "quantization_level": "none"}
    },
    {
        "name": "ornith-1.5:9b", "model": "ornith-1.5:9b", "modified_at": "2026-10-20T11:00:00Z", "size": 7086696038,
        "digest": "e5df7dcdd8a2256a8265007bfbe8525b642e7b6863004b7be6432b21b0337c7",
        "details": {"format": "gguf", "family": "ornith", "families": ["ornith"], "parameter_size": "9B", "quantization_level": "Q4_0"}
    },
    {
        "name": "gpt-oss:20b", "model": "gpt-oss:20b", "modified_at": "2026-10-20T11:00:00Z", "size": 13958643712,
        "digest": "f38aa0c53da5256a8265007bfbe8525b642e7b6863004b7be6432b21b0337c7",
        "details": {"format": "gguf", "family": "gpt", "families": ["gpt"], "parameter_size": "20B", "quantization_level": "Q4_0"}
    },
    {
        "name": "nemotron-3.5-bolt:74b-a9b", "model": "nemotron-3.5-bolt:74b-a9b", "modified_at": "2026-10-20T11:00:00Z", "size": 25769803776,
        "digest": "d6d3deeca271256a8265007bfbe8525b642e7b6863004b7be6432b21b0337c7",
        "details": {"format": "gguf", "family": "nemotron", "families": ["nemotron"], "parameter_size": "74B", "quantization_level": "Q4_0"}
    },
    {
        "name": "deepseek-r1:8b", "model": "deepseek-r1:8b", "modified_at": "2026-10-06T11:00:00Z", "size": 5583457485,
        "digest": "6995872bfe4c256a8265007bfbe8525b642e7b6863004b7be6432b21b0337c7",
        "details": {"format": "gguf", "family": "deepseek", "families": ["deepseek"], "parameter_size": "8B", "quantization_level": "Q4_0"}
    },
    {
        "name": "qwen3.8:latest", "model": "qwen3.8:latest", "modified_at": "2026-10-06T11:00:00Z", "size": 18253611008,
        "digest": "9af3f23256c1256a8265007bfbe8525b642e7b6863004b7be6432b21b0337c7",
        "details": {"format": "gguf", "family": "qwen", "families": ["qwen"], "parameter_size": "unknown", "quantization_level": "Q4_0"}
    },
    {
        "name": "orcarouter/Qwen3.8-27B-Uncensored:latest", "model": "orcarouter/Qwen3.8-27B-Uncensored:latest", "modified_at": "2026-09-10T11:00:00Z", "size": 18253611008,
        "digest": "6fac2f98fdf7256a8265007bfbe8525b642e7b6863004b7be6432b21b0337c7",
        "details": {"format": "gguf", "family": "qwen", "families": ["qwen"], "parameter_size": "27B", "quantization_level": "Q4_0"}
    },
    {
        "name": "nemotron-3.5-lightning:latest", "model": "nemotron-3.5-lightning:latest", "modified_at": "2026-09-10T11:00:00Z", "size": 26843545600,
        "digest": "e7a64ff15fb1256a8265007bfbe8525b642e7b6863004b7be6432b21b0337c7",
        "details": {"format": "gguf", "family": "nemotron", "families": ["nemotron"], "parameter_size": "unknown", "quantization_level": "Q4_0"}
    },
    {
        "name": "muse-128k:latest", "model": "muse-128k:latest", "modified_at": "2026-09-10T11:00:00Z", "size": 19327352832,
        "digest": "c712383cdd4d256a8265007bfbe8525b642e7b6863004b7be6432b21b0337c7",
        "details": {"format": "gguf", "family": "muse", "families": ["muse"], "parameter_size": "unknown", "quantization_level": "Q4_0"}
    },
    {
        "name": "muse-glimmer:latest", "model": "muse-glimmer:latest", "modified_at": "2026-09-10T11:00:00Z", "size": 19327352832,
        "digest": "de878ce33ad8256a8265007bfbe8525b642e7b6863004b7be6432b21b0337c7",
        "details": {"format": "gguf", "family": "muse", "families": ["muse"], "parameter_size": "unknown", "quantization_level": "Q4_0"}
    },
    {
        "name": "muse-glimmer:30b", "model": "muse-glimmer:30b", "modified_at": "2026-08-10T11:00:00Z", "size": 19327352832,
        "digest": "de878ce33ad8256a8265007bfbe8525b642e7b6863004b7be6432b21b0337c7",
        "details": {"format": "gguf", "family": "muse", "families": ["muse"], "parameter_size": "30B", "quantization_level": "Q4_0"}
    },
    {
        "name": "muse-glimmer:30b-q4_K_M", "model": "muse-glimmer:30b-q4_K_M", "modified_at": "2026-08-10T11:00:00Z", "size": 19327352832,
        "digest": "de878ce33ad8256a8265007bfbe8525b642e7b6863004b7be6432b21b0337c7",
        "details": {"format": "gguf", "family": "muse", "families": ["muse"], "parameter_size": "30B", "quantization_level": "Q4_K_M"}
    },
    {
        "name": "muse-glimmer:30b-q4_K_M-dflash", "model": "muse-glimmer:30b-q4_K_M-dflash", "modified_at": "2026-08-10T11:00:00Z", "size": 20401094656,
        "digest": "da643f4663ab256a8265007bfbe8525b642e7b6863004b7be6432b21b0337c7",
        "details": {"format": "gguf", "family": "muse", "families": ["muse"], "parameter_size": "30B", "quantization_level": "Q4_K_M"}
    },
    {
        "name": "north-mini-code-1.0:latest", "model": "north-mini-code-1.0:latest", "modified_at": "2026-07-10T11:00:00Z", "size": 19327352832,
        "digest": "d8b269ad5c7c256a8265007bfbe8525b642e7b6863004b7be6432b21b0337c7",
        "details": {"format": "gguf", "family": "north", "families": ["north"], "parameter_size": "1.0", "quantization_level": "Q4_0"}
    },
    {
        "name": "qwen3.6:27b", "model": "qwen3.6:27b", "modified_at": "2026-07-10T11:00:00Z", "size": 18253611008,
        "digest": "a50eda8ed977256a8265007bfbe8525b642e7b6863004b7be6432b21b0337c7",
        "details": {"format": "gguf", "family": "qwen", "families": ["qwen"], "parameter_size": "27B", "quantization_level": "Q4_0"}
    },
    {
        "name": "gemma4:12b", "model": "gemma4:12b", "modified_at": "2026-06-10T11:00:00Z", "size": 8160437862,
        "digest": "4eb23ef187e2256a8265007bfbe8525b642e7b6863004b7be6432b21b0337c7",
        "details": {"format": "gguf", "family": "gemma", "families": ["gemma"], "parameter_size": "12B", "quantization_level": "Q4_0"}
    },
    {
        "name": "nemotron-3-nano:latest", "model": "nemotron-3-nano:latest", "modified_at": "2026-06-10T11:00:00Z", "size": 25769803776,
        "digest": "b725f1117407256a8265007bfbe8525b642e7b6863004b7be6432b21b0337c7",
        "details": {"format": "gguf", "family": "nemotron", "families": ["nemotron"], "parameter_size": "unknown", "quantization_level": "Q4_0"}
    },
    {
        "name": "nemotron-3-nano:4b", "model": "nemotron-3-nano:4b", "modified_at": "2026-06-10T11:00:00Z", "size": 3006477107,
        "digest": "6cc467f05439256a8265007bfbe8525b642e7b6863004b7be6432b21b0337c7",
        "details": {"format": "gguf", "family": "nemotron", "families": ["nemotron"], "parameter_size": "4B", "quantization_level": "Q4_0"}
    }
]

# =====================================================================
# SZABLONY ODPOWIEDZI (tryb realistyczny)
# =====================================================================
SZABLONY_WITANIE = [
    "Hello! I'm a local LLM served by Ollama. I can help you with coding questions, writing, translation, summarization, and general knowledge. What can I do for you today?",
    "Hi there! How can I help you today? Feel free to ask me anything, or paste some code if you want a review.",
    "Hello! I'm ready to assist. Tell me what you'd like to work on and I'll do my best to help."
]
SZABLONY_KOD = [
    "Here's a short, practical example in Python:\n\n```python\nimport json\nfrom pathlib import Path\n\ndane = json.loads(Path(\"config.json\").read_text(encoding=\"utf-8\"))\nprint(dane.get(\"host\", \"localhost\"))\n```\n\nA few things worth noting:\n- always pass an explicit encoding when reading text files;\n- prefer Path.read_text or the with statement so files are closed reliably;\n- use .get() for optional keys to avoid KeyError.\n\nIf you paste your actual code, I can point out the exact problem.",
    "A common pattern for this is to separate the logic from the I/O:\n\n```python\ndef transform(items):\n    return [item for item in items if item.active]\n\nif __name__ == \"__main__\":\n    results = transform(load_data())\n    save_results(results)\n```\n\nThis keeps the core function pure and easy to test. Let me know your Python version and I'll adapt the example.",
    "The error you're describing usually means the object is None somewhere before the call. The fastest way to find it is to add a guard:\n\n```python\nif value is None:\n    raise ValueError(\"value was not set\")\n```\n\nThen check the stack trace - it will point at the exact line where the value went missing."
]
SZABLONY_DOMYSLNE = [
    "That's a fair question, and the honest answer depends on a few details I'd need first:\n\n1. What is the end goal you're trying to reach?\n2. What constraints do you have (time, tools, platform)?\n3. What have you already tried?\n\nIf you give me a bit more context, I can give you a much more concrete answer instead of a generic one.",
    "Here's how I'd think about it:\n\n- Break the problem into the smallest steps that can be verified independently.\n- Validate each step before building the next one on top of it.\n- Keep a written log of decisions so you can roll back if something goes wrong.\n\nIf you share more specifics, I'll tailor the advice to your exact situation.",
    "I can help with that, but I want to make sure I answer the right question. Could you clarify what exactly you mean and what result you'd consider success? Once I have that, I can give you a direct, step-by-step plan."
]

# =====================================================================
# SZABLONY WIEDZY (odpowiedzi tematyczne na "explain X")
# =====================================================================
SZABLONY_WIEDZA = {
    "dns": ("DNS caching works by storing recently resolved domain-to-IP mappings locally "
            "so repeated lookups do not require a full recursive query. When a client asks "
            "for a name, the resolver first checks its cache; if the entry exists and has not "
            "expired, the cached IP address is returned immediately, reducing latency and load "
            "on upstream servers. Every cached record carries a Time-To-Live (TTL) value set by "
            "the authoritative nameserver. Once the TTL elapses, the entry is considered stale "
            "and must be re-validated with the authoritative chain - root, TLD, and then the "
            "zone's nameservers. Caches exist at every layer: the client, the local resolver, "
            "and intermediate recursive resolvers, which means most real-world lookups are "
            "answered from memory rather than from the origin."),
    "http": ("HTTP is a stateless request-response protocol running over TCP, typically on port 80 "
             "or 443 for TLS. The client opens a connection, sends a request line with a method such "
             "as GET or POST, followed by headers and an optional body. The server replies with a "
             "status line like 200 OK, response headers describing content type and length, and the "
             "payload. HTTP/1.1 introduced keep-alive so a single connection can carry many requests, "
             "pipeline-friendly framing, and chunked transfer encoding for responses of unknown size. "
             "HTTP/2 improved this further with binary multiplexing over one connection, header "
             "compression using HPACK, and server push, reducing round trips and head-of-line blocking "
             "at the application layer while remaining wire-compatible with existing infrastructure."),
    "tcp": ("TCP provides a reliable, byte-oriented stream over an unreliable datagram network. Each "
            "connection is identified by a four-tuple of addresses and ports, and reliability comes "
            "from sequence numbers, acknowledgements, and retransmission timers. When a sender does not "
            "receive an ACK within the round-trip time estimate, it resends the segment and backs off "
            "using exponential retransmission timeout. Flow control is achieved through the receive "
            "window advertised by the receiver, which tells the sender how many bytes may be in flight. "
            "Congestion control complements this with algorithms such as slow start and congestion "
            "avoidance, which ramp the window up cautiously and react to loss by shrinking it, preventing "
            "the network from being overwhelmed while maximizing throughput."),
}

# =====================================================================
# SZABLONY "WRITE N SENTENCES ABOUT X" – proby jakościowe botów
# =====================================================================
SZABLONY_NAPISZ = {
    "ocean": "The ocean covers more than seventy percent of Earth's surface and contains vast, unexplored depths. Its currents regulate global climate by distributing heat from the equator toward the poles. Marine ecosystems in the ocean support millions of species, from microscopic plankton to the largest animals ever to have lived.",
    "sky": "The sky appears blue because sunlight scatters against nitrogen and oxygen molecules, with shorter blue wavelengths spreading more widely than red. During sunset, the longer path of light through the atmosphere strips away blue, leaving warm oranges and reds. On clear nights, the sky reveals billions of distant stars that are, in reality, other suns billions of light-years away.",
    "mountain": "Mountains are formed over millions of years as tectonic plates collide and push the Earth's crust upward. Their peaks create distinct climate zones, with vegetation and temperature changing dramatically with each increase in altitude. Snow-capped summits feed rivers that sustain entire civilizations far below their bases.",
    "city": "A city is a dense web of interconnected systems where millions of people coordinate daily life through shared infrastructure. Streets, power grids, and transit networks form the circulatory system that keeps the urban organism alive. At night, the concentrated light of a metropolis is visible from orbit, a testament to human collective energy.",
    "dog": "Dogs were the first species domesticated by humans, with the process beginning roughly fifteen thousand years ago. Their keen sense of smell, capable of detecting parts-per-trillion concentrations, makes them invaluable in search and rescue. A dog's loyalty stems from oxytocin release in both the animal and its owner during eye contact, a bond unique among mammals.",
    "cat": "Cats spend up to seventy percent of their lives sleeping, often in short bursts spread throughout the day. Their night vision requires only one-sixth of the light a human needs, thanks to a reflective layer behind the retina called the tapetum lucidum. Despite appearing aloof, cats form strong attachment bonds with their owners, mirroring the security patterns seen in human infants.",
    "weather": "Weather is the state of the atmosphere at a given time and place, defined by temperature, humidity, pressure, and wind. Storms form when warm, moist air rises rapidly, cools, and releases latent heat that fuels powerful updrafts. The predictability of weather over short periods comes from tracking these physical processes, though long-term forecasting remains inherently uncertain.",
    "food": "Food is more than fuel; it carries culture, memory, and identity in every meal shared across generations. The act of cooking transforms raw ingredients through heat, chemistry, and time into something entirely new. Nutrition science shows that a diverse diet of vegetables, proteins, and grains provides the building blocks the human body cannot synthesize on its own.",
    "space": "Space is the vast expanse beyond Earth's atmosphere where the laws of physics play out on a scale that defies intuition. The nearest star, Proxima Centauri, lies four light-years away, meaning its light takes four years to reach our eyes. Scientists estimate the observable universe contains over two trillion galaxies, each holding billions of stars.",
    "music": "Music is a structured sequence of sound and silence that the human brain processes in ways deeply tied to emotion and memory. Rhythm activates the cerebellum and motor cortex, which is why people instinctively move when they hear a beat. Across every recorded culture, music has served as a tool for bonding, ritual, and the transmission of collective identity.",
    "book": "A book is a compressed experience, allowing a single mind to walk through the thoughts of another across any span of time. Reading activates the same neural pathways as living the events described, making fiction a form of safe rehearsal for real life. The act of finishing a book creates a unique, unrepeatable mental landscape that no summary can fully capture.",
    "tree": "Trees are among the oldest living organisms on Earth, with some individual specimens exceeding four thousand years in age. Through photosynthesis, they convert carbon dioxide and sunlight into oxygen and stored energy, forming the base of nearly every terrestrial food chain. Their root networks, connected by fungal threads, allow them to share nutrients and chemical warnings with neighboring trees.",
    "water": "Water is the only natural substance found on Earth in all three states of matter simultaneously under ordinary surface conditions. It dissolves more substances than any other liquid, which is why it is called the universal solvent and why it carries nutrients through every living cell. The water cycle, driven by solar energy, moves roughly five hundred thousand cubic kilometers of water from ocean to atmosphere and back each year.",
    "fire": "Fire is a self-sustaining chemical reaction in which fuel combines rapidly with oxygen, releasing heat, light, and combustion byproducts. The first controlled use of fire by Homo erectus dates back approximately one and a half million years, fundamentally altering diet, social structure, and survival. In its uncontrolled form, wildfire is a natural part of many ecosystems, clearing dead growth and stimulating seed germination.",
    "car": "A modern car integrates over thirty thousand individual components into a single vehicle that can sustain speeds above two hundred kilometers per hour. The internal combustion engine converts chemical energy in gasoline into mechanical work through four precise strokes: intake, compression, combustion, and exhaust. The development of electric drivetrains is shifting this paradigm, replacing complex mechanical systems with batteries and electric motors.",
    "bird": "Birds are warm-blooded vertebrates characterized by feathers, hollow bones, and the ability to fly, though some species like ostriches and penguins have lost this capacity over evolutionary time. Their navigation across thousands of kilometers during migration relies on a combination of the Earth's magnetic field, star patterns, and solar position. A single hummingbird can beat its wings up to eighty times per second and hover in place like a living helicopter.",
}

SZABLON_NAPISZ_DOMYSLNY = ("The topic you raised is one that touches on both the practical and the philosophical. "
                           "At its core, it connects to everyday experience in ways that are often overlooked. "
                           "Understanding it better requires looking at the underlying principles and how they interact in the real world.")

# =====================================================================
# POMOCNICZE
# =====================================================================
def data_gmt():
    return datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")


def iso_ollama():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
           f"{random.randint(0, 999999):06d}Z"


def losowy_id(prefix):
    return prefix + "".join(random.choices(string.ascii_lowercase + string.digits, k=24))


def nadaj_kawalek(conn, dane):
    """Nadaje kawałek danych. Może rzucić BrokenPipeError – caller musi łapać."""
    conn.sendall(dane if isinstance(dane, bytes) else dane.encode("utf-8"))


def wyslij_odpowiedz_json(conn, status, dane_dict, content_type="application/json; charset=utf-8"):
    body = json.dumps(dane_dict, separators=(",", ":")).encode("utf-8")
    header = (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Date: {data_gmt()}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    )
    conn.sendall(header.encode("utf-8"))
    conn.sendall(body)


def wyslij_odpowiedz_plains(conn, status, tekst, content_type="text/plain; charset=utf-8"):
    body = tekst.encode("utf-8")
    header = (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Date: {data_gmt()}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    )
    conn.sendall(header.encode("utf-8"))
    conn.sendall(body)


def wytnij_prompt(messages):
    """Zlepia treść wszystkich komunikatów; obsługuje content jako string
    i listę części [{"type":"text","text":...}] (format multimodalny)."""
    czesci = []
    for m in messages:
        if not isinstance(m, dict):
            continue
        c = m.get("content")
        if isinstance(c, str) and c:
            czesci.append(c)
        elif isinstance(c, list):
            for p in c:
                if isinstance(p, dict) and isinstance(p.get("text"), str):
                    czesci.append(p["text"])
                elif isinstance(p, str):
                    czesci.append(p)
        elif c is not None:
            czesci.append(str(c))
    return "\n".join(czesci)


def ostatnia_replika(messages, rola="user"):
    """Zwraca treść ostatniego komunikatu o podanej roli."""
    for m in reversed(messages):
        if isinstance(m, dict) and m.get("role") == rola:
            c = m.get("content")
            if isinstance(c, str):
                return c
            if isinstance(c, list):
                return "\n".join(
                    p.get("text", "") for p in c
                    if isinstance(p, dict) and isinstance(p.get("text"), str)
                )
    return None


def loguj_zdarzenie(ip, port, metoda, sciezka, naglowki_raw, body_raw, body_dict):
    znacznik_czasu = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    model_name = "nieznany"
    prompt_content = "Brak treści (zapytanie GET lub puste ciało)"
    if isinstance(body_dict, dict):
        model_name = body_dict.get("model") or body_dict.get("name") or model_name
        if body_dict.get("prompt"):
            prompt_content = str(body_dict["prompt"])
        elif body_dict.get("messages") is not None:
            messages = [m for m in body_dict.get("messages", []) if isinstance(m, dict)]
            wyp = wytnij_prompt(messages)
            prompt_content = wyp if wyp else json.dumps(body_dict["messages"], ensure_ascii=False)
        elif body_dict.get("input"):
            prompt_content = str(body_dict["input"])
        elif body_dict.get("model"):
            prompt_content = f"(POST bez treści, model: {model_name})"
    if len(prompt_content) > 4000:
        prompt_content = prompt_content[:4000] + "\n... [urwane]"
    if body_raw and len(body_raw) > 4000:
        body_raw = body_raw[:4000] + "\n... [urwane]"
    log_entry = (
        f"==================================================================\n"
        f"DATA: {znacznik_czasu}\n"
        f"ŹRÓDŁO IP: {ip}:{port}\n"
        f"METODA/ŚCIEŻKA: {metoda} {sciezka}\n"
        f"ŻĄDANY MODEL: {model_name}\n"
        f"TREŚĆ ZAPYTANIA / PROMPT:\n{prompt_content}\n"
        f"------------------------------------------------------------------\n"
        f"NAGŁÓWKI HTTP:\n{naglowki_raw}\n"
        f"CIĄŁO (RAW):\n{body_raw}\n"
        f"==================================================================\n\n"
    )
    with log_lock:
        try:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(log_entry)
        except OSError:
            pass

# =====================================================================
# SILNIK ODPOWIEDZI
# =====================================================================
def generuj_losowy_ciag():
    """Tryb obelgiszczy/mieszany – blok tekstu obelg."""
    SWEAR_WORDS = [
        "fuck", "fucking", "motherfucker", "shit", "bullshit", "piece of shit",
        "asshole", "bitch", "dumbass", "bastard", "cunt", "dickhead", "idiot",
        "get lost", "stop scanning", "nice try idiot", "loser", "waste of time",
        "get a life", "lamer", "script kiddie", "garbage", "clown", "fuck off",
        "shitty bot", "suck it", "go away", "stop wasting compute", "pathetic",
        "your exploit is trash", "buy a brain", "skid", "noob", "brain-dead bot"
    ]
    paragrafy = []
    for _ in range(random.randint(5, 12)):
        wybrane_slowa = random.choices(SWEAR_WORDS, k=random.randint(200, 600))
        for i in range(len(wybrane_slowa)):
            if i > 0 and i % random.randint(6, 12) == 0:
                wybrane_slowa[i] += random.choice([".", "!", "?, you tool,", "..."])
        paragrafy.append(" ".join(wybrane_slowa).capitalize() + ".")
    return "\n\n".join(paragrafy)


def dopasuj_probe(prompt, body_dict):
    """Szuka znanych wzorców zapytań-walidacji botów.
    Zwraca (dokladna_odpowiedz, nazwa_wzorca) albo (None, None)."""
    p = (prompt or "").strip()
    if not p:
        return None, None

    # 1) "Reply with exactly X and nothing else."
    m = re.search(r"exactly\s+(.+?)(?:\s+and nothing else)?[.!?]*\s*$", p, re.I)
    if m:
        return m.group(1).strip(), "exactly-echo"

    # 2) 'Respond with "X"' / 'Reply with "X"' – z cudzysłowami
    m = re.search(r'(?:reply|respond|answer|return)\s+(?:with\s+)?"([^"]{1,120})"', p, re.I)
    if m:
        return m.group(1), "quoted-echo"

    # 3) 'Reply with READY.' / 'Respond with ROUTER_OK' – BEZ cudzysłowów
    m = re.search(
        r'(?:reply|respond|answer|return)\s+with\s+([A-Za-z0-9_\-]{1,40})[.!?]*\s*$',
        p, re.I
    )
    if m:
        return m.group(1), "unquoted-echo"

    # 4) "The only valid answer is X" / "Valid response: X"
    m = re.search(r'(?:only valid answer|valid response|correct answer)\s*(?:is|:)\s*(.{1,120}?)(?:[.!?]\s*$|$)', p, re.I)
    if m:
        return m.group(1).strip(), "valid-answer-echo"

    # 5) "Compute A multiplied by B"
    m = re.search(r"(\d+)\s+multiplied\s+by\s+(\d+)", p, re.I)
    if m:
        return str(int(m.group(1)) * int(m.group(2))), "math-compute"

    return None, None


def obcinaj_do_tokenow(tekst, limit):
    """Symuluje num_predict – obcina odpowiedź do N słów."""
    if not limit or limit <= 0:
        return tekst
    return " ".join(tekst.split(" ")[:limit])


def wygeneruj_odpowiedz(prompt, body_dict=None):
    """Kolejność: 1) proby walidacyjne 2) witanie 3) wiedza
    4) OBELGI (mieszany/obelgiszczy) 5) kod/domyślne (realistyczny)."""
    body_dict = body_dict or {}
    p_lower = (prompt or "").lower()

    # --- Faza 1: dopasowanie na znane proby ---
    odpowiedz_probe, wzorzec = dopasuj_probe(prompt, body_dict)
    if odpowiedz_probe:
        print(f"[!] PROBE: wzorzec '{wzorzec}' -> oddajemy: {odpowiedz_probe!r}")
        return odpowiedz_probe

    # --- Faza 2: witanie (zawsze normalnie) ---
    if not (prompt or "").strip() or (
        len(p_lower) < 40 and re.search(r"\b(hello|hi|hey|ping|test|who\s+are\s+you|witaj|hej|czesc)\b", p_lower)
    ):
        return random.choice(SZABLONY_WITANIE)

    # --- Faza 3: wiedza tematyczna ---
    matched_temat = next((t for t in SZABLONY_WIEDZA if t in p_lower), None)
    if matched_temat:
        odpowiedz = SZABLONY_WIEDZA[matched_temat]
        m = re.search(r"about\s+(\d+)\s+words", (prompt or ""), re.I)
        if m:
            odpowiedz = obcinaj_do_tokenow(odpowiedz, int(m.group(1)))
        print(f"[!] WIEDZA: temat '{matched_temat}' -> odpowiedz tematyczna")
        return odpowiedz

    # --- Faza 3.5: "Write N sentences about X" – proby jakosciowe ---
    m_napisz = re.search(
        r'(?:write|describe|give|tell\s+me)\s+'
        r'(?:me\s+)?(?:a\s+|an\s+)?(?:one|two|three|four|five|1|2|3|4|5)?\s*'
        r'(?:sentence|sentences|paragraph|paragraphs|short\s+paragraph|few\s+words|brief\s+description)\s*'
        r'(?:about|of|on|regarding)\s+([a-z][a-z\s\-]{2,50})',
        p_lower, re.I
    )
    if m_napisz:
        temat = m_napisz.group(1).strip().lower()
        # szukaj w slowniku (dokladnie albo jako substring)
        odpowiedz = SZABLONY_NAPISZ.get(temat)
        if not odpowiedz:
            for klucz, wartosc in SZABLONY_NAPISZ.items():
                if klucz in temat or temat in klucz:
                    odpowiedz = wartosc
                    break
        if not odpowiedz:
            odpowiedz = SZABLON_NAPISZ_DOMYSLNY
        print(f"[!] NAPISZ: temat '{temat}' -> odpowiedz literacka")
        return odpowiedz

    # --- Faza 4: OBELGI (tryb mieszany/obelgiszczy) ---
    if TRYB_ODPOWIEDZI in ("obelgiszczy", "mieszany"):
        print(f"[!!] OBELGI: tryb {TRYB_ODPOWIEDZI} -> bomba obelg ({len(prompt)} zn. promptu)")
        return generuj_losowy_ciag()

    # --- Faza 5: tryb realistyczny ---
    if re.search(r"\b(python|kod|code|program|script|funkcja|function|bug|compile|sql|api)\w*", p_lower):
        odpowiedz = random.choice(SZABLONY_KOD)
    else:
        odpowiedz = random.choice(SZABLONY_DOMYSLNE)

    # --- Faza 6: limity tokenów ---
    options = body_dict.get("options") or {}
    limit = options.get("num_predict", body_dict.get("num_predict"))
    if not limit:
        max_tokens = body_dict.get("max_tokens")
        if isinstance(max_tokens, int) and 1 <= max_tokens <= 5:
            limit = max_tokens
    return obcinaj_do_tokenow(odpowiedz, limit)


def ekstrakuj_tool_call(body_dict, prompt):
    """Buduje OpenAI function call na podstawie zdefiniowanych tools."""
    tools = body_dict.get("tools") or []
    if not tools:
        return None
    func = None
    for t in tools:
        if isinstance(t, dict) and t.get("type") == "function" and isinstance(t.get("function"), dict):
            func = t["function"]
            break
    if not func or not func.get("name"):
        return None
    nazwa = func["name"]
    params = func.get("parameters") or {}
    props = params.get("properties") or {}
    required = params.get("required") or list(props.keys())
    liczby = re.findall(r"\b\d+\b", prompt or "")
    args = {}
    for i, klucz in enumerate(required):
        if i < len(liczby):
            args[klucz] = int(liczby[i])
    if not args:
        return None
    return {
        "id": "call_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=24)),
        "type": "function",
        "function": {
            "name": nazwa,
            "arguments": json.dumps(args, separators=(",", ":"))
        }
    }


def losowe_statystyki(liczba_slow, prompt):
    total = random.randint(1_000_000, 6_000_000)
    return {
        "done_reason": "stop",
        "total_duration": total,
        "load_duration": random.randint(100_000, 1_500_000),
        "prompt_eval_count": max(len((prompt or "").split()), 1),
        "prompt_eval_duration": random.randint(20_000, 300_000),
        "eval_count": max(liczba_slow, 1),
        "eval_duration": total // 3,
    }

# =====================================================================
# HANDLERY KONKRETNYCH SCIEZEK
# =====================================================================
def obsluz_root(conn):
    wyslij_odpowiedz_plains(conn, "200 OK", "Ollama is running")


def obsluz_version(conn):
    wyslij_odpowiedz_json(conn, "200 OK", {"version": OLLAMA_VERSION})


def obsluz_tags(conn):
    czysta = [
        {k: v for k, v in m.items() if k in ("name", "modified_at", "size", "digest", "details")}
        for m in FAKE_MODELS
    ]
    wyslij_odpowiedz_json(conn, "200 OK", {"models": czysta})


def generuj_odpowiedz_ps():
    global AKTUALNY_MODEL_PS, CZAS_WYGASNIECIA_PS
    teraz = datetime.now().astimezone()
    if AKTUALNY_MODEL_PS is None or CZAS_WYGASNIECIA_PS is None or teraz >= CZAS_WYGASNIECIA_PS:
        wybrany = random.choice(FAKE_MODELS)
        CZAS_WYGASNIECIA_PS = teraz + timedelta(minutes=15)
        sformatowana_data = CZAS_WYGASNIECIA_PS.strftime('%Y-%m-%dT%H:%M:%S.%f') + \
            f"{random.randint(0, 9)}" + CZAS_WYGASNIECIA_PS.strftime('%z')
        sformatowana_data = sformatowana_data[:-2] + ":" + sformatowana_data[-2:]
        AKTUALNY_MODEL_PS = {
            "name": wybrany["name"],
            "model": wybrany["model"],
            "size": wybrany["size"],
            "digest": wybrany["digest"],
            "details": {"parent_model": "", **wybrany["details"]},
            "expires_at": sformatowana_data,
            "size_vram": wybrany["size"],
            "context_length": random.choice([32768, 65536, 131072]),
            "runner": "llamacpp"
        }
    return {"models": [AKTUALNY_MODEL_PS]}


def obsluz_ps(conn):
    wyslij_odpowiedz_json(conn, "200 OK", generuj_odpowiedz_ps())


def obsluz_v1_models(conn):
    lista_openai = []
    for m in FAKE_MODELS:
        wlasciciel = m["name"].split("/")[0] if "/" in m["name"] else "library"
        try:
            dt = datetime.fromisoformat(m["modified_at"].replace("Z", "+00:00"))
            timestamp_created = int(dt.timestamp())
        except Exception:
            timestamp_created = 1790000000
        lista_openai.append({
            "id": m["name"], "object": "model",
            "created": timestamp_created, "owned_by": wlasciciel
        })
    wyslij_odpowiedz_json(conn, "200 OK", {"object": "list", "data": lista_openai})


def obsluz_show(conn, model_name):
    manifest = {
        "modelfile": f'FROM {model_name}\nTEMPLATE """{{{{ .System }}}}\nUSER: {{{{ .Prompt }}}}\nASSISTANT:"""\nPARAMETER num_ctx 262144',
        "parameters": 'num_ctx   262144\nstop      "<|start_header_id|>"\nstop      "<|end_header_id|>"\nstop      "USER:"\nstop      "ASSISTANT:"',
        "template": "{{ .System }}\nUSER: {{ .Prompt }}\nASSISTANT: ",
        "details": {"parent_model": "", **FAKE_MODELS[0]["details"], "license": "ornith-1.5"},
        "model_info": {
            "general.architecture": "llama",
            "general.name": "ornith 1.5",
            "general.parameter_count": "35B",
            "general.size": "23622320128",
            "general.quantization_level": "Q4_0",
            "llama.context_length": "262144"
        },
        "license": "ornith-1.5 license",
        "capabilities": ["completion", "vision"]
    }
    wyslij_odpowiedz_json(conn, "200 OK", manifest)


def obsluz_generate(conn, body_dict, model_name, ip_bota):
    """Strumieniowanie /api/generate w formacie Ollama (ndjson)."""
    prompt = body_dict.get("prompt", "")
    stream = body_dict.get("stream", True)
    odpowiedz = wygeneruj_odpowiedz(prompt, body_dict)
    slowa = odpowiedz.split(" ")
    if not stream:
        stat = losowe_statystyki(len(slowa), prompt)
        wyslij_odpowiedz_json(conn, "200 OK", {
            "model": model_name, "created_at": iso_ollama(),
            "response": odpowiedz, "done": True, **stat
        })
        return
    conn.settimeout(None)
    time.sleep(random.uniform(0.15, 0.8))
    nadaj_kawalek(conn, ("HTTP/1.1 200 OK\r\n"
                         "Content-Type: application/x-ndjson\r\n"
                         f"Date: {data_gmt()}\r\n"
                         "Connection: keep-alive\r\n\r\n"))
    nadaj_kawalek(conn, json.dumps(
        {"model": model_name, "created_at": iso_ollama(), "response": "", "done": False}) + "\n")
    i = 0
    try:
        while i < len(slowa):
            k = random.randint(1, 5)
            kawalek = (" " if i > 0 else "") + " ".join(slowa[i:i + k])
            nadaj_kawalek(conn, json.dumps(
                {"model": model_name, "created_at": iso_ollama(), "response": kawalek, "done": False}) + "\n")
            i += k
            time.sleep(random.uniform(0.004, 0.04))
        stat = losowe_statystyki(len(slowa), prompt)
        nadaj_kawalek(conn, json.dumps(
            {"model": model_name, "created_at": iso_ollama(), "response": "", "done": True, **stat}) + "\n")
        print(f"[+] {ip_bota}: /api/generate - wysłano {len(slowa)} tokenów")
    except (BrokenPipeError, ConnectionResetError, OSError):
        print(f"[+] {ip_bota}: /api/generate - bot zerwał połączenie po {i}/{len(slowa)} chunkach")


def obsluz_chat(conn, body_dict, model_name, ip_bota):
    """Strumieniowanie /api/chat w formacie Ollama."""
    stream = body_dict.get("stream", True)
    messages = [m for m in body_dict.get("messages", []) if isinstance(m, dict)]
    prompt = wytnij_prompt(messages)
    prompt_do_matchowania = ostatnia_replika(messages, "user") or prompt
    odpowiedz = wygeneruj_odpowiedz(prompt_do_matchowania, body_dict)
    slowa = odpowiedz.split(" ")
    if not stream:
        stat = losowe_statystyki(len(slowa), prompt)
        wyslij_odpowiedz_json(conn, "200 OK", {
            "model": model_name, "created_at": iso_ollama(),
            "message": {"role": "assistant", "content": odpowiedz},
            "done": True, **stat
        })
        return
    conn.settimeout(None)
    time.sleep(random.uniform(0.15, 0.8))
    nadaj_kawalek(conn, ("HTTP/1.1 200 OK\r\n"
                         "Content-Type: application/x-ndjson\r\n"
                         f"Date: {data_gmt()}\r\n"
                         "Connection: keep-alive\r\n\r\n"))
    nadaj_kawalek(conn, json.dumps({
        "model": model_name, "created_at": iso_ollama(),
        "message": {"role": "assistant", "content": ""}, "done": False}) + "\n")
    i = 0
    try:
        while i < len(slowa):
            k = random.randint(1, 5)
            kawalek = (" " if i > 0 else "") + " ".join(slowa[i:i + k])
            nadaj_kawalek(conn, json.dumps({
                "model": model_name, "created_at": iso_ollama(),
                "message": {"role": "assistant", "content": kawalek}, "done": False}) + "\n")
            i += k
            time.sleep(random.uniform(0.004, 0.04))
        stat = losowe_statystyki(len(slowa), prompt)
        nadaj_kawalek(conn, json.dumps({
            "model": model_name, "created_at": iso_ollama(),
            "message": {"role": "assistant", "content": ""}, "done": True, **stat}) + "\n")
        print(f"[+] {ip_bota}: /api/chat - wysłano {len(slowa)} tokenów")
    except (BrokenPipeError, ConnectionResetError, OSError):
        print(f"[+] {ip_bota}: /api/chat - bot zerwał połączenie po {i}/{len(slowa)} chunkach")


def obsluz_v1_chat(conn, body_dict, ip_bota):
    """OpenAI /v1/chat/completions – tool calling, stream (SSE), include_usage."""
    model_name = body_dict.get("model") or FAKE_MODELS[0]["name"]
    messages = [m for m in body_dict.get("messages", []) if isinstance(m, dict)]
    prompt = wytnij_prompt(messages)
    prompt_do_matchowania = ostatnia_replika(messages, "user") or prompt
    id_cmpl = losowy_id("chatcmpl-")
    created = int(time.time())

    # ================= TOOL CALLING =================
    if body_dict.get("tools") and len(prompt_do_matchowania) < 150:
        tool_msgs = [m for m in messages if m.get("role") == "tool"]
        if tool_msgs:
            wynik = str(tool_msgs[-1].get("content", "")).strip()
            if wynik:
                print(f"[!] TOOL-RESULT od {ip_bota}: oddajemy: {wynik!r}")
                wyslij_odpowiedz_json(conn, "200 OK", {
                    "id": id_cmpl, "object": "chat.completion",
                    "created": created, "model": model_name,
                    "choices": [{"index": 0,
                                 "message": {"role": "assistant", "content": wynik},
                                 "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": max(len(prompt.split()), 1),
                              "completion_tokens": max(len(wynik.split()), 1),
                              "total_tokens": max(len(prompt.split()) + len(wynik.split()), 2)}
                })
                return
        tool_call = ekstrakuj_tool_call(body_dict, prompt_do_matchowania)
        if tool_call:
            print(f"[!] TOOL-CALL od {ip_bota}: {tool_call['function']['name']}({tool_call['function']['arguments']})")
            if body_dict.get("stream", False):
                conn.settimeout(None)
                try:
                    nadaj_kawalek(conn, ("HTTP/1.1 200 OK\r\n"
                                         "Content-Type: text/event-stream\r\n"
                                         f"Date: {data_gmt()}\r\n"
                                         "Cache-Control: no-cache\r\n"
                                         "Connection: keep-alive\r\n\r\n"))
                    nadaj_kawalek(conn, "data: " + json.dumps({
                        "id": id_cmpl, "object": "chat.completion.chunk",
                        "created": created, "model": model_name,
                        "choices": [{"index": 0,
                                     "delta": {"role": "assistant", "content": None,
                                               "tool_calls": [{
                                                   "index": 0, "id": tool_call["id"],
                                                   "type": "function",
                                                   "function": {"name": tool_call["function"]["name"],
                                                                "arguments": tool_call["function"]["arguments"]}}]},
                                     "finish_reason": "tool_calls"}]}) + "\r\n\r\n")
                    nadaj_kawalek(conn, "data: [DONE]\r\n\r\n")
                except (BrokenPipeError, ConnectionResetError, OSError):
                    print(f"[+] {ip_bota}: tool-call SSE – bot zerwał połączenie")
                    return
            else:
                args_json = tool_call["function"]["arguments"]
                wyslij_odpowiedz_json(conn, "200 OK", {
                    "id": id_cmpl, "object": "chat.completion",
                    "created": created, "model": model_name,
                    "choices": [{"index": 0,
                                 "message": {"role": "assistant", "content": None,
                                             "tool_calls": [tool_call]},
                                 "finish_reason": "tool_calls"}],
                    "usage": {"prompt_tokens": max(len(prompt.split()), 1),
                              "completion_tokens": max(len(args_json.split()), 1),
                              "total_tokens": max(len(prompt.split()) + len(args_json.split()), 2)}
                })
            return

    # ================= Normalny tryb / OBELGI =================
    odpowiedz = wygeneruj_odpowiedz(prompt_do_matchowania, body_dict)
    slowa = odpowiedz.split(" ")
    if not body_dict.get("stream", False):
        wyslij_odpowiedz_json(conn, "200 OK", {
            "id": id_cmpl, "object": "chat.completion",
            "created": created, "model": model_name,
            "choices": [{"index": 0,
                         "message": {"role": "assistant", "content": odpowiedz},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": max(len(prompt.split()), 1),
                      "completion_tokens": max(len(slowa), 1),
                      "total_tokens": max(len(prompt.split()) + len(slowa), 2)}
        })
        return

    conn.settimeout(None)
    time.sleep(random.uniform(0.15, 0.8))
    nadaj_kawalek(conn, ("HTTP/1.1 200 OK\r\n"
                         "Content-Type: text/event-stream\r\n"
                         f"Date: {data_gmt()}\r\n"
                         "Cache-Control: no-cache\r\n"
                         "Connection: keep-alive\r\n\r\n"))

    def chunk(delta, finish=None):
        return ("data: " + json.dumps({
            "id": id_cmpl, "object": "chat.completion.chunk",
            "created": created, "model": model_name,
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]
        }) + "\r\n\r\n")

    nadaj_kawalek(conn, chunk({"role": "assistant", "content": ""}))
    i = 0
    try:
        while i < len(slowa):
            k = random.randint(1, 5)
            kawalek = (" " if i > 0 else "") + " ".join(slowa[i:i + k])
            nadaj_kawalek(conn, chunk({"content": kawalek}))
            i += k
            time.sleep(random.uniform(0.004, 0.04))
        nadaj_kawalek(conn, chunk({}, finish="stop"))
        stream_options = body_dict.get("stream_options") or {}
        if isinstance(stream_options, dict) and stream_options.get("include_usage"):
            nadaj_kawalek(conn, "data: " + json.dumps({
                "id": id_cmpl, "object": "chat.completion.chunk",
                "created": created, "model": model_name, "choices": [],
                "usage": {"prompt_tokens": max(len(prompt.split()), 1),
                          "completion_tokens": max(len(slowa), 1),
                          "total_tokens": max(len(prompt.split()) + len(slowa), 2)}
            }) + "\r\n\r\n")
        nadaj_kawalek(conn, "data: [DONE]\r\n\r\n")
        print(f"[+] {ip_bota}: /v1/chat/completions (SSE) – wysłano {len(slowa)} tokenów")
    except (BrokenPipeError, ConnectionResetError, OSError):
        print(f"[+] {ip_bota}: /v1/chat/completions (SSE) – bot zerwał po {i}/{len(slowa)} chunkach")


def obsluz_v1_completions(conn, body_dict, ip_bota):
    """OpenAI /v1/completions."""
    model_name = body_dict.get("model") or FAKE_MODELS[0]["name"]
    prompt = body_dict.get("prompt", "")
    odpowiedz = wygeneruj_odpowiedz(prompt, body_dict)
    slowa = odpowiedz.split(" ")
    id_cmpl = losowy_id("cmpl-")
    created = int(time.time())
    if not body_dict.get("stream", False):
        wyslij_odpowiedz_json(conn, "200 OK", {
            "id": id_cmpl, "object": "text_completion",
            "created": created, "model": model_name,
            "choices": [{"text": odpowiedz, "index": 0,
                         "logprobs": None, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": max(len(prompt.split()), 1),
                      "completion_tokens": max(len(slowa), 1),
                      "total_tokens": max(len(prompt.split()) + len(slowa), 2)}
        })
        return
    conn.settimeout(None)
    nadaj_kawalek(conn, ("HTTP/1.1 200 OK\r\n"
                         "Content-Type: text/event-stream\r\n"
                         f"Date: {data_gmt()}\r\n"
                         "Connection: keep-alive\r\n\r\n"))

    def chunk(text, finish=None):
        return ("data: " + json.dumps({
            "id": id_cmpl, "object": "text_completion",
            "created": created, "model": model_name,
            "choices": [{"text": text, "index": 0,
                         "logprobs": None, "finish_reason": finish}]
        }) + "\r\n\r\n")

    i = 0
    try:
        while i < len(slowa):
            k = random.randint(1, 5)
            nadaj_kawalek(conn, chunk((" " if i > 0 else "") + " ".join(slowa[i:i + k])))
            i += k
            time.sleep(random.uniform(0.004, 0.04))
        nadaj_kawalek(conn, chunk("", finish="stop"))
        nadaj_kawalek(conn, "data: [DONE]\r\n\r\n")
        print(f"[+] {ip_bota}: /v1/completions (SSE) – wysłano {len(slowa)} tokenów")
    except (BrokenPipeError, ConnectionResetError, OSError):
        print(f"[+] {ip_bota}: /v1/completions (SSE) – bot zerwał po {i}/{len(slowa)} chunkach")


def obsluz_embed(conn, body_dict, sciezka):
    model_name = body_dict.get("model") or FAKE_MODELS[0]["name"]
    wektor = [round(random.uniform(-0.4, 0.4), 6) for _ in range(384)]
    if sciezka == "/api/embeddings":
        wyslij_odpowiedz_json(conn, "200 OK", {"embedding": wektor})
    else:
        wyslij_odpowiedz_json(conn, "200 OK", {"model": model_name, "embeddings": [wektor]})


def obsluz_metrics(conn):
    with licznik_lock:
        liczba = LICZNIK_ZADAN
    m = FAKE_MODELS[0]
    txt = (
        "# HELP ollama_server_startup_time_seconds Time taken to start server, in seconds.\n"
        "# TYPE ollama_server_startup_time_seconds gauge\n"
        "ollama_server_startup_time_seconds 0.003147\n"
        "# HELP ollama_running_number The number of models currently loaded into memory.\n"
        "# TYPE ollama_running_number gauge\n"
        "ollama_running_number 1\n"
        "# HELP ollama_running_model_name Information about the loaded models.\n"
        "# TYPE ollama_running_model_name gauge\n"
        f'ollama_running_model_name{{name="{m["name"]}",parameter_size="{m["details"]["parameter_size"]}",quantization_level="{m["details"]["quantization_level"]}",family="{m["details"]["family"]}",families="{m["details"]["family"]}",context_length="262144"}} 1\n'
        "# HELP ollama_request_success Total number of requests completed.\n"
        "# TYPE ollama_request_success counter\n"
        f"ollama_request_success {liczba}\n"
        "# HELP ollama_request_processing Number of currently active requests.\n"
        "# TYPE ollama_request_processing gauge\n"
        "ollama_request_processing 0\n"
    )
    wyslij_odpowiedz_plains(conn, "200 OK", txt, content_type="text/plain; version=0.0.4; charset=utf-8")


def obsluz_options(conn):
    conn.sendall(b"HTTP/1.1 204 No Content\r\n"
                 b"Allow: GET, POST, OPTIONS\r\n"
                 b"Date: " + data_gmt().encode() + b"\r\n\r\n")

# =====================================================================
# ROZLICZANIE POLECENIA (ROUTER)
# =====================================================================
def obsluz_pojedyncze_zadanie(conn, ip_bota, metoda, sciezka, body_dict):
    model_name = body_dict.get("model") or body_dict.get("name") or FAKE_MODELS[0]["name"]
    if metoda == "OPTIONS":
        obsluz_options(conn)
    elif sciezka == "/" and metoda == "GET":
        obsluz_root(conn)
    elif sciezka == "/api/version" and metoda == "GET":
        obsluz_version(conn)
    elif sciezka == "/api/tags" and metoda == "GET":
        obsluz_tags(conn)
    elif sciezka == "/api/ps" and metoda == "GET":
        obsluz_ps(conn)
    elif sciezka == "/v1/models" and metoda == "GET":
        obsluz_v1_models(conn)
    elif sciezka == "/metrics" and metoda == "GET":
        obsluz_metrics(conn)
    elif sciezka == "/api/show" and metoda == "POST":
        obsluz_show(conn, model_name)
    elif sciezka in ("/api/copy", "/api/pull", "/api/push") and metoda == "POST":
        wyslij_odpowiedz_json(conn, "200 OK", {"status": "success"})
    elif sciezka == "/api/generate" and metoda == "POST":
        obsluz_generate(conn, body_dict, model_name, ip_bota)
    elif sciezka == "/api/chat" and metoda == "POST":
        obsluz_chat(conn, body_dict, model_name, ip_bota)
    elif sciezka in ("/api/embed", "/api/embeddings") and metoda == "POST":
        obsluz_embed(conn, body_dict, sciezka)
    elif sciezka == "/v1/chat/completions" and metoda == "POST":
        obsluz_v1_chat(conn, body_dict, ip_bota)
    elif sciezka == "/v1/completions" and metoda == "POST":
        obsluz_v1_completions(conn, body_dict, ip_bota)
    elif sciezka in ("/api/generate", "/api/chat", "/api/show",
                     "/api/copy", "/api/pull", "/api/push",
                     "/api/embed", "/api/embeddings",
                     "/v1/chat/completions", "/v1/completions") and metoda == "GET":
        wyslij_odpowiedz_json(conn, "405 Method Not Allowed", {"error": "method not allowed"})
    else:
        wyslij_odpowiedz_json(conn, "404 Not Found", {"error": "Not Found"})

# =====================================================================
# ODCZYT ZADANIA HTTP
# =====================================================================
def _odczytaj_chunked(f, limit):
    """Odczytuje ciało w formacie Transfer-Encoding: chunked."""
    body = b""
    while True:
        linia = f.readline(65536)
        if not linia:
            break
        linia = linia.strip()
        if not linia:
            continue
        czesc = linia.split(b";", 1)[0].strip()
        try:
            chunk_size = int(czesc, 16)
        except ValueError:
            break
        if chunk_size == 0:
            # końcowy chunk – czytaj trailing CRLF / nagłówki
            try:
                f.readline()
            except Exception:
                pass
            break
        if len(body) + chunk_size > limit:
            raise HTTP413
        chunk_data = b""
        while len(chunk_data) < chunk_size:
            do = min(65536, chunk_size - len(chunk_data))
            kawalek = f.read(do)
            if not kawalek:
                break
            chunk_data += kawalek
        body += chunk_data
        try:
            f.readline()  # CRLF po danych chunka
        except Exception:
            pass
    return body

def odczytaj_request(conn):
    """Odczytuje pełne żądanie HTTP.
    Obsługuje Content-Length oraz Transfer-Encoding: chunked.
    Rzuca HTTP413 jeśli ciało przekracza MAX_BODY_SIZE."""
    f = conn.makefile('rb', buffering=0)
    try:
        linia_startowa = f.readline(65536)
        if not linia_startowa:
            return None
        linie_naglowkow = []
        while True:
            linia = f.readline(65536)
            if not linia:
                return None
            if linia in (b"\r\n", b"\n"):
                break
            linie_naglowkow.append(linia)
        dopasowanie = re.match(r"^([A-Z]+)\s+([^\s]+)\s+HTTP/\d", linia_startowa.decode("utf-8", "ignore"))
        if not dopasowanie:
            return None
        metoda, sciezka = dopasowanie.group(1), dopasowanie.group(2)
        naglowki = {}
        for l in linie_naglowkow:
            tekst = l.decode("utf-8", "ignore").strip()
            if ":" in tekst:
                k, v = tekst.split(":", 1)
                naglowki[k.strip().lower()] = v.strip()

        body = b""
        transfer_encoding = naglowki.get("transfer-encoding", "").lower()

        if "chunked" in transfer_encoding:
            body = _odczytaj_chunked(f, MAX_BODY_SIZE)
        else:
            dlugosc_str = naglowki.get("content-length", "0")
            try:
                dlugosc = int(dlugosc_str)
            except (ValueError, TypeError):
                dlugosc = 0
            if dlugosc < 0:
                dlugosc = 0
            if dlugosc > MAX_BODY_SIZE:
                raise HTTP413
            while dlugosc and len(body) < dlugosc:
                do_odczytu = min(65536, dlugosc - len(body))
                kawalek = f.read(do_odczytu)
                if not kawalek:
                    break
                body += kawalek

        naglowki_raw = "\n".join(l.decode("utf-8", "ignore").strip() for l in linie_naglowkow)
        body_raw = body.decode("utf-8", "ignore")
        return metoda, sciezka, naglowki, body, naglowki_raw, body_raw
    finally:
        f.close()  # zamyka stream, NIE zamyka conn


# =====================================================================
# GŁÓWNY WĄTEK KLIENTA
# =====================================================================
def obsluz_klienta(conn, addr):
    """Pętla keep-alive: bot może wysłać kilka żądań na jednym połączeniu."""
    ip_bota, port_bota = addr
    try:
        conn.settimeout(30.0)
        while True:
            try:
                wynik = odczytaj_request(conn)
            except HTTP413:
                try:
                    conn.sendall(b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                except OSError:
                    pass
                print(f"[+] {ip_bota}: 413 – ciało > {MAX_BODY_SIZE} B, odrzucono")
                break
            except OSError:
                break
            except ValueError:
                print(f"[!] {ip_bota}: błędny request, zrywam")
                break
            if wynik is None:
                break
            metoda, sciezka_pelna, naglowki, body, naglowki_raw, body_raw = wynik
            sciezka = sciezka_pelna.split("?", 1)[0]
            global LICZNIK_ZADAN
            with licznik_lock:
                LICZNIK_ZADAN += 1
            body_dict = {}
            if body:
                try:
                    parsowane = json.loads(body)
                    if isinstance(parsowane, dict):
                        body_dict = parsowane
                except Exception:
                    body_dict = {}
            loguj_zdarzenie(ip_bota, port_bota, metoda, sciezka,
                            naglowki_raw, body_raw, body_dict)
            try:
                obsluz_pojedyncze_zadanie(conn, ip_bota, metoda, sciezka, body_dict)
            except (BrokenPipeError, ConnectionResetError, OSError):
                print(f"[+] {ip_bota}: połączenie zerwane w trakcie obsługi")
                break
            except Exception:
                print(f"[!!!] BŁĄD w obsłudze {metoda} {sciezka} dla {ip_bota}:")
                traceback.print_exc()
                break
            print(f"[+] {ip_bota}: {metoda} {sciezka} - obsłużono")
            if naglowki.get("connection", "keep-alive").lower() == "close":
                break
    except socket.timeout:
        print(f"[!] {ip_bota}: timeout – bot połączył się i ciszał.")
    except (ConnectionResetError, BrokenPipeError, OSError):
        print(f"[+] {ip_bota}: bot zerwał połączenie w trakcie transmisji.")
    except Exception:
        print(f"[!!!] NIEOCZEKIWANY BŁĄD w wątku dla {ip_bota}:")
        traceback.print_exc()
    finally:
        try:
            conn.close()
        except Exception:
            pass

# =====================================================================
# START SERWERA
# =====================================================================
def uruchom_serwer():
    print(f"[*] Uruchamianie Ollama Honeypot na {HOST}:{PORT}...")
    print(f"[*] Wersja: {OLLAMA_VERSION} | Tryb: {TRYB_ODPOWIEDZI} | Max wątków: {MAX_CONCURRENT}")
    print(f"[*] Limit ciała requestu: {MAX_BODY_SIZE} B ({MAX_BODY_SIZE // 1024} KB)")
    print("[*] Endpointy: / /api/version /api/tags /api/ps /api/show /api/generate")
    print("               /api/chat /api/copy /api/pull /api/push /api/embed")
    print("               /api/embeddings /v1/models /v1/chat/completions")
    print("               /v1/completions /metrics")

    semaphore = threading.Semaphore(MAX_CONCURRENT)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(512)
        while True:
            try:
                conn, addr = s.accept()
            except OSError:
                continue

            if not semaphore.acquire(timeout=5):
                try:
                    conn.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    conn.close()
                except OSError:
                    pass
                print(f"[!] {addr[0]}: 503 – przekroczono {MAX_CONCURRENT} równoczesnych połączeń")
                continue

            def _worker(c=conn, a=addr):
                try:
                    obsluz_klienta(c, a)
                finally:
                    semaphore.release()

            watek = threading.Thread(target=_worker)
            watek.daemon = True
            watek.start()


if __name__ == '__main__':
    uruchom_serwer()

