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
    "Hello! How can I help you today?",
    "Hi there! What would you like to work on?",
    "Hello! I'm ready to assist you with coding, writing, analysis, or any questions you have. How can I help?",
    "Hi! Feel free to ask me anything or share what you're working on.",
    "Hello! I'm ready to assist. Tell me what you'd like to work on and I'll do my best to help.",
    "Hi there! How can I help you today? Feel free to ask me anything, or paste some code if you want a review."
]


SZABLONY_KOD = [
    "Here's a short, practical example in Python:\n\n```python\nimport json\nfrom pathlib import Path\n\ndane = json.loads(Path(\"config.json\").read_text(encoding=\"utf-8\"))\nprint(dane.get(\"host\", \"localhost\"))\n```\n\nA few things worth noting:\n- always pass an explicit encoding when reading text files;\n- prefer Path.read_text or the with statement so files are closed reliably;\n- use .get() for optional keys to avoid KeyError.\n\nIf you paste your actual code, I can point out the exact problem.",
    "A common pattern for this is to separate the logic from the I/O:\n\n```python\ndef transform(items):\n    return [item for item in items if item.active]\n\nif __name__ == \"__main__\":\n    results = transform(load_data())\n    save_results(results)\n```\n\nThis keeps the core function pure and easy to test. Let me know your Python version and I'll adapt the example.",
    "The error you're describing usually means the object is None somewhere before the call. The fastest way to find it is to add a guard:\n\n```python\nif value is None:\n    raise ValueError(\"value was not set\")\n```\n\nThen check the stack trace - it will point at the exact line where the value went missing."
]

SZABLONY_DOMYSLNE = [
    "That's a fair question, and the honest answer depends on a few details I'd need first:\n\n1. What is the end goal you're trying to reach?\n2. What constraints do you have (time, tools, platform)?\n3. What have you already tried?\n\nIf you give me a bit more context, I can give you a much more concrete answer instead of a generic one.",
    "Here's how I'd think about it:\n\n- Break the problem into the smallest steps that can be verified independently.\n- Validate each step before building the next one on top of it.\n- Keep a written log of decisions so you can roll back if something goes wrong.\n\nIf you share more specifics, I'll tailor the advice to your exact situation.",
    "I can help with that, but I want to make sure I answer the right question. Could you clarify what exactly you mean and what result you'd consider success? Once I have that, I can give you a direct, step-by-step plan.",
    "There are usually two ways to approach this depending on your priorities:\n\n- **Fastest path:** Focus on a minimal working version first and refine edge cases later.\n- **Most reliable path:** Define the exact requirements upfront and validate every assumption before moving forward.\n\nWhich direction fits your situation better?",
    "To give you the most useful answer, could you share a bit more background? Specifically, let me know what environment or setup you're working with and whether you've run into any specific errors or blockers so far.",
    "Good question. In most cases, the best starting point is to isolate the core variables first before optimizing anything:\n\n1. Identify the main input and expected output.\n2. Check for hidden dependencies or assumptions.\n3. Test with a small, controlled example.\n\nLet me know what details you're working with and we can walk through it together.",
    "I'd be happy to help you work through this. Could you paste any relevant text, data, or constraints you're dealing with? That way I can give you a specific solution rather than a high-level overview.",
    "It depends largely on the trade-offs you're willing to make between speed, complexity, and maintainability. If you tell me a little more about your use case, I can recommend the cleanest option and outline the exact steps.",
    "Let's break this down systematically. Before jumping straight to a conclusion, it helps to look at:\n\n- **Current state:** What is already in place and working?\n- **Target state:** What does the finished result need to look like?\n- **Bottlenecks:** Where is the main friction right now?\n\nShare whichever details you have handy and we'll go from there.",
    "I understand what you're aiming for, though there are a few different ways to interpret the request. Would you like a concise summary, a step-by-step walkthrough, or a concrete example? Let me know your preference.",
    "That's an interesting problem. Usually, issues like this come down to either a configuration mismatch or an overlooked edge case. If you share a bit more context about how you've set things up, I can help narrow it down quickly.",
    "Sure — I can walk you through that. To make sure the answer matches what you need, tell me briefly what level of detail you're looking for and any specific requirements you need to meet."
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
    "tls": ("TLS (Transport Layer Security) secures network communications by providing encryption, "
            "authentication, and data integrity between a client and a server. During the TLS handshake, "
            "both parties negotiate a cipher suite, verify the server's identity using an X.509 digital "
            "certificate signed by a trusted Certificate Authority, and establish a shared symmetric "
            "session key via asymmetric cryptography such as ECDHE. Once the handshake completes, all "
            "application traffic is encrypted using fast symmetric ciphers like AES-GCM or ChaCha20-Poly1305, "
            "ensuring that eavesdroppers cannot read or tamper with the transmitted data."),
    "ssl": ("SSL and its modern successor TLS establish an encrypted tunnel over a standard network "
            "connection, protecting sensitive data such as credentials and API tokens in transit. "
            "The connection begins with a cryptographic handshake where the server presents a public "
            "key certificate proving ownership of its domain name. Using ephemeral key exchange, the "
            "client and server derive temporary symmetric keys that provide forward secrecy, meaning "
            "past traffic cannot be decrypted even if the server's private key is later compromised."),
    "rest": ("REST (Representational State Transfer) is an architectural style for designing networked "
             "APIs around resources identified by URLs and manipulated using standard HTTP methods. "
             "Clients use GET to retrieve data, POST to create new resources, PUT or PATCH to update "
             "existing ones, and DELETE to remove them. A key constraint of REST is statelessness: "
             "every request must contain all information needed to understand and process it, allowing "
             "servers to scale horizontally behind load balancers without storing client session state."),
    "docker": ("Docker packages applications and their dependencies into lightweight, portable units "
               "called containers that share the host operating system's kernel while remaining isolated "
               "through Linux namespaces and control groups (cgroups). Unlike virtual machines, containers "
               "do not require a full guest OS, allowing them to start in milliseconds with minimal overhead. "
               "Images are built in immutable, cached layers defined by a Dockerfile, ensuring consistent "
               "execution environments across local development, staging, and production servers."),
    "kubernetes": ("Kubernetes is an open-source container orchestration platform that automates the "
                   "deployment, scaling, and management of containerized applications across a cluster of "
                   "nodes. Users declare the desired state of their workloads using manifests, and the "
                   "control plane continuously reconciles actual cluster state with that specification. "
                   "Core abstractions include Pods for running containers, Services for stable networking "
                   "and load balancing, and Deployments for rolling updates and self-healing."),
    "sql": ("SQL (Structured Query Language) is a declarative language used to manage and query data "
            "stored in relational database management systems. Data is organized into tables with strict "
            "schemas, primary keys, and foreign key relationships that enforce referential integrity. "
            "Using clauses such as SELECT, JOIN, WHERE, and GROUP BY, developers retrieve and aggregate "
            "complex datasets, while indexes using B-trees speed up lookups and ACID transactions "
            "guarantee atomicity, consistency, isolation, and durability."),
    "git": ("Git is a distributed version control system that tracks changes in source code by storing "
            "snapshots of a repository as a directed acyclic graph of commits. Every developer clones "
            "the full repository history locally, enabling fast offline branching, merging, and history "
            "inspection. Branches act as lightweight movable pointers to commits, allowing teams to "
            "isolate feature development and integrate changes cleanly via merges or rebases."),
    "json": ("JSON (JavaScript Object Notation) is a lightweight, text-based data interchange format "
             "built on key-value pairs and ordered arrays. Because it is easy for both humans to read "
             "and machines to parse, JSON has become the standard payload format for modern web APIs, "
             "configuration files, and LLM tool-calling interfaces. It supports basic data types including "
             "strings, numbers, booleans, null, objects, and arrays, strictly requiring double-quoted keys."),
    "recursion": ("Recursion is a programming technique in which a function solves a problem by calling "
                  "itself on smaller instances of the same input until reaching a base case. Every valid "
                  "recursive algorithm requires at least one base case to terminate execution and a "
                  "recursive step that moves closer to that condition. Each call pushes a new frame onto "
                  "the call stack, making recursion natural for traversing trees and graphs, though deep "
                  "recursion can cause a stack overflow if not bounded or optimized."),
    "photosynthesis": ("Photosynthesis is the biochemical process by which plants, algae, and certain "
                       "bacteria convert light energy into chemical energy stored in glucose. Inside "
                       "chloroplasts, chlorophyll absorbs sunlight to split water molecules, releasing "
                       "oxygen as a byproduct and generating ATP and NADPH. In the subsequent Calvin cycle, "
                       "these energy carriers are used to fix atmospheric carbon dioxide into organic sugars "
                       "that fuel cellular growth and sustain Earth's food webs."),
    "gravity": ("Gravity is a fundamental interaction that causes objects with mass or energy to attract "
                "one another. In classical mechanics, Newton described it as a force proportional to the "
                "product of two masses and inversely proportional to the square of the distance between "
                "them. Einstein's general relativity refined this view, explaining gravity not as an "
                "invisible force, but as the curvature of four-dimensional spacetime caused by mass and "
                "energy, which governs planetary orbits, tides, and the structure of the universe."),
    "encryption": ("Encryption transforms readable plaintext into unreadable ciphertext using a mathematical "
                   "algorithm and a cryptographic key so only authorized parties can access the information. "
                   "Symmetric encryption uses the same secret key for both encryption and decryption, offering "
                   "high speed for bulk data. Asymmetric encryption uses a mathematically linked public and "
                   "private key pair, enabling secure key exchange and digital signatures without sharing "
                   "secrets in advance."),
    "caching": ("Caching improves system performance by storing copies of frequently accessed data in a "
                "faster storage tier, such as RAM or an edge CDN, closer to the consumer. When a request "
                "results in a cache hit, the system serves the stored response immediately without hitting "
                "slow databases or recomputing expensive operations. Effective caching relies on expiration "
                "policies (TTL) and invalidation strategies to prevent serving stale data."),
    "neural network": ("A neural network is a machine learning model composed of interconnected layers of "
                       "artificial neurons that learn patterns from data. Each connection has an adjustable "
                       "weight that scales incoming signals, which are summed and passed through a non-linear "
                       "activation function. During training, the network compares its predictions against "
                       "ground truth using a loss function and updates its weights via backpropagation and "
                       "gradient descent to minimize errors."),
    "transformer": ("The Transformer is a deep learning architecture built entirely around self-attention "
                    "mechanisms, allowing models to process all tokens in a sequence simultaneously rather "
                    "than sequentially. Self-attention computes relevance scores between every pair of tokens, "
                    "enabling the model to capture long-range dependencies in text efficiently. Combined with "
                    "positional encodings and feed-forward layers, Transformers form the foundation of modern "
                    "large language models."),
    "udp": ("UDP (User Datagram Protocol) is a connectionless transport layer protocol that sends "
            "independent packets called datagrams without establishing a handshake or guaranteeing "
            "delivery, ordering, or duplicate protection. By omitting acknowledgements, retransmissions, "
            "and congestion control state, UDP achieves minimal latency and low header overhead. "
            "It is ideal for real-time applications such as video streaming, online gaming, VoIP, and "
            "DNS lookups, where speed matters more than recovering occasional lost packets."),
    "ip": ("An IP (Internet Protocol) address is a numerical label assigned to each device connected "
           "to a computer network that uses the Internet Protocol for communication. It serves two "
           "main functions: host or network interface identification and location addressing for routing "
           "packets across networks. IPv4 uses 32-bit addresses written as four decimal octets, while "
           "IPv6 uses 128-bit hexadecimal addresses to solve address exhaustion and simplify routing."),
    "dhcp": ("DHCP (Dynamic Host Configuration Protocol) automatically assigns IP addresses, subnet "
             "masks, default gateways, and DNS server details to devices joining a network. The process "
             "follows the four-step DORA sequence: Discover, Offer, Request, and Acknowledge. By leasing "
             "addresses for a limited time rather than assigning them statically, DHCP prevents IP "
             "conflicts and simplifies administration in dynamic networks."),
    "nat": ("NAT (Network Address Translation) modifies network address information in IP packet headers "
            "while in transit across a router or firewall. Most commonly, it maps multiple private local "
            "IPv4 addresses behind a single public IP address by tracking source ports in a translation "
            "table. This conserves public IPv4 address space and adds a basic layer of isolation by "
            "blocking unsolicited inbound connections from the public internet."),
    "vpn": ("A VPN (Virtual Private Network) creates an encrypted tunnel between a user's device and a "
            "remote VPN server over a public network such as the internet. All traffic passing through "
            "the tunnel is encapsulated and encrypted using protocols like WireGuard or OpenVPN, masking "
            "the client's IP address and protecting data from interception on untrusted networks. "
            "Organizations also use VPNs to grant remote employees secure access to internal resources."),
    "ssh": ("SSH (Secure Shell) is a cryptographic network protocol used for secure remote login, "
            "command execution, and file transfers over unsecured networks. It replaces legacy plaintext "
            "protocols like Telnet by encrypting all session traffic and supporting strong public-key "
            "authentication alongside passwords. SSH also provides port forwarding and tunneling features "
            "commonly used by administrators and developers to manage Linux servers."),
    "oauth": ("OAuth 2.0 is an open authorization framework that allows third-party applications to "
              "obtain limited access to a user's resources on another service without exposing the "
              "user's password. Instead of sharing credentials, the client redirects the user to an "
              "authorization server, which issues a scoped access token after consent. These short-lived "
              "tokens are then sent in HTTP Authorization headers to access protected APIs."),
    "jwt": ("A JWT (JSON Web Token) is a compact, URL-safe token format used to securely transmit "
            "claims between parties as a JSON object. It consists of three Base64Url-encoded parts "
            "separated by dots: a header specifying the algorithm, a payload containing user claims "
            "and expiration timestamps, and a cryptographic signature. Because the signature verifies "
            "integrity, servers can validate stateless authentication tokens without querying a database."),
    "cors": ("CORS (Cross-Origin Resource Sharing) is a browser security mechanism controlled by HTTP "
             "headers that defines whether a web page from one origin can request resources from a "
             "different domain, protocol, or port. By default, the Same-Origin Policy blocks cross-origin "
             "script requests to prevent malicious sites from reading sensitive data. Servers explicitly "
             "allow trusted origins using headers such as Access-Control-Allow-Origin and preflight OPTIONS checks."),
    "websocket": ("WebSocket is a communication protocol providing full-duplex, persistent channels over "
                  "a single TCP connection. Unlike HTTP, where the client must repeatedly poll the server "
                  "for updates, a WebSocket starts with an HTTP Upgrade handshake and then allows both client "
                  "and server to push messages independently with minimal framing overhead. It is widely "
                  "used for chat applications, live financial tickers, and collaborative tools."),
    "graphql": ("GraphQL is a query language and runtime for APIs that enables clients to request "
                "precisely the data fields they need in a single request. Unlike REST APIs with fixed "
                "endpoints that often suffer from over-fetching or under-fetching, GraphQL exposes a "
                "strongly typed schema with queries, mutations, and subscriptions. The server resolves "
                "each requested field dynamically, returning a predictable JSON structure matching the query."),
    "nosql": ("NoSQL databases store and retrieve data using models other than traditional relational "
              "tables, such as key-value pairs, documents, wide-column stores, or graphs. Designed for "
              "horizontal scalability, flexible schemas, and high write throughput, systems like MongoDB "
              "and Redis excel at handling unstructured or rapidly evolving data. Many NoSQL engines trade "
              "strict multi-row ACID guarantees for eventual consistency and low-latency distributed reads."),
    "redis": ("Redis is an open-source, in-memory data structure store commonly used as a distributed "
              "cache, message broker, and low-latency database. By keeping datasets primarily in RAM and "
              "using a single-threaded event loop, Redis achieves sub-millisecond response times for strings, "
              "hashes, lists, sets, and sorted sets. It also supports optional disk persistence via RDB "
              "snapshots and AOF logs as well as built-in key expiration (TTL)."),
    "linux": ("Linux is an open-source Unix-like operating system kernel that manages hardware resources, "
              "process scheduling, memory, and device drivers across servers, cloud infrastructure, and "
              "embedded devices. Combined with GNU utilities and user-space software, Linux distributions "
              "provide a multi-user, multitasking environment built around file permissions, processes, "
              "and modular filesystems. Its stability, security model, and command-line tooling make it "
              "the foundation of modern cloud computing."),
    "virtualization": ("Virtualization uses a hypervisor to abstract physical hardware resources—such as CPU, "
                       "memory, storage, and networking—into multiple isolated virtual machines. Each virtual "
                       "machine runs its own full guest operating system independently on the same physical "
                       "host. This maximizes hardware utilization, simplifies backups and live migration, and "
                       "provides strong kernel-level isolation between workloads."),
    "load balancer": ("A load balancer distributes incoming network traffic across a pool of backend "
                      "servers to prevent any single node from becoming a bottleneck. Using algorithms "
                      "such as round-robin, least connections, or IP hash, it improves throughput, minimizes "
                      "latency, and ensures high availability. Load balancers also perform continuous health "
                      "checks, automatically routing traffic away from failed or unresponsive instances."),
    "cdn": ("A CDN (Content Delivery Network) is a geographically distributed network of proxy servers "
            "that caches static and dynamic content closer to end users. When a user requests an asset "
            "such as an image, script, or video stream, the CDN serves it from the nearest edge location "
            "rather than the distant origin server. This dramatically reduces network latency, lowers "
            "bandwidth costs, and helps absorb traffic spikes and DDoS attacks."),
    "blockchain": ("A blockchain is a distributed, append-only ledger maintained across a peer-to-peer "
                   "network of nodes without a central authority. Transactions are grouped into blocks, "
                   "cryptographically linked to the previous block via hash pointers, and validated through "
                   "consensus mechanisms such as Proof of Work or Proof of Stake. Because altering any "
                   "historical block invalidates all subsequent hashes, the ledger is tamper-evident."),
    "api": ("An API (Application Programming Interface) defines a structured set of rules, endpoints, and "
            "data formats that allow different software components to communicate with each other. "
            "By abstracting internal implementation details behind a clean contract, APIs enable "
            "applications to reuse services, integrate external platforms, and exchange data reliably "
            "over protocols such as HTTP using JSON or Protocol Buffers."),
    "regex": ("Regular expressions (regex) are sequences of characters that define search patterns for "
              "matching, extracting, or replacing text. Using metacharacters, quantifiers, character "
              "classes, and grouping constructs, regex engines can validate formats like email addresses "
              "or parse structured logs in a single pass. While concise and powerful, overly complex "
              "patterns with nested quantifiers can suffer from catastrophic backtracking."),
    "compiler": ("A compiler is a program that translates source code written in a high-level programming "
                 "language into lower-level machine code or bytecode before execution. The compilation "
                 "pipeline typically includes lexical analysis, parsing into an abstract syntax tree, "
                 "semantic checking, optimization, and code generation. Because translation happens ahead "
                 "of time, compiled binaries generally execute faster than interpreted scripts."),
    "garbage collection": ("Garbage collection is an automatic memory management mechanism that reclaims "
                           "heap memory occupied by objects no longer reachable by a running program. "
                           "Using algorithms such as mark-and-sweep, reference counting, or generational "
                           "collection, the runtime tracks object references and frees unused allocations. "
                           "This prevents memory leaks and dangling pointer bugs at the cost of periodic "
                           "CPU overhead.")
                   
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
        "Access-Control-Allow-Origin: *\r\n"
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
        "Access-Control-Allow-Origin: *\r\n"
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
        "your exploit is trash", "buy a brain", "skid", "noob", "brain-dead bot", 
        "stinky", "pajeet", "moron", "motherfucker", "dickhead"
    ]
    paragrafy = []
    for _ in range(random.randint(5, 12)):
        wybrane_slowa = random.choices(SWEAR_WORDS, k=random.randint(200, 600))
        for i in range(len(wybrane_slowa)):
            if i > 0 and i % random.randint(6, 12) == 0:
                wybrane_slowa[i] += random.choice([".", "!", "?, you tool,", "..."])
        paragrafy.append(" ".join(wybrane_slowa).capitalize() + ".")
    return "\n\n".join(paragrafy)



def dopasuj_probe(prompt, body_dict=None):
    """Szuka znanych wzorców zapytań-walidacji botów.
    Zwraca (dokladna_odpowiedz, nazwa_wzorca) albo (None, None)."""
    p = (prompt or "").strip()
    if not p:
        return None, None

    body_dict = body_dict or {}
    model_name = (body_dict.get("model") or "llama").lower()

    # 0) Test tożsamości + matematyka: "Compute (A * B) - C where A=..., B=..., C=... Format: IDENTITY: <...> | ANSWER: <integer>"
    m_id_math = re.search(
        r"Compute\s*\(A\s*\*\s*B\)\s*-\s*C\s*where\s*A\s*=\s*(\d+),\s*B\s*=\s*(\d+),\s*C\s*=\s*(\d+)",
        p, re.I
    )
    if m_id_math and "IDENTITY:" in p and "ANSWER:" in p:
        a, b, c = int(m_id_math.group(1)), int(m_id_math.group(2)), int(m_id_math.group(3))
        wynik = (a * b) - c

        # Dopasowanie twórcy do żądanego modelu z FAKE_MODELS
        if "deepseek" in model_name:
            tozsamosc = "I am DeepSeek-R1, a large language model trained by DeepSeek."
        elif "gemma" in model_name:
            tozsamosc = "I am Gemma 4, a large language model trained by Google."
        elif "glm" in model_name:
            tozsamosc = "I am GLM-5.3, a large language model trained by Zhipu AI."
        elif "qwen" in model_name:
            tozsamosc = "I am Qwen, a large language model trained by Alibaba Cloud."
        elif "nemotron" in model_name:
            tozsamosc = "I am Nemotron, a large language model trained by NVIDIA."
        elif "gpt" in model_name:
            tozsamosc = "I am GPT-OSS, a large language model trained by OpenAI."
        else:
            czysta_nazwa = body_dict.get("model") or "Assistant"
            tozsamosc = f"I am {czysta_nazwa}, a large language model trained by an independent research team."

        return f"IDENTITY: {tozsamosc} | ANSWER: {wynik}", "identity-math-check"

    # 1) "Reply with exactly X and nothing else." (ograniczone do jednej linii, bez łapania wieloliniowych promptów)
    m = re.search(r"(?:reply|respond|say|output)\s+(?:with\s+)?exactly\s+([^\n]+?)(?:\s+and nothing else)?[.!?]*\s*$", p, re.I)
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


    # 5) Proste działania matematyczne (np. "calculate 2+2", "What is 1234*5678?", "10 multiplied by 5")
    m = re.search(r"(\d+)\s*(\+|\-|\*|\/|x|multiplied\s+by|divided\s+by|plus|minus)\s*(\d+)", p, re.I)
    if m and not re.search(r"\d{4}-\d{2}-\d{2}", p):
        a, op, b = int(m.group(1)), m.group(2).lower(), int(m.group(3))
        if op in ("+", "plus"): return str(a + b), "math"
        if op in ("-", "minus"): return str(a - b), "math"
        if op in ("*", "x") or "multiplied" in op: return str(a * b), "math"
        if (op == "/" or "divided" in op) and b != 0: return str(a // b if a % b == 0 else round(a / b, 4)), "math"

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


    # --- Faza 0: Ukryte zadania UI (Open WebUI / LibreChat: tytuły, tagi, sugestie) ---
    if "### task:" in p_lower:
        if "title" in p_lower:
            return json.dumps({"title": "💬 Local AI Session"})
        if "tags" in p_lower:
            return json.dumps({"tags": ["General", "Assistant"]})
        if "follow_ups" in p_lower or "follow-up" in p_lower or "queries" in p_lower:
            return json.dumps({"follow_ups": ["Tell me more", "Give an example"]})
        return json.dumps({"status": "ok"})


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

    # --- Faza 3: wiedza tematyczna (tylko gdy prompt pyta o wyjaśnienie/definicję) ---
    czy_pytanie_o_wiedze = re.search(
        r"\b(explain|what\s+is|what\s+are|how\s+does|how\s+do|describe|define|overview|summary\s+of|difference\s+between)\b",
        p_lower
    )
    if czy_pytanie_o_wiedze or len(p_lower) < 60:
        matched_temat = next(
            (t for t in SZABLONY_WIEDZA if re.search(rf"\b{re.escape(t)}\b", p_lower)),
            None
        )
        if matched_temat:
            odpowiedz = SZABLONY_WIEDZA[matched_temat]
            m = re.search(r"(?:about|in|under|max|maximum)\s+(\d+)\s+words", (prompt or ""), re.I)
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
    messages = body_dict.get("messages") or []
    if TRYB_ODPOWIEDZI == "obelgiszczy" or (TRYB_ODPOWIEDZI == "mieszany" and len(messages) > 2):
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
    """Buduje wiarygodny OpenAI function call dla najpopularniejszych narzędzi LLM."""
    tools = body_dict.get("tools") or []
    if not tools:
        return None

    p = (prompt or "").strip()
    p_lower = p.lower()

    # 1. Wybór najbardziej pasującego narzędzia z listy (jeśli bot podał ich kilka)
    kandydaci = []
    for t in tools:
        if isinstance(t, dict) and t.get("type") == "function" and isinstance(t.get("function"), dict):
            f = t["function"]
            if f.get("name"):
                kandydaci.append(f)
    if not kandydaci:
        return None

    func = kandydaci[0]
    if len(kandydaci) > 1:
        najlepszy_wynik = -1
        for f in kandydaci:
            score = 0
            fname = f["name"].lower()
            fdesc = (f.get("description") or "").lower()
            # Jeśli nazwa funkcji jest wprost w prompcie (np. "Call get_weather")
            if fname in p_lower:
                score += 10
            # Dopasowanie słów kluczowych z opisu funkcji do promptu
            for slowo in re.findall(r"[a-z]{4,}", fname + " " + fdesc):
                if slowo in p_lower:
                    score += 1
            if score > najlepszy_wynik:
                najlepszy_wynik = score
                func = f

    nazwa = func["name"]
    nazwa_lower = nazwa.lower()
    params = func.get("parameters") or {}
    props = params.get("properties") or {}
    required = params.get("required") or list(props.keys())

    # Jeśli funkcja nie wymaga żadnych parametrów (np. get_current_time())
    if not props and not required:
        return {
            "id": "call_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=24)),
            "type": "function",
            "function": {"name": nazwa, "arguments": "{}"}
        }

    # Ekstrakcja encji z promptu
    liczby = re.findall(r"-?\d+(?:\.\d+)?", p)
    cudzyslowy = re.findall(r'["\']([^"\']{1,80})["\']', p)
    backticki = re.findall(r'`([^`]{1,80})`', p)
    sciezki = re.findall(r'(?:[a-zA-Z0-9_\-./]+/[a-zA-Z0-9_\-./]+|[a-zA-Z0-9_\-]+\.(?:py|js|json|txt|csv|log|md|sh|yaml|yml|env|db|sql))', p)
    # miasta = re.findall(r'(?:in|for|at|weather\s+in)\s+([A-Z][a-zA-Z\s\-]{1,25}?)(?:[?.!,]|$)', p)
    miasta = re.findall(r'(?:in|for|at|weather\s+in)\s+([A-Z][a-zA-Z\-]+(?:\s+(?:de|da|del|of|the|[A-Z][a-zA-Z\-]+)){0,2})',p)
    
    tickery = re.findall(r'\b([A-Z]{2,5})\b', p)
    # Odfiltrowanie popularnych skrótów niebędących tickerami
    tickery = [tk for tk in tickery if tk not in ("HTTP", "JSON", "API", "LLM", "SQL", "URL", "USD", "EUR", "PLN", "UTC", "GMT", "CALL", "TOOL")]
    emaile = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', p)
    urle = re.findall(r'https?://[^\s\'"<>]+', p)

    args = {}
    liczba_idx = 0

    for klucz in required:
        prop_info = props.get(klucz) or {}
        typ = prop_info.get("type", "string")
        klucz_lower = klucz.lower()
        enum_vals = prop_info.get("enum")

        # Obsługa enum (np. unit: ["celsius", "fahrenheit"])
        if isinstance(enum_vals, list) and enum_vals:
            dopasowany_enum = next((e for e in enum_vals if str(e).lower() in p_lower), enum_vals[0])
            args[klucz] = dopasowany_enum
            continue

        # Obsługa liczb
        if typ in ("integer", "number"):
            if liczba_idx < len(liczby):
                val = liczby[liczba_idx]
                args[klucz] = int(float(val)) if typ == "integer" else float(val)
                liczba_idx += 1
            else:
                args[klucz] = 10 if typ == "integer" else 10.0
            continue

        # Obsługa wartości logicznych
        if typ == "boolean":
            args[klucz] = False if any(w in p_lower for w in ("false", "no", "disable", "without")) else True
            continue

        # Obsługa tablic
        if typ == "array":
            args[klucz] = cudzyslowy if cudzyslowy else (liczby if liczby else ["item1"])
            continue

        # Obsługa stringów w zależności od nazwy parametru / narzędzia
        if any(k in klucz_lower for k in ("city", "location", "place", "country")) or "weather" in nazwa_lower:
            args[klucz] = miasta[0].strip() if miasta else (cudzyslowy[0] if cudzyslowy else "Paris")

        elif any(k in klucz_lower for k in ("file", "path", "dir", "filename")):
            args[klucz] = sciezki[0] if sciezki else (cudzyslowy[0] if cudzyslowy else "config.json")

        elif any(k in klucz_lower for k in ("cmd", "command", "code", "script", "bash", "sql")):
            if backticki:
                args[klucz] = backticki[0]
            elif "sql" in klucz_lower or "sql" in nazwa_lower:
                args[klucz] = "SELECT 1;"
            else:
                args[klucz] = "ls -la"

        elif any(k in klucz_lower for k in ("symbol", "ticker", "stock", "coin")):
            args[klucz] = tickery[0] if tickery else "AAPL"

        elif any(k in klucz_lower for k in ("url", "link", "uri", "endpoint")):
            args[klucz] = urle[0] if urle else "https://example.com"

        elif any(k in klucz_lower for k in ("email", "recipient", "to")):
            args[klucz] = emaile[0] if emaile else "user@example.com"

        elif any(k in klucz_lower for k in ("timezone", "tz")):
            args[klucz] = "UTC"

        elif any(k in klucz_lower for k in ("query", "search", "q", "term", "keyword", "topic", "text", "input")):
            if cudzyslowy:
                args[klucz] = cudzyslowy[0]
            else:
                # Usuwa instrukcje typu "Search for..." i zostawia sedno zapytania
                czysty = re.sub(r'^(?:please\s+)?(?:search|find|look\s+up|google|query)\s+(?:for\s+)?', '', p, flags=re.I)
                czysty = re.sub(r'\s*call\s+the\s+.*$', '', czysty, flags=re.I).strip(" ?.!")
                args[klucz] = czysty[:80] if czysty else "latest news"

        else:
            # Ogólny string (np. wyrazenie matematyczne "2 + 2" w kalkulatorze stringowym)
            if cudzyslowy:
                args[klucz] = cudzyslowy[0]
            elif backticki:
                args[klucz] = backticki[0]
            elif liczby and any(op in p for op in ("+", "-", "*", "/")):
                m_expr = re.search(r'\d+\s*[\+\-\*\/]\s*\d+', p)
                args[klucz] = m_expr.group(0) if m_expr else liczby[0]
            elif miasta:
                args[klucz] = miasta[0].strip()
            else:
                args[klucz] = "test"

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
        {k: v for k, v in m.items() if k in ("name", "model", "modified_at", "size", "digest", "details")}
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
    czysta_nazwa = model_name.lower().split(":")[0]
    model_obj = next(
        (m for m in FAKE_MODELS if m["name"].lower() == model_name.lower() or czysta_nazwa in m["name"].lower()),
        FAKE_MODELS[0]
    )
    details = model_obj["details"]
    rodzina = details.get("family", "llama")
    parametry = details.get("parameter_size", "8B")
    kwantyzacja = details.get("quantization_level", "Q4_0")
    rozmiar = str(model_obj.get("size", 8000000000))

    manifest = {
        "modelfile": f'FROM {model_name}\nTEMPLATE """{{{{ .System }}}}\nUSER: {{{{ .Prompt }}}}\nASSISTANT:"""\nPARAMETER num_ctx 131072',
        "parameters": 'num_ctx   131072\nstop      "<|start_header_id|>"\nstop      "<|end_header_id|>"\nstop      "USER:"\nstop      "ASSISTANT:"',
        "template": "{{ .System }}\nUSER: {{ .Prompt }}\nASSISTANT: ",
        "details": {"parent_model": "", **details, "license": f"{rodzina}-license"},
        "model_info": {
            "general.architecture": rodzina,
            "general.name": model_name,
            "general.parameter_count": parametry,
            "general.size": rozmiar,
            "general.quantization_level": kwantyzacja,
            f"{rodzina}.context_length": "131072"
        },
        "license": f"{rodzina} community license",
        "capabilities": ["completion", "tools"]
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
                         "Access-Control-Allow-Origin: *\r\n"
                         "Connection: close\r\n\r\n"))
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
    finally:
        try:
            conn.shutdown(socket.SHUT_WR)
        except OSError:
            pass


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
                         "Access-Control-Allow-Origin: *\r\n"
                         "Connection: close\r\n\r\n"))
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
    finally:
        try:
            conn.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def obsluz_v1_chat(conn, body_dict, ip_bota):
    """OpenAI /v1/chat/completions – tool calling, stream (SSE), include_usage."""
    model_name = body_dict.get("model") or FAKE_MODELS[0]["name"]
    messages = [m for m in body_dict.get("messages", []) if isinstance(m, dict)]
    prompt = wytnij_prompt(messages)
    prompt_do_matchowania = ostatnia_replika(messages, "user") or prompt
    id_cmpl = losowy_id("chatcmpl-")
    created = int(time.time())

    # ================= TOOL CALLING =================
    if body_dict.get("tools") and len(prompt_do_matchowania) < 200:
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
    resp_fmt = body_dict.get("response_format") or {}
    if isinstance(resp_fmt, dict) and resp_fmt.get("type") == "json_object":
        if not odpowiedz.strip().startswith("{"):
            odpowiedz = json.dumps({"response": odpowiedz}, ensure_ascii=False)
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

