"""Centralized pattern registry for capability detection and taint analysis.

All SDK method names, database access patterns, network clients, execution sinks,
and filesystem hints live here. Adding support for a new provider or framework
requires updating this registry file without modifying rule logic.
"""
from typing import Dict, List, Set

LLM_SDK_PATTERNS: Dict[str, dict] = {
    "google_generativeai": {
        "vendor": "Google Gemini",
        "method_tails": ["generate_content", "models.generate_content"],
        "source_hints": ["google.generativeai", "google.genai", "genai."],
    },
    "openai": {
        "vendor": "OpenAI",
        "method_tails": ["chat.completions.create", "completions.create", "ChatCompletion.create"],
        "source_hints": ["openai.", "api.openai.com"],
    },
    "anthropic": {
        "vendor": "Anthropic",
        "method_tails": ["messages.create"],
        "source_hints": ["anthropic.", "api.anthropic.com"],
    },
    "langchain": {
        "vendor": "LangChain",
        "method_tails": [".invoke(", ".generate("],
        "source_hints": ["langchain", "LangChain"],
    },
}

DB_LIBRARY_PATTERNS: Dict[str, dict] = {
    "raw_cursor": {
        "style": "raw_cursor",
        "call_hints": ["cursor.execute(", "execute(", "conn.execute("],
        "prop_hints": ["sql", "table", "database", "db"],
        "source_hints": ["SELECT ", "INSERT ", "UPDATE ", "DELETE ", "cursor.", ".connect("],
    },
    "sqlalchemy": {
        "style": "orm",
        "call_hints": ["session.query(", "session.execute(", ".filter("],
        "prop_hints": ["sql", "table", "collection", "database", "db"],
        "source_hints": ["sqlalchemy", "Session(", "create_engine("],
    },
    "pymongo": {
        "style": "nosql",
        "call_hints": [".find(", ".insert_one(", ".update_one(", ".delete_one("],
        "prop_hints": ["collection", "database", "db"],
        "source_hints": ["pymongo", "MongoClient("],
    },
    "django_orm": {
        "style": "orm",
        "call_hints": [".objects.filter(", ".objects.get(", ".objects.create("],
        "prop_hints": ["table", "database", "db"],
        "source_hints": ["models.Model", "objects.filter"],
    },
}

NETWORK_PATTERNS: Dict[str, dict] = {
    "http_clients": {
        "source_hints": [
            "requests.", "httpx.", "urllib.", "fetch(", "axios.", "http.client", "aiohttp.",
            "requests.get(", "requests.post(", "requests.request(",
            "httpx.get(", "httpx.post(", "httpx.Client(", "aiohttp.ClientSession(",
        ],
        "prop_hints": ["url", "uri", "endpoint", "host", "domain", "address"],
    },
    "cloud_sdks": {
        "source_hints": ["boto3.", "azure."],
        "prop_hints": ["bucket", "s3", "endpoint"],
    },
    "url_patterns": {
        "patterns": [
            "generativelanguage.googleapis.com",
            "api.openai.com",
            "api.anthropic.com",
            "http://",
            "https://",
        ],
    },
}

EXECUTION_PATTERNS: Dict[str, dict] = {
    "shell": {
        "source_hints": ["subprocess.", "os.system(", "os.popen(", "shell=True"],
        "prop_hints": ["command", "cmd", "shell", "script", "code", "args"],
    },
    "eval_exec": {
        "source_hints": ["exec(", "eval(", "compile("],
        "prop_hints": ["code", "script"],
    },
}

FILESYSTEM_PATTERNS: Dict[str, dict] = {
    "file_ops": {
        "source_hints": [
            "open(", "os.remove", "os.path", "shutil.", "pathlib.", "Path(", "os.walk", "os.listdir",
        ],
        "prop_hints": ["path", "file", "filepath", "filename", "dir", "directory", "folder"],
    },
}

# Standard library, built-in functions, and common helper names that do NOT represent
# unrecognized I/O calls. Tools making ONLY these calls are truly safe/trivial.
STDLIB_CALL_HINTS: Set[str] = {
    "print", "len", "str", "int", "float", "list", "dict", "set", "tuple", "range",
    "enumerate", "zip", "map", "filter", "sorted", "isinstance", "hasattr", "getattr",
    "setattr", "super", "type", "open", "format", "append", "extend", "update", "get",
    "items", "keys", "values", "lower", "upper", "strip", "split", "join", "replace",
    "encode", "decode", "read", "write", "close", "dumps", "loads", "abspath",
    "dirname", "basename", "exists", "isdir", "isfile", "now", "utcnow", "sleep",
    "max", "min", "sum", "abs", "round", "any", "all", "isinstance", "issubclass",
}


def get_all_llm_method_tails() -> List[str]:
    tails: List[str] = []
    for sdk_info in LLM_SDK_PATTERNS.values():
        tails.extend(sdk_info.get("method_tails", []))
    return tails


def get_all_db_source_hints() -> List[str]:
    hints: List[str] = []
    for db_info in DB_LIBRARY_PATTERNS.values():
        hints.extend(db_info.get("call_hints", []))
        hints.extend(db_info.get("source_hints", []))
    return list(set(hints))


def get_all_network_source_hints() -> List[str]:
    hints: List[str] = []
    for net_info in NETWORK_PATTERNS.values():
        hints.extend(net_info.get("source_hints", []))
    for sdk_info in LLM_SDK_PATTERNS.values():
        hints.extend(sdk_info.get("source_hints", []))
    return list(set(hints))


def get_all_execution_source_hints() -> List[str]:
    hints: List[str] = []
    for exec_info in EXECUTION_PATTERNS.values():
        hints.extend(exec_info.get("source_hints", []))
    return list(set(hints))


def get_all_filesystem_source_hints() -> List[str]:
    hints: List[str] = []
    for fs_info in FILESYSTEM_PATTERNS.values():
        hints.extend(fs_info.get("source_hints", []))
    return list(set(hints))
