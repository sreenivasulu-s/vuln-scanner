import re
from dataclasses import dataclass

@dataclass(frozen=True)
class Category:
    key: str
    name: str
    severity: str
    tools: tuple[str, ...]
    manual: bool
    markers: tuple[str, ...]

CATEGORIES = (
    Category("sql_injection","SQL Injection","high",("nuclei","burp"),True,("sql injection","sqli","cwe-89")),
    Category("xss","Cross-Site Scripting","high",("nuclei","burp"),True,("cross-site scripting","xss","cwe-79")),
    Category("csrf","Cross-Site Request Forgery","medium",("nuclei","burp"),True,("csrf","cross-site request forgery")),
    Category("clickjacking","Clickjacking","low",("httpx","nuclei"),False,("clickjacking","x-frame-options")),
    Category("dom_xss","DOM-Based Vulnerabilities","high",("burp","nuclei"),True,("dom xss","dom-based","dom based")),
    Category("cors","Cross-Origin Resource Sharing (CORS)","medium",("httpx","burp","nuclei"),True,("cors","cross-origin")),
    Category("xxe","XML External Entity (XXE) Injection","high",("burp","nuclei"),True,("xxe","xml external entity")),
    Category("ssrf","Server-Side Request Forgery","high",("burp","nuclei"),True,("ssrf","server-side request forgery")),
    Category("request_smuggling","HTTP Request Smuggling","high",("burp","nuclei"),True,("request smuggling","http desync")),
    Category("os_command_injection","OS Command Injection","critical",("burp","nuclei"),True,("os command injection","command injection")),
    Category("ssti","Server-Side Template Injection","high",("burp","nuclei"),True,("ssti","server-side template injection")),
    Category("path_traversal","Path Traversal","high",("burp","nuclei"),True,("path traversal","directory traversal")),
    Category("access_control","Access Control Vulnerabilities","high",("burp","nuclei"),True,("access control","idor","broken access control","authorization")),
    Category("authentication","Authentication","high",("burp","nuclei"),True,("authentication","auth bypass","authentication bypass")),
    Category("websockets","WebSockets","medium",("burp","nuclei"),True,("websocket","websockets")),
    Category("web_cache_poisoning","Web Cache Poisoning","high",("burp","nuclei"),True,("cache poisoning","web cache poisoning")),
    Category("insecure_deserialization","Insecure Deserialization","high",("burp","nuclei"),True,("deserialization","insecure deserialization")),
    Category("information_disclosure","Information Disclosure","low",("httpx","whatweb","nuclei","nikto"),False,("information disclosure","information leak","server header","technology disclosure")),
    Category("business_logic","Business Logic Vulnerabilities","high",("burp",),True,("business logic","workflow abuse")),
    Category("host_header","HTTP Host Header Attacks","high",("burp","nuclei"),True,("host header","host-header")),
    Category("oauth","OAuth Authentication","high",("burp","nuclei"),True,("oauth","open redirect")),
    Category("file_upload","File Upload Vulnerabilities","high",("burp","nuclei"),True,("file upload","unrestricted upload")),
    Category("jwt","JWT","high",("burp","nuclei"),True,("jwt","json web token")),
    Category("prototype_pollution","Prototype Pollution","high",("burp","nuclei"),True,("prototype pollution")),
    Category("graphql","GraphQL API Vulnerabilities","high",("burp","nuclei"),True,("graphql")),
    Category("race_conditions","Race Conditions","high",("burp",),True,("race condition","race conditions")),
    Category("nosql_injection","NoSQL Injection","high",("burp","nuclei"),True,("nosql injection","nosqli")),
    Category("api_testing","API Testing","medium",("httpx","burp","nuclei"),True,("openapi","swagger","api")),
    Category("web_llm","Web LLM Attacks","high",("burp",),True,("web llm","prompt injection","llm")),
    Category("web_cache_deception","Web Cache Deception","medium",("burp","nuclei"),True,("cache deception","web cache deception")),
)

def classify(
    title: str,
    description: str = "",
    evidence: str = "",
    tool: str = "",
):
    text = " ".join(
        value or ""
        for value in (title, description, evidence, tool)
    ).lower()

    normalized = re.sub(r"[^a-z0-9]+", " ", text)
    words = set(normalized.split())

    def has_phrase(*tokens: str) -> bool:
        phrase = " ".join(tokens)
        return phrase in normalized

    # Ordered from specific to broad to avoid false classification.
    rules = [
        ("sql_injection", lambda: has_phrase("sql", "injection") or "sqli" in words),
        ("xss", lambda: has_phrase("cross", "site", "scripting") or "xss" in words),
        ("csrf", lambda: "csrf" in words or has_phrase("cross", "site", "request", "forgery")),
        ("clickjacking", lambda: "clickjacking" in words),
        ("dom_xss", lambda: has_phrase("dom", "xss") or has_phrase("dom", "based", "xss")),
        ("cors", lambda: "cors" in words or has_phrase("cross", "origin", "resource", "sharing")),
        ("xxe", lambda: "xxe" in words or has_phrase("xml", "external", "entity")),
        ("ssrf", lambda: "ssrf" in words or has_phrase("server", "side", "request", "forgery")),
        ("request_smuggling", lambda: "smuggling" in words or has_phrase("http", "request", "smuggling")),
        ("os_command_injection", lambda: has_phrase("os", "command", "injection") or has_phrase("command", "injection")),
        ("ssti", lambda: "ssti" in words or has_phrase("server", "side", "template", "injection")),
        ("path_traversal", lambda: "path" in words and "traversal" in words),
        ("access_control", lambda: has_phrase("access", "control")),
        ("authentication", lambda: "authentication" in words or "auth" in words),
        ("websockets", lambda: "websocket" in words or "websockets" in words),
        ("web_cache_poisoning", lambda: has_phrase("web", "cache", "poisoning")),
        ("insecure_deserialization", lambda: has_phrase("insecure", "deserialization") or "deserialization" in words),
        ("information_disclosure", lambda: has_phrase("information", "disclosure")),
        ("business_logic", lambda: has_phrase("business", "logic")),
        ("host_header", lambda: has_phrase("host", "header")),
        ("oauth", lambda: "oauth" in words),
        ("file_upload", lambda: has_phrase("file", "upload")),
        ("jwt", lambda: "jwt" in words or has_phrase("json", "web", "token")),
        ("prototype_pollution", lambda: has_phrase("prototype", "pollution")),
        ("graphql", lambda: "graphql" in words),
        ("race_conditions", lambda: has_phrase("race", "condition") or has_phrase("race", "conditions")),
        ("nosql_injection", lambda: has_phrase("nosql", "injection") or "nosql" in words),
        ("api_testing", lambda: "api" in words or has_phrase("api", "testing")),
        ("web_llm", lambda: has_phrase("web", "llm") or "llm" in words),
        ("web_cache_deception", lambda: has_phrase("web", "cache", "deception")),
    ]

    for key, matcher in rules:
        if matcher():
            for category in CATEGORIES:
                if category.key == key:
                    return category

    return None

def catalog():
    return [
        {
            "key":c.key,
            "name":c.name,
            "severity":c.severity,
            "tools":list(c.tools),
            "manual_validation":c.manual,
        }
        for c in CATEGORIES
    ]

def coverage(findings):
    result=[]
    for c in CATEGORIES:
        hits=[f for f in findings if f.get("category_key")==c.key]
        result.append({
            "key":c.key,
            "name":c.name,
            "state":"potential" if hits else "not_observed",
            "severity":c.severity,
            "manual_validation":c.manual,
            "finding_count":len(hits),
        })
    return result
