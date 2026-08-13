import httpx

from backend.scanner.base import ScannerBase


class LabScanner(ScannerBase):
    """
    Authorized lab scanner adapter.

    Performs a non-intrusive HTTP request and reports passive
    security observations only.
    """

    async def scan(self, target: str) -> list[dict]:
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=5.0,
            ) as client:
                response = await client.get(target)

            findings = [
                {
                    "title": "HTTP service reachable",
                    "severity": "info",
                    "description": (
                        "The authorized lab target responded to an HTTP GET request."
                    ),
                    "evidence": f"HTTP {response.status_code} from {response.url}",
                    "tool": "httpx",
                }
            ]

            findings.extend(self._check_security_headers(response))
            findings.extend(self._check_information_disclosure(response))
            findings.extend(self._check_cookies(response))

            return findings

        except httpx.HTTPError as exc:
            return [
                {
                    "title": "HTTP request failed",
                    "severity": "info",
                    "description": (
                        "The authorized lab target could not be reached "
                        "with the configured HTTP client."
                    ),
                    "evidence": str(exc),
                    "tool": "httpx",
                }
            ]

    @staticmethod
    def _header_get(headers, name: str, default=None):
        """
        Read a header from httpx.Headers, dict-like mocks, or simple
        test doubles.
        """
        getter = getattr(headers, "get", None)

        if callable(getter):
            return getter(name, default)

        try:
            return headers[name]
        except (KeyError, TypeError):
            return default

    @staticmethod
    def _header_present(headers, name: str) -> bool:
        """
        Check header presence without requiring the headers object to
        implement __contains__.
        """
        value = LabScanner._header_get(headers, name)

        return value is not None

    @staticmethod
    def _get_set_cookie_headers(headers) -> list[str]:
        """
        Return all Set-Cookie header values.

        httpx.Headers supports get_list(). Plain dictionaries may contain
        a single Set-Cookie value, while test doubles may implement either
        get_list() or get().
        """
        get_list = getattr(headers, "get_list", None)

        if callable(get_list):
            values = get_list("set-cookie")
            return list(values or [])

        value = LabScanner._header_get(headers, "set-cookie")

        if value is None:
            return []

        if isinstance(value, (list, tuple)):
            return [str(item) for item in value]

        return [str(value)]

    @staticmethod
    def _check_security_headers(response: httpx.Response) -> list[dict]:
        checks = {
            "x-content-type-options": (
                "Missing X-Content-Type-Options header",
                "The response does not include X-Content-Type-Options.",
            ),
            "content-security-policy": (
                "Missing Content-Security-Policy header",
                "The response does not include Content-Security-Policy.",
            ),
            "strict-transport-security": (
                "Missing Strict-Transport-Security header",
                "The response does not include Strict-Transport-Security.",
            ),
            "referrer-policy": (
                "Missing Referrer-Policy header",
                "The response does not include Referrer-Policy.",
            ),
            "permissions-policy": (
                "Missing Permissions-Policy header",
                "The response does not include Permissions-Policy.",
            ),
        }

        findings = []

        for header, (title, description) in checks.items():
            if not LabScanner._header_present(response.headers, header):
                findings.append(
                    {
                        "title": title,
                        "severity": "low",
                        "description": description,
                        "evidence": (
                            f"HTTP {response.status_code} from {response.url}"
                        ),
                        "tool": "httpx",
                    }
                )

        return findings

    @staticmethod
    def _check_information_disclosure(response: httpx.Response) -> list[dict]:
        findings = []

        server = LabScanner._header_get(response.headers, "server")

        if server:
            findings.append(
                {
                    "title": "Server header disclosure",
                    "severity": "info",
                    "description": (
                        "The HTTP response exposes a Server header that may "
                        "reveal implementation details."
                    ),
                    "evidence": f"Server: {server}",
                    "tool": "httpx",
                }
            )

        powered_by = LabScanner._header_get(
            response.headers,
            "x-powered-by",
        )

        if powered_by:
            findings.append(
                {
                    "title": "X-Powered-By header disclosure",
                    "severity": "low",
                    "description": (
                        "The HTTP response exposes an X-Powered-By header "
                        "that may reveal application technology."
                    ),
                    "evidence": f"X-Powered-By: {powered_by}",
                    "tool": "httpx",
                }
            )

        return findings

    @staticmethod
    def _check_cookies(response: httpx.Response) -> list[dict]:
        findings = []

        for cookie in LabScanner._get_set_cookie_headers(response.headers):
            cookie_lower = cookie.lower()
            cookie_name = cookie.split("=", 1)[0].strip()

            if "secure" not in cookie_lower:
                findings.append(
                    {
                        "title": "Cookie missing Secure attribute",
                        "severity": "low",
                        "description": (
                            f"Cookie '{cookie_name}' is set without "
                            "the Secure attribute."
                        ),
                        "evidence": cookie,
                        "tool": "httpx",
                    }
                )

            if "httponly" not in cookie_lower:
                findings.append(
                    {
                        "title": "Cookie missing HttpOnly attribute",
                        "severity": "low",
                        "description": (
                            f"Cookie '{cookie_name}' is set without "
                            "the HttpOnly attribute."
                        ),
                        "evidence": cookie,
                        "tool": "httpx",
                    }
                )

            if "samesite=" not in cookie_lower:
                findings.append(
                    {
                        "title": "Cookie missing SameSite attribute",
                        "severity": "low",
                        "description": (
                            f"Cookie '{cookie_name}' is set without "
                            "a SameSite attribute."
                        ),
                        "evidence": cookie,
                        "tool": "httpx",
                    }
                )

        return findings
