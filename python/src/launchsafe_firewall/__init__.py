"""Python SDK for the LaunchSafe Agent Firewall's local API sidecar (docs/api-v0.md).

`Guard` / `AsyncGuard` decide each tool call and never raise from `authorize()`: every failure is a
decision from the contract's fail-closed table. `Client` / `AsyncClient` are the raw API.
Framework integrations live in `launchsafe_firewall.integrations` (optional extras).
"""

from ._core import FW_API_ERROR, FW_RATE_LIMITED, FW_UNAVAILABLE, Authorization, ReportOutcome, is_read_only
from .client import (
    DEFAULT_DECIDE_TIMEOUT,
    DEFAULT_TIMEOUT,
    AsyncClient,
    Client,
    default_socket_path,
    firewall_home,
    new_key,
)
from .errors import (
    FirewallAPIError,
    FirewallError,
    FirewallHTTPError,
    FirewallProtocolError,
    FirewallRateLimited,
    FirewallServerError,
    FirewallTimeout,
    FirewallUnavailable,
    FirewallUntrustedSocket,
    Problem,
)
from .formats import engine, from_anthropic_tool_use, from_mcp_call, from_openai_tool_call, native
from .guard import AsyncGuard, Guard
from .types import (
    Action,
    ApprovalRef,
    ApprovalState,
    ApprovalStatus,
    DecideContext,
    DecideRequest,
    Decision,
    EngineInfo,
    Health,
    LogRef,
    McpInfo,
    ModelUsage,
    Recorded,
    ResultRecorded,
    RuleHit,
    SessionInfo,
    Traffic,
    Verdict,
)

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_DECIDE_TIMEOUT",
    "DEFAULT_TIMEOUT",
    "FW_API_ERROR",
    "FW_RATE_LIMITED",
    "FW_UNAVAILABLE",
    "Action",
    "ApprovalRef",
    "ApprovalState",
    "ApprovalStatus",
    "AsyncClient",
    "AsyncGuard",
    "Authorization",
    "Client",
    "DecideContext",
    "DecideRequest",
    "Decision",
    "EngineInfo",
    "FirewallAPIError",
    "FirewallError",
    "FirewallHTTPError",
    "FirewallProtocolError",
    "FirewallRateLimited",
    "FirewallServerError",
    "FirewallTimeout",
    "FirewallUnavailable",
    "FirewallUntrustedSocket",
    "Guard",
    "Health",
    "LogRef",
    "McpInfo",
    "ModelUsage",
    "Problem",
    "Recorded",
    "ReportOutcome",
    "ResultRecorded",
    "RuleHit",
    "SessionInfo",
    "Traffic",
    "Verdict",
    "__version__",
    "default_socket_path",
    "engine",
    "firewall_home",
    "from_anthropic_tool_use",
    "from_mcp_call",
    "from_openai_tool_call",
    "is_read_only",
    "native",
    "new_key",
]
