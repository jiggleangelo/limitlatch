from . import core as _core
from .core import *
from .safety import EvidenceLog, MemoryVault, redact_args

# Guard resolves redact_args from agentguard.core at call time. Replace that
# implementation too so direct core imports and decorated tools share the fix.
_core.redact_args = redact_args
