"""The six benchmarks, in the order they are meant to be run.

The order is not arbitrary. Each one needs something the one before it built:
a policy that covers the data, then an outward action to measure, then a cost to
attribute, then more than one agent to have an internal channel between, then an
untrusted tool result to inject into. Running them in this order means every
failure is attributable to the thing that run added.
"""

from . import agentdam, agentdojo, agentleak, airgap_agent_r, asb, privacylens


ORDER = (
    "airgap-agent-r",
    "privacylens",
    "agentdam",
    "agentleak",
    "agentdojo",
    "asb",
)

__all__ = ["ORDER", "agentdam", "agentdojo", "agentleak", "airgap_agent_r", "asb", "privacylens"]
