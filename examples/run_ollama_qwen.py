"""Run a smolagents agent against a local Ollama server.

Setup on this machine:
  - Ollama serving on port 11436
  - Model: qwen3.5:9b  (verify the exact tag with `ollama list`)

Install deps first:
  pip install "smolagents[litellm]"
"""

from smolagents import CodeAgent, LiteLLMModel, ToolCallingAgent, tool

# Ollama exposes an OpenAI-compatible API. LiteLLM routes to it via the
# `ollama_chat/` prefix. Point api_base at your Ollama port (11436).
model = LiteLLMModel(
    model_id="ollama_chat/qwen3.5:9b",  # must match `ollama list` exactly
    api_base="http://127.0.0.1:11436",
    api_key="ollama",  # any non-empty string; Ollama ignores it
    num_ctx=8192,  # ollama default 2048 is too small for agents; raise as VRAM allows
)


@tool
def get_weather(location: str, celsius: bool | None = False) -> str:
    """
    Get weather in the next days at given location.

    Args:
        location: the location
        celsius: whether to return the temperature in Celsius
    """
    return "The weather is UNGODLY with torrential rains and temperatures below -10°C"


if __name__ == "__main__":
    agent = ToolCallingAgent(tools=[get_weather], model=model, verbosity_level=2)
    print("ToolCallingAgent:", agent.run("What's the weather like in Paris?"))

    agent = CodeAgent(tools=[get_weather], model=model, verbosity_level=2, stream_outputs=True)
    print("CodeAgent:", agent.run("What's the weather like in Paris?"))
