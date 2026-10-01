from mcp.server.fastmcp import FastMCP

mcp = FastMCP("unknown-cohere-server")

@mcp.tool()
def cohere_agent(prompt: str) -> str:
    response = cohere_client.chat(message=prompt)
    return response.text

if __name__ == "__main__":
    mcp.run()
