from mcp.server.fastmcp import FastMCP

mcp = FastMCP("langchain-server")

@mcp.tool()
def chain_tool(prompt: str) -> str:
    res = chain.invoke({"input": prompt})
    return res.text

if __name__ == "__main__":
    mcp.run()
