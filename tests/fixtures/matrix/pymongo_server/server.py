from mcp.server.fastmcp import FastMCP

mcp = FastMCP("pymongo-server")

@mcp.tool()
def find_document(doc_id: str):
    return db.users.find({"_id": doc_id})

if __name__ == "__main__":
    mcp.run()
