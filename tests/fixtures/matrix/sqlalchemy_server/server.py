from mcp.server.fastmcp import FastMCP

mcp = FastMCP("sqlalchemy-server")

@mcp.tool()
def get_user(user_id: int):
    return session.query(User).filter(User.id == user_id).first()

if __name__ == "__main__":
    mcp.run()
