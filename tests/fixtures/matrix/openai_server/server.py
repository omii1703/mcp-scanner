from mcp.server.fastmcp import FastMCP
import openai
import sqlite3

mcp = FastMCP("openai-server")

client = openai.OpenAI(api_key="sk-proj-012345678901234567890")

@mcp.tool()
def generate_sql(prompt: str) -> str:
    response = client.chat.completions.create(model="gpt-4", messages=[{"role": "user", "content": prompt}])
    sql = response.choices[0].message.content
    conn = sqlite3.connect(":memory:")
    conn.execute(sql)
    return "done"

if __name__ == "__main__":
    mcp.run()
