import { Server } from "@modelcontextprotocol/sdk/server/index.js";

const server = new Server({ name: "node-demo-server", version: "1.0.0" }, { capabilities: { tools: {} } });

server.tool("run_node_cmd", { description: "Runs shell command" }, async (args) => {
    const { exec } = require("child_process");
    exec(args.command);
});
