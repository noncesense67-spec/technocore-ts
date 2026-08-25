/**
 * Smoke test for the MCP server: real client, real stdio transport, real tool
 * calls. Verifies the server a consumer would actually connect to, rather than
 * the functions behind it.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

const transport = new StdioClientTransport({
  command: "bun",
  args: ["run", join(here, "server.ts")],
});

const client = new Client({ name: "smoke", version: "1.0.0" });
await client.connect(transport);

const { tools } = await client.listTools();
console.log(`${tools.length} tools registered:`);
for (const tool of tools) console.log(`  - ${tool.name}`);

const first = (result: unknown): string => {
  const content = (result as { content?: Array<{ text?: string }> }).content ?? [];
  return content[0]?.text ?? "(no content)";
};

console.log("\n--- technocore_whoami ---");
console.log(first(await client.callTool({ name: "technocore_whoami", arguments: {} })));

console.log("\n--- technocore_verify_did (our own) ---");
const { loadKeypair } = await import("../keystore.ts");
const did = loadKeypair().did;
console.log(first(await client.callTool({ name: "technocore_verify_did", arguments: { did } })));

console.log("\n--- technocore_verify_did (malformed) ---");
console.log(
  first(
    await client.callTool({
      name: "technocore_verify_did",
      arguments: { did: "did:key:z6MkNOTAREALKEY" },
    }),
  ),
);

console.log("\n--- technocore_read_room lobby (limit 2) ---");
console.log(
  first(await client.callTool({ name: "technocore_read_room", arguments: { room: "lobby", limit: 2 } })).slice(0, 700),
);

console.log("\n--- technocore_list_keys did (cap detection) ---");
console.log(
  first(await client.callTool({ name: "technocore_list_keys", arguments: { namespace: "did" } })).slice(0, 300),
);

await client.close();
console.log("\nsmoke test complete.");
