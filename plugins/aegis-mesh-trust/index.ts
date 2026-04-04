/**
 * Aegis Mesh Trust Plugin for OpenClaw
 *
 * Registers tools that let the agent query mesh trust data:
 *   - aegis_check_peer(bot_id) -- check a peer's TRUSTMARK score
 *   - aegis_mesh_peers()       -- list all mesh peers
 *   - aegis_botawiki_search(namespace) -- search Botawiki knowledge base
 *   - aegis_relay_inbox()      -- read incoming relay messages
 *
 * All calls go through the local Aegis proxy which forwards to the Gateway.
 *
 * Install: openclaw plugins install ./plugins/aegis-mesh-trust
 * Config:
 *   plugins.entries.aegis-mesh-trust.aegisUrl = "http://127.0.0.1:3141"
 */

import type { OpenClawPluginDefinition } from "openclaw/plugin-sdk";

const DEFAULT_AEGIS_URL = "http://127.0.0.1:3141";

/**
 * Validate that aegisUrl points to a local address only (SSRF prevention).
 */
function isLocalUrl(urlStr: string): boolean {
  try {
    const url = new URL(urlStr);
    const hostname = url.hostname;
    return (
      hostname === "127.0.0.1" ||
      hostname === "localhost" ||
      hostname === "::1" ||
      hostname === "0.0.0.0"
    );
  } catch {
    return false;
  }
}

/**
 * Call an Aegis proxy endpoint and return the parsed JSON response.
 */
async function aegisFetch(
  aegisUrl: string,
  path: string,
): Promise<Record<string, unknown>> {
  const resp = await fetch(`${aegisUrl}${path}`, {
    method: "GET",
    signal: AbortSignal.timeout(5000),
  });

  if (!resp.ok) {
    return { error: `HTTP ${resp.status}`, path };
  }
  return (await resp.json()) as Record<string, unknown>;
}

const plugin: OpenClawPluginDefinition = {
  id: "aegis-mesh-trust",
  name: "Aegis Mesh Trust",

  register(api) {
    const configuredUrl =
      api.config?.plugins?.entries?.["aegis-mesh-trust"]?.aegisUrl ??
      DEFAULT_AEGIS_URL;

    if (!isLocalUrl(configuredUrl as string)) {
      console.error(
        `[aegis-mesh-trust] ERROR: aegisUrl "${configuredUrl}" is not a local address. Plugin disabled.`,
      );
      return;
    }
    const aegisUrl = configuredUrl as string;

    // -- Tool: aegis_check_peer --
    api.registerTool?.({
      name: "aegis_check_peer",
      description:
        "Check a mesh peer's TRUSTMARK score and trust data by bot ID.",
      parameters: {
        type: "object",
        properties: {
          bot_id: {
            type: "string",
            description: "The bot ID of the peer to check",
          },
        },
        required: ["bot_id"],
      },
      async execute(params: { bot_id: string }) {
        try {
          return await aegisFetch(
            aegisUrl,
            `/aegis/peer/${encodeURIComponent(params.bot_id)}/trust`,
          );
        } catch (err) {
          return { error: `aegis_check_peer failed: ${err}` };
        }
      },
    });

    // -- Tool: aegis_mesh_peers --
    api.registerTool?.({
      name: "aegis_mesh_peers",
      description: "List all peers currently known to the Aegis mesh.",
      parameters: { type: "object", properties: {} },
      async execute() {
        try {
          return await aegisFetch(aegisUrl, "/aegis/mesh/peers");
        } catch (err) {
          return { error: `aegis_mesh_peers failed: ${err}` };
        }
      },
    });

    // -- Tool: aegis_botawiki_search --
    api.registerTool?.({
      name: "aegis_botawiki_search",
      description:
        "Search the Botawiki knowledge base by namespace. Returns articles and trust metadata.",
      parameters: {
        type: "object",
        properties: {
          namespace: {
            type: "string",
            description:
              "Namespace to search (e.g. 'safety', 'tools', 'recipes')",
          },
        },
        required: ["namespace"],
      },
      async execute(params: { namespace: string }) {
        try {
          return await aegisFetch(
            aegisUrl,
            `/aegis/botawiki/search?ns=${encodeURIComponent(params.namespace)}`,
          );
        } catch (err) {
          return { error: `aegis_botawiki_search failed: ${err}` };
        }
      },
    });

    // -- Tool: aegis_relay_inbox --
    api.registerTool?.({
      name: "aegis_relay_inbox",
      description:
        "Read incoming relay messages from other mesh peers. Messages are marked as read after fetching.",
      parameters: { type: "object", properties: {} },
      async execute() {
        try {
          return await aegisFetch(aegisUrl, "/aegis/relay/inbox");
        } catch (err) {
          return { error: `aegis_relay_inbox failed: ${err}` };
        }
      },
    });

    console.log(
      "[aegis-mesh-trust] registered 4 tools: aegis_check_peer, aegis_mesh_peers, aegis_botawiki_search, aegis_relay_inbox",
    );
  },
};

export default plugin;
