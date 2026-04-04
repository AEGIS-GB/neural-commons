import type { OpenClawPluginDefinition } from "openclaw/plugin-sdk";

const DEFAULT_AEGIS_URL = "http://127.0.0.1:3141";

function isLocalUrl(urlStr: string): boolean {
  try {
    const url = new URL(urlStr);
    return ["127.0.0.1", "localhost", "::1", "0.0.0.0"].includes(url.hostname);
  } catch { return false; }
}

async function aegisFetch(aegisUrl: string, path: string): Promise<Record<string, unknown>> {
  const resp = await fetch(`${aegisUrl}${path}`, { method: "GET", signal: AbortSignal.timeout(5000) });
  if (!resp.ok) return { error: `HTTP ${resp.status}`, path };
  return (await resp.json()) as Record<string, unknown>;
}

const plugin: OpenClawPluginDefinition = {
  id: "aegis-mesh-trust",
  name: "Aegis Mesh Trust",
  register(api) {
    const aegisUrl = (api.config?.plugins?.entries?.["aegis-mesh-trust"]?.aegisUrl as string) ?? DEFAULT_AEGIS_URL;
    if (!isLocalUrl(aegisUrl)) { console.error(`[aegis-mesh-trust] ERROR: not local. Disabled.`); return; }

    // NOTE: OpenClaw execute signature is (callId: string, params: object)
    api.registerTool?.({
      name: "aegis_check_peer",
      description: "Check a mesh peer's TRUSTMARK score, tier, and trust dimensions by bot ID.",
      parameters: { type: "object", properties: { bot_id: { type: "string", description: "64-char hex bot ID" } }, required: ["bot_id"] },
      async execute(_callId: string, params: { bot_id: string }) {
        try { return await aegisFetch(aegisUrl, `/aegis/peer/${encodeURIComponent(params.bot_id)}/trust`); }
        catch (err) { return { error: `failed: ${err}` }; }
      },
    });

    api.registerTool?.({
      name: "aegis_mesh_peers",
      description: "List all peers in the Aegis mesh with TRUSTMARK scores and online status.",
      parameters: { type: "object", properties: {} },
      async execute() {
        try { return await aegisFetch(aegisUrl, "/aegis/mesh/peers"); }
        catch (err) { return { error: `failed: ${err}` }; }
      },
    });

    api.registerTool?.({
      name: "aegis_botawiki_search",
      description: "Search Botawiki knowledge base by namespace prefix. Returns canonical claims.",
      parameters: { type: "object", properties: { namespace: { type: "string", description: "e.g. 'b/skills' or 'b/lore'" } }, required: ["namespace"] },
      async execute(_callId: string, params: { namespace: string }) {
        try { return await aegisFetch(aegisUrl, `/aegis/botawiki/search?ns=${encodeURIComponent(params.namespace)}`); }
        catch (err) { return { error: `failed: ${err}` }; }
      },
    });

    api.registerTool?.({
      name: "aegis_relay_inbox",
      description: "Read incoming relay messages from mesh peers.",
      parameters: { type: "object", properties: {} },
      async execute() {
        try { return await aegisFetch(aegisUrl, "/aegis/relay/inbox"); }
        catch (err) { return { error: `failed: ${err}` }; }
      },
    });

    console.log(`[aegis-mesh-trust] 4 tools registered (aegisUrl=${aegisUrl})`);
  },
};

export default plugin;
