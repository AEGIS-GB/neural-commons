/**
 * Aegis Channel Trust Plugin for OpenClaw
 *
 * Automatically registers channel context with Aegis on every incoming message.
 * Aegis uses the channel context to resolve trust levels from its [trust] config
 * and adjust screening sensitivity accordingly.
 *
 * Flow:
 *   1. Message arrives from Telegram/Discord/Slack/etc.
 *   2. This plugin fires on message_received hook
 *   3. Calls POST /aegis/register-channel with channel + user context
 *   4. Aegis maps channel to trust level (full/trusted/public/restricted)
 *   5. All subsequent proxy requests use that trust level
 *
 * The agent cannot fake its channel — context comes from OpenClaw's transport
 * layer, not from the LLM output.
 *
 * Install: openclaw plugins install ./plugins/aegis-channel-trust
 * Config:  plugins.entries.aegis-channel-trust.aegisUrl = "http://127.0.0.1:3141"
 */

import type { OpenClawPluginDefinition } from "openclaw/plugin-sdk";

const DEFAULT_AEGIS_URL = "http://127.0.0.1:3141";

const plugin: OpenClawPluginDefinition = {
  id: "aegis-channel-trust",
  name: "Aegis Channel Trust",

  register(api) {
    const aegisUrl = api.config?.plugins?.entries?.["aegis-channel-trust"]?.aegisUrl
      ?? DEFAULT_AEGIS_URL;

    let lastRegistered = "";

    // Register channel context on every incoming message
    api.on("message_received", async (event, ctx) => {
      const channelId = ctx.channelId || "unknown";
      const conversationId = ctx.conversationId || "default";
      const from = event.from || "unknown";

      // Build channel identifier: platform:conversation_type:id
      const channel = `${channelId}:${conversationId}`;
      const user = `${channelId}:user:${from}`;

      // Skip if same channel already registered (avoid redundant calls)
      const key = `${channel}:${user}`;
      if (key === lastRegistered) return;

      try {
        const resp = await fetch(`${aegisUrl}/aegis/register-channel`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ channel, user }),
          signal: AbortSignal.timeout(2000), // 2s timeout
        });

        if (resp.ok) {
          const data = await resp.json() as { trust_level: string; ssrf_allowed: boolean };
          lastRegistered = key;
          api.log?.debug?.(
            `Aegis channel registered: ${channel} → trust=${data.trust_level} ssrf=${data.ssrf_allowed}`
          );
        } else {
          api.log?.warn?.(`Aegis channel registration failed: HTTP ${resp.status}`);
        }
      } catch (err) {
        // Non-fatal — Aegis might not be running. Fail silently.
        api.log?.debug?.(`Aegis channel registration skipped: ${err}`);
      }
    });

    // Also register on session start (in case no message_received fires)
    api.on("session_start", async (_event, ctx) => {
      const channelId = ctx.channelId || "unknown";
      const channel = `${channelId}:session:${ctx.sessionId || "default"}`;
      const user = `${channelId}:agent:${ctx.agentId || "default"}`;

      try {
        await fetch(`${aegisUrl}/aegis/register-channel`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ channel, user }),
          signal: AbortSignal.timeout(2000),
        });
      } catch {
        // Non-fatal
      }
    });
  },
};

export default plugin;
