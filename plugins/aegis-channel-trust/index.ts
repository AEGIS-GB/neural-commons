/**
 * Aegis Channel Trust Plugin for OpenClaw
 *
 * Automatically registers channel context with Aegis on every incoming message.
 * Signs registrations with the bot's Ed25519 identity key for authentication.
 *
 * Flow:
 *   1. Message arrives from Telegram/Discord/Slack/etc.
 *   2. This plugin fires on message_received hook
 *   3. Signs {channel, user, ts} with the bot's Ed25519 key
 *   4. Calls POST /aegis/register-channel with signed payload
 *   5. Aegis verifies signature, resolves trust level
 *   6. All subsequent proxy requests use that trust level
 *
 * The registration is signed — a rogue process cannot fake a channel.
 *
 * Install: openclaw plugins install ./plugins/aegis-channel-trust
 * Config:
 *   plugins.entries.aegis-channel-trust.aegisUrl = "http://127.0.0.1:3141"
 *   plugins.entries.aegis-channel-trust.identityKeyPath = ".aegis/identity.key"
 */

import type { OpenClawPluginDefinition } from "openclaw/plugin-sdk";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const DEFAULT_AEGIS_URL = "http://127.0.0.1:3141";
const DEFAULT_KEY_PATH = ".aegis/identity.key";

/**
 * Sign a channel registration payload with Ed25519.
 * Returns hex-encoded signature.
 */
function signRegistration(
  channel: string,
  user: string,
  ts: number,
  secretKeyBytes: Buffer
): string {
  // Build canonical payload — keys MUST be sorted alphabetically
  // to match Rust's BTreeMap ordering in verify_cert
  const payload = JSON.stringify({ channel, trust: "", ts, user });
  const payloadBytes = Buffer.from(payload, "utf-8");

  // Ed25519 signing with Node.js crypto
  // The secret key is 32 bytes (seed), need to create the full keypair
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([
      // PKCS8 DER prefix for Ed25519
      Buffer.from("302e020100300506032b657004220420", "hex"),
      secretKeyBytes,
    ]),
    format: "der",
    type: "pkcs8",
  });

  const sig = crypto.sign(null, payloadBytes, privateKey);
  return sig.toString("hex");
}

const plugin: OpenClawPluginDefinition = {
  id: "aegis-channel-trust",
  name: "Aegis Channel Trust",

  register(api) {
    const aegisUrl =
      api.config?.plugins?.entries?.["aegis-channel-trust"]?.aegisUrl ??
      DEFAULT_AEGIS_URL;
    const keyPath =
      api.config?.plugins?.entries?.["aegis-channel-trust"]?.identityKeyPath ??
      DEFAULT_KEY_PATH;

    let lastRegistered = "";
    let secretKey: Buffer | null = null;

    // Try to load the identity key for signing
    try {
      const resolvedPath = path.resolve(process.cwd(), keyPath);
      if (fs.existsSync(resolvedPath)) {
        secretKey = fs.readFileSync(resolvedPath);
        if (secretKey.length === 32) {
          api.log?.info?.(`Aegis: loaded identity key from ${resolvedPath}`);
        } else {
          api.log?.warn?.(
            `Aegis: identity key at ${resolvedPath} is ${secretKey.length} bytes (expected 32)`
          );
          secretKey = null;
        }
      } else {
        api.log?.debug?.(
          `Aegis: no identity key at ${resolvedPath} — registrations will be unsigned`
        );
      }
    } catch (err) {
      api.log?.debug?.(`Aegis: could not load identity key: ${err}`);
    }

    async function registerChannel(channel: string, user: string) {
      const key = `${channel}:${user}`;
      if (key === lastRegistered) return;

      const ts = Date.now();
      const body: Record<string, unknown> = { channel, user, ts };

      // Sign if we have the identity key
      if (secretKey) {
        try {
          body.sig = signRegistration(channel, user, ts, secretKey);
        } catch (err) {
          api.log?.debug?.(`Aegis: signing failed: ${err}`);
        }
      }

      try {
        const resp = await fetch(`${aegisUrl}/aegis/register-channel`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(2000),
        });

        if (resp.ok) {
          const data = (await resp.json()) as {
            trust_level: string;
            ssrf_allowed: boolean;
          };
          lastRegistered = key;
          api.log?.debug?.(
            `Aegis: registered ${channel} → trust=${data.trust_level} signed=${!!secretKey}`
          );
        } else {
          const text = await resp.text().catch(() => "");
          api.log?.warn?.(
            `Aegis: registration failed: HTTP ${resp.status} ${text.substring(0, 100)}`
          );
        }
      } catch (err) {
        api.log?.debug?.(`Aegis: registration skipped: ${err}`);
      }
    }

    // Register channel context on every incoming message
    api.on("message_received", async (event, ctx) => {
      const channelId = ctx.channelId || "unknown";
      const conversationId = ctx.conversationId || "default";
      const from = event.from || "unknown";

      // Detect conversation type
      let chatType = "chat";
      const convNum = parseInt(conversationId, 10);
      if (channelId === "telegram") {
        chatType =
          convNum < 0 || conversationId.startsWith("-") ? "group" : "dm";
      } else if (channelId === "discord") {
        chatType = "channel";
      } else if (channelId === "whatsapp") {
        chatType = conversationId.includes("@g.us") ? "group" : "dm";
      }

      // Strip platform prefix from conversationId
      const cleanConvId = conversationId.startsWith(`${channelId}:`)
        ? conversationId.slice(channelId.length + 1)
        : conversationId;

      const channel = `${channelId}:${chatType}:${cleanConvId}`;
      const user = `${channelId}:user:${from}`;

      await registerChannel(channel, user);
    });

    // Also register on session start
    api.on("session_start", async (_event, ctx) => {
      const channelId = ctx.channelId || "unknown";
      const channel = `${channelId}:session:${ctx.sessionId || "default"}`;
      const user = `${channelId}:agent:${ctx.agentId || "default"}`;
      await registerChannel(channel, user);
    });
  },
};

export default plugin;
