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
const DEFAULT_KEY_PATH = "/home/aegis/aegis/neural-commons/.aegis/identity.key";

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
    console.log("[aegis-channel-trust] plugin register() called");
    console.log("[aegis-channel-trust] api.on type:", typeof api.on);
    console.log("[aegis-channel-trust] api keys:", Object.keys(api).join(", "));
    const aegisUrl =
      api.config?.plugins?.entries?.["aegis-channel-trust"]?.aegisUrl ??
      DEFAULT_AEGIS_URL;
    const keyPath =
      api.config?.plugins?.entries?.["aegis-channel-trust"]?.identityKeyPath ??
      DEFAULT_KEY_PATH;

    // No caching — always register. Aegis may restart and lose the
    // ACTIVE_CHANNEL state. The registration call is <2ms and signed,
    // so repeating it is cheap and safe.
    let secretKey: Buffer | null = null;

    // Try to load the identity key for signing — search multiple paths
    const searchPaths = [
      keyPath,
      path.join(process.cwd(), ".aegis", "identity.key"),
      path.join(process.env.HOME || "", ".aegis", "data", "identity.key"),
      path.join(process.env.HOME || "", "aegis", "neural-commons", ".aegis", "identity.key"),
    ];
    console.log("[aegis-channel-trust] searching for identity key:", searchPaths.map(p => path.resolve(p)).join(", "));
    for (const candidate of searchPaths) {
      try {
        const resolvedPath = path.resolve(candidate);
        if (fs.existsSync(resolvedPath)) {
          const key = fs.readFileSync(resolvedPath);
          console.log(`[aegis-channel-trust] found key at ${resolvedPath}: ${key.length} bytes`);
          if (key.length === 32) {
            secretKey = key;
            console.log(`[aegis-channel-trust] identity key loaded OK`);
            break;
          }
        }
      } catch (err) {
        console.log(`[aegis-channel-trust] key search error: ${err}`);
      }
    }
    if (!secretKey) {
      console.log("[aegis-channel-trust] WARNING: identity key not found — registrations will be unsigned");
    }

    async function registerChannel(channel: string, user: string) {

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

    // Register channel on message_received — fires when a real message arrives
    api.on("message_received", async (event: any, ctx: any) => {
      const channelId = ctx.channelId || "unknown";
      const conversationId = ctx.conversationId || "default";
      // event.metadata.senderId has the clean numeric ID
      const senderId = event?.metadata?.senderId || event?.from || "unknown";

      // Detect conversation type (refined after stripping prefix)
      let chatType = "chat";
      if (channelId === "discord") {
        chatType = "channel";
      } else if (channelId === "whatsapp") {
        chatType = conversationId.includes("@g.us") ? "group" : "dm";
      }

      // Strip platform prefix from conversationId (e.g. "telegram:7965174951" → "7965174951")
      const cleanConvId = conversationId.startsWith(`${channelId}:`)
        ? conversationId.slice(channelId.length + 1)
        : conversationId;

      // For DM/group detection, use the clean numeric ID
      const numId = parseInt(cleanConvId, 10);
      if (channelId === "telegram" && !isNaN(numId)) {
        chatType = numId < 0 ? "group" : "dm";
      }

      // Normalize platform name: "web" and "openclaw" both map to "openclaw"
      // so channel matches config pattern "openclaw:web:*"
      let platform = channelId;
      if (channelId === "web" || channelId === "openclaw" || channelId === "webchat") {
        platform = "openclaw";
        chatType = "web";
      }

      const channel = `${platform}:${chatType}:${cleanConvId}`;
      const user = `${platform}:user:${senderId}`;

      await registerChannel(channel, user);
    });
  },
};

export default plugin;
