#!/usr/bin/env bash
# provision.sh: Cloudflare side of the Proxmox MCP build (V2: Worker in front, Windows broker behind).
# Run from an admin workstation. Idempotent: every object is looked up before it is created.
#
#   Claude -> MCP server portal -> Access app (Worker hostname, Managed OAuth, named users, Entra)
#          -> Worker "proxmox-mcp" -> [vpc]    Workers VPC Service -> broker tunnel -> 127.0.0.1:8765
#                                     [access] broker hostname -> Access app (service token only)
#                                              -> broker tunnel (access.required) -> 127.0.0.1:8765
#
# Workers VPC is BETA (Cloudflare docs, 2026-10). BROKER_MODE=access is the fully scripted fallback.
#
# Secrets never appear in argv or on stdout:
#   - Cloudflare API token: env CF_API_TOKEN or one line on stdin. Sent to curl as a header file
#     through a process substitution, and to wrangler as CLOUDFLARE_API_TOKEN (environment).
#   - Ed25519 identity key: generated in a pipe; the private key goes straight into
#     `wrangler secret put IDENTITY_SIGNING_KEY` (stdin); the public key goes to the broker.
#   - Access service token secret (access mode): straight into `wrangler secret put` (stdin).
#   - Tunnel token: straight into Install-Cloudflared.ps1 -TokenOnly on the broker over SSH (stdin),
#     or into a 0600 file when BROKER_SSH is not set.
#
# Required variables:
#   ACCOUNT_ID ZONE_ID WORKER_HOSTNAME TEAM_DOMAIN (https://<team>.cloudflareaccess.com)
#   IDP_ID (Entra IdP id) ALLOWED_EMAILS (comma list) PORTAL_ID SERVER_ID (a-z0-9-, <= 32)
#   WORKER_DIR (path to worker/) AUDIT_BUCKET (R2 bucket name)
# access mode also: BROKER_HOSTNAME
# Optional:
#   BROKER_MODE=vpc|access (vpc)  ORIGIN_PORT (8765)  TUNNEL_NAME (proxmox-mcp-broker)
#   BROKER_SSH (user@broker, OpenSSH server on Windows with pwsh)  STATE_DIR (~/.proxmox-mcp)
#   RATELIMIT_NAMESPACE_ID (1001)  DEPLOY_WORKER=1  ROTATE_IDENTITY_KEY=1  ROTATE_SERVICE_TOKEN=1
#   SESSION_DURATION (8h)  ACCESS_TOKEN_LIFETIME (10m)  DRY_RUN=1  STEPS (all; or e.g. "verify")
#
# API token permissions: Account: Cloudflare Tunnel Edit, Access: Apps and Policies Edit,
#   Access: Service Tokens Edit, Access: Organizations Read, Connectivity Directory Admin (vpc),
#   Workers Scripts Edit, Workers R2 Storage Edit, Zero Trust (MCP portals) Edit; Zone: DNS Edit.
set -euo pipefail
umask 077

API="https://api.cloudflare.com/client/v4"
DRY_RUN="${DRY_RUN:-0}"
BROKER_MODE="${BROKER_MODE:-vpc}"
ORIGIN_PORT="${ORIGIN_PORT:-8765}"
TUNNEL_NAME="${TUNNEL_NAME:-proxmox-mcp-broker}"
VPC_SERVICE_NAME="${VPC_SERVICE_NAME:-proxmox-mcp-broker}"
SERVICE_TOKEN_NAME="${SERVICE_TOKEN_NAME:-proxmox-mcp-worker}"
WORKER_NAME="${WORKER_NAME:-proxmox-mcp}"
SESSION_DURATION="${SESSION_DURATION:-8h}"
ACCESS_TOKEN_LIFETIME="${ACCESS_TOKEN_LIFETIME:-10m}"
RATELIMIT_NAMESPACE_ID="${RATELIMIT_NAMESPACE_ID:-1001}"
STATE_DIR="${STATE_DIR:-$HOME/.proxmox-mcp}"
STEPS="${STEPS:-all}"
BROKER_SSH="${BROKER_SSH:-}"
BROKER_HOSTNAME="${BROKER_HOSTNAME:-}"
readonly RETENTION_SECONDS=$((2190 * 86400))
readonly CLAUDE_CALLBACKS='["https://claude.ai/api/mcp/auth_callback","https://claude.com/api/mcp/auth_callback"]'
readonly BROKER_SCRIPTS='C:\Program Files\ProxmoxMCP\scripts'

log() { printf '==> %s\n' "$*" >&2; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
want() { [[ "$STEPS" == "all" || " $STEPS " == *" $1 "* ]]; }

need() { [[ -n "${!1:-}" ]] || die "set $1"; }
for t in curl jq openssl; do command -v "$t" >/dev/null 2>&1 || die "$t is required"; done

for v in ACCOUNT_ID ZONE_ID WORKER_HOSTNAME TEAM_DOMAIN IDP_ID ALLOWED_EMAILS PORTAL_ID SERVER_ID WORKER_DIR AUDIT_BUCKET; do need "$v"; done
[[ "$ACCOUNT_ID" =~ ^[0-9a-f]{32}$ ]] || die "ACCOUNT_ID must be 32 hex"
[[ "$ZONE_ID" =~ ^[0-9a-f]{32}$ ]] || die "ZONE_ID must be 32 hex"
[[ "$TEAM_DOMAIN" =~ ^https://([a-z0-9-]+)\.cloudflareaccess\.com$ ]] || die "TEAM_DOMAIN must be https://<team>.cloudflareaccess.com"
TEAM_NAME="${BASH_REMATCH[1]}"   # tunnel originRequest.access.teamName wants the short name
[[ "$SERVER_ID" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ && ${#SERVER_ID} -le 32 ]] || die "SERVER_ID must match ^[a-z0-9]+(-[a-z0-9]+)*$, max 32"
[[ "$ORIGIN_PORT" =~ ^[0-9]+$ ]] || die "ORIGIN_PORT must be a number"
[[ "$BROKER_MODE" == "vpc" || "$BROKER_MODE" == "access" ]] || die "BROKER_MODE must be vpc or access"
[[ "$WORKER_HOSTNAME" =~ ^[a-z0-9.-]+$ ]] || die "bad WORKER_HOSTNAME"
if [[ "$BROKER_MODE" == "access" ]]; then
  need BROKER_HOSTNAME
  [[ "$BROKER_HOSTNAME" =~ ^[a-z0-9.-]+$ ]] || die "bad BROKER_HOSTNAME"
fi
EMAILS_JSON="$(printf '%s' "$ALLOWED_EMAILS" | tr '[:upper:]' '[:lower:]' | jq -R 'split(",") | map(gsub("^\\s+|\\s+$";"")) | map(select(length>0))')"
[[ "$(jq 'length' <<<"$EMAILS_JSON")" -ge 1 ]] || die "ALLOWED_EMAILS is empty"
jq -e 'all(test("^[a-z0-9._%+-]+@[a-z0-9-]+(\\.[a-z0-9-]+)+$"))' <<<"$EMAILS_JSON" >/dev/null || die "ALLOWED_EMAILS has an invalid address"

mkdir -p "$STATE_DIR"
STATE_FILE="$STATE_DIR/${WORKER_HOSTNAME}.json"     # non-secret ids only
[[ -f "$STATE_FILE" ]] || echo '{}' >"$STATE_FILE"
state_get() { jq -r --arg k "$1" '.[$k] // empty' "$STATE_FILE"; }
state_set() { local t; t="$(mktemp "$STATE_DIR/.st.XXXXXX")"; jq --arg k "$1" --arg v "$2" '.[$k]=$v' "$STATE_FILE" >"$t" && mv "$t" "$STATE_FILE"; }

# ---- API token: environment or stdin, never argv ------------------------------------
if [[ -z "${CF_API_TOKEN:-}" ]]; then
  if [[ -t 0 ]]; then read -r -s -p "Cloudflare API token: " CF_API_TOKEN; echo >&2; else read -r CF_API_TOKEN; fi
fi
[[ -n "$CF_API_TOKEN" ]] || die "no Cloudflare API token"
auth_header() { printf 'Authorization: Bearer %s\n' "$CF_API_TOKEN"; }

# api METHOD PATH [JSON]  -> prints .result ; fails on success=false. Writes are skipped in DRY_RUN.
api() {
  local method="$1" path="$2" body="${3:-}" out code
  if [[ "$DRY_RUN" == "1" && "$method" != "GET" ]]; then
    log "DRY_RUN $method $path"
    [[ -n "$body" ]] && jq . <<<"$body" >&2
    echo 'null'
    return 0
  fi
  out="$(mktemp)"
  local args=(-sS --proto '=https' --tlsv1.2 -o "$out" -w '%{http_code}' -X "$method" "$API$path")
  if [[ -n "$body" ]]; then args+=(-H 'Content-Type: application/json' --data-binary @-); fi
  # The header comes from a process substitution on the curl command itself: the token is in
  # no argv and no file.
  if [[ -n "$body" ]]; then
    code="$(curl "${args[@]}" -H @<(auth_header) <<<"$body")"
  else
    code="$(curl "${args[@]}" -H @<(auth_header))"
  fi
  if ! jq -e '.success == true' "$out" >/dev/null 2>&1; then
    printf 'API %s %s failed (HTTP %s): %s\n' "$method" "$path" "$code" "$(jq -c '.errors // .' "$out" 2>/dev/null | head -c 600)" >&2
    rm -f "$out"
    return 1
  fi
  jq -c '.result' "$out"
  rm -f "$out"
}
# Like api, but prints nothing and returns 1 on HTTP 404 (lookups).
api_get_opt() { api GET "$1" 2>/dev/null || return 1; }

wrangler() {
  # CLOUDFLARE_API_TOKEN in the environment of this one process; never in argv.
  (cd "$WORKER_DIR" && CLOUDFLARE_API_TOKEN="$CF_API_TOKEN" CLOUDFLARE_ACCOUNT_ID="$ACCOUNT_ID" npx --no-install wrangler "$@")
}

# ---- 0. Preflight -------------------------------------------------------------------
if want preflight; then
  log "Preflight: Zero Trust organization and IdP"
  auth_domain="$(api GET "/accounts/$ACCOUNT_ID/access/organizations" | jq -r '.auth_domain // empty')"
  [[ "$auth_domain" == "${TEAM_DOMAIN#https://}" ]] || die "TEAM_DOMAIN does not match the account's auth_domain"
  idp_type="$(api GET "/accounts/$ACCOUNT_ID/access/identity_providers/$IDP_ID" | jq -r '.type // empty')"
  [[ "$idp_type" == "azureAD" ]] || warn "IdP $IDP_ID has type '$idp_type', expected azureAD (Entra ID)"
  [[ -f "$WORKER_DIR/wrangler.jsonc" ]] || die "WORKER_DIR has no wrangler.jsonc"
fi

# ---- 1. Tunnel (remote-managed) -----------------------------------------------------------
TUNNEL_ID="$(state_get tunnel_id)"
if want tunnel; then
  log "Tunnel $TUNNEL_NAME"
  t="$(api GET "/accounts/$ACCOUNT_ID/cfd_tunnel?name=$TUNNEL_NAME&is_deleted=false")"
  TUNNEL_ID="$(jq -r --arg n "$TUNNEL_NAME" '[.[] | select(.name==$n)][0].id // empty' <<<"$t")"
  if [[ -n "$TUNNEL_ID" ]]; then
    src="$(jq -r --arg n "$TUNNEL_NAME" '[.[] | select(.name==$n)][0] | ((.remote_config == true) or (.config_src == "cloudflare"))' <<<"$t")"
    [[ "$src" == "true" ]] || die "tunnel $TUNNEL_NAME exists but is locally managed; use another TUNNEL_NAME"
  else
    TUNNEL_ID="$(api POST "/accounts/$ACCOUNT_ID/cfd_tunnel" "$(jq -n --arg n "$TUNNEL_NAME" '{name:$n, config_src:"cloudflare"}')" | jq -r '.id // empty')"
  fi
  [[ -n "$TUNNEL_ID" || "$DRY_RUN" == "1" ]] || die "no tunnel id"
  [[ -z "$TUNNEL_ID" ]] || state_set tunnel_id "$TUNNEL_ID"
fi

# Look up a self-hosted Access app by exact domain; print its JSON or nothing.
find_app() { api GET "/accounts/$ACCOUNT_ID/access/apps?domain=$1" | jq -c --arg d "$1" '[.[] | select(.domain==$d)][0] // empty'; }

# Create or converge an app. Existing apps get a PUT only when a managed field drifted;
# the PUT carries the existing policy links so they are not dropped.
ensure_app() {
  local domain="$1" body="$2" app id
  app="$(find_app "$domain")"
  if [[ -z "$app" ]]; then
    api POST "/accounts/$ACCOUNT_ID/access/apps" "$body"
    return
  fi
  id="$(jq -r .id <<<"$app")"
  if jq -e --argjson want "$body" 'to_entries | map(select(.key as $k | $want | has($k))) | from_entries == ($want | with_entries(select(.key != "policies")))' <<<"$app" >/dev/null 2>&1; then
    printf '%s' "$app"
    return
  fi
  log "Access app for $domain drifted; converging"
  body="$(jq -c --argjson cur "$app" '. + {policies: [($cur.policies // [])[] | {id, precedence}]}' <<<"$body")"
  api PUT "/accounts/$ACCOUNT_ID/access/apps/$id" "$body"
}

# Create or replace the single named policy of an app.
ensure_policy() {
  local app_id="$1" body="$2" name pid
  name="$(jq -r .name <<<"$body")"
  pid="$(api GET "/accounts/$ACCOUNT_ID/access/apps/$app_id/policies" | jq -r --arg n "$name" '[.[] | select(.name==$n)][0].id // empty')"
  if [[ -n "$pid" ]]; then
    api PUT "/accounts/$ACCOUNT_ID/access/apps/$app_id/policies/$pid" "$body" >/dev/null
  else
    api POST "/accounts/$ACCOUNT_ID/access/apps/$app_id/policies" "$body" >/dev/null
  fi
}

ensure_cname() {
  local name="$1" target="$2" rec
  rec="$(api GET "/zones/$ZONE_ID/dns_records?name=$name" | jq -c '.[0] // empty')"
  if [[ -z "$rec" ]]; then
    api POST "/zones/$ZONE_ID/dns_records" "$(jq -n --arg n "$name" --arg c "$target" '{type:"CNAME",name:$n,content:$c,proxied:true,ttl:1,comment:"Proxmox MCP broker tunnel"}')" >/dev/null
  elif [[ "$(jq -r '.type + " " + .content + " " + (.proxied|tostring)' <<<"$rec")" != "CNAME $target true" ]]; then
    die "DNS record $name exists with other content; fix it by hand"
  fi
}

# ---- 2. Broker path ------------------------------------------------------------------------
BROKER_AUD="$(state_get broker_aud)"
if want broker; then
  if [[ "$BROKER_MODE" == "vpc" ]]; then
    log "Workers VPC Service $VPC_SERVICE_NAME -> 127.0.0.1:$ORIGIN_PORT via tunnel (beta)"
    VPC_ID="$(api GET "/accounts/$ACCOUNT_ID/connectivity/directory/services?type=http&per_page=100" | jq -r --arg n "$VPC_SERVICE_NAME" '[.[] | select(.name==$n)][0].service_id // empty')"
    body="$(jq -n --arg n "$VPC_SERVICE_NAME" --arg t "$TUNNEL_ID" --argjson p "$ORIGIN_PORT" \
      '{type:"http", name:$n, http_port:$p, host:{ipv4:"127.0.0.1", network:{tunnel_id:$t}}}')"
    if [[ -z "$VPC_ID" ]]; then
      VPC_ID="$(api POST "/accounts/$ACCOUNT_ID/connectivity/directory/services" "$body" | jq -r '.service_id // empty')"
    else
      api PUT "/accounts/$ACCOUNT_ID/connectivity/directory/services/$VPC_ID" "$body" >/dev/null
    fi
    [[ -z "$VPC_ID" ]] || state_set vpc_service_id "$VPC_ID"
  else
    log "Access fallback: service token, broker Access app (service token only), DNS"
    st="$(api GET "/accounts/$ACCOUNT_ID/access/service_tokens?name=$SERVICE_TOKEN_NAME" | jq -c --arg n "$SERVICE_TOKEN_NAME" '[.[] | select(.name==$n)][0] // empty')"
    ST_ID=""
    if [[ -n "$st" ]]; then ST_ID="$(jq -r '.id // empty' <<<"$st")"; fi
    secret_json=""
    if [[ -z "$ST_ID" ]]; then
      secret_json="$(api POST "/accounts/$ACCOUNT_ID/access/service_tokens" "$(jq -n --arg n "$SERVICE_TOKEN_NAME" '{name:$n, duration:"8760h"}')")"
      ST_ID="$(jq -r '.id // empty' <<<"$secret_json")"
    elif [[ "${ROTATE_SERVICE_TOKEN:-0}" == "1" ]]; then
      secret_json="$(api POST "/accounts/$ACCOUNT_ID/access/service_tokens/$ST_ID/rotate" '{}')"
    fi
    if [[ -n "$secret_json" && "$secret_json" != "null" ]]; then
      jq -r '.client_id' <<<"$secret_json" | wrangler secret put BROKER_ACCESS_CLIENT_ID --name "$WORKER_NAME" >&2
      jq -r '.client_secret' <<<"$secret_json" | wrangler secret put BROKER_ACCESS_CLIENT_SECRET --name "$WORKER_NAME" >&2
      state_set service_token_client_id "$(jq -r '.client_id' <<<"$secret_json")"
      secret_json=""
    fi
    [[ -z "$ST_ID" ]] || state_set service_token_id "$ST_ID"
    app_body="$(jq -n --arg d "$BROKER_HOSTNAME" '{name:"Proxmox MCP broker (service token only)", domain:$d, type:"self_hosted",
      session_duration:"10m", app_launcher_visible:false, auto_redirect_to_identity:false, service_auth_401_redirect:true}')"
    app="$(ensure_app "$BROKER_HOSTNAME" "$app_body")"
    BROKER_APP_ID="$(jq -r '.id // empty' <<<"$app")"; BROKER_AUD="$(jq -r '.aud // empty' <<<"$app")"
    if [[ -n "$BROKER_APP_ID" ]]; then
      ensure_policy "$BROKER_APP_ID" "$(jq -n --arg t "$ST_ID" '{name:"proxmox-mcp worker service token", decision:"non_identity", include:[{service_token:{token_id:$t}}]}')"
      state_set broker_aud "$BROKER_AUD"
    fi
    ensure_cname "$BROKER_HOSTNAME" "$TUNNEL_ID.cfargotunnel.com"
  fi
fi

# ---- 3. Tunnel configuration ---------------------------------------------------------------------
if want tunnel; then
  if [[ "$BROKER_MODE" == "vpc" ]]; then
    # No public hostname at all. The VPC Service routes to 127.0.0.1:<port> through this tunnel.
    cfg='{"config":{"ingress":[{"service":"http_status:404"}],"warp-routing":{"enabled":false}}}'
  else
    [[ -n "$BROKER_AUD" || "$DRY_RUN" == "1" ]] || die "broker AUD unknown; run STEPS=broker first"
    cfg="$(jq -n --arg h "$BROKER_HOSTNAME" --arg s "http://127.0.0.1:$ORIGIN_PORT" --arg team "$TEAM_NAME" --arg aud "$BROKER_AUD" \
      '{config:{ingress:[{hostname:$h, service:$s, originRequest:{access:{required:true, teamName:$team, audTag:[$aud]}, connectTimeout:30, noHappyEyeballs:true}},
                         {service:"http_status:404"}], "warp-routing":{enabled:false}}}')"
  fi
  log "Tunnel ingress ($BROKER_MODE)"
  api PUT "/accounts/$ACCOUNT_ID/cfd_tunnel/$TUNNEL_ID/configurations" "$cfg" >/dev/null
fi

# ---- 4. Access app for the Worker hostname (Managed OAuth, named users, Entra) -------------------
WORKER_AUD="$(state_get worker_aud)"
if want access; then
  log "Access app $WORKER_HOSTNAME: session $SESSION_DURATION, OAuth grant $SESSION_DURATION, access token $ACCESS_TOKEN_LIFETIME"
  app_body="$(jq -n --arg d "$WORKER_HOSTNAME" --arg idp "$IDP_ID" --arg sd "$SESSION_DURATION" --arg atl "$ACCESS_TOKEN_LIFETIME" --argjson cb "$CLAUDE_CALLBACKS" \
    '{name:"Proxmox MCP", domain:$d, type:"self_hosted", session_duration:$sd, allowed_idps:[$idp],
      auto_redirect_to_identity:true, app_launcher_visible:false,
      oauth_configuration:{enabled:true, grant:{session_duration:$sd, access_token_lifetime:$atl},
        dynamic_client_registration:{enabled:true, allowed_uris:$cb, allow_any_on_localhost:true, allow_any_on_loopback:true}}}')"
  app="$(ensure_app "$WORKER_HOSTNAME" "$app_body")"
  WORKER_APP_ID="$(jq -r '.id // empty' <<<"$app")"; WORKER_AUD="$(jq -r '.aud // empty' <<<"$app")"
  if [[ -n "$WORKER_APP_ID" ]]; then
    ensure_policy "$WORKER_APP_ID" "$(jq -n --argjson e "$EMAILS_JSON" --arg idp "$IDP_ID" \
      '{name:"proxmox-mcp named users", decision:"allow", include:[$e[] | {email:{email:.}}], require:[{login_method:{id:$idp}}]}')"
    state_set worker_aud "$WORKER_AUD"
  fi
fi

# ---- 5. R2 audit bucket with bucket lock (2190 days) ---------------------------------------------
if want r2; then
  log "R2 bucket $AUDIT_BUCKET with lock rule (Age, $RETENTION_SECONDS s)"
  if ! api_get_opt "/accounts/$ACCOUNT_ID/r2/buckets/$AUDIT_BUCKET" >/dev/null; then
    api POST "/accounts/$ACCOUNT_ID/r2/buckets" "$(jq -n --arg n "$AUDIT_BUCKET" '{name:$n}')" >/dev/null
  fi
  api PUT "/accounts/$ACCOUNT_ID/r2/buckets/$AUDIT_BUCKET/lock" \
    "$(jq -n --argjson s "$RETENTION_SECONDS" '{rules:[{id:"hipaa-retention-6y", enabled:true, condition:{type:"Age", maxAgeSeconds:$s}}]}')" >/dev/null
fi

# ---- 6. Render wrangler config and deploy the Worker -------------------------------------------------
KEY_ID="$(state_get identity_key_id)"
RENDERED="$WORKER_DIR/wrangler.deploy.jsonc"   # holds ids, not secrets; keep it out of git
if want worker; then
  log "Render $RENDERED"
  vpc_id="$(state_get vpc_service_id)"
  broker_url="http://broker.internal"
  [[ "$BROKER_MODE" == "access" ]] && broker_url="https://$BROKER_HOSTNAME"
  sed -e "s#<worker-hostname>#$WORKER_HOSTNAME#g" \
      -e "s#https://<team>.cloudflareaccess.com#$TEAM_DOMAIN#g" \
      -e "s#<worker-access-app-aud>#${WORKER_AUD:-<worker-access-app-aud>}#g" \
      -e "s#<identity-key-id>#${KEY_ID:-<identity-key-id>}#g" \
      -e "s#<vpc-service-id>#${vpc_id:-<vpc-service-id>}#g" \
      -e "s#<ratelimit-namespace-id>#$RATELIMIT_NAMESPACE_ID#g" \
      -e "s#replace-me-audit-bucket#$AUDIT_BUCKET#g" \
      -e "s#\"BROKER_MODE\": \"vpc\"#\"BROKER_MODE\": \"$BROKER_MODE\"#" \
      -e "s#\"BROKER_URL\": \"http://broker.internal\"#\"BROKER_URL\": \"$broker_url\"#" \
      -e "s#\"ALLOWED_EMAILS\": \"\"#\"ALLOWED_EMAILS\": \"$(jq -r 'join(",")' <<<"$EMAILS_JSON")\"#" \
      "$WORKER_DIR/wrangler.jsonc" >"$RENDERED.tmp"
  if [[ "$BROKER_MODE" == "access" ]]; then sed -i '/"vpc_services"/d' "$RENDERED.tmp"; fi
  mv "$RENDERED.tmp" "$RENDERED"
  if grep -n '<[a-z-]*>' "$RENDERED" | grep -v '^\s*[0-9]*:\s*//' >&2; then
    warn "placeholders remain in $RENDERED (run the earlier steps / identity first)"
  elif [[ "${DEPLOY_WORKER:-0}" == "1" && "$DRY_RUN" != "1" ]]; then
    wrangler deploy --config "$RENDERED" >&2
  fi
fi

# ---- 7. Identity key: private -> Worker secret, public -> broker credential -------------------------
if want identity; then
  have="$(api GET "/accounts/$ACCOUNT_ID/workers/scripts/$WORKER_NAME/secrets" 2>/dev/null | jq -r '[.[]?.name] | index("IDENTITY_SIGNING_KEY") // empty' || true)"
  if [[ -n "$have" && "${ROTATE_IDENTITY_KEY:-0}" != "1" ]]; then
    log "IDENTITY_SIGNING_KEY exists (set ROTATE_IDENTITY_KEY=1 to replace)"
  elif [[ "$DRY_RUN" == "1" ]]; then
    log "DRY_RUN: generate Ed25519, private -> wrangler secret put IDENTITY_SIGNING_KEY, public -> broker"
  else
    log "Generate Ed25519 identity key (private key stays in the pipe)"
    PUB="$STATE_DIR/${WORKER_HOSTNAME}.worker-identity.pub"
    openssl genpkey -algorithm ed25519 -outform PEM \
      | tee >(openssl pkey -pubout -out "$PUB") \
      | wrangler secret put IDENTITY_SIGNING_KEY --name "$WORKER_NAME" >&2
    for _ in 1 2 3 4 5; do [[ -s "$PUB" ]] && break; sleep 1; done
    [[ -s "$PUB" ]] || die "public key not written"
    KEY_ID="ed25519-$(openssl pkey -pubin -in "$PUB" -outform DER | openssl dgst -sha256 -r | cut -c1-16)"
    state_set identity_key_id "$KEY_ID"
    log "IDENTITY_KEY_ID=$KEY_ID: re-render and deploy (STEPS=worker DEPLOY_WORKER=1) so the Worker sends it"
    if [[ -n "$BROKER_SSH" ]]; then
      # shellcheck disable=SC2029  # the path is meant to expand here
      ssh "$BROKER_SSH" "pwsh -NoProfile -File '$BROKER_SCRIPTS\\Protect-BrokerCredential.ps1' -Name worker-identity.pub -NoEncrypt -Force" <"$PUB" >&2
      ssh "$BROKER_SSH" "pwsh -NoProfile -Command Restart-Service ProxmoxMCPBroker" >&2
    else
      log "Public key: $PUB. Copy it to the broker: Get-Content worker-identity.pub | Protect-BrokerCredential.ps1 -Name worker-identity.pub -NoEncrypt -Force"
    fi
  fi
fi

# ---- 8. MCP server portal: register server, append to portal, sync --------------------------------
if want portal; then
  log "MCP server $SERVER_ID -> https://$WORKER_HOSTNAME/mcp (oauth)"
  if srv="$(api_get_opt "/accounts/$ACCOUNT_ID/access/ai-controls/mcp/servers/$SERVER_ID")"; then
    [[ "$(jq -r '.hostname' <<<"$srv")" == "https://$WORKER_HOSTNAME/mcp" ]] || die "MCP server $SERVER_ID exists with another hostname"
  else
    api POST "/accounts/$ACCOUNT_ID/access/ai-controls/mcp/servers" "$(jq -n --arg id "$SERVER_ID" --arg h "https://$WORKER_HOSTNAME/mcp" \
      '{id:$id, name:"Proxmox VE", description:"Proxmox VE through the Proxmox MCP broker (read-only by default)", hostname:$h, auth_type:"oauth"}')" >/dev/null
  fi
  portal="$(api GET "/accounts/$ACCOUNT_ID/access/ai-controls/mcp/portals/$PORTAL_ID")"
  if jq -e --arg s "$SERVER_ID" '[.servers[]? | (.server_id // .id)] | index($s)' <<<"$portal" >/dev/null; then
    log "portal already lists $SERVER_ID"
  else
    backup="$STATE_DIR/portal-$PORTAL_ID-$(date -u +%Y%m%dT%H%M%SZ).json"
    printf '%s\n' "$portal" >"$backup"
    log "portal backup: $backup"
    # PUT replaces the portal wholesale: keep every writable field and every server entry.
    body="$(jq -c --arg s "$SERVER_ID" '
      {name, hostname} + (if .description then {description} else {} end)
      + (if .code_mode then {code_mode} elif (.allow_code_mode != null) then {allow_code_mode} else {} end)
      + (if .secure_web_gateway != null then {secure_web_gateway} else {} end)
      + {servers: ([.servers[]? | {server_id: (.server_id // .id)}
                     + (if .default_disabled != null then {default_disabled} else {} end)
                     + (if .on_behalf != null then {on_behalf} else {} end)
                     + (if .updated_tools then {updated_tools} else {} end)
                     + (if .updated_prompts then {updated_prompts} else {} end)]
                   + [{server_id:$s, on_behalf:true, default_disabled:false}])}' <<<"$portal")"
    api PUT "/accounts/$ACCOUNT_ID/access/ai-controls/mcp/portals/$PORTAL_ID" "$body" >/dev/null
    if [[ "$DRY_RUN" != "1" ]]; then
      after="$(api GET "/accounts/$ACCOUNT_ID/access/ai-controls/mcp/portals/$PORTAL_ID")"
      jq -e --argjson before "$portal" --arg s "$SERVER_ID" \
        '([.servers[] | (.server_id // .id)]) as $now | ([$before.servers[]? | (.server_id // .id)] + [$s]) | all(. as $x | $now | index($x))' <<<"$after" >/dev/null \
        || die "portal lost a server after PUT; restore from $backup"
    fi
  fi
  api POST "/accounts/$ACCOUNT_ID/access/ai-controls/mcp/servers/$SERVER_ID/sync" '{}' >/dev/null \
    || warn "sync failed: an admin may need to authenticate the server in the portal first, then re-run STEPS=portal"
fi

# ---- 9. Tunnel token -> broker (never printed) ----------------------------------------------------
if want token; then
  if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY_RUN: GET tunnel token -> broker (not printed)"
  elif [[ -n "$BROKER_SSH" ]]; then
    log "Tunnel token -> $BROKER_SSH (Install-Cloudflared.ps1 -TokenOnly, stdin)"
    # shellcheck disable=SC2029  # the path is meant to expand here
    api GET "/accounts/$ACCOUNT_ID/cfd_tunnel/$TUNNEL_ID/token" | jq -r . \
      | ssh "$BROKER_SSH" "pwsh -NoProfile -File '$BROKER_SCRIPTS\\Install-Cloudflared.ps1' -TokenOnly" >&2
  else
    f="$STATE_DIR/${TUNNEL_NAME}.tunnel-token"
    api GET "/accounts/$ACCOUNT_ID/cfd_tunnel/$TUNNEL_ID/token" | jq -r . >"$f"
    chmod 600 "$f"
    log "Tunnel token written to $f (mode 0600). Move it to the broker and pipe it into Install-Cloudflared.ps1 -TokenOnly, then delete it."
  fi
fi

# ---- 10. Verify from outside ------------------------------------------------------------------------
if want verify; then
  log "Verify https://$WORKER_HOSTNAME"
  fails=0
  hdrs="$(mktemp)"
  code="$(curl -sS --proto '=https' -o /dev/null -D "$hdrs" -w '%{http_code}' -X POST "https://$WORKER_HOSTNAME/mcp" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"verify","version":"0"}}}')"
  if [[ "$code" == "401" ]] && grep -qi '^www-authenticate:' "$hdrs"; then
    log "PASS POST /mcp unauthenticated -> 401 + WWW-Authenticate: $(grep -i '^www-authenticate:' "$hdrs" | head -1 | tr -d '\r' | cut -c1-200)"
  else
    warn "FAIL POST /mcp unauthenticated -> $code (expect 401 with WWW-Authenticate)"; fails=$((fails + 1))
  fi
  for p in /.well-known/oauth-protected-resource /.well-known/oauth-protected-resource/mcp /.well-known/oauth-authorization-server; do
    c="$(curl -sS --proto '=https' -o "$hdrs" -w '%{http_code}' "https://$WORKER_HOSTNAME$p")"
    log "$p -> $c $(jq -c '{resource, authorization_servers, issuer} | with_entries(select(.value != null))' "$hdrs" 2>/dev/null | cut -c1-200)"
  done
  c="$(curl -sS --proto '=https' -o /dev/null -w '%{http_code}' "https://$WORKER_HOSTNAME/mcp")"
  log "GET /mcp unauthenticated -> $c"
  if [[ "$BROKER_MODE" == "access" ]]; then
    c="$(curl -sS --proto '=https' -o /dev/null -w '%{http_code}' "https://$BROKER_HOSTNAME/healthz")"
    if [[ "$c" == "401" || "$c" == "403" ]]; then log "PASS broker hostname without service token -> $c"; else warn "FAIL broker hostname without service token -> $c"; fails=$((fails + 1)); fi
  else
    if [[ -n "$(api GET "/zones/$ZONE_ID/dns_records?content=$TUNNEL_ID.cfargotunnel.com" | jq -r '.[0].name // empty')" ]]; then
      warn "FAIL a DNS record points at the broker tunnel in vpc mode"; fails=$((fails + 1))
    else
      log "PASS no public hostname routes to the broker tunnel"
    fi
  fi
  ing="$(api GET "/accounts/$ACCOUNT_ID/cfd_tunnel/$TUNNEL_ID/configurations" | jq -c '.config.ingress')"
  jq -e '.[-1].service == "http_status:404"' <<<"$ing" >/dev/null || { warn "FAIL tunnel ingress has no catch-all 404"; fails=$((fails + 1)); }
  jq -e 'all(.[]; (.hostname == null) or (.originRequest.access.required == true))' <<<"$ing" >/dev/null || { warn "FAIL an ingress hostname lacks access.required"; fails=$((fails + 1)); }
  log "Origin: the broker binds 127.0.0.1 only; from the LAN, check: Test-NetConnection <broker> -Port $ORIGIN_PORT (must fail)"
  rm -f "$hdrs"
  ((fails == 0)) || die "$fails verify check(s) failed"
  log "verify passed"
fi

log "State (non-secret ids): $STATE_FILE"
