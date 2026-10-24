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
# Exposure order (nothing is reachable without Access in front):
#   1. tunnel (catch-all 404)  2. broker path: Access app + service-token policy BEFORE the DNS
#   record (access mode) / VPC service (no hostname)  3. tunnel ingress (access.required)
#   4. Worker Access app + named-user policy  5. R2 lock  6. Worker deploy: refused unless the
#   Worker Access app and its policy exist and pass the policy checks  7. identity key
#   8. portal  9. tunnel token  10. verify.
#
# Secrets never appear in argv, on stdout, in a temp file or in xtrace:
#   - The script refuses to run under `bash -x` (xtrace would print the token).
#   - Cloudflare API token: env CF_API_TOKEN or one line on stdin. It is un-exported at once, so
#     no child process inherits it except wrangler (CLOUDFLARE_API_TOKEN, that one process).
#     Sent to curl as a header file through a process substitution (a pipe, not argv).
#   - API responses are kept in shell variables and read through pipes; none is written to disk
#     (the tunnel token and the service token secret are API responses).
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
#   SESSION_DURATION (8h, max 8h)  ACCESS_TOKEN_LIFETIME (10m, max 10m)  DRY_RUN=1
#   REQUIRE_MFA=1 (default): the Worker Access policy also requires the IdP to report MFA
#     (auth_method mfa, from the Entra amr claim). Set 0 only if Conditional Access enforces MFA
#     and Entra does not send amr; record that decision.
#   STEPS (all; or a list such as "verify"). STEPS=off is never part of "all": emergency off.
#     vpc: deletes the Workers VPC service. access: deletes the broker DNS record and sets the
#     tunnel ingress to 404 only. Undo with STEPS="broker tunnel".
#
# API token permissions: Account: Cloudflare Tunnel Edit, Access: Apps and Policies Edit,
#   Access: Service Tokens Edit, Access: Organizations Read, Connectivity Directory Admin (vpc),
#   Workers Scripts Edit, Workers R2 Storage Edit, Zero Trust (MCP portals) Edit; Zone: DNS Edit.
set -euo pipefail
umask 077
case "$-" in *x*) printf 'error: do not run with xtrace (bash -x): it would print secrets\n' >&2; exit 1 ;; esac

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
REQUIRE_MFA="${REQUIRE_MFA:-1}"
STATE_DIR="${STATE_DIR:-$HOME/.proxmox-mcp}"
STEPS="${STEPS:-all}"
BROKER_SSH="${BROKER_SSH:-}"
BROKER_HOSTNAME="${BROKER_HOSTNAME:-}"
readonly RETENTION_SECONDS=$((2190 * 86400))
readonly CLAUDE_CALLBACKS='["https://claude.ai/api/mcp/auth_callback","https://claude.com/api/mcp/auth_callback"]'
readonly BROKER_SCRIPTS='C:\Program Files\ProxmoxMCP\scripts'
# Windows PowerShell 5.1 is in the box on every Windows Server; the scripts support 5.1 and 7.
BROKER_PS="${BROKER_PS:-powershell.exe -NoProfile -NonInteractive}"

log() { printf '==> %s\n' "$*" >&2; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
want() { [[ "$STEPS" == "all" || " $STEPS " == *" $1 "* ]]; }
want_explicit() { [[ " $STEPS " == *" $1 "* ]]; }

need() { [[ -n "${!1:-}" ]] || die "set $1"; }
[[ "$BROKER_PS" =~ ^(powershell\.exe|pwsh)(\ -[A-Za-z]+)*$ ]] || die "BROKER_PS must be powershell.exe or pwsh with switches only"
[[ -z "$BROKER_SSH" || "$BROKER_SSH" =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+$ ]] || die "BROKER_SSH must be user@host"
for t in curl jq openssl; do command -v "$t" >/dev/null 2>&1 || die "$t is required"; done

for v in ACCOUNT_ID ZONE_ID WORKER_HOSTNAME TEAM_DOMAIN IDP_ID ALLOWED_EMAILS PORTAL_ID SERVER_ID WORKER_DIR AUDIT_BUCKET; do need "$v"; done
[[ "$ACCOUNT_ID" =~ ^[0-9a-f]{32}$ ]] || die "ACCOUNT_ID must be 32 hex"
[[ "$ZONE_ID" =~ ^[0-9a-f]{32}$ ]] || die "ZONE_ID must be 32 hex"
[[ "$TEAM_DOMAIN" =~ ^https://([a-z0-9-]+)\.cloudflareaccess\.com$ ]] || die "TEAM_DOMAIN must be https://<team>.cloudflareaccess.com"
TEAM_NAME="${BASH_REMATCH[1]}"   # tunnel originRequest.access.teamName wants the short name
[[ "$SERVER_ID" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ && ${#SERVER_ID} -le 32 ]] || die "SERVER_ID must match ^[a-z0-9]+(-[a-z0-9]+)*$, max 32"
if ! [[ "$ORIGIN_PORT" =~ ^[1-9][0-9]{3,4}$ ]] || ((ORIGIN_PORT < 1024 || ORIGIN_PORT > 65535)); then die "ORIGIN_PORT must be 1024..65535"; fi
# Every value that reaches a URL, a sed expression or a JSON body is validated here.
for v in TUNNEL_NAME VPC_SERVICE_NAME SERVICE_TOKEN_NAME WORKER_NAME; do
  [[ "${!v}" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || die "$v must match ^[a-z0-9][a-z0-9-]{0,62}$"
done
[[ "$AUDIT_BUCKET" =~ ^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$ ]] || die "AUDIT_BUCKET is not a valid R2 bucket name"
[[ "$PORTAL_ID" =~ ^[A-Za-z0-9_-]{1,64}$ ]] || die "PORTAL_ID has unexpected characters"
[[ "$IDP_ID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || die "IDP_ID must be the IdP UUID"
[[ "$RATELIMIT_NAMESPACE_ID" =~ ^[1-9][0-9]{0,9}$ ]] || die "RATELIMIT_NAMESPACE_ID must be a positive integer"
[[ "$REQUIRE_MFA" == "0" || "$REQUIRE_MFA" == "1" ]] || die "REQUIRE_MFA must be 0 or 1"
# Automatic logoff (HIPAA 164.312(a)(2)(iii)): never longer than 8 h / 10 min.
[[ "$SESSION_DURATION" =~ ^([1-9][0-9]{0,3})(m|h)$ ]] || die "SESSION_DURATION must look like 8h or 30m"
sd_min="${BASH_REMATCH[1]}"
if [[ "${BASH_REMATCH[2]}" == "h" ]]; then sd_min=$((sd_min * 60)); fi
((sd_min >= 5 && sd_min <= 480)) || die "SESSION_DURATION must be between 5m and 8h"
if ! [[ "$ACCESS_TOKEN_LIFETIME" =~ ^([1-9][0-9]?)m$ ]] || ((BASH_REMATCH[1] > 10)); then
  die "ACCESS_TOKEN_LIFETIME must be 1m..10m"
fi
[[ "$BROKER_MODE" == "vpc" || "$BROKER_MODE" == "access" ]] || die "BROKER_MODE must be vpc or access"
[[ "$WORKER_HOSTNAME" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] || die "bad WORKER_HOSTNAME"
if [[ "$BROKER_MODE" == "access" ]]; then
  need BROKER_HOSTNAME
  [[ "$BROKER_HOSTNAME" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] || die "bad BROKER_HOSTNAME"
  [[ "$BROKER_HOSTNAME" != "$WORKER_HOSTNAME" ]] || die "BROKER_HOSTNAME must differ from WORKER_HOSTNAME"
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
export -n CF_API_TOKEN   # children (curl, jq, ssh, openssl) must not inherit it
auth_header() { printf 'Authorization: Bearer %s\n' "$CF_API_TOKEN"; }

# api METHOD PATH [JSON]  -> prints .result ; fails on success=false. Writes are skipped in DRY_RUN.
# The response stays in a variable and moves through pipes: it may hold a secret (tunnel token,
# service token secret) and must never land in a temp file.
api() {
  local method="$1" path="$2" body="${3:-}" resp code out
  if [[ "$DRY_RUN" == "1" && "$method" != "GET" ]]; then
    log "DRY_RUN $method $path"
    [[ -n "$body" ]] && printf '%s' "$body" | jq . >&2
    echo 'null'
    return 0
  fi
  local args=(-sS --proto '=https' --tlsv1.2 --max-time 60 -w $'\n%{http_code}' -X "$method")
  # The header comes from a process substitution on the curl command itself: the token is in
  # no argv and no file.
  if [[ -n "$body" ]]; then
    resp="$(printf '%s' "$body" | curl "${args[@]}" -H 'Content-Type: application/json' --data-binary @- -H @<(auth_header) "$API$path")" \
      || { printf 'API %s %s: transport error\n' "$method" "$path" >&2; return 1; }
  else
    resp="$(curl "${args[@]}" -H @<(auth_header) "$API$path")" \
      || { printf 'API %s %s: transport error\n' "$method" "$path" >&2; return 1; }
  fi
  code="${resp##*$'\n'}"
  out="${resp%$'\n'*}"
  if ! printf '%s' "$out" | jq -e '.success == true' >/dev/null 2>&1; then
    printf 'API %s %s failed (HTTP %s): %s\n' "$method" "$path" "$code" "$(printf '%s' "$out" | jq -c '.errors // "no JSON body"' 2>/dev/null | head -c 600)" >&2
    return 1
  fi
  printf '%s' "$out" | jq -c '.result'
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

# Policy checks shared by the deploy gate and verify. Each prints nothing; returns 1 on a problem.
worker_policies_ok() {
  local app_id="$1" pol
  pol="$(api GET "/accounts/$ACCOUNT_ID/access/apps/$app_id/policies")" || return 1
  printf '%s' "$pol" | jq -e --arg idp "$IDP_ID" '
    length > 0 and all(.[];
      .decision == "allow"
      and ((.include // []) | length > 0)
      and all((.include // [])[]; has("email"))
      and any((.require // [])[]; (.login_method.id // "") == $idp))' >/dev/null
}
worker_app_ok() {
  local app="$1"
  printf '%s' "$app" | jq -e --arg idp "$IDP_ID" '
    (.allowed_idps == [$idp]) and (.oauth_configuration.enabled == true)
    and ((.oauth_configuration.dynamic_client_registration.allowed_uris // []) | all(startswith("https://claude.ai/") or startswith("https://claude.com/")))' >/dev/null
}
broker_policies_ok() {
  local app_id="$1" pol
  pol="$(api GET "/accounts/$ACCOUNT_ID/access/apps/$app_id/policies")" || return 1
  printf '%s' "$pol" | jq -e '
    length > 0 and all(.[];
      .decision == "non_identity"
      and ((.include // []) | length > 0)
      and all((.include // [])[]; has("service_token")))' >/dev/null
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
      ST_ID="$(printf '%s' "$secret_json" | jq -r '.id // empty')"
    elif [[ "${ROTATE_SERVICE_TOKEN:-0}" == "1" ]]; then
      secret_json="$(api POST "/accounts/$ACCOUNT_ID/access/service_tokens/$ST_ID/rotate" '{}')"
    fi
    if [[ -n "$secret_json" && "$secret_json" != "null" ]]; then
      # printf | jq: a here-string can be backed by a temp file; a pipe never is.
      printf '%s' "$secret_json" | jq -r '.client_id' | wrangler secret put BROKER_ACCESS_CLIENT_ID --name "$WORKER_NAME" >&2
      printf '%s' "$secret_json" | jq -r '.client_secret' | wrangler secret put BROKER_ACCESS_CLIENT_SECRET --name "$WORKER_NAME" >&2
      state_set service_token_client_id "$(printf '%s' "$secret_json" | jq -r '.client_id')"
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
    # DNS last, and only when the app admits nothing but the Worker's service token.
    if [[ "$DRY_RUN" != "1" ]]; then
      broker_policies_ok "$BROKER_APP_ID" || die "broker Access app has a policy other than the Worker service token; fix it before DNS"
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
    ensure_policy "$WORKER_APP_ID" "$(jq -n --argjson e "$EMAILS_JSON" --arg idp "$IDP_ID" --argjson mfa "$REQUIRE_MFA" \
      '{name:"proxmox-mcp named users", decision:"allow", include:[$e[] | {email:{email:.}}],
        require:([{login_method:{id:$idp}}] + (if $mfa == 1 then [{auth_method:{auth_method:"mfa"}}] else [] end))}')"
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
# Rendered under .wrangler/ (git-ignored): it holds account-specific ids, never secrets, and must
# never be committed. "main" becomes absolute because wrangler resolves it relative to the config.
DEPLOY_DIR="$WORKER_DIR/.wrangler/proxmox-mcp-deploy"
RENDERED="$DEPLOY_DIR/wrangler.deploy.jsonc"
if want worker; then
  log "Render $RENDERED"
  worker_abs="$(cd "$WORKER_DIR" && pwd -P)"
  [[ "$worker_abs" =~ ^[A-Za-z0-9/._-]+$ ]] || die "WORKER_DIR path has characters that are not safe in the rendered config"
  mkdir -p "$DEPLOY_DIR"
  if git -C "$WORKER_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1 && ! git -C "$WORKER_DIR" check-ignore -q "$RENDERED"; then
    die "$RENDERED is not git-ignored; refusing to write account ids where they could be committed"
  fi
  vpc_id="$(state_get vpc_service_id)"
  [[ -z "$vpc_id" || "$vpc_id" =~ ^[A-Za-z0-9-]{1,64}$ ]] || die "state: bad vpc_service_id"
  [[ -z "$WORKER_AUD" || "$WORKER_AUD" =~ ^[0-9a-f]{64}$ ]] || die "state: bad worker_aud"
  [[ -z "$KEY_ID" || "$KEY_ID" =~ ^ed25519-[0-9a-f]{16}$ ]] || die "state: bad identity_key_id"
  broker_url="http://broker.internal"
  [[ "$BROKER_MODE" == "access" ]] && broker_url="https://$BROKER_HOSTNAME"
  sed -e "s#<worker-hostname>#$WORKER_HOSTNAME#g" \
      -e "s#https://<team>.cloudflareaccess.com#$TEAM_DOMAIN#g" \
      -e "s#<worker-access-app-aud>#${WORKER_AUD:-<worker-access-app-aud>}#g" \
      -e "s#<identity-key-id>#${KEY_ID:-<identity-key-id>}#g" \
      -e "s#<vpc-service-id>#${vpc_id:-<vpc-service-id>}#g" \
      -e "s#<ratelimit-namespace-id>#$RATELIMIT_NAMESPACE_ID#g" \
      -e "s#replace-me-audit-bucket#$AUDIT_BUCKET#g" \
      -e "s#\"main\": \"src/index.ts\"#\"main\": \"$worker_abs/src/index.ts\"#" \
      -e "s#\"BROKER_MODE\": \"vpc\"#\"BROKER_MODE\": \"$BROKER_MODE\"#" \
      -e "s#\"BROKER_URL\": \"http://broker.internal\"#\"BROKER_URL\": \"$broker_url\"#" \
      -e "s#\"ALLOWED_EMAILS\": \"\"#\"ALLOWED_EMAILS\": \"$(jq -r 'join(",")' <<<"$EMAILS_JSON")\"#" \
      "$WORKER_DIR/wrangler.jsonc" >"$RENDERED.tmp"
  if [[ "$BROKER_MODE" == "access" ]]; then sed -i '/"vpc_services"/d' "$RENDERED.tmp"; fi
  mv "$RENDERED.tmp" "$RENDERED"
  if ! grep -q '"workers_dev": false' "$RENDERED" || ! grep -q '"preview_urls": false' "$RENDERED"; then
    die "rendered config must keep workers_dev and preview_urls false (no hostname without Access)"
  fi
  if grep -n '<[a-z-]*>' "$RENDERED" | grep -v '^\s*[0-9]*:\s*//' >&2; then
    warn "placeholders remain in $RENDERED (run the earlier steps / identity first)"
  elif [[ "${DEPLOY_WORKER:-0}" == "1" && "$DRY_RUN" != "1" ]]; then
    # Deploy gate: the Worker hostname must already sit behind Access with a named-user policy.
    app="$(find_app "$WORKER_HOSTNAME")"
    [[ -n "$app" ]] || die "no Access app on $WORKER_HOSTNAME: run STEPS=access before deploying the Worker"
    worker_app_ok "$app" || die "Access app on $WORKER_HOSTNAME does not match the required settings (IdP, Managed OAuth, DCR callbacks)"
    worker_policies_ok "$(printf '%s' "$app" | jq -r .id)" || die "Access policy on $WORKER_HOSTNAME is not named users + Entra login"
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
      ssh -o BatchMode=yes "$BROKER_SSH" "$BROKER_PS -File '$BROKER_SCRIPTS\\Protect-BrokerCredential.ps1' -Name worker-identity.pub -NoEncrypt -Force" <"$PUB" >&2
      ssh -o BatchMode=yes "$BROKER_SSH" "$BROKER_PS -Command Restart-Service ProxmoxMCPBroker" >&2
    else
      log "Public key: $PUB. Copy it to the broker, then: Protect-BrokerCredential.ps1 -Name worker-identity.pub -NoEncrypt -Force -PublicKeyFile <path>"
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
      # Every other field must be unchanged (timestamps excepted), for the portal and for
      # every server that was there before.
      jq -e --argjson before "$portal" '
        def strip: del(.servers, .modified_at, .updated_at, .created_at, .modified, .updated);
        def srv: [.servers[]? | del(.modified_at, .updated_at, .last_synced, .last_successful_sync, .status, .error)];
        (strip == ($before | strip))
        and ((srv | map(select(.server_id // .id) ) | sort_by(.server_id // .id)) as $now
             | ($before | srv | sort_by(.server_id // .id)) | all(. as $b | $now | any(. == $b)))' <<<"$after" >/dev/null \
        || die "portal fields changed after PUT; compare with $backup and restore by hand"
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
      | ssh -o BatchMode=yes "$BROKER_SSH" "$BROKER_PS -File '$BROKER_SCRIPTS\\Install-Cloudflared.ps1' -TokenOnly" >&2
  else
    f="$STATE_DIR/${TUNNEL_NAME}.tunnel-token"
    (umask 177 && api GET "/accounts/$ACCOUNT_ID/cfd_tunnel/$TUNNEL_ID/token" | jq -r . >"$f")
    log "Tunnel token written to $f (mode 0600). Move it to the broker and pipe it into Install-Cloudflared.ps1 -TokenOnly, then delete it."
  fi
fi

# ---- Emergency off (explicit only: STEPS=off) ---------------------------------------------------------
if want_explicit off; then
  warn "EMERGENCY OFF ($BROKER_MODE mode). Also stop the broker (Stop-Service ProxmoxMCPBroker) and revoke tokens (setup-proxmox-access.sh revoke-all)."
  if [[ "$BROKER_MODE" == "vpc" ]]; then
    vpc_id="$(state_get vpc_service_id)"
    [[ -n "$vpc_id" ]] && api DELETE "/accounts/$ACCOUNT_ID/connectivity/directory/services/$vpc_id" >/dev/null && log "VPC service deleted"
  else
    rid="$(api GET "/zones/$ZONE_ID/dns_records?name=$BROKER_HOSTNAME" | jq -r '.[0].id // empty')"
    [[ -n "$rid" ]] && api DELETE "/zones/$ZONE_ID/dns_records/$rid" >/dev/null && log "broker DNS record deleted"
    api PUT "/accounts/$ACCOUNT_ID/cfd_tunnel/$TUNNEL_ID/configurations" '{"config":{"ingress":[{"service":"http_status:404"}],"warp-routing":{"enabled":false}}}' >/dev/null
    log "tunnel ingress set to 404 only"
  fi
  log "undo: STEPS=\"broker tunnel\" ./provision.sh (after the incident is closed and approved)"
  exit 0
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
  if [[ "$BROKER_MODE" == "vpc" ]]; then
    jq -e 'all(.[]; .hostname == null)' <<<"$ing" >/dev/null || { warn "FAIL vpc mode: the tunnel ingress publishes a hostname"; fails=$((fails + 1)); }
  fi
  # A forged Access assertion from outside must not get through.
  c="$(curl -sS --proto '=https' -o /dev/null -w '%{http_code}' -X POST "https://$WORKER_HOSTNAME/mcp" -H 'Cf-Access-Jwt-Assertion: forged.invalid.token' \
    -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')"
  if [[ "$c" == "401" || "$c" == "403" ]]; then log "PASS forged Cf-Access-Jwt-Assertion -> $c"; else warn "FAIL forged Cf-Access-Jwt-Assertion -> $c"; fails=$((fails + 1)); fi
  # No hostname that bypasses Access: workers.dev and preview URLs off.
  sub="$(api GET "/accounts/$ACCOUNT_ID/workers/scripts/$WORKER_NAME/subdomain" 2>/dev/null || echo '{}')"
  if jq -e '.enabled == false and (.previews_enabled // false) == false' <<<"$sub" >/dev/null; then
    log "PASS workers.dev and preview URLs are off"
  else
    warn "FAIL workers.dev or preview URLs may be on: $(jq -c . <<<"$sub" | head -c 200)"; fails=$((fails + 1))
  fi
  # Access app and policy shape (named users + Entra login [+ MFA]; session <= 8 h; token <= 10 min).
  app="$(find_app "$WORKER_HOSTNAME")"
  if [[ -z "$app" ]]; then
    warn "FAIL no Access app on $WORKER_HOSTNAME"; fails=$((fails + 1))
  else
    worker_app_ok "$app" || { warn "FAIL Worker Access app settings (IdP, Managed OAuth, DCR callbacks)"; fails=$((fails + 1)); }
    worker_policies_ok "$(jq -r .id <<<"$app")" || { warn "FAIL Worker Access policy is not named users + Entra login"; fails=$((fails + 1)); }
    log "session_duration=$(jq -r '.session_duration' <<<"$app") access_token_lifetime=$(jq -r '.oauth_configuration.grant.access_token_lifetime // "?"' <<<"$app")"
  fi
  if [[ "$BROKER_MODE" == "access" ]]; then
    bapp="$(find_app "$BROKER_HOSTNAME")"
    if [[ -z "$bapp" ]] || ! broker_policies_ok "$(jq -r .id <<<"$bapp")"; then
      warn "FAIL broker Access app must admit only the Worker service token"; fails=$((fails + 1))
    fi
  fi
  # WORM lock on the Worker audit bucket.
  lock="$(api GET "/accounts/$ACCOUNT_ID/r2/buckets/$AUDIT_BUCKET/lock" 2>/dev/null || echo '{}')"
  if jq -e --argjson s "$RETENTION_SECONDS" '[.rules[]? | select(.enabled == true and .condition.type == "Age" and (.condition.maxAgeSeconds // 0) >= $s)] | length > 0' <<<"$lock" >/dev/null; then
    log "PASS R2 bucket lock >= 2190 days on $AUDIT_BUCKET"
  else
    warn "FAIL no enabled R2 lock rule of 2190 days or more on $AUDIT_BUCKET"; fails=$((fails + 1))
  fi
  log "Origin: the broker binds 127.0.0.1 only; from the LAN, check: Test-NetConnection <broker> -Port $ORIGIN_PORT (must fail)"
  rm -f "$hdrs"
  ((fails == 0)) || die "$fails verify check(s) failed"
  log "verify passed"
fi

log "State (non-secret ids): $STATE_FILE"
