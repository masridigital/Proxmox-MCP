#!/usr/bin/env bash
# setup-proxmox-access.sh: Proxmox VE side of the Proxmox MCP broker. Run ON a Proxmox node as root.
#
# One person, one key: every enrolled person gets a pve-realm user mcp-<short>@pve (no password,
# so no interactive login) and ONE privilege-separated API token "mcp" with an expiry. The token
# ACL equals the user ACL, so the token can never exceed the user. ACLs are scoped to a resource
# pool (recommended) so the AI only sees the guests in that pool. root@pam is never touched.
#
# Roles (checked for PVE 9.x; VM.Monitor was dropped in libpve-access-control 9.0.2). Every role
# is a subset of ALLOWED_PRIVILEGES in proxmox_mcp/selfcheck.py for the matching mode, so
# `proxmox-mcp-selfcheck --live` passes:
#   ProxmoxMCP-Read     VM.Audit Datastore.Audit Pool.Audit SDN.Audit Sys.Audit
#                       + VM.GuestAgent.Audit where it exists (PVE 9: guest OS facts for the
#                       read-tier vm_agent_get_* tools; never file content or command output)
#   ProxmoxMCP-Operate  Read + VM.PowerMgmt VM.Snapshot
#   ProxmoxMCP-Admin    Operate + guest-scoped config/allocate/clone/migrate/backup/rollback
#   ProxmoxMCP-NodeAudit  Sys.Audit (+ Sys.Syslog with NODE_SYSLOG=1) on /nodes
#   ProxmoxMCP-Review   Sys.Audit Pool.Audit   (quarterly access review token, read only)
# Never granted (script refuses): Sys.Modify Sys.PowerMgmt Sys.Console Sys.Incoming
#   Sys.AccessNetwork Permissions.Modify Realm.* User.Modify Group.Allocate VM.Console
#   VM.GuestAgent.Unrestricted/FileRead/FileWrite/FileSystemMgmt (guest content: agent exec,
#   file read/write) VM.Config.Cloudinit (user data can hold secrets) Datastore.Allocate
#   Datastore.AllocateTemplate Mapping.* Pool.Allocate SDN.Allocate. Sys.Syslog only on
#   /nodes and only with NODE_SYSLOG=1 (host logs can name guests and users).
#
# Accountability: every run writes one line to syslog (tag proxmox-mcp-access, authpriv):
# the command, its arguments, the login user and the SSH client address. Never a secret.
# ACLs converge: every ProxmoxMCP-* ACL of the subject that is not wanted any more (old pool,
# old mode, storage path, /nodes) is removed. root@pam and non-mcp users are never touched.
#
# Usage (as root on a Proxmox node; or remotely: ssh root@<pve> 'bash -s -- <cmd> ...' < this file):
#   MCP_POOL=mcp ./setup-proxmox-access.sh roles               create/update roles and the pool
#   MCP_POOL=mcp ./setup-proxmox-access.sh user alice ro       create/update user + user ACL
#   MCP_POOL=mcp ./setup-proxmox-access.sh issue-token alice ro    ONE line on stdout: mcp-alice@pve!mcp=<uuid>
#   MCP_POOL=mcp ROTATE=1 ./setup-proxmox-access.sh issue-token alice ro   rotate (new secret)
#   MCP_POOL=mcp ./setup-proxmox-access.sh review-token         token for Export-AccessReview.ps1
#   ./setup-proxmox-access.sh revoke alice                      delete token, disable user, drop ACLs
#   ./setup-proxmox-access.sh revoke-all                        same for every mcp-*@pve user (emergency)
#   ./setup-proxmox-access.sh list                              users, tokens, ACLs (no secrets)
#
# Token delivery: the secret is printed once, to stdout only, and goes straight into the broker's
# DPAPI store. It never touches a disk or a command line. From an admin workstation:
#   ssh root@<proxmox-host> 'MCP_POOL=mcp bash -s -- issue-token alice ro' < setup-proxmox-access.sh \
#     | ssh <admin>@<broker> "powershell.exe -NoProfile -NonInteractive -File 'C:\Program Files\ProxmoxMCP\scripts\Protect-BrokerCredential.ps1' -Name pve-token-alice -Force"
#
# Variables:
#   MCP_POOL         resource pool the AI may see (required for roles/user/issue-token unless ACL_PATHS set)
#   ACL_PATHS        space-separated ACL paths (default "/pool/$MCP_POOL")
#   STORAGE_PATHS    extra paths for operate/admin users, e.g. "/storage/<backup-storage>" (default none)
#   NODE_AUDIT       1 = also grant Sys.Audit on /nodes (node status, task list). Default 1.
#   NODE_SYSLOG      1 = also grant Sys.Syslog on /nodes (get_node_syslog/journal tools). Default 0.
#   TOKEN_TTL_DAYS   token lifetime (default 90, max 365)
#   ROTATE           1 = replace an existing token secret
#   DRY_RUN          1 = print the pveum commands, change nothing, print no token
set -euo pipefail
umask 077

readonly TOKEN_NAME="mcp"
readonly ROLE_READ="ProxmoxMCP-Read"
readonly ROLE_OPERATE="ProxmoxMCP-Operate"
readonly ROLE_ADMIN="ProxmoxMCP-Admin"
readonly ROLE_REVIEW="ProxmoxMCP-Review"
readonly ROLE_NODE="ProxmoxMCP-NodeAudit"
NODE_SYSLOG="${NODE_SYSLOG:-0}"
# VM.GuestAgent.Audit exists from libpve-access-control 9.x on; older nodes reject it.
GUEST_AUDIT=""
if [[ -r /usr/share/perl5/PVE/AccessControl.pm ]] && grep -q "VM.GuestAgent.Audit" /usr/share/perl5/PVE/AccessControl.pm; then
  GUEST_AUDIT=" VM.GuestAgent.Audit"
fi
readonly GUEST_AUDIT
readonly PRIVS_READ="VM.Audit Datastore.Audit Pool.Audit SDN.Audit Sys.Audit${GUEST_AUDIT}"
readonly PRIVS_OPERATE="${PRIVS_READ} VM.PowerMgmt VM.Snapshot"
readonly PRIVS_ADMIN="${PRIVS_OPERATE} VM.Config.Disk VM.Config.CPU VM.Config.Memory VM.Config.Network VM.Config.Options VM.Config.HWType VM.Config.CDROM VM.Allocate VM.Clone VM.Migrate VM.Backup VM.Snapshot.Rollback Datastore.AllocateSpace SDN.Use"
readonly PRIVS_REVIEW="Sys.Audit Pool.Audit"
PRIVS_NODE="Sys.Audit"
[[ "$NODE_SYSLOG" == "1" ]] && PRIVS_NODE="Sys.Audit Sys.Syslog"
readonly PRIVS_NODE
readonly FORBIDDEN="Sys.Modify Sys.PowerMgmt Sys.Console Sys.Incoming Sys.AccessNetwork Permissions.Modify Realm.Allocate Realm.AllocateUser User.Modify Group.Allocate VM.Console VM.GuestAgent.Unrestricted VM.GuestAgent.FileRead VM.GuestAgent.FileWrite VM.GuestAgent.FileSystemMgmt VM.Config.Cloudinit Datastore.Allocate Datastore.AllocateTemplate Mapping.Modify Mapping.Use Mapping.Audit Pool.Allocate SDN.Allocate"

DRY_RUN="${DRY_RUN:-0}"
NODE_AUDIT="${NODE_AUDIT:-1}"
TOKEN_TTL_DAYS="${TOKEN_TTL_DAYS:-90}"
ROTATE="${ROTATE:-0}"
MCP_POOL="${MCP_POOL:-}"
ACL_PATHS="${ACL_PATHS:-}"
STORAGE_PATHS="${STORAGE_PATHS:-}"

log() { printf '%s\n' "$*" >&2; }

# Who ran what, for the access-change audit trail (SOC 2 CC6.2, HIPAA 164.308(a)(4)).
audit_trail() {
  local who="${SUDO_USER:-$(logname 2>/dev/null || id -un)}" from="${SSH_CLIENT%% *}"
  logger -t proxmox-mcp-access -p authpriv.notice -- "run by=${who} from=${from:-local} dry_run=${DRY_RUN} pool=${MCP_POOL:-} cmd=$*" 2>/dev/null || true
}
die() { log "error: $*"; exit 1; }

# Run a pveum/pvesh command, or print it in dry-run. Never used for commands that return secrets.
run() {
  if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY_RUN: $*"
  else
    "$@" >&2
  fi
}

require_pve() {
  [[ "$(id -u)" -eq 0 ]] || die "run as root on a Proxmox VE node"
  command -v pveum >/dev/null 2>&1 || die "pveum not found: run this on a Proxmox VE node"
  command -v pvesh >/dev/null 2>&1 || die "pvesh not found"
}

valid_short() {
  [[ "$1" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || die "short name must match ^[a-z0-9][a-z0-9-]{0,30}$ (got '$1')"
  [[ "$1" != "root" ]] || die "refusing 'root'"
}

role_for_mode() {
  case "$1" in
    ro) echo "$ROLE_READ" ;;
    operator) echo "$ROLE_OPERATE" ;;
    rw) echo "$ROLE_ADMIN" ;;
    *) die "mode must be ro, operator or rw (got '$1')" ;;
  esac
}

acl_paths() {
  local paths="$ACL_PATHS"
  if [[ -z "$paths" ]]; then
    [[ -n "$MCP_POOL" ]] || die "set MCP_POOL (recommended) or ACL_PATHS"
    paths="/pool/${MCP_POOL}"
  fi
  local p
  for p in $paths; do
    [[ "$p" =~ ^/(pool/[A-Za-z0-9_.-]+|vms(/[0-9]+)?|storage/[A-Za-z0-9_.-]+|sdn/zones/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)?)$ ]] \
      || die "ACL path '$p' is not allowed (use /pool/<p>, /vms[/<id>], /storage/<s>, /sdn/zones/<z>)"
  done
  echo "$paths"
}

check_privs() {
  local priv f
  for priv in $2; do
    for f in $FORBIDDEN; do
      [[ "$priv" != "$f" ]] || die "role $1 would contain forbidden privilege $priv"
    done
  done
}

ensure_role() {
  local role="$1" privs="$2"
  check_privs "$role" "$privs"
  local csv="${privs// /,}"
  if pvesh get "/access/roles/${role}" --output-format json >/dev/null 2>&1; then
    # Without --append, modify REPLACES the privilege list: drift is removed.
    run pveum role modify "$role" --privs "$csv"
  else
    run pveum role add "$role" --privs "$csv"
  fi
}

cmd_roles() {
  ensure_role "$ROLE_READ" "$PRIVS_READ"
  ensure_role "$ROLE_OPERATE" "$PRIVS_OPERATE"
  ensure_role "$ROLE_ADMIN" "$PRIVS_ADMIN"
  ensure_role "$ROLE_REVIEW" "$PRIVS_REVIEW"
  ensure_role "$ROLE_NODE" "$PRIVS_NODE"
  if [[ -n "$MCP_POOL" ]]; then
    [[ "$MCP_POOL" =~ ^[A-Za-z0-9_.-]{1,64}$ ]] || die "bad MCP_POOL"
    if pvesh get /pools --output-format json 2>/dev/null | grep -Eq "\"poolid\" *: *\"${MCP_POOL}\""; then
      log "pool ${MCP_POOL} exists"
    else
      run pvesh create /pools --poolid "$MCP_POOL" --comment "Guests visible to the Proxmox MCP broker"
      log "pool ${MCP_POOL} created: add the guests the AI may see (Datacenter > Permissions > Pools)"
    fi
  fi
  log "roles ok"
}

user_exists() { pvesh get "/access/users/$1" --output-format json >/dev/null 2>&1; }
token_exists() { pvesh get "/access/users/$1/token/${TOKEN_NAME}" --output-format json >/dev/null 2>&1; }

# Print "<path> <role>" for every ProxmoxMCP-* ACL entry of one subject.
# kind: user | token. Perl JSON::PP is part of every Proxmox VE node.
mcp_acls_of() {
  local kind="$1" subject="$2"
  pveum acl list --output-format json | perl -MJSON::PP -e '
    my $d = decode_json(join("", <STDIN>));
    for my $e (@$d) {
      next unless $e->{type} eq $ARGV[0] && $e->{ugid} eq $ARGV[1] && $e->{roleid} =~ /^ProxmoxMCP-/;
      print "$e->{path} $e->{roleid}\n";
    }' "$kind" "$subject"
}

# Converge the MCP ACLs of a subject (user or token) to exactly: $role on every path,
# $role on STORAGE_PATHS (operate/admin only), the node role on /nodes (NODE_AUDIT=1).
# Every other ProxmoxMCP-* entry of that subject is removed.
set_acl() {
  local kind="$1" subject="$2" role="$3" paths="$4" p want="" path r
  for p in $paths; do want+="${p} ${role}"$'\n'; done
  if [[ "$role" != "$ROLE_READ" && -n "$STORAGE_PATHS" ]]; then
    for p in $STORAGE_PATHS; do
      [[ "$p" =~ ^/storage/[A-Za-z0-9_.-]+$ ]] || die "STORAGE_PATHS entry '$p' must be /storage/<name>"
      want+="${p} ${role}"$'\n'
    done
  fi
  [[ "$NODE_AUDIT" == "1" ]] && want+="/nodes ${ROLE_NODE}"$'\n'
  local acl_type="user"; [[ "$kind" == "tokens" ]] && acl_type="token"
  # Reading the ACL list is safe in DRY_RUN; only the deletes are printed instead of run.
  while read -r path r; do
    [[ -n "$path" ]] || continue
    if ! grep -qxF "${path} ${r}" <<<"$want"; then
      run pveum acl delete "$path" "--${kind}" "$subject" --roles "$r"
    fi
  done < <(mcp_acls_of "$acl_type" "$subject")
  for p in $paths; do
    run pveum acl modify "$p" "--${kind}" "$subject" --roles "$role" --propagate 1
  done
  if [[ "$role" != "$ROLE_READ" && -n "$STORAGE_PATHS" ]]; then
    for p in $STORAGE_PATHS; do
      run pveum acl modify "$p" "--${kind}" "$subject" --roles "$role" --propagate 0
    done
  fi
  if [[ "$NODE_AUDIT" == "1" ]]; then
    run pveum acl modify /nodes "--${kind}" "$subject" --roles "$ROLE_NODE" --propagate 1
  fi
}

cmd_user() {
  local short="$1" mode="$2"
  valid_short "$short"
  local role userid paths
  role="$(role_for_mode "$mode")"
  userid="mcp-${short}@pve"
  paths="$(acl_paths)"
  if user_exists "$userid"; then
    run pveum user modify "$userid" --enable 1 --comment "Proxmox MCP (${mode})"
  else
    # No --password: a pve-realm user without a password cannot log in to the GUI or get a ticket.
    run pveum user add "$userid" --enable 1 --comment "Proxmox MCP (${mode})"
  fi
  set_acl users "$userid" "$role" "$paths"
  log "user ${userid}: ${role} on ${paths}"
}

expiry_epoch() {
  if ! [[ "$TOKEN_TTL_DAYS" =~ ^[0-9]+$ ]] || ((TOKEN_TTL_DAYS < 1 || TOKEN_TTL_DAYS > 365)); then
    die "TOKEN_TTL_DAYS must be 1..365"
  fi
  date -d "+${TOKEN_TTL_DAYS} days" +%s
}

# Print "<userid>!mcp=<uuid>" on stdout exactly once. Nothing else goes to stdout.
emit_token() {
  local userid="$1" json="$2" value
  value="$(printf '%s' "$json" | sed -n 's/.*"value" *: *"\([0-9a-fA-F-]\{36\}\)".*/\1/p')"
  [[ "$value" =~ ^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$ ]] || die "could not read the token value from pveum output"
  printf '%s!%s=%s\n' "$userid" "$TOKEN_NAME" "$value"
}

new_token() {
  local userid="$1" comment="$2" exp json
  exp="$(expiry_epoch)"
  # The user expires with the token: a forgotten user cannot outlive its key.
  run pveum user modify "$userid" --expire "$exp"
  log "token_expires=$(date -u -d "@${exp}" +%Y-%m-%d) (record it: Set-BrokerEnrollment.ps1 -TokenExpires <date>)"
  if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY_RUN: pveum user token add ${userid} ${TOKEN_NAME} --privsep 1 --expire ${exp} (secret not shown)"
    return 0
  fi
  if token_exists "$userid"; then
    [[ "$ROTATE" == "1" ]] || die "token ${userid}!${TOKEN_NAME} exists. Its secret cannot be shown again. Set ROTATE=1 to replace it."
    if pveum user token modify --help 2>&1 | grep -q -- '--regenerate'; then
      # PVE >= 9.1 (libpve-access-control 9.1.0): new secret, same token id, ACLs kept.
      json="$(pveum user token modify "$userid" "$TOKEN_NAME" --regenerate 1 --expire "$exp" --output-format json)"
      emit_token "$userid" "$json"
      return 0
    fi
    pveum user token delete "$userid" "$TOKEN_NAME" >&2
  fi
  json="$(pveum user token add "$userid" "$TOKEN_NAME" --privsep 1 --expire "$exp" --comment "$comment" --output-format json)"
  emit_token "$userid" "$json"
}

cmd_issue_token() {
  local short="$1" mode="$2"
  cmd_user "$short" "$mode"
  local userid="mcp-${short}@pve" role paths
  role="$(role_for_mode "$mode")"
  paths="$(acl_paths)"
  new_token "$userid" "Proxmox MCP broker (${mode})"
  # Token ACL = user ACL (privsep=1: effective rights are the intersection, never more than the user).
  if [[ "$DRY_RUN" != "1" ]]; then
    set_acl tokens "${userid}!${TOKEN_NAME}" "$role" "$paths"
  fi
  log "token ${userid}!${TOKEN_NAME}: ${role}, expires in ${TOKEN_TTL_DAYS} days"
}

cmd_review_token() {
  local userid="mcp-review@pve" paths
  paths="$(acl_paths)"
  if user_exists "$userid"; then run pveum user modify "$userid" --enable 1; else run pveum user add "$userid" --comment "Proxmox MCP access review (read only)"; fi
  run pveum acl modify /access --users "$userid" --roles "$ROLE_REVIEW" --propagate 1
  local p
  for p in $paths; do run pveum acl modify "$p" --users "$userid" --roles "$ROLE_REVIEW" --propagate 1; done
  new_token "$userid" "Proxmox MCP access review"
  if [[ "$DRY_RUN" != "1" ]]; then
    run pveum acl modify /access --tokens "${userid}!${TOKEN_NAME}" --roles "$ROLE_REVIEW" --propagate 1
    for p in $paths; do run pveum acl modify "$p" --tokens "${userid}!${TOKEN_NAME}" --roles "$ROLE_REVIEW" --propagate 1; done
  fi
}

mcp_users() {
  pveum user list --output-format json | grep -o '"userid" *: *"mcp-[a-z0-9-]*@pve"' | sed 's/.*"\(mcp-[a-z0-9-]*@pve\)"/\1/' | sort -u
}

revoke_user() {
  local userid="$1" path role
  [[ "$userid" =~ ^mcp-[a-z0-9-]+@pve$ ]] || die "refusing to revoke '$userid'"
  if token_exists "$userid"; then run pveum user token delete "$userid" "$TOKEN_NAME"; fi
  run pveum user modify "$userid" --enable 0
  # Remove every ProxmoxMCP-* ACL of the user (token ACLs go with the token).
  while read -r path role; do
    [[ -n "$path" ]] || continue
    run pveum acl delete "$path" --users "$userid" --roles "$role"
  done < <(mcp_acls_of user "$userid")
  log "revoked ${userid}: token deleted, user disabled, ACLs removed"
}

cmd_list() {
  local u
  for u in $(mcp_users); do
    log "== ${u}"
    pveum user token list "$u" --output-format json-pretty >&2 || true
    pveum user permissions "$u" --output-format json-pretty >&2 || true
  done
}

main() {
  local cmd="${1:-}"
  require_pve
  audit_trail "$@"
  shift || true
  case "$cmd" in
    roles) cmd_roles ;;
    user) [[ $# -eq 2 ]] || die "usage: user <short> <ro|operator|rw>"; cmd_user "$1" "$2" ;;
    issue-token) [[ $# -eq 2 ]] || die "usage: issue-token <short> <ro|operator|rw>"; cmd_issue_token "$1" "$2" ;;
    review-token) cmd_review_token ;;
    revoke) [[ $# -eq 1 ]] || die "usage: revoke <short>"; valid_short "$1"; revoke_user "mcp-$1@pve" ;;
    revoke-all)
      local u
      for u in $(mcp_users); do revoke_user "$u"; done
      ;;
    list) cmd_list ;;
    *) die "usage: $0 roles | user <short> <mode> | issue-token <short> <mode> | review-token | revoke <short> | revoke-all | list" ;;
  esac
}

main "$@"
