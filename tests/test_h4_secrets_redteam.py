"""H4 red team: secret redaction bypasses (SOC 2 C1.1 confidentiality)."""
# Token-shaped test values are split across adjacent string literals so that secret
# scanners (GitHub push protection, gitleaks) never see a contiguous fake credential.

import base64
import json

import pytest

from proxmox_mcp import output


def unwrap(text):
    return json.loads("\n".join(text.split("\n")[2:-1]))


@pytest.mark.parametrize(
    "key",
    [
        "Passw0rd",
        "pwd",
        "pass_phrase",
        "passphrase",
        "apikey",
        "api-key",
        "API_KEY",
        "client_secret",
        "clientSecret",
        "auth",
        "Authorization",
        "credentials",
        "credential",
        "cookie",
        "Set-Cookie",
        "sshkeys",
        "pa55word",
        "s3cr3t",
        "t0ken",
        "session_id",
        "sessionToken",
        "keyring",
        "privkey",
        "otp",
        "totp",
        "x-api-key",
        "bind_password",
        "hmac",
        "salt",
        "keys",
        "authorized_keys",
        "signature",
    ],
)
def test_secret_keys(key):
    out = unwrap(output.render_result({"data": {key: "SuperSecretValue123", "vmid": 100}}))
    assert out["data"][key] == "[REDACTED]", key
    assert out["data"]["vmid"] == 100


@pytest.mark.parametrize(
    "key",
    [
        "keyboard",
        "keymap",
        "vmid",
        "name",
        "net0",
        "scsi0",
        "ipconfig0",
        "hostpci0",
        "description",
        "tags",
        "digest",
        "fingerprint",
        "status",
        "uptime",
        "ring0_addr",
        "mp0",
        "efidisk0",
        "tpmstate0",
        "serial0",
        "type",
        "comment",
        "node",
    ],
)
def test_ordinary_keys_untouched(key):
    out = unwrap(output.render_result({key: "value-1"}))
    assert out[key] == "value-1"


PEM_BODY = "MIIEpAIBAAKCAQEAsecretbody0123456789"
FREE_TEXT_SECRETS = [
    f"-----BEGIN RSA PRIVATE KEY-----\r\n{PEM_BODY}\r\n-----END RSA PRIVATE KEY-----\r\n",
    f"-----BEGIN OPENSSH PRIVATE KEY-----\n{PEM_BODY}\n-----END OPENSSH PRIVATE KEY-----",
    f"-----BEGIN ENCRYPTED PRIVATE KEY-----\n{PEM_BODY}\n-----END ENCRYPTED PRIVATE KEY-----",
    f"-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n{PEM_BODY}\n-----END PGP PRIVATE KEY BLOCK-----",
    f"-----BEGIN EC PRIVATE KEY-----\\n{PEM_BODY}\\n-----END EC PRIVATE KEY-----",  # escaped newlines
    f"-----BEGIN PRIVATE KEY-----\n{PEM_BODY}",  # truncated, no END
    "PuTTY-User-Key-File-3: ssh-ed25519\r\nEncryption: none\r\nComment: k\r\nPublic-Lines: 2\r\nAAAAC3Nza\r\n"
    f"Private-Lines: 1\r\n{PEM_BODY}\r\nPrivate-MAC: 0123456789abcdef",
    f"PuTTY-User-Key-File-2: ssh-rsa\nPrivate-Lines: 1\n{PEM_BODY}\n",
]


@pytest.mark.parametrize("text", FREE_TEXT_SECRETS)
def test_private_key_blocks(text):
    assert "secretbody" not in output.redact_text(text)
    assert "secretbody" not in output.render_result({"description": text})


JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIn0."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
TOKENS_IN_TEXT = [
    ("jwt", f"bearer-less {JWT} trailing"),
    ("jwt-none-alg", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."),
    ("aws key id", "aws id AKIAIOSFODNN7EXAMPLE used"),
    ("aws secret", "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("aws env", "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    (
        "azure conn",
        "DefaultEndpointsProtocol=https;AccountName=x;AccountKey=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA==;",
    ),
    (
        "azure sas",
        "https://x.blob.core.windows.net/c?sv=2022-11-02&sig=AbCdEf0123456789%2B%2FxyzXYZ%3D&se=2026",
    ),
    ("azure client secret", "client secret abc8Q~AbCdEfGhIjKlMnOpQrStUvWxYz0123456 ok"),
    (
        "azure shared key",
        "Endpoint=sb://x/;SharedAccessKeyName=root;SharedAccessKey=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA=",
    ),
    ("cf api token env", "CF_API_TOKEN=Abcdefghijklmnopqrstuvwxyz0123456789ABCD"),
    ("cf global key header", "X-Auth-Key: 0123456789abcdef0123456789abcdef01234"),
    (
        "cf access secret",
        "CF-Access-Client-Secret: 0123456789abcdef0123456789abcdef0123456789abcdef",
    ),
    ("cf origin ca", "v1.0-" + "a" * 24 + "-" + "b" * 146),
    (
        "cf tunnel token",
        "cloudflared service install eyJhIjoiMDEyMzQ1Njc4OWFiY2RlZiIsInQiOiJ4eXoiLCJzIjoiYWJjIn0=",
    ),
    ("github", "gh" + "p_0123456789abcdefghijABCDEFGHIJ012345"),
    (
        "github pat",
        "github"
        + "_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRS",
    ),
    ("slack", "xo" + "xb-0123456789-0123456789-abcdefghijklmnopqrstuvwx"),
    ("stripe", "sk" + "_live_0123456789abcdefghijklmn"),
    ("anthropic", "sk" + "-ant-api03-0123456789abcdefghijklmnopqrstuvwxyz"),
    ("google", "AI" + "zaSyA0123456789abcdefghijklmnopqrstuv"),
    ("gitlab", "gl" + "pat-0123456789abcdefghij"),
    ("password kv", "password=hunter2xyz"),
    ("password json", '{"password": "hunter2xyz"}'),
    ("passwd colon", "passwd: hunter2xyz"),
    ("pwd", "pwd=hunter2xyz"),
    ("passphrase", "pass_phrase: hunter2xyz"),
    ("cli flag", "qm set 100 --cipassword hunter2xyz --ciuser root"),
    ("url userinfo", "https://admin:hunter2xyz@pve.example.com:8006/"),
    ("url-encoded", "password%3Dhunter2xyz%26user%3Droot"),
    ("url-encoded json", "%7B%22password%22%3A%22hunter2xyz%22%7D"),
    (
        "sshkeys urlencoded",
        "sshkeys=ssh-rsa%20AAAAB3NzaC1yc2EAAAADAQABAAABAQhunter2xyz%20user%40host",
    ),
    ("bearer", "Authorization: Bearer hunter2xyz.abc.def"),
    ("bare bearer", "curl -H 'bearer hunter2xyz0123'"),
    ("basic", "authorization=Basic aHVudGVyMnh5ejpwdw=="),
    ("cookie hdr", "Cookie: PVEAuthCookie=PVE:root@pam:65A1B2C3::hunter2xyzhunter2xyzhunter2xyz"),
    ("pbs token", "PBSAPIToken=root@pam!backup:hunter2xyz-0000"),
    ("pve ticket", "PVE:root@pam:65A1B2C3::aGVudGVyMnh5ejAxMjM0NTY3ODlhYmNkZWZnaGlqa2xtbm9w"),
    ("api key label", "api-key: hunter2xyz"),
    ("client_secret", "client_secret=hunter2xyz"),
    ("token", "token: hunter2xyz"),
    ("credentials", "credentials=hunter2xyz"),
    ("fullwidth label", "ｐａｓｓｗｏｒｄ＝hunter2xyz"),
    ("zero-width label", "pass​word=hunter2xyz"),
    ("base64 wrapped", base64.b64encode(b"password=hunter2xyz").decode()),
]


@pytest.mark.parametrize("name, text", TOKENS_IN_TEXT, ids=[n for n, _ in TOKENS_IN_TEXT])
def test_secret_tokens_in_free_text(name, text):
    red = output.redact_text(text)
    secretish = (
        "hunter2xyz",
        "SflKxwRJ",
        "IOSFODNN7",
        "wJalrXUtn",
        "Zm9vYmFy",
        "AbCdEf0123",
        "AbCdEfGhIj",
        "abcdefghijklmnopqrstuvwxyz0123456789ABCD",
        "0123456789abcdef0123",
        "aaaaaaaaaaaa",
        "MDEyMzQ1Njc4",
        "ghp_0123",
        "11ABCDEFG",
        "xoxb-0123",
        "sk_live_0",
        "api03-0123",
        "SyA0123",
        "glpat-0",
        "aHVudGVy",
        "eyJzdWIiOiJhZG1pbiJ9",
        "aGVudGVy",
    )
    for s in secretish:
        assert s not in red, (name, red)
    assert "[REDACTED" in red


def test_secret_value_redaction_keeps_label():
    assert output.redact_text("password=hunter2xyz rest") == "password=[REDACTED] rest"
