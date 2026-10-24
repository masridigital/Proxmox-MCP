"""H3 red team: credential file races, token format edge cases, host configuration."""

import os
import stat
import sys
from types import SimpleNamespace

import pytest

from proxmox_mcp import client as client_mod
from proxmox_mcp import credentials

SECRET = "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed"
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file semantics")


@pytest.fixture
def creddir(tmp_path, monkeypatch):
    d = tmp_path / "creds"
    d.mkdir(mode=0o700)
    monkeypatch.delenv("BROKER_CREDENTIALS_DIR", raising=False)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(d))
    return d


def put(d, name, text, mode=0o400):
    p = d / name
    p.write_text(text) if isinstance(text, str) else p.write_bytes(text)
    os.chmod(p, mode)
    return p


@pytest.mark.parametrize("name", ["tok\n", "tok\r", "\ntok", "tok\x00", "tok/../x"])
def test_names_use_fullmatch(creddir, name):
    put(creddir, "tok", "x")
    with pytest.raises(credentials.CredentialError, match="invalid credential name"):
        credentials.read_credential(name)


@posix_only
def test_symlink_swapped_in_between_lstat_and_open(creddir, tmp_path, monkeypatch):
    target = put(tmp_path, "outside", f"root@pam!x={SECRET}", mode=0o400)
    p = put(creddir, "tok", "legit")
    real_open = os.open

    def racing_open(path, flags, *a):
        if str(path) == str(p):
            os.chmod(p, 0o600)
            os.unlink(p)
            os.symlink(target, p)
        return real_open(path, flags, *a)

    monkeypatch.setattr(credentials.os, "open", racing_open)
    with pytest.raises(credentials.CredentialError) as ei:
        credentials.read_credential("tok")
    assert SECRET not in str(ei.value)


@posix_only
def test_regular_file_swapped_in_between_lstat_and_open(creddir, monkeypatch):
    p = put(creddir, "tok", "legit")
    other = put(creddir, "other", "attacker")
    real_open = os.open

    def racing_open(path, flags, *a):
        if str(path) == str(p):
            os.replace(other, p)
        return real_open(path, flags, *a)

    monkeypatch.setattr(credentials.os, "open", racing_open)
    with pytest.raises(credentials.CredentialError, match="changed while opening"):
        credentials.read_credential("tok")


@posix_only
def test_hard_link_refused(creddir, tmp_path):
    p = put(creddir, "tok", "x")
    os.link(p, tmp_path / "second-name")
    with pytest.raises(credentials.CredentialError, match="more than one link"):
        credentials.read_credential("tok")


def _fake_stat(**kw):
    base = {"st_mode": stat.S_IFREG | 0o400, "st_size": 10, "st_uid": 0, "st_nlink": 1, "st_dev": 1,
            "st_ino": 7, "st_mtime_ns": 1, "st_ctime_ns": 1, "st_file_attributes": 0}
    base.update(kw)
    return SimpleNamespace(**base)


def test_windows_reparse_point_refused(monkeypatch):
    monkeypatch.setattr(credentials, "IS_WINDOWS", True)
    with pytest.raises(credentials.CredentialError, match="is a link"):
        credentials._check_stat("tok", _fake_stat(st_file_attributes=0x400))


def test_windows_open_following_a_reparse_point_is_detected(creddir, monkeypatch):
    # On Windows O_NOFOLLOW does not exist: lstat sees the file, open follows a
    # reparse point planted in between. The fd's file id differs from the lstat'd one.
    put(creddir, "tok", "x", mode=0o400)
    monkeypatch.setattr(credentials, "IS_WINDOWS", True)
    real_fstat = os.fstat
    monkeypatch.setattr(credentials.os, "fstat", lambda fd: _with_ino(real_fstat(fd), 999999))
    with pytest.raises(credentials.CredentialError, match="changed while opening"):
        credentials.read_credential("tok")
    monkeypatch.setattr(credentials.os, "fstat", lambda fd: _with_ino(real_fstat(fd), 0))
    with pytest.raises(credentials.CredentialError, match="changed while opening"):
        credentials.read_credential("tok")  # a filesystem without file ids is not trusted


def _with_ino(st, ino):
    fields = {k: getattr(st, k) for k in dir(st) if k.startswith("st_")}
    fields["st_ino"] = ino
    return SimpleNamespace(**fields)


def test_read_with_stat_reports_the_file_read(creddir):
    p = put(creddir, "tok", "abc\n")
    text, st = credentials.read_credential_with_stat("tok")
    assert text == "abc" and st.st_ino == os.stat(p).st_ino


def test_cache_key_includes_ctime():
    a = client_mod._stat_key(_fake_stat(st_ctime_ns=1))
    b = client_mod._stat_key(_fake_stat(st_ctime_ns=2))
    assert a != b


# --- token format ------------------------------------------------------------------------------


def test_bom_is_stripped(creddir):
    put(creddir, "tok", ("﻿" + f"a@pve!mcp={SECRET}\r\n").encode("utf-8"))
    assert credentials.parse_api_token(credentials.read_credential("tok")).secret == SECRET


@pytest.mark.parametrize(
    "text",
    [
        f"PVEAPIToken=a@pve!mcp={SECRET}",
        f"a@pve!mcp={SECRET}\nb@pve!mcp={SECRET}",
        f"a@pve!mcp={SECRET}\x00",
        f"a@pve!mcp ={SECRET}",
        f"a@pve!mcp={SECRET[:-1]}",
        f"a@pve!mcp={SECRET}0",
        f"a@pve!mcp={SECRET.replace('1', '１')}",  # full-width digit
        f"a@pve!mcp={SECRET}\r\nAuthorization: x",
        f"a@pve!m:cp={SECRET}",
        f"a@pve!mcp={{{SECRET}}}",
        f"a@pеve!mcp={SECRET}",  # Cyrillic e
        f"@pve!mcp={SECRET}",
        f"a@!mcp={SECRET}",
        f"a@pve!={SECRET}",
        "",
        None,
        12345,
    ],
)
def test_token_format_edge_cases(text):
    with pytest.raises(credentials.CredentialError) as ei:
        credentials.parse_api_token(text)
    assert SECRET not in str(ei.value)


def test_token_header_has_no_crlf_and_repr_hides_secret():
    tok = credentials.parse_api_token(f"  a+b@pve!mcp-1={SECRET.upper()}  ")
    assert "\r" not in tok.header() and "\n" not in tok.header()
    assert SECRET.upper() not in repr(tok) and SECRET.upper() not in str(tok)


# --- PROXMOX_HOST ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    ["pve\n", "pve.example.internal\n", "2130706433", "999.1.1.1", "0x7f.1", "fe80::1%eth0",
     "-pve", "pve-", "pve_x", "a..b", "pve.", "", "pve:8006", "user@pve", "pve/x", "[::1]",
     "pеve", "a" * 64 + ".example"],
)
def test_bad_hosts_rejected(host):
    with pytest.raises(ValueError, match="PROXMOX_HOST"):
        client_mod.base_url(host, "8006")


@pytest.mark.parametrize(
    "host,url",
    [
        ("pve.example.internal", "https://pve.example.internal:8006/api2/json"),
        ("pve01", "https://pve01:8006/api2/json"),
        ("192.0.2.10", "https://192.0.2.10:8006/api2/json"),
        ("::1", "https://[::1]:8006/api2/json"),
        ("2001:db8::10", "https://[2001:db8::10]:8006/api2/json"),
    ],
)
def test_good_hosts(host, url):
    assert client_mod.base_url(host, "8006") == url
