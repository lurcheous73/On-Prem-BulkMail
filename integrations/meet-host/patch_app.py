#!/usr/bin/env python3
"""Render the adapter import into the reviewed Canada app; never deploy directly."""
import argparse
import hashlib
from pathlib import Path

BASELINE_SHA256 = "5b885603568bb2793f769bfc24dfeb6d25da560b20f6b1060805399d5c5e4c6b"
MARKER = "\n\ninit_db()\n\nHTTPServer(\n"
INSERT = "\n\n# CT400 portal identity adapter; existing accounts and meeting data retained.\nfrom grange_ct400_sso import wrap_handler\nHandler = wrap_handler(Handler, globals())\n\ninit_db()\n\nHTTPServer(\n"
HOOK = "# CT400 portal identity adapter; existing accounts and meeting data retained.\nfrom grange_ct400_sso import wrap_handler\nHandler = wrap_handler(Handler, globals())\n\n"
DELETE_MARKER = '''            with db() as c:
                c.execute(
                    """
                    UPDATE meetings
                    SET deleted=1
                    WHERE id=?
                    """,
                    (mid,)
                )
'''
DELETE_REPLACEMENT = '''            with db() as c:
                changed = c.execute(
                    """
                    UPDATE meetings
                    SET deleted=1
                    WHERE id=? AND deleted=0 AND (owner=? OR ?=1)
                    """,
                    (mid, creator, 1 if HOSTS.get(creator, {}).get("admin") else 0)
                ).rowcount
                if changed != 1:
                    self.send_html(page("<h1>Meeting unavailable or access denied</h1>"), 403)
                    return
'''


def render(source):
    if hashlib.sha256(source).hexdigest() != BASELINE_SHA256:
        raise ValueError("Meeting app differs from the reviewed Canada baseline; reconcile changes before patching")
    text = source.decode("utf-8")
    if text.count(MARKER) != 1:
        raise ValueError("Unique startup hook not found")
    if text.count(DELETE_MARKER) != 1:
        raise ValueError("Unique meeting deletion handler not found")
    patched = text.replace(DELETE_MARKER, DELETE_REPLACEMENT, 1).replace(MARKER, INSERT, 1)
    compile(patched, "app.py", "exec")
    return patched.encode("utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.source.resolve() == args.output.resolve():
        parser.error("Write a reviewable output file; never overwrite the source")
    patched = render(args.source.read_bytes())
    with args.output.open("xb") as output:
        output.write(patched)
    print("Patched copy created; no database, password or service was changed.")
