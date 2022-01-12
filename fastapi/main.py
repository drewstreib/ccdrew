from fastapi import FastAPI, Request
from starlette.responses import Response
import datetime
import os
import re
import json
import time
import typing
import unicodedata

POSTDATADIR = "/app/postdata/"
MAX_POST_AGE = 10800
MAX_DNS_LOGS = 50

app = FastAPI()

USAGE = {
    "WARNING": (
        "If you have made it to this page and don't know why, it is "
        "because you've received some sort of activity that you don't recognize pointing to "
        "ccdrew.cc. This is a testing tool for web vulnerabilities run by "
        "Drew Streib."
    ),
    "WARNING_PASSIVE": (
        "This tool NEVER initiates connections to other "
        "servers to perform its functions. It merely logs activity and reports it back."
    ),
    "Contact": "Please email Drew Streib <drew@alt.org> with any questions.",
    "Usage": {
        "/": (
            "This page. Entire site is accessible over 80 or 443, and TLS certs are valid "
            "for root domain and *.ccdrew.cc."
        ),
        "/dnslog": "Logs of last {} DNS lookups made of ANYTHING.ccdrew.cc.".format(
            MAX_DNS_LOGS
        ),
        "/post/POSTID": (
            "Accepts and logs any data including URL parameters and body "
            "contents. POSTID is arbitrary but required. Overwrites any prior like POSTID. "
            "Works with GET/POST/PUT methods."
        ),
        "/postlog": "Last {} hours of /post data.".format(MAX_POST_AGE / 3600),
        "/postlog/POSTID": "Returns only POSTID data.",
    },
}


class PrettyJSONResponse(Response):
    media_type = "application/json"

    def render(self, content: typing.Any) -> bytes:
        return json.dumps(
            content,
            ensure_ascii=False,
            allow_nan=False,
            indent=4,
            separators=(", ", ": "),
        ).encode("utf-8")


def lastlines(fname, N):
    lines = []
    with open(fname) as file:
        for line in file.readlines()[-N:]:
            # only match subdomains
            if re.search("\(.+(?<!\(www)\.ccdrew\.cc\)", line, re.IGNORECASE):
                lines.append(line)
    return lines[-50:]


def slugify(value):
    value = str(value)
    value = (
        unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    )
    value = re.sub(r"[^\w\s-]", "", value)
    return re.sub(r"[-\s]+", "-", value).strip("-_")


@app.get("/", response_class=PrettyJSONResponse)
def read_root():
    return USAGE


@app.get("/dnslog", response_class=PrettyJSONResponse)
def read_dnslog():
    return lastlines("/bindlog/bind.log", 1000)


@app.get("/dnslog/{subdomain}")
def read_dnslog_sub(subdomain: str):
    return lastlines("/bindlog/bind.log", 1000)


@app.api_route(
    "/post/{post_id}", methods=["GET", "POST", "PUT"], response_class=PrettyJSONResponse
)
async def raw_post(post_id: str, request: Request):
    data = {
        "post_id": post_id,
        "timestamp": datetime.datetime.now().isoformat() + "Z",
        "method": request.method,
        "host": request.headers["x-forwarded-host"],
        "path": str(request.url).replace("http://backends", ""),
        # "params": {k: v for (k, v) in request.query_params.items()},
        "client_ip": request.headers["x-forwarded-for"],
        "content-type": request.headers["content-type"]
        if ("content-type" in request.headers)
        else "",
        "body": (await request.body()).decode(),
    }
    if data["content-type"] == "":
        del data["content-type"]
    if data["body"] == "":
        del data["body"]
    with open(POSTDATADIR + slugify(post_id), "w") as outfile:
        json.dump(data, outfile)
        outfile.close()
    return data


@app.get("/postlog", response_class=PrettyJSONResponse)
def read_postlog():
    output = {}
    for f in os.listdir(POSTDATADIR):
        fullname = os.path.join(POSTDATADIR, f)
        if os.path.isfile(fullname):
            # remove old files
            if time.time() - os.path.getmtime(fullname) > MAX_POST_AGE:
                os.remove(fullname)
            else:
                with open(fullname) as json_file:
                    data = json.load(json_file)
                    output[f] = data
    return output


@app.get("/postlog/{post_id}", response_class=PrettyJSONResponse)
def read_postlog_id(post_id: str):
    try:
        with open(os.path.join(POSTDATADIR, slugify(post_id))) as json_file:
            data = json.load(json_file)
            output = data
    except:
        return {}
    return output
