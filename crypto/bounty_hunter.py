#!/usr/bin/env python3
"""Read-only bounty discovery. Never executes exploits, submits, or credits earnings."""
import argparse
import asyncio
from datetime import datetime, timezone
import json
import logging
import os
import re
import sqlite3
from pathlib import Path
from urllib.parse import urlencode
import aiohttp

IMMUNEFI="https://immunefi.com/public-api/bounties.json"
GITHUB="https://api.github.com/search/issues"
LOG=logging.getLogger("bounty_hunter")

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def amount(value):
    if value is None or isinstance(value,bool): return None
    if isinstance(value,dict):
        for k in ("amount","max","maxBounty","value","usd"):
            if k in value:
                n=amount(value[k])
                if n is not None: return n
        return None
    if isinstance(value,(int,float)): return float(value) if 0<=value<1e12 else None
    if isinstance(value,str):
        m=re.fullmatch(r"\s*\$?\s*([\d,.]+)\s*([kKmM]?)\s*(?:USD|USDC)?\s*",value)
        if m:
            n=float(m.group(1).replace(",",""))*{"":1,"k":1000,"m":1000000}[m.group(2).lower()]
            return n if n<1e12 else None
    return None

def immunefi_rows(data):
    if isinstance(data,dict): data=data.get("bounties",data.get("data"))
    if not isinstance(data,list): raise ValueError("Unexpected Immunefi schema")
    rows=[]
    for p in data:
        if not isinstance(p,dict) or p.get("isPaused") is True: continue
        slug=p.get("slug")
        if not isinstance(slug,str) or not re.fullmatch(r"[A-Za-z0-9_-]+",slug): continue
        end=p.get("endDate")
        if end:
            try:
                d=datetime.fromisoformat(str(end).replace("Z","+00:00"))
                if d.tzinfo is None: d=d.replace(tzinfo=timezone.utc)
                if d<datetime.now(timezone.utc): continue
            except ValueError: pass
        rows.append({"id":"immunefi:"+slug,"platform":"immunefi",
            "title":str(p.get("project") or slug)[:300],
            "url":"https://immunefi.com/bug-bounty/"+slug+"/information/",
            "reward_max_usd":amount(p.get("maxBounty")),
            "status":"listed_not_validated",
            "eligibility":"invite_only" if p.get("inviteOnly") else "check_program_rules",
            "kyc_required":bool(p.get("kyc"))})
    return rows

def github_rows(data):
    if not isinstance(data,dict) or not isinstance(data.get("items"),list):
        raise ValueError("Unexpected GitHub search schema")
    rows=[]
    for p in data["items"]:
        if not isinstance(p,dict) or "pull_request" in p: continue
        url=p.get("html_url")
        if not isinstance(url,str) or not re.fullmatch(r"https://github\.com/[^/]+/[^/]+/issues/\d+",url): continue
        title=str(p.get("title") or "")
        body=str(p.get("body") or "")
        labels=p.get("labels") or []
        has_bounty_label=any("bounty" in str(x.get("name","")).lower()
                             for x in labels if isinstance(x,dict))
        m=re.search(r"\bbounty\s*(?::|=|of|up to)?\s*\$\s*([\d,]+(?:\.\d{1,2})?)([kKmM]?)",title,re.I)
        if m is None and (re.search(r"\bbounty\b",title,re.I) or has_bounty_label):
            m=re.search(r"\b(?:bounty|reward|payout)\s*(?::|=|of|up to)?\s*\$\s*([\d,]+(?:\.\d{1,2})?)([kKmM]?)",
                        body[:1500],re.I)
        rows.append({"id":"github:"+url.split("github.com/",1)[1],
            "platform":"github","title":str(p.get("title") or "")[:300],"url":url,
            "reward_max_usd":amount(m.group(1)+m.group(2)) if m else None,
            "status":"listed_not_validated","eligibility":"check_issue_rules",
            "kyc_required":None})
    return rows

def database(path):
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    con=sqlite3.connect(path)
    con.execute("CREATE TABLE IF NOT EXISTS opportunities (id TEXT PRIMARY KEY, platform TEXT, title TEXT, url TEXT, reward_max_usd REAL, status TEXT, first_seen TEXT, last_seen TEXT)")
    con.execute("CREATE TABLE IF NOT EXISTS scan_runs (at TEXT, source TEXT, status TEXT, found INTEGER, error TEXT)")
    con.commit()
    return con

def save(con,source,rows):
    timestamp=now()
    for r in rows:
        con.execute("""INSERT INTO opportunities VALUES (?,?,?,?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET title=excluded.title,url=excluded.url,
        reward_max_usd=excluded.reward_max_usd,status=excluded.status,
        last_seen=excluded.last_seen""",
        (r["id"],r["platform"],r["title"],r["url"],r["reward_max_usd"],
         r["status"],timestamp,timestamp))
    con.execute("INSERT INTO scan_runs VALUES (?,?,?,?,?)",(timestamp,source,"success",len(rows),None))
    con.commit()

class CryptoBountyHunter:
    def __init__(self,wallet_config=None,db_path="bounties.sqlite3"):
        self.wallet_config={}  # never store/use wallet secrets
        self.db_path=db_path
        self.active_bounties={}
        self.completed_bounties={}
        self.earnings_tracker={"verified_earned_usd":0.0}

    async def scan_bounty_platforms(self):
        con=database(self.db_path)
        found=[]
        failures=[]
        timeout=aiohttp.ClientTimeout(total=45)
        headers={"User-Agent":"Garcar-Bounty-Discovery/1.0"}
        try:
            async with aiohttp.ClientSession(timeout=timeout,headers=headers,raise_for_status=True) as session:
                sources={
                    "immunefi":(IMMUNEFI,immunefi_rows),
                    "github":(GITHUB+"?"+urlencode({"q":"is:issue is:open bounty crypto","per_page":100,"sort":"updated"}),github_rows)
                }
                for source,(url,parser) in sources.items():
                    try:
                        headers2={}
                        if source=="github" and (os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")):
                            headers2["Authorization"]="Bearer "+(os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN"))
                        async with session.get(url,headers=headers2,allow_redirects=False) as response:
                            response.raise_for_status()
                            chunks=[]
                            bytes_read=0
                            async for chunk in response.content.iter_chunked(65536):
                                bytes_read+=len(chunk)
                                if bytes_read>16*1024*1024: raise ValueError("Source too large")
                                chunks.append(chunk)
                            rows=parser(json.loads(b"".join(chunks)))
                        save(con,source,rows)
                        found.extend(rows)
                        LOG.info("%s: %d programs/issues",source,len(rows))
                    except (aiohttp.ClientError,ValueError,TimeoutError,json.JSONDecodeError) as e:
                        msg="%s: %s: %s"%(source,type(e).__name__,str(e))
                        failures.append(msg)
                        LOG.error(msg)
                        con.execute("INSERT INTO scan_runs VALUES (?,?,?,?,?)",(now(),source,"failed",0,msg[:1000]))
                        con.commit()
        finally:
            con.close()
        self.active_bounties={r["id"]:r for r in found}
        if len(failures)==2: raise RuntimeError("Both live sources failed: "+"; ".join(failures))
        return {"scanned_at":now(),"discovered":len(found),"source_errors":failures,
            "top":sorted(found,key=lambda r:r["reward_max_usd"] or 0,reverse=True)}

    async def evaluate_bounty_profitability(self,bounty):
        # Advertised maximum reward is NOT likelihood of earning anything.
        import math
        n=amount(bounty.get("reward_max_usd"))
        return min(1., math.log10(n+1)/7.) if n is not None else 0.

    async def execute_bounty_collection(self,bounty_id):
        return {"status":"not_implemented_approval_required","bounty_id":bounty_id,
            "message":"Confirm authorization, scope, and submission rules before any security testing."}

    async def perform_bounty_task(self,bounty):
        return {"success":False,"status":"not_implemented_approval_required"}

    async def process_payment(self,bounty,proof):
        raise RuntimeError("No verified payment provider integration; earnings cannot be credited.")

    def get_earnings_report(self):
        con=database(self.db_path)
        try:
            count=con.execute("SELECT COUNT(*) FROM opportunities").fetchone()[0]
        finally: con.close()
        return {"timestamp":now(),"listed_opportunities":count,
                "verified_earnings_usd":0.0,"payment_verification":"not_connected"}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("command",nargs="?",choices=["scan","report","list"],default="scan")
    p.add_argument("--db",default="bounties.sqlite3")
    p.add_argument("--output")
    p.add_argument("--limit",type=int,default=100)
    args=p.parse_args()
    h=CryptoBountyHunter(db_path=args.db)
    if args.command=="scan":
        result=asyncio.run(h.scan_bounty_platforms())
        result["top"]=result["top"][:max(0,args.limit)]
    elif args.command=="report":
        result=h.get_earnings_report()
    else:
        con=database(args.db)
        try:
            rows=con.execute("SELECT id,platform,title,url,reward_max_usd,last_seen FROM opportunities ORDER BY reward_max_usd DESC,last_seen DESC LIMIT ?",(max(0,args.limit),)).fetchall()
            result=[dict(zip(["id","platform","title","url","reward_max_usd","last_seen"],r)) for r in rows]
        finally: con.close()
    payload=json.dumps(result,indent=2)
    if args.output:
        dest=Path(args.output)
        dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_text(payload+"\n",encoding="utf-8")
    print(payload)

if __name__=="__main__":
    logging.basicConfig(level=logging.INFO,format="%(levelname)s: %(message)s")
    try: main()
    except (RuntimeError,aiohttp.ClientError) as e:
        LOG.error("%s",e)
        raise SystemExit(2)
