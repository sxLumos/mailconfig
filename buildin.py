import os
import json
import re
from srv import resolve_mx
from autoconfig import from_ISPDB

def getkeylist(keys, item):
    re = []
    for key in keys:
        if key in item:
            re += item[key]
    return re

def buildin(domain):
    """Look up email configuration in builtin provider list and ISPDB"""
    
    mxdomain = None
    mxlist = resolve_mx(domain)
    if mxlist:
        mxdomain = mxlist[0]["hostname"]
    
    data = {}
    filepath = "./buildinlists"
    
    # Check for key.json
    files = os.listdir(filepath)
    if "key.json" not in files:
        data["error"] = "file key.json not found"
        return data
        
    try:
        with open(f"{filepath}/key.json", 'r') as kfile:
            keyinfo = json.loads(kfile.read())
    except Exception as e:
        data["error"] = str(e)
        return data

    # Process builtin configurations
    for key, matchs in keyinfo.items():
        with open(f"{filepath}/{key}.txt", 'r') as f:
            jlist = f.read().split('\n')[0:-1]
            
        relist = []
        for item in jlist:
            item = json.loads(item)
            if "domain" not in item or key not in item:
                continue
                
            match = False
            if matchs:
                if "domainre" in matchs:
                    matcher = getkeylist(matchs["domainre"], item)
                    for restring in matcher:
                        reinfo = re.match(restring, domain)
                        if reinfo and reinfo.group() == domain:
                            match = True
                            break
                            
                if mxdomain and not match and "mxre" in matchs:
                    matcher = getkeylist(matchs["mxre"], item)
                    for restring in matcher:
                        reinfo = re.match(restring, mxdomain)
                        if reinfo and reinfo.group() == mxdomain:
                            match = True
                            break
                            
            if not match and "domain" in item:
                if domain == item["domain"]:
                    match = True
                    
            if match:
                relist.append(item[key])
                
        data[key] = relist

    # Add ISPDB results
    ispdb_result = from_ISPDB(domain)
    if ispdb_result and "config" in ispdb_result:
        data["ISPDB"] = [ispdb_result["config"]]
    else:
        data["ISPDB"] = ["No ISPDB configuration found"]

    return data