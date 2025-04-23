import json
import re
import tldextract

domre = re.compile(
    r'^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|'
    r'([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|'
    r'([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\.'
    r'([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$'
)

class Server:
	def __init__(self, proto, host, port, socket, auth):
		self.type = proto
		self.hostname = host
		self.port = str(port)
		self.socketType = socket
		self.authentication = auth

class Autoconfig:
	def __init__(self, income, outgo):
		self.incomingServers = income
		self.outgoingServers = outgo

 
class Result:
	def __init__(self, domain, dregular, mregular, autoconfig, provider = None):
		self.domain = domain
		self.domain_regular = dregular
		self.mx_regular = mregular
		self.mailcore = autoconfig 
		if(provider):
			self.provider = provider



jfile = "mailcore-provider-settings" 
fr = open(jfile+".json",'r')
json_str = fr.read() 

fw = f = open(jfile+".txt",'w', encoding='utf-8')

d = json.loads(json_str)
print(len(d))
for domain, val in d.items():
	dregular = []
	mregular = []
	inlist = []
	outlist = []
	auth = ""
	pro = None
	if "domain-match" in val:
		dregular = val["domain-match"]
	if "mx-match" in val:
		mregular = val["mx-match"]
	servers = val["servers"]
	for proto, configs in servers.items():
		for config in configs:
			socket = "plain"
			if ("ssl" in config) and (config["ssl"] == True):
				socket = "ssl"
			elif ("tls" in config) and (config["tls"] == True):
				socket = "ssl"
			elif ("starttls" in config) and (config["starttls"] == True):
				socket = "starttls"
			port = config["port"]
			
			# some item do not have hostname, and some hostname have form of .{domain}
			if "hostname" not in config:
				#print(domain, val)
				continue
			host = config["hostname"]
			#a = host.find("{")

			server = Server(proto, host, port, socket, auth)
			if (proto =="imap") or (proto == "pop"):
				inlist.append(server)
			else:
				outlist.append(server)
	if len(inlist)==0 or len(outlist) == 0:
		print(domain, val)
		continue
	autoconfig = Autoconfig(inlist, outlist)
	if(domre.match(domain)):	#a domain name
		domain = domain.lower()
	elif(not dregular and not mregular):
		pro = domain
		allist = inlist + outlist
		if allist:
			domain = tldextract.extract(allist[0].hostname).registered_domain
			
	result = Result(domain, dregular, mregular, autoconfig, pro)
	json_str = json.dumps(result,ensure_ascii=False,default=lambda obj:obj.__dict__)
	f.write(json_str+"\n")
	#print(json_str)
		
		

