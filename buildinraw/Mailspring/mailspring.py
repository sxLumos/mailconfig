import json

class Server:
	def __init__(self, proto, host, port, socket, auth):
		self.type = proto
		self.hostname = host
		self.port = port
		self.socketType = socket
		self.authentication = auth

class Autoconfig:
	def __init__(self, income, outgo):
		self.incomingServers = income
		self.outgoingServers = outgo

 
class Result:
	def __init__(self, domain, autoconfig):
		self.domain = domain
		self.mailspring = autoconfig 

def setserver(proto, var):
	host = var[proto + "_host"]
	port = var[proto + "_port"]
	socket = "plain"
	if (proto + "_security") in var:
		cur = var[proto + "_security"]
		if cur == "SSL / TLS":
			socket = "ssl"
		elif cur == "STARTTLS":
			socket = "starttls"
	else:
		print(var)
	auth = ""
	if (proto + "_authentication") in var:
		auth = var[proto + "_authentication"]
		if len(auth) == 1 :
			auth = auth[0]
	server = Server(proto, host, port, socket, auth)
	return server


jfile = "mailspring-provider-settings" 
fr = open(jfile+".json",'r')
json_str = fr.read() 

fw = f = open(jfile+".txt",'w', encoding='utf-8')

d = json.loads(json_str)
print(len(d))
for domain, val in d.items():
	if "alias" in val:
		val = d[val["alias"]]
	inlist = []
	outlist = []
	
	imap_ser = setserver("imap", val)
	inlist.append(imap_ser)
	smtp_ser = setserver("smtp", val)
	outlist.append(smtp_ser)
	
	autoconfig = Autoconfig(inlist, outlist)
	result = Result(domain, autoconfig)
	json_str = json.dumps(result,ensure_ascii=False,default=lambda obj:obj.__dict__)
	f.write(json_str+"\n")
	#print(json_str)
	
		
		


