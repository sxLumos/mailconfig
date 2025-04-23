import json

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
	def __init__(self, domain, autoconfig):
		self.domain = domain
		self.nodemailer = autoconfig 



fr = open("services.json",'r')
json_str = fr.read() 

fw = f = open("nodemailer.txt",'w', encoding='utf-8')

d = json.loads(json_str)
print(len(d))
for domain, val in d.items():
	outlist = []
	domains = [domain]
	auth = ""
	socket = "starttls"
	
	if "host" not in val:
		print("host", domain, val)
		continue
	host = val["host"]
	if "port" not in val:
		print("port", domain, val)
		continue
	port = val["port"]	
			
	if "domains" in val:
		domains += val["domains"]
	
	if "aliases" in val:
		domains += val["aliases"]
		
	if "secure" in val:
		if val["secure"] == True:
			socket = "ssl"
		elif port == 587:
			socket = "starttls"
		else :
			socket = "plain"
	else :
		if port == 465:
			socket = "ssl"
		else:
			socket = "plain"
			
	if "authMethod" in val:
		auth = val["authMethod"]

	server = Server("smtp", host, port, socket, auth)
	outlist.append(server)

	autoconfig = Autoconfig([], outlist)
	for dd in domains:
		result = Result(dd, autoconfig)
		json_str = json.dumps(result,ensure_ascii=False,default=lambda obj:obj.__dict__)
		f.write(json_str+"\n")
	#print(json_str)
		
		

