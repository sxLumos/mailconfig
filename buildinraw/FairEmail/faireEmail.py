from xml.dom.minidom import parse
import xml.dom.minidom
import json
from ast import literal_eval
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
		self.port = port
		self.socketType = socket
		self.authentication = auth

class Autoconfig:
	def __init__(self, income, outgo):
		self.incomingServers = income
		self.outgoingServers = outgo

 
class Result:
	def __init__(self, domain, regular, autoconfig, provider = None):
		self.domain = domain
		self.domain_regular = regular
		self.FairEmail = autoconfig 
		if(provider):
			self.provider = provider
 
 
DOMTree = xml.dom.minidom.parse("providers.xml")
providers = DOMTree.documentElement
providerList = providers.getElementsByTagName("provider")
print(len(providerList))

def getssl(starttls, port):
	if starttls == "true":
		return "starttls"
	if (port == "465") or (port == "993") or (port == "995") :
		return "ssl"
	return "plain"

def setservers(inlist, proto, auth):
	re = []
	for ser in inlist:
		host = ser.getAttribute("host")
		port = ser.getAttribute("port")
		socket = getssl(ser.getAttribute("starttls"), port)
		server = Server(proto, host, port, socket, auth)
		re.append(server)
	return re

f = open("data.txt",'w', encoding='utf-8')

for provider in providerList:
	domain = ""
	regular = []
	auth = ""
	pro = None
	if provider.hasAttribute("name"):
		domain = provider.getAttribute("name")
	if provider.hasAttribute("domain"):
		cur = provider.getAttribute("domain")
		#cur = regular.replace("\\\\", "\\")
		cur = bytes(cur, "utf-8").decode("unicode_escape")
		regular = cur.split(",")
	if provider.hasAttribute("oauth"):
		auth = "oauth2"
	
	imaplist = setservers(provider.getElementsByTagName("imap"), "imap", auth)
	poplist = setservers(provider.getElementsByTagName("pop"), "pop", auth)
	smtplist = setservers(provider.getElementsByTagName("smtp"), "smtp", auth)
	if(domre.match(domain)):	#a domain name
		domain = domain.lower()
	else:
		pro = domain
		allist = imaplist + poplist + smtplist
		if allist:
			domain = tldextract.extract(allist[0].hostname).registered_domain
	autoconfig = Autoconfig(imaplist + poplist, smtplist)
	result = Result(domain, regular, autoconfig, pro)
	json_str = json.dumps(result,ensure_ascii=False,default=lambda obj:obj.__dict__)
	f.write(json_str+"\n")
	#print(json_str)

f.close()


