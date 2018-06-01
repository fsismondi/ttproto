import requests, json, sys
from xml.etree import ElementTree

def validate(jsond, objectid):
	print("ObjectID: "+objectid)
	jsondata=jsond[2:]
	jsondata=jsondata[:-1]
	jsondata = json.loads(jsondata)
	#print json.dumps(jsondata, sort_keys=True,indent=4, separators=(',', ': '))

	url ='http://www.openmobilealliance.org/api/lwm2m/v1/Object?ObjectID='+objectid;
	print("Registry url: "+url)
	r = requests.get(url )
	#print json.dumps(r.json(), sort_keys=True,indent=4, separators=(',', ': '))
	j =r.json()
	print("ObjectLink: "+j[0]["ObjectLink"])
	r2 = requests.get(j[0]["ObjectLink"])
	#print r2.content
	root = ElementTree.fromstring(r2.content)

	validation = "pass"
	for item in root.iter('Item'):
		for child in item:
			if(child.text=="Mandatory"):
				if(item.find("Operations").text!="E"):
					print("ResourceID: "+item.get("ID"))
					print("Name: "+str(item.find("Name").text))
					print("Type: "+str(item.find("Type").text))
					print("Operations: "+str(item.find("Operations").text))
					print("MultipleInstances: "+str(item.find("MultipleInstances").text))
					for attrs in jsondata['e']:
						itemuri = item.get("ID");
						if(item.find("MultipleInstances").text=="Multiple"):
							itemuri=itemuri+"/0";
						if attrs['n'] == itemuri:
							n = attrs['n']
							print("Found!")
							print
							break
					else:
						validation = "fail"
						print('Not found!')
						print
	print("Validation: " +validation)
	return validation
