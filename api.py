#/usr/bin/env python

'''
URL Categorization 
Based On Blue Coat K9 WEB PROTECT API
'''
import argparse
import requests
import re
import csv

parser = argparse.ArgumentParser() 

parser.add_argument("-t", help="Single Domain Without http/https", dest='domain')
parser.add_argument("-f", help="File With Domain LIST", dest='file')

args = parser.parse_args() #Arguments to be parsed

print '''
\ \      / /__| |__   |  ___(_) | |_ ___ _ __ 
 \ \ /\ / / _ \ '_ \  | |_  | | | __/ _ \ '__|
  \ V  V /  __/ |_) | |  _| | | | ||  __/ |   
   \_/\_/ \___|_.__/  |_|   |_|_|\__\___|_|   
                                              
  ____      _                        _          _   _             
 / ___|__ _| |_ ___  __ _  ___  _ __(_)______ _| |_(_) ___  _ __  
| |   / _` | __/ _ \/ _` |/ _ \| '__| |_  / _` | __| |/ _ \| '_ \ 
| |__| (_| | ||  __/ (_| | (_) | |  | |/ / (_| | |_| | (_) | | | |
 \____\__,_|\__\___|\__, |\___/|_|  |_/___\__,_|\__|_|\___/|_| |_|
                    |___/                                         '''

api='http://sp.cwfservice.net/1/N/00/BLUPROXYCLNT/0/GET/HTTP/'

category_mappings = {'Computer/Information Security': '108', 'For Kids': '87', 'Alcohol': '23', 'Entertainment': '20', 'Travel': '66', 
                             'Proxy Avoidance': '86', 'Potentially Unwanted Software': '102', 'Charitable Organizations': '29', 'Weapons': '15', 
                             'Religion': '54', 'Health': '37', 'Sexual Expression': '93', 'File Storage/Sharing': '56', 'Gambling': '11', 
                             'Software Downloads': '71', 'Email': '52', 'News/Media': '46', 'Personals/Dating': '47', 'Adult/Mature Content': '1', 
                             'Newsgroups/Forums': '53', 'Piracy/Copyright Concerns': '118', 'Mixed Content/Potentially Adult': '50', 'Shopping': '58', 
                             'Remote Access Tools': '57', 'Business/Economy': '21', 'Informational': '107', 'Non-Viewable/Infrastructure': '96', 
                             'Society/Daily Living': '61', 'Peer-to-Peer (P2P)': '83', 'Media Sharing': '112', 'Scam/Questionable/Illegal': '9', 
                             'Audio/Video Clips': '84', 'Humor/Jokes': '68', 'Spam': '101', 'Office/Business Applications': '85', 
                             'Political/Social Advocacy': '36', 'Internet Connected Devices': '109', 'Translation': '95', 
                             'Alternative Spirituality/Belief': '22', 'Extreme': '7', 'Online Meetings': '111', 'Sex Education': '4', 
                             'Web Ads/Analytics': '88', 'Technology/Internet': '38', 'Tobacco': '24', 'Art/Culture': '30', 'Phishing': '18', 
                             'Intimate Apparel/Swimsuit': '5', 'Vehicles': '67', 'Abortion': '16', 'Web Hosting': '89', 'TV/Video Streams': '114', 
                             'Controlled Substances': '25', 'Malicious Outbound Data/Botnets': '44', 'Games': '33', 'Auctions': '59', 
                             'Brokerage/Trading': '32', 'Military': '35', 'Hacking': '17', 'E-Card/Invitations': '106', 'Social Networking': '55', 
                             'Chat (IM)/SMS': '51', 'Sports/Recreation': '65', 'Search Engines/Portals': '40', "I Don't Know": '90', 'Job Search/Careers': '45', 
                             'Reference': '49', 'Content Servers': '97', 'Nudity': '6', 'Restaurants/Dining/Food': '64', 'Suspicious': '92', 
                             'Child Pornography': '26', 'Marijuana': '121', 'Placeholders': '98', 'Radio/Audio Streams': '113', 'Government/Legal': '34', 
                             'Financial Services': '31', 'Malicious Sources/Malnets': '43', 'Real Estate': '60', 'Pornography': '3', 'Dynamic DNS Host': '103', 
                             'Education': '27', 'Internet Telephony': '110', 'Personal Sites': '63', 'Violence/Hate/Racism': '14'}


    


def api_request(domain):
	domain=domain.strip()
	start=0
	end=2
	mylist=[]
	url=api+domain+'/80/'
	r = requests.get(url = url)
	data= r.text
	try:
		pattern = re.compile('<DirC>(.*?)</DirC>')
		tuples = pattern.findall(data)
		x = tuples[0]
		while len(x[start:end])>0:
			mylist.append(x[start:end])
			start+=2
			end+=2
	except:
		pattern = re.compile('<DomC>(.*?)</DomC>')
		tuples = pattern.findall(data)
		x = tuples[0]
		while len(x[start:end])>0:
			mylist.append(x[start:end])
			start+=2
			end+=2
	length=len(mylist)
	begin=0
	data=''
	code=''
	while begin<length:
		x = int(mylist[begin], 16)
		code=code+str(x)
		begin+=1
		for key, value in category_mappings.items():
			x=str(x)
			if x == str(value):
				if data=='':
					data=data+key
				else:
					data=data+' , '+key

	row=[domain ,  code , data.lower() ]
	with open('data.csv', 'a') as csvFile:
		writer = csv.writer(csvFile)
		writer.writerow(row)
	csvFile.close()
def file(file_name):
	with open(file_name) as f:
		for domain in f:
			api_request(domain)



def main():
	
	if args.domain != None :
		domain=args.domain
		api_request(domain)
	elif args.file !=None:
		file_name=args.file
		file(file_name)
	else:
		print "Invalid Options Check -h For Help"

		exit()


if __name__ == '__main__':
    main()
