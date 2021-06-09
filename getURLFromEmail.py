from bs4 import BeautifulSoup

links=[]

#email file to open
email=open(r'','r')

soup=BeautifulSoup(email, features='lxml')

for tag in soup.find_all('a',href=True):
    if tag.__contains__('https://us-cert.cisa.gov/ics/advisories/'):
        links.append(tag['href'])

for link in links:
    print(link)