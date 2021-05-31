import requests
import datetime
import re
from bs4 import BeautifulSoup as bs

url='https://us-cert.cisa.gov/ics/advisories?items_per_page=All'
outfile=open('CISA_Advisory_List_'+datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')+'.csv', 'a')
error=open('CISA_ERROR_FILE_'+datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')+'.txt', 'a')
page = requests.get(url)
soup = bs(page.content, 'html.parser')

for elem in soup.find_all('a', href=re.compile('/ics/advisories/')):
    url='https://us-cert.cisa.gov' + elem['href']
    advisory=url.replace('https://us-cert.cisa.gov/ics/advisories/','')
    try:
        print('https://us-cert.cisa.gov' + elem['href'] + ',' + advisory.replace(",",";") + ',' + elem.text.replace(',',';'), file=outfile)
    except Exception:
        print('CISA Alert: '+advisory+' cannot be parsed correctly', file=error)
outfile.close
error.close