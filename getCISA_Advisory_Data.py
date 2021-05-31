import requests
import csv
import datetime
from bs4 import BeautifulSoup as bs

errorfile=open('ERROR_FILE_ADVISORY_DATA_RETREIVAL'+datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')+'.txt','a')
inFile=''
outFile=open('CISA_Advisory_Data_'+datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')+'.csv','a')

with open(inFile) as f:
    reader=csv.reader(f)
    advisoryList=list(reader)
    for line in advisoryList:
        page=requests.get(line[0])
        soup=bs(page.content, 'html.parser')

        cve_list=[]
        cwe_list=[]
        cve_string=''
        cwe_string=''

        try:
            cvss_score=soup.find(lambda tag:tag.name=="li" and "CVSS v3" in tag.text)
            cvss=cvss_score.text
            cvss=cvss.replace('CVSS v3 ', '')

            equipment=soup.find(lambda tag:tag.name=='li' and "Equipment" in tag.text)
            equipment=equipment.text
            equipment=equipment.replace('Equipment: ', '')

            vendor=soup.find(lambda tag:tag.name=='li' and "Vendor" in tag.text)
            vendor=vendor.text
            vendor=vendor.replace('Vendor: ', '')

            #retrieve list of affected products
            affected_products=soup.find(lambda tag:tag.name=='h3' and 'AFFECTED PRODUCTS' in tag.text)
            affected_products=affected_products.text

            #Find all CVE and CWE links on page
            for a in soup.find_all('a',href=True):
                try:
                    if(a['href'].__contains__('http://web.nvd.nist.gov/view/vuln/detail?vulId=')):
                        cve_list.append(a['href'])
                    elif(a['href'].__contains__('http://web.nvd.nist.gov/view/vuln/detail?vulId=')):
                        cwe_list.append(a['href'])
                except:
                    print('error getting CVE or CWE from the following URL: '+line[0], file=errorfile)
        except:
            print('error parsing the following URL for advisory data: '+line[0], file=errorfile)

        for x in cve_list:
            cve_string=cve_string+x+';'
        
        for x in cwe_list:
            cwe_string=cwe_string+x+';'

        print(advisory_data=cvss +','+equipment+','+vendor+','+affected_products+','+cve_string+','+cwe_string+',', file=outFile)