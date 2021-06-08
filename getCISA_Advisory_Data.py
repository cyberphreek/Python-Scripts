import requests
import csv
import datetime
from bs4 import BeautifulSoup as bs
from bs4 import NavigableString, Tag

errorfile=open('ERROR_FILE_ADVISORY_DATA_RETREIVAL'+datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')+'.txt','a')
inFile=r"C:\\Users\\jeffd\\OneDrive\\Documents\\VSCode Projects\\CISA_Scraper\\infile.csv"
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
        affected_products=[]
        affected_products_string=''

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
            try:
                startTag=soup.find(lambda tag:tag.name=='h3' and 'AFFECTED PRODUCTS' in tag.text)
                endTag=soup.find(lambda tag:tag.name=='h3' and 'VULNERABILITY OVERVIEW' in tag.text)
                #needs to be further simplified. Returns too much data still. Only need afffected product list, probably filter on 'li' tag somehow
                while startTag.next.__contains__(r'VULNERABILITY OVERVIEW')==False:
                        startTag=startTag.next_element
                        affected_products.append(startTag)
            
            except:
                print("Error locating affected products", file=errorfile)
            #Find all CVE and CWE links on page
            for a in soup.find_all('a', href=True):
                try:
                    if(a['href'].__contains__(r'web.nvd.nist.gov/view/vuln/detail')):
                        cve_list.append(a['href'])
                except:
                    print('error getting CVE List from the following URL: '+ a,file=errorfile)
                try:
                    if(a['href'].__contains__(r'cwe.mitre.org/data/definitions/')):
                        cwe_list.append(a['href'])
                except:
                    print('error getting CWE from the following URL: '+a, file=errorfile)
        except:
            print('error parsing the following URL for advisory data: '+line[0], file=errorfile)

        for x in cve_list:
            cve_string=cve_string+x+';'
        
        for x in cwe_list:
            cwe_string=cwe_string+x+';'

        for x in affected_products:
            affected_products_string=affected_products_string+x+';'

        advisory_data=cvss +','+equipment+','+vendor+','+affected_products_string+','+cve_string+','+cwe_string+','

        print(advisory_data, file=outFile)