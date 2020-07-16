from django.shortcuts import render
import requests
import json
import random
from bs4 import BeautifulSoup 
import shodan
import re
# Create your views here.


def button(request):
    
    return render(request,'home.html')

def output(request):
    SHODAN_API_KEY = "cx4tuAzYnXDyMFq252xKy1BGsTLQU3A1"
    #target = 'https://www.yzu.edu.tw/index.php/tw/'
    api = shodan.Shodan(SHODAN_API_KEY) 
    #dnsResolve = 'https://api.shodan.io/dns/resolve?hostnames=' + target + '&key=' + SHODAN_API_KEY

    
   # First we need to resolve our targets domain to an IP
    #resolved = requests.get(dnsResolve)        #抓ip地址
    hostIP = request.POST.get('param')         #input
    inf = ""
    # Then we need to do a Shodan search on that IP
    host = api.host(hostIP)
    inf += "IP: %s \n" % host['ip_str']
    inf += "Organization: %s\n" % host.get('org', 'n/a')
    inf += "Operating System: %s \n" % host.get('os', 'n/a')
    inf += "Country:" + str(host.get('country_name', 'n/a'))
    # Print all banners
    for item in host['data']:
        #print ("Port: %s" % item['port'])  #把開啟的port印出來
        inf += "Port: %s\n" % item['port']
        
    # Print vuln information
    for item in host['vulns']:
        CVE = item.replace('!','')
            #print ('Vulns: %s' % item)
        inf += '\nVulns:' + CVE + '\n'
        inf += Get_Cve_Description(CVE)    #把該ip的CVE印出來                   
        inf += Get_Cve_NVD(CVE)
      
        
    data = inf
    print(data)
    return render(request,'home.html',{'data':data})
 
    
 
    
### function()       
def getHtmlText(url):
    try:
        r = requests.get(url,timeout = 30)
        r.raise_for_status()
        r.encoding = r.apparent_encoding
        return r.text
    except:
        return "Error"
    return ""

def Get_Cve_Description(CVE):
    url = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="+CVE   #CVE官網關鍵字查詢
    html_text = getHtmlText(url);
    soup = BeautifulSoup(html_text,'html.parser')
    Description = '描述\n'
    Description += soup.find_all('tr')[9].find('td').string  #CVE Description
    #print(Description)
    return Description

def Get_Cve_NVD(CVE):
    urlNVD = 'https://nvd.nist.gov/vuln/detail/' + CVE
    html_text = getHtmlText(urlNVD);
    sp = BeautifulSoup(html_text, 'html.parser')

    Score = ""
    detal = sp.select(".severityDetail")
    Score += "CVSS 3.x:" + detal[0].text + '\n' + "CVSS 2.0:" + detal[1].text + '\n'

    Solution = ""
    Solution = "對諮詢，解決方案和工具的引用:" + '\n'
    detal = sp.select(
        "#p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilityDetail_VulnFormView_VulnHyperlinksPanel table.table-striped.table-condensed.table-bordered.detail-table a")
    for i in range(len(detal)):
        Solution += detal[i].text + '\n'

    Weakness = ""
    Weakness =  "弱點枚舉:" + '\n'
    detal = sp.select(
        "#p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilityDetail_VulnFormView_VulnTechnicalDetailsDiv table.table-striped.table-condensed.table-bordered.detail-table a")
    for i in range(len(detal)):
        Weakness += detal[i].text + ":" + '\n' + detal[i]['href'] + '\n'

    KnownAffected = ""
    KnownAffected =  "已知受影響的軟件配置:" + '\n'
    detal = sp.select(".vulnerable")
    for i in range(len(detal)):
        KnownAffected += "配置" + str(i + 1) + ":" + '\n' + detal[i].text.replace(" \xa0", '').replace("\n", '') + '\n'
    allNVD = ""
    allNVD += Score + Solution + Weakness + KnownAffected
    return allNVD





#SecurityFocus:
def Get_Cve_NEW(CVE):
    urlNVD='https://cve.mitre.org/cgi-bin/cvename.cgi?name='+CVE
    res=requests.get(urlNVD)
    sp=BeautifulSoup(res.text,'html.parser')
    detal=sp.find_all("a",string=re.compile("^URL:http://www.securityfocus.com"))
    SecurityFocus=""
    SecurityFocus="SecurityFocus:"+'\n'
    if len(detal)!=0:
        SecurityFocus+=detal[0].text.split(":", 1)[1]+'\n'
        return SecurityFocus   #回傳URL
    else:
        return SecurityFocus



#exploits:
def Get_Cve_EX(CVE):
    urlNVD='https://cve.mitre.org/cgi-bin/cvename.cgi?name='+CVE
    res=requests.get(urlNVD)
    sp=BeautifulSoup(res.text,'html.parser')
    detal=sp.find_all("a",string=re.compile("^URL:http://www.exploit-db.com/exploits/"))
    exploits=""
    exploits="exploits:"+'\n'
    if len(detal)!=0:
        exploits+=detal[0].text.split(":", 1)[1]+'\n'
        return exploits  #回傳URL
    else :
        return exploits

#stackoverflow:

def stackoverflow(CVE):
    new_cve=CVE.split('-',1)[1]
    urlstackoverflow="https://stackoverflow.com/search?q=CVE+"+new_cve
    res=requests.get(urlstackoverflow)
    sp=BeautifulSoup(res.text,'html.parser')
    aaa=sp.select('.result-link a')
    stackoverflow=""
    stackoverflow+="stackoverflow:"+'\n'
    for i in range(len(aaa)):
        stackoverflow+="https://stackoverflow.com"+aaa[i]['href']+'\n'
    return stackoverflow   #回傳URL