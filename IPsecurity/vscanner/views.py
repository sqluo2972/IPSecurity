from django.shortcuts import render
from django.http import HttpResponse
import requests
import os
from queue import Queue
from bs4 import BeautifulSoup 
import shodan
import re
from fake_useragent import UserAgent
from collections import Counter
import threading
import seaborn as sns
import matplotlib
from docx import Document
from docx.shared import Inches
matplotlib.use('Agg')
from matplotlib import pyplot as plt
# Create your views here.


def button(request):
    
    return render(request,'home.html')

def output(request):
    SHODAN_API_KEY = "cx4tuAzYnXDyMFq252xKy1BGsTLQU3A1"
    #target = 'https://www.yzu.edu.tw/index.php/tw/'
    api = shodan.Shodan(SHODAN_API_KEY) 
    #dnsResolve = 'https://api.shodan.io/dns/resolve?hostnames=' + target + '&key=' + SHODAN_API_KEY

    hostIP = request.POST.get('param')         #ip input
   
    Ip_inf = ""                                   #儲存字串
    # Then we need to do a Shodan search on that IP
    host = api.host(hostIP)
    Ip_inf += "IP: %s \n" % host['ip_str']
    Ip_inf += "Organization: %s\n" % host.get('org', 'n/a')
    Ip_inf += "Operating System: %s \n" % host.get('os', 'n/a')
    Ip_inf += "Country:" + str(host.get('country_name', 'n/a')) +'\n'
   
    #print port
    for item in host['data']:       
        Ip_inf += "Port: %s\n" % item['port']
    CveList = list()  #儲存CVE
    CVSS = list()     #儲存CVSS
    cwelist = list()    #儲存所有cwe
    Cve_inf = ""




    for item in host['vulns']:
        CVE = item.replace('!','')
            #print ('Vulns: %s' % item)
        CveList.append(CVE)
        Get_Chart(CVE,CVSS,cwelist)
        Cve_inf += CVE + '\n'
        #inf += multithreading(CVE,CVSS,cwelist)     #多線程爬取資料
    CveList.append('CVE-2017-11882')
    Get_Chart('CVE-2017-11882',CVSS,cwelist)
    CveList.append('CVE-2020-1350')
    Get_Chart('CVE-2020-1350', CVSS, cwelist)
    sns.set()    
    
    ##長條圖
    path_root = os.path.abspath('.')  # 表示當前所處的絕對路徑
   

    key_value = list(Counter(cwelist).keys())
    for i in range(len(key_value)):
        key_value[i] = key_value[i].replace('-', "-\n")
    value_list = list(Counter(cwelist).values())
    plt.bar(key_value, value_list)  # s-:方形
    plt.ylabel("CWE COUNT")
    plt.savefig(path_root + '\\vscanner\\static\\images\\bar.jpg')
    
    plt.close()      #清除figure
    ##圓餅圖
   
    key_value = list(Counter(CVSS).keys())
    value_list = list(Counter(CVSS).values())
    pie_color = ["orange", "red", "limegreen"]
    plt.pie(value_list, colors=pie_color, labels=key_value, autopct="%2.2f%%")
   
    plt.savefig(path_root + '\\vscanner\\static\\images\\pie.jpg')
    plt.close()
    
    cve_dict = dict(zip(CveList,CVSS))

    return render(request,'Ip.html',{'data':Ip_inf,'cve_list':cve_dict})

def report(request):
    path_root = os.path.abspath('.')
    document = Document(path_root + '\\vscanner\\static\\word\\report.docx')

    response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document')
    response['Content-Disposition'] = 'attachment; filename=Vulnerability Report.docx'
    document.save(response)

    return response
    

def cve(request):
    cve = request.POST.get('cve')  # ip input
    cve_list = list(cve.split(' '))
    cvss = list()
    cwe = list()
    for cve in cve_list:
        Get_Chart(cve, cvss, cwe)
    cve_dict = dict(zip(cve_list,cvss))

    return render(request,'cve.html',{'cve_list':cve_dict})


def detail(request,CVE):

    
    return render(request,'detail.html',{'cve':CVE})
    
    
### function()  
def multithreading(CVE,CVSS,cwelist):             #for detail cve
    Q =Queue()         #FIFO 
   
    Description= threading.Thread(target=Get_Cve_Description, args =(CVE,Q))
    NVD= threading.Thread(target=Get_Cve_NVD, args =(CVE,CVSS,cwelist,Q))
    stackoverflow=threading.Thread(target=Get_Cve_stackoverflow, args =(CVE,Q))
    NEW=threading.Thread(target=Get_Cve_NEW, args =(CVE,Q))
    EX=threading.Thread(target=Get_Cve_EX, args =(CVE,Q))
    packetstormsecurity=threading.Thread(target=Get_Cve_packetstormsecurity, args =(CVE,Q))
    
    Description.start()
    NVD.start()
    stackoverflow.start()
    NEW.start()
    EX.start()
    packetstormsecurity.start()
       
    Description.join()
    NVD.join()
    stackoverflow.join()
    NEW.join()
    EX.join()
    packetstormsecurity.join()
    
    inf = ""
    for _ in range(Q.qsize()):
        inf += Q.get()
        
    return inf 
   
    

     
def getHtmlText(url):
    try:
        r = requests.get(url,timeout = 30)
        r.raise_for_status()
        r.encoding = r.apparent_encoding
        return r.text
    except:
        return "Error"
    return ""

def Get_Cve_Description(CVE,q):     # q = Queue
    url = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="+CVE   #CVE官網關鍵字查詢
    html_text = getHtmlText(url);
    soup = BeautifulSoup(html_text,'html.parser')
    Description = '描述\n'
    Description += soup.find_all('tr')[9].find('td').string  #CVE Description
    #print(Description)
    q.put(Description)
    #return Description

def Get_Chart(CVE,CVSS,cwelist):
    urlNVD='https://nvd.nist.gov/vuln/detail/'+CVE
    res=requests.get(urlNVD)
    sp=BeautifulSoup(res.text,'html.parser') 
    detal=sp.select(".severityDetail")
 
    CVSS.append(detal[1].text.split(' ')[2])
     
    detal=sp.select("#vulnTechnicalDetailsDiv table.table-striped.table-condensed.table-bordered.detail-table a")
    for i in range(len(detal)):     
        cwelist.append(detal[i].text)

def Get_Cve_NVD(CVE,CVSS,cwelist,q):
    urlNVD='https://nvd.nist.gov/vuln/detail/'+CVE
    res=requests.get(urlNVD)
    sp=BeautifulSoup(res.text,'html.parser')
   
    Score=""
    detal=sp.select(".severityDetail")
    if detal[0].text!=' N/A':
        Score+="CVSS 3.x:"+detal[0].text.replace('\n','')+'\n'+Get_Cve_CVSSdetail3X(CVE)+"CVSS 2.0:"+detal[1].text+'\n'+Get_Cve_CVSSdetail20(CVE)
    else:
        Score+="CVSS 3.x:"+detal[0].text+'\n'+Get_Cve_CVSSdetail3X(CVE)+"CVSS 2.0:"+detal[1].text+'\n'+Get_Cve_CVSSdetail20(CVE)
   
    CVSS.append(detal[1].text.split(' ')[2])
    Solution="對諮詢，解決方案和工具的引用:"+'\n'
    detal=sp.select("#vulnHyperlinksPanel table.table-striped.table-condensed.table-bordered.detail-table a")
    for i in range(len(detal)):
        Solution+=detal[i].text+'\n'
    CweName = sp.select("#vulnTechnicalDetailsDiv table.table-striped.table-condensed.table-bordered.detail-table td")
    Weakness="弱點枚舉:"+'\n'
    detal=sp.select("#vulnTechnicalDetailsDiv table.table-striped.table-condensed.table-bordered.detail-table a")
    for i in range(len(detal)):
        Weakness+=detal[i].text+":"+CweName[1+i*3].text+'\n'+detal[i]['href']+'\n'
        cwelist.append(detal[i].text)
   
    allNVD =Score+Solution+Weakness    
    q.put(allNVD)
    #return allNVD
    
    
#Security Focus
def Get_Cve_NEW(CVE,q):
    urlNVD='https://cve.mitre.org/cgi-bin/cvename.cgi?name='+CVE
    res=requests.get(urlNVD)
    sp=BeautifulSoup(res.text,'html.parser')
    detal=sp.find_all("a",string=re.compile("^URL:http://www.securityfocus.com"))
    SecurityFocus="SecurityFocus:"+'\n'
    if len(detal)!=0:
        SecurityFocus+=detal[0].text.split(":", 1)[1]+'\n'
        q.put(SecurityFocus)
        #return SecurityFocus
    else :
        SecurityFocus = "SecurityFocus:NONE!"+'\n'
        q.put(SecurityFocus)
        #return ("SecurityFocus:NONE!"+'\n')

#exploits:
def Get_Cve_EX(CVE,q):
    urlNVD='https://cve.mitre.org/cgi-bin/cvename.cgi?name='+CVE
    res=requests.get(urlNVD)
    sp=BeautifulSoup(res.text,'html.parser')
    detal=sp.find_all("a",string=re.compile("^URL:http://www.exploit-db.com/exploits/"))
    exploits="Exploits:"+'\n'
    if len(detal)!=0:
        exploits+=detal[0].text.split(":", 1)[1]+'\n'
        #return exploits
    else :
        exploits = "Exploits:NONE!"+'\n'
        q.put(exploits)
        #return ("Exploits:NONE!"+'\n')

#stackoverflow:

def Get_Cve_stackoverflow(CVE,q):
    new_cve=CVE.split('-',1)[1]
    urlstackoverflow="https://stackoverflow.com/search?q=CVE+"+new_cve
    res=requests.get(urlstackoverflow)
    sp=BeautifulSoup(res.text,'html.parser')
    aaa=sp.select('.result-link a')
    stackoverflow=""
    stackoverflow+="stackoverflow:"+'\n'
    for i in range(len(aaa)):
        stackoverflow+="https://stackoverflow.com"+aaa[i]['href']+'\n'
    if len(aaa)==0:
        stackoverflow = "Stackoverflow:NONE!"+'\n'
    q.put(stackoverflow)
    #return stackoverflow   #回傳URL


def Get_Cve_packetstormsecurity(CVE,q):
    urlCVE="https://packetstormsecurity.com/search/?q="+CVE
    res=requests.get(urlCVE)
    sp=BeautifulSoup(res.text,'html.parser')
    Description = sp.select("dt a")
    aaa="Packetstormsecurity:"+'\n'
    for i in range(len(Description)):
        aaa+="https://packetstormsecurity.com"+Description[i]['href']+'\n'
    if len(Description)!=0:
        q.put(aaa)
        #return aaa
    else:
        q.put("Packetstormsecurity:NONE!"+'\n')
        #return ("Packetstormsecurity:NONE!"+'\n')
def Get_Cve_CVSSdetail20(CVE):
    urlCVE="https://nvd.nist.gov/vuln/detail/"+CVE
    res=requests.get(urlCVE)
    sp=BeautifulSoup(res.text,'html.parser')
    Description = sp.select("#vulnCvssPanel span .tooltipCvss2NistMetrics")
    CVSSdetail=""
    if len(Description)==0:
        return ("NO CVSS 2.0"+'\n')
    else:
        a=Description[0].text.replace("(","").replace(")","").split('/')
        if a[0].split(":")[1]=="L":
            CVSSdetail+="Access Vector(攻擊向量):"+"Local(在不連接網路的狀況下進行攻擊)"+'\n'
        elif a[0].split(":")[1]=="A":
            CVSSdetail+="Access Vector(攻擊向量):"+"Adjacent Network(由受限制的網路進行攻擊，如區域網路及藍芽等)"+'\n'
        elif a[0].split(":")[1]=="N":
            CVSSdetail+="Access Vector(攻擊向量):"+"Network(由網際網路網路進行攻擊)"+'\n'
           
        if a[1].split(":")[1]=="H":
            CVSSdetail+="Access Complexity(攻擊複雜度):"+"HIGH"+'\n'
        elif a[1].split(":")[1]=="M":
            CVSSdetail+="Access Complexity(攻擊複雜度):"+"Medium"+'\n'
        elif a[1].split(":")[1]=="L":
            CVSSdetail+="Access Complexity(攻擊複雜度):"+"LOW"+'\n'

        if a[2].split(":")[1]=="M":
            CVSSdetail+="Authentication(認證方式):"+"Multiple(此漏洞需要攻擊者進行兩次或兩次以上的身份驗證)"+'\n'
        elif a[2].split(":")[1]=="S":
            CVSSdetail+="Authentication(認證方式):"+"Single(該漏洞要求攻擊者登錄到系統中)"+'\n'
        elif a[2].split(":")[1]=="N":
            CVSSdetail+="Authentication(認證方式):"+"NONE"+'\n'

        if a[3].split(":")[1]=="N":
            CVSSdetail+="Confidentiality Impact(機密性影響):"+"NONE"+'\n'
        elif a[3].split(":")[1]=="P":
            CVSSdetail+="Confidentiality Impact(機密性影響):"+"Partial(攻擊者可以取得機密資料，但無法使用該資料)"+'\n'
        elif a[3].split(":")[1]=="C":
            CVSSdetail+="Confidentiality Impact(機密性影響):"+"Complete(攻擊者可以取得機密資料，且可以使用該資料)"+'\n'

        if a[4].split(":")[1]=="N":
            CVSSdetail+="Integrity Impact(完整性影響):"+"NONE"+'\n'
        elif a[4].split(":")[1]=="P":
            CVSSdetail+="Integrity Impact(完整性影響):"+"Partial(攻擊者有部分權限以竄改某些資料，對含有漏洞之元件影響較小)"+'\n'
        elif a[4].split(":")[1]=="C":
            CVSSdetail+="Integrity Impact(完整性影響):"+"Complete(攻擊者有權限竄改所有資料，對含有漏洞之元件有嚴重影響)"+'\n'
       
        if a[5].split(":")[1]=="N":
            CVSSdetail+="Availability Impact(可用性影響):"+"NONE"+'\n'
        elif a[5].split(":")[1]=="P":
            CVSSdetail+="Availability Impact(可用性影響):"+"Partial(可用性受到影響，導致服務或元件仍可被部分取得，或是時好時壞)"+'\n'
        elif a[5].split(":")[1]=="C":
            CVSSdetail+="Availability Impact(可用性影響):"+"Complete(攻擊者有權限竄改所有資料，對含有漏洞之元件有嚴重影響)"+'\n'
       
        return CVSSdetail
   
def Get_Cve_CVSSdetail3X(CVE):
    urlCVE="https://nvd.nist.gov/vuln/detail/"+CVE
    res=requests.get(urlCVE)
    sp=BeautifulSoup(res.text,'html.parser')
    Description = sp.select("#vulnCvssPanel span .tooltipCvss3NistMetrics")
    CVSSdetail=""
    if len(Description)==0:
        return ("NO CVSS 3.X"+'\n')
    else:
        a=Description[0].text.split("/")
        if a[1].split(":")[1]=="N":
            CVSSdetail+="Attack Vector(攻擊向量):"+"Network(由網際網路網路進行攻擊)"+'\n'
        elif a[1].split(":")[1]=="A":
            CVSSdetail+="Attack Vector(攻擊向量):"+"Adjacent(由受限制的網路進行攻擊，如區域網路及藍芽等)"+'\n'
        elif a[1].split(":")[1]=="L":
            CVSSdetail+="Attack Vector(攻擊向量):"+"Local(在不連接網路的狀況下進行攻擊)"+'\n'
        elif a[1].split(":")[1]=="P":
            CVSSdetail+="Attack Vector(攻擊向量):"+"Physical(需接觸到實體機器才能進行攻擊)"+'\n'

        if a[2].split(":")[1]=="L":
            CVSSdetail+="Attack Complexity(攻擊複雜度):"+"LOW"+'\n'
        elif a[2].split(":")[1]=="H":
            CVSSdetail+="Attack Complexity(攻擊複雜度):"+"HIGH"+'\n'

        if a[3].split(":")[1]=="N":
            CVSSdetail+="Privileges Required(是否需要提權):"+"NONE"+'\n'
        elif a[3].split(":")[1]=="L":
            CVSSdetail+="Privileges Required(是否需要提權):"+"LOW"+'\n'
        elif a[3].split(":")[1]=="H":
            CVSSdetail+="Privileges Required(是否需要提權):"+"HIGH"+'\n'

        if a[4].split(":")[1]=="N":
            CVSSdetail+="User Interaction(是否需要使用者操作):"+"NONE"+'\n'
        elif a[4].split(":")[1]=="R":
            CVSSdetail+="User Interaction(是否需要使用者操作):"+"Required"+'\n'

        if a[5].split(":")[1]=="U":
            CVSSdetail+="Scope(影響範圍):"+"Unchanged(僅影響含有漏洞的元件本身)"+'\n'
        elif a[5].split(":")[1]=="C":
            CVSSdetail+="Scope(影響範圍):"+"Changed(會影響到含有漏洞的元件以外的元件)"+'\n'

        if a[6].split(":")[1]=="N":
            CVSSdetail+="Confidentiality(機密性影響):"+"NONE"+'\n'
        elif a[6].split(":")[1]=="L":
            CVSSdetail+="Confidentiality(機密性影響):"+"LOW(攻擊者可以取得機密資料，但無法使用該資料)"+'\n'
        elif a[6].split(":")[1]=="H":
            CVSSdetail+="Confidentiality(機密性影響):"+"HIGH(攻擊者可以取得機密資料，且可以使用該資料)"+'\n'

        if a[7].split(":")[1]=="N":
            CVSSdetail+="Integrity(完整性影響):"+"NONE"+'\n'
        elif a[7].split(":")[1]=="L":
            CVSSdetail+="Integrity(完整性影響):"+"LOW(攻擊者有部分權限以竄改某些資料，對含有漏洞之元件影響較小)"+'\n'
        elif a[7].split(":")[1]=="H":
            CVSSdetail+="Integrity(完整性影響):"+"HIGH(攻擊者有權限竄改所有資料，對含有漏洞之元件有嚴重影響)"+'\n'

        if a[8].split(":")[1]=="N":
            CVSSdetail+="Availability(可用性影響):"+"NONE"+'\n'
        elif a[8].split(":")[1]=="L":
            CVSSdetail+="Availability(可用性影響):"+"LOW(可用性受到影響，導致服務或元件仍可被部分取得，或是時好時壞)"+'\n'
        elif a[8].split(":")[1]=="H":
            CVSSdetail+="Availability(可用性影響):"+"HIGH(攻擊者有權限竄改所有資料，對含有漏洞之元件有嚴重影響)"+'\n'

        return CVSSdetail
    
def Get_Cve_port(port,CVElist):
    ua = UserAgent()
    headers = {'User-Agent': ua.random}
    urlport="https://www.speedguide.net/port.php?port="+port
    res=requests.get(urlport, headers=headers)
    sp=BeautifulSoup(res.text,'html.parser')
    detal=sp.find_all("a",string=re.compile("^CVE-"))
    cve=""
    for i in range(len(detal)):
        k=0
        for j in range(len(CVElist)):
            if detal[i].text==CVElist[j]:
                cve+=detal[i].text+"*"+'\n'
                k+=1
        if k==0:
            cve+=detal[i].text+'\n'
    return (urlport+'\n'+cve)


def Get_Cve_KnownAffected(CVE):
    KnownAffected = ""
    urlNVD = 'https://nvd.nist.gov/vuln/detail/' + CVE
    html = requests.get(urlNVD)
    sp = BeautifulSoup(html.text, 'html.parser')
    detal = sp.select(".vulnerable")
    for i in range(len(detal)):
        KnownAffected += "配置" + str(i + 1) + ":" + '\n' + detal[i].text.replace(" \xa0", '').replace("\n", '') + '\n'
    return KnownAffected


def Get_Cve_civis(CVE):
    urlcivis="https://cert.civis.net/en/index.php?action=alert&param="+CVE
    civis="More CVSS:"+'\n'+urlcivis+'\n'
    return civis


#--------------------------None use--------------------------------------------
#Nvd solution
def Get_Cve_Solution(CVE):
    Solution=""
    urlNVD='https://nvd.nist.gov/vuln/detail/'+CVE
    html=requests.get(urlNVD)
    sp=BeautifulSoup(html.text,'html.parser')
    detal=sp.select("#p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilityDetail_VulnFormView_VulnHyperlinksPanel table.table-striped.table-condensed.table-bordered.detail-table a")
    for i in range(len(detal)):
        Solution+=detal[i].text+'\n'
    return Solution



#nvd weakness    
def Get_Cve_Weakness(CVE):
    Weakness=""
    urlNVD='https://nvd.nist.gov/vuln/detail/'+CVE
    html=requests.get(urlNVD)
    sp=BeautifulSoup(html.text,'html.parser')
    detal=sp.select("#p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilityDetail_VulnFormView_VulnTechnicalDetailsDiv table.table-striped.table-condensed.table-bordered.detail-table a")
    for i in range(len(detal)):
        Weakness+=detal[i].text+":"+'\n'+detal[i]['href']+'\n'
    return Weakness
#------------------------------------------------------------------------------