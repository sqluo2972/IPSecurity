import requests
import json
import random
from bs4 import BeautifulSoup 


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
    Description = soup.find_all('tr')[9].find('td').string  #CVE Description
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





def Get_Cve_Id(CVE):  # CVE 輸入格式 'CVE-2020-4345'
    a = ['def90f54511b9b12894314a961724e62', 'e87acbed256eeb137a54c3a486b480c2', 'b0861f726686ebdff3a848c1a3415c3f',
         '9a78845be67b920c66e07b2c720feddd', '92cfd178f914dfc17ea5672fac1e47a0']
    i = random.randint(0, 4)
    personalApiKey = a[i]
    userAgent = 'VulDB API Advanced Python Demo Agent'
    headers = {'User-Agent': userAgent, 'X-VulDB-ApiKey': personalApiKey}
    url = 'https://vuldb.com/?api'
    search = 'cve:' + CVE
    postData = {'advancedsearch': search}
    response = requests.post(url, headers=headers, data=postData)
    ID = ""
    ID += "vulDB:" + '\n'
    if response.status_code == 200:
        responseJson = json.loads(response.content)
        for i in responseJson['result']:
            ID += 'https://vuldb.com/?id.' + str(i['entry']['id']) + '\n'  # 得到搜尋結果的id
    return ID


def Get_Cve_vulDB(vuldb):
    Price = ""
    urlvuldb = 'https://vuldb.com/?id.' + vuldb
    html = requests.get(urlvuldb)
    sp = BeautifulSoup(html.text, 'html.parser')
    detal = sp.select(".hideonphonesmall.price1")
    Price += "Current Exploit Price≈:" + detal[0].text + '\n'
    return Price