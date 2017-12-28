#!/usr/bin/env python3

# ================================================================================================== #
# THIS PYTHON SCRIPT WAS BUILT TO REPLACE THE PHP-BASED FRONTEND FOR THE ODYSOL NGINX LOAD BALANCER  #
#                                     DO NOT SHARE WITHOUT PERMISSION                                #
#                                         CREATED BY STEVEN SMITH                                    #
# ================================================================================================== #

import shutil
import os
import socket
import requests
import time
import codecs
from splinter import Browser
import re
import subprocess
import ssl
from OpenSSL import crypto
import datetime


class automate:
    'Automating the process of receiving a ticket for an SSL Request and making the changes on the appropriate ngnix load balancer'
    browser = Browser('chrome')
    lb_ip = ''    # IP Address of Load Balancer
    clientID = ''   # Client ID from Ubersmith
    ssl_url = None
    ticketURL = None


    def main():
        automate.startAutomation()

    def startAutomation():

        automate.checkForRequests()

    def checkForRequests():
        watch_url = ""  #insert link to category to watch
        automate.browser.visit(watch_url)

        if automate.browser.title == "Login":
            #   Set username and password
            username = codecs.decode("", "rot13")
            password = codecs.decode("!", "rot13")
            #   input username and password and login
            automate.browser.fill('login', username)
            automate.browser.fill('pass', password)
            automate.browser.find_by_name('logclick').first.click()
            time.sleep(3)
        else:
            time.sleep(3)

        with automate.browser.get_iframe('content') as iframe:
            open('/tmp/htmldump.txt', 'w+').write(iframe.html)
            htmldump = open('/tmp/htmldump.txt', 'r').read()

            table = automate.browser.find_by_xpath('//*[@id="list_container"]/table[2]')
            tbody = table.find_by_tag('tbody')
            tr = tbody.find_by_tag('td')[1]
            td = tr.find_by_tag('a')
            if re.search('.*ssl.*:.*(?!:\/\/)([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{3,11}?.*',htmldump.lower()) is None:
                print('No new tickets found.')
                raise SystemExit
            else:
                SSLRequest = re.search('.*ssl.*:.*(?!:\/\/)([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{3,11}?.*',htmldump.lower())
                ticketSSLRequest = SSLRequest.group(0)
                topicSSLRequest = SSLRequest.group(0)
                topicSSLRequest = topicSSLRequest.replace('>', ' ')
                topicSSLRequest = re.search('(?:\S+\s)?\S*ssl.*:.*(?!:\/\/)([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{3,11}?',topicSSLRequest)
                topicSSLRequest = topicSSLRequest.group(0)
                ticketSSLRequest = re.findall(r'"([^"]*)"', ticketSSLRequest)
            if not ticketSSLRequest:  # If no SSL Requests found, exit.
                print('No new tickets found.')
                raise SystemExit
            else:
                if 'new ssl' in topicSSLRequest.lower():  # Check topic for 'new ssl' and proceeds if present.
                    automate.newSSLREQUEST(topicSSLRequest,ticketSSLRequest)
                elif 'update ssl' in topicSSLRequest.lower():  # Check topic for 'update ssl' and proceeds if present.
                    automate.updateSSLREQUEST(topicSSLRequest,ticketSSLRequest)

                else:
                    print('No SSL Request(s) Found. Exiting.')
                    raise SystemExit
#                return downloadedfilename

    def newSSLREQUEST(topicSSLRequest,ticketSSLRequest):
        print('topicSSLRequest: '+topicSSLRequest+'\nticketSSLRequest: '+ticketSSLRequest[0])
        print('NEW SSL Request Found.')
        automate.ticketURL = '' + ticketSSLRequest[0] #insert base URL in string
        automate.browser.visit(automate.ticketURL)  # Visit URL of ticket containing SSL Requests
        with automate.browser.get_iframe('content') as iframe:
            open('/tmp/htmldump.txt', 'w+').write(iframe.html)
            if iframe.is_element_present_by_xpath('/html/body/table[2]/tbody/tr/td[2]/a[1]/strong'):  # if client ID doesnt match variable above, continue
                if iframe.find_by_xpath('/html/body/table[2]/tbody/tr/td[2]/a[1]/strong').text == automate.clientID:
                    print('Client ID is ' + automate.clientID + '. Proceeding')
                else:
                    print('Client ID is NOT ' + automate.clientID + '. Exiting.')
                    raise SystemExit
            else:
                print('Client ID is NOT ' + automate.clientID + '. Exiting.')
                raise SystemExit

            if iframe.is_text_present('Your request has been completed.'):  # or iframe.is_text_present('We have installed the certificate'):
                print('SSL Request was previously repeated. Skipping ticket.')
                exit()
            elif iframe.is_element_present_by_xpath('//*[@id="check_ticket"]/div/table[3]/tbody/tr[2]/td/div/table/tbody/tr/td[1]/a'):  # Check xpath location is present. Location is attachments.
                print("Attachment Found")
                downloadedfilename = re.search('\s*([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\s*.pfx',automate.browser.html)  # Get Filename of .pfx
                downloadedfilename = downloadedfilename.group(0)  # Get Filename of .pfx
                pfxpassword = re.search('(?<=PASSWORD:)(.*)(?=<br />)',iframe.html)  # Search HTML for 'Password:' and strip the password from it
                pfxpassword = pfxpassword.group(0).strip()  # strip out spaces in password
                serverIPS = re.search('(?<=LB SETUP:)(.*)(?=<br />)',iframe.html)
                serverIPS = serverIPS.group(0).strip()
                serverIPS = serverIPS.split(',')
#                ipv4_address = re.compile('(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])')
#                serverIPS = re.findall(ipv4_address, lbIPS)  # Find valid IPv4 addresses
                iframe.find_link_by_partial_text('.pfx').click()  # Download attached file with .pfx ending
                shutil.move('~/Downloads/' + downloadedfilename,'/tmp/' + downloadedfilename)  # Move file from download directory to /tmp
                automate.convert_ssl(serverIPS, pfxpassword, downloadedfilename)
            else:
                print('No attachment present in latest response. Skipping.')
                exit()


    def updateSSLREQUEST(topicSSLRequest,ticketSSLRequest):
        print('topicSSLRequest: '+topicSSLRequest+'\nticktSSLRequest: '+ticketSSLRequest[0])
        print('Update SSL Request Found.')
        automate.ticketURL = '' + ticketSSLRequest[0] # insert base url in ''
        automate.browser.visit(automate.ticketURL)  # Visit URL of ticket containing SSL Requests
        with automate.browser.get_iframe('content') as iframe:
            open('/tmp/htmldump.txt', 'w+').write(iframe.html)
            if iframe.is_element_present_by_xpath(
                    '/html/body/table[2]/tbody/tr/td[2]/a[1]/strong'):  # if client ID doesnt match variable above, continue
                if iframe.find_by_xpath('/html/body/table[2]/tbody/tr/td[2]/a[1]/strong').text == automate.clientID:
                    print('Client ID is ' + automate.clientID + '. Proceeding')
                else:
                    print('Client ID is NOT ' + automate.clientID + '. Exiting.')
                    raise SystemExit
            else:
                print('Client ID is NOT ' + automate.clientID + '. Exiting.')
                raise SystemExit

            if iframe.is_text_present('Your request has been completed.'):  # or iframe.is_text_present('We have installed the certificate'):
                print('SSL Request was previously repeated. Skipping ticket.')
                exit()
            elif iframe.is_element_present_by_xpath('//*[@id="check_ticket"]/div/table[3]/tbody/tr[2]/td/div/table/tbody/tr/td[1]/a'):  # Check xpath location is present. Location is attachments.
                print("Attachment Found")
                downloadedfilename = re.search('\s*([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\s*.pfx',automate.browser.html)  # Get Filename of .pfx
                downloadedfilename = downloadedfilename.group(0)  # Get Filename of .pfx
                pfxpassword = re.search('(?<=PASSWORD:)(.*)(?=<br />)',iframe.html)  # Search HTML for 'Password:' and strip the password from it
                pfxpassword = pfxpassword.group(0).strip()  # strip out spaces in password
                ipv4_address = re.compile('(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])')
                serverIPS = re.findall(ipv4_address, iframe.html)  # Find valid IPv4 addresses
                iframe.find_link_by_partial_text('.pfx').click()  # Download attached file with .pfx ending
                shutil.move('~/Downloads/' + downloadedfilename,'/tmp/' + downloadedfilename)  # Move file from download directory to /tmp
                automate.convert_ssl(serverIPS, pfxpassword, downloadedfilename)
            else:
                print('No attachment present in latest response. Skipping.')
                exit()

    def convert_ssl(serverIPS, pfxpassword, downloadedfilename):
        print('Filename. ' + downloadedfilename + '\nPassword: ' + pfxpassword + '\nServer IP(s): ' + str(serverIPS).strip("[]"))
        pfx_file = downloadedfilename
        pfx_file = pfx_file.rstrip()
        automate.ssl_url = pfx_file.strip('.pfx')  # Strip .pfx
        automate.ssl_url = automate.ssl_url.split("/")[-1]  # Split at the last /. Now you have your domain!
        print("Domain: " + automate.ssl_url)
        os.system('openssl pkcs12 -in /tmp/' + pfx_file + ' -out /tmp/certificate.cer -nodes -passin pass:' + pfxpassword)
        time.sleep(1)
        certcer = open('/tmp/certificate.cer', 'r')

        #   IF MULTIPLES CERTS FOUND, BREAK AND PRINT MANUAL INPUT NEEDED
        total = 0
        for line in certcer:
            if "-----BEGIN CERTIFICATE-----" in line:
                total += 1
        certcer.close()
        if total > 1:
            os.system("sed '/-----BEGIN.*PRIVATE KEY-----/,/-----END.*PRIVATE KEY-----/!d' /tmp/certificate.cer > /tmp/" + automate.ssl_url + ".key")
            os.system("sed '/-----END CERTIFICATE-----/q' /tmp/certificate.cer > /tmp/" + automate.ssl_url + ".crt")
            os.system("sed '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/!d' /tmp/" + automate.ssl_url + ".crt")
            cert = open('/tmp/' + ssl_url + '.key', 'r')
            cert = cert.read()
            rsaprivkey = open('/tmp/' + ssl_url + '.key', 'r')
            rsaprivkey = rsaprivkey.read()
            automate.addIntermediate(serverIPS)
        else:
            os.system("sed '/-----BEGIN.*PRIVATE KEY-----/,/-----END.*PRIVATE KEY-----/!d' /tmp/certificate.cer > /tmp/" + automate.ssl_url + ".key")
            os.system("sed '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/!d' /tmp/certificate.cer > /tmp/" + automate.ssl_url + ".crt")
            cert = open('/tmp/' + automate.ssl_url + '.key', 'r')
            cert = cert.read()
            rsaprivkey = open('/tmp/' + automate.ssl_url + '.key', 'r')
            rsaprivkey = rsaprivkey.read()
            automate.addIntermediate(serverIPS)

    def addIntermediate(serverIPS):
        cmd = r'''cfssl bundle -cert /tmp/''' + automate.ssl_url + r'''.crt | sed 's/\\n/\
    /g' > /tmp/bundle.cer'''
        print(cmd)
        os.system(cmd)
        certbundle = open('/tmp/bundle.cer')
        certbundle = certbundle.read()
        certbundle = certbundle.lstrip('{"bundle":"')
        certbundle = certbundle.split('",')[0]
        open('/tmp/bundle.cer', 'w+').write(certbundle)
        os.system('cat /tmp/bundle.cer >> /tmp/' + automate.ssl_url + '.crt')
        automate.makeNGINXCONF(serverIPS)


    def check_dns(url):
        domain_ip = socket.gethostbyname(url)
        if domain_ip == lb_ip:
            print('The domain is pointed to the loadbalancer.')
            check_ssl('https://' + automate.ssl_url)
        else:
            messageString = 'Hello,\n\nI hope all is well.\nYour request is now complete, however we are unable to verify the certificate due to the following reason(s):\n\nThe domain is NOT pointed to the loadbalancer.\nPlease have client update A Records to point to ' + lb_ip + '.\nCurrently it is set to ' + domain_ip + '.\n\nKindly,\nDatacenter Staff'
            respondTicket(messageString)

    def check_ssl(url):
        try:
            req = requests.get(url, verify=True)
            cert_file = ssl.get_server_certificate((url, 443))
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file)
            notafter = cert.get_notAfter()
            notafter = str(notafter).lstrip("b'")
            notafter = notafter.rstrip("'")
            utcafter = datetime.datetime.strptime(notafter, "%Y%m%d%H%M%SZ")
            utcnow = datetime.datetime.utcnow()
            expirationdate = utcafter.date()  # Expiration Date Format: YYYY-MM-DD
            expires_in = '{0}'.format(utcafter - utcnow, notafter)
            regex = re.compile('^.*days')
            expires_in = re.match(regex, expires_in)[0]  # How many days until cert expires. Format: XXX days
            messageString = 'Hello,\n\nI hope all is well.\n' + url + ' has a VALID SSL certificate!\nYour certificate is set to expire in' + expires_in + '(' + expirationdate + ').\nTo view the results please, go to https://www.sslshopper.com/ssl-checker.html#hostname=' + url + '\n\nKindly,\nDatacenter Staff'
            print(messageString)
            automate.respondTicket(messageString)
        except requests.exceptions.SSLError:
            messageString = url + ' has an INVALID SSL certificate!\nGo to https://www.sslshopper.com/ssl-checker.html#hostname=' + url + ' to see why.'
            automate.noteTicket(messageString)


    def respondTicket(messageString):
        automate.browser.visit(automate.ticketURL)
        with automate.browser.get_iframe('content') as iframe:
            automate.browser.find_by_text('Post a Followup').first.click()  # Click link to 'Post a Followup'
            automate.browser.fill('minutes', '10')  # set 5 minutes as time worked
            automate.browser.select('state', '5')
            automate.browser.fill('followup', messageString)  # fill out message with dmca notifcation
            automate.browser.find_by_xpath('//*[@id="send_followup"]').first.click()
            if "It looks like you meant to add an attachment." in iframe.html:
                automate.browser.find_by_name('modalYes').click()
            print('Notice Sent.')


    def noteTicket(messageString):
        automate.browser.visit(automate.ticketURL)
        with automate.browser.get_iframe('content') as iframe:
            automate.browser.find_by_text('Add a Comment').first.click()  # Click link to 'Post a Followup'
            automate.browser.fill('followup', messageString + '\n\nReload Output:\n' + open('/tmp/temp.txt','r').read())  # fill out message with dmca notifcation
            automate.browser.find_by_xpath('//*[@id="send_followup"]').first.click()
            if "It looks like you meant to add an attachment." in iframe.html:
                automate.browser.find_by_name('modalYes').click()
        print('Notice Sent.')



    def makeNGINXCONF(serverIPS):
        #   Create nginx conf file
        __location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
        nginxconfig = open(os.path.join(__location__, 'includes', 'nginx_template.conf'), 'r')
        nginxconfig = nginxconfig.read()
        newconfig = nginxconfig
        newconfig = newconfig.replace("<hostname>", automate.ssl_url)
        config_name = automate.ssl_url + ".conf"
        print("Adding " + config_name + " to /etc/nginx/conf.d/.")

        n = 0
        n2 = 0

        try:
            while serverIPS[n2]:
                #    while n < 10 and monitor_page.serverIPS[n2] != []:
                n = n + 1
                #        server = "server"+str(n)
                #        serverIP = input(server+' IP: ')
                if serverIPS[n2] != '':
                    newconfig = newconfig.replace('<server' + str(n) + '>', serverIPS[n2])
                    newconfig = newconfig.replace('#         server', '         server', 1)
                    n2 = n2 + 1
        except IndexError:
            print('End of ServerIP List')

        print(str(n) + ' IPs added')
        newconf = open('/tmp/' + automate.ssl_url + '.conf', 'w')
        newconf.write(newconfig)
        newconf.close()
        os.system('scp /tmp/' + automate.ssl_url + '.conf root@' + automate.lb_ip + ':/etc/nginx/conf.d')  # Transfer .conf to LB
        automate.reloadSERVER()

    def reloadSERVER():
        os.system('scp /tmp/' + automate.ssl_url + '.crt root@' + automate.lb_ip + ':/etc/ssl/certs')  # Transfer .crt to LB
        os.system('scp /tmp/' + automate.ssl_url + '.key root@' + automate.lb_ip + ':/etc/ssl/certs')  # Transfer .key to LB
        with open('/tmp/temp.txt', 'w') as sshOUTPUT:
            a = subprocess.Popen(['ssh', 'root@' + automate.lb_ip, ' nginx -s reload && service nginx reload && /etc/init.d/nginx reload'],stdout=sshOUTPUT, stderr=subprocess.STDOUT)
            a.wait()
            del a
        if 'Reloading nginx configuration (via systemctl): nginx.service.' in open('/tmp/temp.txt', 'r').read():
            print('Ngnix Reloaded Successfully.')
            automate.check_dns(url)
        else:
            print('ERROR RELOADING NGINX. ROLLING BACK AND EXITING.')
            a = subprocess.Popen(['ssh', 'root@' + automate.lb_ip, ' rm -rf /etc/nginx/conf.d/' + automate.ssl_url + '.conf']) # Delete .conf
            a.wait()
            del a
            a = subprocess.Popen(['ssh', 'root@' + automate.lb_ip, ' rm -rf /etc/ssl/certs/' + automate.ssl_url + '.crt']) # Delete .crt
            a.wait()
            del a
            a = subprocess.Popen(['ssh', 'root@' + automate.lb_ip, ' rm -rf /etc/ssl/certs/' + automate.ssl_url + '.key']) # Delete .key
            a.wait()
            del a
            messageString = automate.ssl_url + ' has an INVALID SSL certificate!\nGo to https://www.sslshopper.com/ssl-checker.html#hostname=' + automate.ssl_url + ' to see why.'
            automate.noteTicket(messageString)
        print('DONE')


automate.main()
