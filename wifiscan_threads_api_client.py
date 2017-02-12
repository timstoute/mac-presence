#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

#############
# program sniffs wifi packets
# matches only those which are probe requests
# finds MAC address of device sending probe request and compares it against 
# a known list of addresses, and an ignore list
# if MAC on ignore list then probes are ignored
# if MAC is not on either list, it is logged and printed on screen
# if MAC is know adds MAC to a PRESENT dict with timestamp

import logging, threading, sys
from datetime import datetime, timedelta
from pyrfc3339 import generate, parse
import pytz
import smtplib
from smtplib import SMTP_SSL as SMTP

from scapy.all import *
import pprint
from apiclient.discovery import build
import os
import time
import httplib2

global t_service
global w_service

PROBE_REQUEST_TYPE=0
PROBE_REQUEST_SUBTYPE=4

allDevices = {'00:56:cd:58:64:5b':'RM','cc:20:e8:7a:94:e0':'Judy','ac:bc:32:ad:21:93':'Tim Mac Book','98:FE:94:4E:29:06':'Aine MacBook','6c:94:f8:8f:5e:eb':'Teas ipad','64:bc:0c:51:48:48':'Tim N5x','e8:50:8b:41:d1:33':'Tim S6 Phone','f4:f1:e1:12:ec:67':'Parker','64:77:91:e7:b3:77':'Lina Apple device','2c:f0:ee:29:f8:12':'Renee Laptop','28:5a:eb:c4:5d:96':'Renee Phone','c8:85:50:7a:d0:af':'Aine phone' } # dict of known devices
smartPhones = {'00:56:cd:58:64:5b':'RM','cc:20:e8:7a:94:e0':'Judy','64:bc:0c:51:48:48':'Tim N5x','e8:50:8b:41:d1:33':'Tim S6 Phone','f4:f1:e1:12:ec:67':'Parker Phone','64:77:91:e7:b3:77':'Lina Phone','28:5a:eb:c4:5d:96':'Renee Phone','c8:85:50:7a:d0:af':'Aine phone'} # dict of known devices
otherDevices = {'ac:bc:32:ad:21:93':'Tim Mac Book','98:FE:94:4E:29:06':'Aine MacBook','6c:94:f8:8f:5e:eb':'Teas ipad','2c:f0:ee:29:f8:12':'Renee Laptop',}
IGNORELIST = {'00:1d:63:01:15:8b':'Miele device A','00:1d:63:01:15:39':'Miele device B','00:1d:63:01:33:51':'Miele device C','6c:ad:f8:cc:c6:dd':'Chromecast','b0:05:94:b4:ab:e1':'LiteOn','00:07:80:60:b1:62':'Neighbour device','00:c0:ca:32:c0:bb':'Alfa','b8:e9:37:87:a3:13':'Sonos A','00:0e:58:de:5c:73':'Sonos B','00:0e:58:bb:87:10':'Sonos C','00:0e:58:bb:87:0f':'Sonos D'} #dict of devices to ignore
PRESENT={}
SESSIONIGNORELIST ={}
#PollTime = sys.argv[2]
PollTime = 5


LOG_FILENAME = 'wifiscan_threads_api_client.log'
logging.basicConfig(filename=LOG_FILENAME,
                    level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s] (%(threadName)-10s) %(message)s',
                    )

def PacketHandler(pkt):
    try:
        if pkt.haslayer(Dot11):
            # packet
            if pkt.type==PROBE_REQUEST_TYPE and pkt.subtype == PROBE_REQUEST_SUBTYPE and (pkt.addr2.lower() in smartPhones): 
                # packet is a probe, and known
                mac = pkt.addr2.lower()
                name = smartPhones[pkt.addr2.lower()]
                print 'in packet hander with smartPhone, name: ' + str(name) + ' mac: ' + mac 
                DoKnown(pkt, mac, name, 'smartPhone')
            elif pkt.type==PROBE_REQUEST_TYPE and pkt.subtype == PROBE_REQUEST_SUBTYPE and (pkt.addr2.lower() in otherDevices):
                # packet is a probe, and known     
                mac = pkt.addr2.lower()
                name = otherDevices[pkt.addr2.lower()]
                print 'in packet hander with otherDevice, name: ' + str(name) + ' mac: ' + mac 
                DoKnown(pkt, mac, name, 'otherDevice')
            elif pkt.type==PROBE_REQUEST_TYPE and pkt.subtype == PROBE_REQUEST_SUBTYPE and (pkt.addr2.lower() not in IGNORELIST): 
                # packet is a probe, and is not known and not ignored
                if not SESSIONIGNORELIST.has_key(pkt.addr2.lower()):
                    mac = pkt.addr2.lower()
                    
                    if mac.find('da:a1') < 0: ## filter out Google's mac spam  
                                          
                        #######   Build a service object for interacting with the API for thread w
                        api_root = 'https://homesteadapi.appspot.com/_ah/api'
                        api = 'deviceApi'
                        version = 'v1'
                        discovery_url = '%s/discovery/v1/apis/%s/%s/rest' % (api_root, api, version)
                        t_service = build(api, version, discoveryServiceUrl=discovery_url)
                        
                        ######## API CALLS 
                        # call api with insert method for this UNKNOWN DEVICE mac
                        # home is: true
                        # mac is:  pkt.addr2.lower()
                        
                        
                        response = t_service.insert(body={
                                                          'id': mac,
                                                          'name': 'unknown',
                                                          'home': 'true',
                                                          'lastseen': str(generate(datetime.utcnow().replace(tzinfo=pytz.utc))),
                                                          'deviceType': 'unknown'
                        }).execute()

                    
                        logging.info('a probe from unknown mac has appeared (that\'s not in the ignore list): ' + pkt.addr2.lower())
                        SESSIONIGNORELIST[pkt.addr2.lower()] = datetime.now()
                    print 'in packet hander with unrecognized device,  mac: ' + mac 
            #else:
                # a non-probe packet 
                #logging.info('a non-probe packet from: ' + pkt.addr2.lower())
                #print 'a non-probe packet from: ' + pkt.addr2.lower()
        else:
            print 'dont care about this packet - doesn\'t have Dot11'
            # don't care about this packet
    except Exception as inst:
        import traceback
        traceback.print_exc()
        print 'calling exception handler from PacketHander'
        ExceptionHandler(inst)
   

def DoKnown(pkt, mac, name, deviceType):
        
    global t_service
        
    #######   Build a service object for interacting with the API for thread w
    api_root = 'https://homesteadapi.appspot.com/_ah/api'
    api = 'deviceApi'
    version = 'v1'
    discovery_url = '%s/discovery/v1/apis/%s/%s/rest' % (api_root, api, version)
    t_service = build(api, version, discoveryServiceUrl=discovery_url)
    
    logging.info('in DoKnown with MAC mapped to: ' + name)
    print str(datetime.now().time()) + "---> a known device is present: " + mac
    if PRESENT.has_key(mac):
        now = datetime.now()
        lastNotified = PRESENT[mac]
        d = now - lastNotified
        print str(datetime.now().time()) + " in DoKnown, time delta (now - last notified on this device)= " + str(d) + " for key: " +  name
        PrintPacket(pkt, mac, name)
        if d > timedelta(minutes=PollTime):
            #print "sending email to : " +  name
            #logging.info('sending email to : ' +  smartPhones[pkt.addr2.lower()])
            #SendEmail(pkt.addr2.lower(), ' is still home')
            PRESENT[mac] = datetime.now()
            
            ######## API CALLS 
            # call api with patch method for this mac
            # home is: true
            # mac is:  pkt.addr2.lower()
            # name is: SMARTPHONES[pkt.addr2.lower()]
            
            response = t_service.patch(macid=pkt.addr2.lower(), body={
                                          'home': 'true',
                                          'lastseen': str(generate(datetime.utcnow().replace(tzinfo=pytz.utc))) # doctest:+ELLIPSIS - from https://pypi.python.org/pypi/pyRFC3339
                                        }).execute()
    else:
        # known device is present, but not yet added to PRESENT dict
        PRESENT[mac]= datetime.now()
        # add mac to PRESENT dict as key, and set value to timestamp now
        print str(datetime.now().time()) + " ---> added new entry to PRESENT dict : " + str(mac) + " at time now= " + str(datetime.now())
        #SendEmail(pkt.addr2.lower(), ' has just shown up') # send email the first time we see the known mac
        PrintPacket(pkt, mac, name)

        ######## API CALLS 
        # call api with insert method for this mac
        # home is: true
        # mac is:  pkt.addr2.lower()
        # name is: SMARTPHONES[pkt.addr2.lower()]
        print str(datetime.now().time()) + " ---> about to call insert with id=" + mac + ", name=" + name + ", home=true" + ", lastseen=" + str(generate(datetime.utcnow().replace(tzinfo=pytz.utc))) + ", deviceType=" + deviceType
        response = t_service.insert(body={
                                          'id': mac,
                                          'name': name,
                                          'home': 'true',
                                          'lastseen': str(generate(datetime.utcnow().replace(tzinfo=pytz.utc))),
                                          'deviceType': deviceType
                                        }).execute()

        
        ######## SERVOS 
        # activate servos for specfic devices here
        if pkt.addr2.lower() == 'e8:50:8b:41:d1:33':   # this is Tim
            os.system("sudo echo 0=100% > /dev/servoblaster")  # turn servo 0 to 100%


def PrintPacket(pkt, mac, name):
    print str(datetime.now().time()) + "---> Probe Request Captured from known device:" + name
    logging.info('---> Probe Request Captured from known device:' + name)
    try:
        extra = pkt.notdecoded
    except Exception as inst:
        extra = None
    if extra!=None:
        signal_strength = -(256-ord(extra[-4:-3]))
    else:
        signal_strength = -100
        print str(datetime.now().time()) + "No signal strength found"    
    print str(datetime.now().time()) +" --->Target: %s Source: %s SSID: %s RSSi: %d"%(pkt.addr3,pkt.addr2,pkt.getlayer(Dot11ProbeReq).info,signal_strength)
    logging.info('--->Target: %s Source: %s SSID: %s RSSi: %d'%(pkt.addr3,pkt.addr2,pkt.getlayer(Dot11ProbeReq).info,signal_strength))

def CheckForAbsences():
        global w_service        
        #######   Build a service object for interacting with the API for thread w
        api_root = 'https://homesteadapi.appspot.com/_ah/api'
        api = 'deviceApi'
        version = 'v1'
        discovery_url = '%s/discovery/v1/apis/%s/%s/rest' % (api_root, api, version)
        w_service = build(api, version, discoveryServiceUrl=discovery_url)

        ###### 
        print "\n" + str(datetime.now().time()) + ' in CheckForAbsences function'
        logging.info('in CheckForAbsences function, Present keys are ' + str(PRESENT.keys()))
        print "\n Present Keys are: " + str(PRESENT.keys())
        
        ##### loop through PRESENT DICT
        for key in PRESENT.keys():
            print str(datetime.now().time()) + ' looping through PRESENT dict at key: ' + key + ' which is ' + allDevices[key]
            logging.info('looping through PRESENT dict at key: ' + key + ' which is ' + allDevices[key])
            rightnow = datetime.now()
            print 'now time is: ' + str(rightnow)
            lastNotified = PRESENT[key]
            print 'lastNotified time is '+ str(lastNotified)
            d = rightnow - lastNotified
            print str(datetime.now().time()) + " time delta (now - last notified on this device)= " + str(d) + " for key: " + key + " which is " + allDevices[key]
            if d > timedelta(minutes=(PollTime+5)):
                print str(datetime.now().time()) + "---> key (" + allDevices[key] + ") hasn't been seen in " +  str(PollTime) + " mins, and is being removed from the PRESENT dict : " +  str(key)
                #SendEmail(key, ' is no longer being detected - is being removed from the PRESENT dict')
                logging.info('this mac has been removed from the PRESENT dict: ' + allDevices[key])
                                    
                ######## API CALLS 
                # call api with patch method for this mac
                # home is: false
                # mac is:  key
                # name is: SMARTPHONES[key]
                print str(datetime.now().time()) + "---> about to call API with id = " + key
                response = w_service.patch(macid=key, body={
                                          'home': 'false'
                                        }).execute()
                
                # now remove the key from the local array
                del PRESENT[key]
                
                ###### adjust the servo
                if key == 'e8:50:8b:41:d1:33':
                    os.system("sudo echo 0=0% > /dev/servoblaster")            
        logging.debug('Exiting ' + threading.currentThread().getName())
        print "\n" + str(datetime.now().time()) + " Exiting " + threading.currentThread().getName()

        threading.Timer((PollTime*60), CheckForAbsences).start()

def SendEmail(mac, msg, deviceType):
    smtpUser = 'stoute@gmail.com'
    smtpPass = 'bpdypeiznqkijywy'

    toAdd = 'stoute@gmail.com'
    fromAdd = 'stoute@gmail.com'

    subject = 'device notification'
    header = 'To: ' + toAdd + '\n' + 'From: ' + fromAdd + '\n' + 'Subject: ' + subject
    body = deviceType[mac] + msg
    
    s = smtplib.SMTP('smtp.gmail.com',587)
    s.ehlo()
    s.starttls()
    s.ehlo()

    s.login(smtpUser, smtpPass)
    s.sendmail(fromAdd, toAdd, header + '\n\n' + body)

    s.quit()

def ExceptionHandler(e):
    exc_type, exc_obj, exc_value = sys.exc_info()[:3]
   
    fname = os.path.split(exc_value.tb_frame.f_code.co_filename)[1]
    line = exc_value.tb_lineno
    logging.info('Handling %s exception with message "%s" in %s at line %s' % (exc_type.__name__, exc_value, threading.current_thread().name, line))
    print 'Handling %s exception with message "%s" in %s at line %s' % (exc_type.__name__, exc_value, threading.current_thread().name, line)
    #print 'EXCEPTION IN ({}, LINE {} "{}"): {}'.format(filename, lineno, line.strip(), exc_obj)
    #SendEmail(99999, 'Handling %s exception with message "%s" in %s' % (exc_type.__name__, exc_value, threading.current_thread().name), 'devicetype not provided')
    

def main():
    from datetime import datetime
    global t_service
    print "[%s] ----> Starting main thread now .... " % datetime.now()
    
    #######   Build a service object for interacting with the API for thread t
    api_root = 'https://homesteadapi.appspot.com/_ah/api'
    api = 'deviceApi'
    version = 'v1'
    discovery_url = '%s/discovery/v1/apis/%s/%s/rest' % (api_root, api, version)
    t_service = build(api, version, discoveryServiceUrl=discovery_url)
    
    ##### start the sniffer
    try:
        sniff(iface=sys.argv[1],prn=PacketHandler,store=0)
    except Exception as inst:
       print type(inst)     # the exception instance
       print inst.args      # arguments stored in .args
       print inst           # __str__ allows args to be printed directly
       ExceptionHandler(inst)
        

    
if __name__=="__main__":
    t = threading.Thread(name='main', target=main) 
    w = threading.Thread(name='CheckForAbsences', target=CheckForAbsences)
    w.start()
    t.start()

   # main()


