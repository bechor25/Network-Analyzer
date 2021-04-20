from scapy.all import *
import sys
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
# -*- coding: utf-8 -*-
import time
from datetime import date
from lxml import etree
from collections import OrderedDict

#package load
pkts = sniff(offline="CaptureFile.cap")
firstPkt=pkts[0]
#firstPkt.show()
#firstPkt.pdfdump("CaptureFile.pdf")

#q1
print("-----------q1----------")
#print(firstPkt[DNS].qd)
lenPackage = firstPkt[IP].len
print(firstPkt[IP].len)
#q2
print("-----------q2----------")
pkt=0
for i in range(0, len(pkts)):
    pkt = pkts[i]
    #print(pkt.len)
#q3
print("-----------q3----------")
allLenPackage = len(pkts)
print(len(pkts))
#q4
print("-----------q4----------")
pkt_len_max,pkt_indx_max=max([(len(pkts[i]),i+1) for i in range(len(pkts))])
print("pkt_len=",pkt_len_max,"pkt_indx=",pkt_indx_max)

#q5
print("-----------q5----------")

pkt_len_min,pkt_indx_min=min([(len(pkts[i]),i+1) for i in range(len(pkts))])
print("pkt_len=",pkt_len_min,"pkt_indx=",pkt_indx_min)
#q6
#print("-----------q6----------")
#get_packets=[str(p).split("Host: ")[1].split("\\r\\n")[0] for p in pkts if str(p).count("GET")>0]
#print(count(get_packets))

#####plot

ypoints = np.array([lenPackage, pkt.len, allLenPackage, pkt_len_max, pkt_indx_max, pkt_len_min, pkt_indx_min])

xpoints=np.array(["lenPackage", "sizeofPackage", "allLenPackage", "PackageMax", "pkt_indx_max", "PackageMin", "pkt_indx_min"])


#plt.scatter(xpoints, ypoints, c = colors)
plt.bar(xpoints, ypoints)
plt.title("Analyzer network",loc = 'center')
plt.xlabel("file packet")
plt.ylabel("data packet")
plt.grid(axis='y')
plt.xticks(rotation=90)
plt.subplots_adjust(bottom=0.24)
plt.show()
#plt.savefig("temp.pdf")
#Two  lines to make our compiler able to draw:
plt.savefig(sys.stdout.buffer)
sys.stdout.flush()

##xml file
page = etree.Element('results')
# Make a new document tree
doc = etree.ElementTree(page)
# Add the subelements
pageElement = etree.SubElement(page, 'Analyzer',lenPackage = str(lenPackage), 
                                      allLenPackage = str(allLenPackage),
                                      sizeofPackage =str(pkt.len))

# For multiple multiple attributes, use as shown above
# Save to XML file
outFile = open('output.xml', 'wb')
doc.write(outFile) 















