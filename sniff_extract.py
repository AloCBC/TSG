# --------------------------------------- Imports for Data Science --------------------------------------------------- #
import numpy as np
import pandas as pd
import datetime
# ----------------------------------------- Imports for Sniffing ----------------------------------------------------- #
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP
# --------------------------------------- Imports for OS and comm' --------------------------------------------------- #
import subprocess as cmd
from ftplib import FTP
import socket
# ----------------------------------------------- Constants ---------------------------------------------------------- #
COUNT = 100
# ----------------------------------------------- Functions ---------------------------------------------------------- #
def extract_pcap(count=COUNT):
    '''Applies the sniffing
    Returns the pcap file.'''
    pcap = sniff(count=count)
    return pcap

def extract_ttl(count=COUNT):
    '''Function that extracts the ttl from the pcap sniffing.
    Returns a list of ttls'''
    ttls = []
    for i in range(count):
        try: # In the case we encounter an IP layer
            ttls.append(pcap[i][IP].fields['ttl'])
        except IndexError: # if there is no IP layer, no ttl, then ttl=0
            print('the {}th packet has no layer IP'.format(i))
            ttls.append(0)

    return ttls

def extract_src(count=COUNT):
    '''Function that extracts the src from the pcap sniffing.
    Returns a list of srcs'''
    srcs = []
    for i in range(count):
        try: # In the case we encounter an IP layer
            srcs.append(pcap[i][IP].fields['src'])
        except IndexError: # if there is no IP layer, no src, then src = 0.0.0.0
            print('the {}th packet has no layer IP'.format(i))
            srcs.append('0.0.0.0')

    return srcs

def extract_dst(count=COUNT):
    '''Function that extracts the dst from the pcap sniffing.
    Returns a list of dsts'''
    dsts = []
    for i in range(count):
        try: # In the case we encounter an IP layer
            dsts.append(pcap[i][IP].fields['src'])
        except IndexError: # if there is no IP layer, no dst, then dst = 0.0.0.0
            print('the {}th packet has no layer IP'.format(i))
            dsts.append('0.0.0.0')

    return dsts

def build_dataframe(srcs=[], dsts=[], ttls=[], count=COUNT):
    '''Build the dataframe based on the list extracted before.'''
    if not srcs:
        srcs = ['NaN' for i in range(count)]
    if not dsts:
        dsts = ['NaN' for i in range(count)]
    if not ttls:
        ttls = ['NaN' for i in range(count)]

    return pd.DataFrame(list(zip(srcs, dsts, ttls)), columns=['srcs', 'dsts', 'ttls'])


def connect_ftp(ip, login, pwd):
    '''In case it is necessary to connect voiia ftp protocol'''
    ftp = FTP(ip)
    ftp.login(user=login, passwd=pwd)

def commit(commit_mess=''):
    '''Commit to github in order to push the dataframe.'''
    if not commit_mess:  #Default message if we don't specify one
        commit_mess = f'{datetime.now()} on machine {socket.gethostname()}'

    # Run the add of the file created
    cp = cmd.run('git add .', check=True, shell=True)

    cp = cmd.run(f"git commit -m '{commit_mess}'", check=True, shell=True)
    cp = cmd.run("git push -u origin master -f", check=True, shell=True)
    print(f'{commit_mess} commited successfully')

# --------------------------------------------- Main Function -------------------------------------------------------- #
if __name__ == "__main__":

    #Let's capture data. We must be available to trigger the fault.
    pcap = extract_pcap()

    #Let's extract the data in a matrix first, to put into dataframe
    ttls = extract_ttl()
    dsts = extract_dst()
    srcs = extract_src()

    df = build_dataframe(srcs, dsts, ttls)
    print(df)

    df.to_csv(r'./dataframe.csv')
    print(os.listdir(r'.'))
    # pwd = input('Please enter FTP-User pwd')
    # connect_ftp('37.26.149.134', 'FTP-User', pwd)
    commit()
