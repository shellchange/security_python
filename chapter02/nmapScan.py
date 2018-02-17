import optparse
import nmap
def nmapScan(tgtHost,tgtPort):
  nmScan = nmap.PortScanner()
  results = nmScan.scan(tgtHost,tgtPort)
  state = results['scan'][tgtHost]['tcp'][int(tgtPort)]['state']
  print "[*]" + tgtHost + " tcp/" + tgtPort + " " + state
def main():
  tgtHost = "120.26.135.5"
  tgtPorts = ['20','21','22','80','1750','3306','1521']
  for tgtPort in tgtPorts:
    nmapScan(tgtHost,tgtPort)
if __name__ == '__main__':
  main()
