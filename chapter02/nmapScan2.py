import optparse
import nmap
def nmapScan(tgtHost,tgtPort):
  nmScan = nmap.PortScanner()
  results = nmScan.scan(tgtHost,tgtPort)
  print(results)
  state = results['scan'][tgtHost]['status']['state']
  print "[*]" + tgtHost + " tcp/" + tgtPort + " " + state
def main():
  tgtHost = "92.223.67.81"
  tgtPorts = ['20','21','22','80','1750','3306','1521']
  for tgtPort in tgtPorts:
    nmapScan(tgtHost,tgtPort)
if __name__ == '__main__':
  main()
