import optparse
import socket
import threading
import nmap

screenLock = threading.Semaphore(value=1)
def connScan1(tgtHost,tgtPort):
  try:
    nmScan = nmap.PortScanner()
    results = nmScan.scan(tgtHost,tgtPort)
    state = results['scan'][tgtHost]['tcp'][int(tgtPort)]['state']
    print "[********]" + tgtHost + " tcp/" + tgtPort + " " + state
  except:
    print("[********=====]except tcp "+tgtHost+"closed")
def connScan(tgtHost,tgtPort):
  try:
    nmScan = nmap.PortScanner()
    results = nmScan.scan(tgtHost,tgtPort)
    state = results['scan'][tgtHost]['tcp'][int(tgtPort)]['state']
    print('[*]tcp/' + tgtPort + ' ' + state )
  except:
    print('[-]except %d/tcp closed' % tgtPort)
def portScan(tgtHost,tgtPorts):
  try:
    tgtIP = socket.gethostbyname(tgtHost)
    print('tgtIP=' + tgtIP)
  except:
    print("[-] Cannot resolve '%s':Unknown host"%tgtHost)
    return
  try:
    tgtName = socket.gethostbyadd(tgtIP)
    print('\n[+] Scan Results for:' + tgtName[0])
  except:
    print('\n[+] Scan Results for:' + tgtIP)
  socket.setdefaulttimeout(1)
  for tgtPort in tgtPorts:
    print('Scanning port ' + str(tgtPort))
    t = threading.Thread(target=connScan,args=(tgtIP,tgtPort))
    t.start()
    
def main():
  parser = optparse.OptionParser('usage %prog -H <target host> -p <target port>')
  parser.add_option('-H',dest='tgtHost',type='string',help='specify target host')
  parser.add_option('-p',dest='tgtPort',type='int',help='specify target port')
  (options,args) = parser.parse_args()
  tgtHost = options.tgtHost
  tgtPort = options.tgtPort
  args.append(tgtPort)
  if (tgtHost == None) | (tgtPort == None):
    print('[-] You must specify a target host and port[s]!')
    exit(0)
  portScan(tgtHost,args)

if __name__=='__main__':
  main()
