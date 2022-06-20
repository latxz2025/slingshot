from socket import  *
from concurrent.futures import ThreadPoolExecutor,as_completed

host="47.96.196.246"
# host="121.89.217.56"

th = 5
start, end = 80,81
def scan(port):
    sock= socket(AF_INET,SOCK_STREAM)
    try:
        sock.settimeout(5)
        sock.connect((host,port))
        sock.send('hello\r\n'.encode())
        result=(sock.recv(1024)).decode()
        print(result)
        if "HTTP" in result or "<title>" in result:
            print(host,port)

    except Exception as e:
        print(e)
    finally:
        sock.close()

def main():
    with ThreadPoolExecutor(max_workers=th) as t:
        job_list = []
        for port in range(start,end):
            # print(port)
            obj = t.submit(scan,port)
            job_list.append(obj)
if __name__=='__main__':
    main()
