import docker
import multiprocessing

#TODO: Change the domain variable to the domain you would like to scan
domain = "scanme.nmap.org"
#TODO: Change the home_dir variable to the path to the folder that you'd like the output files written to. Note: End with a forward slash
home_dir = '/Users/samanthamorris/beachcomber-output/'

#Runs Nikto in a container and outputs a text file to the home directory containing the Nikto report.
def nikto_function():
    client = docker.from_env()
    result = client.containers.run("sullo/nikto", "-h " + domain, remove=True, tty=True)
    f = open(home_dir + domain + '_nikto_report.txt', 'wb')
    f.write(result)
    print("Nikto Analysis Completed.")

#Runs SSLYZE in a container and outputs a text file to the home directory containing the SSLYZE report.
def sslyze_function():
    client = docker.from_env()
    result = client.containers.run("nablac0d3/sslyze", "--regular " + domain, remove=True, tty=True)
    f = open(home_dir + domain + '_sslyze_report.txt', 'wb')
    f.write(result)
    print("SSLYZE Analysis Completed.")

#Runs Nmap in a container and outputs a text file to the home directory containing the Nmap report.
def nmap_function():
    client = docker.from_env()
    result = client.containers.run("instrumentisto/nmap", " -A " + domain, remove=True, tty=True)
    f = open(home_dir + domain + '_nmap_report.txt', 'wb')
    f.write(result)
    print("Nmap Analysis Completed.")

#Runs Nmap in a container and outputs a text file to the home directory containing the Nmap report.
def nmap_function2():
    client = docker.from_env()
    container = client.containers.run("instrumentisto/nmap", " -A " + domain + "-oX /home/nmap.xml", detach=True, tty=True)
    f = open(home_dir + domain + '_nmap_report.tar', 'wb')
    flag = 0
    while(flag == 0):
        if(container.status == 'exited'):
            bits, stat = container.get_archive('./')
            flag = 1
        else:
            container.reload()
    for chunk in bits:
        f.write(chunk)
    f.close()
    print('Nmap Analysis Completed.')

def pshtt_function():
    client = docker.from_env()
    container = client.containers.run("18fgsa/domain-scan", domain + " --scan=pshtt", detach=True, tty=True)
    f = open(home_dir + domain + '_pshtt_report.tar', 'wb')
    flag = 0
    while(flag == 0):
        if(container.status == 'exited'):
            bits, stat = container.get_archive('/home/scanner/results/pshtt.csv')
            flag = 1
        else:
            container.reload()
    for chunk in bits:
        f.write(chunk)
    f.close()
    print('PSHTT Analysis Completed.')

if __name__ == "__main__":
    #Warning: Nikto takes ~10 minutes to run
    #p1 = multiprocessing.Process(target=nikto_function)

    #p2 = multiprocessing.Process(target=sslyze_function)
    p3 = multiprocessing.Process(target=nmap_function2)
    #p4 = multiprocessing.Process(target=pshtt_function)

    #p1.start()
    #p2.start()
    p3.start()
    #p4.start()

    #p1.join()
    #p2.join()
    p3.join()
    #p4.join()
    print("Finished Analysis.")




