import xmltodict
import tarfile
import docker
import configparser

config = configparser.ConfigParser()
config.read('config.txt')
home_dir = config['sources']['home_dir']

# Runs Nmap in a container and outputs a text file to the home directory containing the Nmap report.
# params: d: a string which is the domain to scan
# returns: nothing
def run_nmap(d):
    domain = d
    # Set up client and run docker container
    client = docker.from_env()
    container = client.containers.run("instrumentisto/nmap", " -sS " + domain + " -oX /home/nmap.xml", detach=True, tty=True)

    # Grab file from docker container, write to tar file
    f = open(home_dir + '_nmap_report.tar', 'wb')
    flag = 0
    while(flag == 0):
        if(container.status == 'exited'):
            bits, stat = container.get_archive('/home/nmap.xml')
            flag = 1
        else:
            container.reload()
    for chunk in bits:
        f.write(chunk)
    f.close()

    # Extract file from tar
    tar = tarfile.open(home_dir + '_nmap_report.tar')
    tar.extractall(home_dir)
    tar.close()
    print('Nmap Analysis Completed.')

    #Remove container
    container.remove()


# Pulls Nmap scan results and comments on what they mean, making suggestions to the user based on the results
# params: data: Python dictionary containing the results from the Nmap scan
# returns: nothing
def nmap_analysis(data):
    print("\n*  Port Scanning Results:\n-------------")
    ports = data['nmaprun']['host']['ports']['port']
    print('{:<10}{:<20}{:<10}'.format("Port ID", "Service", "State"))
    print('{:<10}{:<20}{:<10}'.format("-------", "-------", "-----"))
    for port in ports:
        portid = port['@portid']
        state = port['state']['@state']
        service = port['service']['@name']
        print('{:<10}{:<20}{:<10}'.format(portid, service, state))


# Converts a .xml file into a Python compatible dictionary
# params: xml_path: Path to the XML file.
# returns: doc: Python dictionary containing the data from the XML file.
def xml_to_dict(xml_path):
    f = open(xml_path, 'r')
    doc = xmltodict.parse(f.read())
    return doc
