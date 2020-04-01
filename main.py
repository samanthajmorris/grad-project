import docker
import multiprocessing
import sslyze
import tldextract
import nmap
import configparser
import pshtt

config = configparser.ConfigParser()
config.read('config.txt')
home_dir = config['sources']['home_dir']

# NOT IMPLEMENTED. Saved for future iteration.
# Runs Nikto in a container and outputs a text file to the home directory containing the Nikto report.
def nikto_function():
    client = docker.from_env()
    result = client.containers.run("sullo/nikto", "-h " + domain, remove=True, tty=True)
    f = open(home_dir + domain + '_nikto_report.txt', 'wb')
    f.write(result)
    print("Nikto Analysis Completed.")


if __name__ == "__main__":

    # Get URL from User
    site = input('What domain would you like to scan?: ')

    # Get registered domain from the url provided by the user
    ext = tldextract.extract(site)
    domain = ext.registered_domain

    p2 = multiprocessing.Process(target=sslyze.run_sslyze, args=(domain,))
    p3 = multiprocessing.Process(target=nmap.run_nmap, args=(domain,))
    p4 = multiprocessing.Process(target=pshtt.run_pshtt, args=(domain,))

    #p1.start()
    p2.start()
    p3.start()
    p4.start()

    #p1.join()
    p2.join()
    p3.join()
    p4.join()

    print("\n\nSCAN COMPLETE\n-------------")

    pshtt_output = pshtt.csv_to_dict(home_dir + '_pshtt_report.csv')
    pshtt.pshtt_analysis(pshtt_output)

    nmap_data = nmap.xml_to_dict(home_dir + 'nmap.xml')
    nmap.nmap_analysis(nmap_data)

    sslyze.sslyze_analysis(sslyze.sslyze_to_dict())





