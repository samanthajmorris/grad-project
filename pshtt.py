import pandas as pd
import docker
import configparser

config = configparser.ConfigParser()
config.read('config.txt')
home_dir = config['sources']['home_dir']

def run_pshtt(d):
    domain = d

    # Set up client and run docker container.
    client = docker.from_env()
    container = client.containers.run("18fgsa/domain-scan", domain + " --scan=pshtt", detach=True, tty=True)

    # Grab file from docker container, write to file
    csvname = home_dir + '_pshtt_report.csv'
    f = open(csvname, 'wb')
    flag = 0
    bits = None
    while(flag == 0):
        if(container.status == 'exited'):
            bits, stat = container.get_archive('/home/scanner/results/pshtt.csv')
            flag = 1
        else:
            container.reload()
    if (bits != None):
        for chunk in bits:
            f.write(chunk)
        f.close()
    else:
        print("Error: Could not complete PSHTT Analysis")
    print('PSHTT Analysis Completed.')

    #Remove container
    container.remove()


# Converts a .csv file into a Python compatible dictionary
# params: csv_path: Path to the CSV file.
# returns: result: Python dictionary containing the data from the CSV file.
def csv_to_dict(csv_path):
    try:
        df = pd.read_csv(csv_path)
        result = df.to_dict(orient='records')
        return result
    except pd.errors.EmptyDataError:
        print("ERROR - PSHTT Analysis could not complete.")


# Pulls PSHTT scan results and comments on what they mean, making suggestions to the user based on the results
# params: data: Python dictionary containing the results from the PSHTT scan
# returns: nothing
def pshtt_analysis(data):
    info = data[0]
    base_domain = info.get("Base Domain")
    print("Domain: " + base_domain)
    print("\n*  HTTPS and HSTS Best Practices Results:\n-------------")
    supports_https = info.get("Domain Supports HTTPS")
    enforces_https = info.get("Domain Enforces HTTPS")
    strong_hsts = info.get("Domain Uses Strong HSTS")

    if (supports_https != True):
        valid_https = info.get("Valid HTTPS")
        if (valid_https != True):
            print("WARNING: Certificate for the hostname may be expired or is invalid.")
        else:
            print("OK- Certificate for hostname is unexpired and valid.")

        downgrades = info.get("Downgrades HTTPS")
        if(downgrades != False):
            print("WARNING: HTTPS is supported, but canonical HTTPS endpoint immediately redirects internally to HTTP.")
        else:
            print("OK - Domain does not downgrade HTTPS")

        bad_hostname = info.get("HTTPS Bad Hostname")
        if (bad_hostname == True):
            print("WARNING: HTTPS endpoint fails hostname validation.")
        else:
            print("OK - HTTPS valid hostname.")

        expired_cert = info.get("HTTPS Expired Cert")
        if (expired_cert == True):
            print("WARNING: One of the HTTPS endpoints has an expired certificate.")
        else:
            print("OK - HTTPS certificates are valid.")

        self_signed = info.get("HTTPS Self Signed Cert")
        if(self_signed == True):
            print("WARNING: Domain has a self-signed certificate, which is not trusted by browsers.")
        else:
            print("OK - Certificate is signed by a certificate authority (CA).")
    else:
        print("OK - Domain Supports all HTTPS best practices.")

    if(enforces_https != True):
        print("WARNING: Domain does not default to HTTPS.")
    else:
        print("OK - Domain defaults to HTTPS.")

    if(strong_hsts != True):
        hsts = info.get("HSTS")
        if (hsts == False):
            print("WARNING: Domain does not support HSTS.")
        else:
            print("OK - Domain supports HSTS.")

        hsts_age = info.get("HSTS Max Age")
        if(hsts_age >= 31536000):
            print("OK - HSTS Max Age very strong.")
        elif (hsts_age >= 10368000):
            print("OK - HSTS Max Age is within guidelines but could be stronger.")
        else:
            print("WARNING: HSTS Max Age too short.")
    else:
        print("OK - Domain supports HSTS best practices.")

