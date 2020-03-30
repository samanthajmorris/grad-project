import docker
import multiprocessing
import pandas as pd
import xmltodict
import tarfile
import json
import tldextract

#TODO: Change the home_dir variable to the path to the folder that you'd like the output files written to. Note: End with a forward slash
home_dir = '/Users/samanthamorris/beachcomber-output/'

# NOT IMPLEMENTED. Saved for future iteration.
# Runs Nikto in a container and outputs a text file to the home directory containing the Nikto report.
def nikto_function():
    client = docker.from_env()
    result = client.containers.run("sullo/nikto", "-h " + domain, remove=True, tty=True)
    f = open(home_dir + domain + '_nikto_report.txt', 'wb')
    f.write(result)
    print("Nikto Analysis Completed.")

# Runs SSLYZE in a container and outputs a text file to the home directory containing the SSLYZE report. --json_out=-
# params: d: a string which is the domain to scan
# returns: nothing
def run_sslyze(d):
    domain = d
    # Set up client and run docker
    client = docker.from_env()
    result = client.containers.run("nablac0d3/sslyze", "--json_out=- --regular " + domain, remove=True, tty=True)

    # Write results to JSON file.
    f = open(home_dir + 'sslyze_report.json', 'wb')
    f.write(result)
    print("SSLYZE Analysis Completed.")

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


# Converts a .xml file into a Python compatible dictionary
# params: xml_path: Path to the XML file.
# returns: doc: Python dictionary containing the data from the XML file.
def xml_to_dict(xml_path):
    f = open(xml_path, 'r')
    doc = xmltodict.parse(f.read())
    return doc


# Converts a .json file into a Python compatible dictionary
# params: json_path: Path to the JSON file.
# returns: data: Python dictionary containing the data from the JSON file.
def json_to_dict(json_path):
    with open(json_path) as json_file:
        data = json.load(json_file)
    return data

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

# SSLYZE has an bug which makes it sometimes not include the closing curly bracket of its JSON report. This function
# checks for the bracket and if it is not there, it adds it, then it converts the file to JSON
# returns: Python dictionary containing the SSLYZE data.
def sslyze_to_dict():
    max_tries = 1
    try:
        output = json_to_dict(home_dir + 'sslyze_report.json')
    except json.decoder.JSONDecodeError:
        if (max_tries > 0):
            f = open(home_dir + 'sslyze_report.json', "a")
            f.write("}")
            f.close()
            output = json_to_dict(home_dir + 'sslyze_report.json')
            max_tries = max_tries - 1
        else:
            print("Error with SSLYZE JSON File. Unable to parse results.")
            return None
    except:
        print("Error with SSLYZE JSON File. Unable to parse results.")
        return None
    return output

# Pulls SSLYZE scan results and comments on what they mean, making suggestions to the user based on the results
# params: data: Python dictionary containing the results from the SSLYZE scan
# returns: nothing
def sslyze_analysis(data):
    print("\n*  SSL/TLS Configuration Scan Results:\n-------------")
    compression = (data.get('accepted_targets')[0]).get('commands_results').get('compression').get('compression_name')
    fallback = (data.get('accepted_targets')[0]).get('commands_results').get('fallback').get('supports_fallback_scsv')
    heartbleed = (data.get('accepted_targets')[0]).get('commands_results').get('heartbleed').get('is_vulnerable_to_heartbleed')
    openssl_ccs = (data.get('accepted_targets')[0]).get('commands_results').get('openssl_ccs').get('is_vulnerable_to_ccs_injection')
    reneg = (data.get('accepted_targets')[0]).get('commands_results').get('reneg')
    robot = (data.get('accepted_targets')[0]).get('commands_results').get('robot').get('robot_result_enum')
    sslv2 = (data.get('accepted_targets')[0]).get('commands_results').get('sslv2').get('accepted_cipher_list')
    sslv3 = (data.get('accepted_targets')[0]).get('commands_results').get('sslv2').get('accepted_cipher_list')
    tlsv1 = (data.get('accepted_targets')[0]).get('commands_results').get('tlsv1').get('accepted_cipher_list')
    tlsv1_1 = (data.get('accepted_targets')[0]).get('commands_results').get('tlsv1_1').get('accepted_cipher_list')
    tlsv1_2 = (data.get('accepted_targets')[0]).get('commands_results').get('tlsv1_2').get('accepted_cipher_list')
    tlsv1_3 = (data.get('accepted_targets')[0]).get('commands_results').get('tlsv1_2').get('accepted_cipher_list')

    print("")
    if (compression != None):
        print('WARNING: Vulnerable to CRIME attack against HTTP compression- Please disable compression algorithms')
    else:
        print('OK - Compression Diabled')

    if (fallback != True):
        print("WARNING: Vulnerable to fallback to a lesser protocol- Please add support for Fallback TLS Signaling Cipher Suite Value")
    else:
        print("OK - Supports Fallback SCSV")

    if (heartbleed != False):
        print("WARNING: Vulnerable to Heartbleed attack- Please upgrade to the latest version of OpenSSL")
    else:
        print("OK - Not vulnerable to Heartbleed")

    if(openssl_ccs != False):
        print("WARNING: Vulnerable to CCS Injection - Please upgrade to the latest version of OpenSSL")
    else:
        print("OK - Not vulnerable to CCS Injection")

    if(robot != 'NOT_VULNERABLE_RSA_NOT_SUPPORTED'):
        print("WARNING: Vulnerable to ROBOT Attack - Please disable support for RSA Cipher Suites")
    else:
        print("OK -  Not vulnerable, RSA cipher suites not supported")

    try:
        if(reneg['accepts_client_renegotiation'] != False):
            print("WARNING: Allowing renegociation makes your site vulnerable to Man-in-the-middle and DDOS Attacks - Please Disable SSL renegociation")
        elif(reneg['supports_secure_renegotiation'] == True):
            print("OK - Only Secure Renegociation suppoted.")
        else:
            print("OK: Renegociation not supported.")
    except KeyError:
        print("WARNING: Test for renegociation timed out. Could be vulnerable.")


    if(sslv2 != []):
        print("WARNING: SSLV2 is vulnerable and outdated - Please disable SSLV2 traffic.")
    else:
        print("OK - Server rejected all SSLV2 cipher suites.")

    if(sslv3 != []):
        print("WARNING: SSLV3 is vulnerable and outdated - Please disable SSLV3 traffic.")
    else:
        print("OK - Server rejected all SSLV3 cipher suites.")

    if(tlsv1 != []):
        print("WARNING: TLSV1 is vulnerable and outdated - Please disable TLSV1 traffic.")
        print('{:<5}{:<30}'.format('', 'TLSV1 Accpeted Ciphers:'))
        for item in tlsv1:
            print('{:<10}{:<40}{:<5}bits'.format('', item['openssl_name'], item['key_size']))
    else:
        print("OK - Server rejected all TLSV1 cipher suites.")

    if (tlsv1_1 != []):
        print('{:<5}{:<30}'.format('', 'TLSV1.1 Accpeted Ciphers:'))
        for item in tlsv1_1:
            print('{:<10}{:<40}{:<5}bits'.format('', item['openssl_name'], item['key_size']))
    else:
        print("Server Rejected all TLSV1.1 Cipher Suites")

    if (tlsv1_2 != []):
        print('{:<5}{:<30}'.format('', 'TLSV1.2 Accpeted Ciphers:'))
        for item in tlsv1_2:
            print('{:<10}{:<40}{:<5}bits'.format('', item['openssl_name'], item['key_size']))
    else:
        print("Server Rejected all TLSV1.2 Cipher Suites")

    if (tlsv1_3 != []):
        print('{:<5}{:<30}'.format('', 'TLSV1.3 Accpeted Ciphers:'))
        for item in tlsv1_3:
            print('{:<10}{:<40}{:<5}bits'.format('', item['openssl_name'], item['key_size']))
    else:
        print("Server Rejected all TLSV1.3 Cipher Suites")

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


if __name__ == "__main__":
    # Warning: Nikto takes ~10 minutes to run, so will be implemented in a future iteration.
    #p1 = multiprocessing.Process(target=nikto_function)

    # Get URL from User
    site = input('What domain would you like to scan?: ')

    # Get registered domain from the url provided by the user
    ext = tldextract.extract(site)
    domain = ext.registered_domain

    p2 = multiprocessing.Process(target=run_sslyze, args=(domain,))
    p3 = multiprocessing.Process(target=run_nmap, args=(domain,))
    p4 = multiprocessing.Process(target=run_pshtt, args=(domain,))

    #p1.start()
    p2.start()
    p3.start()
    p4.start()

    #p1.join()
    p2.join()
    p3.join()
    p4.join()

    print("\n\nSCAN COMPLETE\n-------------")

    pshtt_output = csv_to_dict(home_dir + '_pshtt_report.csv')
    pshtt_analysis(pshtt_output)

    nmap_data = xml_to_dict(home_dir + 'nmap.xml')
    nmap_analysis(nmap_data)

    sslyze_analysis(sslyze_to_dict())





