import json
import docker
import configparser

config = configparser.ConfigParser()
config.read('config.txt')
home_dir = config['sources']['home_dir']

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


# Converts a .json file into a Python compatible dictionary
# params: json_path: Path to the JSON file.
# returns: data: Python dictionary containing the data from the JSON file.
def json_to_dict(json_path):
    with open(json_path) as json_file:
        data = json.load(json_file)
    return data