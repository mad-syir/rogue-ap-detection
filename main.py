import subprocess
import re
import sys

# str = unicode(str, errors='replace')

#make tracert subprocess
def scan_wifi_networks():
    try:
        print("Scanning for Wi-Fi networks...")
        if sys.platform.startswith('win'):
            result = subprocess.check_output(['netsh', 'wlan', 'show', 'network', 'mode=Bssid'])
        else:
            print("Not Windows")
            return
            
        return result.decode('utf-8', errors='ignore')
    except subprocess.CalledProcessError as e:
        print(f"Error: Unable to scan Wi-Fi networks. {e}")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

def analyze_network(ssid, encryption_type):
    try:
        print(f"Analyzing security for network:{ssid}")
        if encryption_type.lower() in ['wep', 'wpa', 'tkip']:
            print("Weak encryption detected")
            print("Try WPA2 or WPA3")
        else:
            print("Security ok")
    except Exception as e:
        print(f"Error: {e}")

def trace_gateway():
    gateway_ips = set()
    try:
        with open('GatewayData.txt', 'r') as gateway_file:
            for line in gateway_file:
                match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                if match:
                    gateway_ips.add(match.group())
    except FileNotFoundError:
        print("GatewayData.txt file not found.")
        return

    print(f"Gateway IPs: {gateway_ips}")
    #now to scan the database
    try:
        print("Traceroute...")
        if sys.platform.startswith('win'): #tracert -h 4 google.com
            result = subprocess.check_output(['tracert', '-h', '2', '-4', 'google.com'])
            result = result.decode('utf-8', errors='ignore')
        else:
            print("Not Windows")
            return
    except subprocess.CalledProcessError as e:
        print(f"Error: Unable to execute tracerout: {e}")
        return None
    
    all_tracert_ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', result)
    traceroute_ips = all_tracert_ips[1:] #ignore the first ip in traceroute aka destination address
    print(f"Extracted Traceroute IPs (in hop order): {traceroute_ips}\n") #debugging

    traceroute_ips_set = set(traceroute_ips)

    # print(f"Traceroute IPs: {traceroute_ips_set}")

    if gateway_ips.issubset(traceroute_ips_set):
        print("All Gateway IPs are present in the traceroute result.")
        return
    else:
        missing_ips = gateway_ips - traceroute_ips_set
        print(f"The following Gateway IPs are missing: {missing_ips}\nDisconnecting...")
        disconnect_wifi()
        return

def data_list():
    with open('WiFiData.txt', 'r') as testfile:
        content = testfile.read()
    
    file_ssid = re.search(r'SSID\s*:\s*(.+)', content)
    wifi_name = file_ssid.group(1).strip()
    print(f'Wifi name: {wifi_name}')

    mac_list = re.findall(r'([0-9a-fA-F:]{17})', content)
    if mac_list:
        print("List of MAC address... ")
        for mac in mac_list:
            print(f"Checking MAC: {mac}")#debug            
    else:
        print("no mac address found in the file") #debug
    return

def disconnect_wifi():
    try:
        result = subprocess.run(['netsh', 'wlan', 'disconnect'], text=True, capture_output=True, check=True)

        # Print the output for debugging purposes
        # print("Command Output:")
        # print(result.stdout)
        
        print("Successfully disconnected from Wi-Fi.")
        
    except subprocess.CalledProcessError as e:
        # Handle errors in command execution
        print(f"Error executing command: {e}")
        print(f"Command Output: {e.output}")
    except Exception as e:
        # Handle any other unexpected errors
        print(f"An unexpected error occurred: {e}")
    return

def main():
    wifi_scan_result = scan_wifi_networks()
    if wifi_scan_result:
        print("\nWi-Fi scan result:")
        print(wifi_scan_result)
        networks = re.findall(r'SSID\s\d+\s:(.+)', wifi_scan_result)
        
        for ssid in networks:
            print(f"\nSSID: {ssid}")
            encryption_match = re.search(r'Encryption\s*:\s(.+)', wifi_scan_result)
            bssid_match = re.search(r'BSSID 1\s*:\s*([0-9a-fA-F:]{17})', wifi_scan_result)
            signal_match = re.search(r'Signal\s*:\s*(\d+)', wifi_scan_result)

            if encryption_match:
                encryption_type = encryption_match.group(1).strip()
                print(f"Encryption Type: {encryption_type}")
                analyze_network(ssid, encryption_type)
            else:
                print("Error: Unable to retrieve encryption type.")
            #finding the MAC address of the Wi-Fi
            if bssid_match:
                bssid_mac_address = bssid_match.group(1)
                print(f'BSSID MAC Address: {bssid_mac_address}')
            else:
                print("BSSID MAC Address not found.")
            #calculating the percentages into radio signals
            if signal_match:
                signal_percentage = int(signal_match.group(1))

                signal_dbm = (signal_percentage / 2) - 100
                print(f'Signal Strength: {signal_percentage}%')
                print(f'Approximate Signal Strength in dBm: {signal_dbm} dBm')
            else:
                print("Signal strength not found.")
        
        first_ssid_match = re.search(r'SSID\s1\s*:\s*(.+)', wifi_scan_result)
        first_bssid_match = re.search(r'BSSID\s1\s*:\s*([\w:]+)', wifi_scan_result)
        if first_ssid_match and first_bssid_match:
            first_ssid = first_ssid_match.group(1).strip()
            first_bssid = first_bssid_match.group(1).strip()
            print(f"\nConnected to Network: {first_ssid}")
            print(f"Mac address: {first_bssid}")
        #since the connection is from the first scanned we just compare to the one we connnected

            print("\nComparing with the database...\n")
            bssid_network_first = re.search(r"BSSID\s*1\s*:\s*([\w:]+)", first_ssid)

            with open(r'WiFiData.txt', 'r') as wifi_data:
                content = wifi_data.read()
                file_ssid_match = re.search(r'SSID\s*:\s*(.+)', content)
                mac_list = re.findall(r'([0-9a-fA-F:]{17})', content)

                if file_ssid_match:
                    file_ssid = file_ssid_match.group(1).strip()
                    # file_mac = file_mac_match.group(1).strip()

                    print(f"\nFile SSID: {file_ssid}")
                    # print(f"File MAC Address: {file_mac}")
                    if mac_list:
                        print("Finding matching MAC address... ")
                        for mac in mac_list:
                        # print(f"Checking MAC: {mac}")#debug
                            if mac.lower() == first_bssid.lower():
                                print(f'Same address detected: {mac}')
                                break
                    else:
                        print("No match found")

                    if first_ssid.lower() == file_ssid.lower() and first_bssid.lower() == mac.lower():
                        print("\nThe SSID and MAC Address match! (Low chance for rogue connection)")
                        #For 2nd layer security tracert to see whether it is correct gateway
                        trace_gateway()
                        quit = input("Press any key to exit: ")
                    else:
                        print("\nSSID or MAC Address does not match.")
                        # print("Potential rogue address detected\nDisconnect?(Y/N)")
                        answer = input("Potential rogue address detected\nDisconnect?(Y/N)")
                        if answer == 'y' or answer == 'Y':
                            disconnect_wifi()
                            print("disconnected")
                        else:
                            print("You are in a potential risk")
    else:
        #debugging
        print("No Wi-Fi networks found or problems occured during scanning")

if __name__ == "__main__":
   main()
