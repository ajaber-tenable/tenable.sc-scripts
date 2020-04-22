from tenable.sc import TenableSC
from pprint import pprint
import collections
import sys
import logging
import progressbar
from time import sleep
import threading
import itertools    
import os
from getpass import getpass
from datetime import datetime
import logging

#logging.basicConfig(level=logging.DEBUG)

now = datetime.now()
time = now.strftime("%d%m%Y_%H%M")



class bcolors:
    HEADER = '\033[31m'
    OKBLUE = '\033[31m'
    OKGREEN = '\033[31m'
    WARNING = '\033[31m'
    FAIL = '\033[31m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
logging.getLogger("requests").setLevel(logging.CRITICAL)

def run_progress_bar(finished_event):
    chars = itertools.cycle(r'-\|/')
    while not finished_event.is_set():
        sys.stdout.write('\rGenerating the report ' + next(chars))
        sys.stdout.flush()
        finished_event.wait(0.2)
        
# Make sure the query ID is integer
def query_is_integer(query):
  try:
    int(query)
    return True
  except ValueError:
    return False  

#Make sure provided IP is correct
def verify_ip_address(ip_address):
  while True:
    try: 
      sc = TenableSC(ip_address)
      return sc
    except:
      ip_address = input("You have provided wrong Tenable.sc IP address, please provide the correct IP: ")
    else:
      break
  
  
#Make sure username and password is correct
def verify_logins(username, password, sc):
  while True:
    try:
      sc.login(username, password)
      return sc
    except:
      print("Your username and/or password were wrong, please re-enter the credentials\n")
      username = input("Enter your Tenable.sc username : ")
      password = getpass("Enter your Tenable.sc password : ")
    else:
      break
  return
  
# Make sure the query is configured
def verify_query_is_configured(query, sc):
  try:
    configuredQuery = sc.queries.details(query)
    return True
  except:
    return False      

#Make sure the user provided the correct query by displaying the query name
def verify_correct_query_name(query, sc):
  configuredQuery = sc.queries.details(query)
  question = "Is this the name of your query: " + str(configuredQuery['name']) + " , please answer (yes/no) to proceed: "
  answer = input(question)
  if answer.lower() == "no":
    return False
  elif answer.lower() == "yes":
    return True
  else:
    return False
    
#Ask the user to enter the query ID
def get_query():
  query = input("Enter your Tenable.sc query ID, to get the query ID, go to Tenable.sc > Analysis > Queries > pick your query and on the right end of the line choose the drop down and select view, the ID is in the box at the right corner of the screen: ")
  return query

#Make sure the query ID is integer, configured and is correct
def verify_query(query, sc):
  while query_is_integer(query) == False:
    query = input("Query ID must be a number, please enter the correct value: ")
  while verify_query_is_configured(query, sc) == False:
    query = input("The query ID you have entered does not exists, please enter the correct ID: ")
  while verify_correct_query_name(query, sc) == False:
    query = input("Please enter the correct query ID: ")
  return query

#Get the list of available solutions on Tenable.sc
def get_solutions(sc, query):
  solutions = {}
  remediationList = {}
  remediationSummary = {}
  i = 1
  for vuln in sc.analysis.vulns(query_id=query, tool='sumremediation', source="cumulative"):
    solutions[i] = vuln['solution']
    remediationList[i] = vuln['remediationList'].split(",")
    remediationSummary_list = (vuln['solution'].strip(), vuln['total'].strip().replace("'", ""), vuln['scorePctg'].strip().strip("'"), vuln['hostTotal'].strip().strip("'"), vuln['cveTotal'].strip().strip("'"), vuln['vprScore'].strip().strip("'"))
    remediationSummary[i] = list(remediationSummary_list)
    i = i +1
  s = open("solutions.txt", "a")
  s.truncate()
  s.write(str(solutions))
  s.close()
  rl = open("remediationList.txt", "a")
  rl.truncate()
  rl.write(str(remediationList))
  rl.close()
  rs = open("remediationSummary.txt", "a")
  rs.truncate()
  rs.write(str(remediationSummary))
  rs.close()
  return remediationList, remediationSummary

#Get vulnerability details
def get_vulnDetails(sc, query):
  vulnDetails = {}
  vulnPluginToIP = {}
  vuln = ""
  i = 1
  for vuln in sc.analysis.vulns(query_id=query):
    vulnDetails_list = (vuln['dnsName'].strip(), vuln['netbiosName'].strip(), vuln['macAddress'].strip(), vuln['pluginID'].strip(),  vuln['pluginName'].strip(), vuln['pluginInfo'].strip(), vuln['pluginText'].strip(), vuln['synopsis'].strip(), vuln['seeAlso'].strip().replace(","," & "), vuln['cve'].strip().replace(","," & "))
    vulnDetails[vuln['ip']] = list(vulnDetails_list)
    if vuln['pluginID'] in vulnPluginToIP:
      vulnPluginToIP[vuln['pluginID']].append(vuln['ip'])
    else: 
      vulnPluginToIP[vuln['pluginID']] = [vuln['ip']]
      vd = open("vulnDetails.txt", "a")
  vd.truncate()
  vd.write(str(vulnDetails))
  vd.close()
  return vulnDetails, vulnPluginToIP

#Map IPs to solutions
def map_ip_solutions(remediationList, vulnPluginToIP, unique_or_all):
  if unique_or_all.lower() == "all":
    solutionsListIPs = {}
    slip= open("slip.txt", "a")
    slip.truncate()
    temp_list = list(remediationList)
    solutionToIP = {}
    for item in temp_list:
      solutionToIP[item] = []
      for x in remediationList[item]:
        text= str(item)+ "," + str(vulnPluginToIP.get(x)) + "\n"  
        if vulnPluginToIP.get(x) is None:
          pass        
        else:
          slip.write(text)
          solutionToIP[item].extend(vulnPluginToIP.get(x))
    slip.close()
  elif unique_or_all.lower() == "ip":
    solutionsListIPs = {}
    slip= open("slip.txt", "a")
    slip.truncate()
    temp_list = list(remediationList)
    solutionToIP = {}
    for item in temp_list:
      solutionToIP[item] = []
      for x in remediationList[item]:
        text= str(item)+ "," + str(vulnPluginToIP.get(x)) + "\n"  
        if vulnPluginToIP.get(x) is None:
          pass        
        else:
          slip.write(text)
          solutionToIP[item].extend(vulnPluginToIP.get(x))
          solutionToIP[item] = list(dict.fromkeys(solutionToIP[item]))
    slip.close()
  return solutionToIP

#Get final remediation summary list
def get_final_remediation_summary(remediationSummary, solutionToIP, vulnDetails, unique_or_all, username):
  frs_name = username + "_" + time + "_finalRemediationSummary_" +  str(unique_or_all) + ".csv"
  frs = open(str(frs_name), "a")
  vulnDetails_str = ""
  sort = list({k: v for k, v in sorted(remediationSummary.items(), key=lambda item: int(float(item[1][2].strip("%").strip("<")) * 100), reverse=True)})
  for item in sort:
    solution_header = "Solution, Total number of vulnerabilities, Risk Reduction, Hosts Affected, CVEs, Highest VPR Score\r"
    frs.write(solution_header)
    frs.write(str(remediationSummary[item]).strip("[").strip("]"))
    details_header = "\rIP Address, DNS Name, netbios Name, MAC Address, plugin ID, plugin Name, plugin Info, plugin Output, Synopsis, Vendor and Download Links, CVEs\r"
    frs.write(details_header)
    for x in solutionToIP[item]: 
      line = str(x) + "," + str(vulnDetails[x]).strip("[").strip("]") + "\n"
      frs.write(str(line))
  frs.close()
  return frs_name
 
#Print solutions and remediation stats:
def get_solutions_stats(solutionToIP, remediationList, vulnPluginToIP):   
# This will remove duplication in IPs put will hide some vulnerabilities
  print ("\r")
  solutionToIPStats = {}
  temp_list = list(remediationList)
  for item in temp_list:
    solutionToIPStats[item] = []
    for x in remediationList[item]:
      text= str(item)+ "," + str(vulnPluginToIP.get(x)) + "\n"  
      if vulnPluginToIP.get(x) is None:
        pass        
      else:
        solutionToIPStats[item].extend(vulnPluginToIP.get(x))
    solutionToIPStats[item] = list(dict.fromkeys(solutionToIPStats[item]))
  number_of_keys = list(solutionToIPStats.keys())
  print (bcolors.WARNING + "The query you have selected resulted in: ", len(number_of_keys), " solutions" + bcolors.ENDC)
  count = 0
  for x in solutionToIPStats: 
    if isinstance(solutionToIPStats[x], list): 
      count += len(solutionToIPStats[x]) 
  print(bcolors.WARNING + "The query you have selected resulted in: ", count, " unique impacted IPs" + bcolors.ENDC) 
  count = 0
  for x in solutionToIP: 
    if isinstance(solutionToIP[x], list): 
      count += len(solutionToIP[x]) 
  print(bcolors.WARNING + "The query you have selected resulted in: ", count, " unique vulnerabilities" + bcolors.ENDC)


def main():
  try: 
    os.remove("finalRemediationSummary.csv")
    os.remove("slip.txt")
    os.remove("vulnDetails.txt")
    os.remove("remediationList.txt")
    os.remove("remediationSummary.txt")
    os.remove("solutions.txt")
  except:
    pass 
  ip_address = input("Enter your Tenable.sc IP : ")
  username = input("Enter your Tenable.sc username : ")
  password = getpass("Enter your Tenable.sc password : ")
  query = get_query()
  sc = verify_ip_address(ip_address)
  sc = verify_logins(username,password, sc)
  query = verify_query(query, sc)
  finished_event = threading.Event()
  progress_bar_thread = threading.Thread(target=run_progress_bar, args=(finished_event,))
  progress_bar_thread.start()
  remediationList, remediationSummary = get_solutions(sc, query)
  vulnDetails, vulnPluginToIP = get_vulnDetails(sc, query)
  finished_event.set()
  progress_bar_thread.join()
  unique_or_all = input("\rDo you like to generate the report on unique IPs or all vulnerabilities (IP/ALL)?: ")
  while ((unique_or_all.lower() != "ip") and (unique_or_all.lower() != "all")):
    unique_or_all = input("Please choose IP or ALL: ")
  solutionToIP = map_ip_solutions(remediationList, vulnPluginToIP, unique_or_all)
  file_name = get_final_remediation_summary(remediationSummary, solutionToIP, vulnDetails, unique_or_all, username)
  get_solutions_stats(solutionToIP, remediationList, vulnPluginToIP)
  print ("Report filename: " + str(file_name) + "\r")

if __name__ == "__main__":
  try:
    main()
  except KeyboardInterrupt:
    print("\r")
    sys.exit()