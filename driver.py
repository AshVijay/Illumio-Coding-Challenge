import unittest
import csv

csv_path = "./input/input.csv"

class Firewall():
   rule_map = {"inbound": { "udp": {"ip": set([])  ,
                                    "port": set([]) 
                                    }
                             ,
                             "tcp":{"ip":set([]),
                                     "port":set([])
                                    }                                
                             },
                 "outbound":{"udp":{"ip": set([])  ,
                                    "port": set([]) 
                                   }
                             ,
                            "tcp":{"ip":set([]),
                                     "port":set([])
                                   }             
                            }

                 }
    
   def __init__(self,filePath):
          # reference: reading csvs using csv.reader
          with open(filePath,'r') as file:
                 readCSV = csv.reader(file, delimiter = ",")
                 ln_count = 0
                 for row in readCSV:
                          ln_count+=1
                          if ln_count == 1:
                                  continue
                          if len(row) > 4:
                                  print("Incorrect row format")

                          IP = self.parseIP(row[3].split("-"))
                          ports = self.parsePorts(row[2].split("-")) 
                          self.rule_map[row[0]][row[1]]["port"].add(ports)
                          self.rule_map[row[0]][row[1]]["ip"].add(IP)


   def acceptPacket(self,packet):
    """
    Function that does the final comparison for a rule match
    """
          foundPort=-1
          foundIP = -1
          if packet[0] in self.rule_map.keys():
                   if packet[1] in self.rule_map[packet[0]].keys():
                          for port in self.rule_map[packet[0]][packet[1]]["port"]:
                                    if self.comparePorts(port, int(packet[2])) :
                                            foundPort = 1

                          for  ip in self.rule_map[packet[0]][packet[1]]["ip"]:
                                    if self.compareIPs(ip, packet[3]):
                                            foundIP = 1

          if foundPort ==1 and foundIP ==1:
                               return True
          return False
         
  
   def parseIP(self,ip):  
    """
    Function that returns a range of IPs as a tuple
    """
          if len(ip) == 1 : 
              return (ip[0],ip[0])
            
          else:
          
              return (ip[0],ip[1])
          

   def parsePorts(self,ports):
    """
    Function that returns a range of ports as a tuple
    """
          if len(ports)== 1:

                 return (int(ports[0]),int(ports[0]))   
          else:  
                 port_low = int(ports[0])
                 port_high = int(ports[1])
                 return (port_low,port_high)
 

   def compareIPs(self,ruleIP, packetIP):
    """
    Function that compares the query IP to a rule( either a single IP or a range of IPs)
    """
                from ipaddress import ip_address

                #reference: documentation of "ipaddress" library
                ip_low = ip_address(ruleIP[0].decode('utf-8','ignore'))
                ip_high = ip_address(ruleIP[1].decode('utf-8','ignore'))
                packetIP =  ip_address(packetIP.decode('utf-8','ignore'))
                if packetIP >= ip_low and packetIP <= ip_high:
                      return True
                return False                                       

   def comparePorts(self,rulePort, packetPort):
    """
    Function that compares the query Port to a rule( either a single Port or a range of Ports)
    """
                if rulePort[0] <= packetPort and rulePort[1]>=packetPort:  
                          return True
                return False


################################################################################################################
### Unit Tests
################################################################################################################
   
class TestCases (unittest.TestCase):
          #Test case for single ports and IPs
          query1 = "inbound,tcp,80,192.168.1.2"

          #Test case for port ranges and single IPs
          query2 = "outbound,tcp,10001,192.168.10.11"

          #Test case for port ranges and IP ranges
          query3 = "inbound,udp,55,192.168.2.5"

          #Test case for absent rules
          query4 =  "inbound,udp,23,192.168.1.1"
          query5 =  "inbound,udp,53,0.168.1.1" 

          obj = Firewall(csv_path)

          def test1(self):
                self.assertEquals(self.obj.acceptPacket(self.query1.split(",")), True)

          def test2(self):
                self.assertEquals(self.obj.acceptPacket(self.query2.split(",")), True) 
          
          def test3(self):
                self.assertEquals(self.obj.acceptPacket(self.query3.split(",")), True)
          
          def test4(self):
                self.assertEquals(self.obj.acceptPacket(self.query4.split(",")), False)
 

          def test5(self):
                self.assertEquals(self.obj.acceptPacket(self.query5.split(",")), False)
           


if __name__ == '__main__':

         unittest.main()
