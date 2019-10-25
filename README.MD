1. **Testing Conditions**  

  I tested my code using unittest library to test for matching rules of the form    
             -  Valid direction, valid protocol, matching single port, matching single ip    
             - Valid direction, valid protocol, matching port ranges, matching single ip    
             - Valid direction, valid protocol, matching port ranges, matching ip ranges    
             - Valid direction, valid protocol, non-matching port and matching ip    
             - Valid direction, valid protocol, matching port and non matching ip    

   Note: I've not tested for invalidity in the inputs because of the prior assumption that the input is valid as stated in the problem description.
    
2. **Approach** 

  I made use of recursive hashmaps indexed by direction, protocol, "ip" and "port". I stored the port and ip results as a set in the hashmap to avoid duplication and save space. The port set and IP set can be accessed in O(1) time. The searching for valid ports and IPs within the set is done within O(N) (worst case). I encapsulated all operations within the class, which creates the mapper object during initialization. I created a unit test class to run a bunch of tests covering different test conditions.   

  **Complexity Analysis:**
 - Insertion Time Complexity: O(1)  ...assuming no collisions 
 - Search Time Complexity :   O(N) 
 - Space Complexity :         O(N) 
                                      
3. **Optimizations:**

  One optimization I could think of was to use a merged set of port and IP intervals and perform binary search on the valid ranges until something is found. The idea behind this is to condense the range to a set of non-overlapping ranges, which could save a lot of space in cases where there are multiple overlapping ranges being stored independently. Although this makes a tradeoff for better space complexity, it still increases the worst case time complexity to O(nlog(n)) for insertion operations because, to merge intervals we need to sort the interval range. Searching is reduced to O(log(n)) because we can implement a modified version of binary search that is cognizant of the start and end of each element in the list and finds the the range where the query port or IP falls into. 

i.e create mappings of the form   
{  "inbound" : { "udp" : [[merged port list],[merged ip list]],  
                 "tcp" : [[merged port list],[merged ip list]] },   
                 
  "outbound": { "udp" : [[merged port list],[merged ip list]],  
                "tcp :  [[merged_port list],[merged ip list]] } 
                                                  }  

  **Complexity Analysis:**
 - Insertion Time Complexity: O(1)...assuming no collisions
 - Merging time complexity :  Worst case(nlog(n)) as sorting is required.
 - Search time complexity:    O(log(n)) with optimized binary search across valid merged intervals.
 - Overall Time Complexity:   O(nlog(n))+ O(log(n)) ~ O(nlog(n))
 - Space Complexity:          Worst case is O(n)  -> where no intervals overlap
                           Average case is << O(N) as more and more intervals overlap           
                           eg: If the port range is 4000-6000, any value within that range is redundant. 
                               Similarly for IP range of 192.0.0.0 to 192.200.200.200, we can shave off all IPs and IP ranges within this large range


4. I'm interested in the Data team as that is where I feel my experience and interests align. I do enjoy working on data platforms and the description of the work sounds really interesting.
