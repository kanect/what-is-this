/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>



#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#include <stdlib.h>
#include <string.h>



/* Forward delcaration*/
void sr_handle_ip();
int longest_prefix_len();
struct sr_rt* sr_lpm();
/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  sr_ethernet_hdr_t *header;
  header = malloc(sizeof(sr_ethernet_hdr_t));
  if (header != NULL) 
  {
	memcpy(header, packet, sizeof(sr_ethernet_hdr_t));	
  }
  
 
 
  /* Ethernet */

  /*TODO: checksum*/
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (len < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(packet);
  
  if(ethtype == ethertype_ip)/*IP packet*/
  {
    fprintf(stderr, "YOU GOT A IP PACKET\n");
    /*print_hdrs(packet, len);*/
  sr_handle_ip(sr, packet, packet + sizeof(sr_ethernet_hdr_t), len, interface);

}
  else if (ethtype == ethertype_arp) /*ARP packet*/
  {
    fprintf(stderr, "ARP packet recieved\n");
    sr_handle_arp(sr, packet, packet + sizeof(sr_ethernet_hdr_t), interface);
  }

  		
  
}/* end sr_ForwardPacket */


/*Make a standard arp header
*With information:
*Hardware type, protocol type, hardware/protocol address length
*
*And the given arguement opcode.
*/
void make_arp_header(uint8_t* buffer, unsigned short op)
{
    sr_arp_hdr_t *arp_header = (sr_arp_hdr_t*) buffer;
    arp_header->ar_hrd = htons(arp_hrd_ethernet);
    arp_header->ar_pro = htons(ethertype_ip);
    arp_header->ar_hln = ETHER_ADDR_LEN;
    arp_header->ar_pln = IP_ADDR_LEN;
    arp_header->ar_op = htons(op);
    return;
}


/*Makes a ethernet header 
*Requires target and source machines address and ethertype, and a allocated space for it.
*/
void make_ethernet_header(uint8_t* buffer, uint8_t* source, uint8_t* target, uint16_t type)
{
    sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t*) buffer;
    memcpy(ether_hdr->ether_dhost, target, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(ether_hdr->ether_shost, source, sizeof(uint8_t) * ETHER_ADDR_LEN);
    ether_hdr->ether_type = type;
    return;
}

void make_icmp_header(uint8_t* buffer, uint8_t type, uint8_t code, uint8_t data[ICMP_DATA_SIZE])
{
    if (type == 0)
    {
	/*Create echo reply*/
	sr_icmp_t0_hdr_t *icmp_hdr = (sr_icmp_t0_hdr_t*) buffer;
	icmp_hdr->icmp_type = type;
	icmp_hdr->icmp_code = code;
        icmp_hdr->icmp_id = 0;
	icmp_hdr->icmp_seq_num = 0;
	/*Set checksum to 0, recalculate and reset.*/
	icmp_hdr->icmp_sum = 0;
	icmp_hdr->icmp_sum = cksum(icmp_hdr,sizeof(uint8_t) * ICMP_DATA_SIZE);
    }
    if (type == 3)
    {
	sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t*) buffer;
	icmp_hdr->icmp_type = type;
	icmp_hdr->icmp_code = code;
	icmp_hdr->icmp_unused = 0;
	icmp_hdr->icmp_mtu = 0;
	memcpy(icmp_hdr->icmp_data,data,sizeof(uint8_t) * ICMP_DATA_SIZE);
	/*Set checksum to 0, recalculate and reset.*/
	icmp_hdr->icmp_sum = 0;
	icmp_hdr->icmp_sum = cksum(icmp_hdr,36);
    }
    if (type == 11)
    {
	sr_icmp_t11_hdr_t *icmp_hdr = (sr_icmp_t11_hdr_t*) buffer;
	icmp_hdr->icmp_type = type;
	icmp_hdr->icmp_code = code;
	icmp_hdr->icmp_unused = 0;
	memcpy(icmp_hdr->icmp_data,data,sizeof(uint8_t) * ICMP_DATA_SIZE);

	/*Set checksum to 0, recalculate and reset.*/
	icmp_hdr->icmp_sum = 0;
	icmp_hdr->icmp_sum = cksum(icmp_hdr,36);
    }
}

/*Handles recived ARP packet*/
void sr_handle_arp(struct sr_instance* sr,
        uint8_t *ethernet_hdr_bits,
        uint8_t *arp_hdr_bits,
        char* interface/* lent */)
{
    sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *)arp_hdr_bits;
    sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)ethernet_hdr_bits;
    unsigned short arp_op = ntohs(arp_header->ar_op);
    if (arp_op == arp_op_request)
    {
        fprintf(stderr, "ARP request recieved.\n");
        
        /*Check if this targets IP is the routers address, if not drop the packet e.g. do nothing*/
        /*print_addr_ip_int(ntohl(arp_header->ar_tip));*/
        struct sr_if *target_interface = (struct sr_if*)sr_get_interface_with_ip(sr, arp_header->ar_tip);
        
        if(target_interface != 0){
            /*This arp packet is for us*/
            int length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
            uint8_t *buffer = malloc(length);
            if(buffer == NULL)
            {
                /*Malloc failed*/
                fprintf(stderr, "Malloc for making arp packet failed.\n");
            }
            
            /*Makes reply start*/

            /*Makes ether header start*/
            /*Flips the ethernet address fields*/
            sr_ethernet_hdr_t *new_ether_header = (sr_ethernet_hdr_t*) buffer;
            
            memcpy(new_ether_header->ether_dhost, ethernet_header->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN); 
            memcpy(new_ether_header->ether_shost, target_interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN); 
            
            /*Copies over ether type */
            /*memcpy(new_ether_header->ether_type, ethernet_header->ether_type, sizeof(uint16_t));    */
            new_ether_header->ether_type = ethernet_header->ether_type;
            /*Makes ether header end*/


            /*Makes arp header start*/
            sr_arp_hdr_t *new_arp_header = (sr_arp_hdr_t*) (buffer + sizeof(sr_ethernet_hdr_t));
            make_arp_header(buffer + sizeof(sr_ethernet_hdr_t), arp_op_reply);
            

            /*Flips source and target IP and hardware address*/
            
            /*Regardless we reply the machine address of the packet receiving interface */
            struct sr_if *real_interface  = sr_get_interface(sr, interface);
            
            memcpy(new_arp_header->ar_sha, real_interface->addr, sizeof(unsigned char) * ETHER_ADDR_LEN);
            memcpy(new_arp_header->ar_tha, arp_header->ar_sha, sizeof(unsigned char) * ETHER_ADDR_LEN);
            new_arp_header->ar_tip = arp_header->ar_sip;
            new_arp_header->ar_sip = arp_header->ar_tip;
            /*Makes arp header end*/
            
            /*Makes reply end*/

            /*Sends packet*/
            sr_send_packet(sr, buffer, length, interface);
            /*print_hdrs(buffer, length);*/
            free(buffer);       
        }
    }
    else if (arp_op== arp_op_reply)
    {
        fprintf(stderr, "ARP response recieved.\n");
        print_hdrs(ethernet_hdr_bits, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    }
    else
    {
        fprintf(stderr, "Unsupported ARP op.\n");
    }
    return;
}
/*Makes an IP header*/
void sr_make_ip_header(uint8_t * buffer, uint8_t tos, uint16_t len, uint8_t protocol, uint32_t ip_src, uint32_t ip_dst)
{
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*) buffer;
    
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
    ip_hdr->ip_tos = tos;
    ip_hdr->ip_len = htons(len);
    ip_hdr->ip_id = 0;
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 0x63;/*99TTL?*/
    ip_hdr->ip_p = protocol;
    ip_hdr->ip_src = ip_src;
    ip_hdr->ip_dst = ip_dst;
    
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(buffer, 20);
    
    return;
}
/*Handles IP packet*/
void sr_handle_ip(struct sr_instance* sr,
        uint8_t *ethernet_hdr_bits,
        uint8_t *ip_hdr_bits,
        unsigned int len,
        char* interface/* lent */)
{
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*) ip_hdr_bits;
    sr_ethernet_hdr_t* ether_hdr = (sr_ethernet_hdr_t*) ethernet_hdr_bits;
    /*TODO: checksum*/
    /*Before we do stuff, we need to know is the packet for us*/
    if (sr_get_interface_with_ip(sr, ip_hdr->ip_dst) != 0)
    {
        /*This packet is for us*/
        fprintf(stderr, "IP packet for us recieved.\n");
        uint8_t ip_p = ip_protocol(ip_hdr_bits);
        if (ip_p == ip_protocol_icmp)
        {
            /*This is a icmp packet*/
            fprintf(stderr, "ICMP packet to us received\n");
            sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(ip_hdr_bits + sizeof(sr_ip_hdr_t));
            /*TODO: checksum*/            
            if(icmp_echo_request == icmp_hdr->icmp_type)
            {
                /*This is a echo request*/
                /*Makes a reply*/
                uint8_t* buffer = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + (sizeof(sr_icmp_hdr_t) * 2));
                make_ethernet_header(buffer, ether_hdr->ether_dhost, ether_hdr->ether_shost, htons( ethertype_ip));
	
                memcpy(buffer + sizeof(sr_ethernet_hdr_t), ip_hdr_bits, sizeof(sr_ip_hdr_t) + (2 *sizeof(sr_icmp_hdr_t)));
		
                sr_ip_hdr_t* new_ip_header = (sr_ip_hdr_t*) (buffer + sizeof(sr_ethernet_hdr_t));
                sr_ip_hdr_t* old_ip_header = (sr_ip_hdr_t*) ip_hdr_bits;
                new_ip_header->ip_src = old_ip_header->ip_dst;
                new_ip_header->ip_dst = old_ip_header->ip_src;        
                new_ip_header->ip_id = old_ip_header->ip_id;
                new_ip_header->ip_sum = 0;
                new_ip_header->ip_sum = cksum( buffer + sizeof(sr_ethernet_hdr_t), new_ip_header->ip_hl * 4);
	
                sr_icmp_hdr_t* new_icmp_header = (sr_icmp_hdr_t*) (buffer + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                new_icmp_header->icmp_type = 0x0000;
                new_icmp_header->icmp_sum = 0;
                new_icmp_header->icmp_sum = cksum( (void*)new_icmp_header, 8);
                        /*Make ICMP header*/

                sr_send_packet(sr, buffer, len, interface);
                free(buffer);
            }
            
        }
        else if(ip_protocol_udp || ip_protocol_tcp)
        {
            /*Make type 3 icmp port unreachable reply.*/
            uint8_t* buffer = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            
            sr_make_ip_header(buffer + sizeof(sr_ethernet_hdr_t),
                                0x0000, sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t),
                                ip_protocol_icmp, ip_hdr->ip_dst, ip_hdr->ip_src);
                                
            print_hdr_ip(buffer + sizeof(sr_ethernet_hdr_t));
            
        }
    }
    else
    {
        /*This packet is not for us, forward it.*/
        fprintf(stderr, "IP packet not for us recieved.\n");
        /*Check routing table*/
        struct sr_rt* target = sr_lpm(sr->routing_table, ip_hdr->ip_dst);
        if(target == NULL)
        {
            /*NO MATCH*/
            fprintf(stderr, "No match in routing table\n");
            
            /*Make ICMP net unreachable packet*/
        }
        else
        {
            /*Check arp cache*/
            fprintf(stderr, "Matching entry found\n");
            sr_print_routing_entry(target);/*TODO: remove*/
            
            /*Check ARP cache*/
            /*According to comments for sr_arpcache_lookup we need to free the struct returned from it, if not null*/
            struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, target->gw.s_addr);
            if (entry == NULL)
            {
                /*Make arp request to gateway*/
                struct sr_arpreq *arp_request = sr_arpcache_queuereq(&sr->cache, target->gw.s_addr, ethernet_hdr_bits, len, interface);
                if(arp_request == NULL)
                {
                    /*Something is terribly wrong, sr_arpcache_queuereq failed to behave as defined.*/
                    fprintf(stderr, "sr_arpcache_queuereq failed\n");
                    return;
                    
                }
                /*J.W.: I beilive there is nothing to be done at this moment in handle ip after the arp_request has be cached*/
                /*TODO: remove*/
                
            }
            else
            {
                /*Forward Packet*/
                
                free(entry);
            }
        }
    }


    return;
}



/*Routing table lookup
* variables 
*    rt: pointer to routing table
*    dest: pointer the the address we are trying to find the longest prefix match form, in NETWORK ORDER.
*/
struct sr_rt* sr_lpm(struct sr_rt *rt, uint32_t dest_ip)
{
    /*Naive implmentation*/
    
    /*Current longest matching number of bytes*/
    int max_num_match = 0;
    
    /*Record holder routing entry*/
    struct sr_rt *max_routing_entry = NULL;
    
    /*Since the rotuing able stores the ip in network order, we need to convert to host order before we do longest prefix match.*/
    int temp_num = 0;
    do
    {
        rt = rt->next; 
        temp_num = longest_prefix_len(ntohl(rt->dest.s_addr) & rt->mask.s_addr, ntohl(dest_ip));
        if (temp_num > max_num_match)
        {
            max_num_match = temp_num;
            max_routing_entry = rt;
        }
    }while(rt->next);
    
    return max_routing_entry;
}

/* Longest prefix match
* Compares the two in_addr, and return the maximum number of bytes of matching prefixes.
* NOTE: parameters needs to be in host order.
*Returns the number the maximum number of bytes of matching prefixes.
*/
int longest_prefix_len(uint32_t addr1, uint32_t addr2)
{
    
    int max_byte_match = 0;
    
    /*Using xor bit wise operator, so that if addr1[x] and addr2[x] have different bits,
      *xor_product[x] will be one, otherwise, if addr1[x] == addr2[x], xor_product[x] will be 0.
      */
    uint32_t xor_product = addr1 ^ addr2;
    
    /*count the leading zeroes*/
    max_byte_match = __builtin_clz(xor_product);
    return max_byte_match;
}
