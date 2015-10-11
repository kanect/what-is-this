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
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (len < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(packet);
  
  if(ethtype == ethertype_ip)/*IP packet*/
  {
    fprintf(stderr, "YOU GOT A IP PACKET\n");
    print_hdrs(packet, len);
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
            
            memcpy(new_arp_header->ar_sha, target_interface->addr, sizeof(unsigned char) * ETHER_ADDR_LEN);
            memcpy(new_arp_header->ar_tha, arp_header->ar_sha, sizeof(unsigned char) * ETHER_ADDR_LEN);
            new_arp_header->ar_tip = arp_header->ar_sip;
            new_arp_header->ar_sip = arp_header->ar_tip;
            /*Makes arp header end*/
            
            /*Makes reply end*/

            /*Sends packet*/
            sr_send_packet(sr, buffer, length, interface);
            print_hdrs(buffer, length);
            free(buffer);
        }
    }
    else if (arp_op== arp_op_reply)
    {
        fprintf(stderr, "ARP response recieved.\n");
    }
    else
    {
        fprintf(stderr, "Unsupported ARP op.\n");
    }
    return;
}



