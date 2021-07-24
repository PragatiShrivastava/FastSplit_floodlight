/*
   Raw socket implementation for mirroring hub.
  Pragati Shrivastava - Indian Institute of Technology, Hyderabad. 
 */
#include<stdio.h> //for printf
#include<unistd.h> //for read/write 
#include<string.h> //memset
#include<sys/socket.h>    //for socket ofcourse
#include<sys/ioctl.h>    //for ifreq 
#include<stdlib.h> //for exit(0);
#include<errno.h> //For errno - the error number
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<net/if.h>    //Provides declarations for ifreq
#include<net/ethernet.h>    //Provides declarations for ETH_P_ALL 
#include<linux/if_packet.h>    //Provides declarations for ETH_P_ALL 
#include<pthread.h>    //Provides declarations for ifreq
#include<fcntl.h>    // non blocking socket
#include<pthread.h>    // multithreading

int s_a, s_b;

struct args {
	int read_port;
	int write_port;
};

void *runner(void *params){
	struct args *func_args = (struct args *) params;
	int s_a = func_args->read_port, s_b = func_args->write_port;
	int len=0;
	unsigned char *buf = (unsigned char *) malloc(65536);
	struct sockaddr saddr;
	int saddr_len = sizeof (saddr);

	printf("Going to start listening loop. Bind, listen, .. successful. \n");

	while(1){
		memset(buf,0,65536);
		// if(len = read(s_a, buf, sizeof(buf)) && printf("%d\n", len)  && len > 0){
		if((len = recvfrom(s_a, buf, 65536,0,&saddr,(socklen_t *)&saddr_len)) && len >= 0){
			printf("\nReceived packet from %d  of length %d\n", s_a, len);
			struct ethhdr *eth = (struct ethhdr *)(buf);
			printf("Size of ethhdr: %d\n", sizeof(struct ethhdr));
			printf("\nEthernet Header\n");
			printf("\t|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
			printf("\t|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
			printf("\t|-Protocol : %d\n",eth->h_proto);
			if (sendto(s_b, buf, len, 0, NULL, 0) < 0 ) {
				printf("Write failed\n");
                                perror("sendto");
			}
		}                
               else {
                       int len = recvfrom(s_a, buf, 65536,0,&saddr,(socklen_t *)&saddr_len);
                       printf("Value of ssize_t : %d\n", len);
                       perror("recvfrom");
                     }
             
	}
}

int main (void)
{
	//Create a raw socket
	s_a = socket (PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	//fcntl(s_a, F_SETFL, O_NONBLOCK);
	s_b = socket (PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	//fcntl(s_b, F_SETFL, O_NONBLOCK);

	if(s_a == -1 || s_b == -1)
	{
		//socket creation failed, may be because of non-root privileges
		perror("Failed to create socket");
		exit(1);
	}

	/******************************************************/
	/* GET the index of corresponding NIC name */
	struct ifreq ifreq_obj_a;
	memset(&ifreq_obj_a, 0, sizeof(struct ifreq));
	strncpy(ifreq_obj_a.ifr_name, "eth1",  //mal_host_port
			sizeof(ifreq_obj_a.ifr_name) - 1);
	if(ioctl(s_a, SIOCGIFINDEX, &ifreq_obj_a) < 0) {
		perror("ioctl");
		close(s_a);
		return(-1);
	}

	struct sockaddr_ll sa;
	sa.sll_family = PF_PACKET;
	sa.sll_protocol = htons(ETH_P_ALL);
	sa.sll_ifindex = ifreq_obj_a.ifr_ifindex;
	/* Reflecting the property to the raw socket */
	if(bind(s_a, (struct sockaddr *) &sa, sizeof(sa)) < 0)
	{
		perror("bind");
		close(s_a);
		return(-1);
	}

	ifreq_obj_a.ifr_flags = ifreq_obj_a.ifr_flags|IFF_PROMISC;
	if(ioctl(s_a, SIOCSIFFLAGS, &ifreq_obj_a) < 0) {
		perror("ioctl");
		close(s_a);
		return(-1);
	}

	// ifreq_obj_a.ifr_mtu = 2000;
	if(ioctl(s_a, SIOCSIFMTU, &ifreq_obj_a) < 0) {
		perror("ioctl");
		close(s_a);
		return(-1);
	}

	printf("[mal_host_port] s_a is: %d \n", s_a);

	/******************************************************/
	/* GET the index of corresponding NIC name */
	struct ifreq ifreq_obj_b;
	memset(&ifreq_obj_b, 0, sizeof(struct ifreq));
	strncpy(ifreq_obj_b.ifr_name, "eth2",  //mal_host_out
			sizeof(ifreq_obj_b.ifr_name) - 1);
	if(ioctl(s_b, SIOCGIFINDEX, &ifreq_obj_b) < 0) {
		perror("ioctl");
		close(s_b);
		return(-1);
	}

	struct sockaddr_ll sb;
	sb.sll_family = PF_PACKET;
	sb.sll_protocol = htons(ETH_P_ALL);
	sb.sll_ifindex = ifreq_obj_b.ifr_ifindex;
	/* Reflecting the property to the raw socket */
	if(bind(s_b, (struct sockaddr *) &sb, sizeof(sb)) < 0)
	{
		perror("bind");
		close(s_b);
		return(-1);
	}

	ifreq_obj_b.ifr_flags = ifreq_obj_b.ifr_flags|IFF_PROMISC;
	if(ioctl(s_b, SIOCSIFFLAGS, &ifreq_obj_b) < 0) {
		perror("ioctl");
		close(s_b);
		return(-1);
	}

	// ifreq_obj_b.ifr_mtu = 2000;
	if(ioctl(s_b, SIOCSIFMTU, &ifreq_obj_b) < 0) {
		perror("ioctl");
		close(s_b);
		return(-1);
	}

	printf("[my_bridge_1] s_b is: %d \n", s_b);

	/******************************************************/
	/************   Two sockets in PROMISC mode ***********/
	/******************************************************/

	pthread_t threads[2];
	struct args threadArgs[2];
	threadArgs[0].read_port = s_a;
	threadArgs[0].write_port = s_b;
	threadArgs[1].read_port = s_b;
	threadArgs[1].write_port = s_a;
        
        int i2;
	for (i2=0; i2<2; i2++){
		pthread_create(&threads[i2], NULL, &runner, &threadArgs[i2]);
	}
        
        int i1;
	for (i1=0; i1<2; i1++){
		pthread_join(threads[i1], NULL);
	}

	return 0;

}

