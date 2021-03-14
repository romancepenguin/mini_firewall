//developer JK&JH ><
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/in.h>
#include<netdb.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<sys/socket.h>

#include<arpa/inet.h>
    
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>

#include <netinet/ip_icmp.h>   
#include <sys/time.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include<time.h>

#define MAX_HOPS 30
#define NUMBER_REPETITAION 3
#define TIME_LIMITED 1 

#define ERROR_COUNT_FILE "ErrorLog_Cnt"


#define LOCAL_PORT 9000

//unsigned short cksum_in(unsigned short *, int);

struct pseudohdr {
	unsigned long s_addr;
	unsigned long d_addr;
	char zero;
	unsigned char protocol;
	unsigned short length;
};

char lan_card[10] = "enp0s3";

unsigned short cksum_ina(unsigned short *addr,int len);

char error_content[64];
char padding[50];

int total_length=0;
unsigned long sum=0;
int ip_checksum=0;

typedef struct IP_VALUE{
	int count;
	char ip_addr[100];
	struct IP_VALUE *next;
}IP_VALUE;


main()
{

	FILE *f;

	char *tok; 
	char buf[32];

	char line[163];
	int header_on=1;
	struct tcphdr *rx_tcph;
	struct iphdr *rx_iph;

	rx_tcph=(struct tcphdr *)malloc(sizeof(struct tcphdr));
	rx_iph=(struct iphdr *)malloc(sizeof(struct iphdr));

	f=fopen("sample.txt","r");

	if(f==NULL){
		printf("error open packet file\n");
		exit(-1);
	}
	while(fgets(line,163,f)) 
	{

		if(header_on == 1){

/////*************************************ip_hdr start******************************
			line[strlen(line)]='\0';
			char line_copy[163];
			strcpy(line_copy,line);
			tok=strtok(line_copy,"|");
			for(int i= 0;i<14;i++){
				tok=strtok(NULL,"|");
			}

			int ve_hl = atoi(tok);
			rx_iph->version = ve_hl/10;
			rx_iph->ihl = ve_hl%10;

			memset(buf,'\0',sizeof(buf));
			tok=strtok(NULL,"|");
			strcat(buf,tok);
			rx_iph->tos = strtol(buf,NULL,16);

			memset(buf,'\0',sizeof(buf));
			for(int i=0;i<2;i++){
				tok=strtok(NULL,"|");
				strcat(buf,tok);
			}
			rx_iph->tot_len = htons(strtol(buf,NULL,16));

			memset(buf,'\0',sizeof(buf));
			for(int i=0;i<2;i++){
				tok=strtok(NULL,"|");
				strcat(buf,tok);
			}
			rx_iph->id = htons(strtol(buf,NULL,16));

			memset(buf,'\0',sizeof(buf));
			for(int i=0;i<2;i++){
				tok=strtok(NULL,"|");
				strcat(buf,tok);
			}
			rx_iph->frag_off = htons(strtol(buf,NULL,16));

			memset(buf,'\0',sizeof(buf));
			for(int i=0;i<1;i++){
				tok=strtok(NULL,"|");
				strcat(buf,tok);
			}
			rx_iph->ttl = strtol(buf,NULL,16);

			memset(buf,'\0',sizeof(buf));
			for(int i=0;i<1;i++){
				tok=strtok(NULL,"|");
				strcat(buf,tok);
			}
			rx_iph->protocol = strtol(buf,NULL,16);

			memset(buf,'\0',sizeof(buf));
			for(int i=0;i<2;i++){
				tok=strtok(NULL,"|");
				strcat(buf,tok);
			}
			rx_iph->check = htons(strtol(buf,NULL,16));

			struct in_addr i_addr;
		
			bzero((char *)&i_addr, sizeof(i_addr));
			memset(buf,'\0',sizeof(buf));
			for(int i=0;i<4;i++){
				tok=strtok(NULL,"|");
				strcat(buf,tok);
			}
			i_addr.s_addr = htonl(strtol(buf,NULL,16));
			rx_iph->saddr = inet_addr(inet_ntoa(i_addr));

			bzero((char *)&i_addr, sizeof(i_addr));
			memset(buf,'\0',sizeof(buf));
			for(int i=0;i<4;i++){
				tok=strtok(NULL,"|");
				strcat(buf,tok);
			}
			i_addr.s_addr = htonl(strtol(buf,NULL,16));
			rx_iph->daddr = inet_addr(inet_ntoa(i_addr));

/////******************************************************ip_hdr end***********************


			if(rx_iph->ihl>5){
				int option_length = rx_iph->ihl*4-20;
				memset(buf,'\0',sizeof(buf));
				for(int i=0;i<option_length;i++){
					tok=strtok(NULL,"|");
					strcat(buf,tok);
				}
				strncpy(padding,buf,strlen(padding));
			}


/////******************************************************tcp_hd start*********************

			memset(buf,'\0',sizeof(buf));
			for(int i=0;i<2;i++){
				tok=strtok(NULL,"|");
				strcat(buf,tok);
			}
			rx_tcph->source = htons(strtol(buf,NULL,16));

			memset(buf,'\0',sizeof(buf));
			for(int i=0;i<2;i++){
				tok=strtok(NULL,"|");
				strcat(buf,tok);
			}
			rx_tcph->dest = htons(strtol(buf,NULL,16));

			memset(buf,'\0',sizeof(buf));
			for(int i=0;i<4;i++){
				tok=strtok(NULL,"|");
				strcat(buf,tok);
			}
			rx_tcph->seq = htons(strtol(buf,NULL,16));

			memset(buf,'\0',sizeof(buf));
			for(int i=0;i<4;i++){
				tok=strtok(NULL,"|");
				strcat(buf,tok);
			}
			rx_tcph->ack_seq = htons(strtol(buf,NULL,16));

			memset(buf,'\0',sizeof(buf));
			for(int i=0;i<1;i++){
				tok=strtok(NULL,"|");
				strcat(buf,tok);
			}
			int do_re = atoi(buf);
			rx_tcph->doff = do_re/10;
			rx_tcph->res1 = do_re%10;

			memset(buf,'\0',sizeof(buf));
			for(int i=0;i<1;i++){
				tok=strtok(NULL,"|");
				strcat(buf,tok);
			}
			rx_tcph->res2 = strtol(buf,NULL,16)/64;

			int flag = strtol(buf,NULL,16);

			rx_tcph->fin = flag%2; flag/=2;
			rx_tcph->syn = flag%2; flag/=2;
			rx_tcph->rst = flag%2; flag/=2;
			rx_tcph->psh = flag%2; flag/=2;
			rx_tcph->ack = flag%2; flag/=2;
			rx_tcph->urg = flag%2;

			memset(buf,'\0',sizeof(buf));
			for(int i=0;i<2;i++){
				tok=strtok(NULL,"|");
				strcat(buf,tok);
			}
			rx_tcph->window = htons(strtol(buf,NULL,16));

			memset(buf,'\0',sizeof(buf));
			for(int i=0;i<2;i++){
				tok=strtok(NULL,"|");
				strcat(buf,tok);
			}
			rx_tcph->check = htons(strtol(buf,NULL,16));

			memset(buf,'\0',sizeof(buf));
			for(int i=0;i<2;i++){
				tok=strtok(NULL,"|");
				strcat(buf,tok);
			}
			rx_tcph->urg_ptr = htons(strtol(buf,NULL,16));

			header_on=0;

///////**************************tcp_hdr_end*********************output_hdr_info*********************


		

		}

		else{
	
			total_length += (strlen(line)/3);
		
		}

		if(line[strlen(line)-1] == 10){

			ip_checksum = cksum_in ((unsigned short int *) rx_iph, sizeof (struct iphdr));

			char source_addr[32];
			inet_ntop(AF_INET, &(rx_iph->saddr), source_addr, sizeof(source_addr));

			printf("\n**************************************************************\n");	

				printf("SRC IP ADDRESS: %s\n",source_addr);
		
				if(error_check(rx_iph, rx_tcph)==0){
					printf("Normal packet!!\n");
				}
				else{
					log_count(source_addr,ntohs(rx_tcph->dest));
					error_log(rx_iph, rx_tcph, error_content);
				}
						
			printf("**************************************************************\n");

			total_length = 0;
			header_on=1;
		}
			
	}	
}

int error_check(struct iphdr *iph,struct tcphdr *tcph){
	
	int error_on=0;

	memset(error_content,'\0',sizeof(error_content));

	if(tcph->syn==1 && tcph->fin==1) {
		strcat(error_content," 1");
		printf("**tcp packet error [SYN,FIN] NO current setup\n"); 
		error_on=1;
	}
	if(tcph->syn==1 && tcph->rst==1) {
		strcat(error_content," 2");
		printf("**tcp packet error [SYN,RST] NO current setup\n"); 
		error_on=1;
	}
	if(tcph->fin==1 && tcph->rst==1) {
		strcat(error_content," 3");
		printf("**tcp packet error [FIN,RST] NO current setup\n");
		error_on=1;
	}
	if(tcph->ack!=1 && tcph->fin==1) {
		strcat(error_content," 4");
		printf("**tcp packet error [ACK,FIN] NO ACK not setup and FIN setup\n");
		error_on=1;
	}
	if(tcph->ack!=1 && tcph->psh==1) {
		strcat(error_content," 5");
		printf("**tcp packet error [ACK,PSH] NO ACK not setup and PSH setup\n"); 
		error_on=1;
	}
	if(tcph->ack!=1 && tcph->urg==1) {
		strcat(error_content," 6");
		printf("**tcp packet error [ACK,URG] NO ACK not setup and URG setup\n");  
		error_on=1;
	}
	if(tcph->urg!=1 && tcph->ack!=1 && tcph->psh!=1 && tcph->rst!=1 && tcph->syn!=1 && tcph->fin!=1) {
		strcat(error_content," 7");
		printf("**tcp packet error NOT All setup\n");  
		error_on=1;
	}
	if(tcph->urg!=1 && tcph->ack!=1 && tcph->psh!=1 && tcph->rst!=1 && tcph->syn!=1 && tcph->fin==1) {
		strcat(error_content," 8");
		printf("**tcp packet error [FIN] only FIN setup\n");  
		error_on=1;
	}
	if(tcph->urg!=1 && tcph->ack!=1 && tcph->psh==1 && tcph->rst!=1 && tcph->syn!=1 && tcph->fin==1) {
		strcat(error_content," 9");
		printf("**tcp packet error [PSH,FIN] only FIN,PSH setup\n"); 
		error_on=1;
	}
	if(tcph->doff < 5) {
		strcat(error_content," 10");
		printf("**tcp header can not be 5 low\n"); 
		error_on=1;
	}

	if(iph->version != 4 && iph->version != 6) {
		strcat(error_content," 100");
		printf("**ip_version must be 4 or 6\n"); 
		error_on=1;
	}
	if((iph->ttl-1) < 0) {
		if(iph->ttl == 0) {
			strcat(error_content," 101");
			printf("**ttl exceed\n"); 
			error_on=1;
		}
		else{
			strcat(error_content," 102");
			printf("**ttl can not be negative number or zero\n"); 
			error_on=1;
		}
	}
	if(iph->ihl < 5) {
		strcat(error_content," 103");
		printf("**ip header length must be 5 or more\n"); 
		error_on=1;
	}
	if(iph->protocol != 6) {
		strcat(error_content," 104");
		printf("**tcp ip protocol number must be 6\n"); 
		error_on=1;
	}
	if(iph->tos > 6 || iph->tos < 0) {
		strcat(error_content," 105");
		printf("**iph type of service must be 0 ~ 6\n"); 
		error_on=1;
	}
	if(iph->tot_len == (total_length+sizeof(*iph)+sizeof(*tcph))) {
		strcat(error_content," 106");
		printf("**total_length Inconsistency \n"); 
		error_on=1;
	}
	if((ip_checksum&0xFFFF) != 0xFFFF) {
		strcat(error_content," 107");
		printf("**ip check_sum error \n"); 
		error_on=1;
	}

	int flag_off = htons(iph->frag_off);
	int offset=0;
	for(int i=0;i<13;i++){
		offset+=(flag_off%2)*(2^i);
		flag_off/=2;
	}
	int not_use_bit=flag_off%2; flag_off/=2;
	int frag_possible_bit=flag_off%2; flag_off/=2;
	int more_frag_bit=flag_off%2; 

	if(frag_possible_bit == 1 && flag_off != 0) {
		strcat(error_content," 108");
		printf("**fragmentation not possible this packet but offsetfield is not 1\n"); 
		error_on=1;
	}
	

	if(error_on == 1){
		return 1;
	}
	else{
		return 0;
	}
}

int log_count(char *ip_address, int port)
{
	FILE *f;
	char line[50];
	char *tok; 
	int pp=0;
	char addr_buf[50];
	char *tok2;
	int count_s;
	int check_array=0;
	int control_buf=0;

	IP_VALUE *head;
	IP_VALUE *first;
	head = (IP_VALUE *)malloc(sizeof(IP_VALUE));

	first=head;
	f=fopen(ERROR_COUNT_FILE,"r");
	if(f==NULL){
		printf("error open ErrorLog_Cnt file\n");
		exit(-1);
	}
	while(fgets(line,50,f)) 
	{
		line[strlen(line)]='\0';
		tok = strtok(line," ");

			head->count = atoi(tok);
			tok = strtok(NULL," ");
			strcpy(head->ip_addr,tok);

		head->next=(IP_VALUE *)malloc(sizeof(IP_VALUE));
		head = head->next;
	} 
	fclose(f);
	head->next=NULL;

	f=fopen("copy_error_cnt.txt","w");

	while(first->next!=NULL){
		
		if(strncmp(first->ip_addr,ip_address,strlen(first->ip_addr)-1)==0){
			first->count=first->count+1;
			if((first->count)%10 == 0){
				traceRoute(ip_address,port);
			}
			printf("*****warning***** : %d error count\n",first->count);
			sprintf(addr_buf,"%d %s",first->count,first->ip_addr);
			pp=1;
			
		}
		else{
			fprintf(f,"%d %s",first->count,first->ip_addr);
		}
		
		first = first->next;
		

	}

	fclose(f);

	char bufbuf[50];
	strcpy(bufbuf,addr_buf);
	if(pp==1){
		tok2 = strtok(bufbuf," ");
		count_s=atoi(bufbuf);
	}
	FILE *fcopy=fopen("copy_error_cnt.txt","r");
	f=fopen(ERROR_COUNT_FILE,"w");

	int count_o;
	control_buf==0;
	char line_copy[50];
	while(fgets(line,50,fcopy)) 
	{
		strcpy(line_copy,line);
		if(pp == 1 && control_buf==0){
			tok = strtok(line_copy," ");
			count_o = atoi(tok);

			if(count_s<count_o){
				fprintf(f,"%s",line);
			}
			else if(control_buf == 0){

				fprintf(f,"%s",addr_buf);
				fprintf(f,"%s",line);
				control_buf=1;
			}
		}
		else fprintf(f,"%s",line);
	} 
	fclose(fcopy);
	fclose(f);
	remove("copy_error_cnt.txt");

	if(pp==0){
		first_error_log_count(ip_address);
	}

}


int first_error_log_count(char *ip_address)
{
	FILE *f;

	f=fopen(ERROR_COUNT_FILE,"a");

	fprintf(f,"%d %s\n",1,ip_address); 
	fclose(f);
}

int error_log(struct iphdr *iph, struct tcphdr *tcph, char error_content[])
{
	FILE *f;
	char table[9]="ErrorLog";

	f=fopen(table,"a");
	
	char now_t[32];
	char to_d[32];
	nowtime(now_t);
	today(to_d);

	fprintf(f,"%s\n","--------------------------------------------------------------------"); 
	fprintf(f,"TIME : %s %s\n",to_d,now_t); 
	fprintf(f,"IP_VERSION : IP v%1u\n",iph->version); 
	fprintf(f,"SRC IP: %s\n",inet_ntoa(*(struct in_addr *)&iph->saddr)); 
	fprintf(f,"DEST IP: %s\n",inet_ntoa(*(struct in_addr *)&iph->daddr)); 
	fprintf(f,"SOURCE PORT : %5u\n",ntohs(tcph->source)); 
	fprintf(f,"DESTINATAION PORT : %5u\n",ntohs(tcph->dest)); 
	fprintf(f,"ERROR NUMBER :%s\n",error_content);
	fprintf(f,"%s\n","-------------------------------------------------------------------\n");  

	fclose(f);
}

int cksum_in(unsigned short *addr,int len){
	sum=0;
	unsigned short answer=0;
	unsigned short *w=addr;
	int nleft=len;

	while(nleft>1){
		sum+=*w++;
		//printf("sum %X\n",*w);
		if(sum & 0x80000000)
			sum=(sum&0xffff)+(sum>>16);
		nleft-=2;

	}

	if(nleft==1){
		*(unsigned char *)(&answer)=*(unsigned char *)w;
		sum+=answer;

	}

	while(sum>>16)
		sum=(sum&0xffff)+(sum>>16);

	//printf("sum %X\n",sum);
	return sum;
}


int traceRoute(char *destination_ip,int port){

        unsigned long saddr;//출발 ip
        unsigned long daddr; //도착 ip

        char* buffer; 
	int addrlen;
	char local_addr[20];
	local_ipaddr(local_addr);
        saddr = inet_addr(local_addr); //localip 저장소
        daddr = inet_addr(destination_ip); //도착지 주소

	printf("----------------------------------------------------------\n");
	printf("**	    trace the route to detination source	**\n");
	printf("	        you can see stagnation zone 	 	  \n");
	printf("            Source ip_addr : %s 			  \n",local_addr);
	printf("            Destination ip_addr : %s 			  \n",destination_ip);
	printf("**          Max Hops : %d 				**\n",MAX_HOPS);
	printf("----------------------------------------------------------\n");
	printf("\n");


       

        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

       

        if (sockfd < 0)

        {

            printf("socket open error\n");

            exit(0);

        }

       

        int ttl;
	float delay_time;
	int second_third_check = 0;

        for(ttl = 1; ttl<MAX_HOPS+1; ttl++){ //1부터 30까지 maxhop 

	delay_time=0.0;

            for (int i = 0; i < NUMBER_REPETITAION; ++i) { //3번씩 보냄

               

                int on = 1; //socket opt iphdr can control

               	

               	//socket 옵션 ip 조정가능 하게 설정

                if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof (on)) == -1)

                {

                    printf("set socketopt error\n");

                    exit(0);

                }

               

                int packet_size = sizeof (struct iphdr) + sizeof (struct icmphdr);

                char *packet = (char *) malloc (packet_size);

               

                if (!packet)

                {

                    printf("memory over\n");

                    close(sockfd);

                    exit (0);

                }

               

                struct iphdr *ip = (struct iphdr *) packet;

                struct icmphdr *icmp = (struct icmphdr *) (packet + sizeof (struct iphdr));

               

                memset (packet, 0, packet_size);

               

                ip->version = 4;

                ip->ihl = 5;

                ip->tos = 0;

                ip->tot_len = htons (packet_size);

                ip->id = ttl+1000;

                ip->frag_off = 0;

                ip->ttl = ttl;

                ip->protocol = IPPROTO_ICMP;

                ip->saddr = saddr;

                ip->daddr = daddr;

                ip->check = cksum_ina ((unsigned short int *) ip, sizeof (struct iphdr));//checksum




                icmp->type = 8;//icmp_echo type 8

                icmp->code = 0;//code ??

                icmp->checksum = cksum_ina((unsigned short *)icmp, sizeof(struct icmphdr));//checksum

               

				//보내는 addr의 초기화

                struct sockaddr_in servaddr;

                servaddr.sin_family = AF_INET;

                servaddr.sin_addr.s_addr = daddr;

               

                addrlen = sizeof(servaddr);

               

                struct timeval end_time;

                struct timeval start_time;

                memset(&start_time, 0, sizeof(struct timeval));

                gettimeofday((struct timeval *)&start_time, NULL);

               
                if (sendto(sockfd, packet, packet_size, 0, (struct sockaddr*) &servaddr, sizeof (servaddr)) < 1)

                {

                   printf("send socket error\n");

                   exit(-1);

                }

                buffer = malloc(sizeof(struct iphdr) + sizeof(struct icmphdr));

                fd_set sockfdset;

                struct timeval t;

                FD_ZERO(&sockfdset);

                FD_SET(sockfd, &sockfdset);

                t.tv_sec = TIME_LIMITED;

                t.tv_usec = 0;

               

                int timeOut = 0;

               

                int control_select = select(sockfd+1, &sockfdset, NULL, NULL, &t); //select start

               

                if (control_select < 0){

                    printf("select error\n");

                } else if (control_select == 0){

                    timeOut = 1; //select time over!!

                } else {

                    recvfrom(sockfd, buffer, sizeof(struct iphdr) + sizeof(struct icmphdr), 0, (struct sockaddr *)&servaddr, &addrlen);

                }


                memset(&end_time, 0, sizeof(struct timeval));

                gettimeofday((struct timeval *)&end_time, NULL);

                float rtt = 0;

               

                if ((rtt = (end_time.tv_usec - start_time.tv_usec)/100)<0){

                    rtt += 10000;

                }

                rtt += (end_time.tv_sec - start_time.tv_sec) * 10000;

                rtt = rtt/10;
		delay_time+=rtt;

                struct iphdr* ip_reply;

                ip_reply = (struct iphdr*) buffer;

               

                char str[INET_ADDRSTRLEN];

                inet_ntop(AF_INET, &(ip_reply->saddr), str, INET_ADDRSTRLEN);

               

                struct hostent *nomeHost;

               

                nomeHost = gethostbyaddr((const void *)&ip_reply->saddr,

                                         sizeof(struct in_addr), AF_INET); // hostname get

               

                if (timeOut == 0){

                    if (i==0 && nomeHost!=NULL){ //addr nothing

                        printf("TTL : %d  %s  (%s) %0.1f ms ", ttl, nomeHost->h_name, str, rtt);
			second_third_check = 1;

                    }else if (i==0){ //addr output

                        printf("TTL : %d  %s  (%s) %0.1f ms ", ttl, str, str, rtt);
			second_third_check = 1;

                    }else if(strcmp(destination_ip, str) ==0 && i==2){ // last addr = exit //'i' is second first 

                        printf("%0.1f ms", rtt);
 	    		delay_time/=3;
	    		stagnation_check(&delay_time);
			printf("\n");
			printf("***************success***************\n");

               		free(packet);
        		close(sockfd);
                	free(buffer);
                        //exit(0);
			printf("\n--------------------port scan start------------------\n");
			for(int i=0;i<10;i++){
				scan_syn_port(daddr, port-5+i);
			}
			return 1;

                    }else {
			if(second_third_check == 0){
                        	printf("TTL : %d  %s  (%s) %0.1f ms ", ttl, str, str, rtt);
			}
                        printf("%0.1f ms ", rtt);
	
                    }

                } else if (timeOut==1 && i==0) { //time over

                    printf("TTL : %d * ",ttl);

                } else if (timeOut==1 && i==2) { //time over

                    printf("* ");

                } else { //time over

                    printf("* ");

                }

               

                free(packet);

                free(buffer);


               

            }

 	    delay_time/=3;
	    stagnation_check(&delay_time);
            printf("\n");

        }
	printf("***************false***************\n");
        close(sockfd);
	return 0;

}     

void stagnation_check(float *delay_t){

	if(*delay_t>1000){
		printf(" Can't recive packet");
	}
	else if(*delay_t>500){
		printf(" Poor");
	}
	else if(*delay_t>100){		
		printf(" Fair");
	}
	else if(*delay_t>10){
		printf(" Good");
	}
	else{
		printf(" Excellent");
	}
}

void local_ipaddr(char local_addr[]){

	 int sockfd;
	 char ipstr[40];
	 struct ifreq ifr;
	//printf("lan %s\n",lan_card);
	 strncpy(ifr.ifr_name,lan_card,7);
	 sockfd =socket(AF_INET,SOCK_STREAM,0);

	 if (ioctl(sockfd,SIOCGIFADDR,&ifr)< 0 )
	 {
		printf("ioctl error\n");
		exit(-1);
	 }

	 inet_ntop(AF_INET,ifr.ifr_addr.sa_data+2,ipstr,sizeof(struct sockaddr));

	strcpy(local_addr,ipstr);
	local_addr[strlen(local_addr)]='\0';

}

unsigned short cksum_ina(unsigned short *addr,int len){
	unsigned long sum=0;
	unsigned short answer=0;
	unsigned short *w=addr;
	int nleft=len;

	while(nleft>1){
		sum+=*w++;
		if(sum & 0x80000000)
			sum=(sum&0xffff)+(sum>>16);
		nleft-=2;
	}

	if(nleft==1){
		*(unsigned char *)(&answer)=*(unsigned char *)w;
		sum+=answer;

	}

	while(sum>>16)
		sum=(sum&0xffff)+(sum>>16);
	return(sum==0xffff)?sum:~sum;
}

int today(char *to_d)
{
	time_t ltime;

	    struct tm *today;

	    char SDate[32];


	    time(&ltime);

	    today = localtime(&ltime);

	sprintf(SDate, "%04d-%02d-%02d",

		    today->tm_year + 1900,

		    today->tm_mon + 1, 
		    today->tm_mday);
	strcpy(to_d,SDate);

	return 1;

}

int nowtime(char *now_t)
{
	time_t ltime;

	    struct tm *today;

	    char STime[32];

	    time(&ltime);

	    today = localtime(&ltime);

	sprintf(STime, "%02d:%02d:%02d",

		    today->tm_hour,
		    today->tm_min,
		    today->tm_sec);
	strcpy(now_t,STime);

	return 1;

}


scan_syn_port(unsigned long target, int port)
{
	int sd;

	int on = 1;
	int len;

	int tx_packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct pseudohdr);
	int rx_packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr);
	char *rx_packet = (char *)malloc(rx_packet_size);
	char *tx_packet = (char *)malloc(tx_packet_size);

	struct tcphdr *tcph, *rx_tcph;
	struct iphdr *iph, *rx_iph;
	struct pseudohdr *pseudoh;

	struct in_addr s_addr, d_addr;
	struct sockaddr_in local, remote;
	
	struct servent *serv;

	iph = (struct iphdr *)(tx_packet);
	tcph = (struct tcphdr *)(tx_packet + sizeof(struct iphdr));
	pseudoh = (struct pseudohdr *)(tx_packet + sizeof(struct iphdr) + sizeof(struct tcphdr));

	if((sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
		printf("socket open error\n");
		exit(-1);
	}

	if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on)) < 0) {
		printf("set socket option error\n");
		exit(-2);
	}

	memset(tx_packet, 0, tx_packet_size);

	char local_addr[20];
	local_ipaddr(local_addr);
	d_addr.s_addr = target;
	s_addr.s_addr = inet_addr(local_addr);
	
	pseudoh->s_addr = s_addr.s_addr;
	pseudoh->d_addr = d_addr.s_addr;
	pseudoh->protocol = IPPROTO_TCP;
	pseudoh->zero = 0;
	pseudoh->length = htons(sizeof(struct tcphdr));

	tcph->source = htons(LOCAL_PORT);
	tcph->dest = htons(port);
	tcph->seq = htons(random()%time(NULL));
	tcph->ack_seq = 0;
	tcph->doff = 5;
	tcph->res1 = 0;
	tcph->fin = 0;
	tcph->syn = 1;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->urg = 0;
	tcph->window = htons(1024);
	tcph->check = (unsigned short)cksum_ina((unsigned short *)tcph, (sizeof(struct tcphdr) + sizeof(struct pseudohdr)));

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = htons(tx_packet_size) - sizeof(struct pseudohdr);
	iph->id = 0;
	iph->frag_off =0;
    	iph->ttl = IPDEFTTL;
    	iph->protocol = IPPROTO_TCP;
    	iph->saddr = s_addr.s_addr;
    	iph->daddr = d_addr.s_addr;
    	iph->check = (unsigned short)cksum_ina((unsigned short *)iph,sizeof(struct iphdr));

    	remote.sin_family = PF_INET;
    	remote.sin_addr = d_addr;
    	remote.sin_port =htons(port);
    	remote.sin_port =0;   



   	if(sendto(sd,tx_packet,(tx_packet_size - sizeof(struct pseudohdr)),0x0,(struct sockaddr*)&remote,sizeof(remote))<0)
    	{
        	printf("send error\n");
        	exit(-3);
    	}



    	while(recvfrom(sd,rx_packet,rx_packet_size,0x0,(struct sockaddr*)&local,&len)>0)
    	{


        	rx_iph  = (struct iphdr *)(rx_packet);
        	rx_tcph = (struct tcphdr*)(rx_packet + rx_iph->ihl *4);
       


        	if(rx_iph->saddr != iph->daddr) continue;


        	if((ntohs(tcph->source) == ntohs(rx_tcph->dest))&&(ntohs(tcph->dest) == ntohs(rx_tcph->source)))
        	{


            		if(rx_tcph->syn == 1 && rx_tcph->ack==1){
                		serv = getservbyport(htons(port),"tcp");
                		printf("port[%d] open/%s \n",ntohs(rx_tcph->source),serv->s_name);
            		}           
            		else if(rx_tcph->rst == 1){
                		printf("port[%d] close \n",ntohs(rx_tcph->source));
            		}
            		else{
                		printf("protocol error\n");
                		exit(-1);
            		}
            		break;
        	}
    	}
    	close(sd);
}


