#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>

#define BUF_SIZE 65536

void Server(char *address, char *port, int *socktype, int *family)
{
	struct addrinfo hints, *result, *rp;
	int serverfd, clientfd, s, pid;
	struct sockaddr_storage peer_addr;
	socklen_t peer_addr_len;
	ssize_t nread;
	char buf[BUF_SIZE];

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = *family; 
	hints.ai_socktype = *socktype; 
	hints.ai_flags = AI_PASSIVE; /*For wildcard IP address */
	hints.ai_protocol = 0; /*Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	s = getaddrinfo(address, port, &hints, &result);
	if (s != 0)
	{
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		exit(EXIT_FAILURE);
	}

	/* getaddrinfo() returns a list of address structures.
              Try each address until we successfully bind(2).
              If socket(2) (or bind(2)) fails, we (close the socket
              and) try the next address. */

	for (rp = result; rp != NULL; rp = rp->ai_next)
	{
		serverfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (serverfd == -1)
			continue;
        
        if (*socktype == SOCK_STREAM)
        {
            int sockopt = setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

            if (sockopt == -1)
            {
                perror("server: setsockopt()");
                exit(EXIT_FAILURE);
            }
        }

		if (bind(serverfd, rp->ai_addr, rp->ai_addrlen) == 0)
			break; /*Success */

		close(serverfd);
	}

	if (rp == NULL) /*No address succeeded */
	{
		perror("server: Could not bind");
		exit(EXIT_FAILURE);
	}

	if (*socktype == SOCK_STREAM)
	{
		if(listen(serverfd, 5) == -1)
		{
			perror("server: listen()");
			exit(EXIT_FAILURE);
		}
	}

	freeaddrinfo(result); /*No longer needed */

	peer_addr_len = sizeof(struct sockaddr_storage);

	if (*socktype == SOCK_STREAM)
	{
		if((clientfd = accept(serverfd, (struct sockaddr *) &peer_addr, &peer_addr_len)) == -1)
		{
			perror("server: accept()");
			exit(EXIT_FAILURE);
		}
	}
	else if (*socktype == SOCK_DGRAM)
	{
		clientfd = serverfd;

		if ((nread = recvfrom(serverfd, buf, BUF_SIZE - 1, 0, (struct sockaddr *) &peer_addr, &peer_addr_len)) == -1)
		{
			perror("server: recvfrom()");
			exit(EXIT_FAILURE);
		}

		if (write(STDOUT_FILENO, buf, nread) == -1)
		{
			perror("server: write()");
			exit(EXIT_FAILURE);
		}

		if (connect(serverfd, (struct sockaddr *) &peer_addr, peer_addr_len) == -1)
		{
			perror("sercer: connect()");
			exit(EXIT_FAILURE);
		} 
	}

	if ((pid = fork()) == 0) 
	{
		while ((nread = read(STDIN_FILENO, buf, BUF_SIZE)) > 0)
		{
			if (write(clientfd, buf, nread) == -1)
			{
				perror("server: write()");
				exit(EXIT_FAILURE);
			}
		}
	}
	else 
	{
		while ((nread = read(clientfd, buf, BUF_SIZE)) > 0)
		{
			
			if (write(STDOUT_FILENO, buf, nread) == -1)
			{
                perror("server: send()");
				exit(EXIT_FAILURE);
			}
		}
	} 

	close(clientfd);
	close(serverfd);
}

void Client(char *address, char *port, int *socktype, int *family)
{
	struct addrinfo hints, *result, *rp;
	int clientfd, s, pid;
	ssize_t nread;
	char buf[BUF_SIZE];

	/*Obtain address(es) matching host/port */

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = *family; /*Allow IPv4 or IPv6 */
	hints.ai_socktype = *socktype; /*Datagram socket */
	hints.ai_flags = 0;
	hints.ai_protocol = 0; /*Any protocol */

	s = getaddrinfo(address, port, &hints, &result);
	if (s != 0)
	{
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		exit(EXIT_FAILURE);
	}

	/*getaddrinfo() returns a list of address structures.
	   Try each address until we successfully connect(2).
	   If socket(2) (or connect(2)) fails, we (close the socket
	   and) try the next address. */

	for (rp = result; rp != NULL; rp = rp->ai_next)
	{
		clientfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (clientfd == -1)
			continue;

		if (connect(clientfd, rp->ai_addr, rp->ai_addrlen) == -1)
		{
			close(clientfd);
            perror("client: connect()");
            continue;
		}

		break;
	}

	if (rp == NULL)
	{
		/*No address succeeded */
		perror("client: Could not connect");
		exit(EXIT_FAILURE);
	}

	freeaddrinfo(result); /*No longer needed */

	if ((pid = fork()) == 0) 
	{
		while ((nread = read(STDIN_FILENO, buf, BUF_SIZE)) > 0)
		{
			if (write(clientfd, buf, nread) == -1)
			{
				perror("client: write()");
				exit(EXIT_FAILURE);
			}
		}
	}
	else 
	{
		while ((nread = read(clientfd, buf, BUF_SIZE)) > 0)
		{
			
			if (write(STDOUT_FILENO, buf, nread) == -1)
			{
                perror("client: send()");
				exit(EXIT_FAILURE);
			}
		}
	}

	close(clientfd);
} 

int main(int argc, char *argv[])
{
	int socktype = SOCK_STREAM; /* TCP */
	int family = AF_UNSPEC; /*Allow IPv4 or IPv6 */
	int l = 0, c;
	char *hostname = NULL;
	char *port;

	while ((c = getopt(argc, argv, "lu46")) != -1)
	{
		switch (c)
		{
			case 'l':
				l = 1;
				break;
			case 'u':
				socktype = SOCK_DGRAM;
				break;
			case '4':
				family = AF_INET;
				break;
			case '6':
				family = AF_INET6;
				break;
		}
	}

	if (l)
	{
		if (optind + 1 != argc)
		{	
			printf("Usage: %s[-l listen on port][-u UDP][-4 IPv4][-6 IPv6] port\n", argv[0]);
			exit(0);
		}
		else
		{
			port = argv[optind];
		}

		Server(hostname, port, &socktype, &family);
	}
	else
	{
		if (optind + 2 != argc)
		{
			printf("Usage: %s[-l listen on port][-u UDP][-4 IPv4][-6 IPv6] host port\n", argv[0]);
			exit(0);
		}
		
		Client(argv[optind], argv[optind + 1], &socktype, &family);
	}

	return 0;
}
