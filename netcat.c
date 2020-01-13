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
	int sfd, cfd, s;
	struct sockaddr_storage peer_addr;
	socklen_t peer_addr_len;
	ssize_t nread;
	char buf[BUF_SIZE];

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = *family; /*Allow IPv4 or IPv6 */
	hints.ai_socktype = *socktype; /*Datagram socket */
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

	for (rp = result; rp != NULL; rp = rp->ai_next)
	{
		sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1)
			continue;

		if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
			break; /*Success */

		close(sfd);
	}

	if (rp == NULL) /*No address succeeded */
	{
		fprintf(stderr, "Could not bind\n");
		exit(EXIT_FAILURE);
	}

	if (*socktype == SOCK_STREAM && listen(sfd, 1) == -1)
	{
		fprintf(stderr, "listen()\n");
		exit(EXIT_FAILURE);
	}

	freeaddrinfo(result); /*No longer needed */

	peer_addr_len = sizeof(struct sockaddr_storage);

	if (*socktype == SOCK_STREAM)
	{
		if((cfd = accept(sfd, (struct sockaddr *) &peer_addr, &peer_addr_len)) == -1)
		{
			fprintf(stderr, "accept()\n");
			exit(EXIT_FAILURE);
		}
	}
	else if (*socktype == SOCK_DGRAM)
	{
		cfd = sfd;

		if ((nread = recvfrom(sfd, buf, BUF_SIZE - 1, 0, (struct sockaddr *) &peer_addr, &peer_addr_len)) == -1)
		{
			fprintf(stderr, "recvfrom()\n");
			exit(EXIT_FAILURE);
		}

		if (write(STDOUT_FILENO, buf, nread) == -1)
		{
			fprintf(stderr, "write()\n");
			exit(EXIT_FAILURE);
		}

		if (connect(sfd, (struct sockaddr *) &peer_addr, peer_addr_len) == -1)
		{
			fprintf(stderr, "connect()\n");
			exit(EXIT_FAILURE);
		}
	}

	while ((nread = read(cfd, buf, BUF_SIZE)) > 0)
	{
		if (write(STDOUT_FILENO, buf, nread) == -1)
		{
			fprintf(stderr, "write()\n");
			exit(EXIT_FAILURE);
		}
	}

	if (nread == -1)
	{
		fprintf(stderr, "read()\n");
		exit(EXIT_FAILURE);;
	}

	close(cfd);
	close(sfd);
}

void Client(char *address, char *port, int *socktype, int *family)
{
	struct addrinfo hints, *result, *rp;
	int cfd, s;
	ssize_t nread;
	char buf[BUF_SIZE];

	/*Obtain address(es) matching host/port */

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = *family; /*Allow IPv4 or IPv6 */
	hints.ai_socktype = *socktype; /*Datagram socket */
	//hints.ai_flags = 0;
	//hints.ai_protocol = 0; /*Any protocol */

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
		cfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (cfd == -1)
			continue;

		if (connect(cfd, rp->ai_addr, rp->ai_addrlen) == -1)
		{
			close(cfd);
            perror("client: connect");
            continue;
		}

		break;
	}

	if (rp == NULL)
	{
		/*No address succeeded */
		fprintf(stderr, "Could not connect\n");
		exit(EXIT_FAILURE);
	}

	freeaddrinfo(result); /*No longer needed */

	if ((nread = read(STDIN_FILENO, buf, BUF_SIZE)) > 0)
    {
        if (write(cfd, buf, nread) == -1)
        {
            fprintf(stderr, "write()\n");
			exit(EXIT_FAILURE);
        }

		while ((nread = read(cfd, buf, BUF_SIZE)) > 0)
		{
			
			if (write(STDOUT_FILENO, buf, nread) == -1)
			{
				fprintf(stderr, "send()\n");
				exit(EXIT_FAILURE);
			}
		}

		if (nread == -1)
		{
			fprintf(stderr, "read()\n");
			exit(EXIT_FAILURE);
		} 
    }

	/*Send remaining command-line arguments as separate
	   datagrams, and read responses from server */

	close(cfd);
} 

int main(int argc, char *argv[])
{
	int socktype = SOCK_STREAM;
	int family = AF_UNSPEC; /*Allow IPv4 or IPv6 */
	int listen = 0;
	int c;
	char *hostname = NULL;
	char *port;

	while ((c = getopt(argc, argv, "lu46")) != -1)
	{
		switch (c)
		{
			case 'l':
				listen = 1;
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

	if (listen == 0)
	{
		if (optind + 2 != argc)
		{
			printf("Usage: %s[-l listen on port][-u UDP][-4 IPv4][-6 IPv6] host port\n", argv[0]);
			exit(0);
		}
		
		Client(argv[optind], argv[optind + 1], &socktype, &family);
	}
	else
	{
		if (optind + 1 == argc)
		{
			port = argv[optind];
		}
		else if (optind + 2 == argc)
		{
			hostname = argv[1];
			port = argv[optind + 1];
		}
		else
		{
			printf("Usage: %s[-l listen on port][-u UDP][-4 IPv4][-6 IPv6] host port\n", argv[0]);
			exit(0);
		}

		Server(hostname, port, &socktype, &family);
	}

	return 0;
}