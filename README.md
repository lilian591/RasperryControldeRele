# RasperryControldeRele
//Control de 8 sockets en relevador de 4 salidas
/*
Interfaz de Alexa a Raspberry Pi de Stuart
Proceso de demonio de dispositivo
Inicia varios procesos de controlador de dispositivos que supervisan puertos TCP independientes
* Responde a las llamadas del dispositivo:
GetBinaryState
SetBinaryState
Inicia un controlador de paquetes de detección SSDP en el subproceso local
* Responde a paquetes de descubrimiento XML
Inicia un servidor de páginas Web
* Acciones y respuestas a las solicitudes de alternancia de la página web
Recuerde configurar la interfaz en modo promiscuo con
sudo ifconfig eth0 promisc
función:
Abre controladores de dispositivos en sockets locales contando desde PORTBASE (43540)
Relojes para paquetes de descubrimiento en UDP SSDP 239.255.255.250 puerto 1900
responde con un puntero de detección a http://<ip>:P ORTBASE+n/setup.xml para cada dispositivo
A continuación, Alexa sondea cada dispositivo lógico
A continuación, los dispositivos responden con xml de configuración
Alexa registra dispositivos basados en la configuración XML
Alexa llama a los dispositivos con solicitudes de estado GET y SET
A continuación, los controladores de dispositivos alternan los pines GPIO asociados.
Inicia un servidor de páginas web en WEBPORT
genera un botón por dispositivo
acciones alternar las solicitudes procedentes de la página Web
Utiliza la biblioteca wiringPi para manejar GPIO por lo que
necesita el modificador -l wiringPi agregado en la compilación:
gcc -o StuPiMo StuPiMo.c -l cableadoPi
*/
// Bibliotecas a incluir
#incluir  <> unistd.h
#Incluir  <> sys/types.h
#Incluya  <> Sys/Socket.h
#incluir  <> Netinet/in.h
#Incluir  <> arpa/inet.h
#Incluir  <> time.h
#Incluir  <> String.h
#incluir  <> stdio.h
#Incluir  <> stdlib.h
#Incluir  <> Errno.h
#Incluir  <> net/if.h
#Incluya  <> sys/ioctl.h
#include  <> wiringPi.h  // Biblioteca de control GPIO

// definiciones globales
#definir el puerto WEBPORT 5353  // en el que ejecutar el servidor Web
#definir MSGBUFSIZE 2048  // longitud de los búferes HTTP
#definir NUMDEVICES 8  // Número de dispositivos virtuales a crear
#define NAMELEN 30  // Tamaño de los nombres de los dispositivos
#define TAGLEN 128  // Tamaño de las cadenas pasadas
#definir PORTBASE 43450  // puerto IP base para incrementar desde
#definir MAXIF 5  // número de interfaces locales


// Configurar tablas de dispositivos
// Esto rellena una tabla de nombres descriptivos- se conocerán como "Socket 1" a "Socket 8"
int setup_names(char friendly[NUMDEVICES][NAMELEN]) {
	int i = 0;
	// Utilice este bucle
	for (i = 0; i < NUMDEVICES; i++) {
		sprintf(friendly[i],  "Socket %d", i + 1);
	}
	// O bien, la siguiente tabla manual para rellenar los nombres de los dispositivos
	/*
	strcpy(friendly[0], "Socket 1");
	strcpy(friendly[1], "Socket 2");
	strcpy(friendly[2], "Socket 3");
	strcpy(friendly[3], "Socket 4");
	strcpy(friendly[4], "Socket 5");
	strcpy(friendly[5], "Socket 6");
 strcpy(amistoso[6], "Zócalo 7");
 strcpy(amistoso[7], "Zócalo 8");
	*/
	devolver i;
}
//
// controlador de dispositivos
// 
int device(int port, char devicename[NAMELEN], int verbose_mode, int pin)
{

	// Setup Variables
	int ret;						// used for return status etc
	int device_state = 0;			// state of the device 1 = on 0 = off -1 = disconnected
	char msgbuf[MSGBUFSIZE];		// inbound message buffer 
	char packet[MSGBUFSIZE];		// outbound packet buffer
	respuesta char[MSGBUFSIZE - 256];  // búfer para la carga útil
	int server_fd;  // Descriptor de archivo para el socket de servidor
	int child_fd;  // descriptor de archivo para socket de entrada
	etiqueta char[ 128];  // Etiqueta para buscar
	char *p;  // puntero para uso general
	int nbytes;  // Número de bytes enviados o recibidos
	/*
 * El código comienza aquí
	*/
	// crear un socket TCP
 server_fd = socket(AF_INET, SOCK_STREAM, 0);  // Socket TCP ordinario
	si (server_fd < 0) {
		printf("%s: socket create failed\n", devicename);
		volver -1;
	}
	// Permitir que varios sockets utilicen el mismo número de puerto
	u_int sí = 1;
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes)) < 0)
	{
		printf("Error al reutilizar ADDR\n" );
		volver -1;
	}

	// configurar la dirección de origen
	struct sockaddr_in addr;  // nuestra dirección de socket local
	memset(&addr, 0, sizeof(addr));  // borrarlo
 Addr. sin_family = AF_INET;
 Addr. sin_addr. s_addr = htonl(INADDR_ANY);  // cualquier dirección inbount
 Addr. sin_port = htons(puerto);

	// enlazar a la dirección de recepción
	if (bind(server_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		printf("%s: error de enlace\n", nombrededispositivo);
		volver -1;
	}
	// Utilice Listen para preparar el socket para las conexiones
	if (listen(server_fd, 1) < 0)  // aparently allows 1 requests to queue
	{
		printf("%s:error de escucha\n", nombrededispositivo);
		cerrar(server_fd);
		volver -1;
	}
	printf("%s: Escuchando en el puerto:%d... \n", devicename, puerto);
	// Ahora sólo tienes que entrar en un bucle
	mientras que (1) {

		int addrlen = sizeof(addr);

		// Intente aceptar una conexión
 child_fd = aceptar(server_fd, (struct sockaddr *) &addr, &addrlen);
		si (child_fd < 0) {
			printf("%s: Error al aceptar\n", devicename);
			cerrar(server_fd);
			volver -1;
		}

		// Tenemos una conexión, por lo que necesitamos generar una instancia de servidor
		int pid = bifurcación();
		si (pid == -1) {
			printf("No se pudo crear el proceso secundario " );
			cerrar(server_fd);
			volver -1;
		}
		else if (pid == 0) {
			// estamos en el proceso infantil
			cerrar(server_fd);
			// bucle que recibe comandos hasta que se produce un error
			mientras que (1) {
				// cero el búfer
				memset(&msgbuf, 0, sizeof(msgbuf));
				// leer en un paquete
				nbytes = recv(
					child_fd,
					msgbuf,
					sizeof(msgbuf),
					0
				);

				if (nbytes < 1) {
					printf("%s: Closing Child\n",devicename);
					cerrar(child_fd);
					_exit(0);
				}

				si (verbose_mode == 1) {
					printf("\n%s:Datagrama recibido - tamaño:%d\n", devicename,nbytes);
 msgbuf[nbytes] =  '\0' ;
					pone(msgbuf);
				}
				// Compruebe los primeros 6 bytes de una solicitud eventservice
				strcpy(etiqueta,  "GET /event" );
 ret = strncmp(etiqueta, msgbuf, 8);
				if (ret == 0) {								// datagram is a M-SEARCH 
					printf("%s:Received EventService request:\n", devicename);
					msgbuf[nbytes] = '\0';
					if (verbose_mode == 1) {
						puts(msgbuf);
					}
					// Build the xml payload into a response

					strcpy(response, "<?xml version=\"1.0\"?><scpd xmlns=\"urn:Belkin:service-1-0\">");
					strcat(response, "<specVersion><major>1</major><minor>0</minor></specVersion>\r\n");

					strcat(response, "<actionList>");
					strcat(response, "<action><name>SetBinaryState</name><argumentList>");
					strcat(response, "<argument><retval></retval><name>BinaryState</name>");
					strcat(response, "<relatedStateVariable>BinaryState</relatedStateVariable>");
					strcat(response, "<direction>in</direction>");
					strcat(response, "</argument></argumentList></action>\r\n");

					strcat(response, "<action><name>GetFriendlyName</name>");
						strcat(response, "<argumentList><argument><retval></retval><name>FriendlyName</name>");
						strcat(response, "<relatedStateVariable>FriendlyName</relatedStateVariable>");
						strcat(response, "<direction>in</direction></argument></argumentList></action>\r\n");
						
						strcat(response, "<action><name>ChangeFriendlyName</name>");
						strcat(response, "<argumentList><argument><retval></retval><name>FriendlyName</name>");
						strcat(response, "<relatedStateVariable>FriendlyName</relatedStateVariable>");
						strcat(response, "<direction>in</direction>");
						strcat(response, "</argument></argumentList></action>\r\n");

						strcat(response, "<action><name>GetBinaryState</name>");
						strcat(response, "<argumentList><argument><retval></retval><name>BinaryState</name>");
						strcat(response, "<relatedStateVariable>BinaryState</relatedStateVariable>");
						strcat(response, "<direction>out</direction>");
						strcat(response, "</argument></argumentList></action>\r\n");
						strcat(response, "</actionList>");

						strcat(response, "<serviceStateTable>");

						strcat(response, "<stateVariable sendEvents=\"yes\">");
						strcat(response, "<name>BinaryState</name>");
						strcat(response, "<dataType>Boolean</dataType>");
						strcat(response, "<defaultValue>0</defaultValue>");
						strcat(response, "</stateVariable>");

						strcat(response, "<stateVariable sendEvents=\"yes\">");
						strcat(response, "<name>FriendlyName</name>");
						strcat(response, "<dataType>string</dataType>");
					strcat(response, "<defaultValue>0</defaultValue>");
					strcat(response, "</stateVariable></serviceStateTable>");
					strcat(response, "</scpd>");

					// build Http packet
					strcpy(packet, "HTTP/1.1 200 OK\r\n");
					strcat(packet, "SERVER: Unspecified,UPnP,Unspecified\r\n");
					strcat(packet, "LAST-MODIFIED: 12-12-18\r\n");

					// get the length of the payload
					sprintf(tag, "CONTENT-LENGTH: %d\r\n", strlen(response)); // get the length as a string
					strcat(packet, tag);
					strcat(packet, "CONTENT-TYPE:text/xml\r\n");
					strcat(packet, "CONNECTION:close\r\n\r\n");
					// add the response payload
					strcat(packet, response);
					/* send */
					if (verbose_mode == 1) {
						printf("%s: Sending:\n %s\n", devicename, packet);
					}
					int cnt = send(child_fd, packet, strlen(packet), 0);
					printf("%s: Response sent\n", devicename);
					if (cnt < 0) {
						printf("%s: Error on sendto\n", devicename);
						close(child_fd);
						exit(1);
					}
				}
				// check the first 6 bytes for a setup request
				strcpy(tag, "GET /setup");
				ret = strncmp(tag, msgbuf, 6);
				if (ret == 0) {								// datagram is a M-SEARCH 
					printf("%s:Received Setup request:\n", devicename);
					msgbuf[nbytes] = '\0';
					if (verbose_mode == 1) {
						puts(msgbuf);
					}
					// Build the xml payload into a response
					strcpy(response, "<?xml version=\"1.0\"?>\r\n");
					strcat(response, "<root>\r\n");
					strcat(response, "<device>\r\n");
					strcat(response, "<deviceType>urn:Belkin:device:controllee:1</deviceType >\r\n");
					// need to build in friendly name
					strcat(response, "<friendlyName>");
					strcat(response, devicename);
					strcat(response, "</friendlyName>\r\n");
					strcat(response, "<manufacturer>Belkin International Inc.</manufacturer>\r\n");
					strcat(response, "<modelName>Emulated Socket</modelName>\r\n");
					strcat(response, "<modelNumber>3.1415</modelNumber>\r\n");
					sprintf(tag, "<UDN>uuid:Socket-1_0-%d</UDN>\r\n", port);
					strcat(response, tag);
					strcat(response, "<serviceList>\r\n");
					strcat(response, "<service>\r\n");
					strcat(response, "<serviceType>urn:Belkin:service:basicevent:1</serviceType>\r\n");
					strcat(response, "<serviceId>urn:Belkin:serviceId:basicevent1</serviceId>\r\n");
					strcat(response, "<controlURL>/upnp/control/basicevent1</controlURL>\r\n");
					strcat(response, "<eventSubURL>/upnp/event/basicevent1</eventSubURL>\r\n");
					strcat(response, "<SCPDURL>/eventservice.xml</SCPDURL>\r\n");
					strcat(response, "</service>\r\n");
					strcat(response, "</serviceList>\r\n");
					strcat(response, "</device>\r\n");
					strcat(response, "</root>");

					// build Http packet
					strcpy(packet, "HTTP/1.1 200 OK\r\n");
					strcat(packet, "SERVER: Unspecified,UPnP,Unspecified\r\n");
					strcat(packet, "LAST-MODIFIED: 12-12-18\r\n");

					// get the length of the payload
					sprintf(tag, "CONTENT-LENGTH: %d\r\n", strlen(response)); // get the length as a string
					strcat(packet, tag);
					strcat(packet, "CONTENT-TYPE:text/xml\r\n");
					strcat(packet, "CONNECTION:close\r\n\r\n");
					// add the response payload
					strcat(packet, response);
					/* send */
					if (verbose_mode == 1) {
						printf("%s: Sending:\n %s\n", devicename, packet);
					}
					int cnt = send(child_fd, packet, strlen(packet), 0);
					printf("%s: Response sent\n", devicename);
					if (cnt < 0) {
						printf("%s: Error on sendto\n", devicename);
						close(child_fd);
						exit(1);
					}
				}
				// check for inbound post request
				
					// Parse the received request
					strcpy(tag, "GetBinaryState");
					p = strstr(msgbuf, tag);
					if (p > 0) {
						// we've found get binary state
						// need to respond with state packet
						printf("%s: Get State Requested\n", devicename);

						strcpy(response, "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" ");
						strcat(response, "s:encodingStyle = \"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>");
						strcat(response, "<u:GetBinaryStateResponse xmlns:u=\"urn:Belkin:service:basicevent:1\">");
						device_state = digitalRead(pin);
						if (device_state == 0) {
							device_state = 1;
						}
						else {
							device_state = 0;
						}
						// read the device state
						sprintf(tag, "<BinaryState>%d</BinaryState>", device_state);
						strcat(response, tag);
						strcat(response, "</u:GetBinaryStateResponse></s:Body></s:Envelope>\r\n\r\n");

						// build full response
						strcpy(packet, "HTTP/1.1 200 OK\r\n");
						strcat(packet, "SERVER: Unspecified,UPnP,Unspecified\r\n");
						strcat(packet, "LAST-MODIFIED: 12-12-18\r\n");

						// get the length of the payload
						sprintf(tag, "CONTENT-LENGTH: %d\r\n", strlen(response)); // get the length as a string
						strcat(packet, tag);
						strcat(packet, "CONTENT-TYPE:text/xml  charset=\"utf-8\"\r\n");
						// strcat(packet, "CONNECTION:close\r\n");
						strcat(packet, "\r\n");								// End the headers with double CRLF
																			// add the response payload
						strcat(packet, response);
						/* send */
						if (verbose_mode == 1) {
							printf("sending:\n%s", packet);
						}
						int cnt = send(child_fd, packet, strlen(packet), 0);
						if (cnt < 0) {
							printf("error on sendto");
						
							close(child_fd);
							exit(1);
						}
					}

					strcpy(tag, "SetBinaryState");
					p = strstr(msgbuf, tag);
					if (p > 0) {   // need to Set binary state
						strcpy(tag, "<BinaryState>");
						p = strstr(msgbuf, tag);
						if (p > 0) {
							// we've found binary state
							char state = *(p + strlen(tag));  // get the state
							printf("state requested: %c \n", *(p + strlen(tag)));
							// set the pins based on the state reveived
							if (state == 0x30) {
								device_state = 0;

								digitalWrite(pin, HIGH);			// Relay card is inverted
								printf("%s:Binary State Set to 0\n", devicename);
							}
							if (state == 0x31) {
								device_state = 1;

								digitalWrite(pin, LOW);	// Relay card is inverted
								printf("%s:Binary State Set to 1\n", devicename);
							}
						}

						strcpy(response, "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" ");
						strcat(response, "s:encodingStyle = \"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>");
						strcat(response, "<u:SetBinaryStateResponse xmlns:u=\"urn:Belkin:service:basicevent:1\">");
						// read the device state
						sprintf(tag, "<BinaryState>%d</BinaryState>", device_state);
						strcat(response, tag);
						strcat(response, "</u:SetBinaryStateResponse></s:Body></s:Envelope>\r\n\r\n");
						// build full response
						strcpy(packet, "HTTP/1.1 200 OK\r\n");
						strcat(packet, "SERVER: Unspecified,UPnP,Unspecified\r\n");
						strcat(packet, "LAST-MODIFIED: 12-12-18\r\n");
						strcat(packet, "ETag:\"10000000565a5-2c-3e94b66c2e680\"\r\n");
						strcat(packet, "Accept-Ranges: bytes\r\n");
						// get the length of the payload
						sprintf(tag, "CONTENT-LENGTH: %d\r\n", strlen(response)); // get the length as a string
						strcat(packet, tag);
						strcat(packet, "CONTENT-TYPE:text/xml\r\n");
						strcat(packet, "CONNECTION:close\r\n");
						strcat(packet, "\r\n");
						// add the response payload
						strcat(packet, response);
						/* send */
						if (verbose_mode == 1) {
							printf("%s: sending: %s\n", devicename, packet);
						}
						int cnt = send(child_fd, packet, strlen(packet), 0);
						if (cnt < 0) {
							printf("%s: Error on sendto\n", devicename);
							close(child_fd);
							exit(1);
						}

					}
				
			}
			close(child_fd);
			_exit(0);
		}
		else {
			// we're in the parent process
			close(child_fd);
		}

	// end of server While loop - go back and receive another client
	}
	
}

// SSDP DAEMON
// myaddress: local IP address to add to SSDP response packets
// verbose mode: 1= print all packets sent and received
int ssdp_main(char myaddress[TAGLEN], int verbose_mode)
{
	// this is the ssdp daemon process that is launched after the child processes have been spawned
	int ret;						// used for return status etc
	char response[1024];
	char group[TAGLEN];
	char tag[TAGLEN];
	strcpy(group, "239.255.255.250");	// e.g. 239.255.255.250 for SSDP
	int port = 1900;					// port for sdiscovery 1900 
	char msgbuf[MSGBUFSIZE];			// our message buffer 
	int i = 0;							// general loop index

										// create ordinary UDP socket
	int fd = socket(AF_INET, SOCK_DGRAM, 0); // ordinary datagram socket
	if (fd < 0) {
		printf("SSDP: Socket create failed\n");
		return 1;
	}
	printf("Socket Created\n");
	// allow multiple sockets to use the same PORT number
	u_int yes = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes)) < 0)
	{
		printf("SSDP: Reusing ADDR failed\n");
		return 1;
	}

	// set up destination address
	struct sockaddr_in addr;		// our local socket address
	memset(&addr, 0, sizeof(addr));  // clear it out
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY); // any inbount address
	addr.sin_port = htons(port);
	printf("SSDP: Address set\n");

	// bind to receive address
	if (bind(fd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
		printf("bind error\n");
		return 1;
	}
	printf("SSDP: Socket Bound\n");

	// use setsockopt() to request that the kernel join a multicast group
	struct ip_mreq mreq;
	mreq.imr_multiaddr.s_addr = inet_addr(group);
	mreq.imr_interface.s_addr = inet_addr(myaddress);
	//mreq.imr_ifindex = 0;
	if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
	{
		printf("setsockopt error\n");
		return 1;
	}
	printf("SSDP Listening...\n");
	// now just enter a read-print loop
	//
	addr.sin_addr.s_addr = inet_addr(group);
	while (1) {

		int addrlen = sizeof(addr);
		int nbytes = recvfrom(
			fd,
			msgbuf,
			MSGBUFSIZE,
			0,
			(struct sockaddr *) &addr,
			&addrlen
		);
		if (nbytes < 0) {
			printf("Error in recvfrom");
			return 1;
		}
		msgbuf[nbytes] = '\0';

		if (verbose_mode == 1) {
			printf("\nSSDP: Received Datagram:%s\n", msgbuf);

		}

		// need to process message
		/*Received Datagram:
		M-SEARCH * HTTP/1.1
		Host: 239.255.255.250:1900
		Man: "ssdp:discover"
		MX: 3
		ST: ssdp:all
		*/
		strcpy(tag, "M-SEARCH");

		// check the first 6 bytes
		ret = strncmp(tag, msgbuf, 6);

		if (ret == 0) {								// datagram is a M-SEARCH 
			printf("\nReceived Search Datagram:\n");
			if (verbose_mode == 1) {
				puts(msgbuf);
			}
			printf("SSDP: Sending responses: ");
			// need to loop through device responses
			for (i = 0; i < NUMDEVICES; i++) {
				// build response message 
				strcpy(response, "HTTP/1.1 200 OK \r\nCACHE-CONTROL: max-age=86400\r\n");
				strcat(response, "DATE: Mon, 22 Jun 2015 17 : 24 : 01 GMT\r\n");
				strcat(response, "EXT:\r\n");
				// code the port number
				sprintf(tag, "LOCATION: http://%s:%d/setup.xml\r\n", myaddress, PORTBASE + i);
				strcat(response, tag);
				strcat(response, "OPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n");
				strcat(response, "01-NLS: 905bfa3c-1dd2-11b2-8928-fd8aebaf491c\r\n");
				strcat(response, "SERVER: Unspecified, UPnP/1.0, Unspecified\r\n");
				strcat(response, "X-User-Agent: redsonic\r\n");
				strcat(response, "ST: urn:Belkin:device:**\r\n");
				// code the USN
				sprintf(tag, "USN: uuid:Socket-1_0-%d::urn:Belkin:device:**\r\n", PORTBASE + i);
				strcat(response, tag);

				if (verbose_mode == 1) {
					printf("SSDP: sending: %s\n", response);
				}
				// Send one per device
				int cnt = sendto(fd, response, strlen(response), 0, (struct sockaddr *) &addr, addrlen);
				if (cnt < 0) {
					printf("SSDP: Error on sendto");
					exit(1);
				}
				printf("%d ", i);
				usleep(100000);			// wait 100ms
			}
			printf("\n");
		}
	}
	return 0;
}

// returns the number of interfaces found and a char array of their IPs and names
int get_if_ips(char ifaddresses[MAXIF][NAMELEN])
{
	int    iSocket = -1;
	struct if_nameindex* pIndex = 0;
	struct if_nameindex* pIndex2 = 0;
	int i = 0;
	printf("Getting Local Interface IP Addresses\n");

	// open a socket to let us ask details about the IP Stack
	if ((iSocket = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
	{
		perror("socket");
		return -1;
	}

	pIndex = pIndex2 = if_nameindex();
	// loop through the interfaces
	while ((pIndex != NULL) && (pIndex->if_name != NULL) && (i<MAXIF))
	{
		struct ifreq req;
		printf("%d: %s\n", pIndex->if_index, pIndex->if_name);
		strncpy(req.ifr_name, pIndex->if_name, IFNAMSIZ);

		if (ioctl(iSocket, SIOCGIFADDR, &req) < 0)
		{
			if (errno == EADDRNOTAVAIL)
			{
				printf("\tN/A\n");
				++pIndex;
				continue;
			}
			perror("Get IP Address ioctl error\n");
			close(iSocket);
			return -1;
		}

		printf("\t %s\n", inet_ntoa(((struct sockaddr_in*)&req.ifr_addr)->sin_addr));
		sprintf(ifaddresses[i], "%s", inet_ntoa(((struct sockaddr_in*)&req.ifr_addr)->sin_addr));

		++pIndex;
		++i;
	}

	if_freenameindex(pIndex2);
	close(iSocket);
	return i;
}

// Present and handle web page interactions
// 
int devicewebSite(int port, char friendly[NUMDEVICES][NAMELEN], int gpioPin[NUMDEVICES], int verbose_mode)
{
	// Setup Variables
	int ret;							// used for return status etc
	int device_state = 0;				// state of the device 1 = on 0 = off -1 = disconnected
	char msgbuf[MSGBUFSIZE];			// inbound message buffer 
	char packet[MSGBUFSIZE];				// outbound packet buffer
	char response[MSGBUFSIZE - 256];		// buffer for payload
	int child_id;							// file descriptor for inbound socket
	char tag[TAGLEN];						// Tag to search for
	char *p;								// pointer for general use 
	int nbytes;								// number of bytes sent or received
	int pinState[NUMDEVICES];				// Holder for the shared gpio state

	int fd = socket(AF_INET, SOCK_STREAM, 0); // create a TCP socket
	if (fd < 0) {
		printf("Webserver: socket create failed\n");
		return 1;
	}

	// allow multiple sockets to use the same PORT number
	u_int yes = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes)) < 0) {
		printf("Web Server: Reusing ADDR failed\n");
		return 1;
	}

	// set up destination address
	struct sockaddr_in addr;		// our local socket address
	memset(&addr, 0, sizeof(addr));  // clear it out
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY); // any inbount address
	addr.sin_port = htons(port);

	// bind to receive address
	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		printf("Webserver: bind error - Port in use?\n");
		return 1;
	}

	// use listen to make the socket ready for connections
	if (listen(fd, 1) < 0)                 // aparently allows 1 requests to queue
	{
		printf("Webserver:listen error\n");
		close(fd);
		return 1;
	}
	printf("Webserver: Listening on port:%d...\n", port);
	// now just enter a loop
	while (1) {
		int addrlen = sizeof(addr);

		// try to accept a connection
		child_id = accept(fd, (struct sockaddr *) &addr, &addrlen);
		if (child_id < 0) {
			printf("Webserver: Error on accept\n");
			close(fd);
			return 1;
		}

		memset(&msgbuf, 0, sizeof(msgbuf));// zero the buffer

		nbytes = recv(
			child_id,
			msgbuf,
			sizeof(msgbuf),
			0
		);// read in a packet

		if (nbytes < 0) {
			printf("Webserver: Error in receive");
			close(fd);
			close(child_id);
			return 1;
		}

		if (verbose_mode == 1) {
			printf("\n%Webserver: Received Datagram:");
			msgbuf[nbytes] = '\0';
			puts(msgbuf);
		}
		// check for inbound post request
		strcpy(tag, "POST ");
		ret = strncmp(tag, msgbuf, 4);
		if (ret == 0) {
			printf("\nWebserver: Received Web Post request:\n");
			msgbuf[nbytes] = '\0';
			// THIS IS WHERE I GOT TO **************
			puts(msgbuf);

			if (verbose_mode == 1) {
				puts(msgbuf);
			}
			// Parse the received request

			strcpy(tag, "toggle");
			p = strstr(msgbuf, tag);
			if (p > 0) {								// we have a toggle request
														// get the socket number
														// Toggle the associated state
				char pc = *(p + strlen(tag));			// get the char after the command
				int  pi = pc - '0';						// convert to int

														// check that device is valid
				if (pi<0 || pi>(NUMDEVICES - 1)) {
					printf("Invalid Device number %d \n", pi);
				}
				else {
					int pin = gpioPin[pi];
					printf("Toggle state of pin: %d GPIO: %d \n", pi, pin);
					if (pinState[pi] == 0) {
						pinState[pi] = 1;
						digitalWrite(pin, HIGH);		// Relay card is inverted
					}
					else {
						pinState[pi] = 0;
						digitalWrite(pin, LOW);			// Relay card is inverted
					}
					// list new states
					for (int j = 0; j < NUMDEVICES; j++) {
						int k = digitalRead(gpioPin[j]);
						printf("Socket: %d  State:%d\n", j, k);
					}
				}
			}
		}

		// check the first 6 bytes for a setup request
		strcpy(tag, "GET /");
		ret = strncmp(tag, msgbuf, 3);
		//if (ret == 0) {								// datagram is a M-SEARCH 
		printf("Webserver: Webpage request:\n");
		msgbuf[nbytes] = '\0';
		if (verbose_mode == 1) {
			puts(msgbuf);
		}
		// refresh the pinstate array from the GPIO
		for (int i = 0; i < NUMDEVICES; i++) {
			pinState[i] = digitalRead(gpioPin[i]);
		}
		/*
		// Build the HTTP payload into a response
		*/
		// setup the start of the HTML content
		strcpy(response, "<body><p> Pi Controller </p>");
		strcat(response, "<form action = \"socket\" method=\"POST\">");
		// Loop Through adding the HTML for the buttons
		for (int i = 0; i < NUMDEVICES; i++) {
			// Pinstate is inverted
			if (pinState[i] == 0) {
				sprintf(tag,
					"<p><button type='submit' name='toggle%d' style='background-color:red' value='1'> %s</button></p>\r\n",
					i,
					friendly[i]
				);
			}
			else {

				sprintf(tag,
					"<p><button type='submit' name='toggle%d' style='background-color:green' value='0'> %s</button></p>\r\n",
					i,
					friendly[i]
				);
			}
			strcat(response, tag);
		}
		// and tail the page
		strcat(response, "</form></body>\r\n");

		// build Http packet
		strcpy(packet, "HTTP/1.1 200 OK\r\n");
		strcat(packet, "SERVER: Unspecified,UPnP,Unspecified\r\n");
		strcat(packet, "LAST-MODIFIED: 12-12-18\r\n");
		// get the length of the payload
		sprintf(tag, "CONTENT-LENGTH: %d\r\n", strlen(response)); // get the length as a string
		strcat(packet, tag);
		strcat(packet, "CONTENT-TYPE:text/html\r\n");
		strcat(packet, "CONNECTION:close\r\n\r\n");
		// add the response payload
		strcat(packet, response);
		/* send */
		if (verbose_mode == 1) {
			printf("Webserver: Sending:\n %s", packet);
		}
		int cnt = send(child_id, packet, strlen(packet), 0);
		printf("Webserver: Response sent\n");
		if (cnt < 0) {
			printf("Webserver: Error on sendto\n");
			close(fd);
			close(child_id);
			exit(1);
		}

		close(child_id);
	}
	close(fd);	// close our connection
	return 0;
}



int main(int argc, char *argv[])
{
	// deal with any arguments
	// -v is verbose mode
	int verbose_mode = 0;			// extended reporting
	int watch_mode = -1;			// port to watch
	if (argc > 1) {
		char* arg1 = argv[1];	// get any args 
		if (strncmp(arg1, "-v", 2) == 0) {		// verbose mode check
			verbose_mode = 1;
		}
		if (strncmp(arg1, "-w1", 3) == 0) {		// watch port 1
			watch_mode = 1;
		}
		if (strncmp(arg1, "-w0", 3) == 0) {		// watch port 0
			watch_mode = 0;
		}
	}
	// Local Variables
	int i = 0;  // generic index
	int root_flag = 1; // mark that this is the root process
	int ret = 0;			// general returns from calls
	int ifcount = 0;						// number of local interfaces
	char ifaddresses[MAXIF][NAMELEN];			// table of local machine interface addresses
	char myaddress[TAGLEN];						// my local IP address as a string
												// table of devices
	char friendly[NUMDEVICES][NAMELEN];			// friendly name of the device as alexa will know it
	int port[NUMDEVICES];					// port numbers of the child processes
	int pid[NUMDEVICES];					// process handles for the child devices
	int gpioPin[NUMDEVICES];				// GPIO Pin assignments per device
											// Load device table
	ret = setup_names(friendly);					// load the friendly name
	wiringPiSetup();				// setup GPIO 

	for (i = 0; i < NUMDEVICES; i++) {

		port[i] = PORTBASE + i;
		gpioPin[i] = i;
		pinMode(i, OUTPUT);			// set our pin to output
	}
	// Get the local interface address
	ifcount = get_if_ips(ifaddresses);
	if (ifcount > 0) {
		printf("Found %d interfaces \n", ifcount);

		for (i = 0; i < ifcount; i++) {
			printf("Address:%s\n", ifaddresses[i]);
		}
		strcpy(myaddress, ifaddresses[ifcount - 1]);		// get the last address on the list
															// Start the devices
															// these are a series of forked processes, one per device
		for (i = 0; i < NUMDEVICES; i++) {
			printf("Root: Spawning \"%s\" on %s port:%d gpio pin:%d\n", friendly[i], myaddress, port[i], gpioPin[i]);
			int newpid = fork();				// Fork a new process here each loop - we'll end up with one child process per device
			if (newpid == 0) {
				// printf("This is being printed from the child process\n");
				root_flag = 0; // we're a child so flag is false
				printf("Child %d: Starting \"%s\" on port %d\n", i, friendly[i], port[i]);
				if (watch_mode == i) {
					verbose_mode = 1;
				}
				ret = device(port[i], friendly[i], verbose_mode, gpioPin[i]);
				printf("*** Child %d ended !!\n", i);
				i = NUMDEVICES + 1;	// We're a child process so Force the loop to end
			}
			else {
				// printf("This is being printed in the parent process:\n");
				pid[i] = newpid;
				printf("Root: - the process identifier (pid) of child: %d is: %d\n", i, newpid);
			}
			usleep(500000);			// wait 500ms between device starts
		}
		if (root_flag == 1) {
			// We're still in the root process
			printf("Root: All devices started\n");

			// We need to start both the SSDP and Web Site sub-processes
			int lastpid = fork();
			if (lastpid == 0) {
				// child
				// Start the ssdp responder
				ret = ssdp_main(myaddress, verbose_mode);   // jump to the ssdp responder
				printf("SSDP RESPONDER EXITED!");
			}
			else {
				// padre
				// Inicie el controlador del sitio Web
 ret = devicewebSite(WEBPORT, friendly, gpioPin, verbose_mode);  // saltar al código del servidor web
				printf(" WebServer RESPONDER EXITED!" );
			}
		}
		retorno 1;  // fin del código
	}
	más {
		printf("No se han encontrado interfaces \n" );
		volver -1;
	}
}



// V0,99
// depuración de registro de un solo dispositivo - DONE
// Obtener la dirección IP local - HECHO (utiliza la última IP en la lista, aunque)
// Agregar controles GPIO - DONE
// Informes más estrictos - HECHO
// Adición de sitio web - Hecho
// Botones de envío de alternancia - Hecho
// Respuesta a la alternancia - Hecho
// colores de los botones - Hecho
// Los nombres de los botones parecen cambiar - Hecho - Punteros incorrectos corregidos
// necesita rutina de salida para matar a PIDS infantil
// Depuración de respuestas de Alexa rotas - Hecho - estados de dispositivo invertidos para relés
// necesidad de bifurcar los procesos de aceptación - Hecho
// Home Assistant envía solicitudes como dos paquetes TCP
//
