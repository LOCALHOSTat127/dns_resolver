/*
    DATA -: Sun-Feb 12 : 2023.
    Written-by -: 7HI2n9hsl02hHL@proton.me

    Purpose - : Basic DNS Client to query Standard record types.

    NOTE -: Google's public DNS server is being used along with some Fallback DNS servers.
    [SERVER-1][8.8.8.8][google-dns]
    [SERVER-2][8.8.4.4][google-dns]


    --> Compiled informaton.
        compiled-on -: minGW.
*/

// Importing Socket Related Header.
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include<unistd.h>


// Importing Basic I/O & utility headers.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include<ctype.h>


// userdefine typedefs using #define
#define SOCKET int
#define CLIENT_INIT main



// utility functions for socket handling.
#define ISVALIDSOCKET(s) (s >= 0)
#define GETSOCKERRNO() (errno)
#define CLOSESOCKET(s) (close(s))



// remote DNS server configuration.
#define SERVER_PORT "53"
#define SERVER_IP "8.8.8.8"
#define FALLBACK_SERVER_IP "8.8.4.4"



// Default-settings.
#define STANDARD_HEADER_SIZE 12 // Bytes
#define PAYLOAD_SIZE 512         // Bytes
#define RECEVE_BUFFER_SIZE 512


// utils-variables.
unsigned char recordType;
char recordName[20];
unsigned int OUT_QUERY_SIZE;
char SERVER_IN_USE[40];
int QUERY_STEPS;




// utility-functions signature.
int validateInput(const int nInput, char **argumentsArr);
void parseInput(char *DNS_QUERY_TEMPLATE, char *query);
void mymemset(void *ptr, const int value, const int size);
struct addrinfo* configureRemoteHost();
void sendQuery(char* DNS_QUERY,struct addrinfo* DNSCONFIGPTR,char **query);
void processResponse(unsigned char *DNS_RESPONSE,int RESPONSE_SIZE);
void hexToBin(const unsigned char* hex_stream,const int nSize,int* bin_stream);



struct DNS_answer{
    short int class;
    short int type;
    int TTL;
    short int rSize;
    int ip[5];
        
    // pointer in case has more than one response.
    struct DNS_answer *Next;
};



typedef struct DNSresponse{
    // response header flags.
    short int isValidResponse;
    short int OPCODE;
    short int isAutherativeServer;
    short int isTruncated;
    short int isRecurssionAvailable;
    short int isRecurssionDesired;
    short int isResponseAuthencated;
    short int isAuthRequired;
    short int responseCode;


    // counters.
    short int QACOUNT;
    short int ANSCOUNT;
    short int NSCOUNT;
    short int ARCOUNT;


    // answer section
    struct DNS_answer *answers;




}DNSresponseStruct;






// ================================================= Main-end-point Function-flow-start ==========================================
int CLIENT_INIT(int argc, char *argv[]){

    // Validating user-input.
    if (validateInput(argc, argv) != 0){
        // exit programm if user has provided invalid inputs.
        // EXIT-CODE-1.
        exit(1);
    }




    // Standard DNS_QUERY Header Template.
    // HEADER_SIZE -: is set the be 12 bytes & shouldn't be changed.
    // PAYLOAD_SIZE -: is set to Default & can be increased or decreased as needed.
    char DNS_QUERY_TEMPLATE[STANDARD_HEADER_SIZE + PAYLOAD_SIZE] = {
        0xAB, 0XCD, // ID
        0x01, 0x00, // Header
        0x00, 0x01, // Question - Count
        0x00, 0x00, // Answer - Count
        0x00, 0x00, // Nameserver - Count
        0x00, 0x00  // Additional - Count
    };

    


    // Parseinput create DNS-Query.
    // Building query by adding label_length & label in DNS_query.
    // Also adding recordType & Class.
    parseInput(DNS_QUERY_TEMPLATE, argv[1]);



    // DNSCONFIGPTR -: Temp pointer to hold DNS_SERV config.(will be freed after use).
    // Sending Query & wating to get response.
    struct addrinfo *DNSCONFIGPTR = configureRemoteHost();
    if(DNSCONFIGPTR != NULL){
        sendQuery(DNS_QUERY_TEMPLATE,DNSCONFIGPTR,argv);
    }


    


    // PROGRAMM-EXIT-CODE = 0 == SUCCESS.
    return 0;
}
















// ======================= Utility-worker-functions===================================================================

// Parsing Input-domain-name & building DNS-Query.
void parseInput(char *DNS_QUERY_TEMPLATE, char *query){
    // Default Query Starting Point.
    int QUERY_START_INDEX = STANDARD_HEADER_SIZE;

    unsigned short int LableLength = 0;
    char LabelStorage[255] = {0};
    unsigned int QueryPointer = 0;
    unsigned int LoopCounter = 0;
    unsigned int InnerLoopCounter = 0;



    while (query[QueryPointer]){
        if (query[QueryPointer] != 46){
            // Updating LabelStorage char-array.
            LabelStorage[LoopCounter] = query[QueryPointer];

            // Updating LoopCounter & LabelLength(Size of query)
            LoopCounter++;
            QueryPointer++;
            LableLength++;

            // NOTE -: Adding chars into LabelStorage till hit ('.' === 46)
            // --> Updating LabelLength to store Label-Size.
            // --> Size & LableStorage would be put into DNS-Query.
        }
        else{
            // Semi-Breakpoint : Hit the ('.' === 46) char in the query.
            // Step-1 -: Store CurrentLableLangth into Dns-query & update currentPointer.
            // Step-2 -: Copy Temp-LabelStorage into DNS-Query untill string ends ('\0').
            // Step -:   Reset Counters & Run Loop till Original Query Ends ('\0').

            // Putting NULL char to LabelStorage so it doesn't loop over forever.
            LabelStorage[LoopCounter] = '\0';

            // copying LableLength to Query & Updating pointer.
            DNS_QUERY_TEMPLATE[QUERY_START_INDEX++] = LableLength;

            // copying LableStorage into Query.
            while (LabelStorage[InnerLoopCounter]){
                DNS_QUERY_TEMPLATE[QUERY_START_INDEX++] = LabelStorage[InnerLoopCounter++];
            }

            // Reseting Counters.
            QueryPointer++;
            LoopCounter = 0;
            LableLength = 0;
            InnerLoopCounter = 0;
            memset(LabelStorage, 0, sizeof(LabelStorage));
        }
    }

    // Copying Remaning chars into DNS-Query.
    LabelStorage[LoopCounter] = '\0';
    DNS_QUERY_TEMPLATE[QUERY_START_INDEX++] = LableLength;
    while (LabelStorage[InnerLoopCounter]){
        DNS_QUERY_TEMPLATE[QUERY_START_INDEX++] = LabelStorage[InnerLoopCounter++];
    }

    // here...
    // QUERY_STEPS =  STANDARD_HEADER_SIZE + QUERY_START_INDEX + 1;


    DNS_QUERY_TEMPLATE[QUERY_START_INDEX++] = 0; // Padding
    DNS_QUERY_TEMPLATE[QUERY_START_INDEX++] = 0;
    DNS_QUERY_TEMPLATE[QUERY_START_INDEX++] = recordType;
    DNS_QUERY_TEMPLATE[QUERY_START_INDEX++] = 0;
    DNS_QUERY_TEMPLATE[QUERY_START_INDEX++] = 1;

  

    OUT_QUERY_SIZE = QUERY_START_INDEX;
}




// Validating Input
int validateInput(const int nInput, char **argumentsArr){
    // checking user-input
    if (nInput < 3 || nInput > 3){
        // IF user has not given hostname
        // IF user has not given record-type.
        fprintf(stderr, "Usage   : Hostname Record-type\n");
        fprintf(stderr, "Example : [example.com] [A]\n");
        return -1;
    }

    // checking length of domain-name
    // since cannot be > 255
    if (strlen(argumentsArr[1]) > 255){
        // IF hostname length is > 255
        fprintf(stderr, "ERR : Hostname length cannot be greather than 255.\n");
        return -2;
    }

    // validating record-type.
    if (strcmp(argumentsArr[2], "A") == 0){
        recordType = 1;
        strcpy(recordName,"IPV4");
    }
    else if (strcmp(argumentsArr[2], "AAAA") == 0){
        recordType = 28;
        strcpy(recordName,"IPV6");
    }
    else if (strcmp(argumentsArr[2], "MX") == 0){
        recordType = 15;
        strcpy(recordName,"Mail-Exchange");
    }
    else if (strcmp(argumentsArr[2], "TXT") == 0){
        recordType = 16;
        strcpy(recordName,"Text");
    }
    else if (strcmp(argumentsArr[2], "ANY") == 0){
        fprintf(stderr, "ERR :  This type of query is not supported At this time.\n");
        return -3;
        // recordType = 255;
    }
    else{
        // IF user has provided undecleared record-type.
        fprintf(stderr, "ERR : Record-type is not valid Usage : \n");
        fprintf(stderr, "(1).  A = IPV4\n(2). AAAA = IPV6\n(3). MX = MailExchange\n(4). TXT = TextRecord\n(5). ANY = AnyTypes\n");
        return -4;
    }

    return 0;
}




// setting-up remote host.
struct addrinfo* configureRemoteHost(){
    // configuring remote-dns-server
    struct addrinfo hints;
    struct addrinfo *DNS_SERVER;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICHOST;

    if (getaddrinfo(SERVER_IP, SERVER_PORT, &hints, &DNS_SERVER) != 0){

        fprintf(stderr, "ERR  :  Remote SERVER cannot be configured...\n");
        fprintf(stderr, "[*] :  Trying fallback server [8.8.4.4]...\n");

        // clearing-up addrinfo buffers to 0.
        mymemset(&hints, 0, sizeof(hints));

        // Trying to resolve fallback server.
        if (getaddrinfo(FALLBACK_SERVER_IP, SERVER_PORT, &hints, &DNS_SERVER) == 0){
            strcpy(SERVER_IN_USE,FALLBACK_SERVER_IP);
            return DNS_SERVER;
        }
        else{
            fprintf(stderr, "ERR : Fallback server configuration failed...\n");
            exit(1);
        }
    }
    else{
        // Primary server configured.
        strcpy(SERVER_IN_USE,SERVER_IP);
        return DNS_SERVER;
    }
}




// Memset-function to 0-out buffers.
void mymemset(void *ptr, const int value, const int size){
    int temp = 0;
    while (temp < size){
        *((char *)(ptr + temp++)) = value;
    }
}





// Sending query & handling response.
void sendQuery(char* DNS_QUERY,struct addrinfo* DNSCONFIGPTR,char **query){
    // IMPORTANT - : Please make sure to free-up the DNSCONFIGPTR
    // To prevent any memory-leaks.
    // use freeaddrinfo(DNSCONFIGPTR) to free-up memory.


    // Buffers to hold hostname & service.
    char remoteHost[100] = {0};
    char remoteHostService[100] = {0};
    unsigned char receveBuffer[RECEVE_BUFFER_SIZE];
    int bytesSent;
    int bytesReceived;




    // Creating clientSocket
    SOCKET clientSocket = socket(DNSCONFIGPTR->ai_family,DNSCONFIGPTR->ai_socktype,DNSCONFIGPTR->ai_protocol);

    if(!ISVALIDSOCKET(clientSocket)){
        fprintf(stderr,"ERR :  Socket creation failed (%d).\n",GETSOCKERRNO());
        exit(1);
    }

    sleep(1);
    // SUCCESS - clientSocket created.
    printf("[*] :  ClientSocket created...\n");
    

    // getting hostname & servicename
    getnameinfo(DNSCONFIGPTR->ai_addr,DNSCONFIGPTR->ai_addrlen,
                remoteHost,sizeof(remoteHost),
                remoteHostService,sizeof(remoteHostService),
                NI_NAMEREQD | NI_NUMERICSERV);
    


    sleep(2);
    printf("[*] :  Trying to Connect...  %s@%s\n",(strlen(remoteHost) == 0 ?  SERVER_IN_USE : remoteHost),
                                                 (strlen(remoteHostService) == 0 ? SERVER_PORT : remoteHostService));

    

    sleep(2);
    printf("[*] :  DNS-Server connection success...\n");




    sleep(1);
    // sending DNS-Query
    printf("[*] :  Sending Query...\n");
    int temp = 0;



    // Sending-query
    bytesSent = sendto(clientSocket,DNS_QUERY,OUT_QUERY_SIZE,0,DNSCONFIGPTR->ai_addr,DNSCONFIGPTR->ai_addrlen);


  


    
    
    // IF-ERR (bytesSent == -1).
    if(bytesSent == -1){
        fprintf(stderr,"ERR : Query cannot be sent (%d).",GETSOCKERRNO());
        exit(1);
    }else{
        printf("[*] :  Sent %d Bytes...\n",bytesSent);
        printf("   -|--------------------------------|-\n");
        printf("   -|             %s             |-\n","0xABCD");
        printf("   -|--------------------------------|-\n");
        printf("   -| QR:%d | OPCODE:%d | RD:%d | AR:%d  |\n",0,0,1,0);
        printf("   -|--------------------------------|-\n");
        printf("   -|           QACOUNT :%d           |-\n",1);
        printf("   -|--------------------------------|-\n");
        printf("   -|           ANCOUNT :%d           |-\n",0);
        printf("   -|--------------------------------|-\n");
        printf("   -|           NSCOUNT :%d           |-\n",0);
        printf("   -|--------------------------------|-\n");
        printf("   -|           ARCOUNT :%d           |-\n",0);
        printf("   -|--------------------------------|-\n\n");
        printf("    Query -: %s\n",query[1]);
        printf("    RecordType -: %s\n",recordName);
        sleep(2);
        printf("[*] :  waiting for response...\n");
    }

    
    bytesReceived = recvfrom(clientSocket,&receveBuffer,RECEVE_BUFFER_SIZE,0,0,0);
    printf("[*] :  Received %d Bytes...\n",bytesReceived-1);



    // Processing-response & showing up on cli.
    processResponse(receveBuffer,bytesReceived);

    
    // free-up memory DNSCONFIGPTR.
    freeaddrinfo(DNSCONFIGPTR);

}

int binToDec(int* bin_stream,const int nSize){
    int decimal = 0;
    int startExpo = 1;

    for(int i=(nSize-1); i >=0; i--){
        // printf("%d ",bin_stream[i]);
        if(startExpo == 1){
            decimal += (bin_stream[i]*startExpo);
            startExpo++;
        }else{
             decimal += (bin_stream[i]*startExpo);
             startExpo *= 2;
        }
    }


    return decimal;
}


void findNlist(struct DNS_answer* NewNode,struct DNS_answer** Head){
    struct DNS_answer* Temp =  *Head;

    if(Temp == NULL){
        *Head = NewNode;
        return;
    }

   

    while(Temp->Next != NULL){
        Temp =  Temp->Next;
    }

    Temp->Next = NewNode;
    NewNode->Next = NULL;

}




void processResponse(unsigned char *DNS_RESPONSE,const int RESPONSE_SIZE){

    

    // validating response size.
    if(RESPONSE_SIZE < 12){
        fprintf(stderr,"ERR : Response is Broken\n");
        exit(1);
    }


    // validating response flags.
    char hex_stream[] = {DNS_RESPONSE[2],DNS_RESPONSE[3]};
    int hex_stream_size = sizeof(hex_stream)/sizeof(hex_stream[0]);
    int bin_stream_size =  (hex_stream_size*8)+1;
    int bin_stream[bin_stream_size];
    hexToBin(hex_stream,hex_stream_size,bin_stream);


    // dns-response storage.
    DNSresponseStruct DNS_RESPONSE_;
    mymemset(&DNS_RESPONSE_,0,sizeof(DNS_RESPONSE_));



    // response flags
    DNS_RESPONSE_.isValidResponse = bin_stream[0];
    
    int temparr[] = {bin_stream[1],bin_stream[2],bin_stream[3],bin_stream[4]};
    DNS_RESPONSE_.OPCODE =  binToDec(temparr,sizeof(temparr)/sizeof(temparr[0]));
    
    DNS_RESPONSE_.isAutherativeServer = bin_stream[5];
    DNS_RESPONSE_.isTruncated = bin_stream[6];
    DNS_RESPONSE_.isRecurssionAvailable = bin_stream[7];
    DNS_RESPONSE_.isRecurssionDesired = bin_stream[8];
    DNS_RESPONSE_.isResponseAuthencated = bin_stream[10];
    DNS_RESPONSE_.isAuthRequired = bin_stream[11];

    int temparr_[] = {bin_stream[12],bin_stream[13],bin_stream[14],bin_stream[15]};
    DNS_RESPONSE_.responseCode = binToDec(temparr_,sizeof(temparr_)/sizeof(temparr_[0]));

    
    // counter.
    DNS_RESPONSE_.QACOUNT = DNS_RESPONSE[4] + DNS_RESPONSE[5];
    DNS_RESPONSE_.ANSCOUNT = DNS_RESPONSE[6] + DNS_RESPONSE[7];
    DNS_RESPONSE_.NSCOUNT = DNS_RESPONSE[8] + DNS_RESPONSE[9];
    DNS_RESPONSE_.ARCOUNT = DNS_RESPONSE[10] + DNS_RESPONSE[11];





    QUERY_STEPS = 11;
    // skipping over the query section and padding and type + class.
    int currentCounter = (QUERY_STEPS + 11 + 2 + 4);
    DNS_RESPONSE_.answers = NULL;
    

    for(int i=0; i<DNS_RESPONSE_.ANSCOUNT; i++){
        struct DNS_answer* newNode = (struct DNS_answer*)malloc(sizeof(struct DNS_answer));
        if(newNode == NULL){
            fprintf(stderr,"Err : Memory allocation failed\n");
            exit(1);
        }

        // linking new node to List.
        findNlist(newNode,&DNS_RESPONSE_.answers);
        
        
        // skipping pointer bytes...
        currentCounter +=2;
        newNode->type = DNS_RESPONSE[++currentCounter] + DNS_RESPONSE[++currentCounter];
        newNode->class = DNS_RESPONSE[currentCounter] + DNS_RESPONSE[++currentCounter];
        newNode->TTL += DNS_RESPONSE[++currentCounter];
        newNode->TTL += DNS_RESPONSE[++currentCounter];
        newNode->TTL += DNS_RESPONSE[++currentCounter];
        newNode->TTL += DNS_RESPONSE[++currentCounter];
        
         printf("%d BC\n",currentCounter);
        // currentCounter++;
        //--- TODO : Upgrade code for ipv6 array size to hold more values...
        int ipsize = DNS_RESPONSE[currentCounter]  + DNS_RESPONSE[++currentCounter];
        printf("%x C\n",DNS_RESPONSE[37]);
    

        currentCounter++;

        printf("%d %d\n",currentCounter,ipsize);
        
        // for(int i=0; i<ipsize; i++){
        //     newNode->ip[i] = DNS_RESPONSE[currentCounter];
        //     currentCounter++;
        // }

        
        currentCounter++;
    }



        for(int i=0; i<4; i++){
            printf("%d.",DNS_RESPONSE_.answers  ->ip[i]);
        }
    // printf("%d\n",DNS_RESPONSE_.ANSCOUNT);
    // printf("%d.",DNS_RESPONSE_.ANSCOUNT);
    



}






 // convert hex_stream to stream of binery...
void hexToBin(const unsigned char* hex_stream,const int nSize,int* bin_stream){

    int binarrsize =  (nSize*8)+1;
    mymemset(bin_stream,0,binarrsize);
    
    int tempbin[8] = {0};
    int innreloopcounter = 7;
    int bin_arr_counter = 0;

    // outerloop for each hex_degit
    for(int i=0; i<nSize; i++){
        int currentHex = hex_stream[i];
        while(currentHex != 0){
            tempbin[innreloopcounter] = currentHex%2;
            currentHex = currentHex/2;
            innreloopcounter--;
        }
        for(int i=0; i<8; i++){
            bin_stream[bin_arr_counter] = tempbin[i];
            bin_arr_counter++;
        }

        mymemset(tempbin,0,8);
        innreloopcounter = 7;
    }

    return;
}































        
        

