static int localport = 10000;
static int remoteport = 10023;
static char remoteIP[32];

static bool debug=false;

///////////////////////////////////////////////////////////////////////////////
//OS dependent includes
///////////////////////////////////////////////////////////////////////////////

#if OS_IS_LINUX == 1 || OS_IS_MACOSX == 1 || OS_IS_CYGWIN == 1
#include <unistd.h>             //  usleep
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>
#elif OS_IS_WIN32 == 1
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include "stdint.h"
#define socklen_t   int
#define snprintf _snprintf
#else
#error "Invalid Platform"
#endif

///////////////////////////////////////////////////////////////////////////////
//general includes
///////////////////////////////////////////////////////////////////////////////

#include <iostream>
#include <stdlib.h>
#include <cstdlib>
#include <string.h>

// Platform-dependent sleep routines.                                                                                                                                
#if OS_IS_LINUX == 1 || OS_IS_MACOSX == 1 || OS_IS_CYGWIN == 1
#include <unistd.h>
#define SLEEP( milliseconds ) usleep( (unsigned long) (milliseconds * 1000.0) )
#elif OS_IS_WIN32 == 1
#include <windows.h>
#define SLEEP( milliseconds ) Sleep( (DWORD) milliseconds )
#else
#error "Invalid Platform"
#endif

///////////////////////////////////////////////////////////////////////////////
//defines
///////////////////////////////////////////////////////////////////////////////

#define PROTOCOL_UDP            17
#define MAX_RX_UDP_PACKET       2048
#define MAX_CHANNELS            80+1

static struct sockaddr_in address;
static int udpSocket;

static int attackCountDefault=1;
static float attackNoiseLevelDefault=0.001f;
static int releaseCountDefault=100;
static float releaseNoiseLevelDefault=0.0001f;

typedef struct 
{
    int attackCount;
    int releaseCount;
    int automatic;
    float signalLevel;
    float restoreSignalLevel;
    float gain;
} SIGNAL_STATE_TYPE;

static int channelState[MAX_CHANNELS];
static int soloState[MAX_CHANNELS];
static int selectState[MAX_CHANNELS];
static SIGNAL_STATE_TYPE signalState[MAX_CHANNELS];

const char *CLIENT_HELP_STR = 
    "\n"
    " x32automix Version 0.01 help\n"
    "\n"
    " Invoking \"x32automix\":\n"
    " x32automix [local port] [X32 port] [X32 IP] [attack count] [attack noise level] [release count] [release noise level] [channelmap]\n"
    "\n"
    "   Sample: x32automix 10000 10023 172.17.100.2 1 0.001 100 0.0001 11000000000000000000000000000000\n"
    "\n";

#if OS_IS_LINUX == 1 || OS_IS_MACOSX == 1 || OS_IS_CYGWIN == 1
    socklen_t addressSize = sizeof(sockaddr_in);
#else
    int addressSize = sizeof(sockaddr_in);
#endif

static volatile bool doExit=false;

#define MAX_POLL_ANSWER 16

void dumpBuffer(char *buffer, size_t bufferLen)
{
    size_t dataIndex=0;
    size_t totalIndex=0;

    while (dataIndex<bufferLen)
    {
        if(totalIndex==0)
        {
            printf("\t\t");
            for (dataIndex = totalIndex; dataIndex<totalIndex+16 && dataIndex < bufferLen; dataIndex++) 
            {
                printf("----");
            }
        }

        printf("\n\t\t");
        for (dataIndex = totalIndex; dataIndex<totalIndex+16 && dataIndex < bufferLen; dataIndex++) 
        {
            printf("%03lu ",dataIndex+1);
        }
        printf("\n\t\t");
        for (dataIndex = totalIndex; dataIndex<totalIndex+16 && dataIndex < bufferLen; dataIndex++) 
        {
            printf("  %c ",(buffer[dataIndex] >= ' ') && (buffer[dataIndex] <  127)?buffer[dataIndex]:(uint8_t)'.');
        }
        printf("\n\t\t");
        for (dataIndex = totalIndex; dataIndex<totalIndex+16 && dataIndex < bufferLen; dataIndex++) 
        {
            printf(" %02X ",(unsigned char) buffer[dataIndex]);
        }
        printf("\n");

        totalIndex+=16;
    }    
    printf("\n");
}

#if OS_IS_LINUX == 1 || OS_IS_MACOSX == 1 || OS_IS_CYGWIN == 1
void signalHandler(int s)
{
    printf("Caught signal %d\n",s);
    doExit=true;
}
#endif

void registerSignalHandler(void)
{
#if OS_IS_LINUX == 1 || OS_IS_MACOSX == 1 || OS_IS_CYGWIN == 1
   struct sigaction sigIntHandler;

   sigIntHandler.sa_handler = signalHandler;
   sigemptyset(&sigIntHandler.sa_mask);
   sigIntHandler.sa_flags = 0;

   sigaction(SIGINT, &sigIntHandler, NULL);
#else
	return;
#endif
}

int networkInit(int port)
{
    int udpSocket;
    int err;
    const int REUSE_TRUE = 1, BROADCAST_TRUE = 1;
    struct sockaddr_in receiveAddress;

#if OS_IS_WIN32 == 1
    //fucking windows winsock startup
    WSADATA wsa;
    err = WSAStartup(MAKEWORD(2, 0), &wsa);
    if (err != 0)
    {
        printf("Error starting Windows udpSocket subsystem.\n");
        return err;
    }
#endif

    //create udpSocket
    udpSocket = socket(AF_INET, SOCK_DGRAM, PROTOCOL_UDP);
    if (udpSocket < 0)
    {
        printf("Create udpSocket error.");
        return udpSocket;
    }
    
    //initialize server address to localhost:port
    receiveAddress.sin_family = AF_INET;
    receiveAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    receiveAddress.sin_port = htons(port);

    //set udpSocket to reuse the address
    err = setsockopt(udpSocket, SOL_SOCKET, SO_REUSEADDR, (const char *) &REUSE_TRUE, sizeof(REUSE_TRUE));
    if (err != 0)
    {
        printf("Error setting udpSocket reuse.");
        return err;
    }

    //enable broadcasting for this
    err = setsockopt(udpSocket, SOL_SOCKET, SO_BROADCAST, (const char *) &BROADCAST_TRUE, sizeof(BROADCAST_TRUE));
    if (err != 0)
    {
        printf("Error setting udpSocket broadcast.");
        return err;
    }
    
    //disable blocking, polling is used.
#if OS_IS_LINUX == 1 || OS_IS_MACOSX == 1 || OS_IS_CYGWIN == 1
    err = fcntl(udpSocket, F_SETFL, O_NONBLOCK);
#elif OS_IS_WIN32 == 1
    unsigned long val = 1;
    err = ioctlsocket(udpSocket, FIONBIO, &val);
#endif
    if (err != 0)
    {
        printf("Error setting udpSocket unblock.");
        return err;
    }

    //bind for listening
    err = bind(udpSocket, (struct sockaddr *) &receiveAddress, addressSize);
    if (err != 0)
    {
        printf("Error udpSocket bind.");
        return err;
    }
    return udpSocket;
}

void networkSend(int udpSocket, struct sockaddr_in *address, const uint8_t *data, int dataLen)
{
#if OS_IS_LINUX == 1 || OS_IS_MACOSX == 1 || OS_IS_CYGWIN == 1
    int actSend = sendto(udpSocket,
                         data,
                         dataLen,
                         0,
                         (struct sockaddr*) address,
                         addressSize);
#else
    int actSend = sendto(udpSocket,
                         (const char *) data,
                         dataLen,
                         0,
                         (struct sockaddr*) address,
                         addressSize);
#endif
    //check if transmission was successful 
    if (dataLen != actSend)
    {
        printf("Error sending packet.");
    }
}


int networkReceive(int udpSocket, uint8_t *data)
{
    struct sockaddr_in receiveAddress;

    receiveAddress.sin_family = AF_INET;
    receiveAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    receiveAddress.sin_port = htons(0);

    //receive from network
#if OS_IS_LINUX == 1 || OS_IS_MACOSX == 1 || OS_IS_CYGWIN == 1
    int received = recvfrom(udpSocket,
                             data,
                             MAX_RX_UDP_PACKET,
                             0,
                             (struct sockaddr *) &receiveAddress,
                             (socklen_t *) & addressSize);
#else
    int received = recvfrom(udpSocket,
                             (char *) data,
                             MAX_RX_UDP_PACKET,
                             0,
                             (struct sockaddr *) &receiveAddress,
                             & addressSize);
#endif

    return received;
}

int networkHalt(int udpSocket)
{
    //close udpSocket...
#if OS_IS_LINUX == 1 || OS_IS_MACOSX == 1 || OS_IS_CYGWIN == 1
    close(udpSocket);
#elif OS_IS_WIN32 == 1
    closesocket(udpSocket);
    WSACleanup();
#endif
    return 0;
}

typedef struct {
    char address[256];
    
    char sPar[128][256];
    int iPar[128];
    float fPar[128];
    bool bPar[128];

    int sCount;
    int iCount;
    int fCount;
    int bCount;
} OSCSTRUCT;

typedef enum {
    OSC_ADDRESS,
    OSC_PARAMETRER_DESC,
    OSC_PARAMETER
} OSC_DECODE_STATE;

void printOSC(OSCSTRUCT *osc)
{
    int i;
    printf("%s\n",osc->address);

    for (i=0;i<osc->iCount;i++)
    {
        printf("\t%i\n",osc->iPar[i]);
    }

    for (i=0;i<osc->fCount;i++)
    {
        printf("\t%f\n",osc->fPar[i]);
    }

    for (i=0;i<osc->sCount;i++)
    {
        printf("\t%s\n",osc->sPar[i]);
    }
}

int decodeOsc(const uint8_t *buffer, int bufferLen, OSCSTRUCT *osc, char *debugString, size_t debugStringLen)
{
    OSC_DECODE_STATE mode=OSC_ADDRESS;
    int dataIndex;

    uint8_t parameterBytes[128];
    size_t parameterIndex=0;
    size_t parameterLength;

    osc->address[0]='\0';
    osc->sCount=0;
    osc->iCount=0;
    osc->fCount=0;
    osc->bCount=0;

    debugString[0]='\0';


    if(debug)
    {
        dumpBuffer((char *) buffer,bufferLen);
    }

    for (dataIndex = 0; dataIndex < bufferLen; dataIndex++) 
    {
        uint8_t     ch;
        
        ch = buffer[dataIndex];
        

        if (mode==OSC_ADDRESS)
        {
            if (ch == 10) 
            {
                strncat(debugString,"\n",debugStringLen);
            } 
            else if (ch == 13) 
            {
                strncat(debugString,"\r",debugStringLen);
            } 
            else if (ch == '"') 
            {
                strncat(debugString,"\\\"",debugStringLen);
            } 
            else if (ch == '\\') 
            {
                strncat(debugString,"\\\\",debugStringLen);
            } 
            else if ( (ch >= ' ') && (ch < 127) ) 
            {
                char c[2];
                c[0]=ch;
                c[1]='\0';
                strncat(debugString,c,debugStringLen);
            } 
            else if (ch == 0) 
            {
                if (dataIndex<256-1)
                {
                    memcpy(osc->address,buffer,dataIndex);
                    osc->address[dataIndex]='\0';
                }
                dataIndex += 3-(dataIndex%4);
                mode=OSC_PARAMETRER_DESC;
            } 
            else 
            {
                snprintf(debugString+strlen(debugString),debugStringLen-strlen(debugString),"\\x%02x", (unsigned int) ch);
            }
        }
        else if (mode==OSC_PARAMETRER_DESC)
        {
            if (ch == 10) 
            {
                strncat(debugString,"\n",debugStringLen);
            } 
            else if (ch == 13) 
            {
                strncat(debugString,"\r",debugStringLen);
            } 
            else if (ch == 'i' || ch=='f' || ch=='s' || ch=='b') 
            {
                char c[2];
                c[0]=ch;
                c[1]='\0';

                if (parameterIndex<128-1)
                {
                    parameterBytes[parameterIndex++]=ch;
                }
                snprintf(debugString+strlen(debugString),debugStringLen-strlen(debugString),"%c", (unsigned int) ch);
            } 
            else if (ch == '"') 
            {
                strncat(debugString,"\\\"",debugStringLen);
            } 
            else if (ch == '\\') 
            {
                strncat(debugString,"\\\\",debugStringLen);
            } 
            else if ( (ch >= ' ') && (ch < 127) ) 
            {
                char c[2];
                c[0]=ch;
                c[1]='\0';
                strncat(debugString,c,debugStringLen);
            } 
            else if (ch == 0) 
            {
                parameterBytes[parameterIndex]='\0';
                dataIndex += 3-(dataIndex%4);
                mode=OSC_PARAMETER;
                parameterLength = strlen((const char *) parameterBytes);
                parameterIndex = 0;
            } 
            else 
            {
                snprintf(debugString+strlen(debugString),debugStringLen-strlen(debugString),"\\x%02x", (unsigned int) ch);
            }
        }
        else if (mode==OSC_PARAMETER)
        {
            for (parameterIndex=0; parameterIndex < parameterLength; parameterIndex++) 
            {
                if (parameterBytes[parameterIndex]=='i') 
                {
                    uint32_t i;
                    uint8_t *p = (uint8_t *) &i;
                    
                    *(p+0)=buffer[dataIndex+3];
                    *(p+1)=buffer[dataIndex+2];
                    *(p+2)=buffer[dataIndex+1];
                    *(p+3)=buffer[dataIndex+0];
                    
                    if(debug)
                    {
                        int index;
                        printf("\n");
                        for (index=dataIndex; index < dataIndex+4; index++) 
                        {
                            printf("---");
                        }
                        printf("\n");
                        for (index=dataIndex; index < dataIndex+4; index++) 
                        {
                            printf("%02d ",index+1);
                        }
                        printf("\n");
                        for (index=dataIndex; index < dataIndex+4; index++) 
                        {
                            printf(" %c ",(buffer[index] >= (uint8_t)' ') && (buffer[index] < (uint8_t) 127)?buffer[index]:(uint8_t)'.');
                        }
                        printf("\n");
                        for (index=dataIndex; index < dataIndex+4; index++) 
                        {
                            printf("%02X ",buffer[index]);
                        }
                        printf("\n");
                        printf("val=%d\n",i);
                     }

                    snprintf(debugString+strlen(debugString),debugStringLen-strlen(debugString)," %d", i);
                    dataIndex+=3;
                    osc->iPar[osc->iCount++]=i;
                }
                else if (parameterBytes[parameterIndex]=='f') 
                {
                    float z;
                    uint8_t *p = (uint8_t *) &z;
                    
                    *(p+0)=buffer[dataIndex+3];
                    *(p+1)=buffer[dataIndex+2];
                    *(p+2)=buffer[dataIndex+1];
                    *(p+3)=buffer[dataIndex+0];
                    
                    snprintf(debugString+strlen(debugString),debugStringLen-strlen(debugString)," %f", z);
                    dataIndex+=3;

                    osc->fPar[osc->fCount++]=z;
                }
                else if (parameterBytes[parameterIndex]=='s') 
                {
                    strncat(debugString," ",debugStringLen);

                    osc->sPar[osc->sCount][0] = '\0';

                    for (; dataIndex < bufferLen; dataIndex++) 
                    {
                        ch = buffer[dataIndex];

                        if (ch == 10) 
                        {
                            strncat(debugString,"\n",debugStringLen);
                            strncat(osc->sPar[osc->sCount],"\n",256);
                        } 
                        else if (ch == 13) 
                        {
                            strncat(debugString,"\r",debugStringLen);
                            strncat(osc->sPar[osc->sCount],"\r",256);
                        } 
                        else if (ch == '"') 
                        {
                            strncat(debugString,"\\\"",debugStringLen);
                            strncat(osc->sPar[osc->sCount],"\\\"",256);
                        } 
                        else if (ch == '\\') 
                        {
                            strncat(debugString,"\\\\",debugStringLen);
                            strncat(osc->sPar[osc->sCount],"\\\\",256);
                        } 
                        else if ( (ch >= ' ') && (ch < 127) ) 
                        {
                            char c[2];
                            c[0]=ch;
                            c[1]='\0';
                            strncat(debugString,c,debugStringLen);
                            strncat(osc->sPar[osc->sCount],c,256);

                        } 
                        else if (ch == 0) 
                        {
                            dataIndex += ((dataIndex+1)%4);
                        } 
                        else 
                        {
                            snprintf(debugString+strlen(debugString),debugStringLen-strlen(debugString),"\\x%02x", (unsigned int) ch);
                            snprintf(osc->sPar[osc->sCount]+strlen(osc->sPar[osc->sCount]),256-strlen(osc->sPar[osc->sCount]),"\\x%02x", (unsigned int) ch);
                        }
                    }
                }
                else if (parameterBytes[parameterIndex]=='b') {
                    uint32_t i;
                    uint8_t *p = (uint8_t *) &i;
                    int dumpLen=8;
                    
                    *(p+0)=buffer[dataIndex+3];
                    *(p+1)=buffer[dataIndex+2];
                    *(p+2)=buffer[dataIndex+1];
                    *(p+3)=buffer[dataIndex+0];

                    snprintf(debugString+strlen(debugString),debugStringLen-strlen(debugString)," %u(%u)", i, i/4);

                    dataIndex+=4;
                    dataIndex+=4;

                    while (i>0)
                    {
                        float z;
                        uint8_t *p = (uint8_t *) &z;

                        *(p+0)=buffer[dataIndex+0];
                        *(p+1)=buffer[dataIndex+1];
                        *(p+2)=buffer[dataIndex+2];
                        *(p+3)=buffer[dataIndex+3];
                        
                        if(dumpLen-->0)
                        {
                            snprintf(debugString+strlen(debugString),debugStringLen-strlen(debugString)," %f", z);
                        }
                        dataIndex+=4;

                        osc->fPar[osc->fCount++]=z;

                        i-=4;
                    }

                    dataIndex-=1;
                }
            }
        }
    }
    
    return 0;
}


size_t encodeOsc(OSCSTRUCT *osc, uint8_t *buffer, size_t bufferLen)
{
    size_t addressLen;
    size_t parameterLen=0;
    size_t valLen=0;
    int i;
    int maxLen=bufferLen;
    char *p = (char *) buffer;
    char *pSav;

    memset(buffer,0,bufferLen);

    addressLen=strlen(osc->address);
    addressLen++;
    if(addressLen%4>0)
    {
        addressLen+=4;
    }
    addressLen=(addressLen/4)*4;

    if (osc->sCount+osc->iCount+osc->fCount>0)
    {
        parameterLen=1+osc->sCount+osc->iCount+osc->fCount;
        parameterLen=((parameterLen/4)+1)*4;
    }   

    valLen=(osc->iCount+osc->fCount)*4;
    for (i=0;i<osc->sCount;i++)
    {
        size_t l = strlen(osc->sPar[i]);
        l++; //terminating zero
        if(l%4>0)
        {
            l+=4;
        }
        valLen+=(l/4)*4;
    }

    if (addressLen + parameterLen + valLen > bufferLen)
    {
        printf("buffer yo small. %lu butes in parameter set\n",addressLen + parameterLen + valLen);
    }
    else
    {
        //address
        strncpy(p,osc->address,maxLen);
        p+=addressLen;

        if (parameterLen>0)
        {

            //parameter
            pSav=p;
                
            *p++=',';

            for (i=0;i<osc->sCount;i++)
            {
                *p++='s';
            }

            for (i=0;i<osc->iCount;i++)
            {
                *p++='i';
            }

            for (i=0;i<osc->fCount;i++)
            {
                *p++='f';
            }

            p=pSav+parameterLen;

            //values
            for (i=0;i<osc->sCount;i++)
            {
                size_t l = strlen(osc->sPar[i]);
                l++; //terminating zero
                if(l%4>0)
                {
                    l+=4;
                }

                strcpy(p,osc->sPar[i]);

                p+=(l/4)*4;
            }

            for (i=0;i<osc->iCount;i++)
            {
                unsigned char *byteval= (unsigned char *) &osc->iPar[i];
                *p++=*(byteval+3);
                *p++=*(byteval+2);
                *p++=*(byteval+1);
                *p++=*(byteval+0);
            }

            for (i=0;i<osc->fCount;i++)
            {
                unsigned char *byteval= (unsigned char *) &osc->fPar[i];
                *p++=*(byteval+3);
                *p++=*(byteval+2);
                *p++=*(byteval+1);
                *p++=*(byteval+0);
            }
        }

        if(debug)
        {
            dumpBuffer((char *) buffer,addressLen + parameterLen + valLen);
        }
        return(addressLen + parameterLen + valLen);
    }

    return 0;
}

void sendCommand(const char *oscAddress)
{
    uint8_t encodeBuffer[2048];
    OSCSTRUCT oscSend;
    size_t sendLen;

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(remoteIP);
    address.sin_port = htons(remoteport);

    memset(&oscSend,0,sizeof(OSCSTRUCT));
    strcpy(oscSend.address,oscAddress);

    sendLen=encodeOsc(&oscSend,encodeBuffer,sizeof(encodeBuffer));
    if (sendLen>0)
    {
        networkSend(udpSocket, &address, encodeBuffer, sendLen);
    }
}

void sendIntCommand(const char *oscAddress,uint32_t iPar)
{
    uint8_t encodeBuffer[2048];
    OSCSTRUCT oscSend;
    size_t sendLen;

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(remoteIP);
    address.sin_port = htons(remoteport);

    memset(&oscSend,0,sizeof(OSCSTRUCT));
    strcpy(oscSend.address,oscAddress);

    oscSend.iCount++;
    oscSend.iPar[0]=iPar;

    sendLen=encodeOsc(&oscSend,encodeBuffer,sizeof(encodeBuffer));
    if (sendLen>0)
    {
        networkSend(udpSocket, &address, encodeBuffer, sendLen);
    }
}

void sendFloatCommand(const char *oscAddress,float fPar)
{
    uint8_t encodeBuffer[2048];
    OSCSTRUCT oscSend;
    size_t sendLen;

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(remoteIP);
    address.sin_port = htons(remoteport);

    memset(&oscSend,0,sizeof(OSCSTRUCT));
    strcpy(oscSend.address,oscAddress);

    oscSend.fCount++;
    oscSend.fPar[0]=fPar;

    sendLen=encodeOsc(&oscSend,encodeBuffer,sizeof(encodeBuffer));
    if (sendLen>0)
    {
        networkSend(udpSocket, &address, encodeBuffer, sendLen);
    }
}

void sendStringCommand(const char *oscAddress, const char *sPar)
{
    uint8_t encodeBuffer[2048];
    OSCSTRUCT oscSend;
    size_t sendLen;

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(remoteIP);
    address.sin_port = htons(remoteport);

    memset(&oscSend,0,sizeof(OSCSTRUCT));
    strcpy(oscSend.address,oscAddress);

    oscSend.sCount++;
    strncpy(oscSend.sPar[0],sPar,sizeof(oscSend.sPar[0]));

    sendLen=encodeOsc(&oscSend,encodeBuffer,sizeof(encodeBuffer));
    if (sendLen>0)
    {
        networkSend(udpSocket, &address, encodeBuffer, sendLen);
    }
}



void analyzeFader(int channel,float f)
{
    uint16_t val;

    val = (uint16_t) (f * 0x3fff);
    //printf("[%02d] Fader %f (%4x)\n",channel, f, val);
    if(f>0.1)
    {
        signalState[channel].restoreSignalLevel = f;
    }
}

void analyzePanning(int channel,float f)
{
    uint16_t val;

    val = (uint16_t) (f * 0x3fff);
    //printf("[%02d] Panning %f (%4x)\n",channel, f, val);
}

void analyzeChannelState(int channel, int state)
{
    channelState[channel]=state;
    //printf("[%02d] Channel State is %s (%4x)\n",channel, state?"on":"off",state);
}   

void analyzeSoloState(int channel, int state)
{
    soloState[channel]=state;
    //printf("[%02d] Solo State is %s (%4x)\n",channel, state?"on":"off",state);
}   

void analyzeSelectState(int channel, int state)
{
    selectState[channel]=state;
    //printf("[%02d] Solo State is %s (%4x)\n",channel, state?"on":"off",state);
}   

void analyzeMeter1(OSCSTRUCT *osc)
{
    int i;
    char buffer[256];

    for(i=0;i<32;i++)
    {
        if (signalState[i].automatic&1)
        {
            if(osc->fPar[i]>attackNoiseLevelDefault && ++(signalState[i].attackCount)>attackCountDefault)
            {
                signalState[i].attackCount=attackCountDefault+1;
                signalState[i].signalLevel=osc->fPar[i];
                if (signalState[i].releaseCount<=0)
                {
                    sprintf(buffer,"/ch/%02d/mix/fader",i+1);
                    sendFloatCommand(buffer,signalState[i].restoreSignalLevel>0?signalState[i].restoreSignalLevel:.5f);
                }
                signalState[i].releaseCount=releaseCountDefault;
            }

            if (signalState[i].releaseCount>0 && osc->fPar[i]<releaseNoiseLevelDefault)
            {
                signalState[i].releaseCount--;
                if (signalState[i].releaseCount<=0)
                {
                    sprintf(buffer,"/ch/%02d/mix/fader",i+1);
                    sendFloatCommand(buffer,0.0);
                    signalState[i].attackCount=0;
                    signalState[i].signalLevel=osc->fPar[i];
                }
            }
        }
        if (signalState[i].automatic&2)
        {
            if(osc->fPar[i]>1.0)
            {
                sprintf(buffer,"/headamp/%03d/gain",i);
                signalState[i].gain -= .05f;           
                sendFloatCommand(buffer,signalState[i].gain);
            }
        }
    }
}

void analyzeHeadamp(int channel,float f)
{
    uint16_t val;

    val = (uint16_t) (f * 0x3fff);
    //printf("[%02d] Gain %f (%4x)\n",channel, f, val);
    signalState[channel].gain = f;
}

void mapOSC(OSCSTRUCT *osc)
{
    if(!strcmp("meters/1",osc->address) && osc->fCount>=31)             {analyzeMeter1(osc); return;}

    //map faders
    if(!strcmp("/ch/01/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader( 0,osc->fPar[0]); return;}
    if(!strcmp("/ch/02/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader( 1,osc->fPar[0]); return;}
    if(!strcmp("/ch/03/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader( 2,osc->fPar[0]); return;}
    if(!strcmp("/ch/04/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader( 3,osc->fPar[0]); return;}
    if(!strcmp("/ch/05/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader( 4,osc->fPar[0]); return;}
    if(!strcmp("/ch/06/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader( 5,osc->fPar[0]); return;}
    if(!strcmp("/ch/07/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader( 6,osc->fPar[0]); return;}
    if(!strcmp("/ch/08/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader( 7,osc->fPar[0]); return;}
    if(!strcmp("/ch/09/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader( 8,osc->fPar[0]); return;}
    if(!strcmp("/ch/10/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader( 9,osc->fPar[0]); return;}
    if(!strcmp("/ch/11/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader(10,osc->fPar[0]); return;}
    if(!strcmp("/ch/12/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader(11,osc->fPar[0]); return;}
    if(!strcmp("/ch/13/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader(12,osc->fPar[0]); return;}
    if(!strcmp("/ch/14/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader(13,osc->fPar[0]); return;}
    if(!strcmp("/ch/15/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader(14,osc->fPar[0]); return;}
    if(!strcmp("/ch/16/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader(15,osc->fPar[0]); return;}
    if(!strcmp("/ch/17/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader(16,osc->fPar[0]); return;}
    if(!strcmp("/ch/18/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader(17,osc->fPar[0]); return;}
    if(!strcmp("/ch/19/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader(18,osc->fPar[0]); return;}
    if(!strcmp("/ch/20/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader(19,osc->fPar[0]); return;}
    if(!strcmp("/ch/21/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader(20,osc->fPar[0]); return;}
    if(!strcmp("/ch/22/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader(21,osc->fPar[0]); return;}
    if(!strcmp("/ch/23/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader(22,osc->fPar[0]); return;}
    if(!strcmp("/ch/24/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader(23,osc->fPar[0]); return;}
    if(!strcmp("/ch/25/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader(24,osc->fPar[0]); return;}
    if(!strcmp("/ch/26/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader(25,osc->fPar[0]); return;}
    if(!strcmp("/ch/27/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader(26,osc->fPar[0]); return;}
    if(!strcmp("/ch/28/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader(27,osc->fPar[0]); return;}
    if(!strcmp("/ch/29/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader(28,osc->fPar[0]); return;}
    if(!strcmp("/ch/30/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader(29,osc->fPar[0]); return;}
    if(!strcmp("/ch/31/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader(30,osc->fPar[0]); return;}
    if(!strcmp("/ch/32/mix/fader",osc->address) && osc->fCount>0)       {analyzeFader(31,osc->fPar[0]); return;}

    if(!strcmp("/auxin/01/mix/fader",osc->address) && osc->fCount>0)    {analyzeFader(32,osc->fPar[0]); return;}
    if(!strcmp("/auxin/02/mix/fader",osc->address) && osc->fCount>0)    {analyzeFader(33,osc->fPar[0]); return;}
    if(!strcmp("/auxin/03/mix/fader",osc->address) && osc->fCount>0)    {analyzeFader(34,osc->fPar[0]); return;}
    if(!strcmp("/auxin/04/mix/fader",osc->address) && osc->fCount>0)    {analyzeFader(35,osc->fPar[0]); return;}
    if(!strcmp("/auxin/05/mix/fader",osc->address) && osc->fCount>0)    {analyzeFader(36,osc->fPar[0]); return;}
    if(!strcmp("/auxin/06/mix/fader",osc->address) && osc->fCount>0)    {analyzeFader(37,osc->fPar[0]); return;}
    if(!strcmp("/auxin/07/mix/fader",osc->address) && osc->fCount>0)    {analyzeFader(38,osc->fPar[0]); return;}
    if(!strcmp("/auxin/08/mix/fader",osc->address) && osc->fCount>0)    {analyzeFader(39,osc->fPar[0]); return;}

    if(!strcmp("/fxrtn/01/mix/fader",osc->address) && osc->fCount>0)    {analyzeFader(40,osc->fPar[0]); return;}
    if(!strcmp("/fxrtn/02/mix/fader",osc->address) && osc->fCount>0)    {analyzeFader(41,osc->fPar[0]); return;}
    if(!strcmp("/fxrtn/03/mix/fader",osc->address) && osc->fCount>0)    {analyzeFader(42,osc->fPar[0]); return;}
    if(!strcmp("/fxrtn/04/mix/fader",osc->address) && osc->fCount>0)    {analyzeFader(43,osc->fPar[0]); return;}
    if(!strcmp("/fxrtn/05/mix/fader",osc->address) && osc->fCount>0)    {analyzeFader(44,osc->fPar[0]); return;}
    if(!strcmp("/fxrtn/06/mix/fader",osc->address) && osc->fCount>0)    {analyzeFader(45,osc->fPar[0]); return;}
    if(!strcmp("/fxrtn/07/mix/fader",osc->address) && osc->fCount>0)    {analyzeFader(46,osc->fPar[0]); return;}
    if(!strcmp("/fxrtn/08/mix/fader",osc->address) && osc->fCount>0)    {analyzeFader(47,osc->fPar[0]); return;}

    if(!strcmp("/dca/1/fader",osc->address) && osc->fCount>0)           {analyzeFader(48,osc->fPar[0]); return;}
    if(!strcmp("/dca/2/fader",osc->address) && osc->fCount>0)           {analyzeFader(49,osc->fPar[0]); return;}
    if(!strcmp("/dca/3/fader",osc->address) && osc->fCount>0)           {analyzeFader(50,osc->fPar[0]); return;}
    if(!strcmp("/dca/4/fader",osc->address) && osc->fCount>0)           {analyzeFader(51,osc->fPar[0]); return;}
    if(!strcmp("/dca/5/fader",osc->address) && osc->fCount>0)           {analyzeFader(52,osc->fPar[0]); return;}
    if(!strcmp("/dca/6/fader",osc->address) && osc->fCount>0)           {analyzeFader(53,osc->fPar[0]); return;}
    if(!strcmp("/dca/7/fader",osc->address) && osc->fCount>0)           {analyzeFader(54,osc->fPar[0]); return;}
    if(!strcmp("/dca/8/fader",osc->address) && osc->fCount>0)           {analyzeFader(55,osc->fPar[0]); return;}

    if(!strcmp("/bus/01/mix/fader",osc->address) && osc->fCount>0)      {analyzeFader(56,osc->fPar[0]); return;}
    if(!strcmp("/bus/02/mix/fader",osc->address) && osc->fCount>0)      {analyzeFader(57,osc->fPar[0]); return;}
    if(!strcmp("/bus/03/mix/fader",osc->address) && osc->fCount>0)      {analyzeFader(58,osc->fPar[0]); return;}
    if(!strcmp("/bus/04/mix/fader",osc->address) && osc->fCount>0)      {analyzeFader(59,osc->fPar[0]); return;}
    if(!strcmp("/bus/05/mix/fader",osc->address) && osc->fCount>0)      {analyzeFader(60,osc->fPar[0]); return;}
    if(!strcmp("/bus/06/mix/fader",osc->address) && osc->fCount>0)      {analyzeFader(61,osc->fPar[0]); return;}
    if(!strcmp("/bus/07/mix/fader",osc->address) && osc->fCount>0)      {analyzeFader(62,osc->fPar[0]); return;}
    if(!strcmp("/bus/08/mix/fader",osc->address) && osc->fCount>0)      {analyzeFader(63,osc->fPar[0]); return;}
    if(!strcmp("/bus/09/mix/fader",osc->address) && osc->fCount>0)      {analyzeFader(64,osc->fPar[0]); return;}
    if(!strcmp("/bus/10/mix/fader",osc->address) && osc->fCount>0)      {analyzeFader(65,osc->fPar[0]); return;}
    if(!strcmp("/bus/11/mix/fader",osc->address) && osc->fCount>0)      {analyzeFader(66,osc->fPar[0]); return;}
    if(!strcmp("/bus/12/mix/fader",osc->address) && osc->fCount>0)      {analyzeFader(67,osc->fPar[0]); return;}
    if(!strcmp("/bus/13/mix/fader",osc->address) && osc->fCount>0)      {analyzeFader(68,osc->fPar[0]); return;}
    if(!strcmp("/bus/14/mix/fader",osc->address) && osc->fCount>0)      {analyzeFader(69,osc->fPar[0]); return;}
    if(!strcmp("/bus/15/mix/fader",osc->address) && osc->fCount>0)      {analyzeFader(70,osc->fPar[0]); return;}
    if(!strcmp("/bus/16/mix/fader",osc->address) && osc->fCount>0)      {analyzeFader(71,osc->fPar[0]); return;}

    if(!strcmp("/mtx/01/mix/fader",osc->address) && osc->fCount>0)      {analyzeFader(72,osc->fPar[0]); return;}
    if(!strcmp("/mtx/02/mix/fader",osc->address) && osc->fCount>0)      {analyzeFader(73,osc->fPar[0]); return;}
    if(!strcmp("/mtx/03/mix/fader",osc->address) && osc->fCount>0)      {analyzeFader(74,osc->fPar[0]); return;}
    if(!strcmp("/mtx/04/mix/fader",osc->address) && osc->fCount>0)      {analyzeFader(75,osc->fPar[0]); return;}
    if(!strcmp("/mtx/05/mix/fader",osc->address) && osc->fCount>0)      {analyzeFader(76,osc->fPar[0]); return;}
    if(!strcmp("/mtx/06/mix/fader",osc->address) && osc->fCount>0)      {analyzeFader(77,osc->fPar[0]); return;}
    //if(!strcmp("not mapped to OSC",osc->address) && osc->fCount>0)    {analyzeFader(78,osc->fPar[0]); return;}
    if(!strcmp("/main/m/mix/fader",osc->address) && osc->fCount>0)      {analyzeFader(79,osc->fPar[0]); return;}

    if(!strcmp("/main/st/mix/fader",osc->address) && osc->fCount>0)     {analyzeFader(80,osc->fPar[0]); return;}


    //map state (mute)
    if(!strcmp("/ch/01/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState( 0,osc->iPar[0]); return;}
    if(!strcmp("/ch/02/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState( 1,osc->iPar[0]); return;}
    if(!strcmp("/ch/03/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState( 2,osc->iPar[0]); return;}
    if(!strcmp("/ch/04/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState( 3,osc->iPar[0]); return;}
    if(!strcmp("/ch/05/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState( 4,osc->iPar[0]); return;}
    if(!strcmp("/ch/06/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState( 5,osc->iPar[0]); return;}
    if(!strcmp("/ch/07/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState( 6,osc->iPar[0]); return;}
    if(!strcmp("/ch/08/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState( 7,osc->iPar[0]); return;}
    if(!strcmp("/ch/09/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState( 8,osc->iPar[0]); return;}
    if(!strcmp("/ch/10/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState( 9,osc->iPar[0]); return;}
    if(!strcmp("/ch/11/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState(10,osc->iPar[0]); return;}
    if(!strcmp("/ch/12/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState(11,osc->iPar[0]); return;}
    if(!strcmp("/ch/13/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState(12,osc->iPar[0]); return;}
    if(!strcmp("/ch/14/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState(13,osc->iPar[0]); return;}
    if(!strcmp("/ch/15/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState(14,osc->iPar[0]); return;}
    if(!strcmp("/ch/16/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState(15,osc->iPar[0]); return;}
    if(!strcmp("/ch/17/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState(16,osc->iPar[0]); return;}
    if(!strcmp("/ch/18/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState(17,osc->iPar[0]); return;}
    if(!strcmp("/ch/19/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState(18,osc->iPar[0]); return;}
    if(!strcmp("/ch/20/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState(19,osc->iPar[0]); return;}
    if(!strcmp("/ch/21/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState(20,osc->iPar[0]); return;}
    if(!strcmp("/ch/22/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState(21,osc->iPar[0]); return;}
    if(!strcmp("/ch/23/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState(22,osc->iPar[0]); return;}
    if(!strcmp("/ch/24/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState(23,osc->iPar[0]); return;}
    if(!strcmp("/ch/25/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState(24,osc->iPar[0]); return;}
    if(!strcmp("/ch/26/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState(25,osc->iPar[0]); return;}
    if(!strcmp("/ch/27/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState(26,osc->iPar[0]); return;}
    if(!strcmp("/ch/28/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState(27,osc->iPar[0]); return;}
    if(!strcmp("/ch/29/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState(28,osc->iPar[0]); return;}
    if(!strcmp("/ch/30/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState(29,osc->iPar[0]); return;}
    if(!strcmp("/ch/31/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState(30,osc->iPar[0]); return;}
    if(!strcmp("/ch/32/mix/on",osc->address) && osc->iCount>0)       {analyzeChannelState(31,osc->iPar[0]); return;}

    if(!strcmp("/auxin/01/mix/on",osc->address) && osc->iCount>0)    {analyzeChannelState(32,osc->iPar[0]); return;}
    if(!strcmp("/auxin/02/mix/on",osc->address) && osc->iCount>0)    {analyzeChannelState(33,osc->iPar[0]); return;}
    if(!strcmp("/auxin/03/mix/on",osc->address) && osc->iCount>0)    {analyzeChannelState(34,osc->iPar[0]); return;}
    if(!strcmp("/auxin/04/mix/on",osc->address) && osc->iCount>0)    {analyzeChannelState(35,osc->iPar[0]); return;}
    if(!strcmp("/auxin/05/mix/on",osc->address) && osc->iCount>0)    {analyzeChannelState(36,osc->iPar[0]); return;}
    if(!strcmp("/auxin/06/mix/on",osc->address) && osc->iCount>0)    {analyzeChannelState(37,osc->iPar[0]); return;}
    if(!strcmp("/auxin/07/mix/on",osc->address) && osc->iCount>0)    {analyzeChannelState(38,osc->iPar[0]); return;}
    if(!strcmp("/auxin/08/mix/on",osc->address) && osc->iCount>0)    {analyzeChannelState(39,osc->iPar[0]); return;}

    if(!strcmp("/fxrtn/01/mix/on",osc->address) && osc->iCount>0)    {analyzeChannelState(40,osc->iPar[0]); return;}
    if(!strcmp("/fxrtn/02/mix/on",osc->address) && osc->iCount>0)    {analyzeChannelState(41,osc->iPar[0]); return;}
    if(!strcmp("/fxrtn/03/mix/on",osc->address) && osc->iCount>0)    {analyzeChannelState(42,osc->iPar[0]); return;}
    if(!strcmp("/fxrtn/04/mix/on",osc->address) && osc->iCount>0)    {analyzeChannelState(43,osc->iPar[0]); return;}
    if(!strcmp("/fxrtn/05/mix/on",osc->address) && osc->iCount>0)    {analyzeChannelState(44,osc->iPar[0]); return;}
    if(!strcmp("/fxrtn/06/mix/on",osc->address) && osc->iCount>0)    {analyzeChannelState(45,osc->iPar[0]); return;}
    if(!strcmp("/fxrtn/07/mix/on",osc->address) && osc->iCount>0)    {analyzeChannelState(46,osc->iPar[0]); return;}
    if(!strcmp("/fxrtn/08/mix/on",osc->address) && osc->iCount>0)    {analyzeChannelState(47,osc->iPar[0]); return;}

    if(!strcmp("/dca/1/on",osc->address) && osc->iCount>0)           {analyzeChannelState(48,osc->iPar[0]); return;}
    if(!strcmp("/dca/2/on",osc->address) && osc->iCount>0)           {analyzeChannelState(49,osc->iPar[0]); return;}
    if(!strcmp("/dca/3/on",osc->address) && osc->iCount>0)           {analyzeChannelState(50,osc->iPar[0]); return;}
    if(!strcmp("/dca/4/on",osc->address) && osc->iCount>0)           {analyzeChannelState(51,osc->iPar[0]); return;}
    if(!strcmp("/dca/5/on",osc->address) && osc->iCount>0)           {analyzeChannelState(52,osc->iPar[0]); return;}
    if(!strcmp("/dca/6/on",osc->address) && osc->iCount>0)           {analyzeChannelState(53,osc->iPar[0]); return;}
    if(!strcmp("/dca/7/on",osc->address) && osc->iCount>0)           {analyzeChannelState(54,osc->iPar[0]); return;}
    if(!strcmp("/dca/8/on",osc->address) && osc->iCount>0)           {analyzeChannelState(55,osc->iPar[0]); return;}

    if(!strcmp("/bus/01/mix/on",osc->address) && osc->iCount>0)      {analyzeChannelState(56,osc->iPar[0]); return;}
    if(!strcmp("/bus/02/mix/on",osc->address) && osc->iCount>0)      {analyzeChannelState(57,osc->iPar[0]); return;}
    if(!strcmp("/bus/03/mix/on",osc->address) && osc->iCount>0)      {analyzeChannelState(58,osc->iPar[0]); return;}
    if(!strcmp("/bus/04/mix/on",osc->address) && osc->iCount>0)      {analyzeChannelState(59,osc->iPar[0]); return;}
    if(!strcmp("/bus/05/mix/on",osc->address) && osc->iCount>0)      {analyzeChannelState(60,osc->iPar[0]); return;}
    if(!strcmp("/bus/06/mix/on",osc->address) && osc->iCount>0)      {analyzeChannelState(61,osc->iPar[0]); return;}
    if(!strcmp("/bus/07/mix/on",osc->address) && osc->iCount>0)      {analyzeChannelState(62,osc->iPar[0]); return;}
    if(!strcmp("/bus/08/mix/on",osc->address) && osc->iCount>0)      {analyzeChannelState(63,osc->iPar[0]); return;}
    if(!strcmp("/bus/09/mix/on",osc->address) && osc->iCount>0)      {analyzeChannelState(64,osc->iPar[0]); return;}
    if(!strcmp("/bus/10/mix/on",osc->address) && osc->iCount>0)      {analyzeChannelState(65,osc->iPar[0]); return;}
    if(!strcmp("/bus/11/mix/on",osc->address) && osc->iCount>0)      {analyzeChannelState(66,osc->iPar[0]); return;}
    if(!strcmp("/bus/12/mix/on",osc->address) && osc->iCount>0)      {analyzeChannelState(67,osc->iPar[0]); return;}
    if(!strcmp("/bus/13/mix/on",osc->address) && osc->iCount>0)      {analyzeChannelState(68,osc->iPar[0]); return;}
    if(!strcmp("/bus/14/mix/on",osc->address) && osc->iCount>0)      {analyzeChannelState(69,osc->iPar[0]); return;}
    if(!strcmp("/bus/15/mix/on",osc->address) && osc->iCount>0)      {analyzeChannelState(70,osc->iPar[0]); return;}
    if(!strcmp("/bus/16/mix/on",osc->address) && osc->iCount>0)      {analyzeChannelState(71,osc->iPar[0]); return;}

    if(!strcmp("/mtx/01/mix/on",osc->address) && osc->iCount>0)      {analyzeChannelState(72,osc->iPar[0]); return;}
    if(!strcmp("/mtx/02/mix/on",osc->address) && osc->iCount>0)      {analyzeChannelState(73,osc->iPar[0]); return;}
    if(!strcmp("/mtx/03/mix/on",osc->address) && osc->iCount>0)      {analyzeChannelState(74,osc->iPar[0]); return;}
    if(!strcmp("/mtx/04/mix/on",osc->address) && osc->iCount>0)      {analyzeChannelState(75,osc->iPar[0]); return;}
    if(!strcmp("/mtx/05/mix/on",osc->address) && osc->iCount>0)      {analyzeChannelState(76,osc->iPar[0]); return;}
    if(!strcmp("/mtx/06/mix/on",osc->address) && osc->iCount>0)      {analyzeChannelState(77,osc->iPar[0]); return;}
    //if(!strcmp("not mapped to OSC",osc->address) && osc->fCount>0)    {analyzeFader(78,osc->iPar[0]); return;}
    if(!strcmp("/main/m/mix/on",osc->address) && osc->iCount>0)      {analyzeChannelState(79,osc->iPar[0]); return;}

    if(!strcmp("/main/st/mix/on",osc->address) && osc->iCount>0)     {analyzeChannelState(80,osc->iPar[0]); return;}


    //pan
    if(!strcmp("/ch/01/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning( 0,osc->fPar[0]); return;}
    if(!strcmp("/ch/02/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning( 1,osc->fPar[0]); return;}
    if(!strcmp("/ch/03/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning( 2,osc->fPar[0]); return;}
    if(!strcmp("/ch/04/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning( 3,osc->fPar[0]); return;}
    if(!strcmp("/ch/05/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning( 4,osc->fPar[0]); return;}
    if(!strcmp("/ch/06/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning( 5,osc->fPar[0]); return;}
    if(!strcmp("/ch/07/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning( 6,osc->fPar[0]); return;}
    if(!strcmp("/ch/08/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning( 7,osc->fPar[0]); return;}
    if(!strcmp("/ch/09/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning( 8,osc->fPar[0]); return;}
    if(!strcmp("/ch/10/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning( 9,osc->fPar[0]); return;}
    if(!strcmp("/ch/11/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning(10,osc->fPar[0]); return;}
    if(!strcmp("/ch/12/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning(11,osc->fPar[0]); return;}
    if(!strcmp("/ch/13/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning(12,osc->fPar[0]); return;}
    if(!strcmp("/ch/14/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning(13,osc->fPar[0]); return;}
    if(!strcmp("/ch/15/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning(14,osc->fPar[0]); return;}
    if(!strcmp("/ch/16/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning(15,osc->fPar[0]); return;}
    if(!strcmp("/ch/17/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning(16,osc->fPar[0]); return;}
    if(!strcmp("/ch/18/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning(17,osc->fPar[0]); return;}
    if(!strcmp("/ch/19/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning(18,osc->fPar[0]); return;}
    if(!strcmp("/ch/20/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning(19,osc->fPar[0]); return;}
    if(!strcmp("/ch/21/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning(20,osc->fPar[0]); return;}
    if(!strcmp("/ch/22/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning(21,osc->fPar[0]); return;}
    if(!strcmp("/ch/23/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning(22,osc->fPar[0]); return;}
    if(!strcmp("/ch/24/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning(23,osc->fPar[0]); return;}
    if(!strcmp("/ch/25/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning(24,osc->fPar[0]); return;}
    if(!strcmp("/ch/26/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning(25,osc->fPar[0]); return;}
    if(!strcmp("/ch/27/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning(26,osc->fPar[0]); return;}
    if(!strcmp("/ch/28/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning(27,osc->fPar[0]); return;}
    if(!strcmp("/ch/29/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning(28,osc->fPar[0]); return;}
    if(!strcmp("/ch/30/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning(29,osc->fPar[0]); return;}
    if(!strcmp("/ch/31/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning(30,osc->fPar[0]); return;}
    if(!strcmp("/ch/32/mix/pan",osc->address) && osc->fCount>0)       {analyzePanning(31,osc->fPar[0]); return;}

    if(!strcmp("/auxin/01/mix/pan",osc->address) && osc->fCount>0)    {analyzePanning(32,osc->fPar[0]); return;}
    if(!strcmp("/auxin/02/mix/pan",osc->address) && osc->fCount>0)    {analyzePanning(33,osc->fPar[0]); return;}
    if(!strcmp("/auxin/03/mix/pan",osc->address) && osc->fCount>0)    {analyzePanning(34,osc->fPar[0]); return;}
    if(!strcmp("/auxin/04/mix/pan",osc->address) && osc->fCount>0)    {analyzePanning(35,osc->fPar[0]); return;}
    if(!strcmp("/auxin/05/mix/pan",osc->address) && osc->fCount>0)    {analyzePanning(36,osc->fPar[0]); return;}
    if(!strcmp("/auxin/06/mix/pan",osc->address) && osc->fCount>0)    {analyzePanning(37,osc->fPar[0]); return;}
    if(!strcmp("/auxin/07/mix/pan",osc->address) && osc->fCount>0)    {analyzePanning(38,osc->fPar[0]); return;}
    if(!strcmp("/auxin/08/mix/pan",osc->address) && osc->fCount>0)    {analyzePanning(39,osc->fPar[0]); return;}

    if(!strcmp("/fxrtn/01/mix/pan",osc->address) && osc->fCount>0)    {analyzePanning(40,osc->fPar[0]); return;}
    if(!strcmp("/fxrtn/02/mix/pan",osc->address) && osc->fCount>0)    {analyzePanning(41,osc->fPar[0]); return;}
    if(!strcmp("/fxrtn/03/mix/pan",osc->address) && osc->fCount>0)    {analyzePanning(42,osc->fPar[0]); return;}
    if(!strcmp("/fxrtn/04/mix/pan",osc->address) && osc->fCount>0)    {analyzePanning(43,osc->fPar[0]); return;}
    if(!strcmp("/fxrtn/05/mix/pan",osc->address) && osc->fCount>0)    {analyzePanning(44,osc->fPar[0]); return;}
    if(!strcmp("/fxrtn/06/mix/pan",osc->address) && osc->fCount>0)    {analyzePanning(45,osc->fPar[0]); return;}
    if(!strcmp("/fxrtn/07/mix/pan",osc->address) && osc->fCount>0)    {analyzePanning(46,osc->fPar[0]); return;}
    if(!strcmp("/fxrtn/08/mix/pan",osc->address) && osc->fCount>0)    {analyzePanning(47,osc->fPar[0]); return;}

    if(!strcmp("/dca/1/pan",osc->address) && osc->fCount>0)           {analyzePanning(48,osc->fPar[0]); return;}
    if(!strcmp("/dca/2/pan",osc->address) && osc->fCount>0)           {analyzePanning(49,osc->fPar[0]); return;}
    if(!strcmp("/dca/3/pan",osc->address) && osc->fCount>0)           {analyzePanning(50,osc->fPar[0]); return;}
    if(!strcmp("/dca/4/pan",osc->address) && osc->fCount>0)           {analyzePanning(51,osc->fPar[0]); return;}
    if(!strcmp("/dca/5/pan",osc->address) && osc->fCount>0)           {analyzePanning(52,osc->fPar[0]); return;}
    if(!strcmp("/dca/6/pan",osc->address) && osc->fCount>0)           {analyzePanning(53,osc->fPar[0]); return;}
    if(!strcmp("/dca/7/pan",osc->address) && osc->fCount>0)           {analyzePanning(54,osc->fPar[0]); return;}
    if(!strcmp("/dca/8/pan",osc->address) && osc->fCount>0)           {analyzePanning(55,osc->fPar[0]); return;}

    if(!strcmp("/bus/01/mix/pan",osc->address) && osc->fCount>0)      {analyzePanning(56,osc->fPar[0]); return;}
    if(!strcmp("/bus/02/mix/pan",osc->address) && osc->fCount>0)      {analyzePanning(57,osc->fPar[0]); return;}
    if(!strcmp("/bus/03/mix/pan",osc->address) && osc->fCount>0)      {analyzePanning(58,osc->fPar[0]); return;}
    if(!strcmp("/bus/04/mix/pan",osc->address) && osc->fCount>0)      {analyzePanning(59,osc->fPar[0]); return;}
    if(!strcmp("/bus/05/mix/pan",osc->address) && osc->fCount>0)      {analyzePanning(60,osc->fPar[0]); return;}
    if(!strcmp("/bus/06/mix/pan",osc->address) && osc->fCount>0)      {analyzePanning(61,osc->fPar[0]); return;}
    if(!strcmp("/bus/07/mix/pan",osc->address) && osc->fCount>0)      {analyzePanning(62,osc->fPar[0]); return;}
    if(!strcmp("/bus/08/mix/pan",osc->address) && osc->fCount>0)      {analyzePanning(63,osc->fPar[0]); return;}
    if(!strcmp("/bus/09/mix/pan",osc->address) && osc->fCount>0)      {analyzePanning(64,osc->fPar[0]); return;}
    if(!strcmp("/bus/10/mix/pan",osc->address) && osc->fCount>0)      {analyzePanning(65,osc->fPar[0]); return;}
    if(!strcmp("/bus/11/mix/pan",osc->address) && osc->fCount>0)      {analyzePanning(66,osc->fPar[0]); return;}
    if(!strcmp("/bus/12/mix/pan",osc->address) && osc->fCount>0)      {analyzePanning(67,osc->fPar[0]); return;}
    if(!strcmp("/bus/13/mix/pan",osc->address) && osc->fCount>0)      {analyzePanning(68,osc->fPar[0]); return;}
    if(!strcmp("/bus/14/mix/pan",osc->address) && osc->fCount>0)      {analyzePanning(69,osc->fPar[0]); return;}
    if(!strcmp("/bus/15/mix/pan",osc->address) && osc->fCount>0)      {analyzePanning(70,osc->fPar[0]); return;}
    if(!strcmp("/bus/16/mix/pan",osc->address) && osc->fCount>0)      {analyzePanning(71,osc->fPar[0]); return;}

    if(!strcmp("/mtx/01/mix/pan",osc->address) && osc->fCount>0)      {analyzePanning(72,osc->fPar[0]); return;}
    if(!strcmp("/mtx/02/mix/pan",osc->address) && osc->fCount>0)      {analyzePanning(73,osc->fPar[0]); return;}
    if(!strcmp("/mtx/03/mix/pan",osc->address) && osc->fCount>0)      {analyzePanning(74,osc->fPar[0]); return;}
    if(!strcmp("/mtx/04/mix/pan",osc->address) && osc->fCount>0)      {analyzePanning(75,osc->fPar[0]); return;}
    if(!strcmp("/mtx/05/mix/pan",osc->address) && osc->fCount>0)      {analyzePanning(76,osc->fPar[0]); return;}
    if(!strcmp("/mtx/06/mix/pan",osc->address) && osc->fCount>0)      {analyzePanning(77,osc->fPar[0]); return;}
    //if(!strcmp("not mapped to OSC",osc->address) && osc->fCount>0)    {analyzeFader(78,osc->fPar[0]); return;}
    if(!strcmp("/main/m/mix/pan",osc->address) && osc->fCount>0)      {analyzePanning(79,osc->fPar[0]); return;}

    if(!strcmp("/main/st/mix/pan",osc->address) && osc->fCount>0)     {analyzePanning(80,osc->fPar[0]); return;}

    //gain
    if(!strcmp("/headamp/000/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp( 0,osc->fPar[0]); return;}
    if(!strcmp("/headamp/001/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp( 1,osc->fPar[0]); return;}
    if(!strcmp("/headamp/002/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp( 2,osc->fPar[0]); return;}
    if(!strcmp("/headamp/003/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp( 3,osc->fPar[0]); return;}
    if(!strcmp("/headamp/004/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp( 4,osc->fPar[0]); return;}
    if(!strcmp("/headamp/005/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp( 5,osc->fPar[0]); return;}
    if(!strcmp("/headamp/006/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp( 6,osc->fPar[0]); return;}
    if(!strcmp("/headamp/007/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp( 7,osc->fPar[0]); return;}
    if(!strcmp("/headamp/008/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp( 8,osc->fPar[0]); return;}
    if(!strcmp("/headamp/009/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp( 9,osc->fPar[0]); return;}
    if(!strcmp("/headamp/010/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp(10,osc->fPar[0]); return;}
    if(!strcmp("/headamp/011/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp(11,osc->fPar[0]); return;}
    if(!strcmp("/headamp/012/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp(12,osc->fPar[0]); return;}
    if(!strcmp("/headamp/013/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp(13,osc->fPar[0]); return;}
    if(!strcmp("/headamp/014/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp(14,osc->fPar[0]); return;}
    if(!strcmp("/headamp/015/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp(15,osc->fPar[0]); return;}
    if(!strcmp("/headamp/016/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp(16,osc->fPar[0]); return;}
    if(!strcmp("/headamp/017/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp(17,osc->fPar[0]); return;}
    if(!strcmp("/headamp/018/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp(18,osc->fPar[0]); return;}
    if(!strcmp("/headamp/019/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp(19,osc->fPar[0]); return;}
    if(!strcmp("/headamp/020/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp(20,osc->fPar[0]); return;}
    if(!strcmp("/headamp/021/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp(21,osc->fPar[0]); return;}
    if(!strcmp("/headamp/022/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp(22,osc->fPar[0]); return;}
    if(!strcmp("/headamp/023/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp(23,osc->fPar[0]); return;}
    if(!strcmp("/headamp/024/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp(24,osc->fPar[0]); return;}
    if(!strcmp("/headamp/025/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp(25,osc->fPar[0]); return;}
    if(!strcmp("/headamp/026/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp(26,osc->fPar[0]); return;}
    if(!strcmp("/headamp/027/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp(27,osc->fPar[0]); return;}
    if(!strcmp("/headamp/028/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp(28,osc->fPar[0]); return;}
    if(!strcmp("/headamp/029/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp(29,osc->fPar[0]); return;}
    if(!strcmp("/headamp/030/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp(30,osc->fPar[0]); return;}
    if(!strcmp("/headamp/031/gain",osc->address) && osc->fCount>0)       {analyzeHeadamp(31,osc->fPar[0]); return;}

    //solo
    if(!strncmp("/-stat/solosw/",osc->address,strlen("/-stat/solosw/")) && osc->iCount>0)
    {
        int channelNumber=-1;
        int number=atoi(&osc->address[strlen("/-stat/solosw/")]);
        if(number==71)
        {
            channelNumber=80;
        }
        else if(number>=1 && number<=48)
        {
            channelNumber=number-1;
        }
        else if(number>=49 && number<=72)
        {
            channelNumber=number+8-1;
        }
        else if(number>=73 && number<=80)
        {
            channelNumber=number-24-1;
        }

        if (channelNumber>=0)
        {    
            analyzeSoloState(channelNumber,osc->iPar[0]);
        }
    }

    //select
    if(!strncmp("/-stat/selidx/",osc->address,strlen("/-stat/selidx/")) && osc->iCount>0)
    {
        int channelNumber=-1;
        int number=atoi(&osc->address[strlen("/-stat/selidx/")]);
        if(number==70)
        {
            channelNumber=80;
        }
        else if(number>=0 && number<=47)
        {
            channelNumber=number-1;
        }
        else if(number>=48 && number<=71)
        {
            channelNumber=number+8-1;
        }
        else if(number>=72 && number<=79)
        {
            channelNumber=number-24-1;
        }

        if (channelNumber>=0)
        {    
            analyzeSelectState(channelNumber,osc->iPar[0]);
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
//main
///////////////////////////////////////////////////////////////////////////////

/**
 * Arguments:
 *  - 1. Local port at which the client listens.
 *  - 2. Remote port at which the remote server listens.
 *  - 3. Remote IP at which the remote server listens.
  */
int main(int argc, char *argv[])
{
	uint8_t rxBuffer[MAX_RX_UDP_PACKET];
	int count;
	int d = 70;
	std::string portName;
    int i;
    int meterPrint=false;
    bool firstInit=true;

	strcpy(remoteIP, "172.17.100.2");
    memset(signalState,0,sizeof(signalState));

	registerSignalHandler();

    //process arguments
    if (argc > 1)
        localport = atoi(argv[1]);
    if (argc > 2)
        remoteport = atoi(argv[2]);
    if (argc > 3)
        strcpy(remoteIP, argv[3]);
    if (argc > 4)
        attackCountDefault=atoi(argv[4]);
    if (argc > 5)
        attackNoiseLevelDefault=(float) atof(argv[5]);
    if (argc > 6)
        releaseCountDefault=atoi(argv[6]);
    if (argc > 7)
        releaseNoiseLevelDefault=(float) atof(argv[7]);
    if (argc > 8)
    {
        char *p=argv[8];
        for(i=0;i<32;i++)
        {
            if(*p=='\0')
            {
                break;
            }
            else
            {
                switch(*p)
                {
                case '0': signalState[i].automatic=0; break;
                case '1': signalState[i].automatic=1; break;
                case '2': signalState[i].automatic=2; break;
                case '3': signalState[i].automatic=3; break;
                case '4': signalState[i].automatic=4; break;
                case '5': signalState[i].automatic=5; break;
                case '6': signalState[i].automatic=6; break;
                case '7': signalState[i].automatic=7; break;
                }
            }
                if(*p=='1')
            {
                signalState[i].automatic=1;
            }
            p++;
        }
    }
    if (argc > 1 && !strncmp(argv[1],"--help",6))
    {
        printf("%s",CLIENT_HELP_STR);
        return 0;
    }
    if (argc<9)
    {
        printf("%s",CLIENT_HELP_STR);
        return -1;
    }

    if (argc>9)
    {
        meterPrint=true;
    }

    if (argc>10)
    {
        debug=true;
    }

    if (argc>11)
	{
        printf("%s",CLIENT_HELP_STR);
		return -1;
	}

    for (i=0;i<32;i++)
    {
        if (signalState[i].automatic&1)
        {
            signalState[i].releaseCount=releaseCountDefault;
        }
    }
    printf("Setting up network layer. local port:%d remote port:%d remote IP:%s\n",localport,remoteport,remoteIP);

    udpSocket = networkInit(localport);
    if ( udpSocket < 0 )
    {
        printf("Exit.\n");
        return -1;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(remoteIP);
    address.sin_port = htons(remoteport);

    printf("Init done\n");

    while (!doExit)
    {

        SLEEP(100);

        if (d%70==0)
        {
            char buffer[256];
            sendCommand("/xremote");

            SLEEP(100);
            
            if(firstInit)
            {
                for (i=0;i<32;i++)
                {
                    sprintf(buffer,"/headamp/%03d/gain",i);
                    sendCommand(buffer);
                }

                for (i=0;i<32;i++)
                {
                    sprintf(buffer,"/ch/%02d/mix/fader",i+1);
                    sendCommand(buffer);
                }
                firstInit=false;
                d=60;
            }
            else
            {
                sendStringCommand("/meters","/meters/1");
            }
        }
        do
        {
            count = networkReceive(udpSocket,rxBuffer);
            if (count>0)
            {
                OSCSTRUCT osc;
                char debugString[4096];
                decodeOsc(rxBuffer, count, &osc, debugString, sizeof(debugString));
                //if (meterPrint || strncmp("meters",debugString,6))
                //    printf("\t\t%s\n",debugString);

                //printOSC(&osc);
                mapOSC(&osc);
            }
        } while (count>0);


        d++;
    }

    //stop network layer
    networkHalt(udpSocket);

    printf("Exiting. Bye.\n");
    return 0;
}
