#ifndef __MAIN_HEADER_
#define __MAIN_HEADER_

#include <iostream>
#include <string>
#include <iomanip>
#include <thread>
#include <list>
#include <map>

#include <pcap.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include "ieee80211/ieee80211.h"
#include "ieee80211/ieee80211_radiotap.h"

using namespace std;
using namespace __gnu_cxx;

#define BIT(n) 1 << n
#define padding(n) setw(n) << setfill(' ')

typedef enum _IEEE80211_ENCRYPTION
{
    IEEE80211_ENCRYPTION_UNKNOWN,
    IEEE80211_ENCRYPTION_OPEN,
    IEEE80211_ENCRYPTION_WEP,
    IEEE80211_ENCRYPTION_WPA,
    IEEE80211_ENCRYPTION_WPA2,
    IEEE80211_ENCRYPTION_WPA2WPA
} IEEE80211_ENCRYPTION;

typedef struct _AP_INFO
{
    string ssid;
    string bssid;
    uint16_t channel;
    uint8_t signal;
    IEEE80211_ENCRYPTION enc;
} AP_INFO, *PAP_INFO;

struct ieee80211_management_infomation
{
    uint8_t    _tag_number;
    uint8_t    _tag_length;
    uint8_t    _tag_data[0];
} __attribute__ ((packed));

struct ieee80211_management_vendor_infomation
{
    uint8_t    _tag_number;
    uint8_t    _tag_length;
    uint32_t   _tag_oui:24;
    uint8_t    _tag_oui_type;
    uint8_t    _tag_data[0];
} __attribute__ ((packed));

class CAnalyze 
{
    #define PCAP_READABLE_SIZE 65536
    #define PCAP_OPENFLAG_PROMISCUOUS 1
    #define PCAP_OPENFLAG_NON_PROMISCUOUS 0
    
    public:
        CAnalyze();
        ~CAnalyze();

        bool selcet_device();
        void do_start(void);
        
        pcap_t *_device_handle;
        char * _device_name;

    private:
        pcap_if_t *_device_all;
        pcap_if_t *_device_temp;
        list<char *> _device_list;
        char _errbuf[PCAP_ERRBUF_SIZE];

        pcap_pkthdr *header;

        AP_INFO ap_info;
        map<string, AP_INFO> all_ap;

    protected:
        bool all_device();
        bool get_info();
        void get_radiotap(const u_char *_data, uint8_t *_signal, uint16_t *_channel);
        bool fake_ap(const u_char *_data);
        void print_ap();
        void change_channel();

        bool addPadding(int tLength) { return tLength % 2; }
        void needPadding(int *thisPointer, size_t addPointer)
        {
            if (addPadding(*thisPointer))
                *thisPointer += addPointer + sizeof(uint8_t);
            else
                *thisPointer += addPointer;
        }
        void needPadding(int *thisPointer)
        {
            if (addPadding(*thisPointer))
                *thisPointer += sizeof(uint8_t);
        }

        string AddrByteToString(uint8_t *_src, int _bufSize);
};

#endif