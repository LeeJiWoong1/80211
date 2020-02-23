#include "main.h"

CAnalyze::CAnalyze()
{
    _device_handle = NULL;
    _device_all = NULL;
    _device_temp = NULL;

    memset(_nonce1, 0, 32);
    memset(_nonce2, 0, 32);
    is_key = false;

    ssid = string("INFOLAP420_WPA2");
    pass = string("info1234");
}

CAnalyze::~CAnalyze()
{
    pcap_freealldevs(_device_all);
    pcap_freealldevs(_device_temp);
    _device_list.clear();
    _device_handle = NULL;
}

bool CAnalyze::selcet_device()
{
    if (all_device())
    {
        list<char *>::iterator iter;
        int inum, selcet;
        for (iter = _device_list.begin(), inum = 1; iter != _device_list.end(); ++iter, inum++)
            cout << "[" << inum << "] " << *iter << endl;
        cout << "[+] Select using wlan device number...";
        cin >> selcet;

        for (iter = _device_list.begin(), inum = 1; inum != selcet; ++iter, inum++)
            ;
        _device_name = *iter;
        string dev_str = string("sudo ifconfig ").append(*iter).append(" down");
        system(dev_str.c_str());
        dev_str = string("sudo iwconfig ").append(*iter).append(" mode monitor");
        system(dev_str.c_str());
        dev_str = string("sudo ifconfig ").append(*iter).append(" up");
        system(dev_str.c_str());

        cout << "[.] pcap_open_live()...";
        _device_handle = pcap_open_live(*iter, PCAP_READABLE_SIZE, PCAP_OPENFLAG_PROMISCUOUS, -1, _errbuf);
        if (_device_handle == NULL)
        {
            cout << "[ERROR] pcap_open_live() error : " << _errbuf << endl;
            return false;
        }
        cout << "ok" << endl;
        cout << "[INFO] Get Device handle : " << _device_handle << endl;

        _dummy = pcap_open_live("dummy0", PCAP_READABLE_SIZE, PCAP_OPENFLAG_PROMISCUOUS, -1, _errbuf);
        if (_dummy == NULL)
        {
            cout << "[ERROR] pcap_open_live() error : " << _errbuf << endl;
            return false;
        }

    }
    else
        return false;
    return true;
}

bool CAnalyze::all_device()
{
    cout << "[.] pcap_findalldevs()...";
    if (pcap_findalldevs(&_device_all, _errbuf) == PCAP_ERROR)
    {
        cout << "[ERROR] pcap_findalldevs() error : " << _errbuf << endl;
        return false;
    }
    cout << "ok" << endl;

    int inum;
    for (_device_temp = _device_all, inum = 0; _device_temp != NULL; _device_temp = _device_temp->next, inum++)
        _device_list.push_back(_device_temp->name);
    if (inum == 0 && _device_temp == NULL)
    {
        cout << "[ERROR] Interface not found!" << endl;
        return false;
    }
    return true;
}

string CAnalyze::AddrByteToString(uint8_t *_src, int _bufSize)
{
    uint8_t uint8_1, uint8_2;
    int index = 0;
    char dst[_bufSize * 3];

    for (int i = 0; i < _bufSize; i++)
    {
        uint8_1 = _src[i] & 0xF0;
        uint8_1 = uint8_1 >> 4;
        if (uint8_1 > 9)
            uint8_1 = uint8_1 + 'A' - 10;
        else
            uint8_1 = uint8_1 + '0';

        uint8_2 = _src[i] & 0x0F;
        if (uint8_2 > 9)
            uint8_2 = uint8_2 + 'A' - 10;
        else
            uint8_2 = uint8_2 + '0';
        dst[index++] = uint8_1;
        dst[index++] = uint8_2;
        dst[index++] = ':';
    }
    dst[--index] = '\0';
    return string(dst);
}

void CAnalyze::AddrStringToByte(string _src, int _bufSize, uint8_t *_dst)
{
    int index = 0;
    for (int i = 0; i < _bufSize; i++)
    {
        unsigned char ch1, ch2;
        ch1 = (int)_src[i];
        if (ch1 == ':')
            continue;

        if (ch1 >= '0' && ch1 <= '9')
            ch1 -= 0x30;
        else if (ch1 >= 'A' && ch1 <= 'Z')
            ch1 -= 0x37;

        ch2 = (int)_src[i + 1];
        if (ch2 >= '0' && ch2 <= '9')
            ch2 -= 0x30;
        else if (ch2 >= 'A' && ch2 <= 'Z')
            ch2 -= 0x37;

        ch1 = ch1 << 4;
        _dst[index++] = ch1 + ch2;
        i++;
    }
    _dst[index] = '\0';
}

bool CAnalyze::is_equal(uint8_t _c1[], uint8_t _c2[], int _len)
{
    for(int i = 0; i < _len; i++)
    {
        if(_c1[i] != _c2[i])
            return false;
    }
    return true;
}

bool CAnalyze::get_info()
{
    const u_char *data;
    pcap_pkthdr *header;

    while (true)
    {
        int result = pcap_next_ex(_device_handle, &header, &data);
        if (result == 0)
            continue;
        else if (result < 0)
        {
            cout << "[ERROR] pcap_next_ex() ERROR! " << endl;
            return false;
        }

        struct ieee80211_radiotap_header* pRadiotap = (struct ieee80211_radiotap_header*)data;
        int dataPointer = pRadiotap->it_len;

        struct ieee80211_frame* pFrame = (struct ieee80211_frame*)(data + dataPointer);
        uint8_t fType = pFrame->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
        uint8_t fsubType = pFrame->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

        if(fType == IEEE80211_FC0_TYPE_DATA && fsubType == IEEE80211_FC0_SUBTYPE_QOS)
        {
            struct ieee80211_qosframe* pQosFrame = (struct ieee80211_qosframe*)(data + dataPointer);
            dataPointer += sizeof(struct ieee80211_qosframe);
            uint8_t ds = pQosFrame->i_fc[1] & IEEE80211_FC1_DIR_MASK;

            uint8_t tDev[IEEE80211_ADDR_LEN], tAp[IEEE80211_ADDR_LEN];
            if(ds == IEEE80211_FC1_DIR_TODS)
            {
                memcpy(tDev, pFrame->i_addr2, IEEE80211_ADDR_LEN);
                memcpy(tAp, pFrame->i_addr1, IEEE80211_ADDR_LEN);
            }
            else if(ds == IEEE80211_FC1_DIR_FROMDS)
            {
                memcpy(tDev, pFrame->i_addr1, IEEE80211_ADDR_LEN);
                memcpy(tAp, pFrame->i_addr2, IEEE80211_ADDR_LEN);
            }

            if(is_equal(tDev, dev_addr, IEEE80211_ADDR_LEN) && is_equal(tAp, ap_addr, IEEE80211_ADDR_LEN))
            {
                if(!is_key)
                {
                    struct ieee80211_llc_header *pLogical = (struct ieee80211_llc_header *)(data + dataPointer);
                    dataPointer += sizeof(struct ieee80211_llc_header);
                    
                    if (pLogical->ethertype == IEEE80211_LLC_ETHERTYPE_AUTH)
                    {
                        struct eapol_hdr *pEapol = (struct eapol_hdr *)(data + dataPointer);
                        dataPointer += sizeof(struct eapol_hdr);

                        if (pEapol->eapol_type == EAPOL_TYPE_KEY)
                        {
                            struct eapol_key *pKey = (struct eapol_key *)(data + dataPointer);
                            if (pKey->ek_type == EAPOL_KEY_TYPE_RSN || pKey->ek_type == EAPOL_KEY_TYPE_WPA)
                            {
                                struct eapol_wpa_key *pWpa = (struct eapol_wpa_key *)(data + dataPointer);
                                if (_nonce1[0] == 0 && pWpa->ewk_nonce[0] != 0)
                                {
                                    memcpy(_nonce1, pWpa->ewk_nonce, sizeof(pWpa->ewk_nonce));
                                    cout << "NONCE CAPTURE!" << endl;
                                }
                                else if (_nonce1[0] != 0)
                                {
                                    if (!is_equal(_nonce1, pWpa->ewk_nonce, 32) && _nonce2[0] == 0)
                                    {
                                        memcpy(_nonce2, pWpa->ewk_nonce, sizeof(pWpa->ewk_nonce));
                                        PKCS5_PBKDF2_HMAC_SHA1(pass.c_str(), pass.length(), (const u_char*)ssid.c_str(), ssid.length(), 4096, 32, PMK);

                                        // Pairwise key expansion\0
                                        unsigned char pke[100] = {0x50, 0x61, 0x69, 0x72, 0x77, 0x69, 0x73, 0x65, 0x20, 0x6B, 0x65, 0x79, 0x20, 0x65, 0x78, 0x70, 0x61, 0x6E, 0x73, 0x69, 0x6F, 0x6E, 0x00};
                                        if (ap_addr[0] > dev_addr[0])
                                        {
                                            memcpy(pke + 23, dev_addr, IEEE80211_ADDR_LEN);
                                            memcpy(pke + 29, ap_addr, IEEE80211_ADDR_LEN);
                                        }
                                        else
                                        {
                                            memcpy(pke + 23, ap_addr, IEEE80211_ADDR_LEN);
                                            memcpy(pke + 29, dev_addr, IEEE80211_ADDR_LEN);
                                        }

                                        if (_nonce1[0] > _nonce2[0])
                                        {
                                            memcpy(pke + 35, _nonce2, 32);
                                            memcpy(pke + 67, _nonce1, 32);
                                        }
                                        else
                                        {
                                            memcpy(pke + 35, _nonce1, 32);
                                            memcpy(pke + 67, _nonce2, 32);
                                        }

                                        for (int i = 0; i < 4; i++)
                                        {
                                            pke[99] = i;
                                            HMAC(EVP_sha1(), PMK, 32, pke, 100, PTK + i * 20, NULL);
                                        }

                                        for (int i = 0; i < 16; i++)
                                            TK[i] = PTK[i + 32];

                                        cout << "KEY CAPTURE!" << endl;
                                        is_key = true;
                                    }
                                }
                            }
                        }
                    }
                }
                else
                {
                    const char* deData = (const char*)(data + dataPointer);
                    int dataLength = header->len - dataPointer;
                    dataPointer = 0;
                    
                    wpa2_ccmp *pCcmp = (struct wpa2_ccmp *)deData;
                    dataPointer += sizeof(struct wpa2_ccmp);

                    unsigned char ta[IEEE80211_ADDR_LEN];
                    for (int i = 0; i < IEEE80211_ADDR_LEN; i++)
                        ta[i] = dev_addr[i];

                    unsigned char pn[6];
                    pn[0] = pCcmp->ccmp[7];
                    pn[1] = pCcmp->ccmp[6];
                    pn[2] = pCcmp->ccmp[5];
                    pn[3] = pCcmp->ccmp[4];
                    pn[4] = pCcmp->ccmp[1];
                    pn[5] = pCcmp->ccmp[0];

                    unsigned char tk[16];
                    for (int i = 0; i < 16; i++)
                        tk[i] = TK[i];

                    int data_size = dataLength - dataPointer;
                    int block_len = data_size / 16;
                    if (data_size % 16 != 0)
                        block_len++;

                    unsigned char decryptData[data_size];
                    AES_KEY key;
                    AES_set_encrypt_key(tk, 128, &key);

                    for (int i = 0; i < block_len; i++)
                    {
                        unsigned char incounter[16] = {
                            0x01, // flag
                            0x00, // priority
                        };
                        memcpy(incounter + 2, ta, 6);
                        memcpy(incounter + 8, pn, 6);
                        incounter[14] = 0x00;
                        incounter[15] = i + 1;
                        unsigned char outcounter[16] = {0};
                        AES_ecb_encrypt(incounter, outcounter, &key, AES_ENCRYPT);

                        unsigned char deDatas[16] = {0};
                        for (int j = 0; j < 16; j++)
                        {
                            int index = i * 16 + j;
                            deDatas[j] = (unsigned char)deData[index + dataPointer];
                            decryptData[index] = deDatas[j] ^ outcounter[j];
                        }
                    }

                    data_size -= 8;
                    data_size -= sizeof(struct ieee80211_llc_header);
                    dataPointer = sizeof(struct ieee80211_llc_header);

                    unsigned char outData[data_size + 14];
                    memcpy(outData + 0, ap_addr, IEEE80211_ADDR_LEN);
                    memcpy(outData + 6, dev_addr, IEEE80211_ADDR_LEN);
                    outData[12] = 0x08;
                    outData[13] = 0x00;
                    memcpy(outData + 14, decryptData + dataPointer, data_size);

                    pcap_sendpacket(_dummy, outData, sizeof(outData));
                    cout << "DATA CAPTURE!" << endl;
                }
            }
        }
    }
}

int main(int agrc, char* agrv[])
{
    CAnalyze analyze;
    if (analyze.selcet_device())
        analyze.get_info();
    return 0;
}