#include "main.h"

CAnalyze::CAnalyze()
{
    _device_handle = NULL;
    _device_all = NULL;
    _device_temp = NULL;
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

bool CAnalyze::get_info()
{
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

        ieee80211_radiotap_header *pRadiotap = (struct ieee80211_radiotap_header *)data;
        int dataPointer = pRadiotap->it_len;

        ieee80211_frame *pFrame = (struct ieee80211_frame *)(data + dataPointer);
        dataPointer += sizeof(struct ieee80211_frame);

        uint8_t fType = pFrame->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
        uint8_t fSubType = pFrame->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

        //if (fType == IEEE80211_FC0_TYPE_MGT && (fSubType == IEEE80211_FC0_SUBTYPE_BEACON || fSubType == IEEE80211_FC0_SUBTYPE_PROBE_RESP))
        if (fType == IEEE80211_FC0_TYPE_MGT && (fSubType == IEEE80211_FC0_SUBTYPE_BEACON))
        {
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
                get_radiotap(data, &ap_info.signal, &ap_info.channel);
                iter->second.signal = ap_info.signal;
            }
            else
            {
                fake_ap(data);
                get_radiotap(data, &ap_info.signal, &ap_info.channel);
                ap_info.channel = ((int)ap_info.channel - 2407) / 5;
                all_ap.insert(pair<string, AP_INFO>(ap_info.bssid, ap_info));
            }
        }
    }
}

void CAnalyze::get_radiotap(const u_char *_data, uint8_t *_signal, uint16_t *_channel)
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
            *_channel = *((uint16_t *)(_data + dataPointer));
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

bool CAnalyze::fake_ap(const u_char *_data)
{
    while (true)
    {
        u_char fake_packet[2500] = {0};

        ieee80211_radiotap_header *pRadiotap = (struct ieee80211_radiotap_header *)_data;
        int dataPointer = pRadiotap->it_len;

        memcpy(fake_packet, _data, pRadiotap->it_len);

        ieee80211_frame *pFrame = (struct ieee80211_frame *)(_data + dataPointer);

        uint8_t fake_mac[IEEE80211_ADDR_LEN] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
        memcpy(pFrame->i_addr2, fake_mac, IEEE80211_ADDR_LEN);
        memcpy(pFrame->i_addr3, fake_mac, IEEE80211_ADDR_LEN);
        pFrame->i_seq[1] += 1;

        memcpy(fake_packet + dataPointer, pFrame, sizeof(struct ieee80211_frame));
        dataPointer += sizeof(struct ieee80211_frame);

        memcpy(fake_packet + dataPointer, _data + dataPointer, (sizeof(uint8_t) * 12));
        dataPointer += (sizeof(uint8_t) * 12); // Skip(Fixed Parameters)

        ieee80211_management_infomation *pInfo = (struct ieee80211_management_infomation *)(_data + dataPointer);
        uint8_t temp_len;

        if (pInfo->_tag_number == IEEE80211_ELEMID_SSID)
        {
            temp_len = pInfo->_tag_length;
            pInfo->_tag_length = 4;
            strcpy((char *)pInfo->_tag_data, "abcd");
        }

        memcpy(fake_packet + dataPointer, pInfo, (sizeof(uint8_t) * 2) + strlen((char *)pInfo->_tag_data));
        int tdataPointer = dataPointer + (sizeof(uint8_t) * 2) + temp_len;
        dataPointer += (sizeof(uint8_t) * 2) + strlen((char *)pInfo->_tag_data);

        memcpy(fake_packet + dataPointer, _data + tdataPointer, header->len - dataPointer);
        dataPointer = (header->len - temp_len) + strlen((char *)pInfo->_tag_data);

        pcap_sendpacket(_device_handle, fake_packet, dataPointer);
        sleep(1);
    }
}

void CAnalyze::print_ap()
{
    while (true)
    {
        sleep(1);
        system("clear");
        cout << " [SSID]\t\t\t\t  [BSSID]\t\t[CHANNEL]\t[SIGNAL]\t[ENC]" << endl;
        cout << endl;
        for (auto iter = all_ap.begin(); iter != all_ap.end(); iter++)
        {
            cout.setf(ios::left);
            cout << " " << padding(28) << iter->second.ssid;
            cout << padding(31) << iter->second.bssid;
            cout << padding(14) << (int)iter->second.channel;
            cout << padding(14) << ((int)(iter->second.signal) - 256);
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
        }
    }
}

void CAnalyze::change_channel()
{
    int channel_num = 1;
    while (true)
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

void CAnalyze::do_start()
{
    thread info(&CAnalyze::get_info, this);
    thread print(&CAnalyze::print_ap, this);
    thread channel(&CAnalyze::change_channel, this);

    info.join();
    print.join();
    channel.join();
}

int main(int agrc, char *argv[])
{
    CAnalyze analyze;
    if (analyze.selcet_device())
        analyze.do_start();

    return 0;
}