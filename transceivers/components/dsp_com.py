import time
import struct
import math
from ...cmis import CMIS
import ctypes

class DspCom:
    def __init__(self, trx: CMIS):
        self.__trx = trx
    
    def calc_cdb_chkcode(self, vals):
        chkcode = ctypes.c_ubyte(0)
        for b in vals:
            chkcode.value += b
        chkcode.value = - chkcode.value - 1
        return chkcode.value

    def api_epl(self, byteArray):
        while self.__trx.cdb1.STS_BUSY:
            pass
        txLen = len(byteArray)
        rspLen = struct.unpack('<H',byteArray[4:6])[0]
        #write data to AX Page
        pages = txLen // 128
        for i in range(pages):
            bank = 0
            page = 0xa0 + i
            self.__trx.select_bank_page(bank, page)
            time.sleep(0.1)
            self.__trx[128: 255] = byteArray[i*128: (i+1)*128]
            time.sleep(0.1)       
        if txLen % 128:
            bank = 0
            page = 0xa0 + pages
            self.__trx.select_bank_page(bank, page)
            time.sleep(0.1)
            data = byteArray[pages*128:]
            self.__trx[128: 128+len(data)-1] = data
            time.sleep(0.1) 

        self.__trx.select_bank_page(0, 0x9F)
        cmd = bytearray(b'\x80\x00\x00\x00\x03\x00\x00\x00\x0f\x07\x02')
        cmd[2] = (txLen >> 8) & 0xff # EPL MSB
        cmd[3] = txLen & 0xff # EPL LSB
        cmd[133-128] = self.calc_cdb_chkcode(cmd)
        
        data = cmd[2:]
        self.__trx[130: 130+len(data)-1] = data
        self.__trx[128:129] = cmd[:2]

        time.sleep(0.5)
        while self.__trx.cdb1.STS_BUSY or self.__trx[37] == 0:
            pass

        if (not self.__trx.cdb1.STS_BUSY) and (not self.__trx.cdb1.STS_FAIL):
            pages = rspLen // 128
            rlp = b''
            for i in range(pages):
                bank = 0
                page = 0xa0 + i
                self.__trx.select_bank_page(bank, page)
                time.sleep(0.1)
                rlp += self.__trx[128: 255]
                time.sleep(0.1)       

            if rspLen % 128:
                bank = 0
                page = 0xa0 + pages
                self.__trx.select_bank_page(bank, page)
                time.sleep(0.1)
                rlp += self.__trx[128: 128 + rspLen%128 - 1]
                time.sleep(0.1)      
            
            return struct.pack('%sB'%len(rlp), *rlp)

    
    def api_lpl(self, byteArray):
        while self.__trx.cdb1.STS_BUSY:
            pass
        self.__trx.select_bank_page(0, 0x9F)
        cmd = bytearray(b'\x80\x00\x00\x00\x03\x00\x00\x00\x0f\x07\x02')
        txlen = len(byteArray)
        # print(txlen)
        cmd[4] = 3 + txlen #total tx len
        # print(cmd[4])
        i = 0
        while i < txlen:
            cmd.append(byteArray[i])
            i += 1
        cmd[133-128] = self.calc_cdb_chkcode(cmd)
        # print(cmd)
        data = cmd[2:]
        self.__trx[130: 130+len(data)-1] = data
        self.__trx[128: 129] = cmd[:2]
        time.sleep(0.5)
        while self.__trx.cdb1.STS_BUSY or self.__trx[37] == 0:
            pass

        if (not self.__trx.cdb1.STS_BUSY) and (not self.__trx.cdb1.STS_FAIL):
            rlplen = self.__trx[134]
            print('rlplen %d.\n' % rlplen)
            rlp_chkcode = self.__trx[135]
            rlp = self.__trx[136: 136+rlplen-1]
            if self.calc_cdb_chkcode(rlp) == rlp_chkcode:
                # print(struct.pack('%sB'%len(rlp), *rlp))
                return struct.pack('%sB'%len(rlp), *rlp)

    def api(self, byteArray):
        return self.api_epl(byteArray)

    def send_command(self, data):
        print(data)
        length = len(data)
        i = 0
        while i < length:
            data[i] = data[i] & 0xff
            i += 1
        print(data)
        rsp = self.api(bytearray(data))
        print(rsp)
        return rsp
