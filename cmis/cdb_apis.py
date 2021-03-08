import struct

class CdbApi:

    def __init__(self, cdb):
        self.__cdb = cdb
        # alias of APIs
        self.CMD0000h = self.QueryStatus
        self.CMD0040h = self.ModuleFeaturesImplemented
        self.CMD0100h = self.GetFirmwareInfo

    def QueryStatus(self, delay=0):
        """
        alias: CMD0000h
        delay: delay time before reply in ms
        """
        lpl = delay.to_bytes(2, 'big')
        success, last_command_result = self.__cdb(0x0000, lpl=lpl)
        if not success:
            raise ValueError('CDB command failed. Last command result: {result:02X}h'.format(result=last_command_result))
        rlpl = self.__cdb.read_rlpl()
        reply = {
            'Length of Status': rlpl[0],
            'Unlock level and privileges': rlpl[1],
            'Firmware download allowed': rlpl[2]
        }
        return reply

    def ModuleFeaturesImplemented(self):
        """
        alias: CMD0040h
        return: Module return LPL (bytes)
        """
        success, last_command_result = self.__cdb(0x0040)
        if not success:
            raise ValueError('CDB command failed. Last command result: {result:02X}h'.format(result=last_command_result))
        rlpl = self.__cdb.read_rlpl()
        return rlpl

    def GetFirmwareInfo(self):
        """
        alias: CMD0100h
        """
        success, last_command_result = self.__cdb(0x0100)
        if not success:
            raise ValueError('CDB command failed. Last command result: {result:02X}h'.format(result=last_command_result))
        rlpl = self.__cdb.read_rlpl()
        fw_status = rlpl[0]
        result = {}
        result['Image A is Running'] = fw_status & 0x01  # bit0
        result['Image A is Committed'] = (fw_status >> 1) & 0x01  # bit1
        result['Image A is Empty'] = (fw_status >> 2) & 0x01  # bit2
        result['Image B is Running'] = (fw_status >> 4) & 0x01  # bit4
        result['Image B is Committed'] = (fw_status >> 5) & 0x01  # bit5
        result['Image B is Empty'] = (fw_status >> 6) & 0x01  # bit6
        result['Image A Major'] = rlpl[2]
        result['Image A Minor'] = rlpl[3]
        result['Image A Build'] = (rlpl[4]<<8) | rlpl[5]
        result['Sub-MCU Image A Version'] = struct.unpack('>I', rlpl[6:10])[0]  # 142-145
        result['Sub-MCU Running Image'] = rlpl[10]
        result['DSP Image A Version'] = struct.unpack('>I', rlpl[11:15])[0]  #147-150
        result['Image B Major'] = rlpl[174-136]  # 174
        result['Image B Minor'] = rlpl[175-136]  # 175
        result['Image B Build'] = (rlpl[176-136]<<8) | rlpl[177-136]  #176,177
        result['Sub-MCU Image B Version'] = struct.unpack('>I', rlpl[(178-136):(182-136)])[0]#178-181
        result['DSP Image B Version'] = struct.unpack('>I', rlpl[(182-136):(186-136)])[0]#182-185
        return result