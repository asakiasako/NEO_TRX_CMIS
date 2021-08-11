import struct
import time

class CdbApi:

    def __init__(self, cdb):
        self.__cdb = cdb
        # alias of APIs
        self.CMD0000h = self.QueryStatus
        self.CMD0001h = self.EnterPassword
        self.CMD0002h = self.ChangePassword
        self.CMD0040h = self.ModuleFeaturesImplemented
        self.CMD0100h = self.GetFirmwareInfo
        self.CMD0109h = self.RunFirmwareImage
        self.CMD010Ah = self.CommitImage

    def QueryStatus(self, delay=0):
        """
        alias: CMD0000h
        delay: delay time before reply in ms
        """
        lpl = delay.to_bytes(2, 'big')
        success, last_command_result = self.__cdb(0x0000, lpl=lpl)
        if not success:
            last_command_result_desc_map = {
                0b000000: 'Failed, no specific failure code',
                0b000101: 'CdbChkCode error',
            }
            raise ValueError('CDB command failed. Last command result: {result:06b}b | {msg}'.format(
                result=last_command_result, msg=last_command_result_desc_map.get(last_command_result, 'Unknown failure code')))
        else:
            rlpl = self.__cdb.read_rlpl()
            reply = {
                'Length of Status': rlpl[0],
                'Unlock level and privileges': rlpl[1],
                'Firmware download allowed': rlpl[2]
            }
            return reply

    def EnterPassword(self, password):
        """
        alias: CMD0001h
        password: int|bytes, 4-byte password
        """
        cmd_code = 0x0001
        if isinstance(password, int):
            if not 0 <= password <= 0xFFFFFFFF:
                raise ValueError('Invalid password: {psw:08X}h. Out of range.'.format(psw=password))
            password = password.to_bytes(4, 'big')
        elif isinstance(password, bytes):
            if len(bytes) != 4:
                raise ValueError('Invalid password: length of bytes should be 4.')
        else:
            raise TypeError('Invalid type for password. Only int or bytes are valid.')
        success, last_command_result = self.__cdb(cmd_code, lpl=password)
        if not success:
            last_command_result_desc_map = {
                0b000000: 'Failed, no specific failure code',
                0b000101: 'CdbChkCode error',
                0b000110: 'Password error – not accepted',
            }
            raise ValueError('CDB command failed. Last command result: {result:06b}b | {msg}'.format(
                result=last_command_result, msg=last_command_result_desc_map.get(last_command_result, 'Unknown failure code')))
    
    def ChangePassword(self, password):
        """
        alias: CMD0002h
        password: int|bytes, 4-byte password
        """
        cmd_code = 0x0002
        if isinstance(password, int):
            if not 0 <= password <= 0xFFFFFFFF:
                raise ValueError('Invalid password: {psw:08X}h. Out of range.'.format(psw=password))
            password = password.to_bytes(4, 'big')
        elif isinstance(password, bytes):
            if len(bytes) != 4:
                raise ValueError('Invalid password: length of bytes should be 4.')
        else:
            raise TypeError('Invalid type for password. Only int or bytes are valid.')
        success, last_command_result = self.__cdb(cmd_code, lpl=password)
        if not success:
            last_command_result_desc_map = {
                0b000000: 'Failed, no specific failure code',
                0b000010: 'Parameter range error (e.g. Bit 31 is set).',
                0b000101: 'CdbChkCode error',
                0b000110: 'Password error – not accepted',
            }
            raise ValueError('CDB command failed. Last command result: {result:06b}b | {msg}'.format(
                result=last_command_result, msg=last_command_result_desc_map.get(last_command_result, 'Unknown failure code')))

    def ModuleFeaturesImplemented(self):
        """
        alias: CMD0040h
        return: Module return LPL (bytes)
        """
        success, last_command_result = self.__cdb(0x0040)
        if not success:
            last_command_result_desc_map = {
                0b000000: 'Failed, no specific failure code',
                0b000101: 'CdbChkCode error',
            }
            raise ValueError('CDB command failed. Last command result: {result:06b}b | {msg}'.format(
                result=last_command_result, msg=last_command_result_desc_map.get(last_command_result, 'Unknown failure code')))
        else:
            rlpl = self.__cdb.read_rlpl()
            return rlpl

    def GetFirmwareInfo(self):
        """
        alias: CMD0100h
        """
        success, last_command_result = self.__cdb(0x0100)
        if not success:
            last_command_result_desc_map = {
                0b000000: 'Failed, no specific failure code',
                0b000010: 'Parameter range error or not supported',
                0b000101: 'CdbChkCode error',
            }
            raise ValueError('CDB command failed. Last command result: {result:06b}b | {msg}'.format(
                result=last_command_result, msg=last_command_result_desc_map.get(last_command_result, 'Unknown failure code')))
        else:
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

    def RunFirmwareImage(self, reset_mode=0x01, delay_to_reset=0):
        """
        alias: CMD0109h
        reset_mode: <int> 
            00h = Traffic affecting Reset to Inactive Image.
            01h = Attempt Hitless Reset to Inactive Image
            02h = Traffic affecting Reset to Running Image.
            03h = Attempt Hitless Reset to Running Image
        delay_to_reset: <int> unit in ms
        """
        lpl = bytes([0, reset_mode]) + int.to_bytes(delay_to_reset, 2, 'big')
        self.__cdb(0x0109, lpl=lpl, _async=True)

        time.sleep(2) # CMIS: TWI should ready in 2s after run image
        # self.__cdb.wait_for_complete()
        success = not self.__cdb.STS_FAIL
        last_command_result = self.__cdb.last_command_result

        if not success:
            last_command_result_desc_map = {
                0b000000: 'Failed, no specific failure code',
                0b000010: 'Parameter range error or not supported',
                0b000101: 'CdbChkCode error',
            }
            raise ValueError('CDB command failed. Last command result: {result:06b}b | {msg}'.format(
                result=last_command_result, msg=last_command_result_desc_map.get(last_command_result, 'Unknown failure code')))

    def CommitImage(self):
        """
        alias: CMD010Ah
        """
        success, last_command_result = self.__cdb(0x010A)
        if not success:
            last_command_result_desc_map = {
                0b000000: 'Failed, no specific failure code',
                0b000010: 'Parameter range error or not supported',
                0b000101: 'CdbChkCode error',
            }
            raise ValueError('CDB command failed. Last command result: {result:06b}b | {msg}'.format(
                result=last_command_result, msg=last_command_result_desc_map.get(last_command_result, 'Unknown failure code')))
