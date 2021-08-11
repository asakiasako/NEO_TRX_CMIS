####################################################
#          Copyright (c) 2021 Inphi Corp.          #
####################################################
####################################################
#                Inphi Confidential                #
####################################################


class CommandStatus:
    COMMAND_SUCCESS = 0
    COMMAND_INVALID = 1
    COMMAND_INVALID_FIELD = 2
    COMMAND_FAILED = 3
    COMMAND_EXCEPTION = 4

class HLU_Actions:
    HLU_PREPARE = 0
    HLU_START = 1
    HLU_ABORT = 2

class HLU_Info:
    HLU_ALREADY_PREPARED = 1
    HLU_NOT_PREPARED = 2
    HLU_TASK_ERRORED = 3
    HLU_NOT_COMPATIBLE = 4
    HLU_DU_MEMORY_IN_USE = 5

class Actions:
    STOP_ROUTINE = 0
    START_ROUTINE = 1
    PAUSE_ROUTINE = 2
    NONE_ROUTINE = 3
    STATUS_ROUTINE = 4
    STOP_ALL_ROUTINE = 5

class Path:
    BOTH = 0
    INGRESS = 1
    EGRESS = 2

class Direction:
    DIRECTION__INGRESS = 1
    DIRECTION__EGRESS = 2

class Line_Fec:
    CFEC = 2
    STAIRCASE = 3
    ZR = 4
    OFEC = 9
    GFEC = 10
    OFEC_LL = 11

class Line_Modulation:
    LM_QPSK = 4
    LM_QAM8 = 6
    LM_QAM16 = 8

class Host_Modulation:
    HM_PAM4 = 0
    HM_NRZ = 1

class Signal_Type:
    ST_DISABLE = 0
    ST_OTL = 1
    ST_FLEXO = 2
    ST_100GEBA = 3
    ST_100GEBJSR = 4
    ST_100GEBJLR = 5
    ST_400GE = 6
    ST_FLEXO_LITE = 7

class Line_Mapping:
    GMP_NONE = 0
    GMP_4 = 1
    GMP_C = 2
    GMP_4C = 3
    GMP_P = 4
    GMP_4P = 5
    GMP_CP = 6
    GMP_4CP = 7
    GMP_ZR = 16

class Osr_Line:
    ONE = 0
    THREE_OVER_TWO = 1
    SIX_OVER_FIVE = 2
    TWELVE_OVER_FIVE = 3
    THREE = 4

class Enable:
    DISABLE = 0
    ENABLE = 1

class Lpbk_Mode:
    LPBK_HOST_VERY_NEAR = 0
    LPBK_HOST_NEAR = 1
    LPBK_HOST_CORE = 2
    RESERVED_0 = 3
    LPBK_HOST_FAR = 4
    RESERVED_1 = 5
    LPBK_LINE_CORE = 6
    LPBK_LINE_FAR = 7
    LPBK_LINE_VERY_FAR = 8

class Framer_Channel:
    FRAMER_CH_A = 0
    FRAMER_CH_B = 1
    FRAMER_CH_C = 2
    FRAMER_CH_D = 3
    FRAMER_X00GE = 4

class Framer_100G_Channel:
    FRAMER_100G_CHANNEL__CH_A = 0
    FRAMER_100G_CHANNEL__CH_B = 1
    FRAMER_100G_CHANNEL__CH_C = 2
    FRAMER_100G_CHANNEL__CH_D = 3

class Config_Override:
    OVERRIDE_PLL_MODE_RPLL_PLL_TOP = 12
    OVERRIDE_DISABLE_EGRESS_SM = 16

class Oha_Otn_Overhead_Fields:
    OHA_OTN_FAS_1 = 1
    OHA_OTN_FAS_2 = 2
    OHA_OTN_FAS_3 = 3
    OHA_OTN_FAS_4 = 4
    OHA_OTN_FAS_5 = 5
    OHA_OTN_FAS_6 = 6
    OHA_OTN_MFAS = 7
    OHA_OTN_SM_1 = 8
    OHA_OTN_SM_2 = 9
    OHA_OTN_SM_3 = 10
    OHA_OTN_GCC0_0 = 11
    OHA_OTN_GCC0_1 = 12
    OHA_OTN_RES_A_0 = 13
    OHA_OTN_RES_A_1 = 14
    OHA_OTN_RES_X = 15
    OHA_OTN_JC_XX = 16
    OHA_OTN_RSB_1 = 17
    OHA_OTN_RSB_2 = 18
    OHA_OTN_PM_TCM = 19
    OHA_OTN_TCM_ACT = 20
    OHA_OTN_TCM6_1 = 21
    OHA_OTN_TCM6_2 = 22
    OHA_OTN_TCM6_3 = 23
    OHA_OTN_TCM5_1 = 24
    OHA_OTN_TCM5_2 = 25
    OHA_OTN_TCM5_3 = 26
    OHA_OTN_TCM4_1 = 27
    OHA_OTN_TCM4_2 = 28
    OHA_OTN_TCM4_3 = 29
    OHA_OTN_FTFL = 30
    OHA_OTN_RES_Y = 31
    OHA_OTN_JC_Y = 32
    OHA_OTN_TCM3_1 = 33
    OHA_OTN_TCM3_2 = 34
    OHA_OTN_TCM3_3 = 35
    OHA_OTN_TCM2_1 = 36
    OHA_OTN_TCM2_2 = 37
    OHA_OTN_TCM2_3 = 38
    OHA_OTN_TCM1_1 = 39
    OHA_OTN_TCM1_2 = 40
    OHA_OTN_TCM1_3 = 41
    OHA_OTN_PM_1 = 42
    OHA_OTN_PM_2 = 43
    OHA_OTN_PM_3 = 44
    OHA_OTN_EXP_1 = 45
    OHA_OTN_EXP_2 = 46
    OHA_OTN_RES_Z = 47
    OHA_OTN_JC_Z = 48
    OHA_OTN_GCC1_1 = 49
    OHA_OTN_GCC1_2 = 50
    OHA_OTN_GCC2_1 = 51
    OHA_OTN_GCC2_2 = 52
    OHA_OTN_APS_1 = 53
    OHA_OTN_APS_2 = 54
    OHA_OTN_APS_3 = 55
    OHA_OTN_APS_4 = 56
    OHA_OTN_RES_C_1 = 57
    OHA_OTN_RES_C_2 = 58
    OHA_OTN_RES_C_3 = 59
    OHA_OTN_RES_C_4 = 60
    OHA_OTN_RES_C_5 = 61
    OHA_OTN_RES_C_6 = 62
    OHA_OTN_PSI = 63
    OHA_OTN_NJO = 64

class Oha_Flexo_Overhead_Fields:
    OHA_FLEXO_MFFF_F = 1
    OHA_FLEXO_STAT_F = 2
    OHA_FLEXO_GID_0 = 3
    OHA_FLEXO_GID_1 = 4
    OHA_FLEXO_GID_2 = 5
    OHA_FLEXO_PID = 6
    OHA_FLEXO_MAP_0 = 7
    OHA_FLEXO_MAP_1 = 8
    OHA_FLEXO_MAP_2 = 9
    OHA_FLEXO_MAP_3 = 10
    OHA_FLEXO_CRC_0 = 11
    OHA_FLEXO_CRC_1 = 12
    OHA_FLEXO_FCC_0 = 13
    OHA_FLEXO_FCC_1 = 14
    OHA_FLEXO_FCC_2 = 15
    OHA_FLEXO_FCC_3 = 16
    OHA_FLEXO_FCC_4 = 17
    OHA_FLEXO_FCC_5 = 18
    OHA_FLEXO_FCC_6 = 19
    OHA_FLEXO_FCC_7 = 20
    OHA_FLEXO_FCC_8 = 21
    OHA_FLEXO_FCC_9 = 22
    OHA_FLEXO_FCC_10 = 23
    OHA_FLEXO_FCC_11 = 24
    OHA_FLEXO_FCC_12 = 25
    OHA_FLEXO_FCC_13 = 26
    OHA_FLEXO_OSMC_0 = 27
    OHA_FLEXO_OSMC_1 = 28
    OHA_FLEXO_RES_F0 = 29
    OHA_FLEXO_RES_F1 = 30
    OHA_FLEXO_RES_F2 = 31
    OHA_FLEXO_RES_F3 = 32
    OHA_FLEXO_RES_F4 = 33
    OHA_FLEXO_RES_F5 = 34
    OHA_FLEXO_RES_F6 = 35
    OHA_FLEXO_RES_F7 = 36
    OHA_FLEXO_RES_F8 = 37
    OHA_FLEXO_RES_F9 = 38
    OHA_FLEXO_RES_F10 = 39
    OHA_FLEXO_RES_F11 = 40

class Oha_Sgmii_Interface_Mode:
    OHA_SGMII_OFF = 0
    OHA_SGMII_HALF_SPEED = 1
    OHA_SGMII_FULL_SPEED = 2
    OHA_SGMII_CLOCKS = 3

class Oha_Sgmii_Channel:
    OHA_SGMII_CHANNEL_0 = 0
    OHA_SGMII_CHANNEL_1 = 1

class Oha_Loopback_Mode:
    OHA_LPBK_DISABLED = 0
    OHA_LPBK_TXPCS_TO_RXPCS = 1
    OHA_LPBK_RXMAC_TO_TXMAC = 2

class Oha_Frame_Discard_Mode:
    OHA_FRAME_ACCEPTED = 0
    OHA_FRAME_REJECTED = 1

class Oh_Map_Level:
    FRAMER_OH_SEL_HOST = 0
    FRAMER_OH_SEL_MAP1 = 1
    FRAMER_OH_SEL_MAP2 = 2
    FRAMER_OH_SEL_LINE = 3

class Oh_Layer_Level:
    FRAMER_OH_TCM1 = 0
    FRAMER_OH_TCM2 = 1
    FRAMER_OH_TCM3 = 2
    FRAMER_OH_TCM4 = 3
    FRAMER_OH_TCM5 = 4
    FRAMER_OH_TCM6 = 5
    FRAMER_OH_PM = 6
    FRAMER_OH_SM = 7

class Pcs_Signal_Type:
    IDLE = 0
    LOCAL_FAULT = 1
    REMOTE_FAULT = 2

class Pcs_Mode:
    PCS_MODE__TRANSPARENT = 0
    PCS_MODE__FLEXE = 1
    PCS_MODE__REGEN_WO_BIP_PROP = 2
    PCS_MODE__REGEN_W_BIP_PROP = 3
    PCS_MODE__IMP_WO_BIP_PROP = 4
    PCS_MODE__IMP_W_BIP_PROP = 5
    PCS_MODE__NO_TRANSCODING_ZR = 6

class Framer_Gen_Check_Signal_Type:
    FRAMER_PRBS_7 = 0
    FRAMER_PRBS_9 = 1
    FRAMER_PRBS_11 = 2
    FRAMER_PRBS_15 = 3
    FRAMER_PRBS_20 = 4
    FRAMER_PRBS_23 = 5
    FRAMER_PRBS_29 = 6
    FRAMER_PRBS_31 = 7
    FRAMER_NULL = 8
    FRAMER_AIS = 9
    FRAMER_LCK = 10
    FRAMER_OCI = 11

class Host_Lane:
    HOST_LANE_0 = 0
    HOST_LANE_1 = 1
    HOST_LANE_2 = 2
    HOST_LANE_3 = 3
    HOST_LANE_4 = 4
    HOST_LANE_5 = 5
    HOST_LANE_6 = 6
    HOST_LANE_7 = 7

class Host_Unframed_Standard_Pattern_Type:
    HOST_JP03B = 2
    HOST_LIN = 3
    HOST_CJT = 4
    HOST_SSPRQ = 5

class Host_Unframed_Prbs_Type:
    HOST_PRBS_31 = 0
    HOST_PRBS_7 = 1
    HOST_PRBS_9 = 2
    HOST_PRBS_11 = 4
    HOST_PRBS_13 = 5
    HOST_PRBS_15 = 6
    HOST_PRBS_23 = 7
    HOST_PRBS_16 = 9

class Line_Lane_Selector:
    LINE_LANE_HI = 0
    LINE_LANE_HQ = 1
    LINE_LANE_VI = 2
    LINE_LANE_VQ = 3

class Dsp_Action:
    STOP_DSP = 0
    START_DSP = 1
    TOGGLE_DSP = 2

class Polarization:
    POLARIZATION_H = 0
    POLARIZATION_V = 1

class Cfec_Prbs_Mode:
    CFEC_PRBS_7 = 0
    CFEC_PRBS_9 = 1
    CFEC_PRBS_11 = 2
    CFEC_PRBS_13 = 3
    CFEC_PRBS_15 = 4
    CFEC_PRBS_23 = 5
    CFEC_PRBS_31 = 6

class Gpio_Direction:
    INPUT = 0
    OUTPUT = 1

class Gpio_Status:
    LOW = 0
    HIGH = 1

class Pulse_Shaping_Filter:
    RAISED_COSINE = 0
    ROOT_RAISED_COSINE = 1

class Roll_Off_Factor:
    PSF_ROF_0P1 = 1
    PSF_ROF_0P2 = 2
    PSF_ROF_0P3 = 3
    PSF_ROF_0P4 = 4
    PSF_ROF_0P5 = 5

class Lane_Polarity:
    LANE_POLARITY__NOT_INVERTED = 0
    LANE_POLARITY__INVERTED = 1

class Sync_Status:
    SYNC_STATUS__OUT_OF_SYNC = 0
    SYNC_STATUS__ON_SYNC = 1

class Oh_Source_Mode:
    OH_SOURCE_MODE__TRANSPARENT = 0
    OH_SOURCE_MODE__OPERATIONAL = 1

class Oh_Sink_Mode:
    OH_SINK_MODE__MONITOR = 0
    OH_SINK_MODE__OPERATIONAL = 1

class Oh_Aps_Channel:
    OH_APS_CHANNEL__ODUK_PATH = 0
    OH_APS_CHANNEL__ODUK_TCM1 = 1
    OH_APS_CHANNEL__ODUK_TCM2 = 2
    OH_APS_CHANNEL__ODUK_TCM3 = 3
    OH_APS_CHANNEL__ODUK_TCM4 = 4
    OH_APS_CHANNEL__ODUK_TCM5 = 5
    OH_APS_CHANNEL__ODUK_TCM6 = 6
    OH_APS_CHANNEL__ODUK_SLT = 7

class Oh_Dm_Mode:
    OH_DM_MODE__TRANSIT = 0
    OH_DM_MODE__LOOPBACK = 1
    OH_DM_MODE__MEASURE = 2

class Oh_Dm_Subfield:
    OH_DM_SUBFIELD__DMT1 = 0
    OH_DM_SUBFIELD__DMT2 = 1
    OH_DM_SUBFIELD__DMT3 = 2
    OH_DM_SUBFIELD__DMT4 = 3
    OH_DM_SUBFIELD__DMT5 = 4
    OH_DM_SUBFIELD__DMT6 = 5
    OH_DM_SUBFIELD__DMP = 6

class Oh_Dm_Action:
    OH_DM_ACTION__READ = 0
    OH_DM_ACTION__START = 1

class Oh_Dm_Result:
    OH_DM_RESULT__FAIL = 0
    OH_DM_RESULT__SUCCESS = 1

class Egress_Ethernet_Maintenance_Signal:
    EGRESS_ETHERNET_MAINTENANCE_SIGNAL__LF = 0
    EGRESS_ETHERNET_MAINTENANCE_SIGNAL__AIS = 1

class Ingress_Ethernet_Maintenance_Signal:
    INGRESS_ETHERNET_MAINTENANCE_SIGNAL__LF = 0
    INGRESS_ETHERNET_MAINTENANCE_SIGNAL__UPRBS = 1

class Otn_Maintenance_Signal:
    OTN_MAINTENANCE_SIGNAL__AIS = 0
    OTN_MAINTENANCE_SIGNAL__UPRBS = 1

class FlexO_Maintenance_Signal:
    FLEXO_MAINTENANCE_SIGNAL__AIS = 0
    FLEXO_MAINTENANCE_SIGNAL__UPRBS = 1

class Error_Code_Info:
    ERROR_CODE_INFO__SUCCESS = 0
    ERROR_CODE_INFO__FRAMER_CHANNEL_DISABLE = 1
    ERROR_CODE_INFO__SIGNAL_TYPE_INCORRECT = 2
    ERROR_CODE_INFO__LINE_FEC_INCORRECT = 3
    ERROR_CODE_INFO__OSR_INCORRECT = 4
    ERROR_CODE_INFO__HRX_MAPPING_EQUALS = 5
    ERROR_CODE_INFO__HTX_MAPPING_EQUALS = 6
    ERROR_CODE_INFO__HRX_HTX_MAPPING_EQUALS = 7
    ERROR_CODE_INFO__RESERVED_0 = 8
    ERROR_CODE_INFO__LANE_DISABLED = 9
    ERROR_CODE_INFO__FIR_COEFFS_ABS_VAL_SUM = 10
    ERROR_CODE_INFO__MAP_LEVEL_ERROR = 11
    ERROR_CODE_INFO__NO_MAPPING_ENABLED = 12
    ERROR_CODE_INFO__INVALID_REORDER = 13
    ERROR_CODE_INFO__BCD_DISABLE = 14
    ERROR_CODE_INFO__CD_WRONG_VALUES = 15
    ERROR_CODE_INFO__FRAMER_CHANNELS_EQUALS = 16
    ERROR_CODE_INFO__ONE_FRAMER_CHANNEL_ENABLED = 17
    ERROR_CODE_INFO__ENCRYPTION_ENABLED = 18
    ERROR_CODE_INFO__ENCRYPTION_DISABLED = 19
    ERROR_CODE_INFO__BAD_PATTERN_MODULATION_COMB = 20
    ERROR_CODE_INFO__DUAL_DISABLED = 21
    ERROR_CODE_INFO__LANE_REASSIGNMENT_EQUALS = 22
    ERROR_CODE_INFO__MODULE_DISABLED = 23
    ERROR_CODE_INFO__STILL_TRANSMITTING = 24
    ERROR_CODE_INFO__LTX_MASK_OUT_OF_FILTER_RANGE = 25
    ERROR_CODE_INFO__WRONG_API_PAGE = 26
    ERROR_CODE_INFO__FIR_COEFF_MAIN_TAP_ZERO = 27
    ERROR_CODE_INFO__CANT_CHANGE_HI_LANE_SKEW = 28
    ERROR_CODE_INFO__PLEASE_RETRY_IN_5_SECONDS = 29
    ERROR_CODE_INFO__UNCORRECTED_CODEWORD_NOT_ZERO = 30
    ERROR_CODE_INFO__API_UNAVAILABLE_IN_THIS_MODE = 31
    ERROR_CODE_INFO__PCS_MODE_DISABLE = 32
    ERROR_CODE_INFO__UNAVAILABLE_PCS_MODE = 33
    ERROR_CODE_INFO__CHIP_NOT_EFUSED = 35
    ERROR_CODE_INFO__WINDOW_PARAMETER_NOT_ALLOWED = 37
    ERROR_CODE_INFO__UNCALIBRATED_TEMPERATURE = 38
    ERROR_CODE_INFO__INVALID_LINE_HARDWARE_PINS = 41
    ERROR_CODE_INFO__UP_CANT_BE_LOWER_THAN_DOWN = 43
    ERROR_CODE_INFO__SIMILAR_MAIN_TAPS_REQ = 44
    ERROR_CODE_INFO__FW_SYRMA_NOT_LOADED = 45
    ERROR_CODE_INFO__DISABLED_BACK_CHANNEL = 46
    ERROR_CODE_INFO__SNR_NRZ_NOT_SUPPORTED = 47
    ERROR_CODE_INFO__FLEXO_GROUP_PRESENT = 49
    ERROR_CODE_INFO__NO_FLEXO_GROUP_PRESENT = 50
    ERROR_CODE_INFO__CANT_UNGROUP_CHANNELS = 51
    ERROR_CODE_INFO__CANT_GROUP_ONE_CHANNEL = 52
    ERROR_CODE_INFO__SAME_GROUP_CONFIG = 53
    ERROR_CODE_INFO__DIFFERENT_CLIENT_TYPES = 54
    ERROR_CODE_INFO__INVALID_BYTE_VALUE = 55
    ERROR_CODE_INFO__DU_EMPTY = 56
    ERROR_CODE_INFO__DU_WRONG_CONFIGURATION = 57
    ERROR_CODE_INFO__DSP_NOT_IN_LOCK = 58
    ERROR_CODE_INFO__FRAMER_NOT_IN_LOCK = 59

class Hardware_Pins:
    HARDWARE_PINS__SSD = 0
    HARDWARE_PINS__SSF = 1
    HARDWARE_PINS__LASER_OFF = 2

class Alarm_Status:
    ALARM_STATUS__CLEAR = 0
    ALARM_STATUS__SET = 1

class Value:
    VALUE__CLEAR = 0
    VALUE__SET = 1

class Pm_Trigger_Source:
    PM_TRIGGER_SOURCE__MANUAL_TRIGGER = 0
    PM_TRIGGER_SOURCE__EXTERNAL_TRIGGER = 1

class Optical_Trigger_Source:
    OPTICAL_TRIGGER_SOURCE__MANUAL_TRIGGER = 0
    OPTICAL_TRIGGER_SOURCE__INTERVAL_TRIGGER = 1

class Api_IDs:
    DENEBAPI_SETTRANSCEIVERMODE_ID = 256
    DENEBAPI_GETTRANSCEIVERMODE_ID = 257
    DENEBAPI_SETHOSTDYNAMICREPROVISIONING_ID = 258
    DENEBAPI_SETHOSTBALLMAP_ID = 259
    DENEBAPI_GETHOSTBALLMAP_ID = 260
    DENEBAPI_SETLOOPBACKMODE_ID = 261
    DENEBAPI_GETLOOPBACKMODE_ID = 262
    DENEBAPI_SETPCSMODE_ID = 263
    DENEBAPI_GETPCSMODE_ID = 264
    DENEBAPI_SETHOSTEGRESSLANEPOLARITY_ID = 268
    DENEBAPI_GETHOSTEGRESSLANEPOLARITY_ID = 269
    DENEBAPI_SETHOSTINGRESSLANEPOLARITY_ID = 272
    DENEBAPI_GETHOSTINGRESSLANEPOLARITY_ID = 273
    DENEBAPI_SETHOSTINGRESSFILTERCOEFFICIENTS_ID = 274
    DENEBAPI_GETHOSTINGRESSFILTERCOEFFICIENTS_ID = 275
    DENEBAPI_SETHOSTINGRESSLANEMUTE_ID = 276
    DENEBAPI_GETHOSTINGRESSLANEMUTE_ID = 277
    DENEBAPI_SETLINEEGRESSLANEPOLARITY_ID = 278
    DENEBAPI_GETLINEEGRESSLANEPOLARITY_ID = 279
    DENEBAPI_SETLINEEGRESSLANEREASSIGNMENT_ID = 280
    DENEBAPI_GETLINEEGRESSLANEREASSIGNMENT_ID = 281
    DENEBAPI_SETLINEEGRESSHIGHSRFILTERCOEFFICIENTS_ID = 282
    DENEBAPI_GETLINEEGRESSHIGHSRFILTERCOEFFICIENTS_ID = 283
    DENEBAPI_SETLINEEGRESSLOWSRFILTERCOEFFICIENTS_ID = 284
    DENEBAPI_GETLINEEGRESSLOWSRFILTERCOEFFICIENTS_ID = 285
    DENEBAPI_SETLINEEGRESSHIGHSRLANESKEW_ID = 286
    DENEBAPI_GETLINEEGRESSHIGHSRLANESKEW_ID = 287
    DENEBAPI_SETLINEEGRESSLOWSRLANESKEW_ID = 288
    DENEBAPI_GETLINEEGRESSLOWSRLANESKEW_ID = 289
    DENEBAPI_SETLINEEGRESSHIGHSRPULSESHAPING_ID = 290
    DENEBAPI_GETLINEEGRESSHIGHSRPULSESHAPING_ID = 291
    DENEBAPI_SETLINEEGRESSHIGHSRPREEMPHASIS_ID = 292
    DENEBAPI_GETLINEEGRESSHIGHSRPREEMPHASIS_ID = 293
    DENEBAPI_SETLINEEGRESSHIGHSRLANEAMPLITUDE_ID = 294
    DENEBAPI_GETLINEEGRESSHIGHSRLANEAMPLITUDE_ID = 295
    DENEBAPI_SETLINEEGRESSLOWSRLANEATTENUATION_ID = 296
    DENEBAPI_GETLINEEGRESSLOWSRLANEATTENUATION_ID = 297
    DENEBAPI_SETLINEEGRESSLANEMUTE_ID = 300
    DENEBAPI_GETLINEEGRESSLANEMUTE_ID = 301
    DENEBAPI_SETLINEINGRESSSKEW_ID = 302
    DENEBAPI_GETLINEINGRESSSKEW_ID = 303
    DENEBAPI_SETLINEINGRESSBCDFILTER_ID = 304
    DENEBAPI_GETLINEINGRESSBCDFILTER_ID = 305
    DENEBAPI_SETLINEINGRESSCCRBYPASS_ID = 306
    DENEBAPI_GETLINEINGRESSCCRBYPASS_ID = 307
    DENEBAPI_SETLINEINGRESSBPS_ID = 308
    DENEBAPI_GETLINEINGRESSBPS_ID = 309
    DENEBAPI_SETLINEINGRESSMATRIXROTATOR_ID = 310
    DENEBAPI_GETLINEINGRESSMATRIXROTATOR_ID = 311
    DENEBAPI_SETLINEINGRESSFLECDRANGE_ID = 312
    DENEBAPI_GETLINEINGRESSFLECDRANGE_ID = 313
    DENEBAPI_SETLINEINGRESSLOSCONFIG_ID = 314
    DENEBAPI_GETLINEINGRESSLOSCONFIG_ID = 315
    DENEBAPI_SETLINEINGRESSAGCCONFIG_ID = 316
    DENEBAPI_GETLINEINGRESSAGCCONFIG_ID = 317
    DENEBAPI_GETLINEINGRESSAGCSTATUS_ID = 318
    DENEBAPI_GETLINEINGRESSDSPSTATUS_ID = 319
    DENEBAPI_GETLINEOPTICALCHANNELMONITORSITEM_ID = 320
    DENEBAPI_GETLINEOPTICALCHANNELMONITORSALL_ID = 321
    DENEBAPI_GETZROHPMSIACCEPTED_ID = 322
    DENEBAPI_GETZROHPMSICONFIG_ID = 323
    DENEBAPI_SETZROHPMSICONFIG_ID = 324
    DENEBAPI_SETOTNHARDWAREALARMSINTERFACESCONFIG_ID = 325
    DENEBAPI_GETOTNHARDWAREALARMSINTERFACESCONFIG_ID = 326
    DENEBAPI_SETOTNGMPHARDWAREALARMSINTERFACESCONFIG_ID = 327
    DENEBAPI_GETOTNGMPHARDWAREALARMSINTERFACESCONFIG_ID = 328
    DENEBAPI_SETOTNOHPHARDWAREALARMSINTERFACESCONFIG_ID = 329
    DENEBAPI_GETOTNOHPHARDWAREALARMSINTERFACESCONFIG_ID = 330
    DENEBAPI_SETETHERNETHARDWAREALARMSINTERFACESCONFIG_ID = 331
    DENEBAPI_GETETHERNETHARDWAREALARMSINTERFACESCONFIG_ID = 332
    DENEBAPI_SETFLEXOHARDWAREALARMSINTERFACESCONFIG_ID = 333
    DENEBAPI_GETFLEXOHARDWAREALARMSINTERFACESCONFIG_ID = 334
    DENEBAPI_SETFLEXEHARDWAREALARMSINTERFACESCONFIG_ID = 335
    DENEBAPI_GETFLEXEHARDWAREALARMSINTERFACESCONFIG_ID = 336
    DENEBAPI_SETFLEXOGROUPCONFIG_ID = 337
    DENEBAPI_GETFLEXOGROUPCONFIG_ID = 338
    DENEBAPI_SETCLIENTSWAP_ID = 339
    DENEBAPI_GETCLIENTSWAP_ID = 340
    DENEBAPI_SETETHERNETCONSEQUENTACTIONSCONFIG_ID = 341
    DENEBAPI_GETETHERNETCONSEQUENTACTIONSCONFIG_ID = 342
    DENEBAPI_SETFLEXOCONSEQUENTACTIONSCONFIG_ID = 343
    DENEBAPI_GETFLEXOCONSEQUENTACTIONSCONFIG_ID = 344
    DENEBAPI_SETENABLECONSEQUENTACTIONS_ID = 347
    DENEBAPI_GETENABLECONSEQUENTACTIONS_ID = 348
    DENEBAPI_SETETHERNETMAINTENANCESIGNALCONFIG_ID = 349
    DENEBAPI_GETETHERNETMAINTENANCESIGNALCONFIG_ID = 350
    DENEBAPI_GETOTNALARMS_ID = 351
    DENEBAPI_GETOTNGMPALARMS_ID = 352
    DENEBAPI_GETOTNOHPALARMS_ID = 353
    DENEBAPI_GETETHERNETALARMS_ID = 354
    DENEBAPI_GETFLEXOALARMS_ID = 355
    DENEBAPI_GETFLEXEALARMS_ID = 356
    DENEBAPI_GETFAWERRORSTATISTICS_ID = 357
    DENEBAPI_GETPCSERRORSTATISTICS_ID = 358
    DENEBAPI_GETERRORCORRECTIONSTATISTICS_ID = 359
    DENEBAPI_GETOTNOHPPMCOUNTERS_ID = 360
    DENEBAPI_GETETHERNETCOUNTERS_ID = 361
    DENEBAPI_SETPERFORMANCEMONITORTRIGGERSOURCE_ID = 362
    DENEBAPI_GETPERFORMANCEMONITORTRIGGERSOURCE_ID = 363
    DENEBAPI_TRIGGERMONITORS_ID = 364
    DENEBAPI_SETHOSTUNFRAMEDTESTPATTERNGENERATORCONFIG_ID = 365
    DENEBAPI_GETHOSTUNFRAMEDTESTPATTERNGENERATORCONFIG_ID = 366
    DENEBAPI_SETHOSTUNFRAMEDTESTPATTERNCHECKERCONFIG_ID = 367
    DENEBAPI_GETHOSTUNFRAMEDTESTPATTERNCHECKERCONFIG_ID = 368
    DENEBAPI_SETHOSTUNFRAMEDCUSTOMPATTERNGENERATORCONFIG_ID = 369
    DENEBAPI_GETHOSTUNFRAMEDCUSTOMPATTERNGENERATORCONFIG_ID = 370
    DENEBAPI_SETHOSTUNFRAMEDCUSTOMPATTERNCHECKERCONFIG_ID = 371
    DENEBAPI_GETHOSTUNFRAMEDCUSTOMPATTERNCHECKERCONFIG_ID = 372
    DENEBAPI_GETHOSTUNFRAMEDTESTPATTERNCHECKERSTATISTICS_ID = 373
    DENEBAPI_SETOTUCLIENTTESTPATTERNGENERATORCONFIG_ID = 374
    DENEBAPI_GETOTUCLIENTTESTPATTERNGENERATORCONFIG_ID = 375
    DENEBAPI_SETOTUCLIENTTESTPATTERNCHECKERCONFIG_ID = 376
    DENEBAPI_GETOTUCLIENTTESTPATTERNCHECKERCONFIG_ID = 377
    DENEBAPI_SETOTUSERVERTESTPATTERNGENERATORCONFIG_ID = 378
    DENEBAPI_GETOTUSERVERTESTPATTERNGENERATORCONFIG_ID = 379
    DENEBAPI_SETOTUSERVERTESTPATTERNCHECKERCONFIG_ID = 380
    DENEBAPI_GETOTUSERVERTESTPATTERNCHECKERCONFIG_ID = 381
    DENEBAPI_GETOTUTESTPATTERNCHECKERSTATISTICS_ID = 382
    DENEBAPI_SETPCSTESTPATTERNGENERATORCONFIG_ID = 383
    DENEBAPI_GETPCSTESTPATTERNGENERATORCONFIG_ID = 384
    DENEBAPI_SETPCSTESTPATTERNCHECKERCONFIG_ID = 385
    DENEBAPI_GETPCSTESTPATTERNCHECKERCONFIG_ID = 386
    DENEBAPI_GETPCSTESTPATTERNCHECKERSTATISTICS_ID = 387
    DENEBAPI_SETCORECFECTESTPATTERNGENERATORCONFIG_ID = 393
    DENEBAPI_GETCORECFECTESTPATTERNGENERATORCONFIG_ID = 394
    DENEBAPI_SETCORECFECTESTPATTERNCHECKERCONFIG_ID = 395
    DENEBAPI_GETCORECFECTESTPATTERNCHECKERCONFIG_ID = 396
    DENEBAPI_GETLINEOFECFRAMEDTESTPATTERNGENERATORCONFIG_ID = 401
    DENEBAPI_GETLINEOFECFRAMEDTESTPATTERNCHECKERCONFIG_ID = 402
    DENEBAPI_SETETHERNETFEC_ID = 406
    DENEBAPI_GETETHERNETFEC_ID = 407
    DENEBAPI_SETETHERNETPACKETTRAPCONFIG_ID = 408
    DENEBAPI_GETETHERNETPACKETTRAPCONFIG_ID = 409
    DENEBAPI_READETHERNETPACKETTRAP_ID = 410
    DENEBAPI_SETETHERNETMAXFRAMELENGTH_ID = 411
    DENEBAPI_GETETHERNETMAXFRAMELENGTH_ID = 412
    DENEBAPI_SETOTNOHPLAYERREORDER_ID = 413
    DENEBAPI_GETOTNOHPLAYERREORDER_ID = 414
    DENEBAPI_SETOTNOHPSOURCEBIP8_ID = 415
    DENEBAPI_GETOTNOHPSOURCEBIP8_ID = 416
    DENEBAPI_SETOTNOHPSOURCETTI_ID = 417
    DENEBAPI_GETOTNOHPSOURCETTI_ID = 418
    DENEBAPI_SETOTNOHPSOURCEAPSCHANNELS_ID = 419
    DENEBAPI_GETOTNOHPSOURCEAPSCHANNELS_ID = 420
    DENEBAPI_SETOTNOHPSOURCEPT_ID = 421
    DENEBAPI_GETOTNOHPSOURCEPT_ID = 422
    DENEBAPI_SETOTNOHPSOURCECSF_ID = 423
    DENEBAPI_GETOTNOHPSOURCECSF_ID = 424
    DENEBAPI_SETOTNOHPSOURCEMSI_ID = 425
    DENEBAPI_GETOTNOHPSOURCEMSI_ID = 426
    DENEBAPI_SETOTNOHPSOURCEFTFL_ID = 427
    DENEBAPI_GETOTNOHPSOURCEFTFL_ID = 428
    DENEBAPI_SETOTNOHPSINKMODE_ID = 429
    DENEBAPI_GETOTNOHPSINKMODE_ID = 430
    DENEBAPI_SETOTNOHPSINKTTIEXPECTED_ID = 431
    DENEBAPI_GETOTNOHPSINKTTIEXPECTED_ID = 432
    DENEBAPI_GETOTNOHPSINKAPSCHANNELS_ID = 434
    DENEBAPI_SETOTNOHPSINKDDEGTHRESHOLD_ID = 439
    DENEBAPI_GETOTNOHPSINKDDEGTHRESHOLD_ID = 440
    DENEBAPI_SETOTNOHPDMMODE_ID = 443
    DENEBAPI_GETOTNOHPDMMODE_ID = 444
    DENEBAPI_RUNOTNOHPDM_ID = 445
    DENEBAPI_SETFLEXOOHPSOURCEMODE_ID = 446
    DENEBAPI_GETFLEXOOHPSOURCEMODE_ID = 447
    DENEBAPI_SETFLEXOOHPSINKFIELDSEXPECTED_ID = 448
    DENEBAPI_GETFLEXOOHPSINKFIELDSEXPECTED_ID = 449
    DENEBAPI_SETFLEXEOHPSINKFIELDSEXPECTED_ID = 450
    DENEBAPI_GETFLEXEOHPSINKFIELDSEXPECTED_ID = 451
    DENEBAPI_SETOHAGLOBALCONFIG_ID = 452
    DENEBAPI_GETOHAGLOBALCONFIG_ID = 453
    DENEBAPI_GETOHAGLOBALSTATUS_ID = 454
    DENEBAPI_GETOTNOHACONFIG_ID = 455
    DENEBAPI_SETOTNOHACONFIG_ID = 456
    DENEBAPI_GETFLEXOOHACONFIG_ID = 461
    DENEBAPI_SETFLEXOOHACONFIG_ID = 462
    DENEBAPI_GETFLEXEOHACONFIG_ID = 467
    DENEBAPI_SETFLEXEOHACONFIG_ID = 468
    DENEBAPI_SETGPIO_ID = 475
    DENEBAPI_GETGPIO_ID = 476
    DENEBAPI_SETGPIOMAP_ID = 477
    DENEBAPI_GETGPIOMAP_ID = 478
    DENEBAPI_READFIRMWAREINFORMATION_ID = 481
    DENEBAPI_UPDATEONEREGISTER_ID = 482
    DENEBAPI_WRITEREGISTER_ID = 483
    DENEBAPI_READREGISTER_ID = 484
    DENEBAPI_GETCHIPID_ID = 485
    DENEBAPI_GETTEMPERATURE_ID = 486
    DENEBAPI_SETOVERRIDEDEFAULTCONFIG_ID = 494
    DENEBAPI_RESETTRANSCEIVER_ID = 500
    DENEBAPI_RESTARTLINEINGRESSDSP_ID = 501
    DENEBAPI_SETGMPCONSEQUENTACTIONCONFIG_ID = 505
    DENEBAPI_GETGMPCONSEQUENTACTIONCONFIG_ID = 506
    DENEBAPI_SETOTNOHPSINKPTEXPECTED_ID = 507
    DENEBAPI_GETOTNOHPSINKPTEXPECTED_ID = 508
    DENEBAPI_GETOTNOHPSINKTTIACCEPTED_ID = 509
    DENEBAPI_GETOTNOHPSINKPTACCEPTED_ID = 510
    DENEBAPI_SETOTNOHPSINKMSIEXPECTED_ID = 511
    DENEBAPI_GETOTNOHPSINKMSIEXPECTED_ID = 512
    DENEBAPI_GETOTNOHPSINKMSIACCEPTED_ID = 513
    DENEBAPI_SETOTNOHPSINKFTFLACCEPTEDMASK_ID = 514
    DENEBAPI_GETOTNOHPSINKFTFLACCEPTEDMASK_ID = 515
    DENEBAPI_GETOTNOHPSINKFTFLACCEPTED_ID = 516
    DENEBAPI_SETOPTICALMONITORTRIGGERSOURCE_ID = 522
    DENEBAPI_GETOPTICALMONITORTRIGGERSOURCE_ID = 523
    DENEBAPI_SETHOSTUNFRAMEDSTANDARDPATTERNGENERATORCONFIG_ID = 525
    DENEBAPI_GETHOSTUNFRAMEDSTANDARDPATTERNGENERATORCONFIG_ID = 526
    DENEBAPI_SETLINEEGRESSHIGHSRFREQUENCYMASKBOOST_ID = 527
    DENEBAPI_GETHOSTHISTOGRAM_ID = 528
    DENEBAPI_CONTROLAVS_ID = 529
    DENEBAPI_GETCORECFECTESTPATTERNCHECKERSTATISTICS_ID = 530
    DENEBAPI_GETFLEXOOHPSINKFIELDSACCEPTED_ID = 531
    DENEBAPI_GETFLEXEOHPSINKFIELDSACCEPTED_ID = 532
    DENEBAPI_SETPCSFRAMEPAUSECONFIG_ID = 533
    DENEBAPI_GETPCSFRAMEPAUSECONFIG_ID = 534
    DENEBAPI_SETMONITORCLOCKS_ID = 535
    DENEBAPI_GETMONITORCLOCKS_ID = 536
    DENEBAPI_SETOPTICALMONITORSCONFIG_ID = 537
    DENEBAPI_GETINGRESSSMINFORMATION_ID = 545
    DENEBAPI_GETHOSTRXSTATUS_ID = 546
    DENEBAPI_SETLINEEGRESSLANEANALOGATTENUATION_ID = 548
    DENEBAPI_SETPCSMLGALIGNMENTMARKERS_ID = 549
    DENEBAPI_GETPCSMLGALIGNMENTMARKERS_ID = 550
    DENEBAPI_SETOTNOHPSOURCEBDI_ID = 551
    DENEBAPI_SETOTNOHPSOURCEBEIBIAE_ID = 552
    DENEBAPI_SETOTNOHPSOURCESTAT_ID = 553
    DENEBAPI_GETOTNOHPSOURCEBDI_ID = 554
    DENEBAPI_GETOTNOHPSOURCEBEIBIAE_ID = 555
    DENEBAPI_GETOTNOHPSOURCESTAT_ID = 556
    DENEBAPI_SETETHERNETIDLETRAFFICTIMER_ID = 558
    DENEBAPI_GETETHERNETIDLETRAFFICTIMER_ID = 559
    DENEBAPI_GETHOSTPULSERESPONSE_ID = 560
    DENEBAPI_SETOTNMAINTENANCESIGNALCONFIG_ID = 566
    DENEBAPI_GETOTNMAINTENANCESIGNALCONFIG_ID = 567
    DENEBAPI_RELEASEDIAGNOSTICUNIT_ID = 568
    DENEBAPI_SETFLEXOMAINTENANCESIGNALCONFIG_ID = 569
    DENEBAPI_GETFLEXOMAINTENANCESIGNALCONFIG_ID = 570
    DENEBAPI_SETETHERNETBJAMCONFIG_ID = 573
    DENEBAPI_GETETHERNETBJAMCONFIG_ID = 574
    DENEBAPI_GETLINEOPTICALCHANNELMONITORSOCCURRENCEINFO_ID = 576
    DENEBAPI_GETFAWERRORSTATISTICSOCCURRENCEINFO_ID = 577
    DENEBAPI_GETPCSERRORSTATISTICSOCCURRENCEINFO_ID = 578
    DENEBAPI_GETERRORCORRECTIONSTATISTICSOCCURRENCEINFO_ID = 579
    DENEBAPI_SETOHAFW_ID = 598
    DENEBAPI_GETOHAFW_ID = 599
    DENEBAPI_LOADOHAFW_ID = 601
    DENEBAPI_GETINGRESSSMSTATE_ID = 609
    DENEBAPI_GETOHAFWVERSION_ID = 610
    DENEBAPI_GETDUADCCAPTURE_ID = 626
    DENEBAPI_GETDUFCRCAPTURE_ID = 627
    DENEBAPI_RELINKHOSTEGRESS_ID = 246
    DENEBAPI_READLINEPOWERSUPPLY_ID = 249
    DENEBAPI_SETHOSTFASTRELOCKMODE_ID = 665
    DENEBAPI_GETHOSTFASTRELOCKMODE_ID = 670
    DENEBAPI_SETLINEOFECFRAMEDTESTPATTERNGENERATORCONFIG_ID = 617
    DENEBAPI_SETLINEOFECFRAMEDTESTPATTERNCHECKERCONFIG_ID = 624
    DENEBAPI_SETCOREOFECTESTPATTERNGENERATORCONFIG_ID = 673
    DENEBAPI_SETCOREOFECTESTPATTERNCHECKERCONFIG_ID = 674
    DENEBAPI_GETCOREOFECTESTPATTERNGENERATORCONFIG_ID = 707
    DENEBAPI_GETCOREOFECTESTPATTERNCHECKERCONFIG_ID = 704
    DENEBAPI_GETCOREOFECTESTPATTERNCHECKERSTATISTICS_ID = 705
    DENEBAPI_GETLINEEGRESSLANEANALOGATTENUATION_ID = 682
    DENEBAPI_SETCANOPUSCFECCOMPATIBILITYMODE_ID = 613
    DENEBAPI_GETCANOPUSCFECCOMPATIBILITYMODE_ID = 615
    DENEBAPI_GETLINESYMBOLRATE_ID = 572
    DENEBAPI_SETALARMPINMODE_ID = 612
    DENEBAPI_SETOTUC128BITSALIGNMENTINTOFLEXO_ID = 646
    DENEBAPI_GETOTUC128BITSALIGNMENTINTOFLEXO_ID = 647
    DENEBAPI_GETDISRUPTIONTIME_ID = 575
    DENEBAPI_SETAUTOMATICHTXSQUELCH_ID = 671
    DENEBAPI_GETAUTOMATICHTXSQUELCH_ID = 672
    DENEBAPI_GETOSNRCALIBRATIONTABLE_ID = 675
    DENEBAPI_GETOTNOHPSINKCSFCONSEQUENTACTIONCONFIG_ID = 676
    DENEBAPI_SETOTNOHPSINKCSFCONSEQUENTACTIONCONFIG_ID = 677
    DENEBAPI_GETOTNOHPSINKMSICONSEQUENTACTIONCONFIG_ID = 679
    DENEBAPI_SETOTNOHPSINKMSICONSEQUENTACTIONCONFIG_ID = 678

class Host_Dual:
    HOST_DUAL_0 = 0
    HOST_DUAL_1 = 1
    HOST_DUAL_2 = 2
    HOST_DUAL_3 = 3

class Optical_Channel_Item:
    OPTICAL_CHANNEL_ITEM__Q = 0
    OPTICAL_CHANNEL_ITEM__CD = 1
    OPTICAL_CHANNEL_ITEM__DGD = 2
    OPTICAL_CHANNEL_ITEM__RESERVED_0 = 3
    OPTICAL_CHANNEL_ITEM__PDL = 4
    OPTICAL_CHANNEL_ITEM__OSNR = 5
    OPTICAL_CHANNEL_ITEM__ESNR = 6
    OPTICAL_CHANNEL_ITEM__CFO = 7
    OPTICAL_CHANNEL_ITEM__EVM = 8
    OPTICAL_CHANNEL_ITEM__SOP = 9
    OPTICAL_CHANNEL_ITEM__RESERVED_1 = 10
    OPTICAL_CHANNEL_ITEM__RX_ANGLE_H = 11
    OPTICAL_CHANNEL_ITEM__RX_ANGLE_V = 12
    OPTICAL_CHANNEL_ITEM__RX_GAIN_MISMATCH_H = 13
    OPTICAL_CHANNEL_ITEM__RX_GAIN_MISMATCH_V = 14
    OPTICAL_CHANNEL_ITEM__RX_SKEW_H = 15
    OPTICAL_CHANNEL_ITEM__RX_SKEW_V = 16
    OPTICAL_CHANNEL_ITEM__RX_DC_H = 17
    OPTICAL_CHANNEL_ITEM__RX_DC_V = 18
    OPTICAL_CHANNEL_ITEM__TX_ANGLE_H = 19
    OPTICAL_CHANNEL_ITEM__TX_ANGLE_V = 20
    OPTICAL_CHANNEL_ITEM__TX_GAIN_MISMATCH_H = 21
    OPTICAL_CHANNEL_ITEM__TX_GAIN_MISMATCH_V = 22
    OPTICAL_CHANNEL_ITEM__TX_SKEW_H = 23
    OPTICAL_CHANNEL_ITEM__TX_SKEW_V = 24

class Line_Egress_Frequency_Mask_Width:
    LINE_EGRESS_FREQUENCY_MASK_WIDTH__0_TAP = 0
    LINE_EGRESS_FREQUENCY_MASK_WIDTH__7_TAP = 1
    LINE_EGRESS_FREQUENCY_MASK_WIDTH__9_TAP = 2
    LINE_EGRESS_FREQUENCY_MASK_WIDTH__11_TAP = 3
    LINE_EGRESS_FREQUENCY_MASK_WIDTH__13_TAP = 4
    LINE_EGRESS_FREQUENCY_MASK_WIDTH__15_TAP = 5

class Config_Opm_Action:
    CONFIG_OPM_ACTION__LOAD_LUT = 0
    CONFIG_OPM_ACTION__CALIBRATION_ENABLE = 1
    CONFIG_OPM_ACTION__CALIBRATION_DISABLE = 2
    CONFIG_OPM_ACTION__TRIGGER = 3
    CONFIG_OPM_ACTION__SET_BETA = 4
    CONFIG_OPM_ACTION__SET_ORT_SWAP = 5
    CONFIG_OPM_ACTION__SET_SKEW_CTR = 6

class Control_Avs_Rate:
    RATE_0_0 = 0
    RATE_0_5 = 1
    RATE_1_0 = 2
    RATE_1_5 = 3
    RATE_2_0 = 4
    RATE_2_5 = 5
    RATE_3_0 = 6
    RATE_3_5 = 7
    RATE_4_0 = 8
    RATE_4_5 = 9
    RATE_5_0 = 10
    RATE_5_5 = 11
    RATE_6_0 = 12
    RATE_6_5 = 13
    RATE_7_0 = 14
    RATE_7_5 = 15
    RATE_8_0 = 16
    RATE_8_5 = 17
    RATE_9_0 = 18
    RATE_9_5 = 19
    RATE_10_0 = 20
    RATE_11_0 = 21
    RATE_11_5 = 22
    RATE_12_0 = 23
    RATE_12_5 = 24
    RATE_13_0 = 25
    RATE_13_5 = 26
    RATE_14_0 = 27
    RATE_14_5 = 28
    RATE_15_0 = 29
    RATE_15_5 = 30

class Control_Avs_Status:
    AVS_READY = 0
    AVS_RUNNING = 1
    AVS_FINISHED = 2
    AVS_STARTED = 3

class Control_Avs_Flag:
    AVS_GOOD = 0
    AVS_LOW = 1
    AVS_HIGH = 2

class Temperature_Sensor_Id:
    TEMPERATURE_SENSOR_ID_RESERVED_0 = 0
    TEMPERATURE_SENSOR_ID_RESERVED_1 = 1
    HRX_2 = 2
    TEMPERATURE_SENSOR_ID_RESERVED_2 = 3
    TEMPERATURE_SENSOR_ID_RESERVED_3 = 4
    TEMPERATURE_SENSOR_ID_RESERVED_4 = 5
    TEMPERATURE_SENSOR_ID_RESERVED_5 = 6
    TEMPERATURE_SENSOR_ID_RESERVED_6 = 7
    LRX = 8
    TEMPERATURE_SENSOR_ID_RESERVED_7 = 9
    LTX_V = 10
    HTX_TOP_0 = 11
    TEMPERATURE_SENSOR_ID_RESERVED_8 = 12
    TEMPERATURE_SENSOR_ID_RESERVED_9 = 13

class Ism_State:
    ISM_STATE__STATE_1 = 0
    ISM_STATE__STATE_2 = 1
    ISM_STATE__STATE_3 = 2
    ISM_STATE__STATE_4 = 3
    ISM_STATE__STATE_5 = 4
    ISM_STATE__STATE_6 = 5
    ISM_STATE__STATE_7 = 6
    ISM_STATE__STATE_8 = 7
    ISM_STATE__STATE_9 = 8
    ISM_STATE__STATE_10 = 9
    ISM_STATE__STATE_11 = 10
    ISM_STATE__STATE_12 = 11
    ISM_STATE__STATE_13 = 12
    ISM_STATE__STATE_14 = 13
    ISM_STATE__STATE_15 = 14
    ISM_STATE__STATE_16 = 15
    ISM_STATE__STATE_17 = 16
    ISM_STATE__STATE_18 = 17
    ISM_STATE__STATE_19 = 18
    ISM_STATE__STATE_20 = 254
    ISM_STATE__NORMAL_OP = 255

class Line_Egress_Analog_Attenuation:
    LINE_EGRESS_ANALOG_ATTENUATION__NONE = 0
    LINE_EGRESS_ANALOG_ATTENUATION__LOWER_MID = 1
    LINE_EGRESS_ANALOG_ATTENUATION__MID = 2
    LINE_EGRESS_ANALOG_ATTENUATION__UPPER_MID = 3
    LINE_EGRESS_ANALOG_ATTENUATION__HIGH = 4

class Mlg_Lane_Markers:
    MLG_LANE_MARKERS__DISABLED = 0
    MLG_LANE_MARKERS__4X10G_1X40G_2X10G = 1
    MLG_LANE_MARKERS__4X10G_4X10G_2X10G = 2
    MLG_LANE_MARKERS__1X40G_4X10G_2X10G = 3
    MLG_LANE_MARKERS__1X40G_1X40G_2X10G = 4

class Flexo_Group_Select:
    FLEXO_GROUP_SELECT__NO_GROUP = 0
    FLEXO_GROUP_SELECT__ONE = 1
    FLEXO_GROUP_SELECT__TWO = 2

class Set_Oha_Fw_Action:
    SET_OHA_FW_ACTION_START = 0
    SET_OHA_FW_ACTION_END = 1

class Los_Pin_Mode:
    LOS_PIN_MODE__LATCH = 0
    LOS_PIN_MODE__LIVE = 1

class Chip_ID:
    INDD400_S01_13 = 0
    INDD400S_S01_13 = 1
    INDD200_S01_13 = 2
    INDD400_S01_13_ZR = 3
    INDD200S_S01_13 = 4
    CHIP_ID_RESERVED1 = 5
    CHIP_ID_RESERVED2 = 6

class Fast_Relock_Mode:
    FAST_RELOCK_DISABLED = 0
    FAST_RELOCK_ENABLED = 1
    FAST_RELOCK_AUTOMATIC = 2

class Automatic_Htx_Squelch:
    AUTOMATIC_HTX_SQUELCH__DISABLE = 0
    AUTOMATIC_HTX_SQUELCH__ENABLE_WITH_RX_LOS = 1
    AUTOMATIC_HTX_SQUELCH__ENABLE_WITH_LOF = 2
