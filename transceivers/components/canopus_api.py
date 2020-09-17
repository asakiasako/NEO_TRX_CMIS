####################################################
#          Copyright (c) 2020 Inphi Corp.          #
####################################################
####################################################
#                Inphi Confidential                #
####################################################


from .canopus_enum import *

class RspHeader:
   def __init__(self): #Elements will be added later
       pass


class ArgHeader:
   def __init__(self): #Elements will be added later
       pass


class CanopusApi:
    def __init__(self, com):
        self.com = com
        self.apis_call_info_list = []
        self.add_api_exec_cb = lambda:None
        self.api_hash = [0x8f,0xa7,0x1d,0x4b,0xae,0x3d,0x9e,0xeb,0xf1,0x60,0x48,0x8c]    # 8fa71d4bae3d9eebf160488c1ce9d90257a47f30
    def check_response(self, apiResponse, rsp):#add by hao
        pass
    def enable_fw_support(self, support):
        self.check_response = support.check_response

    def check_api_compatibility(self):
        fw_api_hash = self.ReadFirmwareInformation()['api_hash']
        # lists are equal if elements at the same index are equal
        if fw_api_hash == self.api_hash:
            print('API and firmware versions are compatible.')
            return True
        else:
            print('API and firmware versions are NOT COMPATIBLE.')
            return False

    
    def Echo (self, data):
        #Default header
        header=ArgHeader()
        header.Length = 512
        header.Command = 0x1
        header.Tag = 0
        header.MaxResponse = 508
        header.Reserved = 0

        #Command stream
        command_array=[0]*512
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = data[0]>>0
        command_array[9] = data[1]>>0
        command_array[10] = data[2]>>0
        command_array[11] = data[3]>>0
        command_array[12] = data[4]>>0
        command_array[13] = data[5]>>0
        command_array[14] = data[6]>>0
        command_array[15] = data[7]>>0
        command_array[16] = data[8]>>0
        command_array[17] = data[9]>>0
        command_array[18] = data[10]>>0
        command_array[19] = data[11]>>0
        command_array[20] = data[12]>>0
        command_array[21] = data[13]>>0
        command_array[22] = data[14]>>0
        command_array[23] = data[15]>>0
        command_array[24] = data[16]>>0
        command_array[25] = data[17]>>0
        command_array[26] = data[18]>>0
        command_array[27] = data[19]>>0
        command_array[28] = data[20]>>0
        command_array[29] = data[21]>>0
        command_array[30] = data[22]>>0
        command_array[31] = data[23]>>0
        command_array[32] = data[24]>>0
        command_array[33] = data[25]>>0
        command_array[34] = data[26]>>0
        command_array[35] = data[27]>>0
        command_array[36] = data[28]>>0
        command_array[37] = data[29]>>0
        command_array[38] = data[30]>>0
        command_array[39] = data[31]>>0
        command_array[40] = data[32]>>0
        command_array[41] = data[33]>>0
        command_array[42] = data[34]>>0
        command_array[43] = data[35]>>0
        command_array[44] = data[36]>>0
        command_array[45] = data[37]>>0
        command_array[46] = data[38]>>0
        command_array[47] = data[39]>>0
        command_array[48] = data[40]>>0
        command_array[49] = data[41]>>0
        command_array[50] = data[42]>>0
        command_array[51] = data[43]>>0
        command_array[52] = data[44]>>0
        command_array[53] = data[45]>>0
        command_array[54] = data[46]>>0
        command_array[55] = data[47]>>0
        command_array[56] = data[48]>>0
        command_array[57] = data[49]>>0
        command_array[58] = data[50]>>0
        command_array[59] = data[51]>>0
        command_array[60] = data[52]>>0
        command_array[61] = data[53]>>0
        command_array[62] = data[54]>>0
        command_array[63] = data[55]>>0
        command_array[64] = data[56]>>0
        command_array[65] = data[57]>>0
        command_array[66] = data[58]>>0
        command_array[67] = data[59]>>0
        command_array[68] = data[60]>>0
        command_array[69] = data[61]>>0
        command_array[70] = data[62]>>0
        command_array[71] = data[63]>>0
        command_array[72] = data[64]>>0
        command_array[73] = data[65]>>0
        command_array[74] = data[66]>>0
        command_array[75] = data[67]>>0
        command_array[76] = data[68]>>0
        command_array[77] = data[69]>>0
        command_array[78] = data[70]>>0
        command_array[79] = data[71]>>0
        command_array[80] = data[72]>>0
        command_array[81] = data[73]>>0
        command_array[82] = data[74]>>0
        command_array[83] = data[75]>>0
        command_array[84] = data[76]>>0
        command_array[85] = data[77]>>0
        command_array[86] = data[78]>>0
        command_array[87] = data[79]>>0
        command_array[88] = data[80]>>0
        command_array[89] = data[81]>>0
        command_array[90] = data[82]>>0
        command_array[91] = data[83]>>0
        command_array[92] = data[84]>>0
        command_array[93] = data[85]>>0
        command_array[94] = data[86]>>0
        command_array[95] = data[87]>>0
        command_array[96] = data[88]>>0
        command_array[97] = data[89]>>0
        command_array[98] = data[90]>>0
        command_array[99] = data[91]>>0
        command_array[100] = data[92]>>0
        command_array[101] = data[93]>>0
        command_array[102] = data[94]>>0
        command_array[103] = data[95]>>0
        command_array[104] = data[96]>>0
        command_array[105] = data[97]>>0
        command_array[106] = data[98]>>0
        command_array[107] = data[99]>>0
        command_array[108] = data[100]>>0
        command_array[109] = data[101]>>0
        command_array[110] = data[102]>>0
        command_array[111] = data[103]>>0
        command_array[112] = data[104]>>0
        command_array[113] = data[105]>>0
        command_array[114] = data[106]>>0
        command_array[115] = data[107]>>0
        command_array[116] = data[108]>>0
        command_array[117] = data[109]>>0
        command_array[118] = data[110]>>0
        command_array[119] = data[111]>>0
        command_array[120] = data[112]>>0
        command_array[121] = data[113]>>0
        command_array[122] = data[114]>>0
        command_array[123] = data[115]>>0
        command_array[124] = data[116]>>0
        command_array[125] = data[117]>>0
        command_array[126] = data[118]>>0
        command_array[127] = data[119]>>0
        command_array[128] = data[120]>>0
        command_array[129] = data[121]>>0
        command_array[130] = data[122]>>0
        command_array[131] = data[123]>>0
        command_array[132] = data[124]>>0
        command_array[133] = data[125]>>0
        command_array[134] = data[126]>>0
        command_array[135] = data[127]>>0
        command_array[136] = data[128]>>0
        command_array[137] = data[129]>>0
        command_array[138] = data[130]>>0
        command_array[139] = data[131]>>0
        command_array[140] = data[132]>>0
        command_array[141] = data[133]>>0
        command_array[142] = data[134]>>0
        command_array[143] = data[135]>>0
        command_array[144] = data[136]>>0
        command_array[145] = data[137]>>0
        command_array[146] = data[138]>>0
        command_array[147] = data[139]>>0
        command_array[148] = data[140]>>0
        command_array[149] = data[141]>>0
        command_array[150] = data[142]>>0
        command_array[151] = data[143]>>0
        command_array[152] = data[144]>>0
        command_array[153] = data[145]>>0
        command_array[154] = data[146]>>0
        command_array[155] = data[147]>>0
        command_array[156] = data[148]>>0
        command_array[157] = data[149]>>0
        command_array[158] = data[150]>>0
        command_array[159] = data[151]>>0
        command_array[160] = data[152]>>0
        command_array[161] = data[153]>>0
        command_array[162] = data[154]>>0
        command_array[163] = data[155]>>0
        command_array[164] = data[156]>>0
        command_array[165] = data[157]>>0
        command_array[166] = data[158]>>0
        command_array[167] = data[159]>>0
        command_array[168] = data[160]>>0
        command_array[169] = data[161]>>0
        command_array[170] = data[162]>>0
        command_array[171] = data[163]>>0
        command_array[172] = data[164]>>0
        command_array[173] = data[165]>>0
        command_array[174] = data[166]>>0
        command_array[175] = data[167]>>0
        command_array[176] = data[168]>>0
        command_array[177] = data[169]>>0
        command_array[178] = data[170]>>0
        command_array[179] = data[171]>>0
        command_array[180] = data[172]>>0
        command_array[181] = data[173]>>0
        command_array[182] = data[174]>>0
        command_array[183] = data[175]>>0
        command_array[184] = data[176]>>0
        command_array[185] = data[177]>>0
        command_array[186] = data[178]>>0
        command_array[187] = data[179]>>0
        command_array[188] = data[180]>>0
        command_array[189] = data[181]>>0
        command_array[190] = data[182]>>0
        command_array[191] = data[183]>>0
        command_array[192] = data[184]>>0
        command_array[193] = data[185]>>0
        command_array[194] = data[186]>>0
        command_array[195] = data[187]>>0
        command_array[196] = data[188]>>0
        command_array[197] = data[189]>>0
        command_array[198] = data[190]>>0
        command_array[199] = data[191]>>0
        command_array[200] = data[192]>>0
        command_array[201] = data[193]>>0
        command_array[202] = data[194]>>0
        command_array[203] = data[195]>>0
        command_array[204] = data[196]>>0
        command_array[205] = data[197]>>0
        command_array[206] = data[198]>>0
        command_array[207] = data[199]>>0
        command_array[208] = data[200]>>0
        command_array[209] = data[201]>>0
        command_array[210] = data[202]>>0
        command_array[211] = data[203]>>0
        command_array[212] = data[204]>>0
        command_array[213] = data[205]>>0
        command_array[214] = data[206]>>0
        command_array[215] = data[207]>>0
        command_array[216] = data[208]>>0
        command_array[217] = data[209]>>0
        command_array[218] = data[210]>>0
        command_array[219] = data[211]>>0
        command_array[220] = data[212]>>0
        command_array[221] = data[213]>>0
        command_array[222] = data[214]>>0
        command_array[223] = data[215]>>0
        command_array[224] = data[216]>>0
        command_array[225] = data[217]>>0
        command_array[226] = data[218]>>0
        command_array[227] = data[219]>>0
        command_array[228] = data[220]>>0
        command_array[229] = data[221]>>0
        command_array[230] = data[222]>>0
        command_array[231] = data[223]>>0
        command_array[232] = data[224]>>0
        command_array[233] = data[225]>>0
        command_array[234] = data[226]>>0
        command_array[235] = data[227]>>0
        command_array[236] = data[228]>>0
        command_array[237] = data[229]>>0
        command_array[238] = data[230]>>0
        command_array[239] = data[231]>>0
        command_array[240] = data[232]>>0
        command_array[241] = data[233]>>0
        command_array[242] = data[234]>>0
        command_array[243] = data[235]>>0
        command_array[244] = data[236]>>0
        command_array[245] = data[237]>>0
        command_array[246] = data[238]>>0
        command_array[247] = data[239]>>0
        command_array[248] = data[240]>>0
        command_array[249] = data[241]>>0
        command_array[250] = data[242]>>0
        command_array[251] = data[243]>>0
        command_array[252] = data[244]>>0
        command_array[253] = data[245]>>0
        command_array[254] = data[246]>>0
        command_array[255] = data[247]>>0
        command_array[256] = data[248]>>0
        command_array[257] = data[249]>>0
        command_array[258] = data[250]>>0
        command_array[259] = data[251]>>0
        command_array[260] = data[252]>>0
        command_array[261] = data[253]>>0
        command_array[262] = data[254]>>0
        command_array[263] = data[255]>>0
        command_array[264] = data[256]>>0
        command_array[265] = data[257]>>0
        command_array[266] = data[258]>>0
        command_array[267] = data[259]>>0
        command_array[268] = data[260]>>0
        command_array[269] = data[261]>>0
        command_array[270] = data[262]>>0
        command_array[271] = data[263]>>0
        command_array[272] = data[264]>>0
        command_array[273] = data[265]>>0
        command_array[274] = data[266]>>0
        command_array[275] = data[267]>>0
        command_array[276] = data[268]>>0
        command_array[277] = data[269]>>0
        command_array[278] = data[270]>>0
        command_array[279] = data[271]>>0
        command_array[280] = data[272]>>0
        command_array[281] = data[273]>>0
        command_array[282] = data[274]>>0
        command_array[283] = data[275]>>0
        command_array[284] = data[276]>>0
        command_array[285] = data[277]>>0
        command_array[286] = data[278]>>0
        command_array[287] = data[279]>>0
        command_array[288] = data[280]>>0
        command_array[289] = data[281]>>0
        command_array[290] = data[282]>>0
        command_array[291] = data[283]>>0
        command_array[292] = data[284]>>0
        command_array[293] = data[285]>>0
        command_array[294] = data[286]>>0
        command_array[295] = data[287]>>0
        command_array[296] = data[288]>>0
        command_array[297] = data[289]>>0
        command_array[298] = data[290]>>0
        command_array[299] = data[291]>>0
        command_array[300] = data[292]>>0
        command_array[301] = data[293]>>0
        command_array[302] = data[294]>>0
        command_array[303] = data[295]>>0
        command_array[304] = data[296]>>0
        command_array[305] = data[297]>>0
        command_array[306] = data[298]>>0
        command_array[307] = data[299]>>0
        command_array[308] = data[300]>>0
        command_array[309] = data[301]>>0
        command_array[310] = data[302]>>0
        command_array[311] = data[303]>>0
        command_array[312] = data[304]>>0
        command_array[313] = data[305]>>0
        command_array[314] = data[306]>>0
        command_array[315] = data[307]>>0
        command_array[316] = data[308]>>0
        command_array[317] = data[309]>>0
        command_array[318] = data[310]>>0
        command_array[319] = data[311]>>0
        command_array[320] = data[312]>>0
        command_array[321] = data[313]>>0
        command_array[322] = data[314]>>0
        command_array[323] = data[315]>>0
        command_array[324] = data[316]>>0
        command_array[325] = data[317]>>0
        command_array[326] = data[318]>>0
        command_array[327] = data[319]>>0
        command_array[328] = data[320]>>0
        command_array[329] = data[321]>>0
        command_array[330] = data[322]>>0
        command_array[331] = data[323]>>0
        command_array[332] = data[324]>>0
        command_array[333] = data[325]>>0
        command_array[334] = data[326]>>0
        command_array[335] = data[327]>>0
        command_array[336] = data[328]>>0
        command_array[337] = data[329]>>0
        command_array[338] = data[330]>>0
        command_array[339] = data[331]>>0
        command_array[340] = data[332]>>0
        command_array[341] = data[333]>>0
        command_array[342] = data[334]>>0
        command_array[343] = data[335]>>0
        command_array[344] = data[336]>>0
        command_array[345] = data[337]>>0
        command_array[346] = data[338]>>0
        command_array[347] = data[339]>>0
        command_array[348] = data[340]>>0
        command_array[349] = data[341]>>0
        command_array[350] = data[342]>>0
        command_array[351] = data[343]>>0
        command_array[352] = data[344]>>0
        command_array[353] = data[345]>>0
        command_array[354] = data[346]>>0
        command_array[355] = data[347]>>0
        command_array[356] = data[348]>>0
        command_array[357] = data[349]>>0
        command_array[358] = data[350]>>0
        command_array[359] = data[351]>>0
        command_array[360] = data[352]>>0
        command_array[361] = data[353]>>0
        command_array[362] = data[354]>>0
        command_array[363] = data[355]>>0
        command_array[364] = data[356]>>0
        command_array[365] = data[357]>>0
        command_array[366] = data[358]>>0
        command_array[367] = data[359]>>0
        command_array[368] = data[360]>>0
        command_array[369] = data[361]>>0
        command_array[370] = data[362]>>0
        command_array[371] = data[363]>>0
        command_array[372] = data[364]>>0
        command_array[373] = data[365]>>0
        command_array[374] = data[366]>>0
        command_array[375] = data[367]>>0
        command_array[376] = data[368]>>0
        command_array[377] = data[369]>>0
        command_array[378] = data[370]>>0
        command_array[379] = data[371]>>0
        command_array[380] = data[372]>>0
        command_array[381] = data[373]>>0
        command_array[382] = data[374]>>0
        command_array[383] = data[375]>>0
        command_array[384] = data[376]>>0
        command_array[385] = data[377]>>0
        command_array[386] = data[378]>>0
        command_array[387] = data[379]>>0
        command_array[388] = data[380]>>0
        command_array[389] = data[381]>>0
        command_array[390] = data[382]>>0
        command_array[391] = data[383]>>0
        command_array[392] = data[384]>>0
        command_array[393] = data[385]>>0
        command_array[394] = data[386]>>0
        command_array[395] = data[387]>>0
        command_array[396] = data[388]>>0
        command_array[397] = data[389]>>0
        command_array[398] = data[390]>>0
        command_array[399] = data[391]>>0
        command_array[400] = data[392]>>0
        command_array[401] = data[393]>>0
        command_array[402] = data[394]>>0
        command_array[403] = data[395]>>0
        command_array[404] = data[396]>>0
        command_array[405] = data[397]>>0
        command_array[406] = data[398]>>0
        command_array[407] = data[399]>>0
        command_array[408] = data[400]>>0
        command_array[409] = data[401]>>0
        command_array[410] = data[402]>>0
        command_array[411] = data[403]>>0
        command_array[412] = data[404]>>0
        command_array[413] = data[405]>>0
        command_array[414] = data[406]>>0
        command_array[415] = data[407]>>0
        command_array[416] = data[408]>>0
        command_array[417] = data[409]>>0
        command_array[418] = data[410]>>0
        command_array[419] = data[411]>>0
        command_array[420] = data[412]>>0
        command_array[421] = data[413]>>0
        command_array[422] = data[414]>>0
        command_array[423] = data[415]>>0
        command_array[424] = data[416]>>0
        command_array[425] = data[417]>>0
        command_array[426] = data[418]>>0
        command_array[427] = data[419]>>0
        command_array[428] = data[420]>>0
        command_array[429] = data[421]>>0
        command_array[430] = data[422]>>0
        command_array[431] = data[423]>>0
        command_array[432] = data[424]>>0
        command_array[433] = data[425]>>0
        command_array[434] = data[426]>>0
        command_array[435] = data[427]>>0
        command_array[436] = data[428]>>0
        command_array[437] = data[429]>>0
        command_array[438] = data[430]>>0
        command_array[439] = data[431]>>0
        command_array[440] = data[432]>>0
        command_array[441] = data[433]>>0
        command_array[442] = data[434]>>0
        command_array[443] = data[435]>>0
        command_array[444] = data[436]>>0
        command_array[445] = data[437]>>0
        command_array[446] = data[438]>>0
        command_array[447] = data[439]>>0
        command_array[448] = data[440]>>0
        command_array[449] = data[441]>>0
        command_array[450] = data[442]>>0
        command_array[451] = data[443]>>0
        command_array[452] = data[444]>>0
        command_array[453] = data[445]>>0
        command_array[454] = data[446]>>0
        command_array[455] = data[447]>>0
        command_array[456] = data[448]>>0
        command_array[457] = data[449]>>0
        command_array[458] = data[450]>>0
        command_array[459] = data[451]>>0
        command_array[460] = data[452]>>0
        command_array[461] = data[453]>>0
        command_array[462] = data[454]>>0
        command_array[463] = data[455]>>0
        command_array[464] = data[456]>>0
        command_array[465] = data[457]>>0
        command_array[466] = data[458]>>0
        command_array[467] = data[459]>>0
        command_array[468] = data[460]>>0
        command_array[469] = data[461]>>0
        command_array[470] = data[462]>>0
        command_array[471] = data[463]>>0
        command_array[472] = data[464]>>0
        command_array[473] = data[465]>>0
        command_array[474] = data[466]>>0
        command_array[475] = data[467]>>0
        command_array[476] = data[468]>>0
        command_array[477] = data[469]>>0
        command_array[478] = data[470]>>0
        command_array[479] = data[471]>>0
        command_array[480] = data[472]>>0
        command_array[481] = data[473]>>0
        command_array[482] = data[474]>>0
        command_array[483] = data[475]>>0
        command_array[484] = data[476]>>0
        command_array[485] = data[477]>>0
        command_array[486] = data[478]>>0
        command_array[487] = data[479]>>0
        command_array[488] = data[480]>>0
        command_array[489] = data[481]>>0
        command_array[490] = data[482]>>0
        command_array[491] = data[483]>>0
        command_array[492] = data[484]>>0
        command_array[493] = data[485]>>0
        command_array[494] = data[486]>>0
        command_array[495] = data[487]>>0
        command_array[496] = data[488]>>0
        command_array[497] = data[489]>>0
        command_array[498] = data[490]>>0
        command_array[499] = data[491]>>0
        command_array[500] = data[492]>>0
        command_array[501] = data[493]>>0
        command_array[502] = data[494]>>0
        command_array[503] = data[495]>>0
        command_array[504] = data[496]>>0
        command_array[505] = data[497]>>0
        command_array[506] = data[498]>>0
        command_array[507] = data[499]>>0
        command_array[508] = data[500]>>0
        command_array[509] = data[501]>>0
        command_array[510] = data[502]>>0
        command_array[511] = data[503]>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'data' : [                          (response[4] & 0xFF),
                          (response[5] & 0xFF),
                          (response[6] & 0xFF),
                          (response[7] & 0xFF),
                          (response[8] & 0xFF),
                          (response[9] & 0xFF),
                          (response[10] & 0xFF),
                          (response[11] & 0xFF),
                          (response[12] & 0xFF),
                          (response[13] & 0xFF),
                          (response[14] & 0xFF),
                          (response[15] & 0xFF),
                          (response[16] & 0xFF),
                          (response[17] & 0xFF),
                          (response[18] & 0xFF),
                          (response[19] & 0xFF),
                          (response[20] & 0xFF),
                          (response[21] & 0xFF),
                          (response[22] & 0xFF),
                          (response[23] & 0xFF),
                          (response[24] & 0xFF),
                          (response[25] & 0xFF),
                          (response[26] & 0xFF),
                          (response[27] & 0xFF),
                          (response[28] & 0xFF),
                          (response[29] & 0xFF),
                          (response[30] & 0xFF),
                          (response[31] & 0xFF),
                          (response[32] & 0xFF),
                          (response[33] & 0xFF),
                          (response[34] & 0xFF),
                          (response[35] & 0xFF),
                          (response[36] & 0xFF),
                          (response[37] & 0xFF),
                          (response[38] & 0xFF),
                          (response[39] & 0xFF),
                          (response[40] & 0xFF),
                          (response[41] & 0xFF),
                          (response[42] & 0xFF),
                          (response[43] & 0xFF),
                          (response[44] & 0xFF),
                          (response[45] & 0xFF),
                          (response[46] & 0xFF),
                          (response[47] & 0xFF),
                          (response[48] & 0xFF),
                          (response[49] & 0xFF),
                          (response[50] & 0xFF),
                          (response[51] & 0xFF),
                          (response[52] & 0xFF),
                          (response[53] & 0xFF),
                          (response[54] & 0xFF),
                          (response[55] & 0xFF),
                          (response[56] & 0xFF),
                          (response[57] & 0xFF),
                          (response[58] & 0xFF),
                          (response[59] & 0xFF),
                          (response[60] & 0xFF),
                          (response[61] & 0xFF),
                          (response[62] & 0xFF),
                          (response[63] & 0xFF),
                          (response[64] & 0xFF),
                          (response[65] & 0xFF),
                          (response[66] & 0xFF),
                          (response[67] & 0xFF),
                          (response[68] & 0xFF),
                          (response[69] & 0xFF),
                          (response[70] & 0xFF),
                          (response[71] & 0xFF),
                          (response[72] & 0xFF),
                          (response[73] & 0xFF),
                          (response[74] & 0xFF),
                          (response[75] & 0xFF),
                          (response[76] & 0xFF),
                          (response[77] & 0xFF),
                          (response[78] & 0xFF),
                          (response[79] & 0xFF),
                          (response[80] & 0xFF),
                          (response[81] & 0xFF),
                          (response[82] & 0xFF),
                          (response[83] & 0xFF),
                          (response[84] & 0xFF),
                          (response[85] & 0xFF),
                          (response[86] & 0xFF),
                          (response[87] & 0xFF),
                          (response[88] & 0xFF),
                          (response[89] & 0xFF),
                          (response[90] & 0xFF),
                          (response[91] & 0xFF),
                          (response[92] & 0xFF),
                          (response[93] & 0xFF),
                          (response[94] & 0xFF),
                          (response[95] & 0xFF),
                          (response[96] & 0xFF),
                          (response[97] & 0xFF),
                          (response[98] & 0xFF),
                          (response[99] & 0xFF),
                          (response[100] & 0xFF),
                          (response[101] & 0xFF),
                          (response[102] & 0xFF),
                          (response[103] & 0xFF),
                          (response[104] & 0xFF),
                          (response[105] & 0xFF),
                          (response[106] & 0xFF),
                          (response[107] & 0xFF),
                          (response[108] & 0xFF),
                          (response[109] & 0xFF),
                          (response[110] & 0xFF),
                          (response[111] & 0xFF),
                          (response[112] & 0xFF),
                          (response[113] & 0xFF),
                          (response[114] & 0xFF),
                          (response[115] & 0xFF),
                          (response[116] & 0xFF),
                          (response[117] & 0xFF),
                          (response[118] & 0xFF),
                          (response[119] & 0xFF),
                          (response[120] & 0xFF),
                          (response[121] & 0xFF),
                          (response[122] & 0xFF),
                          (response[123] & 0xFF),
                          (response[124] & 0xFF),
                          (response[125] & 0xFF),
                          (response[126] & 0xFF),
                          (response[127] & 0xFF),
                          (response[128] & 0xFF),
                          (response[129] & 0xFF),
                          (response[130] & 0xFF),
                          (response[131] & 0xFF),
                          (response[132] & 0xFF),
                          (response[133] & 0xFF),
                          (response[134] & 0xFF),
                          (response[135] & 0xFF),
                          (response[136] & 0xFF),
                          (response[137] & 0xFF),
                          (response[138] & 0xFF),
                          (response[139] & 0xFF),
                          (response[140] & 0xFF),
                          (response[141] & 0xFF),
                          (response[142] & 0xFF),
                          (response[143] & 0xFF),
                          (response[144] & 0xFF),
                          (response[145] & 0xFF),
                          (response[146] & 0xFF),
                          (response[147] & 0xFF),
                          (response[148] & 0xFF),
                          (response[149] & 0xFF),
                          (response[150] & 0xFF),
                          (response[151] & 0xFF),
                          (response[152] & 0xFF),
                          (response[153] & 0xFF),
                          (response[154] & 0xFF),
                          (response[155] & 0xFF),
                          (response[156] & 0xFF),
                          (response[157] & 0xFF),
                          (response[158] & 0xFF),
                          (response[159] & 0xFF),
                          (response[160] & 0xFF),
                          (response[161] & 0xFF),
                          (response[162] & 0xFF),
                          (response[163] & 0xFF),
                          (response[164] & 0xFF),
                          (response[165] & 0xFF),
                          (response[166] & 0xFF),
                          (response[167] & 0xFF),
                          (response[168] & 0xFF),
                          (response[169] & 0xFF),
                          (response[170] & 0xFF),
                          (response[171] & 0xFF),
                          (response[172] & 0xFF),
                          (response[173] & 0xFF),
                          (response[174] & 0xFF),
                          (response[175] & 0xFF),
                          (response[176] & 0xFF),
                          (response[177] & 0xFF),
                          (response[178] & 0xFF),
                          (response[179] & 0xFF),
                          (response[180] & 0xFF),
                          (response[181] & 0xFF),
                          (response[182] & 0xFF),
                          (response[183] & 0xFF),
                          (response[184] & 0xFF),
                          (response[185] & 0xFF),
                          (response[186] & 0xFF),
                          (response[187] & 0xFF),
                          (response[188] & 0xFF),
                          (response[189] & 0xFF),
                          (response[190] & 0xFF),
                          (response[191] & 0xFF),
                          (response[192] & 0xFF),
                          (response[193] & 0xFF),
                          (response[194] & 0xFF),
                          (response[195] & 0xFF),
                          (response[196] & 0xFF),
                          (response[197] & 0xFF),
                          (response[198] & 0xFF),
                          (response[199] & 0xFF),
                          (response[200] & 0xFF),
                          (response[201] & 0xFF),
                          (response[202] & 0xFF),
                          (response[203] & 0xFF),
                          (response[204] & 0xFF),
                          (response[205] & 0xFF),
                          (response[206] & 0xFF),
                          (response[207] & 0xFF),
                          (response[208] & 0xFF),
                          (response[209] & 0xFF),
                          (response[210] & 0xFF),
                          (response[211] & 0xFF),
                          (response[212] & 0xFF),
                          (response[213] & 0xFF),
                          (response[214] & 0xFF),
                          (response[215] & 0xFF),
                          (response[216] & 0xFF),
                          (response[217] & 0xFF),
                          (response[218] & 0xFF),
                          (response[219] & 0xFF),
                          (response[220] & 0xFF),
                          (response[221] & 0xFF),
                          (response[222] & 0xFF),
                          (response[223] & 0xFF),
                          (response[224] & 0xFF),
                          (response[225] & 0xFF),
                          (response[226] & 0xFF),
                          (response[227] & 0xFF),
                          (response[228] & 0xFF),
                          (response[229] & 0xFF),
                          (response[230] & 0xFF),
                          (response[231] & 0xFF),
                          (response[232] & 0xFF),
                          (response[233] & 0xFF),
                          (response[234] & 0xFF),
                          (response[235] & 0xFF),
                          (response[236] & 0xFF),
                          (response[237] & 0xFF),
                          (response[238] & 0xFF),
                          (response[239] & 0xFF),
                          (response[240] & 0xFF),
                          (response[241] & 0xFF),
                          (response[242] & 0xFF),
                          (response[243] & 0xFF),
                          (response[244] & 0xFF),
                          (response[245] & 0xFF),
                          (response[246] & 0xFF),
                          (response[247] & 0xFF),
                          (response[248] & 0xFF),
                          (response[249] & 0xFF),
                          (response[250] & 0xFF),
                          (response[251] & 0xFF),
                          (response[252] & 0xFF),
                          (response[253] & 0xFF),
                          (response[254] & 0xFF),
                          (response[255] & 0xFF),
                          (response[256] & 0xFF),
                          (response[257] & 0xFF),
                          (response[258] & 0xFF),
                          (response[259] & 0xFF),
                          (response[260] & 0xFF),
                          (response[261] & 0xFF),
                          (response[262] & 0xFF),
                          (response[263] & 0xFF),
                          (response[264] & 0xFF),
                          (response[265] & 0xFF),
                          (response[266] & 0xFF),
                          (response[267] & 0xFF),
                          (response[268] & 0xFF),
                          (response[269] & 0xFF),
                          (response[270] & 0xFF),
                          (response[271] & 0xFF),
                          (response[272] & 0xFF),
                          (response[273] & 0xFF),
                          (response[274] & 0xFF),
                          (response[275] & 0xFF),
                          (response[276] & 0xFF),
                          (response[277] & 0xFF),
                          (response[278] & 0xFF),
                          (response[279] & 0xFF),
                          (response[280] & 0xFF),
                          (response[281] & 0xFF),
                          (response[282] & 0xFF),
                          (response[283] & 0xFF),
                          (response[284] & 0xFF),
                          (response[285] & 0xFF),
                          (response[286] & 0xFF),
                          (response[287] & 0xFF),
                          (response[288] & 0xFF),
                          (response[289] & 0xFF),
                          (response[290] & 0xFF),
                          (response[291] & 0xFF),
                          (response[292] & 0xFF),
                          (response[293] & 0xFF),
                          (response[294] & 0xFF),
                          (response[295] & 0xFF),
                          (response[296] & 0xFF),
                          (response[297] & 0xFF),
                          (response[298] & 0xFF),
                          (response[299] & 0xFF),
                          (response[300] & 0xFF),
                          (response[301] & 0xFF),
                          (response[302] & 0xFF),
                          (response[303] & 0xFF),
                          (response[304] & 0xFF),
                          (response[305] & 0xFF),
                          (response[306] & 0xFF),
                          (response[307] & 0xFF),
                          (response[308] & 0xFF),
                          (response[309] & 0xFF),
                          (response[310] & 0xFF),
                          (response[311] & 0xFF),
                          (response[312] & 0xFF),
                          (response[313] & 0xFF),
                          (response[314] & 0xFF),
                          (response[315] & 0xFF),
                          (response[316] & 0xFF),
                          (response[317] & 0xFF),
                          (response[318] & 0xFF),
                          (response[319] & 0xFF),
                          (response[320] & 0xFF),
                          (response[321] & 0xFF),
                          (response[322] & 0xFF),
                          (response[323] & 0xFF),
                          (response[324] & 0xFF),
                          (response[325] & 0xFF),
                          (response[326] & 0xFF),
                          (response[327] & 0xFF),
                          (response[328] & 0xFF),
                          (response[329] & 0xFF),
                          (response[330] & 0xFF),
                          (response[331] & 0xFF),
                          (response[332] & 0xFF),
                          (response[333] & 0xFF),
                          (response[334] & 0xFF),
                          (response[335] & 0xFF),
                          (response[336] & 0xFF),
                          (response[337] & 0xFF),
                          (response[338] & 0xFF),
                          (response[339] & 0xFF),
                          (response[340] & 0xFF),
                          (response[341] & 0xFF),
                          (response[342] & 0xFF),
                          (response[343] & 0xFF),
                          (response[344] & 0xFF),
                          (response[345] & 0xFF),
                          (response[346] & 0xFF),
                          (response[347] & 0xFF),
                          (response[348] & 0xFF),
                          (response[349] & 0xFF),
                          (response[350] & 0xFF),
                          (response[351] & 0xFF),
                          (response[352] & 0xFF),
                          (response[353] & 0xFF),
                          (response[354] & 0xFF),
                          (response[355] & 0xFF),
                          (response[356] & 0xFF),
                          (response[357] & 0xFF),
                          (response[358] & 0xFF),
                          (response[359] & 0xFF),
                          (response[360] & 0xFF),
                          (response[361] & 0xFF),
                          (response[362] & 0xFF),
                          (response[363] & 0xFF),
                          (response[364] & 0xFF),
                          (response[365] & 0xFF),
                          (response[366] & 0xFF),
                          (response[367] & 0xFF),
                          (response[368] & 0xFF),
                          (response[369] & 0xFF),
                          (response[370] & 0xFF),
                          (response[371] & 0xFF),
                          (response[372] & 0xFF),
                          (response[373] & 0xFF),
                          (response[374] & 0xFF),
                          (response[375] & 0xFF),
                          (response[376] & 0xFF),
                          (response[377] & 0xFF),
                          (response[378] & 0xFF),
                          (response[379] & 0xFF),
                          (response[380] & 0xFF),
                          (response[381] & 0xFF),
                          (response[382] & 0xFF),
                          (response[383] & 0xFF),
                          (response[384] & 0xFF),
                          (response[385] & 0xFF),
                          (response[386] & 0xFF),
                          (response[387] & 0xFF),
                          (response[388] & 0xFF),
                          (response[389] & 0xFF),
                          (response[390] & 0xFF),
                          (response[391] & 0xFF),
                          (response[392] & 0xFF),
                          (response[393] & 0xFF),
                          (response[394] & 0xFF),
                          (response[395] & 0xFF),
                          (response[396] & 0xFF),
                          (response[397] & 0xFF),
                          (response[398] & 0xFF),
                          (response[399] & 0xFF),
                          (response[400] & 0xFF),
                          (response[401] & 0xFF),
                          (response[402] & 0xFF),
                          (response[403] & 0xFF),
                          (response[404] & 0xFF),
                          (response[405] & 0xFF),
                          (response[406] & 0xFF),
                          (response[407] & 0xFF),
                          (response[408] & 0xFF),
                          (response[409] & 0xFF),
                          (response[410] & 0xFF),
                          (response[411] & 0xFF),
                          (response[412] & 0xFF),
                          (response[413] & 0xFF),
                          (response[414] & 0xFF),
                          (response[415] & 0xFF),
                          (response[416] & 0xFF),
                          (response[417] & 0xFF),
                          (response[418] & 0xFF),
                          (response[419] & 0xFF),
                          (response[420] & 0xFF),
                          (response[421] & 0xFF),
                          (response[422] & 0xFF),
                          (response[423] & 0xFF),
                          (response[424] & 0xFF),
                          (response[425] & 0xFF),
                          (response[426] & 0xFF),
                          (response[427] & 0xFF),
                          (response[428] & 0xFF),
                          (response[429] & 0xFF),
                          (response[430] & 0xFF),
                          (response[431] & 0xFF),
                          (response[432] & 0xFF),
                          (response[433] & 0xFF),
                          (response[434] & 0xFF),
                          (response[435] & 0xFF),
                          (response[436] & 0xFF),
                          (response[437] & 0xFF),
                          (response[438] & 0xFF),
                          (response[439] & 0xFF),
                          (response[440] & 0xFF),
                          (response[441] & 0xFF),
                          (response[442] & 0xFF),
                          (response[443] & 0xFF),
                          (response[444] & 0xFF),
                          (response[445] & 0xFF),
                          (response[446] & 0xFF),
                          (response[447] & 0xFF),
                          (response[448] & 0xFF),
                          (response[449] & 0xFF),
                          (response[450] & 0xFF),
                          (response[451] & 0xFF),
                          (response[452] & 0xFF),
                          (response[453] & 0xFF),
                          (response[454] & 0xFF),
                          (response[455] & 0xFF),
                          (response[456] & 0xFF),
                          (response[457] & 0xFF),
                          (response[458] & 0xFF),
                          (response[459] & 0xFF),
                          (response[460] & 0xFF),
                          (response[461] & 0xFF),
                          (response[462] & 0xFF),
                          (response[463] & 0xFF),
                          (response[464] & 0xFF),
                          (response[465] & 0xFF),
                          (response[466] & 0xFF),
                          (response[467] & 0xFF),
                          (response[468] & 0xFF),
                          (response[469] & 0xFF),
                          (response[470] & 0xFF),
                          (response[471] & 0xFF),
                          (response[472] & 0xFF),
                          (response[473] & 0xFF),
                          (response[474] & 0xFF),
                          (response[475] & 0xFF),
                          (response[476] & 0xFF),
                          (response[477] & 0xFF),
                          (response[478] & 0xFF),
                          (response[479] & 0xFF),
                          (response[480] & 0xFF),
                          (response[481] & 0xFF),
                          (response[482] & 0xFF),
                          (response[483] & 0xFF),
                          (response[484] & 0xFF),
                          (response[485] & 0xFF),
                          (response[486] & 0xFF),
                          (response[487] & 0xFF),
                          (response[488] & 0xFF),
                          (response[489] & 0xFF),
                          (response[490] & 0xFF),
                          (response[491] & 0xFF),
                          (response[492] & 0xFF),
                          (response[493] & 0xFF),
                          (response[494] & 0xFF),
                          (response[495] & 0xFF),
                          (response[496] & 0xFF),
                          (response[497] & 0xFF),
                          (response[498] & 0xFF),
                          (response[499] & 0xFF),
                          (response[500] & 0xFF),
                          (response[501] & 0xFF),
                          (response[502] & 0xFF),
                          (response[503] & 0xFF),
                          (response[504] & 0xFF),
                          (response[505] & 0xFF),
                          (response[506] & 0xFF),
                          (response[507] & 0xFF),
                          ],
        }
        self.check_response(apiResponse, CanopusApi.Echo)
        self.add_api_exec_cb()
        return apiResponse

    def ControlTask (self, bRoutineSelect, bAction, Reserved):
        #Default header
        header=ArgHeader()
        header.Length = 16
        header.Command = 0x2
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*16
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = bRoutineSelect>>0
        command_array[9] = bAction>>0
        # assert: (x >= 0 && x <= 5)
        command_array[10] = Reserved[0]>>0
        command_array[11] = Reserved[1]>>0
        command_array[12] = Reserved[2]>>0
        command_array[13] = Reserved[3]>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'bState' : (response[4] & 0xFF),
             'Reserved' : [                          (response[5] & 0xFF),
                          (response[6] & 0xFF),
                          ],
        }
        self.check_response(apiResponse, CanopusApi.ControlTask)
        self.add_api_exec_cb()
        return apiResponse

    def ExceptionBacktrace (self, processorId, aReserved):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x6
        header.Tag = 0
        header.MaxResponse = 136
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = processorId>>0
        command_array[9] = aReserved[0]>>0
        command_array[10] = aReserved[1]>>0
        command_array[11] = aReserved[2]>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'exception_cause' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24)),
             'backtrace' : [                          (response[8] & 0xFF)|((response[9]<<8) & (0xFF<<8))|((response[10]<<16) & (0xFF<<16))|((response[11]<<24) & (0xFF<<24)),
                          (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8))|((response[14]<<16) & (0xFF<<16))|((response[15]<<24) & (0xFF<<24)),
                          (response[16] & 0xFF)|((response[17]<<8) & (0xFF<<8))|((response[18]<<16) & (0xFF<<16))|((response[19]<<24) & (0xFF<<24)),
                          (response[20] & 0xFF)|((response[21]<<8) & (0xFF<<8))|((response[22]<<16) & (0xFF<<16))|((response[23]<<24) & (0xFF<<24)),
                          (response[24] & 0xFF)|((response[25]<<8) & (0xFF<<8))|((response[26]<<16) & (0xFF<<16))|((response[27]<<24) & (0xFF<<24)),
                          (response[28] & 0xFF)|((response[29]<<8) & (0xFF<<8))|((response[30]<<16) & (0xFF<<16))|((response[31]<<24) & (0xFF<<24)),
                          (response[32] & 0xFF)|((response[33]<<8) & (0xFF<<8))|((response[34]<<16) & (0xFF<<16))|((response[35]<<24) & (0xFF<<24)),
                          (response[36] & 0xFF)|((response[37]<<8) & (0xFF<<8))|((response[38]<<16) & (0xFF<<16))|((response[39]<<24) & (0xFF<<24)),
                          (response[40] & 0xFF)|((response[41]<<8) & (0xFF<<8))|((response[42]<<16) & (0xFF<<16))|((response[43]<<24) & (0xFF<<24)),
                          (response[44] & 0xFF)|((response[45]<<8) & (0xFF<<8))|((response[46]<<16) & (0xFF<<16))|((response[47]<<24) & (0xFF<<24)),
                          (response[48] & 0xFF)|((response[49]<<8) & (0xFF<<8))|((response[50]<<16) & (0xFF<<16))|((response[51]<<24) & (0xFF<<24)),
                          (response[52] & 0xFF)|((response[53]<<8) & (0xFF<<8))|((response[54]<<16) & (0xFF<<16))|((response[55]<<24) & (0xFF<<24)),
                          (response[56] & 0xFF)|((response[57]<<8) & (0xFF<<8))|((response[58]<<16) & (0xFF<<16))|((response[59]<<24) & (0xFF<<24)),
                          (response[60] & 0xFF)|((response[61]<<8) & (0xFF<<8))|((response[62]<<16) & (0xFF<<16))|((response[63]<<24) & (0xFF<<24)),
                          (response[64] & 0xFF)|((response[65]<<8) & (0xFF<<8))|((response[66]<<16) & (0xFF<<16))|((response[67]<<24) & (0xFF<<24)),
                          (response[68] & 0xFF)|((response[69]<<8) & (0xFF<<8))|((response[70]<<16) & (0xFF<<16))|((response[71]<<24) & (0xFF<<24)),
                          (response[72] & 0xFF)|((response[73]<<8) & (0xFF<<8))|((response[74]<<16) & (0xFF<<16))|((response[75]<<24) & (0xFF<<24)),
                          (response[76] & 0xFF)|((response[77]<<8) & (0xFF<<8))|((response[78]<<16) & (0xFF<<16))|((response[79]<<24) & (0xFF<<24)),
                          (response[80] & 0xFF)|((response[81]<<8) & (0xFF<<8))|((response[82]<<16) & (0xFF<<16))|((response[83]<<24) & (0xFF<<24)),
                          (response[84] & 0xFF)|((response[85]<<8) & (0xFF<<8))|((response[86]<<16) & (0xFF<<16))|((response[87]<<24) & (0xFF<<24)),
                          (response[88] & 0xFF)|((response[89]<<8) & (0xFF<<8))|((response[90]<<16) & (0xFF<<16))|((response[91]<<24) & (0xFF<<24)),
                          (response[92] & 0xFF)|((response[93]<<8) & (0xFF<<8))|((response[94]<<16) & (0xFF<<16))|((response[95]<<24) & (0xFF<<24)),
                          (response[96] & 0xFF)|((response[97]<<8) & (0xFF<<8))|((response[98]<<16) & (0xFF<<16))|((response[99]<<24) & (0xFF<<24)),
                          (response[100] & 0xFF)|((response[101]<<8) & (0xFF<<8))|((response[102]<<16) & (0xFF<<16))|((response[103]<<24) & (0xFF<<24)),
                          (response[104] & 0xFF)|((response[105]<<8) & (0xFF<<8))|((response[106]<<16) & (0xFF<<16))|((response[107]<<24) & (0xFF<<24)),
                          (response[108] & 0xFF)|((response[109]<<8) & (0xFF<<8))|((response[110]<<16) & (0xFF<<16))|((response[111]<<24) & (0xFF<<24)),
                          (response[112] & 0xFF)|((response[113]<<8) & (0xFF<<8))|((response[114]<<16) & (0xFF<<16))|((response[115]<<24) & (0xFF<<24)),
                          (response[116] & 0xFF)|((response[117]<<8) & (0xFF<<8))|((response[118]<<16) & (0xFF<<16))|((response[119]<<24) & (0xFF<<24)),
                          (response[120] & 0xFF)|((response[121]<<8) & (0xFF<<8))|((response[122]<<16) & (0xFF<<16))|((response[123]<<24) & (0xFF<<24)),
                          (response[124] & 0xFF)|((response[125]<<8) & (0xFF<<8))|((response[126]<<16) & (0xFF<<16))|((response[127]<<24) & (0xFF<<24)),
                          (response[128] & 0xFF)|((response[129]<<8) & (0xFF<<8))|((response[130]<<16) & (0xFF<<16))|((response[131]<<24) & (0xFF<<24)),
                          ],
             'reserved_0' : (response[132] & 0xFF)|((response[133]<<8) & (0xFF<<8))|((response[134]<<16) & (0xFF<<16))|((response[135]<<24) & (0xFF<<24)),
        }
        self.check_response(apiResponse, CanopusApi.ExceptionBacktrace)
        self.add_api_exec_cb()
        return apiResponse

    def Hlupgrade (self, action):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x8
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = action>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.Hlupgrade)
        self.add_api_exec_cb()
        return apiResponse

    def ReadRegister (self, address):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1E4
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = address>>0
        command_array[9] = address>>8
        command_array[10] = address>>16
        command_array[11] = address>>24

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'value' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24)),
        }
        self.check_response(apiResponse, CanopusApi.ReadRegister)
        self.add_api_exec_cb()
        return apiResponse

    def WriteRegister (self, address, value):
        #Default header
        header=ArgHeader()
        header.Length = 16
        header.Command = 0x1E3
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*16
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = address>>0
        command_array[9] = address>>8
        command_array[10] = address>>16
        command_array[11] = address>>24
        command_array[12] = value>>0
        command_array[13] = value>>8
        command_array[14] = value>>16
        command_array[15] = value>>24

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'status' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24)),
        }
        self.check_response(apiResponse, CanopusApi.WriteRegister)
        self.add_api_exec_cb()
        return apiResponse

    def UpdateOneRegister (self, address, value, mask):
        #Default header
        header=ArgHeader()
        header.Length = 20
        header.Command = 0x1E2
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*20
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = address>>0
        command_array[9] = address>>8
        command_array[10] = address>>16
        command_array[11] = address>>24
        command_array[12] = value>>0
        command_array[13] = value>>8
        command_array[14] = value>>16
        command_array[15] = value>>24
        command_array[16] = mask>>0
        command_array[17] = mask>>8
        command_array[18] = mask>>16
        command_array[19] = mask>>24

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.UpdateOneRegister)
        self.add_api_exec_cb()
        return apiResponse

    def ReadFirmwareInformation (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x1E1
        header.Tag = 0
        header.MaxResponse = 92
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'dFirmwareVersion' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24)),
             'aGitHash' : [                          (response[8] & 0xFF),
                          (response[9] & 0xFF),
                          (response[10] & 0xFF),
                          (response[11] & 0xFF),
                          (response[12] & 0xFF),
                          (response[13] & 0xFF),
                          (response[14] & 0xFF),
                          (response[15] & 0xFF),
                          (response[16] & 0xFF),
                          (response[17] & 0xFF),
                          (response[18] & 0xFF),
                          (response[19] & 0xFF),
                          ],
             'aCpiosGitHash' : [                          (response[20] & 0xFF),
                          (response[21] & 0xFF),
                          (response[22] & 0xFF),
                          (response[23] & 0xFF),
                          (response[24] & 0xFF),
                          (response[25] & 0xFF),
                          (response[26] & 0xFF),
                          (response[27] & 0xFF),
                          (response[28] & 0xFF),
                          (response[29] & 0xFF),
                          (response[30] & 0xFF),
                          (response[31] & 0xFF),
                          ],
             'sun_git_hash' : [                          (response[32] & 0xFF),
                          (response[33] & 0xFF),
                          (response[34] & 0xFF),
                          (response[35] & 0xFF),
                          (response[36] & 0xFF),
                          (response[37] & 0xFF),
                          (response[38] & 0xFF),
                          (response[39] & 0xFF),
                          (response[40] & 0xFF),
                          (response[41] & 0xFF),
                          (response[42] & 0xFF),
                          (response[43] & 0xFF),
                          ],
             'pll_sw_git_hash' : [                          (response[44] & 0xFF),
                          (response[45] & 0xFF),
                          (response[46] & 0xFF),
                          (response[47] & 0xFF),
                          (response[48] & 0xFF),
                          (response[49] & 0xFF),
                          (response[50] & 0xFF),
                          (response[51] & 0xFF),
                          (response[52] & 0xFF),
                          (response[53] & 0xFF),
                          (response[54] & 0xFF),
                          (response[55] & 0xFF),
                          ],
             'api_hash' : [                          (response[56] & 0xFF),
                          (response[57] & 0xFF),
                          (response[58] & 0xFF),
                          (response[59] & 0xFF),
                          (response[60] & 0xFF),
                          (response[61] & 0xFF),
                          (response[62] & 0xFF),
                          (response[63] & 0xFF),
                          (response[64] & 0xFF),
                          (response[65] & 0xFF),
                          (response[66] & 0xFF),
                          (response[67] & 0xFF),
                          ],
             'hlu_hash' : [                          (response[68] & 0xFF),
                          (response[69] & 0xFF),
                          (response[70] & 0xFF),
                          (response[71] & 0xFF),
                          (response[72] & 0xFF),
                          (response[73] & 0xFF),
                          (response[74] & 0xFF),
                          (response[75] & 0xFF),
                          (response[76] & 0xFF),
                          (response[77] & 0xFF),
                          (response[78] & 0xFF),
                          (response[79] & 0xFF),
                          ],
             'aRm' : [                          (response[80] & 0xFF),
                          (response[81] & 0xFF),
                          (response[82] & 0xFF),
                          (response[83] & 0xFF),
                          ],
             'aDate' : [                          (response[84] & 0xFF),
                          (response[85] & 0xFF),
                          (response[86] & 0xFF),
                          (response[87] & 0xFF),
                          (response[88] & 0xFF),
                          (response[89] & 0xFF),
                          ],
             'bReserved' : (response[90] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.ReadFirmwareInformation)
        self.add_api_exec_cb()
        return apiResponse

    def GetGpio (self, gpio_id):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1DC
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = gpio_id>>0
        # assert: (x < 42)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'gpio_direction' : (response[4] & 0xFF),
             'gpio_status' : (response[5] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetGpio)
        self.add_api_exec_cb()
        return apiResponse

    def SetGpio (self, gpio_id, gpio_direction, gpio_status):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1DB
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = gpio_id>>0
        # assert: (x < 42)
        command_array[9] = gpio_direction>>0
        # assert: (x >= 0 && x <= 1)
        command_array[10] = gpio_status>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetGpio)
        self.add_api_exec_cb()
        return apiResponse

    def GetChipId (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x1E5
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'chip_id' : (response[4] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetChipId)
        self.add_api_exec_cb()
        return apiResponse

    def SetGpioMap (self, register_addr, gpio_id, bit_number, gpio_direction):
        #Default header
        header=ArgHeader()
        header.Length = 16
        header.Command = 0x1DD
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*16
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = register_addr>>0
        command_array[9] = register_addr>>8
        command_array[10] = register_addr>>16
        command_array[11] = register_addr>>24
        command_array[12] = gpio_id>>0
        # assert: (x < 42)
        command_array[13] = bit_number>>0
        # assert: (x < 32)
        command_array[14] = gpio_direction>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetGpioMap)
        self.add_api_exec_cb()
        return apiResponse

    def GetGpioMap (self, gpio_id):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1DE
        header.Tag = 0
        header.MaxResponse = 12
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = gpio_id>>0
        # assert: (x < 42)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'register_addr' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24)),
             'bit_number' : (response[8] & 0xFF),
             'gpio_direction' : (response[9] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetGpioMap)
        self.add_api_exec_cb()
        return apiResponse

    def SetTransceiverMode (self, reserved_0, line_fec, pilot_symbol_separation, line_shaping, line_modulation, bcd_mode, ltx_osr, lrx_osr, reserved_1, signal_type, line_mapping, host_modulation):
        #Default header
        header=ArgHeader()
        header.Length = 32
        header.Command = 0x100
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*32
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = reserved_0>>0
        # assert: (x >= 0 && x <= 2) || (x >= 4 && x <= 9)
        command_array[9] = line_fec>>0
        # assert: (x >= 0 && x <= 6)
        command_array[10] = pilot_symbol_separation>>0
        command_array[11] = line_shaping>>0
        command_array[12] = line_modulation>>0
        # assert: (x == 4) || (x == 6) || (x == 8)
        command_array[13] = bcd_mode>>0
        command_array[14] = bcd_mode>>8
        command_array[15] = bcd_mode>>16
        command_array[16] = bcd_mode>>24
        command_array[17] = ltx_osr>>0
        # assert: (x >= 0 && x <= 2)
        command_array[18] = lrx_osr>>0
        # assert: (x >= 0 && x <= 2)
        command_array[19] = reserved_1>>0
        command_array[20] = reserved_1>>8
        command_array[21] = reserved_1>>16
        command_array[22] = reserved_1>>24
        command_array[23] = signal_type[0]>>0
        # assert: (x >= 0 && x <= 7)
        command_array[24] = signal_type[1]>>0
        # assert: (x >= 0 && x <= 7)
        command_array[25] = signal_type[2]>>0
        # assert: (x >= 0 && x <= 7)
        command_array[26] = signal_type[3]>>0
        # assert: (x >= 0 && x <= 7)
        command_array[27] = line_mapping[0]>>0
        # assert: (x >= 0 && x <= 7)
        command_array[28] = line_mapping[1]>>0
        # assert: (x >= 0 && x <= 7)
        command_array[29] = line_mapping[2]>>0
        # assert: (x >= 0 && x <= 7)
        command_array[30] = line_mapping[3]>>0
        # assert: (x >= 0 && x <= 7)
        command_array[31] = host_modulation>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetTransceiverMode)
        self.add_api_exec_cb()
        return apiResponse

    def SetLoopbackMode (self, lpbk_mode, channel, enable):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x105
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lpbk_mode>>0
        # assert: (x >= 0 && x <= 8)
        command_array[9] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[10] = enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetLoopbackMode)
        self.add_api_exec_cb()
        return apiResponse

    def GetLoopbackMode (self, lpbk_mode, channel):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x106
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lpbk_mode>>0
        # assert: (x >= 0 && x <= 8)
        command_array[9] = channel>>0
        # assert: (x >= 0 && x <= 4)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'enable' : (response[4] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetLoopbackMode)
        self.add_api_exec_cb()
        return apiResponse

    def SetHostBallMap (self, hrx_mapping, htx_mapping):
        #Default header
        header=ArgHeader()
        header.Length = 16
        header.Command = 0x103
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*16
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = hrx_mapping[0]>>0
        # assert: (x<4)
        command_array[9] = hrx_mapping[1]>>0
        # assert: (x<4)
        command_array[10] = hrx_mapping[2]>>0
        # assert: (x<4)
        command_array[11] = hrx_mapping[3]>>0
        # assert: (x<4)
        command_array[12] = htx_mapping[0]>>0
        # assert: (x<4)
        command_array[13] = htx_mapping[1]>>0
        # assert: (x<4)
        command_array[14] = htx_mapping[2]>>0
        # assert: (x<4)
        command_array[15] = htx_mapping[3]>>0
        # assert: (x<4)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetHostBallMap)
        self.add_api_exec_cb()
        return apiResponse

    def SetHostDynamicReprovisioning (self, channel, signal_type):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x102
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = signal_type>>0
        # assert: (x >= 0 && x <= 7)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetHostDynamicReprovisioning)
        self.add_api_exec_cb()
        return apiResponse

    def GetTransceiverMode (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x101
        header.Tag = 0
        header.MaxResponse = 24
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'line_fec' : (response[4] & 0xFF),
             'pilot_symbol_separation' : (response[5] & 0xFF),
             'line_shaping' : (response[6] & 0xFF),
             'line_modulation' : (response[7] & 0xFF),
             'bcd_mode' : (response[8] & 0xFF)|((response[9]<<8) & (0xFF<<8))|((response[10]<<16) & (0xFF<<16))|((response[11]<<24) & (0xFF<<24)),
             'ltx_osr' : (response[12] & 0xFF),
             'lrx_osr' : (response[13] & 0xFF),
             'signal_type' : [                          (response[14] & 0xFF),
                          (response[15] & 0xFF),
                          (response[16] & 0xFF),
                          (response[17] & 0xFF),
                          ],
             'line_mapping' : [                          (response[18] & 0xFF),
                          (response[19] & 0xFF),
                          (response[20] & 0xFF),
                          (response[21] & 0xFF),
                          ],
             'host_modulation' : (response[22] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetTransceiverMode)
        self.add_api_exec_cb()
        return apiResponse

    def GetHostBallMap (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x104
        header.Tag = 0
        header.MaxResponse = 12
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'hrx_mapping' : [                          (response[4] & 0xFF),
                          (response[5] & 0xFF),
                          (response[6] & 0xFF),
                          (response[7] & 0xFF),
                          ],
             'htx_mapping' : [                          (response[8] & 0xFF),
                          (response[9] & 0xFF),
                          (response[10] & 0xFF),
                          (response[11] & 0xFF),
                          ],
        }
        self.check_response(apiResponse, CanopusApi.GetHostBallMap)
        self.add_api_exec_cb()
        return apiResponse

    def SetOpticalMonitorTriggerSource (self, trigger_source, interval):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x20A
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = trigger_source>>0
        # assert: (x >= 0 && x <= 1)
        command_array[9] = interval>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOpticalMonitorTriggerSource)
        self.add_api_exec_cb()
        return apiResponse

    def SetPerformanceMonitorTriggerSource (self, trigger_source):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x16A
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = trigger_source>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetPerformanceMonitorTriggerSource)
        self.add_api_exec_cb()
        return apiResponse

    def GetOpticalMonitorTriggerSource (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x20B
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'trigger_source' : (response[4] & 0xFF),
             'interval' : (response[5] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOpticalMonitorTriggerSource)
        self.add_api_exec_cb()
        return apiResponse

    def GetPerformanceMonitorTriggerSource (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x16B
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'trigger_source' : (response[4] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetPerformanceMonitorTriggerSource)
        self.add_api_exec_cb()
        return apiResponse

    def TriggerMonitors (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x16C
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.TriggerMonitors)
        self.add_api_exec_cb()
        return apiResponse

    def SetPcsMode (self, channel, mode):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x107
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = mode>>0
        # assert: (x >= 0 && x <= 5)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetPcsMode)
        self.add_api_exec_cb()
        return apiResponse

    def GetPcsMode (self, channel):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x108
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'mode' : (response[4] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetPcsMode)
        self.add_api_exec_cb()
        return apiResponse

    def ReStartLineIngressDsp (self, action):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1F5
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = action>>0
        # assert: (x >= 0 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.ReStartLineIngressDsp)
        self.add_api_exec_cb()
        return apiResponse

    def ResetTransceiver (self, path):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1F4
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = path>>0
        # assert: (x >= 0 && x <= 2) || (x >= 4 && x <= 9)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.ResetTransceiver)
        self.add_api_exec_cb()
        return apiResponse

    def SetClientSwap (self, direction, clients):
        #Default header
        header=ArgHeader()
        header.Length = 16
        header.Command = 0x153
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*16
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = direction>>0
        # assert: (x >= 1 && x <= 2)
        command_array[9] = clients[0]>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = clients[1]>>0
        # assert: (x >= 0 && x <= 3)
        command_array[11] = clients[2]>>0
        # assert: (x >= 0 && x <= 3)
        command_array[12] = clients[3]>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetClientSwap)
        self.add_api_exec_cb()
        return apiResponse

    def GetClientSwap (self, direction):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x154
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = direction>>0
        # assert: (x >= 1 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'clients' : [                          (response[4] & 0xFF),
                          (response[5] & 0xFF),
                          (response[6] & 0xFF),
                          (response[7] & 0xFF),
                          ],
        }
        self.check_response(apiResponse, CanopusApi.GetClientSwap)
        self.add_api_exec_cb()
        return apiResponse

    def SetEthernetFec (self, channel, bypass_correction_enable, bypass_indication_enable):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x196
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = bypass_correction_enable>>0
        # assert: (x >= 0 && x <= 1)
        command_array[10] = bypass_indication_enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetEthernetFec)
        self.add_api_exec_cb()
        return apiResponse

    def GetEthernetFec (self, channel):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x197
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'bypass_correction_enable' : (response[4] & 0xFF),
             'bypass_indication_enable' : (response[5] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetEthernetFec)
        self.add_api_exec_cb()
        return apiResponse

    def SetOtnOhpHardwareAlarmsInterfacesConfig (self, channel, map_level, hardware_pin_select, ddeg_bus, dtim_bus, diae_bus, dbiae_bus, dbdi_bus, dltc_bus, dais_bus, doci_bus, dlck_bus, dmsim, dplm, dcsf):
        #Default header
        header=ArgHeader()
        header.Length = 24
        header.Command = 0x149
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*24
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = hardware_pin_select>>0
        # assert: (x >= 0 && x <= 2)
        command_array[11] = ddeg_bus>>0
        command_array[12] = dtim_bus>>0
        command_array[13] = diae_bus>>0
        command_array[14] = dbiae_bus>>0
        command_array[15] = dbdi_bus>>0
        command_array[16] = dltc_bus>>0
        command_array[17] = dais_bus>>0
        command_array[18] = doci_bus>>0
        command_array[19] = dlck_bus>>0
        command_array[20] = dmsim>>0
        # assert: (x >= 0 && x <= 1)
        command_array[21] = dplm>>0
        # assert: (x >= 0 && x <= 1)
        command_array[22] = dcsf>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOtnOhpHardwareAlarmsInterfacesConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnOhpHardwareAlarmsInterfacesConfig (self, channel, map_level, hardware_pin_select):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x14A
        header.Tag = 0
        header.MaxResponse = 16
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = hardware_pin_select>>0
        # assert: (x >= 0 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'ddeg_bus' : (response[4] & 0xFF),
             'dtim_bus' : (response[5] & 0xFF),
             'diae_bus' : (response[6] & 0xFF),
             'dbiae_bus' : (response[7] & 0xFF),
             'dbdi_bus' : (response[8] & 0xFF),
             'dltc_bus' : (response[9] & 0xFF),
             'dais_bus' : (response[10] & 0xFF),
             'doci_bus' : (response[11] & 0xFF),
             'dlck_bus' : (response[12] & 0xFF),
             'dmsim' : (response[13] & 0xFF),
             'dplm' : (response[14] & 0xFF),
             'dcsf' : (response[15] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtnOhpHardwareAlarmsInterfacesConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetOtnHardwareAlarmsInterfacesConfig (self, channel, direction, hardware_pin_select, otu_dloflane, otu_dlol, otu_dlof, otu_dlom):
        #Default header
        header=ArgHeader()
        header.Length = 16
        header.Command = 0x145
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*16
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)
        command_array[10] = hardware_pin_select>>0
        # assert: (x >= 0 && x <= 2)
        command_array[11] = otu_dloflane>>0
        # assert: (x >= 0 && x <= 1)
        command_array[12] = otu_dlol>>0
        # assert: (x >= 0 && x <= 1)
        command_array[13] = otu_dlof>>0
        # assert: (x >= 0 && x <= 1)
        command_array[14] = otu_dlom>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOtnHardwareAlarmsInterfacesConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnHardwareAlarmsInterfacesConfig (self, channel, direction, hardware_pin_select):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x146
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)
        command_array[10] = hardware_pin_select>>0
        # assert: (x >= 0 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'otu_dloflane' : (response[4] & 0xFF),
             'otu_dlol' : (response[5] & 0xFF),
             'otu_dlof' : (response[6] & 0xFF),
             'otu_dlom' : (response[7] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtnHardwareAlarmsInterfacesConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetOtnGmpHardwareAlarmsInterfacesConfig (self, channel, hardware_pin_select, odu_map1_dloflom, odu_map2_dloflom, gmp_host_dloomfi, gmp_map1_dloomfi, gmp_map2_dloomfi):
        #Default header
        header=ArgHeader()
        header.Length = 16
        header.Command = 0x147
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*16
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = hardware_pin_select>>0
        # assert: (x >= 0 && x <= 2)
        command_array[10] = odu_map1_dloflom>>0
        # assert: (x >= 0 && x <= 1)
        command_array[11] = odu_map2_dloflom>>0
        # assert: (x >= 0 && x <= 1)
        command_array[12] = gmp_host_dloomfi>>0
        # assert: (x >= 0 && x <= 1)
        command_array[13] = gmp_map1_dloomfi>>0
        # assert: (x >= 0 && x <= 1)
        command_array[14] = gmp_map2_dloomfi>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOtnGmpHardwareAlarmsInterfacesConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnGmpHardwareAlarmsInterfacesConfig (self, channel, hardware_pin_select):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x148
        header.Tag = 0
        header.MaxResponse = 12
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = hardware_pin_select>>0
        # assert: (x >= 0 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'odu_map1_dloflom' : (response[4] & 0xFF),
             'odu_map2_dloflom' : (response[5] & 0xFF),
             'gmp_host_dloomfi' : (response[6] & 0xFF),
             'gmp_map1_dloomfi' : (response[7] & 0xFF),
             'gmp_map2_dloomfi' : (response[8] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtnGmpHardwareAlarmsInterfacesConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetEthernetHardwareAlarmsInterfacesConfig (self, channel, direction, hardware_pin_select, pcs_align_status_n, pcs_lf_detected, pcs_rf_detected, pcs_hi_ber, pcs_hi_ser, pcs257_am_lock_n, pcs66_block_lock_n, pcs66_am_lock_n):
        #Default header
        header=ArgHeader()
        header.Length = 20
        header.Command = 0x14B
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*20
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)
        command_array[10] = hardware_pin_select>>0
        # assert: (x >= 0 && x <= 2)
        command_array[11] = pcs_align_status_n>>0
        # assert: (x >= 0 && x <= 1)
        command_array[12] = pcs_lf_detected>>0
        # assert: (x >= 0 && x <= 1)
        command_array[13] = pcs_rf_detected>>0
        # assert: (x >= 0 && x <= 1)
        command_array[14] = pcs_hi_ber>>0
        # assert: (x >= 0 && x <= 1)
        command_array[15] = pcs_hi_ser>>0
        # assert: (x >= 0 && x <= 1)
        command_array[16] = pcs257_am_lock_n>>0
        # assert: (x >= 0 && x <= 1)
        command_array[17] = pcs66_block_lock_n>>0
        # assert: (x >= 0 && x <= 1)
        command_array[18] = pcs66_am_lock_n>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetEthernetHardwareAlarmsInterfacesConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetEthernetHardwareAlarmsInterfacesConfig (self, channel, direction, hardware_pin_select):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x14C
        header.Tag = 0
        header.MaxResponse = 12
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)
        command_array[10] = hardware_pin_select>>0
        # assert: (x >= 0 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'pcs_align_status_n' : (response[4] & 0xFF),
             'pcs_lf_detected' : (response[5] & 0xFF),
             'pcs_rf_detected' : (response[6] & 0xFF),
             'pcs_hi_ber' : (response[7] & 0xFF),
             'pcs_hi_ser' : (response[8] & 0xFF),
             'pcs257_am_lock_n' : (response[9] & 0xFF),
             'pcs66_block_lock_n' : (response[10] & 0xFF),
             'pcs66_am_lock_n' : (response[11] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetEthernetHardwareAlarmsInterfacesConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetFlexOHardwareAlarmsInterfacesConfig (self, channel, hardware_pin_select):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x14E
        header.Tag = 0
        header.MaxResponse = 12
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = hardware_pin_select>>0
        # assert: (x >= 0 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'flexo_dlol' : (response[4] & 0xFF),
             'flexo_dlom' : (response[5] & 0xFF),
             'flexo_dloflom' : (response[6] & 0xFF),
             'flexo_drdi' : (response[7] & 0xFF),
             'flexo_dgidm' : (response[8] & 0xFF),
             'flexo_dpmm' : (response[9] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetFlexOHardwareAlarmsInterfacesConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetFlexOHardwareAlarmsInterfacesConfig (self, channel, hardware_pin_select, flexo_dlol, flexo_dlom, flexo_dloflom, flexo_drdi, flexo_dgidm, flexo_dpmm):
        #Default header
        header=ArgHeader()
        header.Length = 16
        header.Command = 0x14D
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*16
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = hardware_pin_select>>0
        # assert: (x >= 0 && x <= 2)
        command_array[10] = flexo_dlol>>0
        # assert: (x >= 0 && x <= 1)
        command_array[11] = flexo_dlom>>0
        # assert: (x >= 0 && x <= 1)
        command_array[12] = flexo_dloflom>>0
        # assert: (x >= 0 && x <= 1)
        command_array[13] = flexo_drdi>>0
        # assert: (x >= 0 && x <= 1)
        command_array[14] = flexo_dgidm>>0
        # assert: (x >= 0 && x <= 1)
        command_array[15] = flexo_dpmm>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetFlexOHardwareAlarmsInterfacesConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetFlexEHardwareAlarmsInterfacesConfig (self, channel, direction, hardware_pin_select):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x150
        header.Tag = 0
        header.MaxResponse = 12
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)
        command_array[10] = hardware_pin_select>>0
        # assert: (x >= 0 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'flexe_drdi' : (response[4] & 0xFF),
             'flexe_dgidm' : (response[5] & 0xFF),
             'flexe_dpmm' : (response[6] & 0xFF),
             'flexe_dlof' : (response[7] & 0xFF),
             'flexe_dlom' : (response[8] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetFlexEHardwareAlarmsInterfacesConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetFlexEHardwareAlarmsInterfacesConfig (self, channel, direction, hardware_pin_select, flexe_drdi, flexe_dgidm, flexe_dpmm, flexe_dlof, flexe_dlom):
        #Default header
        header=ArgHeader()
        header.Length = 16
        header.Command = 0x14F
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*16
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)
        command_array[10] = hardware_pin_select>>0
        # assert: (x >= 0 && x <= 2)
        command_array[11] = flexe_drdi>>0
        # assert: (x >= 0 && x <= 1)
        command_array[12] = flexe_dgidm>>0
        # assert: (x >= 0 && x <= 1)
        command_array[13] = flexe_dpmm>>0
        # assert: (x >= 0 && x <= 1)
        command_array[14] = flexe_dlof>>0
        # assert: (x >= 0 && x <= 1)
        command_array[15] = flexe_dlom>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetFlexEHardwareAlarmsInterfacesConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetGmpConsequentActionConfig (self, channel, map_level, gmp_dloomfi_ca_enable, ohp_dplm_ca_enable):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1F9
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = gmp_dloomfi_ca_enable>>0
        # assert: (x >= 0 && x <= 1)
        command_array[11] = ohp_dplm_ca_enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetGmpConsequentActionConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetGmpConsequentActionConfig (self, channel, map_level):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1FA
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'gmp_dloomfi_ca_enable' : (response[4] & 0xFF),
             'ohp_dplm_ca_enable' : (response[5] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetGmpConsequentActionConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetEthernetConsequentActionsConfig (self, channel, direction, pcs_lf_detected_ca_enable, pcs_rf_detected_ca_enable, pcs_hi_ber_ca_enable, pcs_hi_ser_ca_enable):
        #Default header
        header=ArgHeader()
        header.Length = 16
        header.Command = 0x155
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*16
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)
        command_array[10] = pcs_lf_detected_ca_enable>>0
        # assert: (x >= 0 && x <= 1)
        command_array[11] = pcs_rf_detected_ca_enable>>0
        # assert: (x >= 0 && x <= 1)
        command_array[12] = pcs_hi_ber_ca_enable>>0
        # assert: (x >= 0 && x <= 1)
        command_array[13] = pcs_hi_ser_ca_enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetEthernetConsequentActionsConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetEthernetConsequentActionsConfig (self, channel, direction):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x156
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'pcs_lf_detected_ca_enable' : (response[4] & 0xFF),
             'pcs_rf_detected_ca_enable' : (response[5] & 0xFF),
             'pcs_hi_ber_ca_enable' : (response[6] & 0xFF),
             'pcs_hi_ser_ca_enable' : (response[7] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetEthernetConsequentActionsConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetFlexOConsequentActionsConfig (self, channel, flexo_drdi_ca_enable, flexo_dgidm_ca_enable, flexo_dpmm_ca_enable):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x157
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = flexo_drdi_ca_enable>>0
        # assert: (x >= 0 && x <= 1)
        command_array[10] = flexo_dgidm_ca_enable>>0
        # assert: (x >= 0 && x <= 1)
        command_array[11] = flexo_dpmm_ca_enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetFlexOConsequentActionsConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetFlexOConsequentActionsConfig (self, channel):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x158
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'flexo_drdi_ca_enable' : (response[4] & 0xFF),
             'flexo_dgidm_ca_enable' : (response[5] & 0xFF),
             'flexo_dpmm_ca_enable' : (response[6] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetFlexOConsequentActionsConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetEnableConsequentActions (self, channel, direction, ca_enable):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x15B
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)
        command_array[10] = ca_enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetEnableConsequentActions)
        self.add_api_exec_cb()
        return apiResponse

    def GetEnableConsequentActions (self, channel, direction):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x15C
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'ca_enable' : (response[4] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetEnableConsequentActions)
        self.add_api_exec_cb()
        return apiResponse

    def SetEthernetMaintenanceSignalConfig (self, channel, egress_maintenance_signal, ingress_maintenance_signal):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x15D
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = egress_maintenance_signal>>0
        # assert: (x >= 0 && x <= 1)
        command_array[10] = ingress_maintenance_signal>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetEthernetMaintenanceSignalConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetEthernetMaintenanceSignalConfig (self, channel):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x15E
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'egress_maintenance_signal' : (response[4] & 0xFF),
             'ingress_maintenance_signal' : (response[5] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetEthernetMaintenanceSignalConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnOhpPmCounters (self, channel, map_level, layer_level):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x168
        header.Tag = 0
        header.MaxResponse = 24
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = layer_level>>0
        # assert: (x >= 0 && x <= 7)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'near_ebc_count' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24))|((response[8]<<32) & (0xFF<<32))|((response[9]<<40) & (0xFF<<40))|((response[10]<<48) & (0xFF<<48))|((response[11]<<56) & (0xFF<<56)),
             'far_ebc_count' : (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8))|((response[14]<<16) & (0xFF<<16))|((response[15]<<24) & (0xFF<<24))|((response[16]<<32) & (0xFF<<32))|((response[17]<<40) & (0xFF<<40))|((response[18]<<48) & (0xFF<<48))|((response[19]<<56) & (0xFF<<56)),
             'near_ds' : (response[20] & 0xFF),
             'far_ds' : (response[21] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtnOhpPmCounters)
        self.add_api_exec_cb()
        return apiResponse

    def SetFlexoGroupConfig (self, channel_sync):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x151
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel_sync[0]>>0
        # assert: (x >= 0 && x <= 1)
        command_array[9] = channel_sync[1]>>0
        # assert: (x >= 0 && x <= 1)
        command_array[10] = channel_sync[2]>>0
        # assert: (x >= 0 && x <= 1)
        command_array[11] = channel_sync[3]>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetFlexoGroupConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetFlexoGroupConfig (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x152
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'channel_sync' : [                          (response[4] & 0xFF),
                          (response[5] & 0xFF),
                          (response[6] & 0xFF),
                          (response[7] & 0xFF),
                          ],
        }
        self.check_response(apiResponse, CanopusApi.GetFlexoGroupConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetFlexOOhpSinkFieldsAccepted (self, channel):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x213
        header.Tag = 0
        header.MaxResponse = 44
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'phy_map_accepted' : [                          (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24)),
                          (response[8] & 0xFF)|((response[9]<<8) & (0xFF<<8))|((response[10]<<16) & (0xFF<<16))|((response[11]<<24) & (0xFF<<24)),
                          (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8))|((response[14]<<16) & (0xFF<<16))|((response[15]<<24) & (0xFF<<24)),
                          (response[16] & 0xFF)|((response[17]<<8) & (0xFF<<8))|((response[18]<<16) & (0xFF<<16))|((response[19]<<24) & (0xFF<<24)),
                          (response[20] & 0xFF)|((response[21]<<8) & (0xFF<<8))|((response[22]<<16) & (0xFF<<16))|((response[23]<<24) & (0xFF<<24)),
                          (response[24] & 0xFF)|((response[25]<<8) & (0xFF<<8))|((response[26]<<16) & (0xFF<<16))|((response[27]<<24) & (0xFF<<24)),
                          (response[28] & 0xFF)|((response[29]<<8) & (0xFF<<8))|((response[30]<<16) & (0xFF<<16))|((response[31]<<24) & (0xFF<<24)),
                          (response[32] & 0xFF)|((response[33]<<8) & (0xFF<<8))|((response[34]<<16) & (0xFF<<16))|((response[35]<<24) & (0xFF<<24)),
                          ],
             'gid_accepted' : (response[36] & 0xFF)|((response[37]<<8) & (0xFF<<8))|((response[38]<<16) & (0xFF<<16))|((response[39]<<24) & (0xFF<<24)),
             'pid_accepted' : (response[40] & 0xFF),
             'avail_accepted' : (response[41] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetFlexOOhpSinkFieldsAccepted)
        self.add_api_exec_cb()
        return apiResponse

    def SetPcsFramePauseConfig (self, frame_pause_source_address, frame_pause_destination_address, frame_pause_enable, frame_pause_time_override_enable, frame_pause_time_override_value, frame_pause_gap_override_enable, frame_pause_gap_override_value):
        #Default header
        header=ArgHeader()
        header.Length = 32
        header.Command = 0x215
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*32
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = frame_pause_source_address>>0
        command_array[9] = frame_pause_source_address>>8
        command_array[10] = frame_pause_source_address>>16
        command_array[11] = frame_pause_source_address>>24
        command_array[12] = frame_pause_source_address>>32
        command_array[13] = frame_pause_source_address>>40
        command_array[14] = frame_pause_source_address>>48
        command_array[15] = frame_pause_source_address>>56
        # assert: (x <= 0xFFFFFFFFFFFFULL)
        command_array[16] = frame_pause_destination_address>>0
        command_array[17] = frame_pause_destination_address>>8
        command_array[18] = frame_pause_destination_address>>16
        command_array[19] = frame_pause_destination_address>>24
        command_array[20] = frame_pause_destination_address>>32
        command_array[21] = frame_pause_destination_address>>40
        command_array[22] = frame_pause_destination_address>>48
        command_array[23] = frame_pause_destination_address>>56
        # assert: (x <= 0xFFFFFFFFFFFFULL)
        command_array[24] = frame_pause_enable>>0
        # assert: (x >= 0 && x <= 1)
        command_array[25] = frame_pause_time_override_enable>>0
        # assert: (x >= 0 && x <= 1)
        command_array[26] = frame_pause_time_override_value>>0
        command_array[27] = frame_pause_time_override_value>>8
        command_array[28] = frame_pause_gap_override_enable>>0
        # assert: (x >= 0 && x <= 1)
        command_array[29] = frame_pause_gap_override_value>>0
        # assert: (x <= 0x3F)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetPcsFramePauseConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetPcsFramePauseConfig (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x216
        header.Tag = 0
        header.MaxResponse = 28
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'frame_pause_source_address' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24))|((response[8]<<32) & (0xFF<<32))|((response[9]<<40) & (0xFF<<40))|((response[10]<<48) & (0xFF<<48))|((response[11]<<56) & (0xFF<<56)),
             'frame_pause_destination_address' : (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8))|((response[14]<<16) & (0xFF<<16))|((response[15]<<24) & (0xFF<<24))|((response[16]<<32) & (0xFF<<32))|((response[17]<<40) & (0xFF<<40))|((response[18]<<48) & (0xFF<<48))|((response[19]<<56) & (0xFF<<56)),
             'frame_pause_enable' : (response[20] & 0xFF),
             'frame_pause_time_override_enable' : (response[21] & 0xFF),
             'frame_pause_time_override_value' : (response[22] & 0xFF)|((response[23]<<8) & (0xFF<<8)),
             'frame_pause_gap_override_enable' : (response[24] & 0xFF),
             'frame_pause_gap_override_value' : (response[25] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetPcsFramePauseConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetPcsMlgAlignmentMarkers (self, channel, lane_marker):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x225
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = lane_marker>>0
        # assert: (x >= 0 && x <= 4)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetPcsMlgAlignmentMarkers)
        self.add_api_exec_cb()
        return apiResponse

    def GetPcsMlgAlignmentMarkers (self, channel):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x226
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'lane_marker' : (response[4] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetPcsMlgAlignmentMarkers)
        self.add_api_exec_cb()
        return apiResponse

    def SetEthernetIdleTrafficTimer (self, channel, timer_value):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x22E
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = timer_value>>0
        command_array[10] = timer_value>>8
        # assert: (x <= 10000)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetEthernetIdleTrafficTimer)
        self.add_api_exec_cb()
        return apiResponse

    def GetEthernetIdleTrafficTimer (self, channel):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x22F
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'timer_value' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8)),
        }
        self.check_response(apiResponse, CanopusApi.GetEthernetIdleTrafficTimer)
        self.add_api_exec_cb()
        return apiResponse

    def SetOtnMaintenanceSignalConfig (self, channel, maintenance_signal):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x236
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = maintenance_signal>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOtnMaintenanceSignalConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnMaintenanceSignalConfig (self, channel):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x237
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'maintenance_signal' : (response[4] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtnMaintenanceSignalConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetFlexOMaintenanceSignalConfig (self, channel, maintenance_signal):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x239
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = maintenance_signal>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetFlexOMaintenanceSignalConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetFlexOMaintenanceSignalConfig (self, channel):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x23A
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'maintenance_signal' : (response[4] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetFlexOMaintenanceSignalConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetOverrideDefaultConfig (self, param_index, value):
        #Default header
        header=ArgHeader()
        header.Length = 16
        header.Command = 0x1EE
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*16
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = param_index>>0
        # assert: (x >= 0 && x <= 28)
        command_array[9] = value>>0
        command_array[10] = value>>8
        command_array[11] = value>>16
        command_array[12] = value>>24

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOverrideDefaultConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineEgressLowSrLaneAttenuation (self, lane):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x129
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'attenuation' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8)),
        }
        self.check_response(apiResponse, CanopusApi.GetLineEgressLowSrLaneAttenuation)
        self.add_api_exec_cb()
        return apiResponse

    def SetLineEgressLowSrLaneAttenuation (self, lane, attenuation):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x128
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = attenuation>>0
        command_array[10] = attenuation>>8

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetLineEgressLowSrLaneAttenuation)
        self.add_api_exec_cb()
        return apiResponse

    def SetLineEgressLowSrFilterCoefficients (self, lane, coefficients):
        #Default header
        header=ArgHeader()
        header.Length = 24
        header.Command = 0x11C
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*24
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = coefficients[0]>>0
        command_array[10] = coefficients[0]>>8
        # assert: (x<512)
        command_array[11] = coefficients[1]>>0
        command_array[12] = coefficients[1]>>8
        # assert: (x<512)
        command_array[13] = coefficients[2]>>0
        command_array[14] = coefficients[2]>>8
        # assert: (x<512)
        command_array[15] = coefficients[3]>>0
        command_array[16] = coefficients[3]>>8
        # assert: (x<512)
        command_array[17] = coefficients[4]>>0
        command_array[18] = coefficients[4]>>8
        # assert: (x<512)
        command_array[19] = coefficients[5]>>0
        command_array[20] = coefficients[5]>>8
        # assert: (x<512)
        command_array[21] = coefficients[6]>>0
        command_array[22] = coefficients[6]>>8
        # assert: (x<512)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetLineEgressLowSrFilterCoefficients)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineEgressLowSrFilterCoefficients (self, lane):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x11D
        header.Tag = 0
        header.MaxResponse = 20
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'coefficients' : [                          (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8)),
                          (response[6] & 0xFF)|((response[7]<<8) & (0xFF<<8)),
                          (response[8] & 0xFF)|((response[9]<<8) & (0xFF<<8)),
                          (response[10] & 0xFF)|((response[11]<<8) & (0xFF<<8)),
                          (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8)),
                          (response[14] & 0xFF)|((response[15]<<8) & (0xFF<<8)),
                          (response[16] & 0xFF)|((response[17]<<8) & (0xFF<<8)),
                          ],
        }
        self.check_response(apiResponse, CanopusApi.GetLineEgressLowSrFilterCoefficients)
        self.add_api_exec_cb()
        return apiResponse

    def SetLineEgressLowSrLaneSkew (self, lane, skew, reserved):
        #Default header
        header=ArgHeader()
        header.Length = 16
        header.Command = 0x120
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*16
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = skew>>0
        command_array[10] = skew>>8
        # assert: (x>=-2560 && x<=2560)
        command_array[11] = reserved>>0
        command_array[12] = reserved>>8

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetLineEgressLowSrLaneSkew)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineEgressLowSrLaneSkew (self, lane):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x121
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'skew' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8)),
             'reserved' : (response[6] & 0xFF)|((response[7]<<8) & (0xFF<<8)),
        }
        self.check_response(apiResponse, CanopusApi.GetLineEgressLowSrLaneSkew)
        self.add_api_exec_cb()
        return apiResponse

    def SetLineEgressHighSrFilterCoefficients (self, lane, coefficients):
        #Default header
        header=ArgHeader()
        header.Length = 72
        header.Command = 0x11A
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*72
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = coefficients[0]>>0
        command_array[10] = coefficients[1]>>0
        command_array[11] = coefficients[2]>>0
        command_array[12] = coefficients[3]>>0
        command_array[13] = coefficients[4]>>0
        command_array[14] = coefficients[5]>>0
        command_array[15] = coefficients[6]>>0
        command_array[16] = coefficients[7]>>0
        command_array[17] = coefficients[8]>>0
        command_array[18] = coefficients[9]>>0
        command_array[19] = coefficients[10]>>0
        command_array[20] = coefficients[11]>>0
        command_array[21] = coefficients[12]>>0
        command_array[22] = coefficients[13]>>0
        command_array[23] = coefficients[14]>>0
        command_array[24] = coefficients[15]>>0
        command_array[25] = coefficients[16]>>0
        command_array[26] = coefficients[17]>>0
        command_array[27] = coefficients[18]>>0
        command_array[28] = coefficients[19]>>0
        command_array[29] = coefficients[20]>>0
        command_array[30] = coefficients[21]>>0
        command_array[31] = coefficients[22]>>0
        command_array[32] = coefficients[23]>>0
        command_array[33] = coefficients[24]>>0
        command_array[34] = coefficients[25]>>0
        command_array[35] = coefficients[26]>>0
        command_array[36] = coefficients[27]>>0
        command_array[37] = coefficients[28]>>0
        command_array[38] = coefficients[29]>>0
        command_array[39] = coefficients[30]>>0
        command_array[40] = coefficients[31]>>0
        command_array[41] = coefficients[32]>>0
        command_array[42] = coefficients[33]>>0
        command_array[43] = coefficients[34]>>0
        command_array[44] = coefficients[35]>>0
        command_array[45] = coefficients[36]>>0
        command_array[46] = coefficients[37]>>0
        command_array[47] = coefficients[38]>>0
        command_array[48] = coefficients[39]>>0
        command_array[49] = coefficients[40]>>0
        command_array[50] = coefficients[41]>>0
        command_array[51] = coefficients[42]>>0
        command_array[52] = coefficients[43]>>0
        command_array[53] = coefficients[44]>>0
        command_array[54] = coefficients[45]>>0
        command_array[55] = coefficients[46]>>0
        command_array[56] = coefficients[47]>>0
        command_array[57] = coefficients[48]>>0
        command_array[58] = coefficients[49]>>0
        command_array[59] = coefficients[50]>>0
        command_array[60] = coefficients[51]>>0
        command_array[61] = coefficients[52]>>0
        command_array[62] = coefficients[53]>>0
        command_array[63] = coefficients[54]>>0
        command_array[64] = coefficients[55]>>0
        command_array[65] = coefficients[56]>>0
        command_array[66] = coefficients[57]>>0
        command_array[67] = coefficients[58]>>0
        command_array[68] = coefficients[59]>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetLineEgressHighSrFilterCoefficients)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineEgressHighSrFilterCoefficients (self, lane):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x11B
        header.Tag = 0
        header.MaxResponse = 64
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'coefficients' : [                          (response[4] & 0xFF),
                          (response[5] & 0xFF),
                          (response[6] & 0xFF),
                          (response[7] & 0xFF),
                          (response[8] & 0xFF),
                          (response[9] & 0xFF),
                          (response[10] & 0xFF),
                          (response[11] & 0xFF),
                          (response[12] & 0xFF),
                          (response[13] & 0xFF),
                          (response[14] & 0xFF),
                          (response[15] & 0xFF),
                          (response[16] & 0xFF),
                          (response[17] & 0xFF),
                          (response[18] & 0xFF),
                          (response[19] & 0xFF),
                          (response[20] & 0xFF),
                          (response[21] & 0xFF),
                          (response[22] & 0xFF),
                          (response[23] & 0xFF),
                          (response[24] & 0xFF),
                          (response[25] & 0xFF),
                          (response[26] & 0xFF),
                          (response[27] & 0xFF),
                          (response[28] & 0xFF),
                          (response[29] & 0xFF),
                          (response[30] & 0xFF),
                          (response[31] & 0xFF),
                          (response[32] & 0xFF),
                          (response[33] & 0xFF),
                          (response[34] & 0xFF),
                          (response[35] & 0xFF),
                          (response[36] & 0xFF),
                          (response[37] & 0xFF),
                          (response[38] & 0xFF),
                          (response[39] & 0xFF),
                          (response[40] & 0xFF),
                          (response[41] & 0xFF),
                          (response[42] & 0xFF),
                          (response[43] & 0xFF),
                          (response[44] & 0xFF),
                          (response[45] & 0xFF),
                          (response[46] & 0xFF),
                          (response[47] & 0xFF),
                          (response[48] & 0xFF),
                          (response[49] & 0xFF),
                          (response[50] & 0xFF),
                          (response[51] & 0xFF),
                          (response[52] & 0xFF),
                          (response[53] & 0xFF),
                          (response[54] & 0xFF),
                          (response[55] & 0xFF),
                          (response[56] & 0xFF),
                          (response[57] & 0xFF),
                          (response[58] & 0xFF),
                          (response[59] & 0xFF),
                          (response[60] & 0xFF),
                          (response[61] & 0xFF),
                          (response[62] & 0xFF),
                          (response[63] & 0xFF),
                          ],
        }
        self.check_response(apiResponse, CanopusApi.GetLineEgressHighSrFilterCoefficients)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineEgressHighSrLaneSkew (self, lane):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x11F
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'skew' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8)),
        }
        self.check_response(apiResponse, CanopusApi.GetLineEgressHighSrLaneSkew)
        self.add_api_exec_cb()
        return apiResponse

    def SetLineEgressHighSrLaneSkew (self, lane, skew):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x11E
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = skew>>0
        command_array[10] = skew>>8
        # assert: (x >=-960 && x <= 960)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetLineEgressHighSrLaneSkew)
        self.add_api_exec_cb()
        return apiResponse

    def SetLineEgressHighSrPulseShaping (self, lane, roll_off_factor, pulse_shaping_filter):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x122
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = roll_off_factor>>0
        # assert: (x >= 1 && x <= 5)
        command_array[10] = pulse_shaping_filter>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetLineEgressHighSrPulseShaping)
        self.add_api_exec_cb()
        return apiResponse

    def SetLineEgressHighSrPreEmphasis (self, lane, coefficients, enable):
        #Default header
        header=ArgHeader()
        header.Length = 72
        header.Command = 0x124
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*72
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = coefficients[0]>>0
        command_array[10] = coefficients[1]>>0
        command_array[11] = coefficients[2]>>0
        command_array[12] = coefficients[3]>>0
        command_array[13] = coefficients[4]>>0
        command_array[14] = coefficients[5]>>0
        command_array[15] = coefficients[6]>>0
        command_array[16] = coefficients[7]>>0
        command_array[17] = coefficients[8]>>0
        command_array[18] = coefficients[9]>>0
        command_array[19] = coefficients[10]>>0
        command_array[20] = coefficients[11]>>0
        command_array[21] = coefficients[12]>>0
        command_array[22] = coefficients[13]>>0
        command_array[23] = coefficients[14]>>0
        command_array[24] = coefficients[15]>>0
        command_array[25] = coefficients[16]>>0
        command_array[26] = coefficients[17]>>0
        command_array[27] = coefficients[18]>>0
        command_array[28] = coefficients[19]>>0
        command_array[29] = coefficients[20]>>0
        command_array[30] = coefficients[21]>>0
        command_array[31] = coefficients[22]>>0
        command_array[32] = coefficients[23]>>0
        command_array[33] = coefficients[24]>>0
        command_array[34] = coefficients[25]>>0
        command_array[35] = coefficients[26]>>0
        command_array[36] = coefficients[27]>>0
        command_array[37] = coefficients[28]>>0
        command_array[38] = coefficients[29]>>0
        command_array[39] = coefficients[30]>>0
        command_array[40] = coefficients[31]>>0
        command_array[41] = coefficients[32]>>0
        command_array[42] = coefficients[33]>>0
        command_array[43] = coefficients[34]>>0
        command_array[44] = coefficients[35]>>0
        command_array[45] = coefficients[36]>>0
        command_array[46] = coefficients[37]>>0
        command_array[47] = coefficients[38]>>0
        command_array[48] = coefficients[39]>>0
        command_array[49] = coefficients[40]>>0
        command_array[50] = coefficients[41]>>0
        command_array[51] = coefficients[42]>>0
        command_array[52] = coefficients[43]>>0
        command_array[53] = coefficients[44]>>0
        command_array[54] = coefficients[45]>>0
        command_array[55] = coefficients[46]>>0
        command_array[56] = coefficients[47]>>0
        command_array[57] = coefficients[48]>>0
        command_array[58] = coefficients[49]>>0
        command_array[59] = coefficients[50]>>0
        command_array[60] = coefficients[51]>>0
        command_array[61] = coefficients[52]>>0
        command_array[62] = coefficients[53]>>0
        command_array[63] = coefficients[54]>>0
        command_array[64] = coefficients[55]>>0
        command_array[65] = coefficients[56]>>0
        command_array[66] = coefficients[57]>>0
        command_array[67] = coefficients[58]>>0
        command_array[68] = coefficients[59]>>0
        command_array[69] = enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetLineEgressHighSrPreEmphasis)
        self.add_api_exec_cb()
        return apiResponse

    def SetLineEgressHighSrLaneAmplitude (self, lane, amplitude):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x126
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = amplitude>>0
        command_array[10] = amplitude>>8

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetLineEgressHighSrLaneAmplitude)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineEgressHighSrLaneAmplitude (self, lane):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x127
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'amplitude' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8)),
        }
        self.check_response(apiResponse, CanopusApi.GetLineEgressHighSrLaneAmplitude)
        self.add_api_exec_cb()
        return apiResponse

    def SetLineEgressLaneReassignment (self, lane_0, lane_1, lane_2, lane_3):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x118
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane_0>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = lane_1>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = lane_2>>0
        # assert: (x >= 0 && x <= 3)
        command_array[11] = lane_3>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetLineEgressLaneReassignment)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineEgressLaneReassignment (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x119
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'lane_0' : (response[4] & 0xFF),
             'lane_1' : (response[5] & 0xFF),
             'lane_2' : (response[6] & 0xFF),
             'lane_3' : (response[7] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetLineEgressLaneReassignment)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineEgressHighSrPulseShaping (self, lane):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x123
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'roll_off_factor' : (response[4] & 0xFF),
             'pulse_shaping_filter' : (response[5] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetLineEgressHighSrPulseShaping)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineEgressHighSrPreEmphasis (self, lane):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x125
        header.Tag = 0
        header.MaxResponse = 68
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'coefficients' : [                          (response[4] & 0xFF),
                          (response[5] & 0xFF),
                          (response[6] & 0xFF),
                          (response[7] & 0xFF),
                          (response[8] & 0xFF),
                          (response[9] & 0xFF),
                          (response[10] & 0xFF),
                          (response[11] & 0xFF),
                          (response[12] & 0xFF),
                          (response[13] & 0xFF),
                          (response[14] & 0xFF),
                          (response[15] & 0xFF),
                          (response[16] & 0xFF),
                          (response[17] & 0xFF),
                          (response[18] & 0xFF),
                          (response[19] & 0xFF),
                          (response[20] & 0xFF),
                          (response[21] & 0xFF),
                          (response[22] & 0xFF),
                          (response[23] & 0xFF),
                          (response[24] & 0xFF),
                          (response[25] & 0xFF),
                          (response[26] & 0xFF),
                          (response[27] & 0xFF),
                          (response[28] & 0xFF),
                          (response[29] & 0xFF),
                          (response[30] & 0xFF),
                          (response[31] & 0xFF),
                          (response[32] & 0xFF),
                          (response[33] & 0xFF),
                          (response[34] & 0xFF),
                          (response[35] & 0xFF),
                          (response[36] & 0xFF),
                          (response[37] & 0xFF),
                          (response[38] & 0xFF),
                          (response[39] & 0xFF),
                          (response[40] & 0xFF),
                          (response[41] & 0xFF),
                          (response[42] & 0xFF),
                          (response[43] & 0xFF),
                          (response[44] & 0xFF),
                          (response[45] & 0xFF),
                          (response[46] & 0xFF),
                          (response[47] & 0xFF),
                          (response[48] & 0xFF),
                          (response[49] & 0xFF),
                          (response[50] & 0xFF),
                          (response[51] & 0xFF),
                          (response[52] & 0xFF),
                          (response[53] & 0xFF),
                          (response[54] & 0xFF),
                          (response[55] & 0xFF),
                          (response[56] & 0xFF),
                          (response[57] & 0xFF),
                          (response[58] & 0xFF),
                          (response[59] & 0xFF),
                          (response[60] & 0xFF),
                          (response[61] & 0xFF),
                          (response[62] & 0xFF),
                          (response[63] & 0xFF),
                          ],
             'enable' : (response[64] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetLineEgressHighSrPreEmphasis)
        self.add_api_exec_cb()
        return apiResponse

    def SetLineEgressLaneMute (self, lane, mute):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x12C
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = mute>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetLineEgressLaneMute)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineEgressLaneMute (self, lane):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x12D
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'mute' : (response[4] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetLineEgressLaneMute)
        self.add_api_exec_cb()
        return apiResponse

    def SetLineEgressLanePolarity (self, lane, polarity):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x116
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = polarity>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetLineEgressLanePolarity)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineEgressLanePolarity (self, lane):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x117
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'polarity' : (response[4] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetLineEgressLanePolarity)
        self.add_api_exec_cb()
        return apiResponse

    def SetLineEgressHighSrFrequencyMaskBoost (self, lane, frequency_bin, gain, frequency_mask_width):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x20F
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = frequency_bin>>0
        # assert: (x<=30)
        command_array[10] = gain>>0
        command_array[11] = frequency_mask_width>>0
        # assert: (x >= 0 && x <= 5)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetLineEgressHighSrFrequencyMaskBoost)
        self.add_api_exec_cb()
        return apiResponse

    def SetLineEgressLaneAnalogAttenuation (self, lane, attenuation):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x224
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = attenuation>>0
        # assert: (x >= 0 && x <= 4)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetLineEgressLaneAnalogAttenuation)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineSymbolRate (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x23C
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'line_ingress_symbol_rate' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8)),
             'line_egress_symbol_rate' : (response[6] & 0xFF)|((response[7]<<8) & (0xFF<<8)),
        }
        self.check_response(apiResponse, CanopusApi.GetLineSymbolRate)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineIngressDspStatus (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x13F
        header.Tag = 0
        header.MaxResponse = 28
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'amplitude_hi' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8)),
             'amplitude_hq' : (response[6] & 0xFF)|((response[7]<<8) & (0xFF<<8)),
             'amplitude_vi' : (response[8] & 0xFF)|((response[9]<<8) & (0xFF<<8)),
             'amplitude_vq' : (response[10] & 0xFF)|((response[11]<<8) & (0xFF<<8)),
             'mse_hi' : (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8)),
             'mse_hq' : (response[14] & 0xFF)|((response[15]<<8) & (0xFF<<8)),
             'mse_vi' : (response[16] & 0xFF)|((response[17]<<8) & (0xFF<<8)),
             'mse_vq' : (response[18] & 0xFF)|((response[19]<<8) & (0xFF<<8)),
             'cg_h' : (response[20] & 0xFF),
             'cg_v' : (response[21] & 0xFF),
             'evm_h' : (response[22] & 0xFF)|((response[23]<<8) & (0xFF<<8)),
             'evm_v' : (response[24] & 0xFF)|((response[25]<<8) & (0xFF<<8)),
        }
        self.check_response(apiResponse, CanopusApi.GetLineIngressDspStatus)
        self.add_api_exec_cb()
        return apiResponse

    def SetLineIngressCcrBypass (self, enable):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x132
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetLineIngressCcrBypass)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineIngressCcrBypass (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x133
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'enable' : (response[4] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetLineIngressCcrBypass)
        self.add_api_exec_cb()
        return apiResponse

    def SetLineIngressSkew (self, polarization, skew_phase_i):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x12E
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = polarization>>0
        # assert: (x >= 0 && x <= 1)
        command_array[9] = skew_phase_i>>0
        command_array[10] = skew_phase_i>>8
        # assert: (x >= -320 && x <= 320)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetLineIngressSkew)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineIngressSkew (self, polarization):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x12F
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = polarization>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'skew_phase_i' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8)),
        }
        self.check_response(apiResponse, CanopusApi.GetLineIngressSkew)
        self.add_api_exec_cb()
        return apiResponse

    def SetLineIngressMatrixRotator (self, coefficients, mtr_mode, bypass):
        #Default header
        header=ArgHeader()
        header.Length = 28
        header.Command = 0x136
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*28
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = coefficients[0]>>0
        # assert: (x <= 0x3F)
        command_array[9] = coefficients[1]>>0
        # assert: (x <= 0x3F)
        command_array[10] = coefficients[2]>>0
        # assert: (x <= 0x3F)
        command_array[11] = coefficients[3]>>0
        # assert: (x <= 0x3F)
        command_array[12] = coefficients[4]>>0
        # assert: (x <= 0x3F)
        command_array[13] = coefficients[5]>>0
        # assert: (x <= 0x3F)
        command_array[14] = coefficients[6]>>0
        # assert: (x <= 0x3F)
        command_array[15] = coefficients[7]>>0
        # assert: (x <= 0x3F)
        command_array[16] = coefficients[8]>>0
        # assert: (x <= 0x3F)
        command_array[17] = coefficients[9]>>0
        # assert: (x <= 0x3F)
        command_array[18] = coefficients[10]>>0
        # assert: (x <= 0x3F)
        command_array[19] = coefficients[11]>>0
        # assert: (x <= 0x3F)
        command_array[20] = coefficients[12]>>0
        # assert: (x <= 0x3F)
        command_array[21] = coefficients[13]>>0
        # assert: (x <= 0x3F)
        command_array[22] = coefficients[14]>>0
        # assert: (x <= 0x3F)
        command_array[23] = coefficients[15]>>0
        # assert: (x <= 0x3F)
        command_array[24] = mtr_mode>>0
        # assert: (x >= 0 && x <= 1)
        command_array[25] = bypass>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetLineIngressMatrixRotator)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineIngressMatrixRotator (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x137
        header.Tag = 0
        header.MaxResponse = 24
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'coefficients' : [                          (response[4] & 0xFF),
                          (response[5] & 0xFF),
                          (response[6] & 0xFF),
                          (response[7] & 0xFF),
                          (response[8] & 0xFF),
                          (response[9] & 0xFF),
                          (response[10] & 0xFF),
                          (response[11] & 0xFF),
                          (response[12] & 0xFF),
                          (response[13] & 0xFF),
                          (response[14] & 0xFF),
                          (response[15] & 0xFF),
                          (response[16] & 0xFF),
                          (response[17] & 0xFF),
                          (response[18] & 0xFF),
                          (response[19] & 0xFF),
                          ],
             'mtr_mode' : (response[20] & 0xFF),
             'bypass' : (response[21] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetLineIngressMatrixRotator)
        self.add_api_exec_cb()
        return apiResponse

    def SetLineIngressFleCdRange (self, min_cd, max_cd):
        #Default header
        header=ArgHeader()
        header.Length = 16
        header.Command = 0x138
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*16
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = min_cd>>0
        command_array[9] = min_cd>>8
        command_array[10] = min_cd>>16
        command_array[11] = min_cd>>24
        command_array[12] = max_cd>>0
        command_array[13] = max_cd>>8
        command_array[14] = max_cd>>16
        command_array[15] = max_cd>>24

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetLineIngressFleCdRange)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineIngressBcdFilter (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x131
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'roll_off_factor' : (response[4] & 0xFF),
             'pulse_shaping_filter' : (response[5] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetLineIngressBcdFilter)
        self.add_api_exec_cb()
        return apiResponse

    def SetLineIngressBcdFilter (self, roll_off_factor, pulse_shaping_filter):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x130
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = roll_off_factor>>0
        # assert: (x >= 1 && x <= 5)
        command_array[9] = pulse_shaping_filter>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetLineIngressBcdFilter)
        self.add_api_exec_cb()
        return apiResponse

    def SetLineIngressBps (self, window_h, window_v, bypass):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x134
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = window_h>>0
        # assert: (x>= 1 && x<126)
        command_array[9] = window_v>>0
        # assert: (x>= 1 && x<126)
        command_array[10] = bypass>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetLineIngressBps)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineIngressBps (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x135
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'window_h' : (response[4] & 0xFF),
             'window_v' : (response[5] & 0xFF),
             'bypass' : (response[6] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetLineIngressBps)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineIngressAgcStatus (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x13E
        header.Tag = 0
        header.MaxResponse = 20
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'amplitude_hi' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8)),
             'amplitude_hq' : (response[6] & 0xFF)|((response[7]<<8) & (0xFF<<8)),
             'amplitude_vi' : (response[8] & 0xFF)|((response[9]<<8) & (0xFF<<8)),
             'amplitude_vq' : (response[10] & 0xFF)|((response[11]<<8) & (0xFF<<8)),
             'gain_hi' : (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8)),
             'gain_hq' : (response[14] & 0xFF)|((response[15]<<8) & (0xFF<<8)),
             'gain_vi' : (response[16] & 0xFF)|((response[17]<<8) & (0xFF<<8)),
             'gain_vq' : (response[18] & 0xFF)|((response[19]<<8) & (0xFF<<8)),
        }
        self.check_response(apiResponse, CanopusApi.GetLineIngressAgcStatus)
        self.add_api_exec_cb()
        return apiResponse

    def SetLineIngressAgcConfig (self, lane, signal_reference, signal_gain, signal_max, signal_min, enable):
        #Default header
        header=ArgHeader()
        header.Length = 20
        header.Command = 0x13C
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*20
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = signal_reference>>0
        # assert: (x<128)
        command_array[10] = signal_gain>>0
        command_array[11] = signal_gain>>8
        # assert: (x<1024)
        command_array[12] = signal_max>>0
        command_array[13] = signal_max>>8
        # assert: (x<512)
        command_array[14] = signal_min>>0
        command_array[15] = signal_min>>8
        # assert: (x<512)
        command_array[16] = enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetLineIngressAgcConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineIngressAgcConfig (self, lane):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x13D
        header.Tag = 0
        header.MaxResponse = 12
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'signal_reference' : (response[4] & 0xFF),
             'signal_gain' : (response[5] & 0xFF)|((response[6]<<8) & (0xFF<<8)),
             'signal_max' : (response[7] & 0xFF)|((response[8]<<8) & (0xFF<<8)),
             'signal_min' : (response[9] & 0xFF)|((response[10]<<8) & (0xFF<<8)),
             'enable' : (response[11] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetLineIngressAgcConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetLineIngressLosConfig (self, lane, signal_detect_dn, signal_detect_up, signal_detect_high, mode, enable):
        #Default header
        header=ArgHeader()
        header.Length = 16
        header.Command = 0x13A
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*16
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = signal_detect_dn>>0
        # assert: (x<128)
        command_array[10] = signal_detect_up>>0
        # assert: (x<128)
        command_array[11] = signal_detect_high>>0
        # assert: (x<128)
        command_array[12] = mode>>0
        # assert: (x >= 0 && x <= 1)
        command_array[13] = enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetLineIngressLosConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineIngressLosConfig (self, lane):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x13B
        header.Tag = 0
        header.MaxResponse = 12
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'signal_detect_dn' : (response[4] & 0xFF),
             'signal_detect_up' : (response[5] & 0xFF),
             'signal_detect_high' : (response[6] & 0xFF),
             'mode' : (response[7] & 0xFF),
             'enable' : (response[8] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetLineIngressLosConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineIngressFleCdRange (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x139
        header.Tag = 0
        header.MaxResponse = 12
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'min_cd' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24)),
             'max_cd' : (response[8] & 0xFF)|((response[9]<<8) & (0xFF<<8))|((response[10]<<16) & (0xFF<<16))|((response[11]<<24) & (0xFF<<24)),
        }
        self.check_response(apiResponse, CanopusApi.GetLineIngressFleCdRange)
        self.add_api_exec_cb()
        return apiResponse

    def GetHostEgressLanePolarity (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x10D
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'polarity' : (response[4] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetHostEgressLanePolarity)
        self.add_api_exec_cb()
        return apiResponse

    def SetHostEgressLanePolarity (self, polarity):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x10C
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = polarity>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetHostEgressLanePolarity)
        self.add_api_exec_cb()
        return apiResponse

    def GetHostHistogram (self, lane):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x210
        header.Tag = 0
        header.MaxResponse = 268
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 7)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'histogram' : [                          (response[4] & 0xFF),
                          (response[5] & 0xFF),
                          (response[6] & 0xFF),
                          (response[7] & 0xFF),
                          (response[8] & 0xFF),
                          (response[9] & 0xFF),
                          (response[10] & 0xFF),
                          (response[11] & 0xFF),
                          (response[12] & 0xFF),
                          (response[13] & 0xFF),
                          (response[14] & 0xFF),
                          (response[15] & 0xFF),
                          (response[16] & 0xFF),
                          (response[17] & 0xFF),
                          (response[18] & 0xFF),
                          (response[19] & 0xFF),
                          (response[20] & 0xFF),
                          (response[21] & 0xFF),
                          (response[22] & 0xFF),
                          (response[23] & 0xFF),
                          (response[24] & 0xFF),
                          (response[25] & 0xFF),
                          (response[26] & 0xFF),
                          (response[27] & 0xFF),
                          (response[28] & 0xFF),
                          (response[29] & 0xFF),
                          (response[30] & 0xFF),
                          (response[31] & 0xFF),
                          (response[32] & 0xFF),
                          (response[33] & 0xFF),
                          (response[34] & 0xFF),
                          (response[35] & 0xFF),
                          (response[36] & 0xFF),
                          (response[37] & 0xFF),
                          (response[38] & 0xFF),
                          (response[39] & 0xFF),
                          (response[40] & 0xFF),
                          (response[41] & 0xFF),
                          (response[42] & 0xFF),
                          (response[43] & 0xFF),
                          (response[44] & 0xFF),
                          (response[45] & 0xFF),
                          (response[46] & 0xFF),
                          (response[47] & 0xFF),
                          (response[48] & 0xFF),
                          (response[49] & 0xFF),
                          (response[50] & 0xFF),
                          (response[51] & 0xFF),
                          (response[52] & 0xFF),
                          (response[53] & 0xFF),
                          (response[54] & 0xFF),
                          (response[55] & 0xFF),
                          (response[56] & 0xFF),
                          (response[57] & 0xFF),
                          (response[58] & 0xFF),
                          (response[59] & 0xFF),
                          (response[60] & 0xFF),
                          (response[61] & 0xFF),
                          (response[62] & 0xFF),
                          (response[63] & 0xFF),
                          (response[64] & 0xFF),
                          (response[65] & 0xFF),
                          (response[66] & 0xFF),
                          (response[67] & 0xFF),
                          (response[68] & 0xFF),
                          (response[69] & 0xFF),
                          (response[70] & 0xFF),
                          (response[71] & 0xFF),
                          (response[72] & 0xFF),
                          (response[73] & 0xFF),
                          (response[74] & 0xFF),
                          (response[75] & 0xFF),
                          (response[76] & 0xFF),
                          (response[77] & 0xFF),
                          (response[78] & 0xFF),
                          (response[79] & 0xFF),
                          (response[80] & 0xFF),
                          (response[81] & 0xFF),
                          (response[82] & 0xFF),
                          (response[83] & 0xFF),
                          (response[84] & 0xFF),
                          (response[85] & 0xFF),
                          (response[86] & 0xFF),
                          (response[87] & 0xFF),
                          (response[88] & 0xFF),
                          (response[89] & 0xFF),
                          (response[90] & 0xFF),
                          (response[91] & 0xFF),
                          (response[92] & 0xFF),
                          (response[93] & 0xFF),
                          (response[94] & 0xFF),
                          (response[95] & 0xFF),
                          (response[96] & 0xFF),
                          (response[97] & 0xFF),
                          (response[98] & 0xFF),
                          (response[99] & 0xFF),
                          (response[100] & 0xFF),
                          (response[101] & 0xFF),
                          (response[102] & 0xFF),
                          (response[103] & 0xFF),
                          (response[104] & 0xFF),
                          (response[105] & 0xFF),
                          (response[106] & 0xFF),
                          (response[107] & 0xFF),
                          (response[108] & 0xFF),
                          (response[109] & 0xFF),
                          (response[110] & 0xFF),
                          (response[111] & 0xFF),
                          (response[112] & 0xFF),
                          (response[113] & 0xFF),
                          (response[114] & 0xFF),
                          (response[115] & 0xFF),
                          (response[116] & 0xFF),
                          (response[117] & 0xFF),
                          (response[118] & 0xFF),
                          (response[119] & 0xFF),
                          (response[120] & 0xFF),
                          (response[121] & 0xFF),
                          (response[122] & 0xFF),
                          (response[123] & 0xFF),
                          (response[124] & 0xFF),
                          (response[125] & 0xFF),
                          (response[126] & 0xFF),
                          (response[127] & 0xFF),
                          (response[128] & 0xFF),
                          (response[129] & 0xFF),
                          (response[130] & 0xFF),
                          (response[131] & 0xFF),
                          (response[132] & 0xFF),
                          (response[133] & 0xFF),
                          (response[134] & 0xFF),
                          (response[135] & 0xFF),
                          (response[136] & 0xFF),
                          (response[137] & 0xFF),
                          (response[138] & 0xFF),
                          (response[139] & 0xFF),
                          (response[140] & 0xFF),
                          (response[141] & 0xFF),
                          (response[142] & 0xFF),
                          (response[143] & 0xFF),
                          (response[144] & 0xFF),
                          (response[145] & 0xFF),
                          (response[146] & 0xFF),
                          (response[147] & 0xFF),
                          (response[148] & 0xFF),
                          (response[149] & 0xFF),
                          (response[150] & 0xFF),
                          (response[151] & 0xFF),
                          (response[152] & 0xFF),
                          (response[153] & 0xFF),
                          (response[154] & 0xFF),
                          (response[155] & 0xFF),
                          (response[156] & 0xFF),
                          (response[157] & 0xFF),
                          (response[158] & 0xFF),
                          (response[159] & 0xFF),
                          (response[160] & 0xFF),
                          (response[161] & 0xFF),
                          (response[162] & 0xFF),
                          (response[163] & 0xFF),
                          (response[164] & 0xFF),
                          (response[165] & 0xFF),
                          (response[166] & 0xFF),
                          (response[167] & 0xFF),
                          (response[168] & 0xFF),
                          (response[169] & 0xFF),
                          (response[170] & 0xFF),
                          (response[171] & 0xFF),
                          (response[172] & 0xFF),
                          (response[173] & 0xFF),
                          (response[174] & 0xFF),
                          (response[175] & 0xFF),
                          (response[176] & 0xFF),
                          (response[177] & 0xFF),
                          (response[178] & 0xFF),
                          (response[179] & 0xFF),
                          (response[180] & 0xFF),
                          (response[181] & 0xFF),
                          (response[182] & 0xFF),
                          (response[183] & 0xFF),
                          (response[184] & 0xFF),
                          (response[185] & 0xFF),
                          (response[186] & 0xFF),
                          (response[187] & 0xFF),
                          (response[188] & 0xFF),
                          (response[189] & 0xFF),
                          (response[190] & 0xFF),
                          (response[191] & 0xFF),
                          (response[192] & 0xFF),
                          (response[193] & 0xFF),
                          (response[194] & 0xFF),
                          (response[195] & 0xFF),
                          (response[196] & 0xFF),
                          (response[197] & 0xFF),
                          (response[198] & 0xFF),
                          (response[199] & 0xFF),
                          (response[200] & 0xFF),
                          (response[201] & 0xFF),
                          (response[202] & 0xFF),
                          (response[203] & 0xFF),
                          (response[204] & 0xFF),
                          (response[205] & 0xFF),
                          (response[206] & 0xFF),
                          (response[207] & 0xFF),
                          (response[208] & 0xFF),
                          (response[209] & 0xFF),
                          (response[210] & 0xFF),
                          (response[211] & 0xFF),
                          (response[212] & 0xFF),
                          (response[213] & 0xFF),
                          (response[214] & 0xFF),
                          (response[215] & 0xFF),
                          (response[216] & 0xFF),
                          (response[217] & 0xFF),
                          (response[218] & 0xFF),
                          (response[219] & 0xFF),
                          (response[220] & 0xFF),
                          (response[221] & 0xFF),
                          (response[222] & 0xFF),
                          (response[223] & 0xFF),
                          (response[224] & 0xFF),
                          (response[225] & 0xFF),
                          (response[226] & 0xFF),
                          (response[227] & 0xFF),
                          (response[228] & 0xFF),
                          (response[229] & 0xFF),
                          (response[230] & 0xFF),
                          (response[231] & 0xFF),
                          (response[232] & 0xFF),
                          (response[233] & 0xFF),
                          (response[234] & 0xFF),
                          (response[235] & 0xFF),
                          (response[236] & 0xFF),
                          (response[237] & 0xFF),
                          (response[238] & 0xFF),
                          (response[239] & 0xFF),
                          (response[240] & 0xFF),
                          (response[241] & 0xFF),
                          (response[242] & 0xFF),
                          (response[243] & 0xFF),
                          (response[244] & 0xFF),
                          (response[245] & 0xFF),
                          (response[246] & 0xFF),
                          (response[247] & 0xFF),
                          (response[248] & 0xFF),
                          (response[249] & 0xFF),
                          (response[250] & 0xFF),
                          (response[251] & 0xFF),
                          (response[252] & 0xFF),
                          (response[253] & 0xFF),
                          (response[254] & 0xFF),
                          (response[255] & 0xFF),
                          (response[256] & 0xFF),
                          (response[257] & 0xFF),
                          (response[258] & 0xFF),
                          (response[259] & 0xFF),
                          ],
             'slicer_levels' : [                          (response[260] & 0xFF)|((response[261]<<8) & (0xFF<<8)),
                          (response[262] & 0xFF)|((response[263]<<8) & (0xFF<<8)),
                          (response[264] & 0xFF)|((response[265]<<8) & (0xFF<<8)),
                          ],
        }
        self.check_response(apiResponse, CanopusApi.GetHostHistogram)
        self.add_api_exec_cb()
        return apiResponse

    def RelinkHostEgress (self, lane):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0xF6
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 7)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.RelinkHostEgress)
        self.add_api_exec_cb()
        return apiResponse

    def GetHostRxStatus (self, lane):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x222
        header.Tag = 0
        header.MaxResponse = 68
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 7)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'cstune' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8)),
             'rstune' : (response[6] & 0xFF)|((response[7]<<8) & (0xFF<<8)),
             'lfeq_peak' : (response[8] & 0xFF)|((response[9]<<8) & (0xFF<<8)),
             'lfeq_pole' : (response[10] & 0xFF)|((response[11]<<8) & (0xFF<<8)),
             'vga_gain1' : (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8)),
             'vga_gain2' : (response[14] & 0xFF)|((response[15]<<8) & (0xFF<<8)),
             'dfe_even_taps' : [                          (response[16] & 0xFF)|((response[17]<<8) & (0xFF<<8)),
                          (response[18] & 0xFF)|((response[19]<<8) & (0xFF<<8)),
                          (response[20] & 0xFF)|((response[21]<<8) & (0xFF<<8)),
                          (response[22] & 0xFF)|((response[23]<<8) & (0xFF<<8)),
                          (response[24] & 0xFF)|((response[25]<<8) & (0xFF<<8)),
                          (response[26] & 0xFF)|((response[27]<<8) & (0xFF<<8)),
                          (response[28] & 0xFF)|((response[29]<<8) & (0xFF<<8)),
                          (response[30] & 0xFF)|((response[31]<<8) & (0xFF<<8)),
                          (response[32] & 0xFF)|((response[33]<<8) & (0xFF<<8)),
                          (response[34] & 0xFF)|((response[35]<<8) & (0xFF<<8)),
                          ],
             'dfe_odd_taps' : [                          (response[36] & 0xFF)|((response[37]<<8) & (0xFF<<8)),
                          (response[38] & 0xFF)|((response[39]<<8) & (0xFF<<8)),
                          (response[40] & 0xFF)|((response[41]<<8) & (0xFF<<8)),
                          (response[42] & 0xFF)|((response[43]<<8) & (0xFF<<8)),
                          (response[44] & 0xFF)|((response[45]<<8) & (0xFF<<8)),
                          (response[46] & 0xFF)|((response[47]<<8) & (0xFF<<8)),
                          (response[48] & 0xFF)|((response[49]<<8) & (0xFF<<8)),
                          (response[50] & 0xFF)|((response[51]<<8) & (0xFF<<8)),
                          (response[52] & 0xFF)|((response[53]<<8) & (0xFF<<8)),
                          (response[54] & 0xFF)|((response[55]<<8) & (0xFF<<8)),
                          ],
             'term_att' : (response[56] & 0xFF)|((response[57]<<8) & (0xFF<<8)),
             'srx_14gdelay_in' : (response[58] & 0xFF)|((response[59]<<8) & (0xFF<<8)),
             'srx_14gdelay_ip' : (response[60] & 0xFF)|((response[61]<<8) & (0xFF<<8)),
             'srx_14gdelay_qn' : (response[62] & 0xFF)|((response[63]<<8) & (0xFF<<8)),
             'srx_14gdelay_qp' : (response[64] & 0xFF)|((response[65]<<8) & (0xFF<<8)),
             'rate' : (response[66] & 0xFF)|((response[67]<<8) & (0xFF<<8)),
        }
        self.check_response(apiResponse, CanopusApi.GetHostRxStatus)
        self.add_api_exec_cb()
        return apiResponse

    def GetHostEgressLaneStatus (self, lane):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0xF7
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 7)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'has_signal' : (response[4] & 0xFF),
             'is_clk_locked' : (response[5] & 0xFF),
             'agc_gain' : (response[6] & 0xFF)|((response[7]<<8) & (0xFF<<8)),
        }
        self.check_response(apiResponse, CanopusApi.GetHostEgressLaneStatus)
        self.add_api_exec_cb()
        return apiResponse

    def GetHostPulseResponse (self, lane):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x230
        header.Tag = 0
        header.MaxResponse = 80
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 7)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'rsp_val' : [                          (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24)),
                          (response[8] & 0xFF)|((response[9]<<8) & (0xFF<<8))|((response[10]<<16) & (0xFF<<16))|((response[11]<<24) & (0xFF<<24)),
                          (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8))|((response[14]<<16) & (0xFF<<16))|((response[15]<<24) & (0xFF<<24)),
                          (response[16] & 0xFF)|((response[17]<<8) & (0xFF<<8))|((response[18]<<16) & (0xFF<<16))|((response[19]<<24) & (0xFF<<24)),
                          (response[20] & 0xFF)|((response[21]<<8) & (0xFF<<8))|((response[22]<<16) & (0xFF<<16))|((response[23]<<24) & (0xFF<<24)),
                          (response[24] & 0xFF)|((response[25]<<8) & (0xFF<<8))|((response[26]<<16) & (0xFF<<16))|((response[27]<<24) & (0xFF<<24)),
                          (response[28] & 0xFF)|((response[29]<<8) & (0xFF<<8))|((response[30]<<16) & (0xFF<<16))|((response[31]<<24) & (0xFF<<24)),
                          (response[32] & 0xFF)|((response[33]<<8) & (0xFF<<8))|((response[34]<<16) & (0xFF<<16))|((response[35]<<24) & (0xFF<<24)),
                          (response[36] & 0xFF)|((response[37]<<8) & (0xFF<<8))|((response[38]<<16) & (0xFF<<16))|((response[39]<<24) & (0xFF<<24)),
                          (response[40] & 0xFF)|((response[41]<<8) & (0xFF<<8))|((response[42]<<16) & (0xFF<<16))|((response[43]<<24) & (0xFF<<24)),
                          (response[44] & 0xFF)|((response[45]<<8) & (0xFF<<8))|((response[46]<<16) & (0xFF<<16))|((response[47]<<24) & (0xFF<<24)),
                          (response[48] & 0xFF)|((response[49]<<8) & (0xFF<<8))|((response[50]<<16) & (0xFF<<16))|((response[51]<<24) & (0xFF<<24)),
                          (response[52] & 0xFF)|((response[53]<<8) & (0xFF<<8))|((response[54]<<16) & (0xFF<<16))|((response[55]<<24) & (0xFF<<24)),
                          (response[56] & 0xFF)|((response[57]<<8) & (0xFF<<8))|((response[58]<<16) & (0xFF<<16))|((response[59]<<24) & (0xFF<<24)),
                          (response[60] & 0xFF)|((response[61]<<8) & (0xFF<<8))|((response[62]<<16) & (0xFF<<16))|((response[63]<<24) & (0xFF<<24)),
                          (response[64] & 0xFF)|((response[65]<<8) & (0xFF<<8))|((response[66]<<16) & (0xFF<<16))|((response[67]<<24) & (0xFF<<24)),
                          (response[68] & 0xFF)|((response[69]<<8) & (0xFF<<8))|((response[70]<<16) & (0xFF<<16))|((response[71]<<24) & (0xFF<<24)),
                          (response[72] & 0xFF)|((response[73]<<8) & (0xFF<<8))|((response[74]<<16) & (0xFF<<16))|((response[75]<<24) & (0xFF<<24)),
                          (response[76] & 0xFF)|((response[77]<<8) & (0xFF<<8))|((response[78]<<16) & (0xFF<<16))|((response[79]<<24) & (0xFF<<24)),
                          ],
        }
        self.check_response(apiResponse, CanopusApi.GetHostPulseResponse)
        self.add_api_exec_cb()
        return apiResponse

    def GetHostIngressLanePolarity (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x111
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'polarity' : (response[4] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetHostIngressLanePolarity)
        self.add_api_exec_cb()
        return apiResponse

    def SetHostIngressLanePolarity (self, polarity):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x110
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = polarity>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetHostIngressLanePolarity)
        self.add_api_exec_cb()
        return apiResponse

    def SetHostIngressLaneMute (self, dual, mute):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x114
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = dual>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = mute>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetHostIngressLaneMute)
        self.add_api_exec_cb()
        return apiResponse

    def GetHostIngressLaneMute (self, dual):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x115
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = dual>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'mute' : (response[4] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetHostIngressLaneMute)
        self.add_api_exec_cb()
        return apiResponse

    def SetHostIngressFilterCoefficients (self, lane, coefficients, low_eye, high_eye):
        #Default header
        header=ArgHeader()
        header.Length = 20
        header.Command = 0x112
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*20
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 7)
        command_array[9] = coefficients[0]>>0
        command_array[10] = coefficients[0]>>8
        # assert: (x>-1000 && x<1000)
        command_array[11] = coefficients[1]>>0
        command_array[12] = coefficients[1]>>8
        # assert: (x>-1000 && x<1000)
        command_array[13] = coefficients[2]>>0
        command_array[14] = coefficients[2]>>8
        # assert: (x>-1000 && x<1000)
        command_array[15] = low_eye>>0
        command_array[16] = low_eye>>8
        # assert: (x>500   && x<1500)
        command_array[17] = high_eye>>0
        command_array[18] = high_eye>>8
        # assert: (x>1500  && x<2500)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetHostIngressFilterCoefficients)
        self.add_api_exec_cb()
        return apiResponse

    def GetHostIngressFilterCoefficients (self, lane):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x113
        header.Tag = 0
        header.MaxResponse = 16
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 7)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'coefficients' : [                          (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8)),
                          (response[6] & 0xFF)|((response[7]<<8) & (0xFF<<8)),
                          (response[8] & 0xFF)|((response[9]<<8) & (0xFF<<8)),
                          ],
             'low_eye' : (response[10] & 0xFF)|((response[11]<<8) & (0xFF<<8)),
             'high_eye' : (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8)),
        }
        self.check_response(apiResponse, CanopusApi.GetHostIngressFilterCoefficients)
        self.add_api_exec_cb()
        return apiResponse

    def SetOtnOhpSourcePt (self, channel, map_level, payload_type_value, payload_type_enable):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1A5
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = payload_type_value>>0
        command_array[11] = payload_type_enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOtnOhpSourcePt)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnOhpSourcePt (self, channel, map_level):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1A6
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'payload_type_value' : (response[4] & 0xFF),
             'payload_type_enable' : (response[5] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtnOhpSourcePt)
        self.add_api_exec_cb()
        return apiResponse

    def SetOtnOhpSinkDdegThreshold (self, channel, map_level, layer_level, degraded_threshold, accum_good_seconds, accum_bad_seconds):
        #Default header
        header=ArgHeader()
        header.Length = 20
        header.Command = 0x1B7
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*20
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = layer_level>>0
        # assert: (x >= 0 && x <= 7)
        command_array[11] = degraded_threshold>>0
        command_array[12] = degraded_threshold>>8
        command_array[13] = degraded_threshold>>16
        command_array[14] = degraded_threshold>>24
        command_array[15] = accum_good_seconds>>0
        command_array[16] = accum_bad_seconds>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOtnOhpSinkDdegThreshold)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnOhpSinkDdegThreshold (self, channel, map_level, layer_level):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1B8
        header.Tag = 0
        header.MaxResponse = 12
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = layer_level>>0
        # assert: (x >= 0 && x <= 7)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'degraded_threshold' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24)),
             'accum_good_seconds' : (response[8] & 0xFF),
             'accum_bad_seconds' : (response[9] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtnOhpSinkDdegThreshold)
        self.add_api_exec_cb()
        return apiResponse

    def SetOtnOhpSourceFtfl (self, channel, map_level, ftfl_value, ftfl_enable):
        #Default header
        header=ArgHeader()
        header.Length = 268
        header.Command = 0x1AB
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*268
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = ftfl_value[0]>>0
        command_array[11] = ftfl_value[1]>>0
        command_array[12] = ftfl_value[2]>>0
        command_array[13] = ftfl_value[3]>>0
        command_array[14] = ftfl_value[4]>>0
        command_array[15] = ftfl_value[5]>>0
        command_array[16] = ftfl_value[6]>>0
        command_array[17] = ftfl_value[7]>>0
        command_array[18] = ftfl_value[8]>>0
        command_array[19] = ftfl_value[9]>>0
        command_array[20] = ftfl_value[10]>>0
        command_array[21] = ftfl_value[11]>>0
        command_array[22] = ftfl_value[12]>>0
        command_array[23] = ftfl_value[13]>>0
        command_array[24] = ftfl_value[14]>>0
        command_array[25] = ftfl_value[15]>>0
        command_array[26] = ftfl_value[16]>>0
        command_array[27] = ftfl_value[17]>>0
        command_array[28] = ftfl_value[18]>>0
        command_array[29] = ftfl_value[19]>>0
        command_array[30] = ftfl_value[20]>>0
        command_array[31] = ftfl_value[21]>>0
        command_array[32] = ftfl_value[22]>>0
        command_array[33] = ftfl_value[23]>>0
        command_array[34] = ftfl_value[24]>>0
        command_array[35] = ftfl_value[25]>>0
        command_array[36] = ftfl_value[26]>>0
        command_array[37] = ftfl_value[27]>>0
        command_array[38] = ftfl_value[28]>>0
        command_array[39] = ftfl_value[29]>>0
        command_array[40] = ftfl_value[30]>>0
        command_array[41] = ftfl_value[31]>>0
        command_array[42] = ftfl_value[32]>>0
        command_array[43] = ftfl_value[33]>>0
        command_array[44] = ftfl_value[34]>>0
        command_array[45] = ftfl_value[35]>>0
        command_array[46] = ftfl_value[36]>>0
        command_array[47] = ftfl_value[37]>>0
        command_array[48] = ftfl_value[38]>>0
        command_array[49] = ftfl_value[39]>>0
        command_array[50] = ftfl_value[40]>>0
        command_array[51] = ftfl_value[41]>>0
        command_array[52] = ftfl_value[42]>>0
        command_array[53] = ftfl_value[43]>>0
        command_array[54] = ftfl_value[44]>>0
        command_array[55] = ftfl_value[45]>>0
        command_array[56] = ftfl_value[46]>>0
        command_array[57] = ftfl_value[47]>>0
        command_array[58] = ftfl_value[48]>>0
        command_array[59] = ftfl_value[49]>>0
        command_array[60] = ftfl_value[50]>>0
        command_array[61] = ftfl_value[51]>>0
        command_array[62] = ftfl_value[52]>>0
        command_array[63] = ftfl_value[53]>>0
        command_array[64] = ftfl_value[54]>>0
        command_array[65] = ftfl_value[55]>>0
        command_array[66] = ftfl_value[56]>>0
        command_array[67] = ftfl_value[57]>>0
        command_array[68] = ftfl_value[58]>>0
        command_array[69] = ftfl_value[59]>>0
        command_array[70] = ftfl_value[60]>>0
        command_array[71] = ftfl_value[61]>>0
        command_array[72] = ftfl_value[62]>>0
        command_array[73] = ftfl_value[63]>>0
        command_array[74] = ftfl_value[64]>>0
        command_array[75] = ftfl_value[65]>>0
        command_array[76] = ftfl_value[66]>>0
        command_array[77] = ftfl_value[67]>>0
        command_array[78] = ftfl_value[68]>>0
        command_array[79] = ftfl_value[69]>>0
        command_array[80] = ftfl_value[70]>>0
        command_array[81] = ftfl_value[71]>>0
        command_array[82] = ftfl_value[72]>>0
        command_array[83] = ftfl_value[73]>>0
        command_array[84] = ftfl_value[74]>>0
        command_array[85] = ftfl_value[75]>>0
        command_array[86] = ftfl_value[76]>>0
        command_array[87] = ftfl_value[77]>>0
        command_array[88] = ftfl_value[78]>>0
        command_array[89] = ftfl_value[79]>>0
        command_array[90] = ftfl_value[80]>>0
        command_array[91] = ftfl_value[81]>>0
        command_array[92] = ftfl_value[82]>>0
        command_array[93] = ftfl_value[83]>>0
        command_array[94] = ftfl_value[84]>>0
        command_array[95] = ftfl_value[85]>>0
        command_array[96] = ftfl_value[86]>>0
        command_array[97] = ftfl_value[87]>>0
        command_array[98] = ftfl_value[88]>>0
        command_array[99] = ftfl_value[89]>>0
        command_array[100] = ftfl_value[90]>>0
        command_array[101] = ftfl_value[91]>>0
        command_array[102] = ftfl_value[92]>>0
        command_array[103] = ftfl_value[93]>>0
        command_array[104] = ftfl_value[94]>>0
        command_array[105] = ftfl_value[95]>>0
        command_array[106] = ftfl_value[96]>>0
        command_array[107] = ftfl_value[97]>>0
        command_array[108] = ftfl_value[98]>>0
        command_array[109] = ftfl_value[99]>>0
        command_array[110] = ftfl_value[100]>>0
        command_array[111] = ftfl_value[101]>>0
        command_array[112] = ftfl_value[102]>>0
        command_array[113] = ftfl_value[103]>>0
        command_array[114] = ftfl_value[104]>>0
        command_array[115] = ftfl_value[105]>>0
        command_array[116] = ftfl_value[106]>>0
        command_array[117] = ftfl_value[107]>>0
        command_array[118] = ftfl_value[108]>>0
        command_array[119] = ftfl_value[109]>>0
        command_array[120] = ftfl_value[110]>>0
        command_array[121] = ftfl_value[111]>>0
        command_array[122] = ftfl_value[112]>>0
        command_array[123] = ftfl_value[113]>>0
        command_array[124] = ftfl_value[114]>>0
        command_array[125] = ftfl_value[115]>>0
        command_array[126] = ftfl_value[116]>>0
        command_array[127] = ftfl_value[117]>>0
        command_array[128] = ftfl_value[118]>>0
        command_array[129] = ftfl_value[119]>>0
        command_array[130] = ftfl_value[120]>>0
        command_array[131] = ftfl_value[121]>>0
        command_array[132] = ftfl_value[122]>>0
        command_array[133] = ftfl_value[123]>>0
        command_array[134] = ftfl_value[124]>>0
        command_array[135] = ftfl_value[125]>>0
        command_array[136] = ftfl_value[126]>>0
        command_array[137] = ftfl_value[127]>>0
        command_array[138] = ftfl_value[128]>>0
        command_array[139] = ftfl_value[129]>>0
        command_array[140] = ftfl_value[130]>>0
        command_array[141] = ftfl_value[131]>>0
        command_array[142] = ftfl_value[132]>>0
        command_array[143] = ftfl_value[133]>>0
        command_array[144] = ftfl_value[134]>>0
        command_array[145] = ftfl_value[135]>>0
        command_array[146] = ftfl_value[136]>>0
        command_array[147] = ftfl_value[137]>>0
        command_array[148] = ftfl_value[138]>>0
        command_array[149] = ftfl_value[139]>>0
        command_array[150] = ftfl_value[140]>>0
        command_array[151] = ftfl_value[141]>>0
        command_array[152] = ftfl_value[142]>>0
        command_array[153] = ftfl_value[143]>>0
        command_array[154] = ftfl_value[144]>>0
        command_array[155] = ftfl_value[145]>>0
        command_array[156] = ftfl_value[146]>>0
        command_array[157] = ftfl_value[147]>>0
        command_array[158] = ftfl_value[148]>>0
        command_array[159] = ftfl_value[149]>>0
        command_array[160] = ftfl_value[150]>>0
        command_array[161] = ftfl_value[151]>>0
        command_array[162] = ftfl_value[152]>>0
        command_array[163] = ftfl_value[153]>>0
        command_array[164] = ftfl_value[154]>>0
        command_array[165] = ftfl_value[155]>>0
        command_array[166] = ftfl_value[156]>>0
        command_array[167] = ftfl_value[157]>>0
        command_array[168] = ftfl_value[158]>>0
        command_array[169] = ftfl_value[159]>>0
        command_array[170] = ftfl_value[160]>>0
        command_array[171] = ftfl_value[161]>>0
        command_array[172] = ftfl_value[162]>>0
        command_array[173] = ftfl_value[163]>>0
        command_array[174] = ftfl_value[164]>>0
        command_array[175] = ftfl_value[165]>>0
        command_array[176] = ftfl_value[166]>>0
        command_array[177] = ftfl_value[167]>>0
        command_array[178] = ftfl_value[168]>>0
        command_array[179] = ftfl_value[169]>>0
        command_array[180] = ftfl_value[170]>>0
        command_array[181] = ftfl_value[171]>>0
        command_array[182] = ftfl_value[172]>>0
        command_array[183] = ftfl_value[173]>>0
        command_array[184] = ftfl_value[174]>>0
        command_array[185] = ftfl_value[175]>>0
        command_array[186] = ftfl_value[176]>>0
        command_array[187] = ftfl_value[177]>>0
        command_array[188] = ftfl_value[178]>>0
        command_array[189] = ftfl_value[179]>>0
        command_array[190] = ftfl_value[180]>>0
        command_array[191] = ftfl_value[181]>>0
        command_array[192] = ftfl_value[182]>>0
        command_array[193] = ftfl_value[183]>>0
        command_array[194] = ftfl_value[184]>>0
        command_array[195] = ftfl_value[185]>>0
        command_array[196] = ftfl_value[186]>>0
        command_array[197] = ftfl_value[187]>>0
        command_array[198] = ftfl_value[188]>>0
        command_array[199] = ftfl_value[189]>>0
        command_array[200] = ftfl_value[190]>>0
        command_array[201] = ftfl_value[191]>>0
        command_array[202] = ftfl_value[192]>>0
        command_array[203] = ftfl_value[193]>>0
        command_array[204] = ftfl_value[194]>>0
        command_array[205] = ftfl_value[195]>>0
        command_array[206] = ftfl_value[196]>>0
        command_array[207] = ftfl_value[197]>>0
        command_array[208] = ftfl_value[198]>>0
        command_array[209] = ftfl_value[199]>>0
        command_array[210] = ftfl_value[200]>>0
        command_array[211] = ftfl_value[201]>>0
        command_array[212] = ftfl_value[202]>>0
        command_array[213] = ftfl_value[203]>>0
        command_array[214] = ftfl_value[204]>>0
        command_array[215] = ftfl_value[205]>>0
        command_array[216] = ftfl_value[206]>>0
        command_array[217] = ftfl_value[207]>>0
        command_array[218] = ftfl_value[208]>>0
        command_array[219] = ftfl_value[209]>>0
        command_array[220] = ftfl_value[210]>>0
        command_array[221] = ftfl_value[211]>>0
        command_array[222] = ftfl_value[212]>>0
        command_array[223] = ftfl_value[213]>>0
        command_array[224] = ftfl_value[214]>>0
        command_array[225] = ftfl_value[215]>>0
        command_array[226] = ftfl_value[216]>>0
        command_array[227] = ftfl_value[217]>>0
        command_array[228] = ftfl_value[218]>>0
        command_array[229] = ftfl_value[219]>>0
        command_array[230] = ftfl_value[220]>>0
        command_array[231] = ftfl_value[221]>>0
        command_array[232] = ftfl_value[222]>>0
        command_array[233] = ftfl_value[223]>>0
        command_array[234] = ftfl_value[224]>>0
        command_array[235] = ftfl_value[225]>>0
        command_array[236] = ftfl_value[226]>>0
        command_array[237] = ftfl_value[227]>>0
        command_array[238] = ftfl_value[228]>>0
        command_array[239] = ftfl_value[229]>>0
        command_array[240] = ftfl_value[230]>>0
        command_array[241] = ftfl_value[231]>>0
        command_array[242] = ftfl_value[232]>>0
        command_array[243] = ftfl_value[233]>>0
        command_array[244] = ftfl_value[234]>>0
        command_array[245] = ftfl_value[235]>>0
        command_array[246] = ftfl_value[236]>>0
        command_array[247] = ftfl_value[237]>>0
        command_array[248] = ftfl_value[238]>>0
        command_array[249] = ftfl_value[239]>>0
        command_array[250] = ftfl_value[240]>>0
        command_array[251] = ftfl_value[241]>>0
        command_array[252] = ftfl_value[242]>>0
        command_array[253] = ftfl_value[243]>>0
        command_array[254] = ftfl_value[244]>>0
        command_array[255] = ftfl_value[245]>>0
        command_array[256] = ftfl_value[246]>>0
        command_array[257] = ftfl_value[247]>>0
        command_array[258] = ftfl_value[248]>>0
        command_array[259] = ftfl_value[249]>>0
        command_array[260] = ftfl_value[250]>>0
        command_array[261] = ftfl_value[251]>>0
        command_array[262] = ftfl_value[252]>>0
        command_array[263] = ftfl_value[253]>>0
        command_array[264] = ftfl_value[254]>>0
        command_array[265] = ftfl_value[255]>>0
        command_array[266] = ftfl_enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOtnOhpSourceFtfl)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnOhpSourceFtfl (self, channel, map_level):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1AC
        header.Tag = 0
        header.MaxResponse = 264
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'ftfl_value' : [                          (response[4] & 0xFF),
                          (response[5] & 0xFF),
                          (response[6] & 0xFF),
                          (response[7] & 0xFF),
                          (response[8] & 0xFF),
                          (response[9] & 0xFF),
                          (response[10] & 0xFF),
                          (response[11] & 0xFF),
                          (response[12] & 0xFF),
                          (response[13] & 0xFF),
                          (response[14] & 0xFF),
                          (response[15] & 0xFF),
                          (response[16] & 0xFF),
                          (response[17] & 0xFF),
                          (response[18] & 0xFF),
                          (response[19] & 0xFF),
                          (response[20] & 0xFF),
                          (response[21] & 0xFF),
                          (response[22] & 0xFF),
                          (response[23] & 0xFF),
                          (response[24] & 0xFF),
                          (response[25] & 0xFF),
                          (response[26] & 0xFF),
                          (response[27] & 0xFF),
                          (response[28] & 0xFF),
                          (response[29] & 0xFF),
                          (response[30] & 0xFF),
                          (response[31] & 0xFF),
                          (response[32] & 0xFF),
                          (response[33] & 0xFF),
                          (response[34] & 0xFF),
                          (response[35] & 0xFF),
                          (response[36] & 0xFF),
                          (response[37] & 0xFF),
                          (response[38] & 0xFF),
                          (response[39] & 0xFF),
                          (response[40] & 0xFF),
                          (response[41] & 0xFF),
                          (response[42] & 0xFF),
                          (response[43] & 0xFF),
                          (response[44] & 0xFF),
                          (response[45] & 0xFF),
                          (response[46] & 0xFF),
                          (response[47] & 0xFF),
                          (response[48] & 0xFF),
                          (response[49] & 0xFF),
                          (response[50] & 0xFF),
                          (response[51] & 0xFF),
                          (response[52] & 0xFF),
                          (response[53] & 0xFF),
                          (response[54] & 0xFF),
                          (response[55] & 0xFF),
                          (response[56] & 0xFF),
                          (response[57] & 0xFF),
                          (response[58] & 0xFF),
                          (response[59] & 0xFF),
                          (response[60] & 0xFF),
                          (response[61] & 0xFF),
                          (response[62] & 0xFF),
                          (response[63] & 0xFF),
                          (response[64] & 0xFF),
                          (response[65] & 0xFF),
                          (response[66] & 0xFF),
                          (response[67] & 0xFF),
                          (response[68] & 0xFF),
                          (response[69] & 0xFF),
                          (response[70] & 0xFF),
                          (response[71] & 0xFF),
                          (response[72] & 0xFF),
                          (response[73] & 0xFF),
                          (response[74] & 0xFF),
                          (response[75] & 0xFF),
                          (response[76] & 0xFF),
                          (response[77] & 0xFF),
                          (response[78] & 0xFF),
                          (response[79] & 0xFF),
                          (response[80] & 0xFF),
                          (response[81] & 0xFF),
                          (response[82] & 0xFF),
                          (response[83] & 0xFF),
                          (response[84] & 0xFF),
                          (response[85] & 0xFF),
                          (response[86] & 0xFF),
                          (response[87] & 0xFF),
                          (response[88] & 0xFF),
                          (response[89] & 0xFF),
                          (response[90] & 0xFF),
                          (response[91] & 0xFF),
                          (response[92] & 0xFF),
                          (response[93] & 0xFF),
                          (response[94] & 0xFF),
                          (response[95] & 0xFF),
                          (response[96] & 0xFF),
                          (response[97] & 0xFF),
                          (response[98] & 0xFF),
                          (response[99] & 0xFF),
                          (response[100] & 0xFF),
                          (response[101] & 0xFF),
                          (response[102] & 0xFF),
                          (response[103] & 0xFF),
                          (response[104] & 0xFF),
                          (response[105] & 0xFF),
                          (response[106] & 0xFF),
                          (response[107] & 0xFF),
                          (response[108] & 0xFF),
                          (response[109] & 0xFF),
                          (response[110] & 0xFF),
                          (response[111] & 0xFF),
                          (response[112] & 0xFF),
                          (response[113] & 0xFF),
                          (response[114] & 0xFF),
                          (response[115] & 0xFF),
                          (response[116] & 0xFF),
                          (response[117] & 0xFF),
                          (response[118] & 0xFF),
                          (response[119] & 0xFF),
                          (response[120] & 0xFF),
                          (response[121] & 0xFF),
                          (response[122] & 0xFF),
                          (response[123] & 0xFF),
                          (response[124] & 0xFF),
                          (response[125] & 0xFF),
                          (response[126] & 0xFF),
                          (response[127] & 0xFF),
                          (response[128] & 0xFF),
                          (response[129] & 0xFF),
                          (response[130] & 0xFF),
                          (response[131] & 0xFF),
                          (response[132] & 0xFF),
                          (response[133] & 0xFF),
                          (response[134] & 0xFF),
                          (response[135] & 0xFF),
                          (response[136] & 0xFF),
                          (response[137] & 0xFF),
                          (response[138] & 0xFF),
                          (response[139] & 0xFF),
                          (response[140] & 0xFF),
                          (response[141] & 0xFF),
                          (response[142] & 0xFF),
                          (response[143] & 0xFF),
                          (response[144] & 0xFF),
                          (response[145] & 0xFF),
                          (response[146] & 0xFF),
                          (response[147] & 0xFF),
                          (response[148] & 0xFF),
                          (response[149] & 0xFF),
                          (response[150] & 0xFF),
                          (response[151] & 0xFF),
                          (response[152] & 0xFF),
                          (response[153] & 0xFF),
                          (response[154] & 0xFF),
                          (response[155] & 0xFF),
                          (response[156] & 0xFF),
                          (response[157] & 0xFF),
                          (response[158] & 0xFF),
                          (response[159] & 0xFF),
                          (response[160] & 0xFF),
                          (response[161] & 0xFF),
                          (response[162] & 0xFF),
                          (response[163] & 0xFF),
                          (response[164] & 0xFF),
                          (response[165] & 0xFF),
                          (response[166] & 0xFF),
                          (response[167] & 0xFF),
                          (response[168] & 0xFF),
                          (response[169] & 0xFF),
                          (response[170] & 0xFF),
                          (response[171] & 0xFF),
                          (response[172] & 0xFF),
                          (response[173] & 0xFF),
                          (response[174] & 0xFF),
                          (response[175] & 0xFF),
                          (response[176] & 0xFF),
                          (response[177] & 0xFF),
                          (response[178] & 0xFF),
                          (response[179] & 0xFF),
                          (response[180] & 0xFF),
                          (response[181] & 0xFF),
                          (response[182] & 0xFF),
                          (response[183] & 0xFF),
                          (response[184] & 0xFF),
                          (response[185] & 0xFF),
                          (response[186] & 0xFF),
                          (response[187] & 0xFF),
                          (response[188] & 0xFF),
                          (response[189] & 0xFF),
                          (response[190] & 0xFF),
                          (response[191] & 0xFF),
                          (response[192] & 0xFF),
                          (response[193] & 0xFF),
                          (response[194] & 0xFF),
                          (response[195] & 0xFF),
                          (response[196] & 0xFF),
                          (response[197] & 0xFF),
                          (response[198] & 0xFF),
                          (response[199] & 0xFF),
                          (response[200] & 0xFF),
                          (response[201] & 0xFF),
                          (response[202] & 0xFF),
                          (response[203] & 0xFF),
                          (response[204] & 0xFF),
                          (response[205] & 0xFF),
                          (response[206] & 0xFF),
                          (response[207] & 0xFF),
                          (response[208] & 0xFF),
                          (response[209] & 0xFF),
                          (response[210] & 0xFF),
                          (response[211] & 0xFF),
                          (response[212] & 0xFF),
                          (response[213] & 0xFF),
                          (response[214] & 0xFF),
                          (response[215] & 0xFF),
                          (response[216] & 0xFF),
                          (response[217] & 0xFF),
                          (response[218] & 0xFF),
                          (response[219] & 0xFF),
                          (response[220] & 0xFF),
                          (response[221] & 0xFF),
                          (response[222] & 0xFF),
                          (response[223] & 0xFF),
                          (response[224] & 0xFF),
                          (response[225] & 0xFF),
                          (response[226] & 0xFF),
                          (response[227] & 0xFF),
                          (response[228] & 0xFF),
                          (response[229] & 0xFF),
                          (response[230] & 0xFF),
                          (response[231] & 0xFF),
                          (response[232] & 0xFF),
                          (response[233] & 0xFF),
                          (response[234] & 0xFF),
                          (response[235] & 0xFF),
                          (response[236] & 0xFF),
                          (response[237] & 0xFF),
                          (response[238] & 0xFF),
                          (response[239] & 0xFF),
                          (response[240] & 0xFF),
                          (response[241] & 0xFF),
                          (response[242] & 0xFF),
                          (response[243] & 0xFF),
                          (response[244] & 0xFF),
                          (response[245] & 0xFF),
                          (response[246] & 0xFF),
                          (response[247] & 0xFF),
                          (response[248] & 0xFF),
                          (response[249] & 0xFF),
                          (response[250] & 0xFF),
                          (response[251] & 0xFF),
                          (response[252] & 0xFF),
                          (response[253] & 0xFF),
                          (response[254] & 0xFF),
                          (response[255] & 0xFF),
                          (response[256] & 0xFF),
                          (response[257] & 0xFF),
                          (response[258] & 0xFF),
                          (response[259] & 0xFF),
                          ],
             'ftfl_enable' : (response[260] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtnOhpSourceFtfl)
        self.add_api_exec_cb()
        return apiResponse

    def SetOtnOhpLayerReorder (self, channel, map_level, layer_level_reorder_array):
        #Default header
        header=ArgHeader()
        header.Length = 20
        header.Command = 0x19D
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*20
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = layer_level_reorder_array[0]>>0
        # assert: (x >= 0 && x <= 7)
        command_array[11] = layer_level_reorder_array[1]>>0
        # assert: (x >= 0 && x <= 7)
        command_array[12] = layer_level_reorder_array[2]>>0
        # assert: (x >= 0 && x <= 7)
        command_array[13] = layer_level_reorder_array[3]>>0
        # assert: (x >= 0 && x <= 7)
        command_array[14] = layer_level_reorder_array[4]>>0
        # assert: (x >= 0 && x <= 7)
        command_array[15] = layer_level_reorder_array[5]>>0
        # assert: (x >= 0 && x <= 7)
        command_array[16] = layer_level_reorder_array[6]>>0
        # assert: (x >= 0 && x <= 7)
        command_array[17] = layer_level_reorder_array[7]>>0
        # assert: (x >= 0 && x <= 7)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOtnOhpLayerReorder)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnOhpLayerReorder (self, channel, map_level):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x19E
        header.Tag = 0
        header.MaxResponse = 12
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'layer_level_reorder_array' : [                          (response[4] & 0xFF),
                          (response[5] & 0xFF),
                          (response[6] & 0xFF),
                          (response[7] & 0xFF),
                          (response[8] & 0xFF),
                          (response[9] & 0xFF),
                          (response[10] & 0xFF),
                          (response[11] & 0xFF),
                          ],
        }
        self.check_response(apiResponse, CanopusApi.GetOtnOhpLayerReorder)
        self.add_api_exec_cb()
        return apiResponse

    def SetOtnOhpSinkMode (self, channel, map_level, layer_level, layer_mode, tim_action_enable, ltc_action_enable):
        #Default header
        header=ArgHeader()
        header.Length = 16
        header.Command = 0x1AD
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*16
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = layer_level>>0
        # assert: (x >= 0 && x <= 7)
        command_array[11] = layer_mode>>0
        # assert: (x >= 0 && x <= 1)
        command_array[12] = tim_action_enable>>0
        # assert: (x >= 0 && x <= 1)
        command_array[13] = ltc_action_enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOtnOhpSinkMode)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnOhpSinkMode (self, channel, map_level, layer_level):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1AE
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = layer_level>>0
        # assert: (x >= 0 && x <= 7)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'layer_mode' : (response[4] & 0xFF),
             'tim_action_enable' : (response[5] & 0xFF),
             'ltc_action_enable' : (response[6] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtnOhpSinkMode)
        self.add_api_exec_cb()
        return apiResponse

    def SetOtnOhpDmMode (self, channel, map_level, dm_subfield, dm_mode):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1BB
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = dm_subfield>>0
        # assert: (x >= 0 && x <= 6)
        command_array[11] = dm_mode>>0
        # assert: (x >= 0 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOtnOhpDmMode)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnOhpDmMode (self, channel, map_level, dm_subfield):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1BC
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = dm_subfield>>0
        # assert: (x >= 0 && x <= 6)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'dm_mode' : (response[4] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtnOhpDmMode)
        self.add_api_exec_cb()
        return apiResponse

    def RunOtnOhpDm (self, channel, map_level, dm_subfield, dm_action):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1BD
        header.Tag = 0
        header.MaxResponse = 12
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = dm_subfield>>0
        # assert: (x >= 0 && x <= 6)
        command_array[11] = dm_action>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'dm_result' : (response[4] & 0xFF),
             'dm_measure' : (response[5] & 0xFF)|((response[6]<<8) & (0xFF<<8))|((response[7]<<16) & (0xFF<<16))|((response[8]<<24) & (0xFF<<24)),
        }
        self.check_response(apiResponse, CanopusApi.RunOtnOhpDm)
        self.add_api_exec_cb()
        return apiResponse

    def SetOtnOhpSourceBip8 (self, channel, map_level, layer_level, mode):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x19F
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = layer_level>>0
        # assert: (x >= 0 && x <= 7)
        command_array[11] = mode>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOtnOhpSourceBip8)
        self.add_api_exec_cb()
        return apiResponse

    def SetOtnOhpSourceBdi (self, channel, map_level, layer_level, mode, override_enable, override_value):
        #Default header
        header=ArgHeader()
        header.Length = 16
        header.Command = 0x227
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*16
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = layer_level>>0
        # assert: (x >= 0 && x <= 7)
        command_array[11] = mode>>0
        # assert: (x >= 0 && x <= 1)
        command_array[12] = override_enable>>0
        # assert: (x >= 0 && x <= 1)
        command_array[13] = override_value>>0
        # assert: (x < 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOtnOhpSourceBdi)
        self.add_api_exec_cb()
        return apiResponse

    def SetOtnOhpSourceBeiBiae (self, channel, map_level, layer_level, mode, override_enable, override_value):
        #Default header
        header=ArgHeader()
        header.Length = 16
        header.Command = 0x228
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*16
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = layer_level>>0
        # assert: (x >= 0 && x <= 7)
        command_array[11] = mode>>0
        # assert: (x >= 0 && x <= 1)
        command_array[12] = override_enable>>0
        # assert: (x >= 0 && x <= 1)
        command_array[13] = override_value>>0
        # assert: (x < 16)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOtnOhpSourceBeiBiae)
        self.add_api_exec_cb()
        return apiResponse

    def SetOtnOhpSourceStat (self, channel, map_level, layer_level, mode, override_enable, override_value):
        #Default header
        header=ArgHeader()
        header.Length = 16
        header.Command = 0x229
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*16
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = layer_level>>0
        # assert: (x >= 0 && x <= 7)
        command_array[11] = mode>>0
        # assert: (x >= 0 && x <= 1)
        command_array[12] = override_enable>>0
        # assert: (x >= 0 && x <= 1)
        command_array[13] = override_value>>0
        # assert: (x < 8)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOtnOhpSourceStat)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnOhpSourceBip8 (self, channel, map_level, layer_level):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1A0
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = layer_level>>0
        # assert: (x >= 0 && x <= 7)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'mode' : (response[4] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtnOhpSourceBip8)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnOhpSourceBdi (self, channel, map_level, layer_level):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x22A
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = layer_level>>0
        # assert: (x >= 0 && x <= 7)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'mode' : (response[4] & 0xFF),
             'override_enable' : (response[5] & 0xFF),
             'override_value' : (response[6] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtnOhpSourceBdi)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnOhpSourceBeiBiae (self, channel, map_level, layer_level):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x22B
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = layer_level>>0
        # assert: (x >= 0 && x <= 7)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'mode' : (response[4] & 0xFF),
             'override_enable' : (response[5] & 0xFF),
             'override_value' : (response[6] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtnOhpSourceBeiBiae)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnOhpSourceStat (self, channel, map_level, layer_level):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x22C
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = layer_level>>0
        # assert: (x >= 0 && x <= 7)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'mode' : (response[4] & 0xFF),
             'override_enable' : (response[5] & 0xFF),
             'override_value' : (response[6] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtnOhpSourceStat)
        self.add_api_exec_cb()
        return apiResponse

    def SetFlexOOhpSourceMode (self, channel, phy_map_value, gid_value, pid_value, avail_value):
        #Default header
        header=ArgHeader()
        header.Length = 48
        header.Command = 0x1BE
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*48
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = phy_map_value[0]>>0
        command_array[10] = phy_map_value[0]>>8
        command_array[11] = phy_map_value[0]>>16
        command_array[12] = phy_map_value[0]>>24
        command_array[13] = phy_map_value[1]>>0
        command_array[14] = phy_map_value[1]>>8
        command_array[15] = phy_map_value[1]>>16
        command_array[16] = phy_map_value[1]>>24
        command_array[17] = phy_map_value[2]>>0
        command_array[18] = phy_map_value[2]>>8
        command_array[19] = phy_map_value[2]>>16
        command_array[20] = phy_map_value[2]>>24
        command_array[21] = phy_map_value[3]>>0
        command_array[22] = phy_map_value[3]>>8
        command_array[23] = phy_map_value[3]>>16
        command_array[24] = phy_map_value[3]>>24
        command_array[25] = phy_map_value[4]>>0
        command_array[26] = phy_map_value[4]>>8
        command_array[27] = phy_map_value[4]>>16
        command_array[28] = phy_map_value[4]>>24
        command_array[29] = phy_map_value[5]>>0
        command_array[30] = phy_map_value[5]>>8
        command_array[31] = phy_map_value[5]>>16
        command_array[32] = phy_map_value[5]>>24
        command_array[33] = phy_map_value[6]>>0
        command_array[34] = phy_map_value[6]>>8
        command_array[35] = phy_map_value[6]>>16
        command_array[36] = phy_map_value[6]>>24
        command_array[37] = phy_map_value[7]>>0
        command_array[38] = phy_map_value[7]>>8
        command_array[39] = phy_map_value[7]>>16
        command_array[40] = phy_map_value[7]>>24
        command_array[41] = gid_value>>0
        command_array[42] = gid_value>>8
        command_array[43] = gid_value>>16
        command_array[44] = gid_value>>24
        # assert: (x < 0xFFFFF)
        command_array[45] = pid_value>>0
        command_array[46] = avail_value>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetFlexOOhpSourceMode)
        self.add_api_exec_cb()
        return apiResponse

    def GetFlexOOhpSourceMode (self, channel):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1BF
        header.Tag = 0
        header.MaxResponse = 44
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'phy_map_value' : [                          (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24)),
                          (response[8] & 0xFF)|((response[9]<<8) & (0xFF<<8))|((response[10]<<16) & (0xFF<<16))|((response[11]<<24) & (0xFF<<24)),
                          (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8))|((response[14]<<16) & (0xFF<<16))|((response[15]<<24) & (0xFF<<24)),
                          (response[16] & 0xFF)|((response[17]<<8) & (0xFF<<8))|((response[18]<<16) & (0xFF<<16))|((response[19]<<24) & (0xFF<<24)),
                          (response[20] & 0xFF)|((response[21]<<8) & (0xFF<<8))|((response[22]<<16) & (0xFF<<16))|((response[23]<<24) & (0xFF<<24)),
                          (response[24] & 0xFF)|((response[25]<<8) & (0xFF<<8))|((response[26]<<16) & (0xFF<<16))|((response[27]<<24) & (0xFF<<24)),
                          (response[28] & 0xFF)|((response[29]<<8) & (0xFF<<8))|((response[30]<<16) & (0xFF<<16))|((response[31]<<24) & (0xFF<<24)),
                          (response[32] & 0xFF)|((response[33]<<8) & (0xFF<<8))|((response[34]<<16) & (0xFF<<16))|((response[35]<<24) & (0xFF<<24)),
                          ],
             'gid_value' : (response[36] & 0xFF)|((response[37]<<8) & (0xFF<<8))|((response[38]<<16) & (0xFF<<16))|((response[39]<<24) & (0xFF<<24)),
             'pid_value' : (response[40] & 0xFF),
             'avail_value' : (response[41] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetFlexOOhpSourceMode)
        self.add_api_exec_cb()
        return apiResponse

    def SetFlexOOhpSinkFieldsExpected (self, channel, phy_map_expected, gid_expected, pid_expected):
        #Default header
        header=ArgHeader()
        header.Length = 48
        header.Command = 0x1C0
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*48
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = phy_map_expected[0]>>0
        command_array[10] = phy_map_expected[0]>>8
        command_array[11] = phy_map_expected[0]>>16
        command_array[12] = phy_map_expected[0]>>24
        command_array[13] = phy_map_expected[1]>>0
        command_array[14] = phy_map_expected[1]>>8
        command_array[15] = phy_map_expected[1]>>16
        command_array[16] = phy_map_expected[1]>>24
        command_array[17] = phy_map_expected[2]>>0
        command_array[18] = phy_map_expected[2]>>8
        command_array[19] = phy_map_expected[2]>>16
        command_array[20] = phy_map_expected[2]>>24
        command_array[21] = phy_map_expected[3]>>0
        command_array[22] = phy_map_expected[3]>>8
        command_array[23] = phy_map_expected[3]>>16
        command_array[24] = phy_map_expected[3]>>24
        command_array[25] = phy_map_expected[4]>>0
        command_array[26] = phy_map_expected[4]>>8
        command_array[27] = phy_map_expected[4]>>16
        command_array[28] = phy_map_expected[4]>>24
        command_array[29] = phy_map_expected[5]>>0
        command_array[30] = phy_map_expected[5]>>8
        command_array[31] = phy_map_expected[5]>>16
        command_array[32] = phy_map_expected[5]>>24
        command_array[33] = phy_map_expected[6]>>0
        command_array[34] = phy_map_expected[6]>>8
        command_array[35] = phy_map_expected[6]>>16
        command_array[36] = phy_map_expected[6]>>24
        command_array[37] = phy_map_expected[7]>>0
        command_array[38] = phy_map_expected[7]>>8
        command_array[39] = phy_map_expected[7]>>16
        command_array[40] = phy_map_expected[7]>>24
        command_array[41] = gid_expected>>0
        command_array[42] = gid_expected>>8
        command_array[43] = gid_expected>>16
        command_array[44] = gid_expected>>24
        # assert: (x < 0xFFFFF)
        command_array[45] = pid_expected>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetFlexOOhpSinkFieldsExpected)
        self.add_api_exec_cb()
        return apiResponse

    def GetFlexOOhpSinkFieldsExpected (self, channel):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1C1
        header.Tag = 0
        header.MaxResponse = 44
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'phy_map_expected' : [                          (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24)),
                          (response[8] & 0xFF)|((response[9]<<8) & (0xFF<<8))|((response[10]<<16) & (0xFF<<16))|((response[11]<<24) & (0xFF<<24)),
                          (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8))|((response[14]<<16) & (0xFF<<16))|((response[15]<<24) & (0xFF<<24)),
                          (response[16] & 0xFF)|((response[17]<<8) & (0xFF<<8))|((response[18]<<16) & (0xFF<<16))|((response[19]<<24) & (0xFF<<24)),
                          (response[20] & 0xFF)|((response[21]<<8) & (0xFF<<8))|((response[22]<<16) & (0xFF<<16))|((response[23]<<24) & (0xFF<<24)),
                          (response[24] & 0xFF)|((response[25]<<8) & (0xFF<<8))|((response[26]<<16) & (0xFF<<16))|((response[27]<<24) & (0xFF<<24)),
                          (response[28] & 0xFF)|((response[29]<<8) & (0xFF<<8))|((response[30]<<16) & (0xFF<<16))|((response[31]<<24) & (0xFF<<24)),
                          (response[32] & 0xFF)|((response[33]<<8) & (0xFF<<8))|((response[34]<<16) & (0xFF<<16))|((response[35]<<24) & (0xFF<<24)),
                          ],
             'gid_expected' : (response[36] & 0xFF)|((response[37]<<8) & (0xFF<<8))|((response[38]<<16) & (0xFF<<16))|((response[39]<<24) & (0xFF<<24)),
             'pid_expected' : (response[40] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetFlexOOhpSinkFieldsExpected)
        self.add_api_exec_cb()
        return apiResponse

    def SetFlexEOhpSinkFieldsExpected (self, channel, direction, phy_map_expected, gid_expected, pid_expected):
        #Default header
        header=ArgHeader()
        header.Length = 48
        header.Command = 0x1C2
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*48
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)
        command_array[10] = phy_map_expected[0]>>0
        command_array[11] = phy_map_expected[1]>>0
        command_array[12] = phy_map_expected[2]>>0
        command_array[13] = phy_map_expected[3]>>0
        command_array[14] = phy_map_expected[4]>>0
        command_array[15] = phy_map_expected[5]>>0
        command_array[16] = phy_map_expected[6]>>0
        command_array[17] = phy_map_expected[7]>>0
        command_array[18] = phy_map_expected[8]>>0
        command_array[19] = phy_map_expected[9]>>0
        command_array[20] = phy_map_expected[10]>>0
        command_array[21] = phy_map_expected[11]>>0
        command_array[22] = phy_map_expected[12]>>0
        command_array[23] = phy_map_expected[13]>>0
        command_array[24] = phy_map_expected[14]>>0
        command_array[25] = phy_map_expected[15]>>0
        command_array[26] = phy_map_expected[16]>>0
        command_array[27] = phy_map_expected[17]>>0
        command_array[28] = phy_map_expected[18]>>0
        command_array[29] = phy_map_expected[19]>>0
        command_array[30] = phy_map_expected[20]>>0
        command_array[31] = phy_map_expected[21]>>0
        command_array[32] = phy_map_expected[22]>>0
        command_array[33] = phy_map_expected[23]>>0
        command_array[34] = phy_map_expected[24]>>0
        command_array[35] = phy_map_expected[25]>>0
        command_array[36] = phy_map_expected[26]>>0
        command_array[37] = phy_map_expected[27]>>0
        command_array[38] = phy_map_expected[28]>>0
        command_array[39] = phy_map_expected[29]>>0
        command_array[40] = phy_map_expected[30]>>0
        command_array[41] = phy_map_expected[31]>>0
        command_array[42] = gid_expected>>0
        command_array[43] = gid_expected>>8
        command_array[44] = gid_expected>>16
        command_array[45] = gid_expected>>24
        # assert: (x < 0xFFFFF)
        command_array[46] = pid_expected>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetFlexEOhpSinkFieldsExpected)
        self.add_api_exec_cb()
        return apiResponse

    def GetFlexEOhpSinkFieldsExpected (self, channel, direction):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1C3
        header.Tag = 0
        header.MaxResponse = 44
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'phy_map_expected' : [                          (response[4] & 0xFF),
                          (response[5] & 0xFF),
                          (response[6] & 0xFF),
                          (response[7] & 0xFF),
                          (response[8] & 0xFF),
                          (response[9] & 0xFF),
                          (response[10] & 0xFF),
                          (response[11] & 0xFF),
                          (response[12] & 0xFF),
                          (response[13] & 0xFF),
                          (response[14] & 0xFF),
                          (response[15] & 0xFF),
                          (response[16] & 0xFF),
                          (response[17] & 0xFF),
                          (response[18] & 0xFF),
                          (response[19] & 0xFF),
                          (response[20] & 0xFF),
                          (response[21] & 0xFF),
                          (response[22] & 0xFF),
                          (response[23] & 0xFF),
                          (response[24] & 0xFF),
                          (response[25] & 0xFF),
                          (response[26] & 0xFF),
                          (response[27] & 0xFF),
                          (response[28] & 0xFF),
                          (response[29] & 0xFF),
                          (response[30] & 0xFF),
                          (response[31] & 0xFF),
                          (response[32] & 0xFF),
                          (response[33] & 0xFF),
                          (response[34] & 0xFF),
                          (response[35] & 0xFF),
                          ],
             'gid_expected' : (response[36] & 0xFF)|((response[37]<<8) & (0xFF<<8))|((response[38]<<16) & (0xFF<<16))|((response[39]<<24) & (0xFF<<24)),
             'pid_expected' : (response[40] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetFlexEOhpSinkFieldsExpected)
        self.add_api_exec_cb()
        return apiResponse

    def GetFlexEOhpSinkFieldsAccepted (self, channel, direction):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x214
        header.Tag = 0
        header.MaxResponse = 44
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'phy_map_accepted' : [                          (response[4] & 0xFF),
                          (response[5] & 0xFF),
                          (response[6] & 0xFF),
                          (response[7] & 0xFF),
                          (response[8] & 0xFF),
                          (response[9] & 0xFF),
                          (response[10] & 0xFF),
                          (response[11] & 0xFF),
                          (response[12] & 0xFF),
                          (response[13] & 0xFF),
                          (response[14] & 0xFF),
                          (response[15] & 0xFF),
                          (response[16] & 0xFF),
                          (response[17] & 0xFF),
                          (response[18] & 0xFF),
                          (response[19] & 0xFF),
                          (response[20] & 0xFF),
                          (response[21] & 0xFF),
                          (response[22] & 0xFF),
                          (response[23] & 0xFF),
                          (response[24] & 0xFF),
                          (response[25] & 0xFF),
                          (response[26] & 0xFF),
                          (response[27] & 0xFF),
                          (response[28] & 0xFF),
                          (response[29] & 0xFF),
                          (response[30] & 0xFF),
                          (response[31] & 0xFF),
                          (response[32] & 0xFF),
                          (response[33] & 0xFF),
                          (response[34] & 0xFF),
                          (response[35] & 0xFF),
                          ],
             'gid_accepted' : (response[36] & 0xFF)|((response[37]<<8) & (0xFF<<8))|((response[38]<<16) & (0xFF<<16))|((response[39]<<24) & (0xFF<<24)),
             'pid_accepted' : (response[40] & 0xFF),
             'rpf_accepted' : (response[41] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetFlexEOhpSinkFieldsAccepted)
        self.add_api_exec_cb()
        return apiResponse

    def SetOtnOhpSourceApsChannels (self, channel, map_level, aps_channel_select, aps_value, aps_enable):
        #Default header
        header=ArgHeader()
        header.Length = 16
        header.Command = 0x1A3
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*16
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = aps_channel_select>>0
        # assert: (x >= 0 && x <= 7)
        command_array[11] = aps_value>>0
        command_array[12] = aps_value>>8
        command_array[13] = aps_value>>16
        command_array[14] = aps_value>>24
        command_array[15] = aps_enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOtnOhpSourceApsChannels)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnOhpSourceApsChannels (self, channel, map_level, aps_channel_select):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1A4
        header.Tag = 0
        header.MaxResponse = 12
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = aps_channel_select>>0
        # assert: (x >= 0 && x <= 7)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'aps_value' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24)),
             'aps_enable' : (response[8] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtnOhpSourceApsChannels)
        self.add_api_exec_cb()
        return apiResponse

    def SetOtnOhpSourceTti (self, channel, field_level, map_level, tti_sapi, tti_dapi, tti_os, enable):
        #Default header
        header=ArgHeader()
        header.Length = 76
        header.Command = 0x1A1
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*76
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = field_level>>0
        # assert: (x >= 0 && x <= 7)
        command_array[10] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[11] = tti_sapi[0]>>0
        command_array[12] = tti_sapi[1]>>0
        command_array[13] = tti_sapi[2]>>0
        command_array[14] = tti_sapi[3]>>0
        command_array[15] = tti_sapi[4]>>0
        command_array[16] = tti_sapi[5]>>0
        command_array[17] = tti_sapi[6]>>0
        command_array[18] = tti_sapi[7]>>0
        command_array[19] = tti_sapi[8]>>0
        command_array[20] = tti_sapi[9]>>0
        command_array[21] = tti_sapi[10]>>0
        command_array[22] = tti_sapi[11]>>0
        command_array[23] = tti_sapi[12]>>0
        command_array[24] = tti_sapi[13]>>0
        command_array[25] = tti_sapi[14]>>0
        command_array[26] = tti_sapi[15]>>0
        command_array[27] = tti_dapi[0]>>0
        command_array[28] = tti_dapi[1]>>0
        command_array[29] = tti_dapi[2]>>0
        command_array[30] = tti_dapi[3]>>0
        command_array[31] = tti_dapi[4]>>0
        command_array[32] = tti_dapi[5]>>0
        command_array[33] = tti_dapi[6]>>0
        command_array[34] = tti_dapi[7]>>0
        command_array[35] = tti_dapi[8]>>0
        command_array[36] = tti_dapi[9]>>0
        command_array[37] = tti_dapi[10]>>0
        command_array[38] = tti_dapi[11]>>0
        command_array[39] = tti_dapi[12]>>0
        command_array[40] = tti_dapi[13]>>0
        command_array[41] = tti_dapi[14]>>0
        command_array[42] = tti_dapi[15]>>0
        command_array[43] = tti_os[0]>>0
        command_array[44] = tti_os[1]>>0
        command_array[45] = tti_os[2]>>0
        command_array[46] = tti_os[3]>>0
        command_array[47] = tti_os[4]>>0
        command_array[48] = tti_os[5]>>0
        command_array[49] = tti_os[6]>>0
        command_array[50] = tti_os[7]>>0
        command_array[51] = tti_os[8]>>0
        command_array[52] = tti_os[9]>>0
        command_array[53] = tti_os[10]>>0
        command_array[54] = tti_os[11]>>0
        command_array[55] = tti_os[12]>>0
        command_array[56] = tti_os[13]>>0
        command_array[57] = tti_os[14]>>0
        command_array[58] = tti_os[15]>>0
        command_array[59] = tti_os[16]>>0
        command_array[60] = tti_os[17]>>0
        command_array[61] = tti_os[18]>>0
        command_array[62] = tti_os[19]>>0
        command_array[63] = tti_os[20]>>0
        command_array[64] = tti_os[21]>>0
        command_array[65] = tti_os[22]>>0
        command_array[66] = tti_os[23]>>0
        command_array[67] = tti_os[24]>>0
        command_array[68] = tti_os[25]>>0
        command_array[69] = tti_os[26]>>0
        command_array[70] = tti_os[27]>>0
        command_array[71] = tti_os[28]>>0
        command_array[72] = tti_os[29]>>0
        command_array[73] = tti_os[30]>>0
        command_array[74] = tti_os[31]>>0
        command_array[75] = enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOtnOhpSourceTti)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnOhpSourceTti (self, channel, field_level, map_level):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1A2
        header.Tag = 0
        header.MaxResponse = 72
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = field_level>>0
        # assert: (x >= 0 && x <= 7)
        command_array[10] = map_level>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'tti_sapi' : [                          (response[4] & 0xFF),
                          (response[5] & 0xFF),
                          (response[6] & 0xFF),
                          (response[7] & 0xFF),
                          (response[8] & 0xFF),
                          (response[9] & 0xFF),
                          (response[10] & 0xFF),
                          (response[11] & 0xFF),
                          (response[12] & 0xFF),
                          (response[13] & 0xFF),
                          (response[14] & 0xFF),
                          (response[15] & 0xFF),
                          (response[16] & 0xFF),
                          (response[17] & 0xFF),
                          (response[18] & 0xFF),
                          (response[19] & 0xFF),
                          ],
             'tti_dapi' : [                          (response[20] & 0xFF),
                          (response[21] & 0xFF),
                          (response[22] & 0xFF),
                          (response[23] & 0xFF),
                          (response[24] & 0xFF),
                          (response[25] & 0xFF),
                          (response[26] & 0xFF),
                          (response[27] & 0xFF),
                          (response[28] & 0xFF),
                          (response[29] & 0xFF),
                          (response[30] & 0xFF),
                          (response[31] & 0xFF),
                          (response[32] & 0xFF),
                          (response[33] & 0xFF),
                          (response[34] & 0xFF),
                          (response[35] & 0xFF),
                          ],
             'tti_os' : [                          (response[36] & 0xFF),
                          (response[37] & 0xFF),
                          (response[38] & 0xFF),
                          (response[39] & 0xFF),
                          (response[40] & 0xFF),
                          (response[41] & 0xFF),
                          (response[42] & 0xFF),
                          (response[43] & 0xFF),
                          (response[44] & 0xFF),
                          (response[45] & 0xFF),
                          (response[46] & 0xFF),
                          (response[47] & 0xFF),
                          (response[48] & 0xFF),
                          (response[49] & 0xFF),
                          (response[50] & 0xFF),
                          (response[51] & 0xFF),
                          (response[52] & 0xFF),
                          (response[53] & 0xFF),
                          (response[54] & 0xFF),
                          (response[55] & 0xFF),
                          (response[56] & 0xFF),
                          (response[57] & 0xFF),
                          (response[58] & 0xFF),
                          (response[59] & 0xFF),
                          (response[60] & 0xFF),
                          (response[61] & 0xFF),
                          (response[62] & 0xFF),
                          (response[63] & 0xFF),
                          (response[64] & 0xFF),
                          (response[65] & 0xFF),
                          (response[66] & 0xFF),
                          (response[67] & 0xFF),
                          ],
             'enable' : (response[68] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtnOhpSourceTti)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnOhpSinkTtiAccepted (self, channel, field_level, map_level):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1FD
        header.Tag = 0
        header.MaxResponse = 68
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = field_level>>0
        # assert: (x >= 0 && x <= 7)
        command_array[10] = map_level>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'tti_sapi_accepted' : [                          (response[4] & 0xFF),
                          (response[5] & 0xFF),
                          (response[6] & 0xFF),
                          (response[7] & 0xFF),
                          (response[8] & 0xFF),
                          (response[9] & 0xFF),
                          (response[10] & 0xFF),
                          (response[11] & 0xFF),
                          (response[12] & 0xFF),
                          (response[13] & 0xFF),
                          (response[14] & 0xFF),
                          (response[15] & 0xFF),
                          (response[16] & 0xFF),
                          (response[17] & 0xFF),
                          (response[18] & 0xFF),
                          (response[19] & 0xFF),
                          ],
             'tti_dapi_accepted' : [                          (response[20] & 0xFF),
                          (response[21] & 0xFF),
                          (response[22] & 0xFF),
                          (response[23] & 0xFF),
                          (response[24] & 0xFF),
                          (response[25] & 0xFF),
                          (response[26] & 0xFF),
                          (response[27] & 0xFF),
                          (response[28] & 0xFF),
                          (response[29] & 0xFF),
                          (response[30] & 0xFF),
                          (response[31] & 0xFF),
                          (response[32] & 0xFF),
                          (response[33] & 0xFF),
                          (response[34] & 0xFF),
                          (response[35] & 0xFF),
                          ],
             'tti_os_accepted' : [                          (response[36] & 0xFF),
                          (response[37] & 0xFF),
                          (response[38] & 0xFF),
                          (response[39] & 0xFF),
                          (response[40] & 0xFF),
                          (response[41] & 0xFF),
                          (response[42] & 0xFF),
                          (response[43] & 0xFF),
                          (response[44] & 0xFF),
                          (response[45] & 0xFF),
                          (response[46] & 0xFF),
                          (response[47] & 0xFF),
                          (response[48] & 0xFF),
                          (response[49] & 0xFF),
                          (response[50] & 0xFF),
                          (response[51] & 0xFF),
                          (response[52] & 0xFF),
                          (response[53] & 0xFF),
                          (response[54] & 0xFF),
                          (response[55] & 0xFF),
                          (response[56] & 0xFF),
                          (response[57] & 0xFF),
                          (response[58] & 0xFF),
                          (response[59] & 0xFF),
                          (response[60] & 0xFF),
                          (response[61] & 0xFF),
                          (response[62] & 0xFF),
                          (response[63] & 0xFF),
                          (response[64] & 0xFF),
                          (response[65] & 0xFF),
                          (response[66] & 0xFF),
                          (response[67] & 0xFF),
                          ],
        }
        self.check_response(apiResponse, CanopusApi.GetOtnOhpSinkTtiAccepted)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnOhpSinkTtiExpected (self, channel, field_level, map_level):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1B0
        header.Tag = 0
        header.MaxResponse = 76
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = field_level>>0
        # assert: (x >= 0 && x <= 7)
        command_array[10] = map_level>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'tti_sapi_expected' : [                          (response[4] & 0xFF),
                          (response[5] & 0xFF),
                          (response[6] & 0xFF),
                          (response[7] & 0xFF),
                          (response[8] & 0xFF),
                          (response[9] & 0xFF),
                          (response[10] & 0xFF),
                          (response[11] & 0xFF),
                          (response[12] & 0xFF),
                          (response[13] & 0xFF),
                          (response[14] & 0xFF),
                          (response[15] & 0xFF),
                          (response[16] & 0xFF),
                          (response[17] & 0xFF),
                          (response[18] & 0xFF),
                          (response[19] & 0xFF),
                          ],
             'tti_dapi_expected' : [                          (response[20] & 0xFF),
                          (response[21] & 0xFF),
                          (response[22] & 0xFF),
                          (response[23] & 0xFF),
                          (response[24] & 0xFF),
                          (response[25] & 0xFF),
                          (response[26] & 0xFF),
                          (response[27] & 0xFF),
                          (response[28] & 0xFF),
                          (response[29] & 0xFF),
                          (response[30] & 0xFF),
                          (response[31] & 0xFF),
                          (response[32] & 0xFF),
                          (response[33] & 0xFF),
                          (response[34] & 0xFF),
                          (response[35] & 0xFF),
                          ],
             'tti_os_expected' : [                          (response[36] & 0xFF),
                          (response[37] & 0xFF),
                          (response[38] & 0xFF),
                          (response[39] & 0xFF),
                          (response[40] & 0xFF),
                          (response[41] & 0xFF),
                          (response[42] & 0xFF),
                          (response[43] & 0xFF),
                          (response[44] & 0xFF),
                          (response[45] & 0xFF),
                          (response[46] & 0xFF),
                          (response[47] & 0xFF),
                          (response[48] & 0xFF),
                          (response[49] & 0xFF),
                          (response[50] & 0xFF),
                          (response[51] & 0xFF),
                          (response[52] & 0xFF),
                          (response[53] & 0xFF),
                          (response[54] & 0xFF),
                          (response[55] & 0xFF),
                          (response[56] & 0xFF),
                          (response[57] & 0xFF),
                          (response[58] & 0xFF),
                          (response[59] & 0xFF),
                          (response[60] & 0xFF),
                          (response[61] & 0xFF),
                          (response[62] & 0xFF),
                          (response[63] & 0xFF),
                          (response[64] & 0xFF),
                          (response[65] & 0xFF),
                          (response[66] & 0xFF),
                          (response[67] & 0xFF),
                          ],
             'tti_sapi_expected_mask' : (response[68] & 0xFF)|((response[69]<<8) & (0xFF<<8)),
             'tti_dapi_expected_mask' : (response[70] & 0xFF)|((response[71]<<8) & (0xFF<<8)),
             'tti_os_expected_mask' : (response[72] & 0xFF)|((response[73]<<8) & (0xFF<<8))|((response[74]<<16) & (0xFF<<16))|((response[75]<<24) & (0xFF<<24)),
        }
        self.check_response(apiResponse, CanopusApi.GetOtnOhpSinkTtiExpected)
        self.add_api_exec_cb()
        return apiResponse

    def SetOtnOhpSinkTtiExpected (self, channel, field_level, map_level, tti_sapi_expected, tti_dapi_expected, tti_os_expected, tti_sapi_expected_mask, tti_dapi_expected_mask, tti_os_expected_mask):
        #Default header
        header=ArgHeader()
        header.Length = 84
        header.Command = 0x1AF
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*84
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = field_level>>0
        # assert: (x >= 0 && x <= 7)
        command_array[10] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[11] = tti_sapi_expected[0]>>0
        command_array[12] = tti_sapi_expected[1]>>0
        command_array[13] = tti_sapi_expected[2]>>0
        command_array[14] = tti_sapi_expected[3]>>0
        command_array[15] = tti_sapi_expected[4]>>0
        command_array[16] = tti_sapi_expected[5]>>0
        command_array[17] = tti_sapi_expected[6]>>0
        command_array[18] = tti_sapi_expected[7]>>0
        command_array[19] = tti_sapi_expected[8]>>0
        command_array[20] = tti_sapi_expected[9]>>0
        command_array[21] = tti_sapi_expected[10]>>0
        command_array[22] = tti_sapi_expected[11]>>0
        command_array[23] = tti_sapi_expected[12]>>0
        command_array[24] = tti_sapi_expected[13]>>0
        command_array[25] = tti_sapi_expected[14]>>0
        command_array[26] = tti_sapi_expected[15]>>0
        command_array[27] = tti_dapi_expected[0]>>0
        command_array[28] = tti_dapi_expected[1]>>0
        command_array[29] = tti_dapi_expected[2]>>0
        command_array[30] = tti_dapi_expected[3]>>0
        command_array[31] = tti_dapi_expected[4]>>0
        command_array[32] = tti_dapi_expected[5]>>0
        command_array[33] = tti_dapi_expected[6]>>0
        command_array[34] = tti_dapi_expected[7]>>0
        command_array[35] = tti_dapi_expected[8]>>0
        command_array[36] = tti_dapi_expected[9]>>0
        command_array[37] = tti_dapi_expected[10]>>0
        command_array[38] = tti_dapi_expected[11]>>0
        command_array[39] = tti_dapi_expected[12]>>0
        command_array[40] = tti_dapi_expected[13]>>0
        command_array[41] = tti_dapi_expected[14]>>0
        command_array[42] = tti_dapi_expected[15]>>0
        command_array[43] = tti_os_expected[0]>>0
        command_array[44] = tti_os_expected[1]>>0
        command_array[45] = tti_os_expected[2]>>0
        command_array[46] = tti_os_expected[3]>>0
        command_array[47] = tti_os_expected[4]>>0
        command_array[48] = tti_os_expected[5]>>0
        command_array[49] = tti_os_expected[6]>>0
        command_array[50] = tti_os_expected[7]>>0
        command_array[51] = tti_os_expected[8]>>0
        command_array[52] = tti_os_expected[9]>>0
        command_array[53] = tti_os_expected[10]>>0
        command_array[54] = tti_os_expected[11]>>0
        command_array[55] = tti_os_expected[12]>>0
        command_array[56] = tti_os_expected[13]>>0
        command_array[57] = tti_os_expected[14]>>0
        command_array[58] = tti_os_expected[15]>>0
        command_array[59] = tti_os_expected[16]>>0
        command_array[60] = tti_os_expected[17]>>0
        command_array[61] = tti_os_expected[18]>>0
        command_array[62] = tti_os_expected[19]>>0
        command_array[63] = tti_os_expected[20]>>0
        command_array[64] = tti_os_expected[21]>>0
        command_array[65] = tti_os_expected[22]>>0
        command_array[66] = tti_os_expected[23]>>0
        command_array[67] = tti_os_expected[24]>>0
        command_array[68] = tti_os_expected[25]>>0
        command_array[69] = tti_os_expected[26]>>0
        command_array[70] = tti_os_expected[27]>>0
        command_array[71] = tti_os_expected[28]>>0
        command_array[72] = tti_os_expected[29]>>0
        command_array[73] = tti_os_expected[30]>>0
        command_array[74] = tti_os_expected[31]>>0
        command_array[75] = tti_sapi_expected_mask>>0
        command_array[76] = tti_sapi_expected_mask>>8
        command_array[77] = tti_dapi_expected_mask>>0
        command_array[78] = tti_dapi_expected_mask>>8
        command_array[79] = tti_os_expected_mask>>0
        command_array[80] = tti_os_expected_mask>>8
        command_array[81] = tti_os_expected_mask>>16
        command_array[82] = tti_os_expected_mask>>24

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOtnOhpSinkTtiExpected)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnOhpSinkPtExpected (self, channel, map_level):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1FC
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'payload_type_expected' : (response[4] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtnOhpSinkPtExpected)
        self.add_api_exec_cb()
        return apiResponse

    def SetOtnOhpSinkPtExpected (self, channel, map_level, payload_type_expected):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1FB
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = payload_type_expected>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOtnOhpSinkPtExpected)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnOhpSinkPtAccepted (self, channel, map_level):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1FE
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'payload_type_accepted' : (response[4] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtnOhpSinkPtAccepted)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnOhpSinkApsChannels (self, channel, map_level, aps_channel_select):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1B2
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = aps_channel_select>>0
        # assert: (x >= 0 && x <= 7)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'aps_value' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24)),
        }
        self.check_response(apiResponse, CanopusApi.GetOtnOhpSinkApsChannels)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnOhpSinkFtflAcceptedMask (self, channel, map_level):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x203
        header.Tag = 0
        header.MaxResponse = 36
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'ftfl_mask' : [                          (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24)),
                          (response[8] & 0xFF)|((response[9]<<8) & (0xFF<<8))|((response[10]<<16) & (0xFF<<16))|((response[11]<<24) & (0xFF<<24)),
                          (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8))|((response[14]<<16) & (0xFF<<16))|((response[15]<<24) & (0xFF<<24)),
                          (response[16] & 0xFF)|((response[17]<<8) & (0xFF<<8))|((response[18]<<16) & (0xFF<<16))|((response[19]<<24) & (0xFF<<24)),
                          (response[20] & 0xFF)|((response[21]<<8) & (0xFF<<8))|((response[22]<<16) & (0xFF<<16))|((response[23]<<24) & (0xFF<<24)),
                          (response[24] & 0xFF)|((response[25]<<8) & (0xFF<<8))|((response[26]<<16) & (0xFF<<16))|((response[27]<<24) & (0xFF<<24)),
                          (response[28] & 0xFF)|((response[29]<<8) & (0xFF<<8))|((response[30]<<16) & (0xFF<<16))|((response[31]<<24) & (0xFF<<24)),
                          (response[32] & 0xFF)|((response[33]<<8) & (0xFF<<8))|((response[34]<<16) & (0xFF<<16))|((response[35]<<24) & (0xFF<<24)),
                          ],
        }
        self.check_response(apiResponse, CanopusApi.GetOtnOhpSinkFtflAcceptedMask)
        self.add_api_exec_cb()
        return apiResponse

    def SetOtnOhpSinkFtflAcceptedMask (self, channel, map_level, ftfl_mask):
        #Default header
        header=ArgHeader()
        header.Length = 44
        header.Command = 0x202
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*44
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = ftfl_mask[0]>>0
        command_array[11] = ftfl_mask[0]>>8
        command_array[12] = ftfl_mask[0]>>16
        command_array[13] = ftfl_mask[0]>>24
        command_array[14] = ftfl_mask[1]>>0
        command_array[15] = ftfl_mask[1]>>8
        command_array[16] = ftfl_mask[1]>>16
        command_array[17] = ftfl_mask[1]>>24
        command_array[18] = ftfl_mask[2]>>0
        command_array[19] = ftfl_mask[2]>>8
        command_array[20] = ftfl_mask[2]>>16
        command_array[21] = ftfl_mask[2]>>24
        command_array[22] = ftfl_mask[3]>>0
        command_array[23] = ftfl_mask[3]>>8
        command_array[24] = ftfl_mask[3]>>16
        command_array[25] = ftfl_mask[3]>>24
        command_array[26] = ftfl_mask[4]>>0
        command_array[27] = ftfl_mask[4]>>8
        command_array[28] = ftfl_mask[4]>>16
        command_array[29] = ftfl_mask[4]>>24
        command_array[30] = ftfl_mask[5]>>0
        command_array[31] = ftfl_mask[5]>>8
        command_array[32] = ftfl_mask[5]>>16
        command_array[33] = ftfl_mask[5]>>24
        command_array[34] = ftfl_mask[6]>>0
        command_array[35] = ftfl_mask[6]>>8
        command_array[36] = ftfl_mask[6]>>16
        command_array[37] = ftfl_mask[6]>>24
        command_array[38] = ftfl_mask[7]>>0
        command_array[39] = ftfl_mask[7]>>8
        command_array[40] = ftfl_mask[7]>>16
        command_array[41] = ftfl_mask[7]>>24

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOtnOhpSinkFtflAcceptedMask)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnOhpSinkFtflAccepted (self, channel, map_level):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x204
        header.Tag = 0
        header.MaxResponse = 260
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'ftfl_accepted' : [                          (response[4] & 0xFF),
                          (response[5] & 0xFF),
                          (response[6] & 0xFF),
                          (response[7] & 0xFF),
                          (response[8] & 0xFF),
                          (response[9] & 0xFF),
                          (response[10] & 0xFF),
                          (response[11] & 0xFF),
                          (response[12] & 0xFF),
                          (response[13] & 0xFF),
                          (response[14] & 0xFF),
                          (response[15] & 0xFF),
                          (response[16] & 0xFF),
                          (response[17] & 0xFF),
                          (response[18] & 0xFF),
                          (response[19] & 0xFF),
                          (response[20] & 0xFF),
                          (response[21] & 0xFF),
                          (response[22] & 0xFF),
                          (response[23] & 0xFF),
                          (response[24] & 0xFF),
                          (response[25] & 0xFF),
                          (response[26] & 0xFF),
                          (response[27] & 0xFF),
                          (response[28] & 0xFF),
                          (response[29] & 0xFF),
                          (response[30] & 0xFF),
                          (response[31] & 0xFF),
                          (response[32] & 0xFF),
                          (response[33] & 0xFF),
                          (response[34] & 0xFF),
                          (response[35] & 0xFF),
                          (response[36] & 0xFF),
                          (response[37] & 0xFF),
                          (response[38] & 0xFF),
                          (response[39] & 0xFF),
                          (response[40] & 0xFF),
                          (response[41] & 0xFF),
                          (response[42] & 0xFF),
                          (response[43] & 0xFF),
                          (response[44] & 0xFF),
                          (response[45] & 0xFF),
                          (response[46] & 0xFF),
                          (response[47] & 0xFF),
                          (response[48] & 0xFF),
                          (response[49] & 0xFF),
                          (response[50] & 0xFF),
                          (response[51] & 0xFF),
                          (response[52] & 0xFF),
                          (response[53] & 0xFF),
                          (response[54] & 0xFF),
                          (response[55] & 0xFF),
                          (response[56] & 0xFF),
                          (response[57] & 0xFF),
                          (response[58] & 0xFF),
                          (response[59] & 0xFF),
                          (response[60] & 0xFF),
                          (response[61] & 0xFF),
                          (response[62] & 0xFF),
                          (response[63] & 0xFF),
                          (response[64] & 0xFF),
                          (response[65] & 0xFF),
                          (response[66] & 0xFF),
                          (response[67] & 0xFF),
                          (response[68] & 0xFF),
                          (response[69] & 0xFF),
                          (response[70] & 0xFF),
                          (response[71] & 0xFF),
                          (response[72] & 0xFF),
                          (response[73] & 0xFF),
                          (response[74] & 0xFF),
                          (response[75] & 0xFF),
                          (response[76] & 0xFF),
                          (response[77] & 0xFF),
                          (response[78] & 0xFF),
                          (response[79] & 0xFF),
                          (response[80] & 0xFF),
                          (response[81] & 0xFF),
                          (response[82] & 0xFF),
                          (response[83] & 0xFF),
                          (response[84] & 0xFF),
                          (response[85] & 0xFF),
                          (response[86] & 0xFF),
                          (response[87] & 0xFF),
                          (response[88] & 0xFF),
                          (response[89] & 0xFF),
                          (response[90] & 0xFF),
                          (response[91] & 0xFF),
                          (response[92] & 0xFF),
                          (response[93] & 0xFF),
                          (response[94] & 0xFF),
                          (response[95] & 0xFF),
                          (response[96] & 0xFF),
                          (response[97] & 0xFF),
                          (response[98] & 0xFF),
                          (response[99] & 0xFF),
                          (response[100] & 0xFF),
                          (response[101] & 0xFF),
                          (response[102] & 0xFF),
                          (response[103] & 0xFF),
                          (response[104] & 0xFF),
                          (response[105] & 0xFF),
                          (response[106] & 0xFF),
                          (response[107] & 0xFF),
                          (response[108] & 0xFF),
                          (response[109] & 0xFF),
                          (response[110] & 0xFF),
                          (response[111] & 0xFF),
                          (response[112] & 0xFF),
                          (response[113] & 0xFF),
                          (response[114] & 0xFF),
                          (response[115] & 0xFF),
                          (response[116] & 0xFF),
                          (response[117] & 0xFF),
                          (response[118] & 0xFF),
                          (response[119] & 0xFF),
                          (response[120] & 0xFF),
                          (response[121] & 0xFF),
                          (response[122] & 0xFF),
                          (response[123] & 0xFF),
                          (response[124] & 0xFF),
                          (response[125] & 0xFF),
                          (response[126] & 0xFF),
                          (response[127] & 0xFF),
                          (response[128] & 0xFF),
                          (response[129] & 0xFF),
                          (response[130] & 0xFF),
                          (response[131] & 0xFF),
                          (response[132] & 0xFF),
                          (response[133] & 0xFF),
                          (response[134] & 0xFF),
                          (response[135] & 0xFF),
                          (response[136] & 0xFF),
                          (response[137] & 0xFF),
                          (response[138] & 0xFF),
                          (response[139] & 0xFF),
                          (response[140] & 0xFF),
                          (response[141] & 0xFF),
                          (response[142] & 0xFF),
                          (response[143] & 0xFF),
                          (response[144] & 0xFF),
                          (response[145] & 0xFF),
                          (response[146] & 0xFF),
                          (response[147] & 0xFF),
                          (response[148] & 0xFF),
                          (response[149] & 0xFF),
                          (response[150] & 0xFF),
                          (response[151] & 0xFF),
                          (response[152] & 0xFF),
                          (response[153] & 0xFF),
                          (response[154] & 0xFF),
                          (response[155] & 0xFF),
                          (response[156] & 0xFF),
                          (response[157] & 0xFF),
                          (response[158] & 0xFF),
                          (response[159] & 0xFF),
                          (response[160] & 0xFF),
                          (response[161] & 0xFF),
                          (response[162] & 0xFF),
                          (response[163] & 0xFF),
                          (response[164] & 0xFF),
                          (response[165] & 0xFF),
                          (response[166] & 0xFF),
                          (response[167] & 0xFF),
                          (response[168] & 0xFF),
                          (response[169] & 0xFF),
                          (response[170] & 0xFF),
                          (response[171] & 0xFF),
                          (response[172] & 0xFF),
                          (response[173] & 0xFF),
                          (response[174] & 0xFF),
                          (response[175] & 0xFF),
                          (response[176] & 0xFF),
                          (response[177] & 0xFF),
                          (response[178] & 0xFF),
                          (response[179] & 0xFF),
                          (response[180] & 0xFF),
                          (response[181] & 0xFF),
                          (response[182] & 0xFF),
                          (response[183] & 0xFF),
                          (response[184] & 0xFF),
                          (response[185] & 0xFF),
                          (response[186] & 0xFF),
                          (response[187] & 0xFF),
                          (response[188] & 0xFF),
                          (response[189] & 0xFF),
                          (response[190] & 0xFF),
                          (response[191] & 0xFF),
                          (response[192] & 0xFF),
                          (response[193] & 0xFF),
                          (response[194] & 0xFF),
                          (response[195] & 0xFF),
                          (response[196] & 0xFF),
                          (response[197] & 0xFF),
                          (response[198] & 0xFF),
                          (response[199] & 0xFF),
                          (response[200] & 0xFF),
                          (response[201] & 0xFF),
                          (response[202] & 0xFF),
                          (response[203] & 0xFF),
                          (response[204] & 0xFF),
                          (response[205] & 0xFF),
                          (response[206] & 0xFF),
                          (response[207] & 0xFF),
                          (response[208] & 0xFF),
                          (response[209] & 0xFF),
                          (response[210] & 0xFF),
                          (response[211] & 0xFF),
                          (response[212] & 0xFF),
                          (response[213] & 0xFF),
                          (response[214] & 0xFF),
                          (response[215] & 0xFF),
                          (response[216] & 0xFF),
                          (response[217] & 0xFF),
                          (response[218] & 0xFF),
                          (response[219] & 0xFF),
                          (response[220] & 0xFF),
                          (response[221] & 0xFF),
                          (response[222] & 0xFF),
                          (response[223] & 0xFF),
                          (response[224] & 0xFF),
                          (response[225] & 0xFF),
                          (response[226] & 0xFF),
                          (response[227] & 0xFF),
                          (response[228] & 0xFF),
                          (response[229] & 0xFF),
                          (response[230] & 0xFF),
                          (response[231] & 0xFF),
                          (response[232] & 0xFF),
                          (response[233] & 0xFF),
                          (response[234] & 0xFF),
                          (response[235] & 0xFF),
                          (response[236] & 0xFF),
                          (response[237] & 0xFF),
                          (response[238] & 0xFF),
                          (response[239] & 0xFF),
                          (response[240] & 0xFF),
                          (response[241] & 0xFF),
                          (response[242] & 0xFF),
                          (response[243] & 0xFF),
                          (response[244] & 0xFF),
                          (response[245] & 0xFF),
                          (response[246] & 0xFF),
                          (response[247] & 0xFF),
                          (response[248] & 0xFF),
                          (response[249] & 0xFF),
                          (response[250] & 0xFF),
                          (response[251] & 0xFF),
                          (response[252] & 0xFF),
                          (response[253] & 0xFF),
                          (response[254] & 0xFF),
                          (response[255] & 0xFF),
                          (response[256] & 0xFF),
                          (response[257] & 0xFF),
                          (response[258] & 0xFF),
                          (response[259] & 0xFF),
                          ],
        }
        self.check_response(apiResponse, CanopusApi.GetOtnOhpSinkFtflAccepted)
        self.add_api_exec_cb()
        return apiResponse

    def SetOtnOhpSinkMsiExpected (self, channel, map_level, msi_expected, msi_expected_mask):
        #Default header
        header=ArgHeader()
        header.Length = 100
        header.Command = 0x1FF
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*100
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = msi_expected[0]>>0
        command_array[11] = msi_expected[1]>>0
        command_array[12] = msi_expected[2]>>0
        command_array[13] = msi_expected[3]>>0
        command_array[14] = msi_expected[4]>>0
        command_array[15] = msi_expected[5]>>0
        command_array[16] = msi_expected[6]>>0
        command_array[17] = msi_expected[7]>>0
        command_array[18] = msi_expected[8]>>0
        command_array[19] = msi_expected[9]>>0
        command_array[20] = msi_expected[10]>>0
        command_array[21] = msi_expected[11]>>0
        command_array[22] = msi_expected[12]>>0
        command_array[23] = msi_expected[13]>>0
        command_array[24] = msi_expected[14]>>0
        command_array[25] = msi_expected[15]>>0
        command_array[26] = msi_expected[16]>>0
        command_array[27] = msi_expected[17]>>0
        command_array[28] = msi_expected[18]>>0
        command_array[29] = msi_expected[19]>>0
        command_array[30] = msi_expected[20]>>0
        command_array[31] = msi_expected[21]>>0
        command_array[32] = msi_expected[22]>>0
        command_array[33] = msi_expected[23]>>0
        command_array[34] = msi_expected[24]>>0
        command_array[35] = msi_expected[25]>>0
        command_array[36] = msi_expected[26]>>0
        command_array[37] = msi_expected[27]>>0
        command_array[38] = msi_expected[28]>>0
        command_array[39] = msi_expected[29]>>0
        command_array[40] = msi_expected[30]>>0
        command_array[41] = msi_expected[31]>>0
        command_array[42] = msi_expected[32]>>0
        command_array[43] = msi_expected[33]>>0
        command_array[44] = msi_expected[34]>>0
        command_array[45] = msi_expected[35]>>0
        command_array[46] = msi_expected[36]>>0
        command_array[47] = msi_expected[37]>>0
        command_array[48] = msi_expected[38]>>0
        command_array[49] = msi_expected[39]>>0
        command_array[50] = msi_expected[40]>>0
        command_array[51] = msi_expected[41]>>0
        command_array[52] = msi_expected[42]>>0
        command_array[53] = msi_expected[43]>>0
        command_array[54] = msi_expected[44]>>0
        command_array[55] = msi_expected[45]>>0
        command_array[56] = msi_expected[46]>>0
        command_array[57] = msi_expected[47]>>0
        command_array[58] = msi_expected[48]>>0
        command_array[59] = msi_expected[49]>>0
        command_array[60] = msi_expected[50]>>0
        command_array[61] = msi_expected[51]>>0
        command_array[62] = msi_expected[52]>>0
        command_array[63] = msi_expected[53]>>0
        command_array[64] = msi_expected[54]>>0
        command_array[65] = msi_expected[55]>>0
        command_array[66] = msi_expected[56]>>0
        command_array[67] = msi_expected[57]>>0
        command_array[68] = msi_expected[58]>>0
        command_array[69] = msi_expected[59]>>0
        command_array[70] = msi_expected[60]>>0
        command_array[71] = msi_expected[61]>>0
        command_array[72] = msi_expected[62]>>0
        command_array[73] = msi_expected[63]>>0
        command_array[74] = msi_expected[64]>>0
        command_array[75] = msi_expected[65]>>0
        command_array[76] = msi_expected[66]>>0
        command_array[77] = msi_expected[67]>>0
        command_array[78] = msi_expected[68]>>0
        command_array[79] = msi_expected[69]>>0
        command_array[80] = msi_expected[70]>>0
        command_array[81] = msi_expected[71]>>0
        command_array[82] = msi_expected[72]>>0
        command_array[83] = msi_expected[73]>>0
        command_array[84] = msi_expected[74]>>0
        command_array[85] = msi_expected[75]>>0
        command_array[86] = msi_expected[76]>>0
        command_array[87] = msi_expected[77]>>0
        command_array[88] = msi_expected[78]>>0
        command_array[89] = msi_expected[79]>>0
        command_array[90] = msi_expected_mask[0]>>0
        command_array[91] = msi_expected_mask[1]>>0
        command_array[92] = msi_expected_mask[2]>>0
        command_array[93] = msi_expected_mask[3]>>0
        command_array[94] = msi_expected_mask[4]>>0
        command_array[95] = msi_expected_mask[5]>>0
        command_array[96] = msi_expected_mask[6]>>0
        command_array[97] = msi_expected_mask[7]>>0
        command_array[98] = msi_expected_mask[8]>>0
        command_array[99] = msi_expected_mask[9]>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOtnOhpSinkMsiExpected)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnOhpSinkMsiExpected (self, channel, map_level):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x200
        header.Tag = 0
        header.MaxResponse = 96
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'msi_expected' : [                          (response[4] & 0xFF),
                          (response[5] & 0xFF),
                          (response[6] & 0xFF),
                          (response[7] & 0xFF),
                          (response[8] & 0xFF),
                          (response[9] & 0xFF),
                          (response[10] & 0xFF),
                          (response[11] & 0xFF),
                          (response[12] & 0xFF),
                          (response[13] & 0xFF),
                          (response[14] & 0xFF),
                          (response[15] & 0xFF),
                          (response[16] & 0xFF),
                          (response[17] & 0xFF),
                          (response[18] & 0xFF),
                          (response[19] & 0xFF),
                          (response[20] & 0xFF),
                          (response[21] & 0xFF),
                          (response[22] & 0xFF),
                          (response[23] & 0xFF),
                          (response[24] & 0xFF),
                          (response[25] & 0xFF),
                          (response[26] & 0xFF),
                          (response[27] & 0xFF),
                          (response[28] & 0xFF),
                          (response[29] & 0xFF),
                          (response[30] & 0xFF),
                          (response[31] & 0xFF),
                          (response[32] & 0xFF),
                          (response[33] & 0xFF),
                          (response[34] & 0xFF),
                          (response[35] & 0xFF),
                          (response[36] & 0xFF),
                          (response[37] & 0xFF),
                          (response[38] & 0xFF),
                          (response[39] & 0xFF),
                          (response[40] & 0xFF),
                          (response[41] & 0xFF),
                          (response[42] & 0xFF),
                          (response[43] & 0xFF),
                          (response[44] & 0xFF),
                          (response[45] & 0xFF),
                          (response[46] & 0xFF),
                          (response[47] & 0xFF),
                          (response[48] & 0xFF),
                          (response[49] & 0xFF),
                          (response[50] & 0xFF),
                          (response[51] & 0xFF),
                          (response[52] & 0xFF),
                          (response[53] & 0xFF),
                          (response[54] & 0xFF),
                          (response[55] & 0xFF),
                          (response[56] & 0xFF),
                          (response[57] & 0xFF),
                          (response[58] & 0xFF),
                          (response[59] & 0xFF),
                          (response[60] & 0xFF),
                          (response[61] & 0xFF),
                          (response[62] & 0xFF),
                          (response[63] & 0xFF),
                          (response[64] & 0xFF),
                          (response[65] & 0xFF),
                          (response[66] & 0xFF),
                          (response[67] & 0xFF),
                          (response[68] & 0xFF),
                          (response[69] & 0xFF),
                          (response[70] & 0xFF),
                          (response[71] & 0xFF),
                          (response[72] & 0xFF),
                          (response[73] & 0xFF),
                          (response[74] & 0xFF),
                          (response[75] & 0xFF),
                          (response[76] & 0xFF),
                          (response[77] & 0xFF),
                          (response[78] & 0xFF),
                          (response[79] & 0xFF),
                          (response[80] & 0xFF),
                          (response[81] & 0xFF),
                          (response[82] & 0xFF),
                          (response[83] & 0xFF),
                          ],
             'msi_expected_mask' : [                          (response[84] & 0xFF),
                          (response[85] & 0xFF),
                          (response[86] & 0xFF),
                          (response[87] & 0xFF),
                          (response[88] & 0xFF),
                          (response[89] & 0xFF),
                          (response[90] & 0xFF),
                          (response[91] & 0xFF),
                          (response[92] & 0xFF),
                          (response[93] & 0xFF),
                          ],
        }
        self.check_response(apiResponse, CanopusApi.GetOtnOhpSinkMsiExpected)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnOhpSinkMsiAccepted (self, channel, map_level):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x201
        header.Tag = 0
        header.MaxResponse = 84
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'msi_accepted' : [                          (response[4] & 0xFF),
                          (response[5] & 0xFF),
                          (response[6] & 0xFF),
                          (response[7] & 0xFF),
                          (response[8] & 0xFF),
                          (response[9] & 0xFF),
                          (response[10] & 0xFF),
                          (response[11] & 0xFF),
                          (response[12] & 0xFF),
                          (response[13] & 0xFF),
                          (response[14] & 0xFF),
                          (response[15] & 0xFF),
                          (response[16] & 0xFF),
                          (response[17] & 0xFF),
                          (response[18] & 0xFF),
                          (response[19] & 0xFF),
                          (response[20] & 0xFF),
                          (response[21] & 0xFF),
                          (response[22] & 0xFF),
                          (response[23] & 0xFF),
                          (response[24] & 0xFF),
                          (response[25] & 0xFF),
                          (response[26] & 0xFF),
                          (response[27] & 0xFF),
                          (response[28] & 0xFF),
                          (response[29] & 0xFF),
                          (response[30] & 0xFF),
                          (response[31] & 0xFF),
                          (response[32] & 0xFF),
                          (response[33] & 0xFF),
                          (response[34] & 0xFF),
                          (response[35] & 0xFF),
                          (response[36] & 0xFF),
                          (response[37] & 0xFF),
                          (response[38] & 0xFF),
                          (response[39] & 0xFF),
                          (response[40] & 0xFF),
                          (response[41] & 0xFF),
                          (response[42] & 0xFF),
                          (response[43] & 0xFF),
                          (response[44] & 0xFF),
                          (response[45] & 0xFF),
                          (response[46] & 0xFF),
                          (response[47] & 0xFF),
                          (response[48] & 0xFF),
                          (response[49] & 0xFF),
                          (response[50] & 0xFF),
                          (response[51] & 0xFF),
                          (response[52] & 0xFF),
                          (response[53] & 0xFF),
                          (response[54] & 0xFF),
                          (response[55] & 0xFF),
                          (response[56] & 0xFF),
                          (response[57] & 0xFF),
                          (response[58] & 0xFF),
                          (response[59] & 0xFF),
                          (response[60] & 0xFF),
                          (response[61] & 0xFF),
                          (response[62] & 0xFF),
                          (response[63] & 0xFF),
                          (response[64] & 0xFF),
                          (response[65] & 0xFF),
                          (response[66] & 0xFF),
                          (response[67] & 0xFF),
                          (response[68] & 0xFF),
                          (response[69] & 0xFF),
                          (response[70] & 0xFF),
                          (response[71] & 0xFF),
                          (response[72] & 0xFF),
                          (response[73] & 0xFF),
                          (response[74] & 0xFF),
                          (response[75] & 0xFF),
                          (response[76] & 0xFF),
                          (response[77] & 0xFF),
                          (response[78] & 0xFF),
                          (response[79] & 0xFF),
                          (response[80] & 0xFF),
                          (response[81] & 0xFF),
                          (response[82] & 0xFF),
                          (response[83] & 0xFF),
                          ],
        }
        self.check_response(apiResponse, CanopusApi.GetOtnOhpSinkMsiAccepted)
        self.add_api_exec_cb()
        return apiResponse

    def SetOtnOhpSourceMsi (self, channel, map_level, msi_value, msi_enable):
        #Default header
        header=ArgHeader()
        header.Length = 92
        header.Command = 0x1A9
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*92
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = msi_value[0]>>0
        command_array[11] = msi_value[1]>>0
        command_array[12] = msi_value[2]>>0
        command_array[13] = msi_value[3]>>0
        command_array[14] = msi_value[4]>>0
        command_array[15] = msi_value[5]>>0
        command_array[16] = msi_value[6]>>0
        command_array[17] = msi_value[7]>>0
        command_array[18] = msi_value[8]>>0
        command_array[19] = msi_value[9]>>0
        command_array[20] = msi_value[10]>>0
        command_array[21] = msi_value[11]>>0
        command_array[22] = msi_value[12]>>0
        command_array[23] = msi_value[13]>>0
        command_array[24] = msi_value[14]>>0
        command_array[25] = msi_value[15]>>0
        command_array[26] = msi_value[16]>>0
        command_array[27] = msi_value[17]>>0
        command_array[28] = msi_value[18]>>0
        command_array[29] = msi_value[19]>>0
        command_array[30] = msi_value[20]>>0
        command_array[31] = msi_value[21]>>0
        command_array[32] = msi_value[22]>>0
        command_array[33] = msi_value[23]>>0
        command_array[34] = msi_value[24]>>0
        command_array[35] = msi_value[25]>>0
        command_array[36] = msi_value[26]>>0
        command_array[37] = msi_value[27]>>0
        command_array[38] = msi_value[28]>>0
        command_array[39] = msi_value[29]>>0
        command_array[40] = msi_value[30]>>0
        command_array[41] = msi_value[31]>>0
        command_array[42] = msi_value[32]>>0
        command_array[43] = msi_value[33]>>0
        command_array[44] = msi_value[34]>>0
        command_array[45] = msi_value[35]>>0
        command_array[46] = msi_value[36]>>0
        command_array[47] = msi_value[37]>>0
        command_array[48] = msi_value[38]>>0
        command_array[49] = msi_value[39]>>0
        command_array[50] = msi_value[40]>>0
        command_array[51] = msi_value[41]>>0
        command_array[52] = msi_value[42]>>0
        command_array[53] = msi_value[43]>>0
        command_array[54] = msi_value[44]>>0
        command_array[55] = msi_value[45]>>0
        command_array[56] = msi_value[46]>>0
        command_array[57] = msi_value[47]>>0
        command_array[58] = msi_value[48]>>0
        command_array[59] = msi_value[49]>>0
        command_array[60] = msi_value[50]>>0
        command_array[61] = msi_value[51]>>0
        command_array[62] = msi_value[52]>>0
        command_array[63] = msi_value[53]>>0
        command_array[64] = msi_value[54]>>0
        command_array[65] = msi_value[55]>>0
        command_array[66] = msi_value[56]>>0
        command_array[67] = msi_value[57]>>0
        command_array[68] = msi_value[58]>>0
        command_array[69] = msi_value[59]>>0
        command_array[70] = msi_value[60]>>0
        command_array[71] = msi_value[61]>>0
        command_array[72] = msi_value[62]>>0
        command_array[73] = msi_value[63]>>0
        command_array[74] = msi_value[64]>>0
        command_array[75] = msi_value[65]>>0
        command_array[76] = msi_value[66]>>0
        command_array[77] = msi_value[67]>>0
        command_array[78] = msi_value[68]>>0
        command_array[79] = msi_value[69]>>0
        command_array[80] = msi_value[70]>>0
        command_array[81] = msi_value[71]>>0
        command_array[82] = msi_value[72]>>0
        command_array[83] = msi_value[73]>>0
        command_array[84] = msi_value[74]>>0
        command_array[85] = msi_value[75]>>0
        command_array[86] = msi_value[76]>>0
        command_array[87] = msi_value[77]>>0
        command_array[88] = msi_value[78]>>0
        command_array[89] = msi_value[79]>>0
        command_array[90] = msi_enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOtnOhpSourceMsi)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnOhpSourceMsi (self, channel, map_level):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1AA
        header.Tag = 0
        header.MaxResponse = 88
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'msi_value' : [                          (response[4] & 0xFF),
                          (response[5] & 0xFF),
                          (response[6] & 0xFF),
                          (response[7] & 0xFF),
                          (response[8] & 0xFF),
                          (response[9] & 0xFF),
                          (response[10] & 0xFF),
                          (response[11] & 0xFF),
                          (response[12] & 0xFF),
                          (response[13] & 0xFF),
                          (response[14] & 0xFF),
                          (response[15] & 0xFF),
                          (response[16] & 0xFF),
                          (response[17] & 0xFF),
                          (response[18] & 0xFF),
                          (response[19] & 0xFF),
                          (response[20] & 0xFF),
                          (response[21] & 0xFF),
                          (response[22] & 0xFF),
                          (response[23] & 0xFF),
                          (response[24] & 0xFF),
                          (response[25] & 0xFF),
                          (response[26] & 0xFF),
                          (response[27] & 0xFF),
                          (response[28] & 0xFF),
                          (response[29] & 0xFF),
                          (response[30] & 0xFF),
                          (response[31] & 0xFF),
                          (response[32] & 0xFF),
                          (response[33] & 0xFF),
                          (response[34] & 0xFF),
                          (response[35] & 0xFF),
                          (response[36] & 0xFF),
                          (response[37] & 0xFF),
                          (response[38] & 0xFF),
                          (response[39] & 0xFF),
                          (response[40] & 0xFF),
                          (response[41] & 0xFF),
                          (response[42] & 0xFF),
                          (response[43] & 0xFF),
                          (response[44] & 0xFF),
                          (response[45] & 0xFF),
                          (response[46] & 0xFF),
                          (response[47] & 0xFF),
                          (response[48] & 0xFF),
                          (response[49] & 0xFF),
                          (response[50] & 0xFF),
                          (response[51] & 0xFF),
                          (response[52] & 0xFF),
                          (response[53] & 0xFF),
                          (response[54] & 0xFF),
                          (response[55] & 0xFF),
                          (response[56] & 0xFF),
                          (response[57] & 0xFF),
                          (response[58] & 0xFF),
                          (response[59] & 0xFF),
                          (response[60] & 0xFF),
                          (response[61] & 0xFF),
                          (response[62] & 0xFF),
                          (response[63] & 0xFF),
                          (response[64] & 0xFF),
                          (response[65] & 0xFF),
                          (response[66] & 0xFF),
                          (response[67] & 0xFF),
                          (response[68] & 0xFF),
                          (response[69] & 0xFF),
                          (response[70] & 0xFF),
                          (response[71] & 0xFF),
                          (response[72] & 0xFF),
                          (response[73] & 0xFF),
                          (response[74] & 0xFF),
                          (response[75] & 0xFF),
                          (response[76] & 0xFF),
                          (response[77] & 0xFF),
                          (response[78] & 0xFF),
                          (response[79] & 0xFF),
                          (response[80] & 0xFF),
                          (response[81] & 0xFF),
                          (response[82] & 0xFF),
                          (response[83] & 0xFF),
                          ],
             'msi_enable' : (response[84] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtnOhpSourceMsi)
        self.add_api_exec_cb()
        return apiResponse

    def SetOtnOhpSourceCsf (self, channel, map_level, csf_mode, csf_override_value, csf_override_enable):
        #Default header
        header=ArgHeader()
        header.Length = 16
        header.Command = 0x1A7
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*16
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = csf_mode>>0
        # assert: (x >= 0 && x <= 1)
        command_array[11] = csf_override_value>>0
        # assert: (x >= 0 && x <= 1)
        command_array[12] = csf_override_enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOtnOhpSourceCsf)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnOhpSourceCsf (self, channel, map_level):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1A8
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'csf_mode' : (response[4] & 0xFF),
             'csf_override_value' : (response[5] & 0xFF),
             'csf_override_enable' : (response[6] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtnOhpSourceCsf)
        self.add_api_exec_cb()
        return apiResponse

    def SetOhaGlobalConfig (self, sgmii_channel, sgmii_rate, lpbk_mode, rx_discard_on_address_mismatch, tx_mac_src_address, tx_mac_dst_address):
        #Default header
        header=ArgHeader()
        header.Length = 28
        header.Command = 0x1C4
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*28
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = sgmii_channel>>0
        # assert: (x >= 0 && x <= 1)
        command_array[9] = sgmii_rate>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = lpbk_mode>>0
        # assert: (x >= 0 && x <= 2)
        command_array[11] = rx_discard_on_address_mismatch>>0
        # assert: (x >= 0 && x <= 1)
        command_array[12] = tx_mac_src_address>>0
        command_array[13] = tx_mac_src_address>>8
        command_array[14] = tx_mac_src_address>>16
        command_array[15] = tx_mac_src_address>>24
        command_array[16] = tx_mac_src_address>>32
        command_array[17] = tx_mac_src_address>>40
        command_array[18] = tx_mac_src_address>>48
        command_array[19] = tx_mac_src_address>>56
        command_array[20] = tx_mac_dst_address>>0
        command_array[21] = tx_mac_dst_address>>8
        command_array[22] = tx_mac_dst_address>>16
        command_array[23] = tx_mac_dst_address>>24
        command_array[24] = tx_mac_dst_address>>32
        command_array[25] = tx_mac_dst_address>>40
        command_array[26] = tx_mac_dst_address>>48
        command_array[27] = tx_mac_dst_address>>56

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOhaGlobalConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetOhaGlobalConfig (self, sgmii_channel):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1C5
        header.Tag = 0
        header.MaxResponse = 24
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = sgmii_channel>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'sgmii_rate' : (response[4] & 0xFF),
             'lpbk_mode' : (response[5] & 0xFF),
             'rx_discard_on_address_mismatch' : (response[6] & 0xFF),
             'tx_mac_src_address' : (response[7] & 0xFF)|((response[8]<<8) & (0xFF<<8))|((response[9]<<16) & (0xFF<<16))|((response[10]<<24) & (0xFF<<24))|((response[11]<<32) & (0xFF<<32))|((response[12]<<40) & (0xFF<<40))|((response[13]<<48) & (0xFF<<48))|((response[14]<<56) & (0xFF<<56)),
             'tx_mac_dst_address' : (response[15] & 0xFF)|((response[16]<<8) & (0xFF<<8))|((response[17]<<16) & (0xFF<<16))|((response[18]<<24) & (0xFF<<24))|((response[19]<<32) & (0xFF<<32))|((response[20]<<40) & (0xFF<<40))|((response[21]<<48) & (0xFF<<48))|((response[22]<<56) & (0xFF<<56)),
        }
        self.check_response(apiResponse, CanopusApi.GetOhaGlobalConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetOhaGlobalStatus (self, sgmii_channel):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1C6
        header.Tag = 0
        header.MaxResponse = 20
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = sgmii_channel>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'ether_stats_pkts' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24)),
             'ether_stats_octets' : (response[8] & 0xFF)|((response[9]<<8) & (0xFF<<8))|((response[10]<<16) & (0xFF<<16))|((response[11]<<24) & (0xFF<<24)),
             'ether_stats_crcalignerrors' : (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8))|((response[14]<<16) & (0xFF<<16))|((response[15]<<24) & (0xFF<<24)),
             'pcs_link' : (response[16] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOhaGlobalStatus)
        self.add_api_exec_cb()
        return apiResponse

    def SetOtnOhaConfig (self, channel, map_level, sgmii_channel, add_byte_select, add_byte_mask, add_mfas_align, drop_byte_select, drop_ohbu_length, port_enable):
        #Default header
        header=ArgHeader()
        header.Length = 208
        header.Command = 0x1C8
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*208
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)
        command_array[10] = sgmii_channel>>0
        # assert: (x >= 0 && x <= 1)
        command_array[11] = add_byte_select[0]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[12] = add_byte_select[1]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[13] = add_byte_select[2]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[14] = add_byte_select[3]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[15] = add_byte_select[4]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[16] = add_byte_select[5]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[17] = add_byte_select[6]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[18] = add_byte_select[7]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[19] = add_byte_select[8]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[20] = add_byte_select[9]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[21] = add_byte_select[10]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[22] = add_byte_select[11]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[23] = add_byte_select[12]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[24] = add_byte_select[13]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[25] = add_byte_select[14]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[26] = add_byte_select[15]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[27] = add_byte_select[16]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[28] = add_byte_select[17]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[29] = add_byte_select[18]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[30] = add_byte_select[19]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[31] = add_byte_select[20]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[32] = add_byte_select[21]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[33] = add_byte_select[22]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[34] = add_byte_select[23]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[35] = add_byte_select[24]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[36] = add_byte_select[25]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[37] = add_byte_select[26]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[38] = add_byte_select[27]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[39] = add_byte_select[28]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[40] = add_byte_select[29]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[41] = add_byte_select[30]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[42] = add_byte_select[31]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[43] = add_byte_select[32]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[44] = add_byte_select[33]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[45] = add_byte_select[34]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[46] = add_byte_select[35]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[47] = add_byte_select[36]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[48] = add_byte_select[37]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[49] = add_byte_select[38]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[50] = add_byte_select[39]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[51] = add_byte_select[40]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[52] = add_byte_select[41]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[53] = add_byte_select[42]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[54] = add_byte_select[43]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[55] = add_byte_select[44]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[56] = add_byte_select[45]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[57] = add_byte_select[46]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[58] = add_byte_select[47]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[59] = add_byte_select[48]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[60] = add_byte_select[49]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[61] = add_byte_select[50]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[62] = add_byte_select[51]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[63] = add_byte_select[52]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[64] = add_byte_select[53]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[65] = add_byte_select[54]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[66] = add_byte_select[55]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[67] = add_byte_select[56]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[68] = add_byte_select[57]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[69] = add_byte_select[58]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[70] = add_byte_select[59]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[71] = add_byte_select[60]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[72] = add_byte_select[61]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[73] = add_byte_select[62]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[74] = add_byte_select[63]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[75] = add_byte_mask[0]>>0
        command_array[76] = add_byte_mask[1]>>0
        command_array[77] = add_byte_mask[2]>>0
        command_array[78] = add_byte_mask[3]>>0
        command_array[79] = add_byte_mask[4]>>0
        command_array[80] = add_byte_mask[5]>>0
        command_array[81] = add_byte_mask[6]>>0
        command_array[82] = add_byte_mask[7]>>0
        command_array[83] = add_byte_mask[8]>>0
        command_array[84] = add_byte_mask[9]>>0
        command_array[85] = add_byte_mask[10]>>0
        command_array[86] = add_byte_mask[11]>>0
        command_array[87] = add_byte_mask[12]>>0
        command_array[88] = add_byte_mask[13]>>0
        command_array[89] = add_byte_mask[14]>>0
        command_array[90] = add_byte_mask[15]>>0
        command_array[91] = add_byte_mask[16]>>0
        command_array[92] = add_byte_mask[17]>>0
        command_array[93] = add_byte_mask[18]>>0
        command_array[94] = add_byte_mask[19]>>0
        command_array[95] = add_byte_mask[20]>>0
        command_array[96] = add_byte_mask[21]>>0
        command_array[97] = add_byte_mask[22]>>0
        command_array[98] = add_byte_mask[23]>>0
        command_array[99] = add_byte_mask[24]>>0
        command_array[100] = add_byte_mask[25]>>0
        command_array[101] = add_byte_mask[26]>>0
        command_array[102] = add_byte_mask[27]>>0
        command_array[103] = add_byte_mask[28]>>0
        command_array[104] = add_byte_mask[29]>>0
        command_array[105] = add_byte_mask[30]>>0
        command_array[106] = add_byte_mask[31]>>0
        command_array[107] = add_byte_mask[32]>>0
        command_array[108] = add_byte_mask[33]>>0
        command_array[109] = add_byte_mask[34]>>0
        command_array[110] = add_byte_mask[35]>>0
        command_array[111] = add_byte_mask[36]>>0
        command_array[112] = add_byte_mask[37]>>0
        command_array[113] = add_byte_mask[38]>>0
        command_array[114] = add_byte_mask[39]>>0
        command_array[115] = add_byte_mask[40]>>0
        command_array[116] = add_byte_mask[41]>>0
        command_array[117] = add_byte_mask[42]>>0
        command_array[118] = add_byte_mask[43]>>0
        command_array[119] = add_byte_mask[44]>>0
        command_array[120] = add_byte_mask[45]>>0
        command_array[121] = add_byte_mask[46]>>0
        command_array[122] = add_byte_mask[47]>>0
        command_array[123] = add_byte_mask[48]>>0
        command_array[124] = add_byte_mask[49]>>0
        command_array[125] = add_byte_mask[50]>>0
        command_array[126] = add_byte_mask[51]>>0
        command_array[127] = add_byte_mask[52]>>0
        command_array[128] = add_byte_mask[53]>>0
        command_array[129] = add_byte_mask[54]>>0
        command_array[130] = add_byte_mask[55]>>0
        command_array[131] = add_byte_mask[56]>>0
        command_array[132] = add_byte_mask[57]>>0
        command_array[133] = add_byte_mask[58]>>0
        command_array[134] = add_byte_mask[59]>>0
        command_array[135] = add_byte_mask[60]>>0
        command_array[136] = add_byte_mask[61]>>0
        command_array[137] = add_byte_mask[62]>>0
        command_array[138] = add_byte_mask[63]>>0
        command_array[139] = add_mfas_align>>0
        # assert: (x >= 0 && x <= 1)
        command_array[140] = drop_byte_select[0]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[141] = drop_byte_select[1]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[142] = drop_byte_select[2]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[143] = drop_byte_select[3]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[144] = drop_byte_select[4]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[145] = drop_byte_select[5]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[146] = drop_byte_select[6]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[147] = drop_byte_select[7]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[148] = drop_byte_select[8]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[149] = drop_byte_select[9]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[150] = drop_byte_select[10]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[151] = drop_byte_select[11]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[152] = drop_byte_select[12]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[153] = drop_byte_select[13]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[154] = drop_byte_select[14]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[155] = drop_byte_select[15]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[156] = drop_byte_select[16]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[157] = drop_byte_select[17]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[158] = drop_byte_select[18]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[159] = drop_byte_select[19]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[160] = drop_byte_select[20]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[161] = drop_byte_select[21]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[162] = drop_byte_select[22]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[163] = drop_byte_select[23]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[164] = drop_byte_select[24]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[165] = drop_byte_select[25]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[166] = drop_byte_select[26]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[167] = drop_byte_select[27]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[168] = drop_byte_select[28]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[169] = drop_byte_select[29]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[170] = drop_byte_select[30]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[171] = drop_byte_select[31]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[172] = drop_byte_select[32]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[173] = drop_byte_select[33]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[174] = drop_byte_select[34]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[175] = drop_byte_select[35]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[176] = drop_byte_select[36]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[177] = drop_byte_select[37]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[178] = drop_byte_select[38]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[179] = drop_byte_select[39]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[180] = drop_byte_select[40]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[181] = drop_byte_select[41]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[182] = drop_byte_select[42]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[183] = drop_byte_select[43]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[184] = drop_byte_select[44]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[185] = drop_byte_select[45]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[186] = drop_byte_select[46]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[187] = drop_byte_select[47]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[188] = drop_byte_select[48]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[189] = drop_byte_select[49]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[190] = drop_byte_select[50]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[191] = drop_byte_select[51]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[192] = drop_byte_select[52]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[193] = drop_byte_select[53]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[194] = drop_byte_select[54]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[195] = drop_byte_select[55]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[196] = drop_byte_select[56]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[197] = drop_byte_select[57]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[198] = drop_byte_select[58]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[199] = drop_byte_select[59]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[200] = drop_byte_select[60]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[201] = drop_byte_select[61]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[202] = drop_byte_select[62]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[203] = drop_byte_select[63]>>0
        # assert: (x >= 1 && x <= 64)
        command_array[204] = drop_ohbu_length>>0
        command_array[205] = port_enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOtnOhaConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnOhaConfig (self, channel, map_level):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1C7
        header.Tag = 0
        header.MaxResponse = 200
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'sgmii_channel' : (response[4] & 0xFF),
             'add_byte_select' : [                          (response[5] & 0xFF),
                          (response[6] & 0xFF),
                          (response[7] & 0xFF),
                          (response[8] & 0xFF),
                          (response[9] & 0xFF),
                          (response[10] & 0xFF),
                          (response[11] & 0xFF),
                          (response[12] & 0xFF),
                          (response[13] & 0xFF),
                          (response[14] & 0xFF),
                          (response[15] & 0xFF),
                          (response[16] & 0xFF),
                          (response[17] & 0xFF),
                          (response[18] & 0xFF),
                          (response[19] & 0xFF),
                          (response[20] & 0xFF),
                          (response[21] & 0xFF),
                          (response[22] & 0xFF),
                          (response[23] & 0xFF),
                          (response[24] & 0xFF),
                          (response[25] & 0xFF),
                          (response[26] & 0xFF),
                          (response[27] & 0xFF),
                          (response[28] & 0xFF),
                          (response[29] & 0xFF),
                          (response[30] & 0xFF),
                          (response[31] & 0xFF),
                          (response[32] & 0xFF),
                          (response[33] & 0xFF),
                          (response[34] & 0xFF),
                          (response[35] & 0xFF),
                          (response[36] & 0xFF),
                          (response[37] & 0xFF),
                          (response[38] & 0xFF),
                          (response[39] & 0xFF),
                          (response[40] & 0xFF),
                          (response[41] & 0xFF),
                          (response[42] & 0xFF),
                          (response[43] & 0xFF),
                          (response[44] & 0xFF),
                          (response[45] & 0xFF),
                          (response[46] & 0xFF),
                          (response[47] & 0xFF),
                          (response[48] & 0xFF),
                          (response[49] & 0xFF),
                          (response[50] & 0xFF),
                          (response[51] & 0xFF),
                          (response[52] & 0xFF),
                          (response[53] & 0xFF),
                          (response[54] & 0xFF),
                          (response[55] & 0xFF),
                          (response[56] & 0xFF),
                          (response[57] & 0xFF),
                          (response[58] & 0xFF),
                          (response[59] & 0xFF),
                          (response[60] & 0xFF),
                          (response[61] & 0xFF),
                          (response[62] & 0xFF),
                          (response[63] & 0xFF),
                          (response[64] & 0xFF),
                          (response[65] & 0xFF),
                          (response[66] & 0xFF),
                          (response[67] & 0xFF),
                          (response[68] & 0xFF),
                          ],
             'add_byte_mask' : [                          (response[69] & 0xFF),
                          (response[70] & 0xFF),
                          (response[71] & 0xFF),
                          (response[72] & 0xFF),
                          (response[73] & 0xFF),
                          (response[74] & 0xFF),
                          (response[75] & 0xFF),
                          (response[76] & 0xFF),
                          (response[77] & 0xFF),
                          (response[78] & 0xFF),
                          (response[79] & 0xFF),
                          (response[80] & 0xFF),
                          (response[81] & 0xFF),
                          (response[82] & 0xFF),
                          (response[83] & 0xFF),
                          (response[84] & 0xFF),
                          (response[85] & 0xFF),
                          (response[86] & 0xFF),
                          (response[87] & 0xFF),
                          (response[88] & 0xFF),
                          (response[89] & 0xFF),
                          (response[90] & 0xFF),
                          (response[91] & 0xFF),
                          (response[92] & 0xFF),
                          (response[93] & 0xFF),
                          (response[94] & 0xFF),
                          (response[95] & 0xFF),
                          (response[96] & 0xFF),
                          (response[97] & 0xFF),
                          (response[98] & 0xFF),
                          (response[99] & 0xFF),
                          (response[100] & 0xFF),
                          (response[101] & 0xFF),
                          (response[102] & 0xFF),
                          (response[103] & 0xFF),
                          (response[104] & 0xFF),
                          (response[105] & 0xFF),
                          (response[106] & 0xFF),
                          (response[107] & 0xFF),
                          (response[108] & 0xFF),
                          (response[109] & 0xFF),
                          (response[110] & 0xFF),
                          (response[111] & 0xFF),
                          (response[112] & 0xFF),
                          (response[113] & 0xFF),
                          (response[114] & 0xFF),
                          (response[115] & 0xFF),
                          (response[116] & 0xFF),
                          (response[117] & 0xFF),
                          (response[118] & 0xFF),
                          (response[119] & 0xFF),
                          (response[120] & 0xFF),
                          (response[121] & 0xFF),
                          (response[122] & 0xFF),
                          (response[123] & 0xFF),
                          (response[124] & 0xFF),
                          (response[125] & 0xFF),
                          (response[126] & 0xFF),
                          (response[127] & 0xFF),
                          (response[128] & 0xFF),
                          (response[129] & 0xFF),
                          (response[130] & 0xFF),
                          (response[131] & 0xFF),
                          (response[132] & 0xFF),
                          ],
             'add_mfas_align' : (response[133] & 0xFF),
             'drop_byte_select' : [                          (response[134] & 0xFF),
                          (response[135] & 0xFF),
                          (response[136] & 0xFF),
                          (response[137] & 0xFF),
                          (response[138] & 0xFF),
                          (response[139] & 0xFF),
                          (response[140] & 0xFF),
                          (response[141] & 0xFF),
                          (response[142] & 0xFF),
                          (response[143] & 0xFF),
                          (response[144] & 0xFF),
                          (response[145] & 0xFF),
                          (response[146] & 0xFF),
                          (response[147] & 0xFF),
                          (response[148] & 0xFF),
                          (response[149] & 0xFF),
                          (response[150] & 0xFF),
                          (response[151] & 0xFF),
                          (response[152] & 0xFF),
                          (response[153] & 0xFF),
                          (response[154] & 0xFF),
                          (response[155] & 0xFF),
                          (response[156] & 0xFF),
                          (response[157] & 0xFF),
                          (response[158] & 0xFF),
                          (response[159] & 0xFF),
                          (response[160] & 0xFF),
                          (response[161] & 0xFF),
                          (response[162] & 0xFF),
                          (response[163] & 0xFF),
                          (response[164] & 0xFF),
                          (response[165] & 0xFF),
                          (response[166] & 0xFF),
                          (response[167] & 0xFF),
                          (response[168] & 0xFF),
                          (response[169] & 0xFF),
                          (response[170] & 0xFF),
                          (response[171] & 0xFF),
                          (response[172] & 0xFF),
                          (response[173] & 0xFF),
                          (response[174] & 0xFF),
                          (response[175] & 0xFF),
                          (response[176] & 0xFF),
                          (response[177] & 0xFF),
                          (response[178] & 0xFF),
                          (response[179] & 0xFF),
                          (response[180] & 0xFF),
                          (response[181] & 0xFF),
                          (response[182] & 0xFF),
                          (response[183] & 0xFF),
                          (response[184] & 0xFF),
                          (response[185] & 0xFF),
                          (response[186] & 0xFF),
                          (response[187] & 0xFF),
                          (response[188] & 0xFF),
                          (response[189] & 0xFF),
                          (response[190] & 0xFF),
                          (response[191] & 0xFF),
                          (response[192] & 0xFF),
                          (response[193] & 0xFF),
                          (response[194] & 0xFF),
                          (response[195] & 0xFF),
                          (response[196] & 0xFF),
                          (response[197] & 0xFF),
                          ],
             'drop_ohbu_length' : (response[198] & 0xFF),
             'port_enable' : (response[199] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtnOhaConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetFlexeOhaConfig (self, channel, sgmii_channel, drop_ohbu_length, add_pcs_mask, port_enable):
        #Default header
        header=ArgHeader()
        header.Length = 16
        header.Command = 0x1D4
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*16
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = sgmii_channel>>0
        # assert: (x >= 0 && x <= 1)
        command_array[10] = drop_ohbu_length>>0
        command_array[11] = add_pcs_mask>>0
        command_array[12] = port_enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetFlexeOhaConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetFlexeOhaConfig (self, channel):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1D3
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'sgmii_channel' : (response[4] & 0xFF),
             'drop_ohbu_length' : (response[5] & 0xFF),
             'add_pcs_mask' : (response[6] & 0xFF),
             'port_enable' : (response[7] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetFlexeOhaConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetFlexoOhaConfig (self, channel, sgmii_channel, add_byte_select, add_byte_mask, drop_byte_select, drop_ohbu_length, mfas_insertion_enable, port_enable):
        #Default header
        header=ArgHeader()
        header.Length = 136
        header.Command = 0x1CE
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*136
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = sgmii_channel>>0
        # assert: (x >= 0 && x <= 1)
        command_array[10] = add_byte_select[0]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[11] = add_byte_select[1]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[12] = add_byte_select[2]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[13] = add_byte_select[3]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[14] = add_byte_select[4]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[15] = add_byte_select[5]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[16] = add_byte_select[6]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[17] = add_byte_select[7]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[18] = add_byte_select[8]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[19] = add_byte_select[9]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[20] = add_byte_select[10]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[21] = add_byte_select[11]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[22] = add_byte_select[12]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[23] = add_byte_select[13]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[24] = add_byte_select[14]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[25] = add_byte_select[15]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[26] = add_byte_select[16]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[27] = add_byte_select[17]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[28] = add_byte_select[18]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[29] = add_byte_select[19]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[30] = add_byte_select[20]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[31] = add_byte_select[21]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[32] = add_byte_select[22]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[33] = add_byte_select[23]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[34] = add_byte_select[24]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[35] = add_byte_select[25]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[36] = add_byte_select[26]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[37] = add_byte_select[27]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[38] = add_byte_select[28]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[39] = add_byte_select[29]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[40] = add_byte_select[30]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[41] = add_byte_select[31]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[42] = add_byte_select[32]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[43] = add_byte_select[33]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[44] = add_byte_select[34]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[45] = add_byte_select[35]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[46] = add_byte_select[36]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[47] = add_byte_select[37]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[48] = add_byte_select[38]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[49] = add_byte_select[39]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[50] = add_byte_mask[0]>>0
        command_array[51] = add_byte_mask[1]>>0
        command_array[52] = add_byte_mask[2]>>0
        command_array[53] = add_byte_mask[3]>>0
        command_array[54] = add_byte_mask[4]>>0
        command_array[55] = add_byte_mask[5]>>0
        command_array[56] = add_byte_mask[6]>>0
        command_array[57] = add_byte_mask[7]>>0
        command_array[58] = add_byte_mask[8]>>0
        command_array[59] = add_byte_mask[9]>>0
        command_array[60] = add_byte_mask[10]>>0
        command_array[61] = add_byte_mask[11]>>0
        command_array[62] = add_byte_mask[12]>>0
        command_array[63] = add_byte_mask[13]>>0
        command_array[64] = add_byte_mask[14]>>0
        command_array[65] = add_byte_mask[15]>>0
        command_array[66] = add_byte_mask[16]>>0
        command_array[67] = add_byte_mask[17]>>0
        command_array[68] = add_byte_mask[18]>>0
        command_array[69] = add_byte_mask[19]>>0
        command_array[70] = add_byte_mask[20]>>0
        command_array[71] = add_byte_mask[21]>>0
        command_array[72] = add_byte_mask[22]>>0
        command_array[73] = add_byte_mask[23]>>0
        command_array[74] = add_byte_mask[24]>>0
        command_array[75] = add_byte_mask[25]>>0
        command_array[76] = add_byte_mask[26]>>0
        command_array[77] = add_byte_mask[27]>>0
        command_array[78] = add_byte_mask[28]>>0
        command_array[79] = add_byte_mask[29]>>0
        command_array[80] = add_byte_mask[30]>>0
        command_array[81] = add_byte_mask[31]>>0
        command_array[82] = add_byte_mask[32]>>0
        command_array[83] = add_byte_mask[33]>>0
        command_array[84] = add_byte_mask[34]>>0
        command_array[85] = add_byte_mask[35]>>0
        command_array[86] = add_byte_mask[36]>>0
        command_array[87] = add_byte_mask[37]>>0
        command_array[88] = add_byte_mask[38]>>0
        command_array[89] = add_byte_mask[39]>>0
        command_array[90] = drop_byte_select[0]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[91] = drop_byte_select[1]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[92] = drop_byte_select[2]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[93] = drop_byte_select[3]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[94] = drop_byte_select[4]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[95] = drop_byte_select[5]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[96] = drop_byte_select[6]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[97] = drop_byte_select[7]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[98] = drop_byte_select[8]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[99] = drop_byte_select[9]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[100] = drop_byte_select[10]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[101] = drop_byte_select[11]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[102] = drop_byte_select[12]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[103] = drop_byte_select[13]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[104] = drop_byte_select[14]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[105] = drop_byte_select[15]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[106] = drop_byte_select[16]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[107] = drop_byte_select[17]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[108] = drop_byte_select[18]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[109] = drop_byte_select[19]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[110] = drop_byte_select[20]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[111] = drop_byte_select[21]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[112] = drop_byte_select[22]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[113] = drop_byte_select[23]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[114] = drop_byte_select[24]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[115] = drop_byte_select[25]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[116] = drop_byte_select[26]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[117] = drop_byte_select[27]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[118] = drop_byte_select[28]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[119] = drop_byte_select[29]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[120] = drop_byte_select[30]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[121] = drop_byte_select[31]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[122] = drop_byte_select[32]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[123] = drop_byte_select[33]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[124] = drop_byte_select[34]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[125] = drop_byte_select[35]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[126] = drop_byte_select[36]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[127] = drop_byte_select[37]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[128] = drop_byte_select[38]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[129] = drop_byte_select[39]>>0
        # assert: (x >= 1 && x <= 40)
        command_array[130] = drop_ohbu_length>>0
        command_array[131] = mfas_insertion_enable>>0
        # assert: (x >= 0 && x <= 1)
        command_array[132] = port_enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetFlexoOhaConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetFlexoOhaConfig (self, channel):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1CD
        header.Tag = 0
        header.MaxResponse = 128
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'sgmii_channel' : (response[4] & 0xFF),
             'add_byte_select' : [                          (response[5] & 0xFF),
                          (response[6] & 0xFF),
                          (response[7] & 0xFF),
                          (response[8] & 0xFF),
                          (response[9] & 0xFF),
                          (response[10] & 0xFF),
                          (response[11] & 0xFF),
                          (response[12] & 0xFF),
                          (response[13] & 0xFF),
                          (response[14] & 0xFF),
                          (response[15] & 0xFF),
                          (response[16] & 0xFF),
                          (response[17] & 0xFF),
                          (response[18] & 0xFF),
                          (response[19] & 0xFF),
                          (response[20] & 0xFF),
                          (response[21] & 0xFF),
                          (response[22] & 0xFF),
                          (response[23] & 0xFF),
                          (response[24] & 0xFF),
                          (response[25] & 0xFF),
                          (response[26] & 0xFF),
                          (response[27] & 0xFF),
                          (response[28] & 0xFF),
                          (response[29] & 0xFF),
                          (response[30] & 0xFF),
                          (response[31] & 0xFF),
                          (response[32] & 0xFF),
                          (response[33] & 0xFF),
                          (response[34] & 0xFF),
                          (response[35] & 0xFF),
                          (response[36] & 0xFF),
                          (response[37] & 0xFF),
                          (response[38] & 0xFF),
                          (response[39] & 0xFF),
                          (response[40] & 0xFF),
                          (response[41] & 0xFF),
                          (response[42] & 0xFF),
                          (response[43] & 0xFF),
                          (response[44] & 0xFF),
                          ],
             'add_byte_mask' : [                          (response[45] & 0xFF),
                          (response[46] & 0xFF),
                          (response[47] & 0xFF),
                          (response[48] & 0xFF),
                          (response[49] & 0xFF),
                          (response[50] & 0xFF),
                          (response[51] & 0xFF),
                          (response[52] & 0xFF),
                          (response[53] & 0xFF),
                          (response[54] & 0xFF),
                          (response[55] & 0xFF),
                          (response[56] & 0xFF),
                          (response[57] & 0xFF),
                          (response[58] & 0xFF),
                          (response[59] & 0xFF),
                          (response[60] & 0xFF),
                          (response[61] & 0xFF),
                          (response[62] & 0xFF),
                          (response[63] & 0xFF),
                          (response[64] & 0xFF),
                          (response[65] & 0xFF),
                          (response[66] & 0xFF),
                          (response[67] & 0xFF),
                          (response[68] & 0xFF),
                          (response[69] & 0xFF),
                          (response[70] & 0xFF),
                          (response[71] & 0xFF),
                          (response[72] & 0xFF),
                          (response[73] & 0xFF),
                          (response[74] & 0xFF),
                          (response[75] & 0xFF),
                          (response[76] & 0xFF),
                          (response[77] & 0xFF),
                          (response[78] & 0xFF),
                          (response[79] & 0xFF),
                          (response[80] & 0xFF),
                          (response[81] & 0xFF),
                          (response[82] & 0xFF),
                          (response[83] & 0xFF),
                          (response[84] & 0xFF),
                          ],
             'drop_byte_select' : [                          (response[85] & 0xFF),
                          (response[86] & 0xFF),
                          (response[87] & 0xFF),
                          (response[88] & 0xFF),
                          (response[89] & 0xFF),
                          (response[90] & 0xFF),
                          (response[91] & 0xFF),
                          (response[92] & 0xFF),
                          (response[93] & 0xFF),
                          (response[94] & 0xFF),
                          (response[95] & 0xFF),
                          (response[96] & 0xFF),
                          (response[97] & 0xFF),
                          (response[98] & 0xFF),
                          (response[99] & 0xFF),
                          (response[100] & 0xFF),
                          (response[101] & 0xFF),
                          (response[102] & 0xFF),
                          (response[103] & 0xFF),
                          (response[104] & 0xFF),
                          (response[105] & 0xFF),
                          (response[106] & 0xFF),
                          (response[107] & 0xFF),
                          (response[108] & 0xFF),
                          (response[109] & 0xFF),
                          (response[110] & 0xFF),
                          (response[111] & 0xFF),
                          (response[112] & 0xFF),
                          (response[113] & 0xFF),
                          (response[114] & 0xFF),
                          (response[115] & 0xFF),
                          (response[116] & 0xFF),
                          (response[117] & 0xFF),
                          (response[118] & 0xFF),
                          (response[119] & 0xFF),
                          (response[120] & 0xFF),
                          (response[121] & 0xFF),
                          (response[122] & 0xFF),
                          (response[123] & 0xFF),
                          (response[124] & 0xFF),
                          ],
             'drop_ohbu_length' : (response[125] & 0xFF),
             'mfas_insertion_enable' : (response[126] & 0xFF),
             'port_enable' : (response[127] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetFlexoOhaConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetOhaFw (self, action):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x256
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = action>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOhaFw)
        self.add_api_exec_cb()
        return apiResponse

    def GetOhaFw (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x257
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOhaFw)
        self.add_api_exec_cb()
        return apiResponse

    def LoadOhaFw (self, data):
        #Default header
        header=ArgHeader()
        header.Length = 360
        header.Command = 0x259
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*360
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = data[0]>>0
        command_array[9] = data[0]>>8
        command_array[10] = data[1]>>0
        command_array[11] = data[1]>>8
        command_array[12] = data[2]>>0
        command_array[13] = data[2]>>8
        command_array[14] = data[3]>>0
        command_array[15] = data[3]>>8
        command_array[16] = data[4]>>0
        command_array[17] = data[4]>>8
        command_array[18] = data[5]>>0
        command_array[19] = data[5]>>8
        command_array[20] = data[6]>>0
        command_array[21] = data[6]>>8
        command_array[22] = data[7]>>0
        command_array[23] = data[7]>>8
        command_array[24] = data[8]>>0
        command_array[25] = data[8]>>8
        command_array[26] = data[9]>>0
        command_array[27] = data[9]>>8
        command_array[28] = data[10]>>0
        command_array[29] = data[10]>>8
        command_array[30] = data[11]>>0
        command_array[31] = data[11]>>8
        command_array[32] = data[12]>>0
        command_array[33] = data[12]>>8
        command_array[34] = data[13]>>0
        command_array[35] = data[13]>>8
        command_array[36] = data[14]>>0
        command_array[37] = data[14]>>8
        command_array[38] = data[15]>>0
        command_array[39] = data[15]>>8
        command_array[40] = data[16]>>0
        command_array[41] = data[16]>>8
        command_array[42] = data[17]>>0
        command_array[43] = data[17]>>8
        command_array[44] = data[18]>>0
        command_array[45] = data[18]>>8
        command_array[46] = data[19]>>0
        command_array[47] = data[19]>>8
        command_array[48] = data[20]>>0
        command_array[49] = data[20]>>8
        command_array[50] = data[21]>>0
        command_array[51] = data[21]>>8
        command_array[52] = data[22]>>0
        command_array[53] = data[22]>>8
        command_array[54] = data[23]>>0
        command_array[55] = data[23]>>8
        command_array[56] = data[24]>>0
        command_array[57] = data[24]>>8
        command_array[58] = data[25]>>0
        command_array[59] = data[25]>>8
        command_array[60] = data[26]>>0
        command_array[61] = data[26]>>8
        command_array[62] = data[27]>>0
        command_array[63] = data[27]>>8
        command_array[64] = data[28]>>0
        command_array[65] = data[28]>>8
        command_array[66] = data[29]>>0
        command_array[67] = data[29]>>8
        command_array[68] = data[30]>>0
        command_array[69] = data[30]>>8
        command_array[70] = data[31]>>0
        command_array[71] = data[31]>>8
        command_array[72] = data[32]>>0
        command_array[73] = data[32]>>8
        command_array[74] = data[33]>>0
        command_array[75] = data[33]>>8
        command_array[76] = data[34]>>0
        command_array[77] = data[34]>>8
        command_array[78] = data[35]>>0
        command_array[79] = data[35]>>8
        command_array[80] = data[36]>>0
        command_array[81] = data[36]>>8
        command_array[82] = data[37]>>0
        command_array[83] = data[37]>>8
        command_array[84] = data[38]>>0
        command_array[85] = data[38]>>8
        command_array[86] = data[39]>>0
        command_array[87] = data[39]>>8
        command_array[88] = data[40]>>0
        command_array[89] = data[40]>>8
        command_array[90] = data[41]>>0
        command_array[91] = data[41]>>8
        command_array[92] = data[42]>>0
        command_array[93] = data[42]>>8
        command_array[94] = data[43]>>0
        command_array[95] = data[43]>>8
        command_array[96] = data[44]>>0
        command_array[97] = data[44]>>8
        command_array[98] = data[45]>>0
        command_array[99] = data[45]>>8
        command_array[100] = data[46]>>0
        command_array[101] = data[46]>>8
        command_array[102] = data[47]>>0
        command_array[103] = data[47]>>8
        command_array[104] = data[48]>>0
        command_array[105] = data[48]>>8
        command_array[106] = data[49]>>0
        command_array[107] = data[49]>>8
        command_array[108] = data[50]>>0
        command_array[109] = data[50]>>8
        command_array[110] = data[51]>>0
        command_array[111] = data[51]>>8
        command_array[112] = data[52]>>0
        command_array[113] = data[52]>>8
        command_array[114] = data[53]>>0
        command_array[115] = data[53]>>8
        command_array[116] = data[54]>>0
        command_array[117] = data[54]>>8
        command_array[118] = data[55]>>0
        command_array[119] = data[55]>>8
        command_array[120] = data[56]>>0
        command_array[121] = data[56]>>8
        command_array[122] = data[57]>>0
        command_array[123] = data[57]>>8
        command_array[124] = data[58]>>0
        command_array[125] = data[58]>>8
        command_array[126] = data[59]>>0
        command_array[127] = data[59]>>8
        command_array[128] = data[60]>>0
        command_array[129] = data[60]>>8
        command_array[130] = data[61]>>0
        command_array[131] = data[61]>>8
        command_array[132] = data[62]>>0
        command_array[133] = data[62]>>8
        command_array[134] = data[63]>>0
        command_array[135] = data[63]>>8
        command_array[136] = data[64]>>0
        command_array[137] = data[64]>>8
        command_array[138] = data[65]>>0
        command_array[139] = data[65]>>8
        command_array[140] = data[66]>>0
        command_array[141] = data[66]>>8
        command_array[142] = data[67]>>0
        command_array[143] = data[67]>>8
        command_array[144] = data[68]>>0
        command_array[145] = data[68]>>8
        command_array[146] = data[69]>>0
        command_array[147] = data[69]>>8
        command_array[148] = data[70]>>0
        command_array[149] = data[70]>>8
        command_array[150] = data[71]>>0
        command_array[151] = data[71]>>8
        command_array[152] = data[72]>>0
        command_array[153] = data[72]>>8
        command_array[154] = data[73]>>0
        command_array[155] = data[73]>>8
        command_array[156] = data[74]>>0
        command_array[157] = data[74]>>8
        command_array[158] = data[75]>>0
        command_array[159] = data[75]>>8
        command_array[160] = data[76]>>0
        command_array[161] = data[76]>>8
        command_array[162] = data[77]>>0
        command_array[163] = data[77]>>8
        command_array[164] = data[78]>>0
        command_array[165] = data[78]>>8
        command_array[166] = data[79]>>0
        command_array[167] = data[79]>>8
        command_array[168] = data[80]>>0
        command_array[169] = data[80]>>8
        command_array[170] = data[81]>>0
        command_array[171] = data[81]>>8
        command_array[172] = data[82]>>0
        command_array[173] = data[82]>>8
        command_array[174] = data[83]>>0
        command_array[175] = data[83]>>8
        command_array[176] = data[84]>>0
        command_array[177] = data[84]>>8
        command_array[178] = data[85]>>0
        command_array[179] = data[85]>>8
        command_array[180] = data[86]>>0
        command_array[181] = data[86]>>8
        command_array[182] = data[87]>>0
        command_array[183] = data[87]>>8
        command_array[184] = data[88]>>0
        command_array[185] = data[88]>>8
        command_array[186] = data[89]>>0
        command_array[187] = data[89]>>8
        command_array[188] = data[90]>>0
        command_array[189] = data[90]>>8
        command_array[190] = data[91]>>0
        command_array[191] = data[91]>>8
        command_array[192] = data[92]>>0
        command_array[193] = data[92]>>8
        command_array[194] = data[93]>>0
        command_array[195] = data[93]>>8
        command_array[196] = data[94]>>0
        command_array[197] = data[94]>>8
        command_array[198] = data[95]>>0
        command_array[199] = data[95]>>8
        command_array[200] = data[96]>>0
        command_array[201] = data[96]>>8
        command_array[202] = data[97]>>0
        command_array[203] = data[97]>>8
        command_array[204] = data[98]>>0
        command_array[205] = data[98]>>8
        command_array[206] = data[99]>>0
        command_array[207] = data[99]>>8
        command_array[208] = data[100]>>0
        command_array[209] = data[100]>>8
        command_array[210] = data[101]>>0
        command_array[211] = data[101]>>8
        command_array[212] = data[102]>>0
        command_array[213] = data[102]>>8
        command_array[214] = data[103]>>0
        command_array[215] = data[103]>>8
        command_array[216] = data[104]>>0
        command_array[217] = data[104]>>8
        command_array[218] = data[105]>>0
        command_array[219] = data[105]>>8
        command_array[220] = data[106]>>0
        command_array[221] = data[106]>>8
        command_array[222] = data[107]>>0
        command_array[223] = data[107]>>8
        command_array[224] = data[108]>>0
        command_array[225] = data[108]>>8
        command_array[226] = data[109]>>0
        command_array[227] = data[109]>>8
        command_array[228] = data[110]>>0
        command_array[229] = data[110]>>8
        command_array[230] = data[111]>>0
        command_array[231] = data[111]>>8
        command_array[232] = data[112]>>0
        command_array[233] = data[112]>>8
        command_array[234] = data[113]>>0
        command_array[235] = data[113]>>8
        command_array[236] = data[114]>>0
        command_array[237] = data[114]>>8
        command_array[238] = data[115]>>0
        command_array[239] = data[115]>>8
        command_array[240] = data[116]>>0
        command_array[241] = data[116]>>8
        command_array[242] = data[117]>>0
        command_array[243] = data[117]>>8
        command_array[244] = data[118]>>0
        command_array[245] = data[118]>>8
        command_array[246] = data[119]>>0
        command_array[247] = data[119]>>8
        command_array[248] = data[120]>>0
        command_array[249] = data[120]>>8
        command_array[250] = data[121]>>0
        command_array[251] = data[121]>>8
        command_array[252] = data[122]>>0
        command_array[253] = data[122]>>8
        command_array[254] = data[123]>>0
        command_array[255] = data[123]>>8
        command_array[256] = data[124]>>0
        command_array[257] = data[124]>>8
        command_array[258] = data[125]>>0
        command_array[259] = data[125]>>8
        command_array[260] = data[126]>>0
        command_array[261] = data[126]>>8
        command_array[262] = data[127]>>0
        command_array[263] = data[127]>>8
        command_array[264] = data[128]>>0
        command_array[265] = data[128]>>8
        command_array[266] = data[129]>>0
        command_array[267] = data[129]>>8
        command_array[268] = data[130]>>0
        command_array[269] = data[130]>>8
        command_array[270] = data[131]>>0
        command_array[271] = data[131]>>8
        command_array[272] = data[132]>>0
        command_array[273] = data[132]>>8
        command_array[274] = data[133]>>0
        command_array[275] = data[133]>>8
        command_array[276] = data[134]>>0
        command_array[277] = data[134]>>8
        command_array[278] = data[135]>>0
        command_array[279] = data[135]>>8
        command_array[280] = data[136]>>0
        command_array[281] = data[136]>>8
        command_array[282] = data[137]>>0
        command_array[283] = data[137]>>8
        command_array[284] = data[138]>>0
        command_array[285] = data[138]>>8
        command_array[286] = data[139]>>0
        command_array[287] = data[139]>>8
        command_array[288] = data[140]>>0
        command_array[289] = data[140]>>8
        command_array[290] = data[141]>>0
        command_array[291] = data[141]>>8
        command_array[292] = data[142]>>0
        command_array[293] = data[142]>>8
        command_array[294] = data[143]>>0
        command_array[295] = data[143]>>8
        command_array[296] = data[144]>>0
        command_array[297] = data[144]>>8
        command_array[298] = data[145]>>0
        command_array[299] = data[145]>>8
        command_array[300] = data[146]>>0
        command_array[301] = data[146]>>8
        command_array[302] = data[147]>>0
        command_array[303] = data[147]>>8
        command_array[304] = data[148]>>0
        command_array[305] = data[148]>>8
        command_array[306] = data[149]>>0
        command_array[307] = data[149]>>8
        command_array[308] = data[150]>>0
        command_array[309] = data[150]>>8
        command_array[310] = data[151]>>0
        command_array[311] = data[151]>>8
        command_array[312] = data[152]>>0
        command_array[313] = data[152]>>8
        command_array[314] = data[153]>>0
        command_array[315] = data[153]>>8
        command_array[316] = data[154]>>0
        command_array[317] = data[154]>>8
        command_array[318] = data[155]>>0
        command_array[319] = data[155]>>8
        command_array[320] = data[156]>>0
        command_array[321] = data[156]>>8
        command_array[322] = data[157]>>0
        command_array[323] = data[157]>>8
        command_array[324] = data[158]>>0
        command_array[325] = data[158]>>8
        command_array[326] = data[159]>>0
        command_array[327] = data[159]>>8
        command_array[328] = data[160]>>0
        command_array[329] = data[160]>>8
        command_array[330] = data[161]>>0
        command_array[331] = data[161]>>8
        command_array[332] = data[162]>>0
        command_array[333] = data[162]>>8
        command_array[334] = data[163]>>0
        command_array[335] = data[163]>>8
        command_array[336] = data[164]>>0
        command_array[337] = data[164]>>8
        command_array[338] = data[165]>>0
        command_array[339] = data[165]>>8
        command_array[340] = data[166]>>0
        command_array[341] = data[166]>>8
        command_array[342] = data[167]>>0
        command_array[343] = data[167]>>8
        command_array[344] = data[168]>>0
        command_array[345] = data[168]>>8
        command_array[346] = data[169]>>0
        command_array[347] = data[169]>>8
        command_array[348] = data[170]>>0
        command_array[349] = data[170]>>8
        command_array[350] = data[171]>>0
        command_array[351] = data[171]>>8
        command_array[352] = data[172]>>0
        command_array[353] = data[172]>>8
        command_array[354] = data[173]>>0
        command_array[355] = data[173]>>8
        command_array[356] = data[174]>>0
        command_array[357] = data[174]>>8
        command_array[358] = data[175]>>0
        command_array[359] = data[175]>>8

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.LoadOhaFw)
        self.add_api_exec_cb()
        return apiResponse

    def SetPcsTestPatternGeneratorConfig (self, channel, direction, pcs_signal_type, enable):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x17F
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)
        command_array[10] = pcs_signal_type>>0
        # assert: (x >= 0 && x <= 2)
        command_array[11] = enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetPcsTestPatternGeneratorConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetPcsTestPatternGeneratorConfig (self, channel, direction):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x180
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'pcs_signal_type' : (response[4] & 0xFF),
             'enable' : (response[5] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetPcsTestPatternGeneratorConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetPcsTestPatternCheckerConfig (self, channel, direction, pcs_signal_type, enable):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x181
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)
        command_array[10] = pcs_signal_type>>0
        # assert: (x >= 0 && x <= 2)
        command_array[11] = enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetPcsTestPatternCheckerConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetPcsTestPatternCheckerConfig (self, channel, direction):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x182
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'pcs_signal_type' : (response[4] & 0xFF),
             'enable' : (response[5] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetPcsTestPatternCheckerConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetOtuServerTestPatternGeneratorConfig (self, channel, signal_type, enable):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x17A
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = signal_type>>0
        # assert: (x >= 0 && x <= 11)
        command_array[10] = enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOtuServerTestPatternGeneratorConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetOtuServerTestPatternCheckerConfig (self, channel, signal_type, enable):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x17C
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = signal_type>>0
        # assert: (x >= 0 && x <= 11)
        command_array[10] = enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOtuServerTestPatternCheckerConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetCoreCfecTestPatternCheckerConfig (self, signal_type, enable):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x18B
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = signal_type>>0
        # assert: (x >= 0 && x <= 6)
        command_array[9] = enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetCoreCfecTestPatternCheckerConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetCoreCfecTestPatternGeneratorConfig (self, signal_type, enable):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x189
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = signal_type>>0
        # assert: (x >= 0 && x <= 6)
        command_array[9] = enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetCoreCfecTestPatternGeneratorConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetCoreCfecTestPatternCheckerConfig (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x18C
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'signal_type' : (response[4] & 0xFF),
             'enable' : (response[5] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetCoreCfecTestPatternCheckerConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetCoreCfecTestPatternGeneratorConfig (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x18A
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'signal_type' : (response[4] & 0xFF),
             'enable' : (response[5] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetCoreCfecTestPatternGeneratorConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetLineCfecEvmTestPatternGeneratorConfig (self, signal_type, enable):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x191
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = signal_type>>0
        # assert: (x >= 0 && x <= 6)
        command_array[9] = enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetLineCfecEvmTestPatternGeneratorConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineCfecEvmTestPatternGeneratorConfig (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x192
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'signal_type' : (response[4] & 0xFF),
             'enable' : (response[5] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetLineCfecEvmTestPatternGeneratorConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetHostUnframedTestPatternGeneratorConfig (self, dual, prbs_type_1, prbs_type_2, enable):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x16D
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = dual>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = prbs_type_1>>0
        # assert: (x >= 0 && x <= 2) || (x >= 4 && x <= 7) || (x == 9)
        command_array[10] = prbs_type_2>>0
        # assert: (x >= 0 && x <= 2) || (x >= 4 && x <= 7) || (x == 9)
        command_array[11] = enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetHostUnframedTestPatternGeneratorConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetHostUnframedTestPatternGeneratorConfig (self, dual):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x16E
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = dual>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'prbs_type_1' : (response[4] & 0xFF),
             'prbs_type_2' : (response[5] & 0xFF),
             'enable' : (response[6] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetHostUnframedTestPatternGeneratorConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetHostUnframedTestPatternCheckerConfig (self, dual, prbs_type_1, prbs_type_2, enable):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x16F
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = dual>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = prbs_type_1>>0
        # assert: (x >= 0 && x <= 2) || (x >= 4 && x <= 7) || (x == 9)
        command_array[10] = prbs_type_2>>0
        # assert: (x >= 0 && x <= 2) || (x >= 4 && x <= 7) || (x == 9)
        command_array[11] = enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetHostUnframedTestPatternCheckerConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetHostUnframedTestPatternCheckerConfig (self, dual):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x170
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = dual>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'prbs_type_1' : (response[4] & 0xFF),
             'prbs_type_2' : (response[5] & 0xFF),
             'enable' : (response[6] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetHostUnframedTestPatternCheckerConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtuServerTestPatternGeneratorConfig (self, channel):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x17B
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'signal_type' : (response[4] & 0xFF),
             'enable' : (response[5] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtuServerTestPatternGeneratorConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtuServerTestPatternCheckerConfig (self, channel):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x17D
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'signal_type' : (response[4] & 0xFF),
             'enable' : (response[5] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtuServerTestPatternCheckerConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetOtuClientTestPatternGeneratorConfig (self, channel, direction, signal_type, keep_incoming_fs, enable):
        #Default header
        header=ArgHeader()
        header.Length = 16
        header.Command = 0x176
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*16
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)
        command_array[10] = signal_type>>0
        # assert: (x >= 0 && x <= 11)
        command_array[11] = keep_incoming_fs>>0
        # assert: (x >= 0 && x <= 1)
        command_array[12] = enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOtuClientTestPatternGeneratorConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetOtuClientTestPatternCheckerConfig (self, channel, direction, signal_type, enable):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x178
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)
        command_array[10] = signal_type>>0
        # assert: (x >= 0 && x <= 11)
        command_array[11] = enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOtuClientTestPatternCheckerConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtuClientTestPatternGeneratorConfig (self, channel, direction):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x177
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'signal_type' : (response[4] & 0xFF),
             'enable' : (response[5] & 0xFF),
             'keep_incoming_fs' : (response[6] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtuClientTestPatternGeneratorConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtuClientTestPatternCheckerConfig (self, channel, direction):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x179
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'signal_type' : (response[4] & 0xFF),
             'enable' : (response[5] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtuClientTestPatternCheckerConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetHostUnframedStandardPatternGeneratorConfig (self, dual, standard_type_1, standard_type_2, enable):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x20D
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = dual>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = standard_type_1>>0
        # assert: (x >= 2 && x <= 5)
        command_array[10] = standard_type_2>>0
        # assert: (x >= 2 && x <= 5)
        command_array[11] = enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetHostUnframedStandardPatternGeneratorConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetHostUnframedStandardPatternGeneratorConfig (self, dual):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x20E
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = dual>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'standard_type_1' : (response[4] & 0xFF),
             'standard_type_2' : (response[5] & 0xFF),
             'enable' : (response[6] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetHostUnframedStandardPatternGeneratorConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetHostUnframedCustomPatternGeneratorConfig (self, dual, fixed_pattern_1, fixed_pattern_2, enable):
        #Default header
        header=ArgHeader()
        header.Length = 28
        header.Command = 0x171
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*28
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = dual>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = fixed_pattern_1[0]>>0
        command_array[10] = fixed_pattern_1[1]>>0
        command_array[11] = fixed_pattern_1[2]>>0
        command_array[12] = fixed_pattern_1[3]>>0
        command_array[13] = fixed_pattern_1[4]>>0
        command_array[14] = fixed_pattern_1[5]>>0
        command_array[15] = fixed_pattern_1[6]>>0
        command_array[16] = fixed_pattern_1[7]>>0
        command_array[17] = fixed_pattern_2[0]>>0
        command_array[18] = fixed_pattern_2[1]>>0
        command_array[19] = fixed_pattern_2[2]>>0
        command_array[20] = fixed_pattern_2[3]>>0
        command_array[21] = fixed_pattern_2[4]>>0
        command_array[22] = fixed_pattern_2[5]>>0
        command_array[23] = fixed_pattern_2[6]>>0
        command_array[24] = fixed_pattern_2[7]>>0
        command_array[25] = enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetHostUnframedCustomPatternGeneratorConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetHostUnframedCustomPatternGeneratorConfig (self, dual):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x172
        header.Tag = 0
        header.MaxResponse = 24
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = dual>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'fixed_pattern_1' : [                          (response[4] & 0xFF),
                          (response[5] & 0xFF),
                          (response[6] & 0xFF),
                          (response[7] & 0xFF),
                          (response[8] & 0xFF),
                          (response[9] & 0xFF),
                          (response[10] & 0xFF),
                          (response[11] & 0xFF),
                          ],
             'fixed_pattern_2' : [                          (response[12] & 0xFF),
                          (response[13] & 0xFF),
                          (response[14] & 0xFF),
                          (response[15] & 0xFF),
                          (response[16] & 0xFF),
                          (response[17] & 0xFF),
                          (response[18] & 0xFF),
                          (response[19] & 0xFF),
                          ],
             'enable' : (response[20] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetHostUnframedCustomPatternGeneratorConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetHostUnframedCustomPatternCheckerConfig (self, dual, fixed_pattern_1, fixed_pattern_2, enable):
        #Default header
        header=ArgHeader()
        header.Length = 28
        header.Command = 0x173
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*28
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = dual>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = fixed_pattern_1[0]>>0
        command_array[10] = fixed_pattern_1[1]>>0
        command_array[11] = fixed_pattern_1[2]>>0
        command_array[12] = fixed_pattern_1[3]>>0
        command_array[13] = fixed_pattern_1[4]>>0
        command_array[14] = fixed_pattern_1[5]>>0
        command_array[15] = fixed_pattern_1[6]>>0
        command_array[16] = fixed_pattern_1[7]>>0
        command_array[17] = fixed_pattern_2[0]>>0
        command_array[18] = fixed_pattern_2[1]>>0
        command_array[19] = fixed_pattern_2[2]>>0
        command_array[20] = fixed_pattern_2[3]>>0
        command_array[21] = fixed_pattern_2[4]>>0
        command_array[22] = fixed_pattern_2[5]>>0
        command_array[23] = fixed_pattern_2[6]>>0
        command_array[24] = fixed_pattern_2[7]>>0
        command_array[25] = enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetHostUnframedCustomPatternCheckerConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetHostUnframedCustomPatternCheckerConfig (self, dual):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x174
        header.Tag = 0
        header.MaxResponse = 24
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = dual>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'fixed_pattern_1' : [                          (response[4] & 0xFF),
                          (response[5] & 0xFF),
                          (response[6] & 0xFF),
                          (response[7] & 0xFF),
                          (response[8] & 0xFF),
                          (response[9] & 0xFF),
                          (response[10] & 0xFF),
                          (response[11] & 0xFF),
                          ],
             'fixed_pattern_2' : [                          (response[12] & 0xFF),
                          (response[13] & 0xFF),
                          (response[14] & 0xFF),
                          (response[15] & 0xFF),
                          (response[16] & 0xFF),
                          (response[17] & 0xFF),
                          (response[18] & 0xFF),
                          (response[19] & 0xFF),
                          ],
             'enable' : (response[20] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetHostUnframedCustomPatternCheckerConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetHostUnframedTestPatternCheckerStatistics (self, lane):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x175
        header.Tag = 0
        header.MaxResponse = 20
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 7)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'bit_count' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24))|((response[8]<<32) & (0xFF<<32))|((response[9]<<40) & (0xFF<<40))|((response[10]<<48) & (0xFF<<48))|((response[11]<<56) & (0xFF<<56)),
             'error_count' : (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8))|((response[14]<<16) & (0xFF<<16))|((response[15]<<24) & (0xFF<<24)),
             'sync_status' : (response[16] & 0xFF),
             'saturated' : (response[17] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetHostUnframedTestPatternCheckerStatistics)
        self.add_api_exec_cb()
        return apiResponse

    def SetLineSdfecUnframedTestPatternGeneratorConfig (self, pattern, seed, enable):
        #Default header
        header=ArgHeader()
        header.Length = 84
        header.Command = 0x184
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*84
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = pattern[0]>>0
        # assert: (x >= 0 && x <= 11)
        command_array[9] = pattern[1]>>0
        # assert: (x >= 0 && x <= 11)
        command_array[10] = pattern[2]>>0
        # assert: (x >= 0 && x <= 11)
        command_array[11] = pattern[3]>>0
        # assert: (x >= 0 && x <= 11)
        command_array[12] = pattern[4]>>0
        # assert: (x >= 0 && x <= 11)
        command_array[13] = pattern[5]>>0
        # assert: (x >= 0 && x <= 11)
        command_array[14] = pattern[6]>>0
        # assert: (x >= 0 && x <= 11)
        command_array[15] = pattern[7]>>0
        # assert: (x >= 0 && x <= 11)
        command_array[16] = seed[0]>>0
        command_array[17] = seed[0]>>8
        command_array[18] = seed[0]>>16
        command_array[19] = seed[0]>>24
        command_array[20] = seed[0]>>32
        command_array[21] = seed[0]>>40
        command_array[22] = seed[0]>>48
        command_array[23] = seed[0]>>56
        # assert: (x < 0x7FFFFFFFFFFFULL)
        command_array[24] = seed[1]>>0
        command_array[25] = seed[1]>>8
        command_array[26] = seed[1]>>16
        command_array[27] = seed[1]>>24
        command_array[28] = seed[1]>>32
        command_array[29] = seed[1]>>40
        command_array[30] = seed[1]>>48
        command_array[31] = seed[1]>>56
        # assert: (x < 0x7FFFFFFFFFFFULL)
        command_array[32] = seed[2]>>0
        command_array[33] = seed[2]>>8
        command_array[34] = seed[2]>>16
        command_array[35] = seed[2]>>24
        command_array[36] = seed[2]>>32
        command_array[37] = seed[2]>>40
        command_array[38] = seed[2]>>48
        command_array[39] = seed[2]>>56
        # assert: (x < 0x7FFFFFFFFFFFULL)
        command_array[40] = seed[3]>>0
        command_array[41] = seed[3]>>8
        command_array[42] = seed[3]>>16
        command_array[43] = seed[3]>>24
        command_array[44] = seed[3]>>32
        command_array[45] = seed[3]>>40
        command_array[46] = seed[3]>>48
        command_array[47] = seed[3]>>56
        # assert: (x < 0x7FFFFFFFFFFFULL)
        command_array[48] = seed[4]>>0
        command_array[49] = seed[4]>>8
        command_array[50] = seed[4]>>16
        command_array[51] = seed[4]>>24
        command_array[52] = seed[4]>>32
        command_array[53] = seed[4]>>40
        command_array[54] = seed[4]>>48
        command_array[55] = seed[4]>>56
        # assert: (x < 0x7FFFFFFFFFFFULL)
        command_array[56] = seed[5]>>0
        command_array[57] = seed[5]>>8
        command_array[58] = seed[5]>>16
        command_array[59] = seed[5]>>24
        command_array[60] = seed[5]>>32
        command_array[61] = seed[5]>>40
        command_array[62] = seed[5]>>48
        command_array[63] = seed[5]>>56
        # assert: (x < 0x7FFFFFFFFFFFULL)
        command_array[64] = seed[6]>>0
        command_array[65] = seed[6]>>8
        command_array[66] = seed[6]>>16
        command_array[67] = seed[6]>>24
        command_array[68] = seed[6]>>32
        command_array[69] = seed[6]>>40
        command_array[70] = seed[6]>>48
        command_array[71] = seed[6]>>56
        # assert: (x < 0x7FFFFFFFFFFFULL)
        command_array[72] = seed[7]>>0
        command_array[73] = seed[7]>>8
        command_array[74] = seed[7]>>16
        command_array[75] = seed[7]>>24
        command_array[76] = seed[7]>>32
        command_array[77] = seed[7]>>40
        command_array[78] = seed[7]>>48
        command_array[79] = seed[7]>>56
        # assert: (x < 0x7FFFFFFFFFFFULL)
        command_array[80] = enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetLineSdfecUnframedTestPatternGeneratorConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineSdfecUnframedTestPatternGeneratorConfig (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x185
        header.Tag = 0
        header.MaxResponse = 80
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'pattern' : [                          (response[4] & 0xFF),
                          (response[5] & 0xFF),
                          (response[6] & 0xFF),
                          (response[7] & 0xFF),
                          (response[8] & 0xFF),
                          (response[9] & 0xFF),
                          (response[10] & 0xFF),
                          (response[11] & 0xFF),
                          ],
             'seed' : [                          (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8))|((response[14]<<16) & (0xFF<<16))|((response[15]<<24) & (0xFF<<24))|((response[16]<<32) & (0xFF<<32))|((response[17]<<40) & (0xFF<<40))|((response[18]<<48) & (0xFF<<48))|((response[19]<<56) & (0xFF<<56)),
                          (response[20] & 0xFF)|((response[21]<<8) & (0xFF<<8))|((response[22]<<16) & (0xFF<<16))|((response[23]<<24) & (0xFF<<24))|((response[24]<<32) & (0xFF<<32))|((response[25]<<40) & (0xFF<<40))|((response[26]<<48) & (0xFF<<48))|((response[27]<<56) & (0xFF<<56)),
                          (response[28] & 0xFF)|((response[29]<<8) & (0xFF<<8))|((response[30]<<16) & (0xFF<<16))|((response[31]<<24) & (0xFF<<24))|((response[32]<<32) & (0xFF<<32))|((response[33]<<40) & (0xFF<<40))|((response[34]<<48) & (0xFF<<48))|((response[35]<<56) & (0xFF<<56)),
                          (response[36] & 0xFF)|((response[37]<<8) & (0xFF<<8))|((response[38]<<16) & (0xFF<<16))|((response[39]<<24) & (0xFF<<24))|((response[40]<<32) & (0xFF<<32))|((response[41]<<40) & (0xFF<<40))|((response[42]<<48) & (0xFF<<48))|((response[43]<<56) & (0xFF<<56)),
                          (response[44] & 0xFF)|((response[45]<<8) & (0xFF<<8))|((response[46]<<16) & (0xFF<<16))|((response[47]<<24) & (0xFF<<24))|((response[48]<<32) & (0xFF<<32))|((response[49]<<40) & (0xFF<<40))|((response[50]<<48) & (0xFF<<48))|((response[51]<<56) & (0xFF<<56)),
                          (response[52] & 0xFF)|((response[53]<<8) & (0xFF<<8))|((response[54]<<16) & (0xFF<<16))|((response[55]<<24) & (0xFF<<24))|((response[56]<<32) & (0xFF<<32))|((response[57]<<40) & (0xFF<<40))|((response[58]<<48) & (0xFF<<48))|((response[59]<<56) & (0xFF<<56)),
                          (response[60] & 0xFF)|((response[61]<<8) & (0xFF<<8))|((response[62]<<16) & (0xFF<<16))|((response[63]<<24) & (0xFF<<24))|((response[64]<<32) & (0xFF<<32))|((response[65]<<40) & (0xFF<<40))|((response[66]<<48) & (0xFF<<48))|((response[67]<<56) & (0xFF<<56)),
                          (response[68] & 0xFF)|((response[69]<<8) & (0xFF<<8))|((response[70]<<16) & (0xFF<<16))|((response[71]<<24) & (0xFF<<24))|((response[72]<<32) & (0xFF<<32))|((response[73]<<40) & (0xFF<<40))|((response[74]<<48) & (0xFF<<48))|((response[75]<<56) & (0xFF<<56)),
                          ],
             'enable' : (response[76] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetLineSdfecUnframedTestPatternGeneratorConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetLineSdfecUnframedTestPatternCheckerConfig (self, pattern, enable):
        #Default header
        header=ArgHeader()
        header.Length = 20
        header.Command = 0x186
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*20
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = pattern[0]>>0
        # assert: (x >= 0 && x <= 11)
        command_array[9] = pattern[1]>>0
        # assert: (x >= 0 && x <= 11)
        command_array[10] = pattern[2]>>0
        # assert: (x >= 0 && x <= 11)
        command_array[11] = pattern[3]>>0
        # assert: (x >= 0 && x <= 11)
        command_array[12] = pattern[4]>>0
        # assert: (x >= 0 && x <= 11)
        command_array[13] = pattern[5]>>0
        # assert: (x >= 0 && x <= 11)
        command_array[14] = pattern[6]>>0
        # assert: (x >= 0 && x <= 11)
        command_array[15] = pattern[7]>>0
        # assert: (x >= 0 && x <= 11)
        command_array[16] = enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetLineSdfecUnframedTestPatternCheckerConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineSdfecUnframedTestPatternCheckerConfig (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x187
        header.Tag = 0
        header.MaxResponse = 16
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'pattern' : [                          (response[4] & 0xFF),
                          (response[5] & 0xFF),
                          (response[6] & 0xFF),
                          (response[7] & 0xFF),
                          (response[8] & 0xFF),
                          (response[9] & 0xFF),
                          (response[10] & 0xFF),
                          (response[11] & 0xFF),
                          ],
             'enable' : (response[12] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetLineSdfecUnframedTestPatternCheckerConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineSdfecUnframedTestPatternCheckerCounters (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x188
        header.Tag = 0
        header.MaxResponse = 164
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'bit_count' : [                          (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24))|((response[8]<<32) & (0xFF<<32))|((response[9]<<40) & (0xFF<<40))|((response[10]<<48) & (0xFF<<48))|((response[11]<<56) & (0xFF<<56)),
                          (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8))|((response[14]<<16) & (0xFF<<16))|((response[15]<<24) & (0xFF<<24))|((response[16]<<32) & (0xFF<<32))|((response[17]<<40) & (0xFF<<40))|((response[18]<<48) & (0xFF<<48))|((response[19]<<56) & (0xFF<<56)),
                          (response[20] & 0xFF)|((response[21]<<8) & (0xFF<<8))|((response[22]<<16) & (0xFF<<16))|((response[23]<<24) & (0xFF<<24))|((response[24]<<32) & (0xFF<<32))|((response[25]<<40) & (0xFF<<40))|((response[26]<<48) & (0xFF<<48))|((response[27]<<56) & (0xFF<<56)),
                          (response[28] & 0xFF)|((response[29]<<8) & (0xFF<<8))|((response[30]<<16) & (0xFF<<16))|((response[31]<<24) & (0xFF<<24))|((response[32]<<32) & (0xFF<<32))|((response[33]<<40) & (0xFF<<40))|((response[34]<<48) & (0xFF<<48))|((response[35]<<56) & (0xFF<<56)),
                          (response[36] & 0xFF)|((response[37]<<8) & (0xFF<<8))|((response[38]<<16) & (0xFF<<16))|((response[39]<<24) & (0xFF<<24))|((response[40]<<32) & (0xFF<<32))|((response[41]<<40) & (0xFF<<40))|((response[42]<<48) & (0xFF<<48))|((response[43]<<56) & (0xFF<<56)),
                          (response[44] & 0xFF)|((response[45]<<8) & (0xFF<<8))|((response[46]<<16) & (0xFF<<16))|((response[47]<<24) & (0xFF<<24))|((response[48]<<32) & (0xFF<<32))|((response[49]<<40) & (0xFF<<40))|((response[50]<<48) & (0xFF<<48))|((response[51]<<56) & (0xFF<<56)),
                          (response[52] & 0xFF)|((response[53]<<8) & (0xFF<<8))|((response[54]<<16) & (0xFF<<16))|((response[55]<<24) & (0xFF<<24))|((response[56]<<32) & (0xFF<<32))|((response[57]<<40) & (0xFF<<40))|((response[58]<<48) & (0xFF<<48))|((response[59]<<56) & (0xFF<<56)),
                          (response[60] & 0xFF)|((response[61]<<8) & (0xFF<<8))|((response[62]<<16) & (0xFF<<16))|((response[63]<<24) & (0xFF<<24))|((response[64]<<32) & (0xFF<<32))|((response[65]<<40) & (0xFF<<40))|((response[66]<<48) & (0xFF<<48))|((response[67]<<56) & (0xFF<<56)),
                          ],
             'error_count' : [                          (response[68] & 0xFF)|((response[69]<<8) & (0xFF<<8))|((response[70]<<16) & (0xFF<<16))|((response[71]<<24) & (0xFF<<24))|((response[72]<<32) & (0xFF<<32))|((response[73]<<40) & (0xFF<<40))|((response[74]<<48) & (0xFF<<48))|((response[75]<<56) & (0xFF<<56)),
                          (response[76] & 0xFF)|((response[77]<<8) & (0xFF<<8))|((response[78]<<16) & (0xFF<<16))|((response[79]<<24) & (0xFF<<24))|((response[80]<<32) & (0xFF<<32))|((response[81]<<40) & (0xFF<<40))|((response[82]<<48) & (0xFF<<48))|((response[83]<<56) & (0xFF<<56)),
                          (response[84] & 0xFF)|((response[85]<<8) & (0xFF<<8))|((response[86]<<16) & (0xFF<<16))|((response[87]<<24) & (0xFF<<24))|((response[88]<<32) & (0xFF<<32))|((response[89]<<40) & (0xFF<<40))|((response[90]<<48) & (0xFF<<48))|((response[91]<<56) & (0xFF<<56)),
                          (response[92] & 0xFF)|((response[93]<<8) & (0xFF<<8))|((response[94]<<16) & (0xFF<<16))|((response[95]<<24) & (0xFF<<24))|((response[96]<<32) & (0xFF<<32))|((response[97]<<40) & (0xFF<<40))|((response[98]<<48) & (0xFF<<48))|((response[99]<<56) & (0xFF<<56)),
                          (response[100] & 0xFF)|((response[101]<<8) & (0xFF<<8))|((response[102]<<16) & (0xFF<<16))|((response[103]<<24) & (0xFF<<24))|((response[104]<<32) & (0xFF<<32))|((response[105]<<40) & (0xFF<<40))|((response[106]<<48) & (0xFF<<48))|((response[107]<<56) & (0xFF<<56)),
                          (response[108] & 0xFF)|((response[109]<<8) & (0xFF<<8))|((response[110]<<16) & (0xFF<<16))|((response[111]<<24) & (0xFF<<24))|((response[112]<<32) & (0xFF<<32))|((response[113]<<40) & (0xFF<<40))|((response[114]<<48) & (0xFF<<48))|((response[115]<<56) & (0xFF<<56)),
                          (response[116] & 0xFF)|((response[117]<<8) & (0xFF<<8))|((response[118]<<16) & (0xFF<<16))|((response[119]<<24) & (0xFF<<24))|((response[120]<<32) & (0xFF<<32))|((response[121]<<40) & (0xFF<<40))|((response[122]<<48) & (0xFF<<48))|((response[123]<<56) & (0xFF<<56)),
                          (response[124] & 0xFF)|((response[125]<<8) & (0xFF<<8))|((response[126]<<16) & (0xFF<<16))|((response[127]<<24) & (0xFF<<24))|((response[128]<<32) & (0xFF<<32))|((response[129]<<40) & (0xFF<<40))|((response[130]<<48) & (0xFF<<48))|((response[131]<<56) & (0xFF<<56)),
                          ],
             'resync_count' : [                          (response[132] & 0xFF)|((response[133]<<8) & (0xFF<<8)),
                          (response[134] & 0xFF)|((response[135]<<8) & (0xFF<<8)),
                          (response[136] & 0xFF)|((response[137]<<8) & (0xFF<<8)),
                          (response[138] & 0xFF)|((response[139]<<8) & (0xFF<<8)),
                          (response[140] & 0xFF)|((response[141]<<8) & (0xFF<<8)),
                          (response[142] & 0xFF)|((response[143]<<8) & (0xFF<<8)),
                          (response[144] & 0xFF)|((response[145]<<8) & (0xFF<<8)),
                          (response[146] & 0xFF)|((response[147]<<8) & (0xFF<<8)),
                          ],
             'lock_count' : [                          (response[148] & 0xFF)|((response[149]<<8) & (0xFF<<8)),
                          (response[150] & 0xFF)|((response[151]<<8) & (0xFF<<8)),
                          (response[152] & 0xFF)|((response[153]<<8) & (0xFF<<8)),
                          (response[154] & 0xFF)|((response[155]<<8) & (0xFF<<8)),
                          (response[156] & 0xFF)|((response[157]<<8) & (0xFF<<8)),
                          (response[158] & 0xFF)|((response[159]<<8) & (0xFF<<8)),
                          (response[160] & 0xFF)|((response[161]<<8) & (0xFF<<8)),
                          (response[162] & 0xFF)|((response[163]<<8) & (0xFF<<8)),
                          ],
        }
        self.check_response(apiResponse, CanopusApi.GetLineSdfecUnframedTestPatternCheckerCounters)
        self.add_api_exec_cb()
        return apiResponse

    def SetLineSdfecCustomPatternGeneratorConfig (self, pattern, enable):
        #Default header
        header=ArgHeader()
        header.Length = 396
        header.Command = 0x193
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*396
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = pattern[0]>>0
        command_array[9] = pattern[0]>>8
        command_array[10] = pattern[0]>>16
        command_array[11] = pattern[0]>>24
        command_array[12] = pattern[1]>>0
        command_array[13] = pattern[1]>>8
        command_array[14] = pattern[1]>>16
        command_array[15] = pattern[1]>>24
        command_array[16] = pattern[2]>>0
        command_array[17] = pattern[2]>>8
        command_array[18] = pattern[2]>>16
        command_array[19] = pattern[2]>>24
        command_array[20] = pattern[3]>>0
        command_array[21] = pattern[3]>>8
        command_array[22] = pattern[3]>>16
        command_array[23] = pattern[3]>>24
        command_array[24] = pattern[4]>>0
        command_array[25] = pattern[4]>>8
        command_array[26] = pattern[4]>>16
        command_array[27] = pattern[4]>>24
        command_array[28] = pattern[5]>>0
        command_array[29] = pattern[5]>>8
        command_array[30] = pattern[5]>>16
        command_array[31] = pattern[5]>>24
        command_array[32] = pattern[6]>>0
        command_array[33] = pattern[6]>>8
        command_array[34] = pattern[6]>>16
        command_array[35] = pattern[6]>>24
        command_array[36] = pattern[7]>>0
        command_array[37] = pattern[7]>>8
        command_array[38] = pattern[7]>>16
        command_array[39] = pattern[7]>>24
        command_array[40] = pattern[8]>>0
        command_array[41] = pattern[8]>>8
        command_array[42] = pattern[8]>>16
        command_array[43] = pattern[8]>>24
        command_array[44] = pattern[9]>>0
        command_array[45] = pattern[9]>>8
        command_array[46] = pattern[9]>>16
        command_array[47] = pattern[9]>>24
        command_array[48] = pattern[10]>>0
        command_array[49] = pattern[10]>>8
        command_array[50] = pattern[10]>>16
        command_array[51] = pattern[10]>>24
        command_array[52] = pattern[11]>>0
        command_array[53] = pattern[11]>>8
        command_array[54] = pattern[11]>>16
        command_array[55] = pattern[11]>>24
        command_array[56] = pattern[12]>>0
        command_array[57] = pattern[12]>>8
        command_array[58] = pattern[12]>>16
        command_array[59] = pattern[12]>>24
        command_array[60] = pattern[13]>>0
        command_array[61] = pattern[13]>>8
        command_array[62] = pattern[13]>>16
        command_array[63] = pattern[13]>>24
        command_array[64] = pattern[14]>>0
        command_array[65] = pattern[14]>>8
        command_array[66] = pattern[14]>>16
        command_array[67] = pattern[14]>>24
        command_array[68] = pattern[15]>>0
        command_array[69] = pattern[15]>>8
        command_array[70] = pattern[15]>>16
        command_array[71] = pattern[15]>>24
        command_array[72] = pattern[16]>>0
        command_array[73] = pattern[16]>>8
        command_array[74] = pattern[16]>>16
        command_array[75] = pattern[16]>>24
        command_array[76] = pattern[17]>>0
        command_array[77] = pattern[17]>>8
        command_array[78] = pattern[17]>>16
        command_array[79] = pattern[17]>>24
        command_array[80] = pattern[18]>>0
        command_array[81] = pattern[18]>>8
        command_array[82] = pattern[18]>>16
        command_array[83] = pattern[18]>>24
        command_array[84] = pattern[19]>>0
        command_array[85] = pattern[19]>>8
        command_array[86] = pattern[19]>>16
        command_array[87] = pattern[19]>>24
        command_array[88] = pattern[20]>>0
        command_array[89] = pattern[20]>>8
        command_array[90] = pattern[20]>>16
        command_array[91] = pattern[20]>>24
        command_array[92] = pattern[21]>>0
        command_array[93] = pattern[21]>>8
        command_array[94] = pattern[21]>>16
        command_array[95] = pattern[21]>>24
        command_array[96] = pattern[22]>>0
        command_array[97] = pattern[22]>>8
        command_array[98] = pattern[22]>>16
        command_array[99] = pattern[22]>>24
        command_array[100] = pattern[23]>>0
        command_array[101] = pattern[23]>>8
        command_array[102] = pattern[23]>>16
        command_array[103] = pattern[23]>>24
        command_array[104] = pattern[24]>>0
        command_array[105] = pattern[24]>>8
        command_array[106] = pattern[24]>>16
        command_array[107] = pattern[24]>>24
        command_array[108] = pattern[25]>>0
        command_array[109] = pattern[25]>>8
        command_array[110] = pattern[25]>>16
        command_array[111] = pattern[25]>>24
        command_array[112] = pattern[26]>>0
        command_array[113] = pattern[26]>>8
        command_array[114] = pattern[26]>>16
        command_array[115] = pattern[26]>>24
        command_array[116] = pattern[27]>>0
        command_array[117] = pattern[27]>>8
        command_array[118] = pattern[27]>>16
        command_array[119] = pattern[27]>>24
        command_array[120] = pattern[28]>>0
        command_array[121] = pattern[28]>>8
        command_array[122] = pattern[28]>>16
        command_array[123] = pattern[28]>>24
        command_array[124] = pattern[29]>>0
        command_array[125] = pattern[29]>>8
        command_array[126] = pattern[29]>>16
        command_array[127] = pattern[29]>>24
        command_array[128] = pattern[30]>>0
        command_array[129] = pattern[30]>>8
        command_array[130] = pattern[30]>>16
        command_array[131] = pattern[30]>>24
        command_array[132] = pattern[31]>>0
        command_array[133] = pattern[31]>>8
        command_array[134] = pattern[31]>>16
        command_array[135] = pattern[31]>>24
        command_array[136] = pattern[32]>>0
        command_array[137] = pattern[32]>>8
        command_array[138] = pattern[32]>>16
        command_array[139] = pattern[32]>>24
        command_array[140] = pattern[33]>>0
        command_array[141] = pattern[33]>>8
        command_array[142] = pattern[33]>>16
        command_array[143] = pattern[33]>>24
        command_array[144] = pattern[34]>>0
        command_array[145] = pattern[34]>>8
        command_array[146] = pattern[34]>>16
        command_array[147] = pattern[34]>>24
        command_array[148] = pattern[35]>>0
        command_array[149] = pattern[35]>>8
        command_array[150] = pattern[35]>>16
        command_array[151] = pattern[35]>>24
        command_array[152] = pattern[36]>>0
        command_array[153] = pattern[36]>>8
        command_array[154] = pattern[36]>>16
        command_array[155] = pattern[36]>>24
        command_array[156] = pattern[37]>>0
        command_array[157] = pattern[37]>>8
        command_array[158] = pattern[37]>>16
        command_array[159] = pattern[37]>>24
        command_array[160] = pattern[38]>>0
        command_array[161] = pattern[38]>>8
        command_array[162] = pattern[38]>>16
        command_array[163] = pattern[38]>>24
        command_array[164] = pattern[39]>>0
        command_array[165] = pattern[39]>>8
        command_array[166] = pattern[39]>>16
        command_array[167] = pattern[39]>>24
        command_array[168] = pattern[40]>>0
        command_array[169] = pattern[40]>>8
        command_array[170] = pattern[40]>>16
        command_array[171] = pattern[40]>>24
        command_array[172] = pattern[41]>>0
        command_array[173] = pattern[41]>>8
        command_array[174] = pattern[41]>>16
        command_array[175] = pattern[41]>>24
        command_array[176] = pattern[42]>>0
        command_array[177] = pattern[42]>>8
        command_array[178] = pattern[42]>>16
        command_array[179] = pattern[42]>>24
        command_array[180] = pattern[43]>>0
        command_array[181] = pattern[43]>>8
        command_array[182] = pattern[43]>>16
        command_array[183] = pattern[43]>>24
        command_array[184] = pattern[44]>>0
        command_array[185] = pattern[44]>>8
        command_array[186] = pattern[44]>>16
        command_array[187] = pattern[44]>>24
        command_array[188] = pattern[45]>>0
        command_array[189] = pattern[45]>>8
        command_array[190] = pattern[45]>>16
        command_array[191] = pattern[45]>>24
        command_array[192] = pattern[46]>>0
        command_array[193] = pattern[46]>>8
        command_array[194] = pattern[46]>>16
        command_array[195] = pattern[46]>>24
        command_array[196] = pattern[47]>>0
        command_array[197] = pattern[47]>>8
        command_array[198] = pattern[47]>>16
        command_array[199] = pattern[47]>>24
        command_array[200] = pattern[48]>>0
        command_array[201] = pattern[48]>>8
        command_array[202] = pattern[48]>>16
        command_array[203] = pattern[48]>>24
        command_array[204] = pattern[49]>>0
        command_array[205] = pattern[49]>>8
        command_array[206] = pattern[49]>>16
        command_array[207] = pattern[49]>>24
        command_array[208] = pattern[50]>>0
        command_array[209] = pattern[50]>>8
        command_array[210] = pattern[50]>>16
        command_array[211] = pattern[50]>>24
        command_array[212] = pattern[51]>>0
        command_array[213] = pattern[51]>>8
        command_array[214] = pattern[51]>>16
        command_array[215] = pattern[51]>>24
        command_array[216] = pattern[52]>>0
        command_array[217] = pattern[52]>>8
        command_array[218] = pattern[52]>>16
        command_array[219] = pattern[52]>>24
        command_array[220] = pattern[53]>>0
        command_array[221] = pattern[53]>>8
        command_array[222] = pattern[53]>>16
        command_array[223] = pattern[53]>>24
        command_array[224] = pattern[54]>>0
        command_array[225] = pattern[54]>>8
        command_array[226] = pattern[54]>>16
        command_array[227] = pattern[54]>>24
        command_array[228] = pattern[55]>>0
        command_array[229] = pattern[55]>>8
        command_array[230] = pattern[55]>>16
        command_array[231] = pattern[55]>>24
        command_array[232] = pattern[56]>>0
        command_array[233] = pattern[56]>>8
        command_array[234] = pattern[56]>>16
        command_array[235] = pattern[56]>>24
        command_array[236] = pattern[57]>>0
        command_array[237] = pattern[57]>>8
        command_array[238] = pattern[57]>>16
        command_array[239] = pattern[57]>>24
        command_array[240] = pattern[58]>>0
        command_array[241] = pattern[58]>>8
        command_array[242] = pattern[58]>>16
        command_array[243] = pattern[58]>>24
        command_array[244] = pattern[59]>>0
        command_array[245] = pattern[59]>>8
        command_array[246] = pattern[59]>>16
        command_array[247] = pattern[59]>>24
        command_array[248] = pattern[60]>>0
        command_array[249] = pattern[60]>>8
        command_array[250] = pattern[60]>>16
        command_array[251] = pattern[60]>>24
        command_array[252] = pattern[61]>>0
        command_array[253] = pattern[61]>>8
        command_array[254] = pattern[61]>>16
        command_array[255] = pattern[61]>>24
        command_array[256] = pattern[62]>>0
        command_array[257] = pattern[62]>>8
        command_array[258] = pattern[62]>>16
        command_array[259] = pattern[62]>>24
        command_array[260] = pattern[63]>>0
        command_array[261] = pattern[63]>>8
        command_array[262] = pattern[63]>>16
        command_array[263] = pattern[63]>>24
        command_array[264] = pattern[64]>>0
        command_array[265] = pattern[64]>>8
        command_array[266] = pattern[64]>>16
        command_array[267] = pattern[64]>>24
        command_array[268] = pattern[65]>>0
        command_array[269] = pattern[65]>>8
        command_array[270] = pattern[65]>>16
        command_array[271] = pattern[65]>>24
        command_array[272] = pattern[66]>>0
        command_array[273] = pattern[66]>>8
        command_array[274] = pattern[66]>>16
        command_array[275] = pattern[66]>>24
        command_array[276] = pattern[67]>>0
        command_array[277] = pattern[67]>>8
        command_array[278] = pattern[67]>>16
        command_array[279] = pattern[67]>>24
        command_array[280] = pattern[68]>>0
        command_array[281] = pattern[68]>>8
        command_array[282] = pattern[68]>>16
        command_array[283] = pattern[68]>>24
        command_array[284] = pattern[69]>>0
        command_array[285] = pattern[69]>>8
        command_array[286] = pattern[69]>>16
        command_array[287] = pattern[69]>>24
        command_array[288] = pattern[70]>>0
        command_array[289] = pattern[70]>>8
        command_array[290] = pattern[70]>>16
        command_array[291] = pattern[70]>>24
        command_array[292] = pattern[71]>>0
        command_array[293] = pattern[71]>>8
        command_array[294] = pattern[71]>>16
        command_array[295] = pattern[71]>>24
        command_array[296] = pattern[72]>>0
        command_array[297] = pattern[72]>>8
        command_array[298] = pattern[72]>>16
        command_array[299] = pattern[72]>>24
        command_array[300] = pattern[73]>>0
        command_array[301] = pattern[73]>>8
        command_array[302] = pattern[73]>>16
        command_array[303] = pattern[73]>>24
        command_array[304] = pattern[74]>>0
        command_array[305] = pattern[74]>>8
        command_array[306] = pattern[74]>>16
        command_array[307] = pattern[74]>>24
        command_array[308] = pattern[75]>>0
        command_array[309] = pattern[75]>>8
        command_array[310] = pattern[75]>>16
        command_array[311] = pattern[75]>>24
        command_array[312] = pattern[76]>>0
        command_array[313] = pattern[76]>>8
        command_array[314] = pattern[76]>>16
        command_array[315] = pattern[76]>>24
        command_array[316] = pattern[77]>>0
        command_array[317] = pattern[77]>>8
        command_array[318] = pattern[77]>>16
        command_array[319] = pattern[77]>>24
        command_array[320] = pattern[78]>>0
        command_array[321] = pattern[78]>>8
        command_array[322] = pattern[78]>>16
        command_array[323] = pattern[78]>>24
        command_array[324] = pattern[79]>>0
        command_array[325] = pattern[79]>>8
        command_array[326] = pattern[79]>>16
        command_array[327] = pattern[79]>>24
        command_array[328] = pattern[80]>>0
        command_array[329] = pattern[80]>>8
        command_array[330] = pattern[80]>>16
        command_array[331] = pattern[80]>>24
        command_array[332] = pattern[81]>>0
        command_array[333] = pattern[81]>>8
        command_array[334] = pattern[81]>>16
        command_array[335] = pattern[81]>>24
        command_array[336] = pattern[82]>>0
        command_array[337] = pattern[82]>>8
        command_array[338] = pattern[82]>>16
        command_array[339] = pattern[82]>>24
        command_array[340] = pattern[83]>>0
        command_array[341] = pattern[83]>>8
        command_array[342] = pattern[83]>>16
        command_array[343] = pattern[83]>>24
        command_array[344] = pattern[84]>>0
        command_array[345] = pattern[84]>>8
        command_array[346] = pattern[84]>>16
        command_array[347] = pattern[84]>>24
        command_array[348] = pattern[85]>>0
        command_array[349] = pattern[85]>>8
        command_array[350] = pattern[85]>>16
        command_array[351] = pattern[85]>>24
        command_array[352] = pattern[86]>>0
        command_array[353] = pattern[86]>>8
        command_array[354] = pattern[86]>>16
        command_array[355] = pattern[86]>>24
        command_array[356] = pattern[87]>>0
        command_array[357] = pattern[87]>>8
        command_array[358] = pattern[87]>>16
        command_array[359] = pattern[87]>>24
        command_array[360] = pattern[88]>>0
        command_array[361] = pattern[88]>>8
        command_array[362] = pattern[88]>>16
        command_array[363] = pattern[88]>>24
        command_array[364] = pattern[89]>>0
        command_array[365] = pattern[89]>>8
        command_array[366] = pattern[89]>>16
        command_array[367] = pattern[89]>>24
        command_array[368] = pattern[90]>>0
        command_array[369] = pattern[90]>>8
        command_array[370] = pattern[90]>>16
        command_array[371] = pattern[90]>>24
        command_array[372] = pattern[91]>>0
        command_array[373] = pattern[91]>>8
        command_array[374] = pattern[91]>>16
        command_array[375] = pattern[91]>>24
        command_array[376] = pattern[92]>>0
        command_array[377] = pattern[92]>>8
        command_array[378] = pattern[92]>>16
        command_array[379] = pattern[92]>>24
        command_array[380] = pattern[93]>>0
        command_array[381] = pattern[93]>>8
        command_array[382] = pattern[93]>>16
        command_array[383] = pattern[93]>>24
        command_array[384] = pattern[94]>>0
        command_array[385] = pattern[94]>>8
        command_array[386] = pattern[94]>>16
        command_array[387] = pattern[94]>>24
        command_array[388] = pattern[95]>>0
        command_array[389] = pattern[95]>>8
        command_array[390] = pattern[95]>>16
        command_array[391] = pattern[95]>>24
        command_array[392] = enable>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetLineSdfecCustomPatternGeneratorConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineSdfecCustomPatternGeneratorConfig (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x194
        header.Tag = 0
        header.MaxResponse = 392
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'pattern' : [                          (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24)),
                          (response[8] & 0xFF)|((response[9]<<8) & (0xFF<<8))|((response[10]<<16) & (0xFF<<16))|((response[11]<<24) & (0xFF<<24)),
                          (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8))|((response[14]<<16) & (0xFF<<16))|((response[15]<<24) & (0xFF<<24)),
                          (response[16] & 0xFF)|((response[17]<<8) & (0xFF<<8))|((response[18]<<16) & (0xFF<<16))|((response[19]<<24) & (0xFF<<24)),
                          (response[20] & 0xFF)|((response[21]<<8) & (0xFF<<8))|((response[22]<<16) & (0xFF<<16))|((response[23]<<24) & (0xFF<<24)),
                          (response[24] & 0xFF)|((response[25]<<8) & (0xFF<<8))|((response[26]<<16) & (0xFF<<16))|((response[27]<<24) & (0xFF<<24)),
                          (response[28] & 0xFF)|((response[29]<<8) & (0xFF<<8))|((response[30]<<16) & (0xFF<<16))|((response[31]<<24) & (0xFF<<24)),
                          (response[32] & 0xFF)|((response[33]<<8) & (0xFF<<8))|((response[34]<<16) & (0xFF<<16))|((response[35]<<24) & (0xFF<<24)),
                          (response[36] & 0xFF)|((response[37]<<8) & (0xFF<<8))|((response[38]<<16) & (0xFF<<16))|((response[39]<<24) & (0xFF<<24)),
                          (response[40] & 0xFF)|((response[41]<<8) & (0xFF<<8))|((response[42]<<16) & (0xFF<<16))|((response[43]<<24) & (0xFF<<24)),
                          (response[44] & 0xFF)|((response[45]<<8) & (0xFF<<8))|((response[46]<<16) & (0xFF<<16))|((response[47]<<24) & (0xFF<<24)),
                          (response[48] & 0xFF)|((response[49]<<8) & (0xFF<<8))|((response[50]<<16) & (0xFF<<16))|((response[51]<<24) & (0xFF<<24)),
                          (response[52] & 0xFF)|((response[53]<<8) & (0xFF<<8))|((response[54]<<16) & (0xFF<<16))|((response[55]<<24) & (0xFF<<24)),
                          (response[56] & 0xFF)|((response[57]<<8) & (0xFF<<8))|((response[58]<<16) & (0xFF<<16))|((response[59]<<24) & (0xFF<<24)),
                          (response[60] & 0xFF)|((response[61]<<8) & (0xFF<<8))|((response[62]<<16) & (0xFF<<16))|((response[63]<<24) & (0xFF<<24)),
                          (response[64] & 0xFF)|((response[65]<<8) & (0xFF<<8))|((response[66]<<16) & (0xFF<<16))|((response[67]<<24) & (0xFF<<24)),
                          (response[68] & 0xFF)|((response[69]<<8) & (0xFF<<8))|((response[70]<<16) & (0xFF<<16))|((response[71]<<24) & (0xFF<<24)),
                          (response[72] & 0xFF)|((response[73]<<8) & (0xFF<<8))|((response[74]<<16) & (0xFF<<16))|((response[75]<<24) & (0xFF<<24)),
                          (response[76] & 0xFF)|((response[77]<<8) & (0xFF<<8))|((response[78]<<16) & (0xFF<<16))|((response[79]<<24) & (0xFF<<24)),
                          (response[80] & 0xFF)|((response[81]<<8) & (0xFF<<8))|((response[82]<<16) & (0xFF<<16))|((response[83]<<24) & (0xFF<<24)),
                          (response[84] & 0xFF)|((response[85]<<8) & (0xFF<<8))|((response[86]<<16) & (0xFF<<16))|((response[87]<<24) & (0xFF<<24)),
                          (response[88] & 0xFF)|((response[89]<<8) & (0xFF<<8))|((response[90]<<16) & (0xFF<<16))|((response[91]<<24) & (0xFF<<24)),
                          (response[92] & 0xFF)|((response[93]<<8) & (0xFF<<8))|((response[94]<<16) & (0xFF<<16))|((response[95]<<24) & (0xFF<<24)),
                          (response[96] & 0xFF)|((response[97]<<8) & (0xFF<<8))|((response[98]<<16) & (0xFF<<16))|((response[99]<<24) & (0xFF<<24)),
                          (response[100] & 0xFF)|((response[101]<<8) & (0xFF<<8))|((response[102]<<16) & (0xFF<<16))|((response[103]<<24) & (0xFF<<24)),
                          (response[104] & 0xFF)|((response[105]<<8) & (0xFF<<8))|((response[106]<<16) & (0xFF<<16))|((response[107]<<24) & (0xFF<<24)),
                          (response[108] & 0xFF)|((response[109]<<8) & (0xFF<<8))|((response[110]<<16) & (0xFF<<16))|((response[111]<<24) & (0xFF<<24)),
                          (response[112] & 0xFF)|((response[113]<<8) & (0xFF<<8))|((response[114]<<16) & (0xFF<<16))|((response[115]<<24) & (0xFF<<24)),
                          (response[116] & 0xFF)|((response[117]<<8) & (0xFF<<8))|((response[118]<<16) & (0xFF<<16))|((response[119]<<24) & (0xFF<<24)),
                          (response[120] & 0xFF)|((response[121]<<8) & (0xFF<<8))|((response[122]<<16) & (0xFF<<16))|((response[123]<<24) & (0xFF<<24)),
                          (response[124] & 0xFF)|((response[125]<<8) & (0xFF<<8))|((response[126]<<16) & (0xFF<<16))|((response[127]<<24) & (0xFF<<24)),
                          (response[128] & 0xFF)|((response[129]<<8) & (0xFF<<8))|((response[130]<<16) & (0xFF<<16))|((response[131]<<24) & (0xFF<<24)),
                          (response[132] & 0xFF)|((response[133]<<8) & (0xFF<<8))|((response[134]<<16) & (0xFF<<16))|((response[135]<<24) & (0xFF<<24)),
                          (response[136] & 0xFF)|((response[137]<<8) & (0xFF<<8))|((response[138]<<16) & (0xFF<<16))|((response[139]<<24) & (0xFF<<24)),
                          (response[140] & 0xFF)|((response[141]<<8) & (0xFF<<8))|((response[142]<<16) & (0xFF<<16))|((response[143]<<24) & (0xFF<<24)),
                          (response[144] & 0xFF)|((response[145]<<8) & (0xFF<<8))|((response[146]<<16) & (0xFF<<16))|((response[147]<<24) & (0xFF<<24)),
                          (response[148] & 0xFF)|((response[149]<<8) & (0xFF<<8))|((response[150]<<16) & (0xFF<<16))|((response[151]<<24) & (0xFF<<24)),
                          (response[152] & 0xFF)|((response[153]<<8) & (0xFF<<8))|((response[154]<<16) & (0xFF<<16))|((response[155]<<24) & (0xFF<<24)),
                          (response[156] & 0xFF)|((response[157]<<8) & (0xFF<<8))|((response[158]<<16) & (0xFF<<16))|((response[159]<<24) & (0xFF<<24)),
                          (response[160] & 0xFF)|((response[161]<<8) & (0xFF<<8))|((response[162]<<16) & (0xFF<<16))|((response[163]<<24) & (0xFF<<24)),
                          (response[164] & 0xFF)|((response[165]<<8) & (0xFF<<8))|((response[166]<<16) & (0xFF<<16))|((response[167]<<24) & (0xFF<<24)),
                          (response[168] & 0xFF)|((response[169]<<8) & (0xFF<<8))|((response[170]<<16) & (0xFF<<16))|((response[171]<<24) & (0xFF<<24)),
                          (response[172] & 0xFF)|((response[173]<<8) & (0xFF<<8))|((response[174]<<16) & (0xFF<<16))|((response[175]<<24) & (0xFF<<24)),
                          (response[176] & 0xFF)|((response[177]<<8) & (0xFF<<8))|((response[178]<<16) & (0xFF<<16))|((response[179]<<24) & (0xFF<<24)),
                          (response[180] & 0xFF)|((response[181]<<8) & (0xFF<<8))|((response[182]<<16) & (0xFF<<16))|((response[183]<<24) & (0xFF<<24)),
                          (response[184] & 0xFF)|((response[185]<<8) & (0xFF<<8))|((response[186]<<16) & (0xFF<<16))|((response[187]<<24) & (0xFF<<24)),
                          (response[188] & 0xFF)|((response[189]<<8) & (0xFF<<8))|((response[190]<<16) & (0xFF<<16))|((response[191]<<24) & (0xFF<<24)),
                          (response[192] & 0xFF)|((response[193]<<8) & (0xFF<<8))|((response[194]<<16) & (0xFF<<16))|((response[195]<<24) & (0xFF<<24)),
                          (response[196] & 0xFF)|((response[197]<<8) & (0xFF<<8))|((response[198]<<16) & (0xFF<<16))|((response[199]<<24) & (0xFF<<24)),
                          (response[200] & 0xFF)|((response[201]<<8) & (0xFF<<8))|((response[202]<<16) & (0xFF<<16))|((response[203]<<24) & (0xFF<<24)),
                          (response[204] & 0xFF)|((response[205]<<8) & (0xFF<<8))|((response[206]<<16) & (0xFF<<16))|((response[207]<<24) & (0xFF<<24)),
                          (response[208] & 0xFF)|((response[209]<<8) & (0xFF<<8))|((response[210]<<16) & (0xFF<<16))|((response[211]<<24) & (0xFF<<24)),
                          (response[212] & 0xFF)|((response[213]<<8) & (0xFF<<8))|((response[214]<<16) & (0xFF<<16))|((response[215]<<24) & (0xFF<<24)),
                          (response[216] & 0xFF)|((response[217]<<8) & (0xFF<<8))|((response[218]<<16) & (0xFF<<16))|((response[219]<<24) & (0xFF<<24)),
                          (response[220] & 0xFF)|((response[221]<<8) & (0xFF<<8))|((response[222]<<16) & (0xFF<<16))|((response[223]<<24) & (0xFF<<24)),
                          (response[224] & 0xFF)|((response[225]<<8) & (0xFF<<8))|((response[226]<<16) & (0xFF<<16))|((response[227]<<24) & (0xFF<<24)),
                          (response[228] & 0xFF)|((response[229]<<8) & (0xFF<<8))|((response[230]<<16) & (0xFF<<16))|((response[231]<<24) & (0xFF<<24)),
                          (response[232] & 0xFF)|((response[233]<<8) & (0xFF<<8))|((response[234]<<16) & (0xFF<<16))|((response[235]<<24) & (0xFF<<24)),
                          (response[236] & 0xFF)|((response[237]<<8) & (0xFF<<8))|((response[238]<<16) & (0xFF<<16))|((response[239]<<24) & (0xFF<<24)),
                          (response[240] & 0xFF)|((response[241]<<8) & (0xFF<<8))|((response[242]<<16) & (0xFF<<16))|((response[243]<<24) & (0xFF<<24)),
                          (response[244] & 0xFF)|((response[245]<<8) & (0xFF<<8))|((response[246]<<16) & (0xFF<<16))|((response[247]<<24) & (0xFF<<24)),
                          (response[248] & 0xFF)|((response[249]<<8) & (0xFF<<8))|((response[250]<<16) & (0xFF<<16))|((response[251]<<24) & (0xFF<<24)),
                          (response[252] & 0xFF)|((response[253]<<8) & (0xFF<<8))|((response[254]<<16) & (0xFF<<16))|((response[255]<<24) & (0xFF<<24)),
                          (response[256] & 0xFF)|((response[257]<<8) & (0xFF<<8))|((response[258]<<16) & (0xFF<<16))|((response[259]<<24) & (0xFF<<24)),
                          (response[260] & 0xFF)|((response[261]<<8) & (0xFF<<8))|((response[262]<<16) & (0xFF<<16))|((response[263]<<24) & (0xFF<<24)),
                          (response[264] & 0xFF)|((response[265]<<8) & (0xFF<<8))|((response[266]<<16) & (0xFF<<16))|((response[267]<<24) & (0xFF<<24)),
                          (response[268] & 0xFF)|((response[269]<<8) & (0xFF<<8))|((response[270]<<16) & (0xFF<<16))|((response[271]<<24) & (0xFF<<24)),
                          (response[272] & 0xFF)|((response[273]<<8) & (0xFF<<8))|((response[274]<<16) & (0xFF<<16))|((response[275]<<24) & (0xFF<<24)),
                          (response[276] & 0xFF)|((response[277]<<8) & (0xFF<<8))|((response[278]<<16) & (0xFF<<16))|((response[279]<<24) & (0xFF<<24)),
                          (response[280] & 0xFF)|((response[281]<<8) & (0xFF<<8))|((response[282]<<16) & (0xFF<<16))|((response[283]<<24) & (0xFF<<24)),
                          (response[284] & 0xFF)|((response[285]<<8) & (0xFF<<8))|((response[286]<<16) & (0xFF<<16))|((response[287]<<24) & (0xFF<<24)),
                          (response[288] & 0xFF)|((response[289]<<8) & (0xFF<<8))|((response[290]<<16) & (0xFF<<16))|((response[291]<<24) & (0xFF<<24)),
                          (response[292] & 0xFF)|((response[293]<<8) & (0xFF<<8))|((response[294]<<16) & (0xFF<<16))|((response[295]<<24) & (0xFF<<24)),
                          (response[296] & 0xFF)|((response[297]<<8) & (0xFF<<8))|((response[298]<<16) & (0xFF<<16))|((response[299]<<24) & (0xFF<<24)),
                          (response[300] & 0xFF)|((response[301]<<8) & (0xFF<<8))|((response[302]<<16) & (0xFF<<16))|((response[303]<<24) & (0xFF<<24)),
                          (response[304] & 0xFF)|((response[305]<<8) & (0xFF<<8))|((response[306]<<16) & (0xFF<<16))|((response[307]<<24) & (0xFF<<24)),
                          (response[308] & 0xFF)|((response[309]<<8) & (0xFF<<8))|((response[310]<<16) & (0xFF<<16))|((response[311]<<24) & (0xFF<<24)),
                          (response[312] & 0xFF)|((response[313]<<8) & (0xFF<<8))|((response[314]<<16) & (0xFF<<16))|((response[315]<<24) & (0xFF<<24)),
                          (response[316] & 0xFF)|((response[317]<<8) & (0xFF<<8))|((response[318]<<16) & (0xFF<<16))|((response[319]<<24) & (0xFF<<24)),
                          (response[320] & 0xFF)|((response[321]<<8) & (0xFF<<8))|((response[322]<<16) & (0xFF<<16))|((response[323]<<24) & (0xFF<<24)),
                          (response[324] & 0xFF)|((response[325]<<8) & (0xFF<<8))|((response[326]<<16) & (0xFF<<16))|((response[327]<<24) & (0xFF<<24)),
                          (response[328] & 0xFF)|((response[329]<<8) & (0xFF<<8))|((response[330]<<16) & (0xFF<<16))|((response[331]<<24) & (0xFF<<24)),
                          (response[332] & 0xFF)|((response[333]<<8) & (0xFF<<8))|((response[334]<<16) & (0xFF<<16))|((response[335]<<24) & (0xFF<<24)),
                          (response[336] & 0xFF)|((response[337]<<8) & (0xFF<<8))|((response[338]<<16) & (0xFF<<16))|((response[339]<<24) & (0xFF<<24)),
                          (response[340] & 0xFF)|((response[341]<<8) & (0xFF<<8))|((response[342]<<16) & (0xFF<<16))|((response[343]<<24) & (0xFF<<24)),
                          (response[344] & 0xFF)|((response[345]<<8) & (0xFF<<8))|((response[346]<<16) & (0xFF<<16))|((response[347]<<24) & (0xFF<<24)),
                          (response[348] & 0xFF)|((response[349]<<8) & (0xFF<<8))|((response[350]<<16) & (0xFF<<16))|((response[351]<<24) & (0xFF<<24)),
                          (response[352] & 0xFF)|((response[353]<<8) & (0xFF<<8))|((response[354]<<16) & (0xFF<<16))|((response[355]<<24) & (0xFF<<24)),
                          (response[356] & 0xFF)|((response[357]<<8) & (0xFF<<8))|((response[358]<<16) & (0xFF<<16))|((response[359]<<24) & (0xFF<<24)),
                          (response[360] & 0xFF)|((response[361]<<8) & (0xFF<<8))|((response[362]<<16) & (0xFF<<16))|((response[363]<<24) & (0xFF<<24)),
                          (response[364] & 0xFF)|((response[365]<<8) & (0xFF<<8))|((response[366]<<16) & (0xFF<<16))|((response[367]<<24) & (0xFF<<24)),
                          (response[368] & 0xFF)|((response[369]<<8) & (0xFF<<8))|((response[370]<<16) & (0xFF<<16))|((response[371]<<24) & (0xFF<<24)),
                          (response[372] & 0xFF)|((response[373]<<8) & (0xFF<<8))|((response[374]<<16) & (0xFF<<16))|((response[375]<<24) & (0xFF<<24)),
                          (response[376] & 0xFF)|((response[377]<<8) & (0xFF<<8))|((response[378]<<16) & (0xFF<<16))|((response[379]<<24) & (0xFF<<24)),
                          (response[380] & 0xFF)|((response[381]<<8) & (0xFF<<8))|((response[382]<<16) & (0xFF<<16))|((response[383]<<24) & (0xFF<<24)),
                          (response[384] & 0xFF)|((response[385]<<8) & (0xFF<<8))|((response[386]<<16) & (0xFF<<16))|((response[387]<<24) & (0xFF<<24)),
                          ],
             'enable' : (response[388] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetLineSdfecCustomPatternGeneratorConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetCoreCfecTestPatternCheckerStatistics (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x212
        header.Tag = 0
        header.MaxResponse = 68
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'accum_bit_count' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24))|((response[8]<<32) & (0xFF<<32))|((response[9]<<40) & (0xFF<<40))|((response[10]<<48) & (0xFF<<48))|((response[11]<<56) & (0xFF<<56)),
             'accum_error_count' : (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8))|((response[14]<<16) & (0xFF<<16))|((response[15]<<24) & (0xFF<<24))|((response[16]<<32) & (0xFF<<32))|((response[17]<<40) & (0xFF<<40))|((response[18]<<48) & (0xFF<<48))|((response[19]<<56) & (0xFF<<56)),
             'max_bit_count' : (response[20] & 0xFF)|((response[21]<<8) & (0xFF<<8))|((response[22]<<16) & (0xFF<<16))|((response[23]<<24) & (0xFF<<24))|((response[24]<<32) & (0xFF<<32))|((response[25]<<40) & (0xFF<<40))|((response[26]<<48) & (0xFF<<48))|((response[27]<<56) & (0xFF<<56)),
             'max_error_count' : (response[28] & 0xFF)|((response[29]<<8) & (0xFF<<8))|((response[30]<<16) & (0xFF<<16))|((response[31]<<24) & (0xFF<<24))|((response[32]<<32) & (0xFF<<32))|((response[33]<<40) & (0xFF<<40))|((response[34]<<48) & (0xFF<<48))|((response[35]<<56) & (0xFF<<56)),
             'min_bit_count' : (response[36] & 0xFF)|((response[37]<<8) & (0xFF<<8))|((response[38]<<16) & (0xFF<<16))|((response[39]<<24) & (0xFF<<24))|((response[40]<<32) & (0xFF<<32))|((response[41]<<40) & (0xFF<<40))|((response[42]<<48) & (0xFF<<48))|((response[43]<<56) & (0xFF<<56)),
             'min_error_count' : (response[44] & 0xFF)|((response[45]<<8) & (0xFF<<8))|((response[46]<<16) & (0xFF<<16))|((response[47]<<24) & (0xFF<<24))|((response[48]<<32) & (0xFF<<32))|((response[49]<<40) & (0xFF<<40))|((response[50]<<48) & (0xFF<<48))|((response[51]<<56) & (0xFF<<56)),
             'instant_bit_count' : (response[52] & 0xFF)|((response[53]<<8) & (0xFF<<8))|((response[54]<<16) & (0xFF<<16))|((response[55]<<24) & (0xFF<<24))|((response[56]<<32) & (0xFF<<32))|((response[57]<<40) & (0xFF<<40))|((response[58]<<48) & (0xFF<<48))|((response[59]<<56) & (0xFF<<56)),
             'instant_error_count' : (response[60] & 0xFF)|((response[61]<<8) & (0xFF<<8))|((response[62]<<16) & (0xFF<<16))|((response[63]<<24) & (0xFF<<24))|((response[64]<<32) & (0xFF<<32))|((response[65]<<40) & (0xFF<<40))|((response[66]<<48) & (0xFF<<48))|((response[67]<<56) & (0xFF<<56)),
        }
        self.check_response(apiResponse, CanopusApi.GetCoreCfecTestPatternCheckerStatistics)
        self.add_api_exec_cb()
        return apiResponse

    def GetCoreCfecTestPatternCheckerCounters (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x212
        header.Tag = 0
        header.MaxResponse = 24
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'bit_count' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24))|((response[8]<<32) & (0xFF<<32))|((response[9]<<40) & (0xFF<<40))|((response[10]<<48) & (0xFF<<48))|((response[11]<<56) & (0xFF<<56)),
             'error_count' : (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8))|((response[14]<<16) & (0xFF<<16))|((response[15]<<24) & (0xFF<<24))|((response[16]<<32) & (0xFF<<32))|((response[17]<<40) & (0xFF<<40))|((response[18]<<48) & (0xFF<<48))|((response[19]<<56) & (0xFF<<56)),
             'resync_count' : (response[20] & 0xFF)|((response[21]<<8) & (0xFF<<8))|((response[22]<<16) & (0xFF<<16))|((response[23]<<24) & (0xFF<<24)),
        }
        self.check_response(apiResponse, CanopusApi.GetCoreCfecTestPatternCheckerCounters)
        self.add_api_exec_cb()
        return apiResponse
		
    def GetIngressSmInformation (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x221
        header.Tag = 0
        header.MaxResponse = 56
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'up_time' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24)),
             'state' : (response[8] & 0xFF),
             'debug_field_1' : (response[9] & 0xFF),
             'debug_field_2' : (response[10] & 0xFF),
             'debug_field_3' : (response[11] & 0xFF),
             'debug_field_4' : (response[12] & 0xFF),
             'debug_field_5' : (response[13] & 0xFF),
             'debug_field_6' : (response[14] & 0xFF),
             'debug_field_7' : (response[15] & 0xFF),
             'debug_field_8' : (response[16] & 0xFF)|((response[17]<<8) & (0xFF<<8))|((response[18]<<16) & (0xFF<<16))|((response[19]<<24) & (0xFF<<24)),
             'debug_field_9' : (response[20] & 0xFF)|((response[21]<<8) & (0xFF<<8))|((response[22]<<16) & (0xFF<<16))|((response[23]<<24) & (0xFF<<24)),
             'debug_field_10' : (response[24] & 0xFF)|((response[25]<<8) & (0xFF<<8))|((response[26]<<16) & (0xFF<<16))|((response[27]<<24) & (0xFF<<24)),
             'debug_field_11' : (response[28] & 0xFF)|((response[29]<<8) & (0xFF<<8))|((response[30]<<16) & (0xFF<<16))|((response[31]<<24) & (0xFF<<24)),
             'debug_field_12' : (response[32] & 0xFF)|((response[33]<<8) & (0xFF<<8))|((response[34]<<16) & (0xFF<<16))|((response[35]<<24) & (0xFF<<24)),
             'debug_field_13' : (response[36] & 0xFF)|((response[37]<<8) & (0xFF<<8))|((response[38]<<16) & (0xFF<<16))|((response[39]<<24) & (0xFF<<24)),
             'dsp_mse_hi' : (response[40] & 0xFF)|((response[41]<<8) & (0xFF<<8)),
             'dsp_mse_hq' : (response[42] & 0xFF)|((response[43]<<8) & (0xFF<<8)),
             'dsp_mse_vi' : (response[44] & 0xFF)|((response[45]<<8) & (0xFF<<8)),
             'dsp_mse_vq' : (response[46] & 0xFF)|((response[47]<<8) & (0xFF<<8)),
             'agc_gain_hi' : (response[48] & 0xFF)|((response[49]<<8) & (0xFF<<8)),
             'agc_gain_hq' : (response[50] & 0xFF)|((response[51]<<8) & (0xFF<<8)),
             'agc_gain_vi' : (response[52] & 0xFF)|((response[53]<<8) & (0xFF<<8)),
             'agc_gain_vq' : (response[54] & 0xFF)|((response[55]<<8) & (0xFF<<8)),
        }
        self.check_response(apiResponse, CanopusApi.GetIngressSmInformation)
        self.add_api_exec_cb()
        return apiResponse

    def GetDisruptionTime (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x23F
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'disruption_time' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24)),
        }
        self.check_response(apiResponse, CanopusApi.GetDisruptionTime)
        self.add_api_exec_cb()
        return apiResponse

    def GetFawErrorStatistics (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x165
        header.Tag = 0
        header.MaxResponse = 68
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'accum_fas_bit_count' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24))|((response[8]<<32) & (0xFF<<32))|((response[9]<<40) & (0xFF<<40))|((response[10]<<48) & (0xFF<<48))|((response[11]<<56) & (0xFF<<56)),
             'accum_fas_error_count' : (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8))|((response[14]<<16) & (0xFF<<16))|((response[15]<<24) & (0xFF<<24))|((response[16]<<32) & (0xFF<<32))|((response[17]<<40) & (0xFF<<40))|((response[18]<<48) & (0xFF<<48))|((response[19]<<56) & (0xFF<<56)),
             'max_fas_bit_count' : (response[20] & 0xFF)|((response[21]<<8) & (0xFF<<8))|((response[22]<<16) & (0xFF<<16))|((response[23]<<24) & (0xFF<<24))|((response[24]<<32) & (0xFF<<32))|((response[25]<<40) & (0xFF<<40))|((response[26]<<48) & (0xFF<<48))|((response[27]<<56) & (0xFF<<56)),
             'max_fas_error_count' : (response[28] & 0xFF)|((response[29]<<8) & (0xFF<<8))|((response[30]<<16) & (0xFF<<16))|((response[31]<<24) & (0xFF<<24))|((response[32]<<32) & (0xFF<<32))|((response[33]<<40) & (0xFF<<40))|((response[34]<<48) & (0xFF<<48))|((response[35]<<56) & (0xFF<<56)),
             'min_fas_bit_count' : (response[36] & 0xFF)|((response[37]<<8) & (0xFF<<8))|((response[38]<<16) & (0xFF<<16))|((response[39]<<24) & (0xFF<<24))|((response[40]<<32) & (0xFF<<32))|((response[41]<<40) & (0xFF<<40))|((response[42]<<48) & (0xFF<<48))|((response[43]<<56) & (0xFF<<56)),
             'min_fas_error_count' : (response[44] & 0xFF)|((response[45]<<8) & (0xFF<<8))|((response[46]<<16) & (0xFF<<16))|((response[47]<<24) & (0xFF<<24))|((response[48]<<32) & (0xFF<<32))|((response[49]<<40) & (0xFF<<40))|((response[50]<<48) & (0xFF<<48))|((response[51]<<56) & (0xFF<<56)),
             'instant_fas_bit_count' : (response[52] & 0xFF)|((response[53]<<8) & (0xFF<<8))|((response[54]<<16) & (0xFF<<16))|((response[55]<<24) & (0xFF<<24))|((response[56]<<32) & (0xFF<<32))|((response[57]<<40) & (0xFF<<40))|((response[58]<<48) & (0xFF<<48))|((response[59]<<56) & (0xFF<<56)),
             'instant_fas_error_count' : (response[60] & 0xFF)|((response[61]<<8) & (0xFF<<8))|((response[62]<<16) & (0xFF<<16))|((response[63]<<24) & (0xFF<<24))|((response[64]<<32) & (0xFF<<32))|((response[65]<<40) & (0xFF<<40))|((response[66]<<48) & (0xFF<<48))|((response[67]<<56) & (0xFF<<56)),
        }
        self.check_response(apiResponse, CanopusApi.GetFawErrorStatistics)
        self.add_api_exec_cb()
        return apiResponse

    def GetErrorCorrectionStatistics (self, channel, direction):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x167
        header.Tag = 0
        header.MaxResponse = 132
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'accum_bit_count' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24))|((response[8]<<32) & (0xFF<<32))|((response[9]<<40) & (0xFF<<40))|((response[10]<<48) & (0xFF<<48))|((response[11]<<56) & (0xFF<<56)),
             'accum_corrected_error_count' : (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8))|((response[14]<<16) & (0xFF<<16))|((response[15]<<24) & (0xFF<<24))|((response[16]<<32) & (0xFF<<32))|((response[17]<<40) & (0xFF<<40))|((response[18]<<48) & (0xFF<<48))|((response[19]<<56) & (0xFF<<56)),
             'accum_uncorrected_codeword_count' : (response[20] & 0xFF)|((response[21]<<8) & (0xFF<<8))|((response[22]<<16) & (0xFF<<16))|((response[23]<<24) & (0xFF<<24))|((response[24]<<32) & (0xFF<<32))|((response[25]<<40) & (0xFF<<40))|((response[26]<<48) & (0xFF<<48))|((response[27]<<56) & (0xFF<<56)),
             'accum_codeword_count' : (response[28] & 0xFF)|((response[29]<<8) & (0xFF<<8))|((response[30]<<16) & (0xFF<<16))|((response[31]<<24) & (0xFF<<24))|((response[32]<<32) & (0xFF<<32))|((response[33]<<40) & (0xFF<<40))|((response[34]<<48) & (0xFF<<48))|((response[35]<<56) & (0xFF<<56)),
             'max_corrected_bit_count' : (response[36] & 0xFF)|((response[37]<<8) & (0xFF<<8))|((response[38]<<16) & (0xFF<<16))|((response[39]<<24) & (0xFF<<24))|((response[40]<<32) & (0xFF<<32))|((response[41]<<40) & (0xFF<<40))|((response[42]<<48) & (0xFF<<48))|((response[43]<<56) & (0xFF<<56)),
             'max_corrected_error_count' : (response[44] & 0xFF)|((response[45]<<8) & (0xFF<<8))|((response[46]<<16) & (0xFF<<16))|((response[47]<<24) & (0xFF<<24))|((response[48]<<32) & (0xFF<<32))|((response[49]<<40) & (0xFF<<40))|((response[50]<<48) & (0xFF<<48))|((response[51]<<56) & (0xFF<<56)),
             'max_uncorrected_codeword_count' : (response[52] & 0xFF)|((response[53]<<8) & (0xFF<<8))|((response[54]<<16) & (0xFF<<16))|((response[55]<<24) & (0xFF<<24))|((response[56]<<32) & (0xFF<<32))|((response[57]<<40) & (0xFF<<40))|((response[58]<<48) & (0xFF<<48))|((response[59]<<56) & (0xFF<<56)),
             'max_codeword_count' : (response[60] & 0xFF)|((response[61]<<8) & (0xFF<<8))|((response[62]<<16) & (0xFF<<16))|((response[63]<<24) & (0xFF<<24))|((response[64]<<32) & (0xFF<<32))|((response[65]<<40) & (0xFF<<40))|((response[66]<<48) & (0xFF<<48))|((response[67]<<56) & (0xFF<<56)),
             'min_corrected_bit_count' : (response[68] & 0xFF)|((response[69]<<8) & (0xFF<<8))|((response[70]<<16) & (0xFF<<16))|((response[71]<<24) & (0xFF<<24))|((response[72]<<32) & (0xFF<<32))|((response[73]<<40) & (0xFF<<40))|((response[74]<<48) & (0xFF<<48))|((response[75]<<56) & (0xFF<<56)),
             'min_corrected_error_count' : (response[76] & 0xFF)|((response[77]<<8) & (0xFF<<8))|((response[78]<<16) & (0xFF<<16))|((response[79]<<24) & (0xFF<<24))|((response[80]<<32) & (0xFF<<32))|((response[81]<<40) & (0xFF<<40))|((response[82]<<48) & (0xFF<<48))|((response[83]<<56) & (0xFF<<56)),
             'min_uncorrected_codeword_count' : (response[84] & 0xFF)|((response[85]<<8) & (0xFF<<8))|((response[86]<<16) & (0xFF<<16))|((response[87]<<24) & (0xFF<<24))|((response[88]<<32) & (0xFF<<32))|((response[89]<<40) & (0xFF<<40))|((response[90]<<48) & (0xFF<<48))|((response[91]<<56) & (0xFF<<56)),
             'min_codeword_count' : (response[92] & 0xFF)|((response[93]<<8) & (0xFF<<8))|((response[94]<<16) & (0xFF<<16))|((response[95]<<24) & (0xFF<<24))|((response[96]<<32) & (0xFF<<32))|((response[97]<<40) & (0xFF<<40))|((response[98]<<48) & (0xFF<<48))|((response[99]<<56) & (0xFF<<56)),
             'instant_corrected_bit_count' : (response[100] & 0xFF)|((response[101]<<8) & (0xFF<<8))|((response[102]<<16) & (0xFF<<16))|((response[103]<<24) & (0xFF<<24))|((response[104]<<32) & (0xFF<<32))|((response[105]<<40) & (0xFF<<40))|((response[106]<<48) & (0xFF<<48))|((response[107]<<56) & (0xFF<<56)),
             'instant_corrected_error_count' : (response[108] & 0xFF)|((response[109]<<8) & (0xFF<<8))|((response[110]<<16) & (0xFF<<16))|((response[111]<<24) & (0xFF<<24))|((response[112]<<32) & (0xFF<<32))|((response[113]<<40) & (0xFF<<40))|((response[114]<<48) & (0xFF<<48))|((response[115]<<56) & (0xFF<<56)),
             'instant_uncorrected_codeword_count' : (response[116] & 0xFF)|((response[117]<<8) & (0xFF<<8))|((response[118]<<16) & (0xFF<<16))|((response[119]<<24) & (0xFF<<24))|((response[120]<<32) & (0xFF<<32))|((response[121]<<40) & (0xFF<<40))|((response[122]<<48) & (0xFF<<48))|((response[123]<<56) & (0xFF<<56)),
             'instant_codeword_count' : (response[124] & 0xFF)|((response[125]<<8) & (0xFF<<8))|((response[126]<<16) & (0xFF<<16))|((response[127]<<24) & (0xFF<<24))|((response[128]<<32) & (0xFF<<32))|((response[129]<<40) & (0xFF<<40))|((response[130]<<48) & (0xFF<<48))|((response[131]<<56) & (0xFF<<56)),
        }
        self.check_response(apiResponse, CanopusApi.GetErrorCorrectionStatistics)
        self.add_api_exec_cb()
        return apiResponse

    def GetPcsErrorStatistics (self, channel, direction):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x166
        header.Tag = 0
        header.MaxResponse = 132
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'accum_bip8_count' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24))|((response[8]<<32) & (0xFF<<32))|((response[9]<<40) & (0xFF<<40))|((response[10]<<48) & (0xFF<<48))|((response[11]<<56) & (0xFF<<56)),
             'accum_bip8_error_count' : (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8))|((response[14]<<16) & (0xFF<<16))|((response[15]<<24) & (0xFF<<24))|((response[16]<<32) & (0xFF<<32))|((response[17]<<40) & (0xFF<<40))|((response[18]<<48) & (0xFF<<48))|((response[19]<<56) & (0xFF<<56)),
             'accum_sh_count' : (response[20] & 0xFF)|((response[21]<<8) & (0xFF<<8))|((response[22]<<16) & (0xFF<<16))|((response[23]<<24) & (0xFF<<24))|((response[24]<<32) & (0xFF<<32))|((response[25]<<40) & (0xFF<<40))|((response[26]<<48) & (0xFF<<48))|((response[27]<<56) & (0xFF<<56)),
             'accum_sh_error_count' : (response[28] & 0xFF)|((response[29]<<8) & (0xFF<<8))|((response[30]<<16) & (0xFF<<16))|((response[31]<<24) & (0xFF<<24))|((response[32]<<32) & (0xFF<<32))|((response[33]<<40) & (0xFF<<40))|((response[34]<<48) & (0xFF<<48))|((response[35]<<56) & (0xFF<<56)),
             'max_bip8_count' : (response[36] & 0xFF)|((response[37]<<8) & (0xFF<<8))|((response[38]<<16) & (0xFF<<16))|((response[39]<<24) & (0xFF<<24))|((response[40]<<32) & (0xFF<<32))|((response[41]<<40) & (0xFF<<40))|((response[42]<<48) & (0xFF<<48))|((response[43]<<56) & (0xFF<<56)),
             'max_bip8_error_count' : (response[44] & 0xFF)|((response[45]<<8) & (0xFF<<8))|((response[46]<<16) & (0xFF<<16))|((response[47]<<24) & (0xFF<<24))|((response[48]<<32) & (0xFF<<32))|((response[49]<<40) & (0xFF<<40))|((response[50]<<48) & (0xFF<<48))|((response[51]<<56) & (0xFF<<56)),
             'max_sh_count' : (response[52] & 0xFF)|((response[53]<<8) & (0xFF<<8))|((response[54]<<16) & (0xFF<<16))|((response[55]<<24) & (0xFF<<24))|((response[56]<<32) & (0xFF<<32))|((response[57]<<40) & (0xFF<<40))|((response[58]<<48) & (0xFF<<48))|((response[59]<<56) & (0xFF<<56)),
             'max_sh_error_count' : (response[60] & 0xFF)|((response[61]<<8) & (0xFF<<8))|((response[62]<<16) & (0xFF<<16))|((response[63]<<24) & (0xFF<<24))|((response[64]<<32) & (0xFF<<32))|((response[65]<<40) & (0xFF<<40))|((response[66]<<48) & (0xFF<<48))|((response[67]<<56) & (0xFF<<56)),
             'min_bip8_count' : (response[68] & 0xFF)|((response[69]<<8) & (0xFF<<8))|((response[70]<<16) & (0xFF<<16))|((response[71]<<24) & (0xFF<<24))|((response[72]<<32) & (0xFF<<32))|((response[73]<<40) & (0xFF<<40))|((response[74]<<48) & (0xFF<<48))|((response[75]<<56) & (0xFF<<56)),
             'min_bip8_error_count' : (response[76] & 0xFF)|((response[77]<<8) & (0xFF<<8))|((response[78]<<16) & (0xFF<<16))|((response[79]<<24) & (0xFF<<24))|((response[80]<<32) & (0xFF<<32))|((response[81]<<40) & (0xFF<<40))|((response[82]<<48) & (0xFF<<48))|((response[83]<<56) & (0xFF<<56)),
             'min_sh_count' : (response[84] & 0xFF)|((response[85]<<8) & (0xFF<<8))|((response[86]<<16) & (0xFF<<16))|((response[87]<<24) & (0xFF<<24))|((response[88]<<32) & (0xFF<<32))|((response[89]<<40) & (0xFF<<40))|((response[90]<<48) & (0xFF<<48))|((response[91]<<56) & (0xFF<<56)),
             'min_sh_error_count' : (response[92] & 0xFF)|((response[93]<<8) & (0xFF<<8))|((response[94]<<16) & (0xFF<<16))|((response[95]<<24) & (0xFF<<24))|((response[96]<<32) & (0xFF<<32))|((response[97]<<40) & (0xFF<<40))|((response[98]<<48) & (0xFF<<48))|((response[99]<<56) & (0xFF<<56)),
             'instant_bip8_count' : (response[100] & 0xFF)|((response[101]<<8) & (0xFF<<8))|((response[102]<<16) & (0xFF<<16))|((response[103]<<24) & (0xFF<<24))|((response[104]<<32) & (0xFF<<32))|((response[105]<<40) & (0xFF<<40))|((response[106]<<48) & (0xFF<<48))|((response[107]<<56) & (0xFF<<56)),
             'instant_bip8_error_count' : (response[108] & 0xFF)|((response[109]<<8) & (0xFF<<8))|((response[110]<<16) & (0xFF<<16))|((response[111]<<24) & (0xFF<<24))|((response[112]<<32) & (0xFF<<32))|((response[113]<<40) & (0xFF<<40))|((response[114]<<48) & (0xFF<<48))|((response[115]<<56) & (0xFF<<56)),
             'instant_sh_count' : (response[116] & 0xFF)|((response[117]<<8) & (0xFF<<8))|((response[118]<<16) & (0xFF<<16))|((response[119]<<24) & (0xFF<<24))|((response[120]<<32) & (0xFF<<32))|((response[121]<<40) & (0xFF<<40))|((response[122]<<48) & (0xFF<<48))|((response[123]<<56) & (0xFF<<56)),
             'instant_sh_error_count' : (response[124] & 0xFF)|((response[125]<<8) & (0xFF<<8))|((response[126]<<16) & (0xFF<<16))|((response[127]<<24) & (0xFF<<24))|((response[128]<<32) & (0xFF<<32))|((response[129]<<40) & (0xFF<<40))|((response[130]<<48) & (0xFF<<48))|((response[131]<<56) & (0xFF<<56)),
        }
        self.check_response(apiResponse, CanopusApi.GetPcsErrorStatistics)
        self.add_api_exec_cb()
        return apiResponse

    def GetPcsTestPatternCheckerStatistics (self, channel, direction):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x183
        header.Tag = 0
        header.MaxResponse = 68
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'accum_bit_count' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24))|((response[8]<<32) & (0xFF<<32))|((response[9]<<40) & (0xFF<<40))|((response[10]<<48) & (0xFF<<48))|((response[11]<<56) & (0xFF<<56)),
             'accum_error_count' : (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8))|((response[14]<<16) & (0xFF<<16))|((response[15]<<24) & (0xFF<<24))|((response[16]<<32) & (0xFF<<32))|((response[17]<<40) & (0xFF<<40))|((response[18]<<48) & (0xFF<<48))|((response[19]<<56) & (0xFF<<56)),
             'max_bit_count' : (response[20] & 0xFF)|((response[21]<<8) & (0xFF<<8))|((response[22]<<16) & (0xFF<<16))|((response[23]<<24) & (0xFF<<24))|((response[24]<<32) & (0xFF<<32))|((response[25]<<40) & (0xFF<<40))|((response[26]<<48) & (0xFF<<48))|((response[27]<<56) & (0xFF<<56)),
             'max_error_count' : (response[28] & 0xFF)|((response[29]<<8) & (0xFF<<8))|((response[30]<<16) & (0xFF<<16))|((response[31]<<24) & (0xFF<<24))|((response[32]<<32) & (0xFF<<32))|((response[33]<<40) & (0xFF<<40))|((response[34]<<48) & (0xFF<<48))|((response[35]<<56) & (0xFF<<56)),
             'min_bit_count' : (response[36] & 0xFF)|((response[37]<<8) & (0xFF<<8))|((response[38]<<16) & (0xFF<<16))|((response[39]<<24) & (0xFF<<24))|((response[40]<<32) & (0xFF<<32))|((response[41]<<40) & (0xFF<<40))|((response[42]<<48) & (0xFF<<48))|((response[43]<<56) & (0xFF<<56)),
             'min_error_count' : (response[44] & 0xFF)|((response[45]<<8) & (0xFF<<8))|((response[46]<<16) & (0xFF<<16))|((response[47]<<24) & (0xFF<<24))|((response[48]<<32) & (0xFF<<32))|((response[49]<<40) & (0xFF<<40))|((response[50]<<48) & (0xFF<<48))|((response[51]<<56) & (0xFF<<56)),
             'instant_bit_count' : (response[52] & 0xFF)|((response[53]<<8) & (0xFF<<8))|((response[54]<<16) & (0xFF<<16))|((response[55]<<24) & (0xFF<<24))|((response[56]<<32) & (0xFF<<32))|((response[57]<<40) & (0xFF<<40))|((response[58]<<48) & (0xFF<<48))|((response[59]<<56) & (0xFF<<56)),
             'instant_error_count' : (response[60] & 0xFF)|((response[61]<<8) & (0xFF<<8))|((response[62]<<16) & (0xFF<<16))|((response[63]<<24) & (0xFF<<24))|((response[64]<<32) & (0xFF<<32))|((response[65]<<40) & (0xFF<<40))|((response[66]<<48) & (0xFF<<48))|((response[67]<<56) & (0xFF<<56)),
        }
        self.check_response(apiResponse, CanopusApi.GetPcsTestPatternCheckerStatistics)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtuTestPatternCheckerStatistics (self, channel, direction):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x17E
        header.Tag = 0
        header.MaxResponse = 68
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'accum_prbs_bit_count' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24))|((response[8]<<32) & (0xFF<<32))|((response[9]<<40) & (0xFF<<40))|((response[10]<<48) & (0xFF<<48))|((response[11]<<56) & (0xFF<<56)),
             'accum_prbs_error_count' : (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8))|((response[14]<<16) & (0xFF<<16))|((response[15]<<24) & (0xFF<<24))|((response[16]<<32) & (0xFF<<32))|((response[17]<<40) & (0xFF<<40))|((response[18]<<48) & (0xFF<<48))|((response[19]<<56) & (0xFF<<56)),
             'max_prbs_bit_count' : (response[20] & 0xFF)|((response[21]<<8) & (0xFF<<8))|((response[22]<<16) & (0xFF<<16))|((response[23]<<24) & (0xFF<<24))|((response[24]<<32) & (0xFF<<32))|((response[25]<<40) & (0xFF<<40))|((response[26]<<48) & (0xFF<<48))|((response[27]<<56) & (0xFF<<56)),
             'max_prbs_error_count' : (response[28] & 0xFF)|((response[29]<<8) & (0xFF<<8))|((response[30]<<16) & (0xFF<<16))|((response[31]<<24) & (0xFF<<24))|((response[32]<<32) & (0xFF<<32))|((response[33]<<40) & (0xFF<<40))|((response[34]<<48) & (0xFF<<48))|((response[35]<<56) & (0xFF<<56)),
             'min_prbs_bit_count' : (response[36] & 0xFF)|((response[37]<<8) & (0xFF<<8))|((response[38]<<16) & (0xFF<<16))|((response[39]<<24) & (0xFF<<24))|((response[40]<<32) & (0xFF<<32))|((response[41]<<40) & (0xFF<<40))|((response[42]<<48) & (0xFF<<48))|((response[43]<<56) & (0xFF<<56)),
             'min_prbs_error_count' : (response[44] & 0xFF)|((response[45]<<8) & (0xFF<<8))|((response[46]<<16) & (0xFF<<16))|((response[47]<<24) & (0xFF<<24))|((response[48]<<32) & (0xFF<<32))|((response[49]<<40) & (0xFF<<40))|((response[50]<<48) & (0xFF<<48))|((response[51]<<56) & (0xFF<<56)),
             'instant_prbs_bit_count' : (response[52] & 0xFF)|((response[53]<<8) & (0xFF<<8))|((response[54]<<16) & (0xFF<<16))|((response[55]<<24) & (0xFF<<24))|((response[56]<<32) & (0xFF<<32))|((response[57]<<40) & (0xFF<<40))|((response[58]<<48) & (0xFF<<48))|((response[59]<<56) & (0xFF<<56)),
             'instant_prbs_error_count' : (response[60] & 0xFF)|((response[61]<<8) & (0xFF<<8))|((response[62]<<16) & (0xFF<<16))|((response[63]<<24) & (0xFF<<24))|((response[64]<<32) & (0xFF<<32))|((response[65]<<40) & (0xFF<<40))|((response[66]<<48) & (0xFF<<48))|((response[67]<<56) & (0xFF<<56)),
        }
        self.check_response(apiResponse, CanopusApi.GetOtuTestPatternCheckerStatistics)
        self.add_api_exec_cb()
        return apiResponse

    def GetEstimatedPreCfecBer (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x23B
        header.Tag = 0
        header.MaxResponse = 16
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'staircaise_estimated_ber_mantissa' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8)),
             'staircaise_estimated_ber_order_of_magnitude' : (response[6] & 0xFF)|((response[7]<<8) & (0xFF<<8)),
             'hamming_estimated_ber_mantissa' : (response[8] & 0xFF)|((response[9]<<8) & (0xFF<<8)),
             'hamming_estimated_ber_order_of_magnitude' : (response[10] & 0xFF)|((response[11]<<8) & (0xFF<<8)),
             'UR_mantissa' : (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8)),
             'UR_order_of_magnitude' : (response[14] & 0xFF)|((response[15]<<8) & (0xFF<<8)),
        }
        self.check_response(apiResponse, CanopusApi.GetEstimatedPreCfecBer)
        self.add_api_exec_cb()
        return apiResponse

    def GetFawErrorStatisticsOccurrenceInfo (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x241
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'occurrence_max_fas_count' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8)),
             'occurrence_min_fas_count' : (response[6] & 0xFF)|((response[7]<<8) & (0xFF<<8)),
        }
        self.check_response(apiResponse, CanopusApi.GetFawErrorStatisticsOccurrenceInfo)
        self.add_api_exec_cb()
        return apiResponse

    def GetPcsErrorStatisticsOccurrenceInfo (self, channel, direction):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x242
        header.Tag = 0
        header.MaxResponse = 12
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'occurrence_max_bip8_count' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8)),
             'occurrence_min_bip8_count' : (response[6] & 0xFF)|((response[7]<<8) & (0xFF<<8)),
             'occurrence_max_sh_count' : (response[8] & 0xFF)|((response[9]<<8) & (0xFF<<8)),
             'occurrence_min_sh_count' : (response[10] & 0xFF)|((response[11]<<8) & (0xFF<<8)),
        }
        self.check_response(apiResponse, CanopusApi.GetPcsErrorStatisticsOccurrenceInfo)
        self.add_api_exec_cb()
        return apiResponse

    def GetErrorCorrectionStatisticsOccurrenceInfo (self, channel, direction):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x243
        header.Tag = 0
        header.MaxResponse = 12
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'occurrence_max_bit_count' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8)),
             'occurrence_min_bit_count' : (response[6] & 0xFF)|((response[7]<<8) & (0xFF<<8)),
             'occurrence_max_codeword_count' : (response[8] & 0xFF)|((response[9]<<8) & (0xFF<<8)),
             'occurrence_min_codeword_count' : (response[10] & 0xFF)|((response[11]<<8) & (0xFF<<8)),
        }
        self.check_response(apiResponse, CanopusApi.GetErrorCorrectionStatisticsOccurrenceInfo)
        self.add_api_exec_cb()
        return apiResponse

    def SetEthernetMaxFrameLength (self, channel, direction, max_packet_length, max_broad_multi_length, max_jabber_length):
        #Default header
        header=ArgHeader()
        header.Length = 16
        header.Command = 0x19B
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*16
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)
        command_array[10] = max_packet_length>>0
        command_array[11] = max_packet_length>>8
        # assert: (x < 0x3FFF)
        command_array[12] = max_broad_multi_length>>0
        command_array[13] = max_broad_multi_length>>8
        # assert: (x < 0x3FFF)
        command_array[14] = max_jabber_length>>0
        command_array[15] = max_jabber_length>>8
        # assert: (x < 0x3FFF)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetEthernetMaxFrameLength)
        self.add_api_exec_cb()
        return apiResponse

    def GetEthernetMaxFrameLength (self, channel, direction):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x19C
        header.Tag = 0
        header.MaxResponse = 12
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'max_packet_length' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8)),
             'max_broad_multi_length' : (response[6] & 0xFF)|((response[7]<<8) & (0xFF<<8)),
             'max_jabber_length' : (response[8] & 0xFF)|((response[9]<<8) & (0xFF<<8)),
        }
        self.check_response(apiResponse, CanopusApi.GetEthernetMaxFrameLength)
        self.add_api_exec_cb()
        return apiResponse

    def GetEthernetCounters (self, channel, direction):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x169
        header.Tag = 0
        header.MaxResponse = 140
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'ether_stats_undersize_pkts' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24))|((response[8]<<32) & (0xFF<<32))|((response[9]<<40) & (0xFF<<40))|((response[10]<<48) & (0xFF<<48))|((response[11]<<56) & (0xFF<<56)),
             'ether_stats_pkts_64_octets' : (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8))|((response[14]<<16) & (0xFF<<16))|((response[15]<<24) & (0xFF<<24))|((response[16]<<32) & (0xFF<<32))|((response[17]<<40) & (0xFF<<40))|((response[18]<<48) & (0xFF<<48))|((response[19]<<56) & (0xFF<<56)),
             'ether_stats_pkts_65_to_127_octets' : (response[20] & 0xFF)|((response[21]<<8) & (0xFF<<8))|((response[22]<<16) & (0xFF<<16))|((response[23]<<24) & (0xFF<<24))|((response[24]<<32) & (0xFF<<32))|((response[25]<<40) & (0xFF<<40))|((response[26]<<48) & (0xFF<<48))|((response[27]<<56) & (0xFF<<56)),
             'ether_stats_pkts_128_to_255_octets' : (response[28] & 0xFF)|((response[29]<<8) & (0xFF<<8))|((response[30]<<16) & (0xFF<<16))|((response[31]<<24) & (0xFF<<24))|((response[32]<<32) & (0xFF<<32))|((response[33]<<40) & (0xFF<<40))|((response[34]<<48) & (0xFF<<48))|((response[35]<<56) & (0xFF<<56)),
             'ether_stats_pkts_256_to_511_octets' : (response[36] & 0xFF)|((response[37]<<8) & (0xFF<<8))|((response[38]<<16) & (0xFF<<16))|((response[39]<<24) & (0xFF<<24))|((response[40]<<32) & (0xFF<<32))|((response[41]<<40) & (0xFF<<40))|((response[42]<<48) & (0xFF<<48))|((response[43]<<56) & (0xFF<<56)),
             'ether_stats_pkts_512_to_1023_octets' : (response[44] & 0xFF)|((response[45]<<8) & (0xFF<<8))|((response[46]<<16) & (0xFF<<16))|((response[47]<<24) & (0xFF<<24))|((response[48]<<32) & (0xFF<<32))|((response[49]<<40) & (0xFF<<40))|((response[50]<<48) & (0xFF<<48))|((response[51]<<56) & (0xFF<<56)),
             'ether_stats_pkts_1024_to_1518_octets' : (response[52] & 0xFF)|((response[53]<<8) & (0xFF<<8))|((response[54]<<16) & (0xFF<<16))|((response[55]<<24) & (0xFF<<24))|((response[56]<<32) & (0xFF<<32))|((response[57]<<40) & (0xFF<<40))|((response[58]<<48) & (0xFF<<48))|((response[59]<<56) & (0xFF<<56)),
             'ether_stats_pkts_1519_to_max_octets' : (response[60] & 0xFF)|((response[61]<<8) & (0xFF<<8))|((response[62]<<16) & (0xFF<<16))|((response[63]<<24) & (0xFF<<24))|((response[64]<<32) & (0xFF<<32))|((response[65]<<40) & (0xFF<<40))|((response[66]<<48) & (0xFF<<48))|((response[67]<<56) & (0xFF<<56)),
             'ether_stats_oversize_pkts' : (response[68] & 0xFF)|((response[69]<<8) & (0xFF<<8))|((response[70]<<16) & (0xFF<<16))|((response[71]<<24) & (0xFF<<24))|((response[72]<<32) & (0xFF<<32))|((response[73]<<40) & (0xFF<<40))|((response[74]<<48) & (0xFF<<48))|((response[75]<<56) & (0xFF<<56)),
             'ether_stats_pkts' : (response[76] & 0xFF)|((response[77]<<8) & (0xFF<<8))|((response[78]<<16) & (0xFF<<16))|((response[79]<<24) & (0xFF<<24))|((response[80]<<32) & (0xFF<<32))|((response[81]<<40) & (0xFF<<40))|((response[82]<<48) & (0xFF<<48))|((response[83]<<56) & (0xFF<<56)),
             'ether_stats_octets' : (response[84] & 0xFF)|((response[85]<<8) & (0xFF<<8))|((response[86]<<16) & (0xFF<<16))|((response[87]<<24) & (0xFF<<24))|((response[88]<<32) & (0xFF<<32))|((response[89]<<40) & (0xFF<<40))|((response[90]<<48) & (0xFF<<48))|((response[91]<<56) & (0xFF<<56)),
             'ether_stats_broadcast_pkts' : (response[92] & 0xFF)|((response[93]<<8) & (0xFF<<8))|((response[94]<<16) & (0xFF<<16))|((response[95]<<24) & (0xFF<<24))|((response[96]<<32) & (0xFF<<32))|((response[97]<<40) & (0xFF<<40))|((response[98]<<48) & (0xFF<<48))|((response[99]<<56) & (0xFF<<56)),
             'ether_stats_multicast_pkts' : (response[100] & 0xFF)|((response[101]<<8) & (0xFF<<8))|((response[102]<<16) & (0xFF<<16))|((response[103]<<24) & (0xFF<<24))|((response[104]<<32) & (0xFF<<32))|((response[105]<<40) & (0xFF<<40))|((response[106]<<48) & (0xFF<<48))|((response[107]<<56) & (0xFF<<56)),
             'ether_stats_jabbers' : (response[108] & 0xFF)|((response[109]<<8) & (0xFF<<8))|((response[110]<<16) & (0xFF<<16))|((response[111]<<24) & (0xFF<<24))|((response[112]<<32) & (0xFF<<32))|((response[113]<<40) & (0xFF<<40))|((response[114]<<48) & (0xFF<<48))|((response[115]<<56) & (0xFF<<56)),
             'ether_stats_fragments' : (response[116] & 0xFF)|((response[117]<<8) & (0xFF<<8))|((response[118]<<16) & (0xFF<<16))|((response[119]<<24) & (0xFF<<24))|((response[120]<<32) & (0xFF<<32))|((response[121]<<40) & (0xFF<<40))|((response[122]<<48) & (0xFF<<48))|((response[123]<<56) & (0xFF<<56)),
             'ether_stats_crcalignerrors' : (response[124] & 0xFF)|((response[125]<<8) & (0xFF<<8))|((response[126]<<16) & (0xFF<<16))|((response[127]<<24) & (0xFF<<24))|((response[128]<<32) & (0xFF<<32))|((response[129]<<40) & (0xFF<<40))|((response[130]<<48) & (0xFF<<48))|((response[131]<<56) & (0xFF<<56)),
             'ether_stats_packet_trap' : (response[132] & 0xFF)|((response[133]<<8) & (0xFF<<8))|((response[134]<<16) & (0xFF<<16))|((response[135]<<24) & (0xFF<<24))|((response[136]<<32) & (0xFF<<32))|((response[137]<<40) & (0xFF<<40))|((response[138]<<48) & (0xFF<<48))|((response[139]<<56) & (0xFF<<56)),
        }
        self.check_response(apiResponse, CanopusApi.GetEthernetCounters)
        self.add_api_exec_cb()
        return apiResponse

    def ReadEthernetPacketTrap (self, channel, direction, clean_memory):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x19A
        header.Tag = 0
        header.MaxResponse = 264
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)
        command_array[10] = clean_memory>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'frame_size' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8)),
             'remaining_bytes' : (response[6] & 0xFF)|((response[7]<<8) & (0xFF<<8)),
             'data' : [                          (response[8] & 0xFF),
                          (response[9] & 0xFF),
                          (response[10] & 0xFF),
                          (response[11] & 0xFF),
                          (response[12] & 0xFF),
                          (response[13] & 0xFF),
                          (response[14] & 0xFF),
                          (response[15] & 0xFF),
                          (response[16] & 0xFF),
                          (response[17] & 0xFF),
                          (response[18] & 0xFF),
                          (response[19] & 0xFF),
                          (response[20] & 0xFF),
                          (response[21] & 0xFF),
                          (response[22] & 0xFF),
                          (response[23] & 0xFF),
                          (response[24] & 0xFF),
                          (response[25] & 0xFF),
                          (response[26] & 0xFF),
                          (response[27] & 0xFF),
                          (response[28] & 0xFF),
                          (response[29] & 0xFF),
                          (response[30] & 0xFF),
                          (response[31] & 0xFF),
                          (response[32] & 0xFF),
                          (response[33] & 0xFF),
                          (response[34] & 0xFF),
                          (response[35] & 0xFF),
                          (response[36] & 0xFF),
                          (response[37] & 0xFF),
                          (response[38] & 0xFF),
                          (response[39] & 0xFF),
                          (response[40] & 0xFF),
                          (response[41] & 0xFF),
                          (response[42] & 0xFF),
                          (response[43] & 0xFF),
                          (response[44] & 0xFF),
                          (response[45] & 0xFF),
                          (response[46] & 0xFF),
                          (response[47] & 0xFF),
                          (response[48] & 0xFF),
                          (response[49] & 0xFF),
                          (response[50] & 0xFF),
                          (response[51] & 0xFF),
                          (response[52] & 0xFF),
                          (response[53] & 0xFF),
                          (response[54] & 0xFF),
                          (response[55] & 0xFF),
                          (response[56] & 0xFF),
                          (response[57] & 0xFF),
                          (response[58] & 0xFF),
                          (response[59] & 0xFF),
                          (response[60] & 0xFF),
                          (response[61] & 0xFF),
                          (response[62] & 0xFF),
                          (response[63] & 0xFF),
                          (response[64] & 0xFF),
                          (response[65] & 0xFF),
                          (response[66] & 0xFF),
                          (response[67] & 0xFF),
                          (response[68] & 0xFF),
                          (response[69] & 0xFF),
                          (response[70] & 0xFF),
                          (response[71] & 0xFF),
                          (response[72] & 0xFF),
                          (response[73] & 0xFF),
                          (response[74] & 0xFF),
                          (response[75] & 0xFF),
                          (response[76] & 0xFF),
                          (response[77] & 0xFF),
                          (response[78] & 0xFF),
                          (response[79] & 0xFF),
                          (response[80] & 0xFF),
                          (response[81] & 0xFF),
                          (response[82] & 0xFF),
                          (response[83] & 0xFF),
                          (response[84] & 0xFF),
                          (response[85] & 0xFF),
                          (response[86] & 0xFF),
                          (response[87] & 0xFF),
                          (response[88] & 0xFF),
                          (response[89] & 0xFF),
                          (response[90] & 0xFF),
                          (response[91] & 0xFF),
                          (response[92] & 0xFF),
                          (response[93] & 0xFF),
                          (response[94] & 0xFF),
                          (response[95] & 0xFF),
                          (response[96] & 0xFF),
                          (response[97] & 0xFF),
                          (response[98] & 0xFF),
                          (response[99] & 0xFF),
                          (response[100] & 0xFF),
                          (response[101] & 0xFF),
                          (response[102] & 0xFF),
                          (response[103] & 0xFF),
                          (response[104] & 0xFF),
                          (response[105] & 0xFF),
                          (response[106] & 0xFF),
                          (response[107] & 0xFF),
                          (response[108] & 0xFF),
                          (response[109] & 0xFF),
                          (response[110] & 0xFF),
                          (response[111] & 0xFF),
                          (response[112] & 0xFF),
                          (response[113] & 0xFF),
                          (response[114] & 0xFF),
                          (response[115] & 0xFF),
                          (response[116] & 0xFF),
                          (response[117] & 0xFF),
                          (response[118] & 0xFF),
                          (response[119] & 0xFF),
                          (response[120] & 0xFF),
                          (response[121] & 0xFF),
                          (response[122] & 0xFF),
                          (response[123] & 0xFF),
                          (response[124] & 0xFF),
                          (response[125] & 0xFF),
                          (response[126] & 0xFF),
                          (response[127] & 0xFF),
                          (response[128] & 0xFF),
                          (response[129] & 0xFF),
                          (response[130] & 0xFF),
                          (response[131] & 0xFF),
                          (response[132] & 0xFF),
                          (response[133] & 0xFF),
                          (response[134] & 0xFF),
                          (response[135] & 0xFF),
                          (response[136] & 0xFF),
                          (response[137] & 0xFF),
                          (response[138] & 0xFF),
                          (response[139] & 0xFF),
                          (response[140] & 0xFF),
                          (response[141] & 0xFF),
                          (response[142] & 0xFF),
                          (response[143] & 0xFF),
                          (response[144] & 0xFF),
                          (response[145] & 0xFF),
                          (response[146] & 0xFF),
                          (response[147] & 0xFF),
                          (response[148] & 0xFF),
                          (response[149] & 0xFF),
                          (response[150] & 0xFF),
                          (response[151] & 0xFF),
                          (response[152] & 0xFF),
                          (response[153] & 0xFF),
                          (response[154] & 0xFF),
                          (response[155] & 0xFF),
                          (response[156] & 0xFF),
                          (response[157] & 0xFF),
                          (response[158] & 0xFF),
                          (response[159] & 0xFF),
                          (response[160] & 0xFF),
                          (response[161] & 0xFF),
                          (response[162] & 0xFF),
                          (response[163] & 0xFF),
                          (response[164] & 0xFF),
                          (response[165] & 0xFF),
                          (response[166] & 0xFF),
                          (response[167] & 0xFF),
                          (response[168] & 0xFF),
                          (response[169] & 0xFF),
                          (response[170] & 0xFF),
                          (response[171] & 0xFF),
                          (response[172] & 0xFF),
                          (response[173] & 0xFF),
                          (response[174] & 0xFF),
                          (response[175] & 0xFF),
                          (response[176] & 0xFF),
                          (response[177] & 0xFF),
                          (response[178] & 0xFF),
                          (response[179] & 0xFF),
                          (response[180] & 0xFF),
                          (response[181] & 0xFF),
                          (response[182] & 0xFF),
                          (response[183] & 0xFF),
                          (response[184] & 0xFF),
                          (response[185] & 0xFF),
                          (response[186] & 0xFF),
                          (response[187] & 0xFF),
                          (response[188] & 0xFF),
                          (response[189] & 0xFF),
                          (response[190] & 0xFF),
                          (response[191] & 0xFF),
                          (response[192] & 0xFF),
                          (response[193] & 0xFF),
                          (response[194] & 0xFF),
                          (response[195] & 0xFF),
                          (response[196] & 0xFF),
                          (response[197] & 0xFF),
                          (response[198] & 0xFF),
                          (response[199] & 0xFF),
                          (response[200] & 0xFF),
                          (response[201] & 0xFF),
                          (response[202] & 0xFF),
                          (response[203] & 0xFF),
                          (response[204] & 0xFF),
                          (response[205] & 0xFF),
                          (response[206] & 0xFF),
                          (response[207] & 0xFF),
                          (response[208] & 0xFF),
                          (response[209] & 0xFF),
                          (response[210] & 0xFF),
                          (response[211] & 0xFF),
                          (response[212] & 0xFF),
                          (response[213] & 0xFF),
                          (response[214] & 0xFF),
                          (response[215] & 0xFF),
                          (response[216] & 0xFF),
                          (response[217] & 0xFF),
                          (response[218] & 0xFF),
                          (response[219] & 0xFF),
                          (response[220] & 0xFF),
                          (response[221] & 0xFF),
                          (response[222] & 0xFF),
                          (response[223] & 0xFF),
                          (response[224] & 0xFF),
                          (response[225] & 0xFF),
                          (response[226] & 0xFF),
                          (response[227] & 0xFF),
                          (response[228] & 0xFF),
                          (response[229] & 0xFF),
                          (response[230] & 0xFF),
                          (response[231] & 0xFF),
                          (response[232] & 0xFF),
                          (response[233] & 0xFF),
                          (response[234] & 0xFF),
                          (response[235] & 0xFF),
                          (response[236] & 0xFF),
                          (response[237] & 0xFF),
                          (response[238] & 0xFF),
                          (response[239] & 0xFF),
                          (response[240] & 0xFF),
                          (response[241] & 0xFF),
                          (response[242] & 0xFF),
                          (response[243] & 0xFF),
                          (response[244] & 0xFF),
                          (response[245] & 0xFF),
                          (response[246] & 0xFF),
                          (response[247] & 0xFF),
                          (response[248] & 0xFF),
                          (response[249] & 0xFF),
                          (response[250] & 0xFF),
                          (response[251] & 0xFF),
                          (response[252] & 0xFF),
                          (response[253] & 0xFF),
                          (response[254] & 0xFF),
                          (response[255] & 0xFF),
                          (response[256] & 0xFF),
                          (response[257] & 0xFF),
                          (response[258] & 0xFF),
                          (response[259] & 0xFF),
                          (response[260] & 0xFF),
                          (response[261] & 0xFF),
                          (response[262] & 0xFF),
                          (response[263] & 0xFF),
                          ],
        }
        self.check_response(apiResponse, CanopusApi.ReadEthernetPacketTrap)
        self.add_api_exec_cb()
        return apiResponse

    def GetEthernetPacketTrapConfig (self, channel, direction):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x199
        header.Tag = 0
        header.MaxResponse = 40
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'mac_source_address' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24))|((response[8]<<32) & (0xFF<<32))|((response[9]<<40) & (0xFF<<40))|((response[10]<<48) & (0xFF<<48))|((response[11]<<56) & (0xFF<<56)),
             'mac_source_address_mask' : (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8))|((response[14]<<16) & (0xFF<<16))|((response[15]<<24) & (0xFF<<24))|((response[16]<<32) & (0xFF<<32))|((response[17]<<40) & (0xFF<<40))|((response[18]<<48) & (0xFF<<48))|((response[19]<<56) & (0xFF<<56)),
             'mac_destination_address' : (response[20] & 0xFF)|((response[21]<<8) & (0xFF<<8))|((response[22]<<16) & (0xFF<<16))|((response[23]<<24) & (0xFF<<24))|((response[24]<<32) & (0xFF<<32))|((response[25]<<40) & (0xFF<<40))|((response[26]<<48) & (0xFF<<48))|((response[27]<<56) & (0xFF<<56)),
             'mac_destination_address_mask' : (response[28] & 0xFF)|((response[29]<<8) & (0xFF<<8))|((response[30]<<16) & (0xFF<<16))|((response[31]<<24) & (0xFF<<24))|((response[32]<<32) & (0xFF<<32))|((response[33]<<40) & (0xFF<<40))|((response[34]<<48) & (0xFF<<48))|((response[35]<<56) & (0xFF<<56)),
             'mac_ethertype' : (response[36] & 0xFF)|((response[37]<<8) & (0xFF<<8)),
             'mac_ethertype_mask' : (response[38] & 0xFF)|((response[39]<<8) & (0xFF<<8)),
        }
        self.check_response(apiResponse, CanopusApi.GetEthernetPacketTrapConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetEthernetPacketTrapConfig (self, channel, direction, mac_source_address, mac_source_address_mask, mac_destination_address, mac_destination_address_mask, mac_ethertype, mac_ethertype_mask):
        #Default header
        header=ArgHeader()
        header.Length = 48
        header.Command = 0x198
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*48
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)
        command_array[10] = mac_source_address>>0
        command_array[11] = mac_source_address>>8
        command_array[12] = mac_source_address>>16
        command_array[13] = mac_source_address>>24
        command_array[14] = mac_source_address>>32
        command_array[15] = mac_source_address>>40
        command_array[16] = mac_source_address>>48
        command_array[17] = mac_source_address>>56
        # assert: (x <= 0xFFFFFFFFFFFFULL)
        command_array[18] = mac_source_address_mask>>0
        command_array[19] = mac_source_address_mask>>8
        command_array[20] = mac_source_address_mask>>16
        command_array[21] = mac_source_address_mask>>24
        command_array[22] = mac_source_address_mask>>32
        command_array[23] = mac_source_address_mask>>40
        command_array[24] = mac_source_address_mask>>48
        command_array[25] = mac_source_address_mask>>56
        # assert: (x <= 0xFFFFFFFFFFFFULL)
        command_array[26] = mac_destination_address>>0
        command_array[27] = mac_destination_address>>8
        command_array[28] = mac_destination_address>>16
        command_array[29] = mac_destination_address>>24
        command_array[30] = mac_destination_address>>32
        command_array[31] = mac_destination_address>>40
        command_array[32] = mac_destination_address>>48
        command_array[33] = mac_destination_address>>56
        # assert: (x <= 0xFFFFFFFFFFFFULL)
        command_array[34] = mac_destination_address_mask>>0
        command_array[35] = mac_destination_address_mask>>8
        command_array[36] = mac_destination_address_mask>>16
        command_array[37] = mac_destination_address_mask>>24
        command_array[38] = mac_destination_address_mask>>32
        command_array[39] = mac_destination_address_mask>>40
        command_array[40] = mac_destination_address_mask>>48
        command_array[41] = mac_destination_address_mask>>56
        # assert: (x <= 0xFFFFFFFFFFFFULL)
        command_array[42] = mac_ethertype>>0
        command_array[43] = mac_ethertype>>8
        command_array[44] = mac_ethertype_mask>>0
        command_array[45] = mac_ethertype_mask>>8

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetEthernetPacketTrapConfig)
        self.add_api_exec_cb()
        return apiResponse

    def SetEthernetBjAmConfig (self, channel, four_lane_pmd):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x23D
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = four_lane_pmd>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetEthernetBjAmConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetEthernetBjAmConfig (self, channel):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x23E
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'four_lane_pmd' : (response[4] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetEthernetBjAmConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnOhpAlarms (self, channel, map_level):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x161
        header.Tag = 0
        header.MaxResponse = 16
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = map_level>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'ddeg_bus' : (response[4] & 0xFF),
             'dtim_bus' : (response[5] & 0xFF),
             'diae_bus' : (response[6] & 0xFF),
             'dbiae_bus' : (response[7] & 0xFF),
             'dbdi_bus' : (response[8] & 0xFF),
             'dltc_bus' : (response[9] & 0xFF),
             'dais_bus' : (response[10] & 0xFF),
             'doci_bus' : (response[11] & 0xFF),
             'dlck_bus' : (response[12] & 0xFF),
             'dmsim' : (response[13] & 0xFF),
             'dplm' : (response[14] & 0xFF),
             'dcsf' : (response[15] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtnOhpAlarms)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnAlarms (self, channel, direction):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x15F
        header.Tag = 0
        header.MaxResponse = 12
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'otu_dloflane_bus' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24)),
             'otu_dlol' : (response[8] & 0xFF),
             'otu_dlof' : (response[9] & 0xFF),
             'otu_dlom' : (response[10] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtnAlarms)
        self.add_api_exec_cb()
        return apiResponse

    def GetOtnGmpAlarms (self, channel):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x160
        header.Tag = 0
        header.MaxResponse = 12
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'odu_map1_dloflom' : (response[4] & 0xFF),
             'odu_map2_dloflom' : (response[5] & 0xFF),
             'gmp_host_dloomfi' : (response[6] & 0xFF),
             'gmp_map1_dloomfi' : (response[7] & 0xFF),
             'gmp_map2_dloomfi' : (response[8] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetOtnGmpAlarms)
        self.add_api_exec_cb()
        return apiResponse

    def GetEthernetAlarms (self, channel, direction):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x162
        header.Tag = 0
        header.MaxResponse = 20
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 4)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'pcs_align_status_n' : (response[4] & 0xFF),
             'pcs_lf_detected' : (response[5] & 0xFF),
             'pcs_rf_detected' : (response[6] & 0xFF),
             'pcs_hi_ber' : (response[7] & 0xFF),
             'pcs_hi_ser' : (response[8] & 0xFF),
             'pcs257_am_lock_n' : (response[9] & 0xFF),
             'pcs66_block_lock_n' : (response[10] & 0xFF)|((response[11]<<8) & (0xFF<<8))|((response[12]<<16) & (0xFF<<16))|((response[13]<<24) & (0xFF<<24)),
             'pcs66_am_lock_n' : (response[14] & 0xFF)|((response[15]<<8) & (0xFF<<8))|((response[16]<<16) & (0xFF<<16))|((response[17]<<24) & (0xFF<<24)),
        }
        self.check_response(apiResponse, CanopusApi.GetEthernetAlarms)
        self.add_api_exec_cb()
        return apiResponse

    def GetFlexOAlarms (self, channel):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x163
        header.Tag = 0
        header.MaxResponse = 12
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'flexo_dlol' : (response[4] & 0xFF),
             'flexo_dlom' : (response[5] & 0xFF),
             'flexo_dloflom' : (response[6] & 0xFF),
             'flexo_drdi' : (response[7] & 0xFF),
             'flexo_dgidm' : (response[8] & 0xFF),
             'flexo_dpmm' : (response[9] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetFlexOAlarms)
        self.add_api_exec_cb()
        return apiResponse

    def GetFlexEAlarms (self, channel, direction):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x164
        header.Tag = 0
        header.MaxResponse = 12
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = channel>>0
        # assert: (x >= 0 && x <= 3)
        command_array[9] = direction>>0
        # assert: (x >= 1 && x <= 2)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'flexe_drdi' : (response[4] & 0xFF),
             'flexe_dgidm' : (response[5] & 0xFF),
             'flexe_dpmm' : (response[6] & 0xFF),
             'flexe_dlof' : (response[7] & 0xFF),
             'flexe_dlom' : (response[8] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetFlexEAlarms)
        self.add_api_exec_cb()
        return apiResponse

    def GetTemperature (self, sensor_id_0, sensor_id_1, sensor_id_2, sensor_id_3):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1E6
        header.Tag = 0
        header.MaxResponse = 20
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = sensor_id_0>>0
        # assert: (x >= 0 && x <= 13)
        command_array[9] = sensor_id_1>>0
        # assert: (x >= 0 && x <= 13)
        command_array[10] = sensor_id_2>>0
        # assert: (x >= 0 && x <= 13)
        command_array[11] = sensor_id_3>>0
        # assert: (x >= 0 && x <= 13)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'temperature_id_0' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8))|((response[6]<<16) & (0xFF<<16))|((response[7]<<24) & (0xFF<<24)),
             'temperature_id_1' : (response[8] & 0xFF)|((response[9]<<8) & (0xFF<<8))|((response[10]<<16) & (0xFF<<16))|((response[11]<<24) & (0xFF<<24)),
             'temperature_id_2' : (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8))|((response[14]<<16) & (0xFF<<16))|((response[15]<<24) & (0xFF<<24)),
             'temperature_id_3' : (response[16] & 0xFF)|((response[17]<<8) & (0xFF<<8))|((response[18]<<16) & (0xFF<<16))|((response[19]<<24) & (0xFF<<24)),
        }
        self.check_response(apiResponse, CanopusApi.GetTemperature)
        self.add_api_exec_cb()
        return apiResponse

    def ReadLinePowerSupply (self, lane):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0xF9
        header.Tag = 0
        header.MaxResponse = 188
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = lane>>0
        # assert: (x >= 0 && x <= 3)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'rx_vdda' : [                          (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8)),
                          (response[6] & 0xFF)|((response[7]<<8) & (0xFF<<8)),
                          (response[8] & 0xFF)|((response[9]<<8) & (0xFF<<8)),
                          (response[10] & 0xFF)|((response[11]<<8) & (0xFF<<8)),
                          (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8)),
                          (response[14] & 0xFF)|((response[15]<<8) & (0xFF<<8)),
                          ],
             'rx_vssa' : [                          (response[16] & 0xFF)|((response[17]<<8) & (0xFF<<8)),
                          (response[18] & 0xFF)|((response[19]<<8) & (0xFF<<8)),
                          (response[20] & 0xFF)|((response[21]<<8) & (0xFF<<8)),
                          (response[22] & 0xFF)|((response[23]<<8) & (0xFF<<8)),
                          (response[24] & 0xFF)|((response[25]<<8) & (0xFF<<8)),
                          (response[26] & 0xFF)|((response[27]<<8) & (0xFF<<8)),
                          (response[28] & 0xFF)|((response[29]<<8) & (0xFF<<8)),
                          (response[30] & 0xFF)|((response[31]<<8) & (0xFF<<8)),
                          (response[32] & 0xFF)|((response[33]<<8) & (0xFF<<8)),
                          (response[34] & 0xFF)|((response[35]<<8) & (0xFF<<8)),
                          ],
             'rx_net1' : [                          (response[36] & 0xFF)|((response[37]<<8) & (0xFF<<8)),
                          (response[38] & 0xFF)|((response[39]<<8) & (0xFF<<8)),
                          (response[40] & 0xFF)|((response[41]<<8) & (0xFF<<8)),
                          (response[42] & 0xFF)|((response[43]<<8) & (0xFF<<8)),
                          (response[44] & 0xFF)|((response[45]<<8) & (0xFF<<8)),
                          (response[46] & 0xFF)|((response[47]<<8) & (0xFF<<8)),
                          (response[48] & 0xFF)|((response[49]<<8) & (0xFF<<8)),
                          (response[50] & 0xFF)|((response[51]<<8) & (0xFF<<8)),
                          (response[52] & 0xFF)|((response[53]<<8) & (0xFF<<8)),
                          (response[54] & 0xFF)|((response[55]<<8) & (0xFF<<8)),
                          (response[56] & 0xFF)|((response[57]<<8) & (0xFF<<8)),
                          (response[58] & 0xFF)|((response[59]<<8) & (0xFF<<8)),
                          ],
             'rx_net2' : [                          (response[60] & 0xFF)|((response[61]<<8) & (0xFF<<8)),
                          (response[62] & 0xFF)|((response[63]<<8) & (0xFF<<8)),
                          (response[64] & 0xFF)|((response[65]<<8) & (0xFF<<8)),
                          (response[66] & 0xFF)|((response[67]<<8) & (0xFF<<8)),
                          (response[68] & 0xFF)|((response[69]<<8) & (0xFF<<8)),
                          (response[70] & 0xFF)|((response[71]<<8) & (0xFF<<8)),
                          (response[72] & 0xFF)|((response[73]<<8) & (0xFF<<8)),
                          (response[74] & 0xFF)|((response[75]<<8) & (0xFF<<8)),
                          (response[76] & 0xFF)|((response[77]<<8) & (0xFF<<8)),
                          (response[78] & 0xFF)|((response[79]<<8) & (0xFF<<8)),
                          (response[80] & 0xFF)|((response[81]<<8) & (0xFF<<8)),
                          (response[82] & 0xFF)|((response[83]<<8) & (0xFF<<8)),
                          ],
             'rx_net3' : [                          (response[84] & 0xFF)|((response[85]<<8) & (0xFF<<8)),
                          (response[86] & 0xFF)|((response[87]<<8) & (0xFF<<8)),
                          (response[88] & 0xFF)|((response[89]<<8) & (0xFF<<8)),
                          (response[90] & 0xFF)|((response[91]<<8) & (0xFF<<8)),
                          (response[92] & 0xFF)|((response[93]<<8) & (0xFF<<8)),
                          (response[94] & 0xFF)|((response[95]<<8) & (0xFF<<8)),
                          (response[96] & 0xFF)|((response[97]<<8) & (0xFF<<8)),
                          (response[98] & 0xFF)|((response[99]<<8) & (0xFF<<8)),
                          (response[100] & 0xFF)|((response[101]<<8) & (0xFF<<8)),
                          (response[102] & 0xFF)|((response[103]<<8) & (0xFF<<8)),
                          (response[104] & 0xFF)|((response[105]<<8) & (0xFF<<8)),
                          (response[106] & 0xFF)|((response[107]<<8) & (0xFF<<8)),
                          ],
             'rx_net4' : [                          (response[108] & 0xFF)|((response[109]<<8) & (0xFF<<8)),
                          (response[110] & 0xFF)|((response[111]<<8) & (0xFF<<8)),
                          (response[112] & 0xFF)|((response[113]<<8) & (0xFF<<8)),
                          (response[114] & 0xFF)|((response[115]<<8) & (0xFF<<8)),
                          (response[116] & 0xFF)|((response[117]<<8) & (0xFF<<8)),
                          (response[118] & 0xFF)|((response[119]<<8) & (0xFF<<8)),
                          (response[120] & 0xFF)|((response[121]<<8) & (0xFF<<8)),
                          (response[122] & 0xFF)|((response[123]<<8) & (0xFF<<8)),
                          (response[124] & 0xFF)|((response[125]<<8) & (0xFF<<8)),
                          (response[126] & 0xFF)|((response[127]<<8) & (0xFF<<8)),
                          (response[128] & 0xFF)|((response[129]<<8) & (0xFF<<8)),
                          (response[130] & 0xFF)|((response[131]<<8) & (0xFF<<8)),
                          ],
             'tx_vdda_h' : (response[132] & 0xFF)|((response[133]<<8) & (0xFF<<8)),
             'tx_vddd_h' : (response[134] & 0xFF)|((response[135]<<8) & (0xFF<<8)),
             'tx_vdda_v' : (response[136] & 0xFF)|((response[137]<<8) & (0xFF<<8)),
             'tx_vddd_v' : (response[138] & 0xFF)|((response[139]<<8) & (0xFF<<8)),
             'tx_net1' : [                          (response[140] & 0xFF)|((response[141]<<8) & (0xFF<<8)),
                          (response[142] & 0xFF)|((response[143]<<8) & (0xFF<<8)),
                          (response[144] & 0xFF)|((response[145]<<8) & (0xFF<<8)),
                          (response[146] & 0xFF)|((response[147]<<8) & (0xFF<<8)),
                          (response[148] & 0xFF)|((response[149]<<8) & (0xFF<<8)),
                          (response[150] & 0xFF)|((response[151]<<8) & (0xFF<<8)),
                          (response[152] & 0xFF)|((response[153]<<8) & (0xFF<<8)),
                          (response[154] & 0xFF)|((response[155]<<8) & (0xFF<<8)),
                          (response[156] & 0xFF)|((response[157]<<8) & (0xFF<<8)),
                          (response[158] & 0xFF)|((response[159]<<8) & (0xFF<<8)),
                          (response[160] & 0xFF)|((response[161]<<8) & (0xFF<<8)),
                          (response[162] & 0xFF)|((response[163]<<8) & (0xFF<<8)),
                          ],
             'tx_net2' : [                          (response[164] & 0xFF)|((response[165]<<8) & (0xFF<<8)),
                          (response[166] & 0xFF)|((response[167]<<8) & (0xFF<<8)),
                          (response[168] & 0xFF)|((response[169]<<8) & (0xFF<<8)),
                          (response[170] & 0xFF)|((response[171]<<8) & (0xFF<<8)),
                          (response[172] & 0xFF)|((response[173]<<8) & (0xFF<<8)),
                          (response[174] & 0xFF)|((response[175]<<8) & (0xFF<<8)),
                          (response[176] & 0xFF)|((response[177]<<8) & (0xFF<<8)),
                          (response[178] & 0xFF)|((response[179]<<8) & (0xFF<<8)),
                          (response[180] & 0xFF)|((response[181]<<8) & (0xFF<<8)),
                          (response[182] & 0xFF)|((response[183]<<8) & (0xFF<<8)),
                          (response[184] & 0xFF)|((response[185]<<8) & (0xFF<<8)),
                          (response[186] & 0xFF)|((response[187]<<8) & (0xFF<<8)),
                          ],
        }
        self.check_response(apiResponse, CanopusApi.ReadLinePowerSupply)
        self.add_api_exec_cb()
        return apiResponse

    def RunDiagnosticUnitCapture (self, signal_source):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1D9
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = signal_source>>0
        # assert: (x >= 1 && x <= 6)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.RunDiagnosticUnitCapture)
        self.add_api_exec_cb()
        return apiResponse

    def GetPllStatus (self, pll_select):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x1F8
        header.Tag = 0
        header.MaxResponse = 76
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = pll_select>>0
        # assert: (x >= 0 && x <= 12)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'pll_lock_int' : (response[4] & 0xFF),
             'pll_lock_ints' : (response[5] & 0xFF),
             'reserved_0' : (response[6] & 0xFF),
             'reserved_1' : (response[7] & 0xFF),
             'reserved_2' : (response[8] & 0xFF),
             'reserved_3' : (response[9] & 0xFF),
             'reserved_4' : (response[10] & 0xFF)|((response[11]<<8) & (0xFF<<8)),
             'reserved_5' : (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8)),
             'reserved_6' : (response[14] & 0xFF)|((response[15]<<8) & (0xFF<<8)),
             'reserved_7' : (response[16] & 0xFF)|((response[17]<<8) & (0xFF<<8)),
             'reserved_8' : (response[18] & 0xFF),
             'reserved_9' : (response[19] & 0xFF),
             'reserved_10' : (response[20] & 0xFF)|((response[21]<<8) & (0xFF<<8)),
             'reserved_11' : (response[22] & 0xFF),
             'reserved_12' : (response[23] & 0xFF),
             'reserved_13' : (response[24] & 0xFF)|((response[25]<<8) & (0xFF<<8)),
             'reserved_14' : (response[26] & 0xFF),
             'reserved_15' : (response[27] & 0xFF),
             'reserved_16' : (response[28] & 0xFF),
             'reserved_17' : (response[29] & 0xFF),
             'reserved_18' : (response[30] & 0xFF)|((response[31]<<8) & (0xFF<<8)),
             'reserved_19' : (response[32] & 0xFF),
             'reserved_20' : (response[33] & 0xFF),
             'reserved_21' : (response[34] & 0xFF),
             'reserved_22' : (response[35] & 0xFF),
             'reserved_23' : (response[36] & 0xFF),
             'reserved_24' : (response[37] & 0xFF),
             'reserved_25' : (response[38] & 0xFF),
             'reserved_26' : (response[39] & 0xFF),
             'reserved_27' : (response[40] & 0xFF),
             'reserved_28' : (response[41] & 0xFF)|((response[42]<<8) & (0xFF<<8))|((response[43]<<16) & (0xFF<<16))|((response[44]<<24) & (0xFF<<24)),
             'reserved_29' : (response[45] & 0xFF)|((response[46]<<8) & (0xFF<<8))|((response[47]<<16) & (0xFF<<16))|((response[48]<<24) & (0xFF<<24)),
             'reserved_30' : (response[49] & 0xFF)|((response[50]<<8) & (0xFF<<8))|((response[51]<<16) & (0xFF<<16))|((response[52]<<24) & (0xFF<<24)),
             'reserved_31' : (response[53] & 0xFF),
             'reserved_32' : (response[54] & 0xFF)|((response[55]<<8) & (0xFF<<8))|((response[56]<<16) & (0xFF<<16))|((response[57]<<24) & (0xFF<<24)),
             'reserved_33' : (response[58] & 0xFF)|((response[59]<<8) & (0xFF<<8))|((response[60]<<16) & (0xFF<<16))|((response[61]<<24) & (0xFF<<24)),
             'reserved_34' : (response[62] & 0xFF),
             'reserved_35' : (response[63] & 0xFF),
             'reserved_36' : (response[64] & 0xFF),
             'reserved_37' : (response[65] & 0xFF),
             'reserved_38' : (response[66] & 0xFF),
             'reserved_39' : (response[67] & 0xFF),
             'reserved_40' : (response[68] & 0xFF),
             'reserved_41' : (response[69] & 0xFF),
             'reserved_42' : (response[70] & 0xFF),
             'reserved_43' : (response[71] & 0xFF),
             'reserved_44' : (response[72] & 0xFF),
             'reserved_45' : (response[73] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetPllStatus)
        self.add_api_exec_cb()
        return apiResponse

    def GetDiagnosticUnitCaptureData (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x1DA
        header.Tag = 0
        header.MaxResponse = 392
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'valid_data_elements' : (response[4] & 0xFF),
             'remaining_pages' : (response[5] & 0xFF),
             'remaining_cycles' : (response[6] & 0xFF)|((response[7]<<8) & (0xFF<<8)),
             'data' : [                          (response[8] & 0xFF)|((response[9]<<8) & (0xFF<<8))|((response[10]<<16) & (0xFF<<16))|((response[11]<<24) & (0xFF<<24)),
                          (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8))|((response[14]<<16) & (0xFF<<16))|((response[15]<<24) & (0xFF<<24)),
                          (response[16] & 0xFF)|((response[17]<<8) & (0xFF<<8))|((response[18]<<16) & (0xFF<<16))|((response[19]<<24) & (0xFF<<24)),
                          (response[20] & 0xFF)|((response[21]<<8) & (0xFF<<8))|((response[22]<<16) & (0xFF<<16))|((response[23]<<24) & (0xFF<<24)),
                          (response[24] & 0xFF)|((response[25]<<8) & (0xFF<<8))|((response[26]<<16) & (0xFF<<16))|((response[27]<<24) & (0xFF<<24)),
                          (response[28] & 0xFF)|((response[29]<<8) & (0xFF<<8))|((response[30]<<16) & (0xFF<<16))|((response[31]<<24) & (0xFF<<24)),
                          (response[32] & 0xFF)|((response[33]<<8) & (0xFF<<8))|((response[34]<<16) & (0xFF<<16))|((response[35]<<24) & (0xFF<<24)),
                          (response[36] & 0xFF)|((response[37]<<8) & (0xFF<<8))|((response[38]<<16) & (0xFF<<16))|((response[39]<<24) & (0xFF<<24)),
                          (response[40] & 0xFF)|((response[41]<<8) & (0xFF<<8))|((response[42]<<16) & (0xFF<<16))|((response[43]<<24) & (0xFF<<24)),
                          (response[44] & 0xFF)|((response[45]<<8) & (0xFF<<8))|((response[46]<<16) & (0xFF<<16))|((response[47]<<24) & (0xFF<<24)),
                          (response[48] & 0xFF)|((response[49]<<8) & (0xFF<<8))|((response[50]<<16) & (0xFF<<16))|((response[51]<<24) & (0xFF<<24)),
                          (response[52] & 0xFF)|((response[53]<<8) & (0xFF<<8))|((response[54]<<16) & (0xFF<<16))|((response[55]<<24) & (0xFF<<24)),
                          (response[56] & 0xFF)|((response[57]<<8) & (0xFF<<8))|((response[58]<<16) & (0xFF<<16))|((response[59]<<24) & (0xFF<<24)),
                          (response[60] & 0xFF)|((response[61]<<8) & (0xFF<<8))|((response[62]<<16) & (0xFF<<16))|((response[63]<<24) & (0xFF<<24)),
                          (response[64] & 0xFF)|((response[65]<<8) & (0xFF<<8))|((response[66]<<16) & (0xFF<<16))|((response[67]<<24) & (0xFF<<24)),
                          (response[68] & 0xFF)|((response[69]<<8) & (0xFF<<8))|((response[70]<<16) & (0xFF<<16))|((response[71]<<24) & (0xFF<<24)),
                          (response[72] & 0xFF)|((response[73]<<8) & (0xFF<<8))|((response[74]<<16) & (0xFF<<16))|((response[75]<<24) & (0xFF<<24)),
                          (response[76] & 0xFF)|((response[77]<<8) & (0xFF<<8))|((response[78]<<16) & (0xFF<<16))|((response[79]<<24) & (0xFF<<24)),
                          (response[80] & 0xFF)|((response[81]<<8) & (0xFF<<8))|((response[82]<<16) & (0xFF<<16))|((response[83]<<24) & (0xFF<<24)),
                          (response[84] & 0xFF)|((response[85]<<8) & (0xFF<<8))|((response[86]<<16) & (0xFF<<16))|((response[87]<<24) & (0xFF<<24)),
                          (response[88] & 0xFF)|((response[89]<<8) & (0xFF<<8))|((response[90]<<16) & (0xFF<<16))|((response[91]<<24) & (0xFF<<24)),
                          (response[92] & 0xFF)|((response[93]<<8) & (0xFF<<8))|((response[94]<<16) & (0xFF<<16))|((response[95]<<24) & (0xFF<<24)),
                          (response[96] & 0xFF)|((response[97]<<8) & (0xFF<<8))|((response[98]<<16) & (0xFF<<16))|((response[99]<<24) & (0xFF<<24)),
                          (response[100] & 0xFF)|((response[101]<<8) & (0xFF<<8))|((response[102]<<16) & (0xFF<<16))|((response[103]<<24) & (0xFF<<24)),
                          (response[104] & 0xFF)|((response[105]<<8) & (0xFF<<8))|((response[106]<<16) & (0xFF<<16))|((response[107]<<24) & (0xFF<<24)),
                          (response[108] & 0xFF)|((response[109]<<8) & (0xFF<<8))|((response[110]<<16) & (0xFF<<16))|((response[111]<<24) & (0xFF<<24)),
                          (response[112] & 0xFF)|((response[113]<<8) & (0xFF<<8))|((response[114]<<16) & (0xFF<<16))|((response[115]<<24) & (0xFF<<24)),
                          (response[116] & 0xFF)|((response[117]<<8) & (0xFF<<8))|((response[118]<<16) & (0xFF<<16))|((response[119]<<24) & (0xFF<<24)),
                          (response[120] & 0xFF)|((response[121]<<8) & (0xFF<<8))|((response[122]<<16) & (0xFF<<16))|((response[123]<<24) & (0xFF<<24)),
                          (response[124] & 0xFF)|((response[125]<<8) & (0xFF<<8))|((response[126]<<16) & (0xFF<<16))|((response[127]<<24) & (0xFF<<24)),
                          (response[128] & 0xFF)|((response[129]<<8) & (0xFF<<8))|((response[130]<<16) & (0xFF<<16))|((response[131]<<24) & (0xFF<<24)),
                          (response[132] & 0xFF)|((response[133]<<8) & (0xFF<<8))|((response[134]<<16) & (0xFF<<16))|((response[135]<<24) & (0xFF<<24)),
                          (response[136] & 0xFF)|((response[137]<<8) & (0xFF<<8))|((response[138]<<16) & (0xFF<<16))|((response[139]<<24) & (0xFF<<24)),
                          (response[140] & 0xFF)|((response[141]<<8) & (0xFF<<8))|((response[142]<<16) & (0xFF<<16))|((response[143]<<24) & (0xFF<<24)),
                          (response[144] & 0xFF)|((response[145]<<8) & (0xFF<<8))|((response[146]<<16) & (0xFF<<16))|((response[147]<<24) & (0xFF<<24)),
                          (response[148] & 0xFF)|((response[149]<<8) & (0xFF<<8))|((response[150]<<16) & (0xFF<<16))|((response[151]<<24) & (0xFF<<24)),
                          (response[152] & 0xFF)|((response[153]<<8) & (0xFF<<8))|((response[154]<<16) & (0xFF<<16))|((response[155]<<24) & (0xFF<<24)),
                          (response[156] & 0xFF)|((response[157]<<8) & (0xFF<<8))|((response[158]<<16) & (0xFF<<16))|((response[159]<<24) & (0xFF<<24)),
                          (response[160] & 0xFF)|((response[161]<<8) & (0xFF<<8))|((response[162]<<16) & (0xFF<<16))|((response[163]<<24) & (0xFF<<24)),
                          (response[164] & 0xFF)|((response[165]<<8) & (0xFF<<8))|((response[166]<<16) & (0xFF<<16))|((response[167]<<24) & (0xFF<<24)),
                          (response[168] & 0xFF)|((response[169]<<8) & (0xFF<<8))|((response[170]<<16) & (0xFF<<16))|((response[171]<<24) & (0xFF<<24)),
                          (response[172] & 0xFF)|((response[173]<<8) & (0xFF<<8))|((response[174]<<16) & (0xFF<<16))|((response[175]<<24) & (0xFF<<24)),
                          (response[176] & 0xFF)|((response[177]<<8) & (0xFF<<8))|((response[178]<<16) & (0xFF<<16))|((response[179]<<24) & (0xFF<<24)),
                          (response[180] & 0xFF)|((response[181]<<8) & (0xFF<<8))|((response[182]<<16) & (0xFF<<16))|((response[183]<<24) & (0xFF<<24)),
                          (response[184] & 0xFF)|((response[185]<<8) & (0xFF<<8))|((response[186]<<16) & (0xFF<<16))|((response[187]<<24) & (0xFF<<24)),
                          (response[188] & 0xFF)|((response[189]<<8) & (0xFF<<8))|((response[190]<<16) & (0xFF<<16))|((response[191]<<24) & (0xFF<<24)),
                          (response[192] & 0xFF)|((response[193]<<8) & (0xFF<<8))|((response[194]<<16) & (0xFF<<16))|((response[195]<<24) & (0xFF<<24)),
                          (response[196] & 0xFF)|((response[197]<<8) & (0xFF<<8))|((response[198]<<16) & (0xFF<<16))|((response[199]<<24) & (0xFF<<24)),
                          (response[200] & 0xFF)|((response[201]<<8) & (0xFF<<8))|((response[202]<<16) & (0xFF<<16))|((response[203]<<24) & (0xFF<<24)),
                          (response[204] & 0xFF)|((response[205]<<8) & (0xFF<<8))|((response[206]<<16) & (0xFF<<16))|((response[207]<<24) & (0xFF<<24)),
                          (response[208] & 0xFF)|((response[209]<<8) & (0xFF<<8))|((response[210]<<16) & (0xFF<<16))|((response[211]<<24) & (0xFF<<24)),
                          (response[212] & 0xFF)|((response[213]<<8) & (0xFF<<8))|((response[214]<<16) & (0xFF<<16))|((response[215]<<24) & (0xFF<<24)),
                          (response[216] & 0xFF)|((response[217]<<8) & (0xFF<<8))|((response[218]<<16) & (0xFF<<16))|((response[219]<<24) & (0xFF<<24)),
                          (response[220] & 0xFF)|((response[221]<<8) & (0xFF<<8))|((response[222]<<16) & (0xFF<<16))|((response[223]<<24) & (0xFF<<24)),
                          (response[224] & 0xFF)|((response[225]<<8) & (0xFF<<8))|((response[226]<<16) & (0xFF<<16))|((response[227]<<24) & (0xFF<<24)),
                          (response[228] & 0xFF)|((response[229]<<8) & (0xFF<<8))|((response[230]<<16) & (0xFF<<16))|((response[231]<<24) & (0xFF<<24)),
                          (response[232] & 0xFF)|((response[233]<<8) & (0xFF<<8))|((response[234]<<16) & (0xFF<<16))|((response[235]<<24) & (0xFF<<24)),
                          (response[236] & 0xFF)|((response[237]<<8) & (0xFF<<8))|((response[238]<<16) & (0xFF<<16))|((response[239]<<24) & (0xFF<<24)),
                          (response[240] & 0xFF)|((response[241]<<8) & (0xFF<<8))|((response[242]<<16) & (0xFF<<16))|((response[243]<<24) & (0xFF<<24)),
                          (response[244] & 0xFF)|((response[245]<<8) & (0xFF<<8))|((response[246]<<16) & (0xFF<<16))|((response[247]<<24) & (0xFF<<24)),
                          (response[248] & 0xFF)|((response[249]<<8) & (0xFF<<8))|((response[250]<<16) & (0xFF<<16))|((response[251]<<24) & (0xFF<<24)),
                          (response[252] & 0xFF)|((response[253]<<8) & (0xFF<<8))|((response[254]<<16) & (0xFF<<16))|((response[255]<<24) & (0xFF<<24)),
                          (response[256] & 0xFF)|((response[257]<<8) & (0xFF<<8))|((response[258]<<16) & (0xFF<<16))|((response[259]<<24) & (0xFF<<24)),
                          (response[260] & 0xFF)|((response[261]<<8) & (0xFF<<8))|((response[262]<<16) & (0xFF<<16))|((response[263]<<24) & (0xFF<<24)),
                          (response[264] & 0xFF)|((response[265]<<8) & (0xFF<<8))|((response[266]<<16) & (0xFF<<16))|((response[267]<<24) & (0xFF<<24)),
                          (response[268] & 0xFF)|((response[269]<<8) & (0xFF<<8))|((response[270]<<16) & (0xFF<<16))|((response[271]<<24) & (0xFF<<24)),
                          (response[272] & 0xFF)|((response[273]<<8) & (0xFF<<8))|((response[274]<<16) & (0xFF<<16))|((response[275]<<24) & (0xFF<<24)),
                          (response[276] & 0xFF)|((response[277]<<8) & (0xFF<<8))|((response[278]<<16) & (0xFF<<16))|((response[279]<<24) & (0xFF<<24)),
                          (response[280] & 0xFF)|((response[281]<<8) & (0xFF<<8))|((response[282]<<16) & (0xFF<<16))|((response[283]<<24) & (0xFF<<24)),
                          (response[284] & 0xFF)|((response[285]<<8) & (0xFF<<8))|((response[286]<<16) & (0xFF<<16))|((response[287]<<24) & (0xFF<<24)),
                          (response[288] & 0xFF)|((response[289]<<8) & (0xFF<<8))|((response[290]<<16) & (0xFF<<16))|((response[291]<<24) & (0xFF<<24)),
                          (response[292] & 0xFF)|((response[293]<<8) & (0xFF<<8))|((response[294]<<16) & (0xFF<<16))|((response[295]<<24) & (0xFF<<24)),
                          (response[296] & 0xFF)|((response[297]<<8) & (0xFF<<8))|((response[298]<<16) & (0xFF<<16))|((response[299]<<24) & (0xFF<<24)),
                          (response[300] & 0xFF)|((response[301]<<8) & (0xFF<<8))|((response[302]<<16) & (0xFF<<16))|((response[303]<<24) & (0xFF<<24)),
                          (response[304] & 0xFF)|((response[305]<<8) & (0xFF<<8))|((response[306]<<16) & (0xFF<<16))|((response[307]<<24) & (0xFF<<24)),
                          (response[308] & 0xFF)|((response[309]<<8) & (0xFF<<8))|((response[310]<<16) & (0xFF<<16))|((response[311]<<24) & (0xFF<<24)),
                          (response[312] & 0xFF)|((response[313]<<8) & (0xFF<<8))|((response[314]<<16) & (0xFF<<16))|((response[315]<<24) & (0xFF<<24)),
                          (response[316] & 0xFF)|((response[317]<<8) & (0xFF<<8))|((response[318]<<16) & (0xFF<<16))|((response[319]<<24) & (0xFF<<24)),
                          (response[320] & 0xFF)|((response[321]<<8) & (0xFF<<8))|((response[322]<<16) & (0xFF<<16))|((response[323]<<24) & (0xFF<<24)),
                          (response[324] & 0xFF)|((response[325]<<8) & (0xFF<<8))|((response[326]<<16) & (0xFF<<16))|((response[327]<<24) & (0xFF<<24)),
                          (response[328] & 0xFF)|((response[329]<<8) & (0xFF<<8))|((response[330]<<16) & (0xFF<<16))|((response[331]<<24) & (0xFF<<24)),
                          (response[332] & 0xFF)|((response[333]<<8) & (0xFF<<8))|((response[334]<<16) & (0xFF<<16))|((response[335]<<24) & (0xFF<<24)),
                          (response[336] & 0xFF)|((response[337]<<8) & (0xFF<<8))|((response[338]<<16) & (0xFF<<16))|((response[339]<<24) & (0xFF<<24)),
                          (response[340] & 0xFF)|((response[341]<<8) & (0xFF<<8))|((response[342]<<16) & (0xFF<<16))|((response[343]<<24) & (0xFF<<24)),
                          (response[344] & 0xFF)|((response[345]<<8) & (0xFF<<8))|((response[346]<<16) & (0xFF<<16))|((response[347]<<24) & (0xFF<<24)),
                          (response[348] & 0xFF)|((response[349]<<8) & (0xFF<<8))|((response[350]<<16) & (0xFF<<16))|((response[351]<<24) & (0xFF<<24)),
                          (response[352] & 0xFF)|((response[353]<<8) & (0xFF<<8))|((response[354]<<16) & (0xFF<<16))|((response[355]<<24) & (0xFF<<24)),
                          (response[356] & 0xFF)|((response[357]<<8) & (0xFF<<8))|((response[358]<<16) & (0xFF<<16))|((response[359]<<24) & (0xFF<<24)),
                          (response[360] & 0xFF)|((response[361]<<8) & (0xFF<<8))|((response[362]<<16) & (0xFF<<16))|((response[363]<<24) & (0xFF<<24)),
                          (response[364] & 0xFF)|((response[365]<<8) & (0xFF<<8))|((response[366]<<16) & (0xFF<<16))|((response[367]<<24) & (0xFF<<24)),
                          (response[368] & 0xFF)|((response[369]<<8) & (0xFF<<8))|((response[370]<<16) & (0xFF<<16))|((response[371]<<24) & (0xFF<<24)),
                          (response[372] & 0xFF)|((response[373]<<8) & (0xFF<<8))|((response[374]<<16) & (0xFF<<16))|((response[375]<<24) & (0xFF<<24)),
                          (response[376] & 0xFF)|((response[377]<<8) & (0xFF<<8))|((response[378]<<16) & (0xFF<<16))|((response[379]<<24) & (0xFF<<24)),
                          (response[380] & 0xFF)|((response[381]<<8) & (0xFF<<8))|((response[382]<<16) & (0xFF<<16))|((response[383]<<24) & (0xFF<<24)),
                          (response[384] & 0xFF)|((response[385]<<8) & (0xFF<<8))|((response[386]<<16) & (0xFF<<16))|((response[387]<<24) & (0xFF<<24)),
                          (response[388] & 0xFF)|((response[389]<<8) & (0xFF<<8))|((response[390]<<16) & (0xFF<<16))|((response[391]<<24) & (0xFF<<24)),
                          ],
        }
        self.check_response(apiResponse, CanopusApi.GetDiagnosticUnitCaptureData)
        self.add_api_exec_cb()
        return apiResponse

    def ReleaseDiagnosticUnit (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x238
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.ReleaseDiagnosticUnit)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineOpticalChannelMonitorsAll (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x141
        header.Tag = 0
        header.MaxResponse = 168
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'q_average' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8)),
             'q_min' : (response[6] & 0xFF)|((response[7]<<8) & (0xFF<<8)),
             'q_max' : (response[8] & 0xFF)|((response[9]<<8) & (0xFF<<8)),
             'cd_average' : (response[10] & 0xFF)|((response[11]<<8) & (0xFF<<8)),
             'cd_min' : (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8)),
             'cd_max' : (response[14] & 0xFF)|((response[15]<<8) & (0xFF<<8)),
             'dgd_average' : (response[16] & 0xFF)|((response[17]<<8) & (0xFF<<8)),
             'dgd_min' : (response[18] & 0xFF)|((response[19]<<8) & (0xFF<<8)),
             'dgd_max' : (response[20] & 0xFF)|((response[21]<<8) & (0xFF<<8)),
             'reserved_0' : (response[22] & 0xFF)|((response[23]<<8) & (0xFF<<8)),
             'reserved_1' : (response[24] & 0xFF)|((response[25]<<8) & (0xFF<<8)),
             'reserved_2' : (response[26] & 0xFF)|((response[27]<<8) & (0xFF<<8)),
             'pdl_average' : (response[28] & 0xFF)|((response[29]<<8) & (0xFF<<8)),
             'pdl_min' : (response[30] & 0xFF)|((response[31]<<8) & (0xFF<<8)),
             'pdl_max' : (response[32] & 0xFF)|((response[33]<<8) & (0xFF<<8)),
             'osnr_average' : (response[34] & 0xFF)|((response[35]<<8) & (0xFF<<8)),
             'osnr_min' : (response[36] & 0xFF)|((response[37]<<8) & (0xFF<<8)),
             'osnr_max' : (response[38] & 0xFF)|((response[39]<<8) & (0xFF<<8)),
             'esnr_average' : (response[40] & 0xFF)|((response[41]<<8) & (0xFF<<8)),
             'esnr_min' : (response[42] & 0xFF)|((response[43]<<8) & (0xFF<<8)),
             'esnr_max' : (response[44] & 0xFF)|((response[45]<<8) & (0xFF<<8)),
             'cfo_average' : (response[46] & 0xFF)|((response[47]<<8) & (0xFF<<8)),
             'cfo_min' : (response[48] & 0xFF)|((response[49]<<8) & (0xFF<<8)),
             'cfo_max' : (response[50] & 0xFF)|((response[51]<<8) & (0xFF<<8)),
             'evm_average' : (response[52] & 0xFF)|((response[53]<<8) & (0xFF<<8)),
             'evm_min' : (response[54] & 0xFF)|((response[55]<<8) & (0xFF<<8)),
             'evm_max' : (response[56] & 0xFF)|((response[57]<<8) & (0xFF<<8)),
             'sop_average' : (response[58] & 0xFF)|((response[59]<<8) & (0xFF<<8)),
             'sop_min' : (response[60] & 0xFF)|((response[61]<<8) & (0xFF<<8)),
             'sop_max' : (response[62] & 0xFF)|((response[63]<<8) & (0xFF<<8)),
             'reserved_3' : (response[64] & 0xFF)|((response[65]<<8) & (0xFF<<8)),
             'reserved_4' : (response[66] & 0xFF)|((response[67]<<8) & (0xFF<<8)),
             'reserved_5' : (response[68] & 0xFF)|((response[69]<<8) & (0xFF<<8)),
             'rx_angle_average_h' : (response[70] & 0xFF)|((response[71]<<8) & (0xFF<<8)),
             'rx_angle_min_h' : (response[72] & 0xFF)|((response[73]<<8) & (0xFF<<8)),
             'rx_angle_max_h' : (response[74] & 0xFF)|((response[75]<<8) & (0xFF<<8)),
             'rx_angle_average_v' : (response[76] & 0xFF)|((response[77]<<8) & (0xFF<<8)),
             'rx_angle_min_v' : (response[78] & 0xFF)|((response[79]<<8) & (0xFF<<8)),
             'rx_angle_max_v' : (response[80] & 0xFF)|((response[81]<<8) & (0xFF<<8)),
             'rx_gain_mism_average_h' : (response[82] & 0xFF)|((response[83]<<8) & (0xFF<<8)),
             'rx_gain_mism_min_h' : (response[84] & 0xFF)|((response[85]<<8) & (0xFF<<8)),
             'rx_gain_mism_max_h' : (response[86] & 0xFF)|((response[87]<<8) & (0xFF<<8)),
             'rx_gain_mism_average_v' : (response[88] & 0xFF)|((response[89]<<8) & (0xFF<<8)),
             'rx_gain_mism_min_v' : (response[90] & 0xFF)|((response[91]<<8) & (0xFF<<8)),
             'rx_gain_mism_max_v' : (response[92] & 0xFF)|((response[93]<<8) & (0xFF<<8)),
             'rx_skew_average_h' : (response[94] & 0xFF)|((response[95]<<8) & (0xFF<<8)),
             'rx_skew_min_h' : (response[96] & 0xFF)|((response[97]<<8) & (0xFF<<8)),
             'rx_skew_max_h' : (response[98] & 0xFF)|((response[99]<<8) & (0xFF<<8)),
             'rx_skew_average_v' : (response[100] & 0xFF)|((response[101]<<8) & (0xFF<<8)),
             'rx_skew_min_v' : (response[102] & 0xFF)|((response[103]<<8) & (0xFF<<8)),
             'rx_skew_max_v' : (response[104] & 0xFF)|((response[105]<<8) & (0xFF<<8)),
             'rx_dc_average_h' : (response[106] & 0xFF)|((response[107]<<8) & (0xFF<<8)),
             'rx_dc_min_h' : (response[108] & 0xFF)|((response[109]<<8) & (0xFF<<8)),
             'rx_dc_max_h' : (response[110] & 0xFF)|((response[111]<<8) & (0xFF<<8)),
             'rx_dc_average_v' : (response[112] & 0xFF)|((response[113]<<8) & (0xFF<<8)),
             'rx_dc_min_v' : (response[114] & 0xFF)|((response[115]<<8) & (0xFF<<8)),
             'rx_dc_max_v' : (response[116] & 0xFF)|((response[117]<<8) & (0xFF<<8)),
             'tx_angle_average_h' : (response[118] & 0xFF)|((response[119]<<8) & (0xFF<<8)),
             'tx_angle_min_h' : (response[120] & 0xFF)|((response[121]<<8) & (0xFF<<8)),
             'tx_angle_max_h' : (response[122] & 0xFF)|((response[123]<<8) & (0xFF<<8)),
             'tx_angle_average_v' : (response[124] & 0xFF)|((response[125]<<8) & (0xFF<<8)),
             'tx_angle_min_v' : (response[126] & 0xFF)|((response[127]<<8) & (0xFF<<8)),
             'tx_angle_max_v' : (response[128] & 0xFF)|((response[129]<<8) & (0xFF<<8)),
             'tx_gain_mism_average_h' : (response[130] & 0xFF)|((response[131]<<8) & (0xFF<<8)),
             'tx_gain_mism_min_h' : (response[132] & 0xFF)|((response[133]<<8) & (0xFF<<8)),
             'tx_gain_mism_max_h' : (response[134] & 0xFF)|((response[135]<<8) & (0xFF<<8)),
             'tx_gain_mism_average_v' : (response[136] & 0xFF)|((response[137]<<8) & (0xFF<<8)),
             'tx_gain_mism_min_v' : (response[138] & 0xFF)|((response[139]<<8) & (0xFF<<8)),
             'tx_gain_mism_max_v' : (response[140] & 0xFF)|((response[141]<<8) & (0xFF<<8)),
             'tx_skew_average_h' : (response[142] & 0xFF)|((response[143]<<8) & (0xFF<<8)),
             'tx_skew_min_h' : (response[144] & 0xFF)|((response[145]<<8) & (0xFF<<8)),
             'tx_skew_max_h' : (response[146] & 0xFF)|((response[147]<<8) & (0xFF<<8)),
             'tx_skew_average_v' : (response[148] & 0xFF)|((response[149]<<8) & (0xFF<<8)),
             'tx_skew_min_v' : (response[150] & 0xFF)|((response[151]<<8) & (0xFF<<8)),
             'tx_skew_max_v' : (response[152] & 0xFF)|((response[153]<<8) & (0xFF<<8)),
             'rx_csr_average_h' : (response[154] & 0xFF)|((response[155]<<8) & (0xFF<<8)),
             'rx_csr_min_h' : (response[156] & 0xFF)|((response[157]<<8) & (0xFF<<8)),
             'rx_csr_max_h' : (response[158] & 0xFF)|((response[159]<<8) & (0xFF<<8)),
             'rx_csr_average_v' : (response[160] & 0xFF)|((response[161]<<8) & (0xFF<<8)),
             'rx_csr_min_v' : (response[162] & 0xFF)|((response[163]<<8) & (0xFF<<8)),
             'rx_csr_max_v' : (response[164] & 0xFF)|((response[165]<<8) & (0xFF<<8)),
             'reserved' : (response[166] & 0xFF)|((response[167]<<8) & (0xFF<<8)),
        }
        self.check_response(apiResponse, CanopusApi.GetLineOpticalChannelMonitorsAll)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineOpticalChannelMonitorsItem (self, item):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x140
        header.Tag = 0
        header.MaxResponse = 12
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = item>>0
        # assert: (x >= 0 && x <= 26)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'average' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8)),
             'min' : (response[6] & 0xFF)|((response[7]<<8) & (0xFF<<8)),
             'max' : (response[8] & 0xFF)|((response[9]<<8) & (0xFF<<8)),
        }
        self.check_response(apiResponse, CanopusApi.GetLineOpticalChannelMonitorsItem)
        self.add_api_exec_cb()
        return apiResponse

    def SetOpticalMonitorsConfig (self, action, lut, arg_array):
        #Default header
        header=ArgHeader()
        header.Length = 76
        header.Command = 0x219
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*76
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = action>>0
        # assert: (x >= 0 && x <= 6)
        command_array[9] = lut>>0
        command_array[10] = arg_array[0]>>0
        command_array[11] = arg_array[0]>>8
        command_array[12] = arg_array[1]>>0
        command_array[13] = arg_array[1]>>8
        command_array[14] = arg_array[2]>>0
        command_array[15] = arg_array[2]>>8
        command_array[16] = arg_array[3]>>0
        command_array[17] = arg_array[3]>>8
        command_array[18] = arg_array[4]>>0
        command_array[19] = arg_array[4]>>8
        command_array[20] = arg_array[5]>>0
        command_array[21] = arg_array[5]>>8
        command_array[22] = arg_array[6]>>0
        command_array[23] = arg_array[6]>>8
        command_array[24] = arg_array[7]>>0
        command_array[25] = arg_array[7]>>8
        command_array[26] = arg_array[8]>>0
        command_array[27] = arg_array[8]>>8
        command_array[28] = arg_array[9]>>0
        command_array[29] = arg_array[9]>>8
        command_array[30] = arg_array[10]>>0
        command_array[31] = arg_array[10]>>8
        command_array[32] = arg_array[11]>>0
        command_array[33] = arg_array[11]>>8
        command_array[34] = arg_array[12]>>0
        command_array[35] = arg_array[12]>>8
        command_array[36] = arg_array[13]>>0
        command_array[37] = arg_array[13]>>8
        command_array[38] = arg_array[14]>>0
        command_array[39] = arg_array[14]>>8
        command_array[40] = arg_array[15]>>0
        command_array[41] = arg_array[15]>>8
        command_array[42] = arg_array[16]>>0
        command_array[43] = arg_array[16]>>8
        command_array[44] = arg_array[17]>>0
        command_array[45] = arg_array[17]>>8
        command_array[46] = arg_array[18]>>0
        command_array[47] = arg_array[18]>>8
        command_array[48] = arg_array[19]>>0
        command_array[49] = arg_array[19]>>8
        command_array[50] = arg_array[20]>>0
        command_array[51] = arg_array[20]>>8
        command_array[52] = arg_array[21]>>0
        command_array[53] = arg_array[21]>>8
        command_array[54] = arg_array[22]>>0
        command_array[55] = arg_array[22]>>8
        command_array[56] = arg_array[23]>>0
        command_array[57] = arg_array[23]>>8
        command_array[58] = arg_array[24]>>0
        command_array[59] = arg_array[24]>>8
        command_array[60] = arg_array[25]>>0
        command_array[61] = arg_array[25]>>8
        command_array[62] = arg_array[26]>>0
        command_array[63] = arg_array[26]>>8
        command_array[64] = arg_array[27]>>0
        command_array[65] = arg_array[27]>>8
        command_array[66] = arg_array[28]>>0
        command_array[67] = arg_array[28]>>8
        command_array[68] = arg_array[29]>>0
        command_array[69] = arg_array[29]>>8
        command_array[70] = arg_array[30]>>0
        command_array[71] = arg_array[30]>>8
        command_array[72] = arg_array[31]>>0
        command_array[73] = arg_array[31]>>8

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'done_ok' : (response[4] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetOpticalMonitorsConfig)
        self.add_api_exec_cb()
        return apiResponse

    def GetLineOpticalChannelMonitorsOccurrenceInfo (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x240
        header.Tag = 0
        header.MaxResponse = 112
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'occurrence_max_q' : (response[4] & 0xFF)|((response[5]<<8) & (0xFF<<8)),
             'occurrence_min_q' : (response[6] & 0xFF)|((response[7]<<8) & (0xFF<<8)),
             'occurrence_max_cd' : (response[8] & 0xFF)|((response[9]<<8) & (0xFF<<8)),
             'occurrence_min_cd' : (response[10] & 0xFF)|((response[11]<<8) & (0xFF<<8)),
             'occurrence_max_dgd' : (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8)),
             'occurrence_min_dgd' : (response[14] & 0xFF)|((response[15]<<8) & (0xFF<<8)),
             'reserved_0' : (response[16] & 0xFF)|((response[17]<<8) & (0xFF<<8)),
             'reserved_1' : (response[18] & 0xFF)|((response[19]<<8) & (0xFF<<8)),
             'occurrence_max_pdl' : (response[20] & 0xFF)|((response[21]<<8) & (0xFF<<8)),
             'occurrence_min_pdl' : (response[22] & 0xFF)|((response[23]<<8) & (0xFF<<8)),
             'occurrence_max_osnr' : (response[24] & 0xFF)|((response[25]<<8) & (0xFF<<8)),
             'occurrence_min_osnr' : (response[26] & 0xFF)|((response[27]<<8) & (0xFF<<8)),
             'occurrence_max_esnr' : (response[28] & 0xFF)|((response[29]<<8) & (0xFF<<8)),
             'occurrence_min_esnr' : (response[30] & 0xFF)|((response[31]<<8) & (0xFF<<8)),
             'occurrence_max_cfo' : (response[32] & 0xFF)|((response[33]<<8) & (0xFF<<8)),
             'occurrence_min_cfo' : (response[34] & 0xFF)|((response[35]<<8) & (0xFF<<8)),
             'occurrence_max_evm' : (response[36] & 0xFF)|((response[37]<<8) & (0xFF<<8)),
             'occurrence_min_evm' : (response[38] & 0xFF)|((response[39]<<8) & (0xFF<<8)),
             'occurrence_max_sop' : (response[40] & 0xFF)|((response[41]<<8) & (0xFF<<8)),
             'occurrence_min_sop' : (response[42] & 0xFF)|((response[43]<<8) & (0xFF<<8)),
             'reserved_2' : (response[44] & 0xFF)|((response[45]<<8) & (0xFF<<8)),
             'reserved_3' : (response[46] & 0xFF)|((response[47]<<8) & (0xFF<<8)),
             'occurrence_max_rx_angle_h' : (response[48] & 0xFF)|((response[49]<<8) & (0xFF<<8)),
             'occurrence_min_rx_angle_h' : (response[50] & 0xFF)|((response[51]<<8) & (0xFF<<8)),
             'occurrence_max_rx_angle_v' : (response[52] & 0xFF)|((response[53]<<8) & (0xFF<<8)),
             'occurrence_min_rx_angle_v' : (response[54] & 0xFF)|((response[55]<<8) & (0xFF<<8)),
             'occurrence_max_rx_gain_mism_h' : (response[56] & 0xFF)|((response[57]<<8) & (0xFF<<8)),
             'occurrence_min_rx_gain_mism_h' : (response[58] & 0xFF)|((response[59]<<8) & (0xFF<<8)),
             'occurrence_max_rx_gain_mism_v' : (response[60] & 0xFF)|((response[61]<<8) & (0xFF<<8)),
             'occurrence_min_rx_gain_mism_v' : (response[62] & 0xFF)|((response[63]<<8) & (0xFF<<8)),
             'occurrence_max_rx_skew_h' : (response[64] & 0xFF)|((response[65]<<8) & (0xFF<<8)),
             'occurrence_min_rx_skew_h' : (response[66] & 0xFF)|((response[67]<<8) & (0xFF<<8)),
             'occurrence_max_rx_skew_v' : (response[68] & 0xFF)|((response[69]<<8) & (0xFF<<8)),
             'occurrence_min_rx_skew_v' : (response[70] & 0xFF)|((response[71]<<8) & (0xFF<<8)),
             'occurrence_max_rx_dc_h' : (response[72] & 0xFF)|((response[73]<<8) & (0xFF<<8)),
             'occurrence_min_rx_dc_h' : (response[74] & 0xFF)|((response[75]<<8) & (0xFF<<8)),
             'occurrence_max_rx_dc_v' : (response[76] & 0xFF)|((response[77]<<8) & (0xFF<<8)),
             'occurrence_min_rx_dc_v' : (response[78] & 0xFF)|((response[79]<<8) & (0xFF<<8)),
             'occurrence_max_tx_angle_h' : (response[80] & 0xFF)|((response[81]<<8) & (0xFF<<8)),
             'occurrence_min_tx_angle_h' : (response[82] & 0xFF)|((response[83]<<8) & (0xFF<<8)),
             'occurrence_max_tx_angle_v' : (response[84] & 0xFF)|((response[85]<<8) & (0xFF<<8)),
             'occurrence_min_tx_angle_v' : (response[86] & 0xFF)|((response[87]<<8) & (0xFF<<8)),
             'occurrence_max_tx_gain_mism_h' : (response[88] & 0xFF)|((response[89]<<8) & (0xFF<<8)),
             'occurrence_min_tx_gain_mism_h' : (response[90] & 0xFF)|((response[91]<<8) & (0xFF<<8)),
             'occurrence_max_tx_gain_mism_v' : (response[92] & 0xFF)|((response[93]<<8) & (0xFF<<8)),
             'occurrence_min_tx_gain_mism_v' : (response[94] & 0xFF)|((response[95]<<8) & (0xFF<<8)),
             'occurrence_max_tx_skew_h' : (response[96] & 0xFF)|((response[97]<<8) & (0xFF<<8)),
             'occurrence_min_tx_skew_h' : (response[98] & 0xFF)|((response[99]<<8) & (0xFF<<8)),
             'occurrence_max_tx_skew_v' : (response[100] & 0xFF)|((response[101]<<8) & (0xFF<<8)),
             'occurrence_min_tx_skew_v' : (response[102] & 0xFF)|((response[103]<<8) & (0xFF<<8)),
             'occurrence_max_rx_csr_h' : (response[104] & 0xFF)|((response[105]<<8) & (0xFF<<8)),
             'occurrence_min_rx_csr_h' : (response[106] & 0xFF)|((response[107]<<8) & (0xFF<<8)),
             'occurrence_max_rx_csr_v' : (response[108] & 0xFF)|((response[109]<<8) & (0xFF<<8)),
             'occurrence_min_rx_csr_v' : (response[110] & 0xFF)|((response[111]<<8) & (0xFF<<8)),
        }
        self.check_response(apiResponse, CanopusApi.GetLineOpticalChannelMonitorsOccurrenceInfo)
        self.add_api_exec_cb()
        return apiResponse

    def ControlAvs (self, Ctrl, Vstep, CurrentV, AVSAnalysisMode, AVSRate, Prv, Reserved):
        #Default header
        header=ArgHeader()
        header.Length = 16
        header.Command = 0x211
        header.Tag = 0
        header.MaxResponse = 24
        header.Reserved = 0

        #Command stream
        command_array=[0]*16
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = Ctrl>>0
        command_array[9] = Vstep>>0
        command_array[10] = CurrentV>>0
        command_array[11] = CurrentV>>8
        command_array[12] = AVSAnalysisMode>>0
        command_array[13] = AVSRate>>0
        command_array[14] = Prv>>0
        command_array[15] = Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'AVSStatus' : (response[4] & 0xFF),
             'Flag' : (response[5] & 0xFF),
             'ROGoalVT1' : (response[6] & 0xFF)|((response[7]<<8) & (0xFF<<8)),
             'ROGoalVT2' : (response[8] & 0xFF)|((response[9]<<8) & (0xFF<<8)),
             'ROGoalVT3' : (response[10] & 0xFF)|((response[11]<<8) & (0xFF<<8)),
             'RODropGoalVT1' : (response[12] & 0xFF)|((response[13]<<8) & (0xFF<<8)),
             'RODropGoalVT2' : (response[14] & 0xFF)|((response[15]<<8) & (0xFF<<8)),
             'RODropGoalVT3' : (response[16] & 0xFF)|((response[17]<<8) & (0xFF<<8)),
             'ROMinCountVT1' : (response[18] & 0xFF)|((response[19]<<8) & (0xFF<<8)),
             'ROMinCountVT2' : (response[20] & 0xFF)|((response[21]<<8) & (0xFF<<8)),
             'ROMinCountVT3' : (response[22] & 0xFF)|((response[23]<<8) & (0xFF<<8)),
        }
        self.check_response(apiResponse, CanopusApi.ControlAvs)
        self.add_api_exec_cb()
        return apiResponse

    def SetMonitorClocks (self, enable_ltx_monclk, reserved):
        #Default header
        header=ArgHeader()
        header.Length = 12
        header.Command = 0x217
        header.Tag = 0
        header.MaxResponse = 4
        header.Reserved = 0

        #Command stream
        command_array=[0]*12
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0
        command_array[8] = enable_ltx_monclk>>0
        # assert: (x >= 0 && x <= 1)
        command_array[9] = reserved>>0
        # assert: (x >= 0 && x <= 1)

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.SetMonitorClocks)
        self.add_api_exec_cb()
        return apiResponse

    def GetMonitorClocks (self, ):
        #Default header
        header=ArgHeader()
        header.Length = 8
        header.Command = 0x218
        header.Tag = 0
        header.MaxResponse = 8
        header.Reserved = 0

        #Command stream
        command_array=[0]*8
        command_array[0] = header.Length>>0
        command_array[1] = header.Length>>8
        command_array[2] = header.Command>>0
        command_array[3] = header.Command>>8
        command_array[4] = header.MaxResponse>>0
        command_array[5] = header.MaxResponse>>8
        command_array[6] = header.Tag>>0
        command_array[7] = header.Reserved>>0

        #Do the call
        response = self.com.send_command( command_array )

        #Response stream
        apiResponse = {
             'Length' : (response[0] & 0xFF)|((response[1]<<8) & (0xFF<<8)),
             'Status' : (response[2] & 0xFF),
             'Info' : (response[3] & 0xFF),
             'enable_ltx_monclk' : (response[4] & 0xFF),
             'reserved' : (response[5] & 0xFF),
        }
        self.check_response(apiResponse, CanopusApi.GetMonitorClocks)
        self.add_api_exec_cb()
        return apiResponse
