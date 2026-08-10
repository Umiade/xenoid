#define _GNU_SOURCE
#define RIL_SHLIB 1
#include <telephony/ril.h>

#include <android/log.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits.h>
#include <net/if.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define PROFILE_PATH "/data/vendor/radio/xenoid/profile.v1"
#define PROFILE_MAGIC "XENOID_PROFILE_V1"
#define PROFILE_VERSION 1u
#define PROFILE_FIELDS 21u
#define PROFILE_MAX_BYTES (64u * 1024u)
#define IFACE "rmnet_data0"
#define ARRAY_SIZE(value) (sizeof(value) / sizeof((value)[0]))

_Static_assert(sizeof(void *) == 8, "Xenoid RIL supports the Android 13 64-bit runtime only");
_Static_assert(sizeof(RIL_RadioFunctions) == 48, "unexpected RIL_RadioFunctions ABI");
_Static_assert(sizeof(RIL_Data_Call_Response_v11) == 72, "unexpected data-call ABI");
_Static_assert(sizeof(RIL_SignalStrength_v10) == 56, "unexpected signal ABI");
_Static_assert(sizeof(RIL_CellInfo_v12) == 72, "unexpected cell-info ABI");
_Static_assert(sizeof(RIL_CardStatus_v6) == 408, "unexpected card-status ABI");

struct sha256_context {
    uint32_t state[8];
    uint64_t bits;
    uint8_t block[64];
    size_t used;
};

static const uint32_t sha256_constants[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u,
};

static uint32_t rotate_right(uint32_t value, unsigned count) {
    return (value >> count) | (value << (32u - count));
}

static uint32_t read_be32(const uint8_t *value) {
    return ((uint32_t)value[0] << 24) | ((uint32_t)value[1] << 16)
        | ((uint32_t)value[2] << 8) | (uint32_t)value[3];
}

static void write_be32(uint8_t *output, uint32_t value) {
    output[0] = (uint8_t)(value >> 24); output[1] = (uint8_t)(value >> 16);
    output[2] = (uint8_t)(value >> 8); output[3] = (uint8_t)value;
}

static void sha256_transform(struct sha256_context *context, const uint8_t block[64]) {
    uint32_t words[64];
    for (size_t index = 0; index < 16; ++index) words[index] = read_be32(block + index * 4);
    for (size_t index = 16; index < 64; ++index) {
        uint32_t first = rotate_right(words[index - 15], 7) ^ rotate_right(words[index - 15], 18)
            ^ (words[index - 15] >> 3);
        uint32_t second = rotate_right(words[index - 2], 17) ^ rotate_right(words[index - 2], 19)
            ^ (words[index - 2] >> 10);
        words[index] = words[index - 16] + first + words[index - 7] + second;
    }
    uint32_t a=context->state[0], b=context->state[1], c=context->state[2], d=context->state[3];
    uint32_t e=context->state[4], f=context->state[5], g=context->state[6], h=context->state[7];
    for (size_t index = 0; index < 64; ++index) {
        uint32_t s1=rotate_right(e,6)^rotate_right(e,11)^rotate_right(e,25);
        uint32_t choice=(e&f)^((~e)&g);
        uint32_t temporary1=h+s1+choice+sha256_constants[index]+words[index];
        uint32_t s0=rotate_right(a,2)^rotate_right(a,13)^rotate_right(a,22);
        uint32_t majority=(a&b)^(a&c)^(b&c);
        uint32_t temporary2=s0+majority;
        h=g; g=f; f=e; e=d+temporary1; d=c; c=b; b=a; a=temporary1+temporary2;
    }
    context->state[0]+=a; context->state[1]+=b; context->state[2]+=c; context->state[3]+=d;
    context->state[4]+=e; context->state[5]+=f; context->state[6]+=g; context->state[7]+=h;
}

static void sha256_init(struct sha256_context *context) {
    memset(context, 0, sizeof(*context));
    context->state[0]=0x6a09e667u; context->state[1]=0xbb67ae85u;
    context->state[2]=0x3c6ef372u; context->state[3]=0xa54ff53au;
    context->state[4]=0x510e527fu; context->state[5]=0x9b05688cu;
    context->state[6]=0x1f83d9abu; context->state[7]=0x5be0cd19u;
}

static void sha256_update(struct sha256_context *context, const uint8_t *value, size_t length) {
    context->bits += (uint64_t)length * 8u;
    while (length) {
        size_t available = sizeof(context->block) - context->used;
        size_t count = length < available ? length : available;
        memcpy(context->block + context->used, value, count);
        context->used += count; value += count; length -= count;
        if (context->used == sizeof(context->block)) {
            sha256_transform(context, context->block); context->used = 0;
        }
    }
}

static void sha256_final(struct sha256_context *context, uint8_t output[32]) {
    context->block[context->used++] = 0x80;
    if (context->used > 56) {
        memset(context->block + context->used, 0, 64 - context->used);
        sha256_transform(context, context->block); context->used = 0;
    }
    memset(context->block + context->used, 0, 56 - context->used);
    for (size_t index = 0; index < 8; ++index) {
        context->block[63 - index] = (uint8_t)(context->bits >> (index * 8));
    }
    sha256_transform(context, context->block);
    for (size_t index = 0; index < 8; ++index) write_be32(output + index * 4, context->state[index]);
    memset(context, 0, sizeof(*context));
}

struct radio_profile {
    char mcc[4], mnc[4], imsi[16], iccid[21], msisdn[17];
    char carrier[129], apn[129], locales[129], timezone[129], digest[65];
    uint32_t tac, eci, pci, earfcn, band, cqi, timing_advance, bandwidth_khz;
    int32_t rsrp, rsrq, rssnr;
};

static struct radio_profile profile;
static int profile_is_bootstrap;
static _Atomic int data_call_active = 1;
static _Atomic int preferred_network_type = 9;
static _Atomic int cell_info_rate;
static const struct RIL_Env *ril_environment;

static uint16_t field_id(const uint8_t *value) {
    return (uint16_t)(((uint16_t)value[0] << 8) | value[1]);
}

static int copy_string_field(char *output, size_t capacity, const uint8_t *value, size_t length) {
    if (!length || length >= capacity || memchr(value, 0, length)) return -1;
    memcpy(output, value, length); output[length] = 0; return 0;
}

static int parse_numeric_field(uint32_t *output, const uint8_t *value, size_t length) {
    if (length != 4) return -1;
    *output = read_be32(value); return 0;
}

static int parse_signed_field(int32_t *output, const uint8_t *value, size_t length) {
    uint32_t encoded;
    if (parse_numeric_field(&encoded, value, length) != 0) return -1;
    *output = (int32_t)encoded; return 0;
}

static int validate_profile_values(const struct radio_profile *value) {
    size_t mcc_length=strlen(value->mcc), mnc_length=strlen(value->mnc);
    if (mcc_length!=3 || (mnc_length!=2 && mnc_length!=3) || strlen(value->imsi)!=15
            || strlen(value->iccid)!=20 || value->msisdn[0]!='+' || strlen(value->digest)!=64
            || value->tac<1 || value->tac>65535 || value->eci<1 || value->eci>268435455
            || value->pci>503 || value->earfcn>262143 || value->band<1 || value->band>256
            || value->rsrp>-44 || value->rsrp<-140 || value->rsrq>-3 || value->rsrq<-20
            || value->rssnr<-200 || value->rssnr>300 || value->cqi>15
            || value->bandwidth_khz!=10000) return -1;
    for (const char *cursor=value->mcc; *cursor; ++cursor) if (*cursor<'0'||*cursor>'9') return -1;
    for (const char *cursor=value->mnc; *cursor; ++cursor) if (*cursor<'0'||*cursor>'9') return -1;
    for (const char *cursor=value->imsi; *cursor; ++cursor) if (*cursor<'0'||*cursor>'9') return -1;
    for (const char *cursor=value->iccid; *cursor; ++cursor) if (*cursor<'0'||*cursor>'9') return -1;
    return strncmp(value->imsi, value->mcc, 3)==0
        && strncmp(value->imsi+3, value->mnc, mnc_length)==0 ? 0 : -1;
}

static int parse_profile(const uint8_t *file, size_t length, struct radio_profile *output) {
    const size_t header_size = sizeof(PROFILE_MAGIC) + 8;
    if (length < header_size + 32 || length > PROFILE_MAX_BYTES
            || memcmp(file, PROFILE_MAGIC, sizeof(PROFILE_MAGIC)) != 0
            || read_be32(file + sizeof(PROFILE_MAGIC)) != PROFILE_VERSION
            || read_be32(file + sizeof(PROFILE_MAGIC) + 4) != PROFILE_FIELDS) return -1;
    const uint8_t *cursor=file+header_size, *digest=file+length-32;
    struct sha256_context hash; uint8_t actual[32];
    sha256_init(&hash); sha256_update(&hash, cursor, (size_t)(digest-cursor)); sha256_final(&hash, actual);
    if (memcmp(actual,digest,sizeof(actual))!=0) return -1;
    memset(output,0,sizeof(*output));
    uint16_t previous=0; unsigned seen=0;
    while (cursor < digest) {
        if ((size_t)(digest-cursor)<6) return -1;
        uint16_t id=field_id(cursor); uint32_t field_length=read_be32(cursor+2); cursor+=6;
        if (id<=previous || id<1 || id>PROFILE_FIELDS || field_length==0
                || field_length>8192 || (size_t)(digest-cursor)<field_length) return -1;
        const uint8_t *value=cursor; int result=0;
        switch(id) {
            case 1: result=copy_string_field(output->mcc,sizeof(output->mcc),value,field_length); break;
            case 2: result=copy_string_field(output->mnc,sizeof(output->mnc),value,field_length); break;
            case 3: result=copy_string_field(output->imsi,sizeof(output->imsi),value,field_length); break;
            case 4: result=copy_string_field(output->iccid,sizeof(output->iccid),value,field_length); break;
            case 5: result=copy_string_field(output->msisdn,sizeof(output->msisdn),value,field_length); break;
            case 6: result=copy_string_field(output->carrier,sizeof(output->carrier),value,field_length); break;
            case 7: result=copy_string_field(output->apn,sizeof(output->apn),value,field_length); break;
            case 8: result=parse_numeric_field(&output->tac,value,field_length); break;
            case 9: result=parse_numeric_field(&output->eci,value,field_length); break;
            case 10: result=parse_numeric_field(&output->pci,value,field_length); break;
            case 11: result=parse_numeric_field(&output->earfcn,value,field_length); break;
            case 12: result=parse_numeric_field(&output->band,value,field_length); break;
            case 13: result=parse_signed_field(&output->rsrp,value,field_length); break;
            case 14: result=parse_signed_field(&output->rsrq,value,field_length); break;
            case 15: result=parse_signed_field(&output->rssnr,value,field_length); break;
            case 16: result=parse_numeric_field(&output->cqi,value,field_length); break;
            case 17: result=parse_numeric_field(&output->timing_advance,value,field_length); break;
            case 18: result=copy_string_field(output->locales,sizeof(output->locales),value,field_length); break;
            case 19: result=copy_string_field(output->timezone,sizeof(output->timezone),value,field_length); break;
            case 20: result=copy_string_field(output->digest,sizeof(output->digest),value,field_length); break;
            case 21: result=parse_numeric_field(&output->bandwidth_khz,value,field_length); break;
            default: return -1;
        }
        if (result!=0) return -1;
        cursor+=field_length; previous=id; seen++;
    }
    return cursor==digest && seen==PROFILE_FIELDS && validate_profile_values(output)==0 ? 0 : -1;
}

static void bootstrap_profile(struct radio_profile *output) {
    memset(output,0,sizeof(*output));
    snprintf(output->mcc,sizeof(output->mcc),"001"); snprintf(output->mnc,sizeof(output->mnc),"01");
    snprintf(output->imsi,sizeof(output->imsi),"001010123456789");
    snprintf(output->iccid,sizeof(output->iccid),"89001010123456789014");
    snprintf(output->msisdn,sizeof(output->msisdn),"+10000000000");
    snprintf(output->carrier,sizeof(output->carrier),"Android Test");
    snprintf(output->apn,sizeof(output->apn),"internet");
    snprintf(output->locales,sizeof(output->locales),"en-US");
    snprintf(output->timezone,sizeof(output->timezone),"America/New_York");
    memset(output->digest,'0',64); output->digest[64]=0;
    output->tac=1; output->eci=1; output->pci=1; output->earfcn=1300; output->band=3;
    output->rsrp=-90; output->rsrq=-12; output->rssnr=100; output->cqi=12; output->timing_advance=1;
    output->bandwidth_khz=10000;
}

static int load_profile_file(struct radio_profile *output) {
    int descriptor=open(PROFILE_PATH,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (descriptor<0) return -1;
    struct stat info;
    if (fstat(descriptor,&info)!=0 || !S_ISREG(info.st_mode) || info.st_size<=0
            || info.st_size>PROFILE_MAX_BYTES || (info.st_mode&0777)!=0640
            || info.st_uid!=1001 || info.st_gid!=1001) { close(descriptor); return -1; }
    size_t length=(size_t)info.st_size; uint8_t *data=(uint8_t *)malloc(length);
    if (!data) { close(descriptor); return -1; }
    size_t used=0; int result=-1;
    while (used<length) {
        ssize_t count=read(descriptor,data+used,length-used);
        if (count<=0) goto done;
        used+=(size_t)count;
    }
    if (read(descriptor,data,1)!=0) goto done;
    result=parse_profile(data,length,output);
done:
    memset(data,0,length); free(data); close(descriptor); return result;
}

static void complete(RIL_Token token, RIL_Errno error, void *response, size_t length) {
    ril_environment->OnRequestComplete(token,error,response,length);
}

static int mnc_encoded(void) {
    return ((int)strlen(profile.mnc)<<28)|atoi(profile.mnc);
}

static void fill_cell_identity(RIL_CellIdentity_v16 *identity) {
    memset(identity,0,sizeof(*identity)); identity->cellInfoType=RIL_CELL_INFO_TYPE_LTE;
    identity->cellIdentityLte.mcc=atoi(profile.mcc); identity->cellIdentityLte.mnc=mnc_encoded();
    identity->cellIdentityLte.ci=(int)profile.eci; identity->cellIdentityLte.pci=(int)profile.pci;
    identity->cellIdentityLte.tac=(int)profile.tac; identity->cellIdentityLte.earfcn=(int)profile.earfcn;
}

static void response_sim_status(RIL_Token token) {
    static RIL_CardStatus_v6 status; memset(&status,0,sizeof(status));
    status.card_state=RIL_CARDSTATE_PRESENT; status.universal_pin_state=RIL_PINSTATE_DISABLED;
    status.gsm_umts_subscription_app_index=0; status.cdma_subscription_app_index=-1;
    status.ims_subscription_app_index=-1; status.num_applications=1;
    status.applications[0].app_type=RIL_APPTYPE_USIM; status.applications[0].app_state=RIL_APPSTATE_READY;
    status.applications[0].perso_substate=RIL_PERSOSUBSTATE_READY;
    status.applications[0].aid_ptr="A0000000871002"; status.applications[0].app_label_ptr="USIM";
    status.applications[0].pin1_replaced=0; status.applications[0].pin1=RIL_PINSTATE_DISABLED;
    status.applications[0].pin2=RIL_PINSTATE_DISABLED;
    complete(token,RIL_E_SUCCESS,&status,sizeof(status));
}

static void bytes_to_hex(const uint8_t *input,size_t length,char *output,size_t capacity) {
    static const char digits[]="0123456789ABCDEF";
    if (capacity<length*2+1) { if(capacity) output[0]=0; return; }
    for(size_t index=0;index<length;++index){output[index*2]=digits[input[index]>>4];output[index*2+1]=digits[input[index]&15];}
    output[length*2]=0;
}

static uint8_t bcd_pair(char low,char high) {
    uint8_t left=(uint8_t)(low-'0'); uint8_t right=high ? (uint8_t)(high-'0') : 0x0f;
    return (uint8_t)(left|(right<<4));
}

static size_t sim_file_data(int file_id,uint8_t *raw,size_t capacity) {
    if(capacity<64)return 0;
    size_t length=0;memset(raw,0xff,capacity);
    if(file_id==0x2fe2){
        length=strlen(profile.iccid)/2;
        for(size_t index=0;index<length;++index)raw[index]=bcd_pair(profile.iccid[index*2],profile.iccid[index*2+1]);
    }else if(file_id==0x6f07){
        raw[0]=8;raw[1]=(uint8_t)(((profile.imsi[0]-'0')<<4)|1);length=9;
        for(size_t index=1;index<8;++index){size_t digit=1+(index-1)*2;raw[index+1]=bcd_pair(profile.imsi[digit],profile.imsi[digit+1]);}
    }else if(file_id==0x6fad){raw[0]=0;raw[1]=0;raw[2]=0;raw[3]=(uint8_t)strlen(profile.mnc);length=4;
    }else if(file_id==0x6f46){raw[0]=0;length=17;size_t name=strlen(profile.carrier);if(name>16)name=16;memcpy(raw+1,profile.carrier,name);
    }else if(file_id==0x6f40){
        length=32;const char *digits=profile.msisdn+1;size_t count=strlen(digits);size_t bytes=(count+1)/2;
        raw[18]=(uint8_t)(bytes+1);raw[19]=0x91;for(size_t index=0;index<bytes&&20+index<30;++index)raw[20+index]=bcd_pair(digits[index*2],index*2+1<count?digits[index*2+1]:0);
    }
    return length;
}

static int sim_file_is_linear_fixed(int file_id){return file_id==0x6f40;}

static size_t sim_file_metadata(int file_id,uint8_t *raw,size_t capacity) {
    uint8_t contents[64];size_t length=sim_file_data(file_id,contents,sizeof(contents));
    if(!length||capacity<15)return 0;
    memset(raw,0,15);raw[2]=(uint8_t)(length>>8);raw[3]=(uint8_t)length;raw[6]=4;
    raw[13]=sim_file_is_linear_fixed(file_id)?1:0;raw[14]=sim_file_is_linear_fixed(file_id)?(uint8_t)length:0;
    return 15;
}

static void response_sim_io(RIL_Token token,const void *data,size_t length) {
    if(!data||length<sizeof(RIL_SIM_IO_v6)){complete(token,RIL_E_INVALID_ARGUMENTS,NULL,0);return;}
    const RIL_SIM_IO_v6 *request=(const RIL_SIM_IO_v6 *)data;uint8_t raw[64];size_t raw_length=0;
    if(request->command==0xc0){
        raw_length=sim_file_metadata(request->fileid,raw,sizeof(raw));
    }else if(request->command==0xb0&&!sim_file_is_linear_fixed(request->fileid)){
        raw_length=sim_file_data(request->fileid,raw,sizeof(raw));
        size_t offset=((size_t)(request->p1&0xff)<<8)|(size_t)(request->p2&0xff);
        if(offset>raw_length){raw_length=0;}else{raw_length-=offset;memmove(raw,raw+offset,raw_length);}
        if(request->p3>0&&(size_t)request->p3<raw_length)raw_length=(size_t)request->p3;
    }else if(request->command==0xb2&&sim_file_is_linear_fixed(request->fileid)&&request->p1==1&&request->p2==4){
        raw_length=sim_file_data(request->fileid,raw,sizeof(raw));
        if(request->p3>0&&(size_t)request->p3<raw_length)raw_length=(size_t)request->p3;
    }
    if(!raw_length){complete(token,RIL_E_REQUEST_NOT_SUPPORTED,NULL,0);return;}
    static char encoded[256];bytes_to_hex(raw,raw_length,encoded,sizeof(encoded));
    static RIL_SIM_IO_Response response;response.sw1=0x90;response.sw2=0;response.simResponse=encoded;
    complete(token,RIL_E_SUCCESS,&response,sizeof(response));
}

static void response_registration(RIL_Token token,int data_registration) {
    if(data_registration){
        static RIL_DataRegistrationStateResponse response; memset(&response,0,sizeof(response));
        response.regState=RIL_REG_HOME;response.rat=RADIO_TECH_LTE;response.reasonDataDenied=0;response.maxDataCalls=1;
        fill_cell_identity(&response.cellIdentity);complete(token,RIL_E_SUCCESS,&response,sizeof(response));
    }else{
        static RIL_VoiceRegistrationStateResponse response; memset(&response,0,sizeof(response));
        response.regState=RIL_REG_HOME;response.rat=RADIO_TECH_LTE;response.roamingIndicator=-1;
        response.systemIsInPrl=-1;response.defaultRoamingIndicator=-1;fill_cell_identity(&response.cellIdentity);
        complete(token,RIL_E_SUCCESS,&response,sizeof(response));
    }
}

static void fill_signal(RIL_SignalStrength_v10 *signal) {
    memset(signal,0,sizeof(*signal));
    signal->GW_SignalStrength.signalStrength=99;signal->GW_SignalStrength.bitErrorRate=99;
    signal->CDMA_SignalStrength.dbm=-1;signal->CDMA_SignalStrength.ecio=-1;
    signal->EVDO_SignalStrength.dbm=-1;signal->EVDO_SignalStrength.ecio=-1;signal->EVDO_SignalStrength.signalNoiseRatio=-1;
    signal->LTE_SignalStrength.signalStrength=99;signal->LTE_SignalStrength.rsrp=-profile.rsrp;
    signal->LTE_SignalStrength.rsrq=-profile.rsrq;signal->LTE_SignalStrength.rssnr=profile.rssnr;
    signal->LTE_SignalStrength.cqi=(int)profile.cqi;signal->LTE_SignalStrength.timingAdvance=(int)profile.timing_advance;
    signal->TD_SCDMA_SignalStrength.rscp=INT_MAX;
}

static void response_signal(RIL_Token token) {
    static RIL_SignalStrength_v10 signal;fill_signal(&signal);complete(token,RIL_E_SUCCESS,&signal,sizeof(signal));
}

static void fill_cell_info(RIL_CellInfo_v12 *info) {
    memset(info,0,sizeof(*info));info->cellInfoType=RIL_CELL_INFO_TYPE_LTE;
    info->registered=1;info->timeStampType=RIL_TIMESTAMP_TYPE_MODEM;
    struct timespec now;if(clock_gettime(CLOCK_BOOTTIME,&now)==0)info->timeStamp=(uint64_t)now.tv_sec*1000000000u+(uint64_t)now.tv_nsec;
    info->CellInfo.lte.cellIdentityLte.mcc=atoi(profile.mcc);info->CellInfo.lte.cellIdentityLte.mnc=mnc_encoded();
    info->CellInfo.lte.cellIdentityLte.ci=(int)profile.eci;info->CellInfo.lte.cellIdentityLte.pci=(int)profile.pci;
    info->CellInfo.lte.cellIdentityLte.tac=(int)profile.tac;info->CellInfo.lte.cellIdentityLte.earfcn=(int)profile.earfcn;
    info->CellInfo.lte.signalStrengthLte.signalStrength=99;info->CellInfo.lte.signalStrengthLte.rsrp=-profile.rsrp;
    info->CellInfo.lte.signalStrengthLte.rsrq=-profile.rsrq;info->CellInfo.lte.signalStrengthLte.rssnr=profile.rssnr;
    info->CellInfo.lte.signalStrengthLte.cqi=(int)profile.cqi;info->CellInfo.lte.signalStrengthLte.timingAdvance=(int)profile.timing_advance;
}

static void response_cell_info(RIL_Token token) {
    static RIL_CellInfo_v12 info;fill_cell_info(&info);complete(token,RIL_E_SUCCESS,&info,sizeof(info));
}

struct live_link {
    char addresses[512],dnses[256],gateways[256],protocol[16];int mtu;
};

static int append_word(char *output,size_t capacity,const char *value) {
    size_t used=strlen(output),length=strlen(value);if(!length||used+length+2>capacity)return -1;
    if(used)output[used++]=' ';memcpy(output+used,value,length+1);return 0;
}

static int prefix_length(const struct sockaddr *mask) {
    if(!mask)return 0;const uint8_t *value;size_t length;
    if(mask->sa_family==AF_INET){value=(const uint8_t *)&((const struct sockaddr_in *)mask)->sin_addr;length=4;}
    else{value=(const uint8_t *)&((const struct sockaddr_in6 *)mask)->sin6_addr;length=16;}
    int bits=0;for(size_t index=0;index<length;++index){uint8_t byte=value[index];while(byte&0x80){bits++;byte<<=1;}}
    return bits;
}

static void read_dns(char *output,size_t capacity) {
    output[0]=0;char property[PROP_VALUE_MAX];
    for(const char *name=(const char *)"net.dns1";name;name=!strcmp(name,"net.dns1")?"net.dns2":NULL){
        if(__system_property_get(name,property)>0)append_word(output,capacity,property);
    }
    if(output[0])return;FILE *stream=fopen("/etc/resolv.conf","re");
    if(stream){char line[256],address[128];while(fgets(line,sizeof(line),stream))if(sscanf(line,"nameserver %127s",address)==1)append_word(output,capacity,address);fclose(stream);}
    if(!output[0]){append_word(output,capacity,"1.1.1.1");append_word(output,capacity,"8.8.8.8");}
}

static void append_derived_gateway(char *output,size_t capacity,const struct sockaddr *address,const struct sockaddr *mask) {
    char text[INET6_ADDRSTRLEN];
    if(address->sa_family==AF_INET&&mask&&mask->sa_family==AF_INET){
        struct in_addr gateway=((const struct sockaddr_in *)address)->sin_addr;
        uint32_t network=ntohl(gateway.s_addr)&ntohl(((const struct sockaddr_in *)mask)->sin_addr.s_addr);
        gateway.s_addr=htonl(network+1);if(inet_ntop(AF_INET,&gateway,text,sizeof(text)))append_word(output,capacity,text);
    }else if(address->sa_family==AF_INET6&&mask&&mask->sa_family==AF_INET6){
        const struct in6_addr *source=&((const struct sockaddr_in6 *)address)->sin6_addr;
        if(IN6_IS_ADDR_LINKLOCAL(source))return;struct in6_addr gateway=*source;
        const struct in6_addr *netmask=&((const struct sockaddr_in6 *)mask)->sin6_addr;
        for(size_t index=0;index<sizeof(gateway.s6_addr);++index)gateway.s6_addr[index]&=netmask->s6_addr[index];
        gateway.s6_addr[15]|=1;if(inet_ntop(AF_INET6,&gateway,text,sizeof(text)))append_word(output,capacity,text);
    }
}

static int live_link(struct live_link *link) {
    memset(link,0,sizeof(*link));int descriptor=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);if(descriptor<0)return -1;
    struct ifreq request;memset(&request,0,sizeof(request));snprintf(request.ifr_name,sizeof(request.ifr_name),"%s",IFACE);
    if(ioctl(descriptor,SIOCGIFFLAGS,&request)!=0||!(request.ifr_flags&IFF_UP)){close(descriptor);return -1;}
    memset(&request,0,sizeof(request));snprintf(request.ifr_name,sizeof(request.ifr_name),"%s",IFACE);
    if(ioctl(descriptor,SIOCGIFMTU,&request)!=0){close(descriptor);return -1;}link->mtu=request.ifr_mtu;close(descriptor);
    struct ifaddrs *addresses=NULL;if(getifaddrs(&addresses)!=0)return -1;int have4=0,have6=0;
    for(struct ifaddrs *item=addresses;item;item=item->ifa_next){if(!item->ifa_addr||strcmp(item->ifa_name,IFACE))continue;
        int family=item->ifa_addr->sa_family;if(family!=AF_INET&&family!=AF_INET6)continue;char text[INET6_ADDRSTRLEN+8],address[INET6_ADDRSTRLEN];
        const void *source=family==AF_INET?(const void *)&((struct sockaddr_in *)item->ifa_addr)->sin_addr:(const void *)&((struct sockaddr_in6 *)item->ifa_addr)->sin6_addr;
        if(!inet_ntop(family,source,address,sizeof(address)))continue;snprintf(text,sizeof(text),"%s/%d",address,prefix_length(item->ifa_netmask));
        if(append_word(link->addresses,sizeof(link->addresses),text)==0){if(family==AF_INET)have4=1;else have6=1;append_derived_gateway(link->gateways,sizeof(link->gateways),item->ifa_addr,item->ifa_netmask);}}
    freeifaddrs(addresses);if(!have4&&!have6)return -1;
    snprintf(link->protocol,sizeof(link->protocol),"%s",have4&&have6?"IPV4V6":have4?"IP":"IPV6");read_dns(link->dnses,sizeof(link->dnses));return 0;
}

static void fill_data_call_response(RIL_Data_Call_Response_v11 *response,struct live_link *link,int connected) {
    memset(response,0,sizeof(*response));response->status=connected?PDP_FAIL_NONE:PDP_FAIL_ERROR_UNSPECIFIED;
    response->suggestedRetryTime=connected?-1:5000;response->cid=1;response->active=connected?2:0;
    response->type=connected?link->protocol:"IPV4V6";response->ifname=connected?(char *)IFACE:"";response->addresses=connected?link->addresses:"";
    response->dnses=connected?link->dnses:"";response->gateways=connected?link->gateways:"";response->pcscf="";response->mtu=connected?link->mtu:0;
}

static void response_data_call(RIL_Token token,int list) {
    RIL_Data_Call_Response_v11 response;struct live_link link;
    int connected=atomic_load(&data_call_active)&&live_link(&link)==0;fill_data_call_response(&response,&link,connected);
    if(list){if(connected)complete(token,RIL_E_SUCCESS,&response,sizeof(response));else complete(token,RIL_E_SUCCESS,NULL,0);}
    else complete(token,connected?RIL_E_SUCCESS:RIL_E_GENERIC_FAILURE,&response,sizeof(response));
}

static void response_operator(RIL_Token token) {
    static char numeric[8];snprintf(numeric,sizeof(numeric),"%s%s",profile.mcc,profile.mnc);
    char *values[3]={profile.carrier,profile.carrier,numeric};complete(token,RIL_E_SUCCESS,values,sizeof(values));
}

static void response_device_identity(RIL_Token token,int kind) {
    static char imei[PROP_VALUE_MAX],imeisv[PROP_VALUE_MAX];
    if(__system_property_get("persist.xenoid.radio.imei",imei)<=0)snprintf(imei,sizeof(imei),"356938035643809");
    if(__system_property_get("persist.xenoid.radio.imeisv",imeisv)<=0)snprintf(imeisv,sizeof(imeisv),"01");
    if(kind==1){char *values[4]={imei,imeisv,"",""};complete(token,RIL_E_SUCCESS,values,sizeof(values));}
    else if(kind==2)complete(token,RIL_E_SUCCESS,imeisv,strlen(imeisv)+1);
    else complete(token,RIL_E_SUCCESS,imei,strlen(imei)+1);
}

static void response_radio_capability(RIL_Token token,const void *data,size_t length) {
    static RIL_RadioCapability capability;memset(&capability,0,sizeof(capability));
    capability.version=RIL_RADIO_CAPABILITY_VERSION;capability.phase=RC_PHASE_CONFIGURED;
    capability.rat=RAF_LTE;snprintf(capability.logicalModemUuid,sizeof(capability.logicalModemUuid),"xenoid.lm0");
    if(data&&length>=sizeof(RIL_RadioCapability)){
        const RIL_RadioCapability *request=(const RIL_RadioCapability *)data;
        capability.session=request->session;capability.phase=request->phase;
        capability.status=request->phase==RC_PHASE_FINISH?RC_STATUS_SUCCESS:RC_STATUS_NONE;
    }
    complete(token,RIL_E_SUCCESS,&capability,sizeof(capability));
}

static int request_supported(int request) {
    switch(request){
        case RIL_REQUEST_GET_SIM_STATUS:case RIL_REQUEST_GET_IMSI:case RIL_REQUEST_ENTER_SIM_PIN:
        case RIL_REQUEST_ENTER_SIM_PUK:case RIL_REQUEST_QUERY_FACILITY_LOCK:case RIL_REQUEST_SET_FACILITY_LOCK:
        case RIL_REQUEST_SIM_IO:case RIL_REQUEST_OPERATOR:case RIL_REQUEST_VOICE_REGISTRATION_STATE:
        case RIL_REQUEST_DATA_REGISTRATION_STATE:case RIL_REQUEST_SIGNAL_STRENGTH:case RIL_REQUEST_GET_CELL_INFO_LIST:
        case RIL_REQUEST_SET_UNSOL_CELL_INFO_LIST_RATE:case RIL_REQUEST_SETUP_DATA_CALL:case RIL_REQUEST_DEACTIVATE_DATA_CALL:
        case RIL_REQUEST_DATA_CALL_LIST:case RIL_REQUEST_QUERY_NETWORK_SELECTION_MODE:case RIL_REQUEST_SET_NETWORK_SELECTION_AUTOMATIC:
        case RIL_REQUEST_GET_PREFERRED_NETWORK_TYPE:case RIL_REQUEST_SET_PREFERRED_NETWORK_TYPE:case RIL_REQUEST_RADIO_POWER:
        case RIL_REQUEST_GET_IMEI:case RIL_REQUEST_GET_IMEISV:case RIL_REQUEST_BASEBAND_VERSION:
        case RIL_REQUEST_DEVICE_IDENTITY:case RIL_REQUEST_VOICE_RADIO_TECH:case RIL_REQUEST_ALLOW_DATA:
        case RIL_REQUEST_SET_INITIAL_ATTACH_APN:case RIL_REQUEST_SET_DATA_PROFILE:case RIL_REQUEST_SET_LOCATION_UPDATES:
        case RIL_REQUEST_SCREEN_STATE:case RIL_REQUEST_SEND_DEVICE_STATE:case RIL_REQUEST_SET_UNSOLICITED_RESPONSE_FILTER:
        case RIL_REQUEST_GET_CURRENT_CALLS:case RIL_REQUEST_IMS_REGISTRATION_STATE:
        case RIL_REQUEST_GET_RADIO_CAPABILITY:case RIL_REQUEST_SET_RADIO_CAPABILITY:
        case RIL_REQUEST_GET_ACTIVITY_INFO:case RIL_REQUEST_SHUTDOWN:return 1;default:return 0;
    }
}

static void on_request(int request,void *data,size_t length,RIL_Token token) {
    __android_log_print(ANDROID_LOG_DEBUG,"XenoidRIL","request=%d bytes=%zu",request,length);
    switch(request){
        case RIL_REQUEST_GET_SIM_STATUS:response_sim_status(token);break;
        case RIL_REQUEST_GET_IMSI:complete(token,RIL_E_SUCCESS,profile.imsi,strlen(profile.imsi)+1);break;
        case RIL_REQUEST_SIM_IO:response_sim_io(token,data,length);break;
        case RIL_REQUEST_OPERATOR:response_operator(token);break;
        case RIL_REQUEST_VOICE_REGISTRATION_STATE:response_registration(token,0);break;
        case RIL_REQUEST_DATA_REGISTRATION_STATE:response_registration(token,1);break;
        case RIL_REQUEST_SIGNAL_STRENGTH:response_signal(token);break;
        case RIL_REQUEST_GET_CELL_INFO_LIST:response_cell_info(token);break;
        case RIL_REQUEST_SETUP_DATA_CALL:atomic_store(&data_call_active,1);response_data_call(token,0);break;
        case RIL_REQUEST_DEACTIVATE_DATA_CALL:atomic_store(&data_call_active,0);complete(token,RIL_E_SUCCESS,NULL,0);break;
        case RIL_REQUEST_DATA_CALL_LIST:response_data_call(token,1);break;
        case RIL_REQUEST_QUERY_FACILITY_LOCK:{static int unlocked=0;complete(token,RIL_E_SUCCESS,&unlocked,sizeof(unlocked));break;}
        case RIL_REQUEST_ENTER_SIM_PIN:case RIL_REQUEST_ENTER_SIM_PUK:case RIL_REQUEST_SET_FACILITY_LOCK:{static int retries=3;complete(token,RIL_E_SUCCESS,&retries,sizeof(retries));break;}
        case RIL_REQUEST_QUERY_NETWORK_SELECTION_MODE:{static int automatic=0;complete(token,RIL_E_SUCCESS,&automatic,sizeof(automatic));break;}
        case RIL_REQUEST_GET_PREFERRED_NETWORK_TYPE:{int value=atomic_load(&preferred_network_type);complete(token,RIL_E_SUCCESS,&value,sizeof(value));break;}
        case RIL_REQUEST_SET_PREFERRED_NETWORK_TYPE:if(data&&length>=sizeof(int))atomic_store(&preferred_network_type,*(int *)data);complete(token,RIL_E_SUCCESS,NULL,0);break;
        case RIL_REQUEST_SET_UNSOL_CELL_INFO_LIST_RATE:if(data&&length>=sizeof(int))atomic_store(&cell_info_rate,*(int *)data);complete(token,RIL_E_SUCCESS,NULL,0);break;
        case RIL_REQUEST_GET_IMEI:response_device_identity(token,0);break;
        case RIL_REQUEST_GET_IMEISV:response_device_identity(token,2);break;
        case RIL_REQUEST_DEVICE_IDENTITY:response_device_identity(token,1);break;
        case RIL_REQUEST_BASEBAND_VERSION:{static char version[]="g5300g-230605-230621-B-10346107";complete(token,RIL_E_SUCCESS,version,sizeof(version));break;}
        case RIL_REQUEST_VOICE_RADIO_TECH:{static int technology=RADIO_TECH_LTE;complete(token,RIL_E_SUCCESS,&technology,sizeof(technology));break;}
        case RIL_REQUEST_GET_CURRENT_CALLS:complete(token,RIL_E_SUCCESS,NULL,0);break;
        case RIL_REQUEST_IMS_REGISTRATION_STATE:{static int state[2]={0,RADIO_TECH_LTE};complete(token,RIL_E_SUCCESS,state,sizeof(state));break;}
        case RIL_REQUEST_GET_RADIO_CAPABILITY:response_radio_capability(token,NULL,0);break;
        case RIL_REQUEST_SET_RADIO_CAPABILITY:response_radio_capability(token,data,length);break;
        case RIL_REQUEST_GET_ACTIVITY_INFO:{static RIL_ActivityStatsInfo activity;memset(&activity,0,sizeof(activity));complete(token,RIL_E_SUCCESS,&activity,sizeof(activity));break;}
        case RIL_REQUEST_RADIO_POWER:case RIL_REQUEST_SET_NETWORK_SELECTION_AUTOMATIC:case RIL_REQUEST_ALLOW_DATA:
        case RIL_REQUEST_SET_INITIAL_ATTACH_APN:case RIL_REQUEST_SET_DATA_PROFILE:case RIL_REQUEST_SET_LOCATION_UPDATES:
        case RIL_REQUEST_SCREEN_STATE:case RIL_REQUEST_SEND_DEVICE_STATE:case RIL_REQUEST_SET_UNSOLICITED_RESPONSE_FILTER:
        case RIL_REQUEST_SHUTDOWN:complete(token,RIL_E_SUCCESS,NULL,0);break;
        default:complete(token,RIL_E_REQUEST_NOT_SUPPORTED,NULL,0);break;
    }
}

static RIL_RadioState on_state_request(void){return RADIO_STATE_ON;}
static int supports(int request){return request_supported(request);}
static void on_cancel(RIL_Token token){(void)token;}
static const char *get_version(void){return "Android reference RIL v15";}

static void poll_data_call(void *unused) {
    (void)unused;static struct live_link prior;static int initialized=0;struct live_link current;
    int connected=atomic_load(&data_call_active)&&live_link(&current)==0;
    if(connected&&(!initialized||memcmp(&prior,&current,sizeof(current))!=0)){
        if(initialized){RIL_Data_Call_Response_v11 response;fill_data_call_response(&response,&current,1);
            ril_environment->OnUnsolicitedResponse(RIL_UNSOL_DATA_CALL_LIST_CHANGED,&response,sizeof(response));}
        RIL_CellInfo_v12 cell;fill_cell_info(&cell);
        ril_environment->OnUnsolicitedResponse(RIL_UNSOL_CELL_INFO_LIST,&cell,sizeof(cell));
        prior=current;initialized=1;
    }else if(!connected)initialized=0;
    struct timeval delay={2,0};ril_environment->RequestTimedCallback(poll_data_call,NULL,&delay);
}

static void initial_unsolicited(void *unused) {
    (void)unused;ril_environment->OnUnsolicitedResponse(RIL_UNSOL_RESPONSE_RADIO_STATE_CHANGED,NULL,0);
    ril_environment->OnUnsolicitedResponse(RIL_UNSOL_RESPONSE_SIM_STATUS_CHANGED,NULL,0);
    ril_environment->OnUnsolicitedResponse(RIL_UNSOL_VOICE_RADIO_TECH_CHANGED,&(int){RADIO_TECH_LTE},sizeof(int));
    RIL_SignalStrength_v10 signal;fill_signal(&signal);ril_environment->OnUnsolicitedResponse(RIL_UNSOL_SIGNAL_STRENGTH,&signal,sizeof(signal));
    RIL_CellInfo_v12 cell;fill_cell_info(&cell);ril_environment->OnUnsolicitedResponse(RIL_UNSOL_CELL_INFO_LIST,&cell,sizeof(cell));
    struct timeval delay={2,0};ril_environment->RequestTimedCallback(poll_data_call,NULL,&delay);
}

static const RIL_RadioFunctions radio_functions={15,on_request,on_state_request,supports,on_cancel,get_version};

__attribute__((visibility("default")))
const RIL_RadioFunctions *RIL_Init(const struct RIL_Env *environment,int argc,char **argv) {
    (void)argc;(void)argv;ril_environment=environment;
    if(load_profile_file(&profile)!=0){bootstrap_profile(&profile);profile_is_bootstrap=1;}else profile_is_bootstrap=0;
    struct timeval delay={1,0};environment->RequestTimedCallback(initial_unsolicited,NULL,&delay);
    return &radio_functions;
}

#ifdef XENOID_RIL_HOST_TEST
int main(int argc,char **argv){
    if(argc!=2)return 2;int descriptor=open(argv[1],O_RDONLY|O_CLOEXEC);if(descriptor<0)return 3;
    struct stat info;if(fstat(descriptor,&info)!=0||info.st_size<=0||info.st_size>PROFILE_MAX_BYTES){close(descriptor);return 4;}
    uint8_t *data=malloc((size_t)info.st_size);if(!data){close(descriptor);return 5;}size_t used=0;
    while(used<(size_t)info.st_size){ssize_t count=read(descriptor,data+used,(size_t)info.st_size-used);if(count<=0){free(data);close(descriptor);return 6;}used+=(size_t)count;}
    close(descriptor);struct radio_profile parsed;int result=parse_profile(data,used,&parsed);memset(data,0,used);free(data);
    if(result!=0)return 7;printf("%s %s %u %u %s\n",parsed.mcc,parsed.mnc,parsed.band,parsed.earfcn,parsed.digest);return 0;
}
#endif
