#include "globals.h"
#ifdef READER_TONGFANG
#include "reader-common.h"
#include "reader-tongfang.h"

int32_t tf_test = 0;//调试信息回显开关，0=关闭，1=打开(.conf>>unlockparental)
int32_t tf_v = 0;//版本标示，2=30&31卡，3=32卡
uchar keyblock[96]={
	0xed,0x44,0x1d,0x92,0xef,0x17,0x2f,0xee,
	0xc5,0x76,0x71,0xbd,0xe2,0x7b,0x4a,0xbb,
	0x3a,0xa5,0xc8,0xc7,0x46,0xe4,0xb2,0x11,
	0x23,0xb2,0x8f,0x49,0xd9,0x88,0x93,0x0e,
	0x96,0xf7,0x64,0x23,0xf7,0x62,0xb8,0x5e,
	0x89,0x6c,0xbd,0xb8,0x76,0xcb,0x24,0x9d,
	0x92,0xca,0x2a,0x26,0x64,0xd3,0x4c,0x2a,
	0x53,0x69,0x94,0xce,0xa5,0xa4,0x9d,0x95,
	0x54,0x3a,0xa5,0x52,0x33,0x29,0xa9,0x99,
	0xa6,0xe5,0xa8,0xf4,0x27,0x15,0x4a,0x49,
	0xe9,0xa9,0x2b,0x1d,0x52,0xb2,0x4f,0x4a,
	0x54,0x4c,0x74,0x54,0xcb,0x27,0xd2,0x52,
};
uchar seed[8]={0};
uchar commkey[8]={0};

static time_t tongfang_cal_date(int xday)
{
    time_t t;
    t = xday * 24 * 3600 + 946656000 - 1;
    return t;
}

static int32_t cw_is_valid(unsigned char *cw) //returns 1 if cw_is_valid, returns 0 if cw is all zeros
{
  int32_t i;

  for (i = 0; i < 8; i++)
  {
    if (cw[i] != 0) //test if cw = 00
    {
      return OK;
    }
  }
  return ERROR;
}

static int32_t tongfang_read_data(struct s_reader *reader, uchar size, uchar *cta_res, uint16_t *status)
{
  uchar read_data_cmd[]={0x00,0xc0,0x00,0x00,0xff};
  uint16_t cta_lr;

  read_data_cmd[4] = size;
  write_cmd(read_data_cmd, NULL);

  *status = (cta_res[cta_lr - 2] << 8) | cta_res[cta_lr - 1];

  return(cta_lr - 2);
}

static int32_t tongfang_card_init(struct s_reader *reader, ATR *newatr)
{
  static const uchar begin_cmd[] = {0x00,0xa4,0x04,0x00,0x05,0xf9,0x5a,0x54,0x00,0x06};
  static const uchar tf3_begin_cmd[] = {0x80,0x46,0x00,0x00,0x04,0x07,0x00,0x00,0x08};
  static const uchar get_serial_cmd[] = {0x80,0x46,0x00,0x00,0x04,0x01,0x00,0x00,0x04};
  static const uchar tf3_get_serial_cmd[] = {0x80,0x46,0x00,0x00,0x04,0x01,0x00,0x00,0x14};
  uchar get_commkey_cmd[17]={
	0x80,0x56,0x00,0x00,0x0c,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	//0x01,0x1F,0x8E,0x7A
	0x01,0x1F,0x84,0x2B
  };
  uchar zero[8] = {0};
  uchar get_commkey_result[8] = {0};
  uchar confirm_commkey_cmd[21]={0x80,0x4c,0x00,0x00,0x10};
  uchar confirm_commkey_result[16] = {0};
  uchar confirm_commkey_stbid[8] = {0x01,0x00,0x12,0x34,0x00,0x00,0x00,0x00};
  uchar pairing_cmd[] = {0x80,0x4c,0x00,0x00,0x04,0xFF,0xFF,0xFF,0xFF};

  uchar data[257];
  int32_t data_len = 0;
  uint16_t status = 0;
  uchar boxID[] = {0xFF, 0xFF, 0xFF, 0xFF};
  int32_t i;

  def_resp;
  get_hist;
  get_atr;
  
  //赋值给调试开关
  tf_test = cfg.ulparent;

  if ((hist_size < 4) || (memcmp(hist, "NTIC",4))) return ERROR;
  
  reader->caid = 0x4A02;//填充默认CAID
  reader->nprov = 4;//填充默认提供商数量
  memset(reader->prid, 0x00, sizeof(reader->prid));//将二位数组全部填零

  //版本判断
  if (atr[8] == 0x30){

	rdr_log(reader, "tongfang 2.x (atr=30) card detected");
	tf_v = 2;

  }else if (atr[8] == 0x31){
  
	rdr_log(reader, "tongfang 2.x (atr=31) card detected");
	tf_v = 2;

  }else if (atr[8] == 0x32){
  
	rdr_log(reader, "tongfang 3.x (atr=32) card detected");
	tf_v = 3;

  }else if (atr[8] == 0x33){
  
	rdr_log(reader, "tongfang 3.x (atr=33) card detected");
	return ERROR;

  }else{
  
	rdr_log(reader, "tongfang X card detected");
	return ERROR;
	
  }

  //准备指令
  if (tf_v == 2){
  
	write_cmd(begin_cmd, begin_cmd + 5);
	if(tf_test) rdr_log(reader, "begin_cmd,rdata=%02X %02X", cta_res[cta_lr - 2], cta_res[cta_lr - 1]);
	if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00)) { return ERROR; }
	
  }else{
  
	write_cmd(tf3_begin_cmd, tf3_begin_cmd + 5);
	if(tf_test) rdr_log(reader, "tf3_begin_cmd,rdata=%02X %02X", cta_res[cta_lr - 2], cta_res[cta_lr - 1]);
	if((cta_res[cta_lr - 2] & 0xf0) != 0x60) return ERROR;
	
	data_len = tongfang_read_data(reader, cta_res[cta_lr - 1], data, &status);
	if(tf_test) rdr_log(reader, "tf3_begin_cmd.tongfang_read_data,data_len=%02u,status=%04X", data_len, status);
	if((data_len < 0) || (status != 0x9000)) return ERROR;

	if(tf_test) rdr_log(reader, "feedback=%02X %02X %02X %02X %02X %02X %02X %02X",
		data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);
	
  }

  //获取卡号
  if (tf_v == 2){

	write_cmd(get_serial_cmd, get_serial_cmd + 5);
	if(tf_test) rdr_log(reader, "get_serial_cmd,rdata=%02X %02X", cta_res[cta_lr - 2], cta_res[cta_lr - 1]);
	if((cta_res[cta_lr - 2] & 0xf0) != 0x60) { return ERROR; }

	data_len = tongfang_read_data(reader, cta_res[cta_lr - 1], data, &status);
	if(tf_test) rdr_log(reader, "get_serial_cmd.tongfang_read_data,data_len=%02u,status=%04X", data_len, status);
	if((data_len < 0) || (status != 0x9000)) return ERROR;

	if(tf_test) rdr_log(reader, "feedback=%02X %02X %02X %02X",	data[0], data[1], data[2], data[3]);

	memset(reader->hexserial, 0, 8);
	memcpy(reader->hexserial + 2, data, 4); // might be incorrect offset
	
  }else{
  
	write_cmd(tf3_get_serial_cmd, tf3_get_serial_cmd + 5);
	if(tf_test) rdr_log(reader, "tf3_get_serial_cmd,rdata=%02X %02X", cta_res[cta_lr - 2], cta_res[cta_lr - 1]);
	if((cta_res[cta_lr - 2] & 0xf0) != 0x60) return ERROR;

	data_len = tongfang_read_data(reader, cta_res[cta_lr - 1], data, &status);
	if(tf_test) rdr_log(reader, "tf3_get_serial_cmd.tongfang_read_data,data_len=%02u,status=%04X", data_len, status);
	if((data_len < 0) || (status != 0x9000)) return ERROR;

	memset(reader->hexserial, 0, 8);
	memcpy(reader->hexserial + 2, data, 4); // might be incorrect offset

	if(tf_test) rdr_log(reader, "feedback=%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
		data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9],
		data[10], data[11], data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19]);
	
  }

  //获取COMMKEY
  if (tf_v == 3){
	des0_ex(true, zero, keyblock, get_commkey_result);
	memcpy(get_commkey_cmd+5, get_commkey_result, 8);
	
	write_cmd(get_commkey_cmd, get_commkey_cmd + 5);
	if(tf_test) rdr_log(reader, "get_commkey_cmd,rdata=%02X %02X", cta_res[cta_lr - 2], cta_res[cta_lr - 1]);
	if((cta_res[cta_lr - 2] & 0xf0) != 0x60) return ERROR;

	data_len = tongfang_read_data(reader, cta_res[cta_lr - 1], data, &status);
	if(tf_test) rdr_log(reader, "get_commkey_cmd.tongfang_read_data,data_len=%02u,status=%04X", data_len, status);
	if((data_len < 0) || (status != 0x9000)) return ERROR;
	
	if(tf_test) rdr_log(reader, "feedback=%02X %02X %02X %02X %02X %02X %02X %02X",
		data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);
	
	memcpy(seed, data, 8);
	if(tf_test) rdr_log(reader, "seed=%02X%02X%02X%02X%02X%02X%02X%02X",
		seed[0], seed[1], seed[2], seed[3], seed[4], seed[5], seed[6], seed[7]);

	des0_ex(true, seed, keyblock, commkey);
	if(tf_test) rdr_log(reader, "commkey=%02X%02X%02X%02X%02X%02X%02X%02X",
		commkey[0], commkey[1], commkey[2], commkey[3], commkey[4], commkey[5], commkey[6], commkey[7]);

  }
  
  //确认COMMKEY
  if (tf_v == 3){
	des0( true, confirm_commkey_stbid, commkey, confirm_commkey_result);
	des0( true, zero, commkey, confirm_commkey_result + 8);
	memcpy(confirm_commkey_cmd + 5, confirm_commkey_result, 16);
	
	write_cmd(confirm_commkey_cmd, confirm_commkey_cmd + 5);
	if(tf_test) rdr_log(reader, "confirm_commkey_cmd,rdata=%02X %02X", cta_res[cta_lr - 2], cta_res[cta_lr - 1]);
	if((cta_res[cta_lr - 2] & 0xf0) != 0x60) return ERROR;

	data_len = tongfang_read_data(reader, cta_res[cta_lr - 1], data, &status);
	if(tf_test) rdr_log(reader, "confirm_commkey_cmd.tongfang_read_data,data_len=%02u,status=%04X", data_len, status);
	if((data_len < 0) || (status != 0x9000)) return ERROR;

	if(tf_test) rdr_log(reader, "feedback=%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
		data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9]);
	
  }

  //填充BOXID
  if (reader->boxid > 0)
  {
    for (i = 0; i < 4; i++)
    {
      boxID[i] = (reader->boxid >> (8 * (3 - i))) % 0x100;
    }
  }

  //机卡配对
  if (tf_v == 2){
	
	//TF2先发送BOXID=FFFFFFFF的检查指令
	write_cmd(pairing_cmd, pairing_cmd + 5);
	if(tf_test) rdr_log(reader, "pairing_cmd.check,rdata=%02X %02X",cta_res[cta_lr - 2],cta_res[cta_lr - 1]);
	
	//TF2再处理判断返回数据
	if((cta_res[cta_lr - 2] == 0x94) && (cta_res[cta_lr - 1] == 0xB1)){

		//没有配对要求，直接PASS
		rdr_log(reader, "not have pairing function");
	
	}else if((cta_res[cta_lr - 2] == 0x94) && (cta_res[cta_lr - 1] == 0xB2)){
	
		//具有配对要求，将boxID填充到指令
		memcpy(pairing_cmd + 5, boxID, sizeof(boxID));

		//发送真正的配对指令
		write_cmd(pairing_cmd, pairing_cmd + 5);
		if(tf_test) rdr_log(reader, "pairing_cmd.pairing,rdata=%02X %02X",cta_res[cta_lr - 2],cta_res[cta_lr - 1]);
	
		if((cta_res[cta_lr - 2] == 0x90) && (cta_res[cta_lr - 1] == 0x00)){

			//配对成功
			rdr_log(reader, "have pairing function,and pairing ok");
		
		}else{

			if (atr[8] == 0x31){
			
				rdr_log(reader, "maybe not have pairing function,(atr=31)");
			
			}else{
			
				//配对失败
				rdr_log(reader, "have pairing function,and pairing nok,but pass also");
				//return ERROR;
			
			}
		
		}

	}else{

		//返回数据异常。
		rdr_log(reader, "Unknown pairing error");
		return ERROR;

	}
  
  }else{

	//TF3直接处理判断返回数据,引用confirm_commkey读取的定长数据,怀疑,未确认正确
	//94 B1 76 D7 77 3B DC 7C DC 1A 90 00 
	if((data[0] == 0x94) && (data[1] == 0xB1)){

		//没有配对要求，直接PASS
		rdr_log(reader, "Not have pairing function");
		
	}else if((data[0] == 0x94) && (data[1] == 0xB2)){
	
		//大概可能估计有机卡配对要求，但是不知道配对指令，也PASS
		rdr_log(reader, "Have pairing function,but i do not know how to pair,sorry");
		//return ERROR;
		
	}else{
	
		//返回数据异常。
		rdr_log(reader, "Unknown pairing error");
		//return ERROR;
	
	}

  }

  //信息回写
  rdr_log_sensitive(reader, "type: tongfang, caid: %04X, serial: %llu, hex serial: %02X%02X%02X%02X, boxid: %02X%02X%02X%02X",
            reader->caid,
			(unsigned long long) b2ll(6, reader->hexserial),
			reader->hexserial[2], reader->hexserial[3], reader->hexserial[4], reader->hexserial[5],
            boxID[0], boxID[1], boxID[2], boxID[3]);
  
  return OK;
}

static int32_t tongfang_do_ecm(struct s_reader * reader, const ECM_REQUEST *er, struct s_ecm_answer *ea)
{
  uchar ecm_cmd[200];
  int32_t ecm_len;
  const uchar *pbuf = er->ecm;
  char *tmp;
  int32_t i = 0;
  int32_t write_len = 0;
  def_resp;
  int32_t read_size = 0;
  uchar data[100];
  int32_t data_len = 0;
  uint16_t status = 0;
  
  if((ecm_len = check_sct_len(er->ecm, 3)) < 0) return ERROR;

  if(cs_malloc(&tmp, ecm_len * 3 + 1)){
	rdr_debug_mask(reader, D_IFD, "ECM: %s", cs_hexdump(1, er->ecm, ecm_len, tmp, ecm_len * 3 + 1));
	free(tmp);
  }
  
  for(i = 0; i < (ecm_len - 1); i++){
    if ((pbuf[0]==0x80)&&(pbuf[1]==0x3A)){
      break;
    }
    pbuf++;
  }

  write_len = pbuf[4] + 5;
  memcpy(ecm_cmd, pbuf, write_len);
  write_cmd(ecm_cmd, ecm_cmd + 5);

  if((cta_lr - 2) >= 2){
  
    read_size = cta_res[1];
	
  }else{
  
    if((cta_res[cta_lr - 2] & 0xf0) == 0x60){
	
      read_size = cta_res[cta_lr - 1];
	  
    }else{
	
      return ERROR;
    
	}

  }

  data_len = tongfang_read_data(reader, read_size, data, &status);
  if(data_len < 23) return ERROR;
  
  if(!(er->ecm[0] & 0x01)){
  
    memcpy(ea->cw, data + 8, 16);//80
	
  }else{
  
    memcpy(ea->cw, data + 16, 8);//81
    memcpy(ea->cw + 8, data + 8, 8);
	
  }
  
  // All zeroes is no valid CW, can be a result of wrong boxid
  if(!cw_is_valid(ea->cw) || !cw_is_valid(ea->cw + 8)) return ERROR;

  if(tf_v == 3){

	//回显未解密的CW
	if(tf_test) rdr_log(reader, "old_cw=%02X%02X%02X%02X%02X%02X%02X%02X %02X%02X%02X%02X%02X%02X%02X%02X",
	ea->cw[0], ea->cw[1], ea->cw[2], ea->cw[3], ea->cw[4], ea->cw[5], ea->cw[6], ea->cw[7],
	ea->cw[8], ea->cw[9], ea->cw[10], ea->cw[11], ea->cw[12], ea->cw[13], ea->cw[14], ea->cw[15]);
 
  	uchar tempcw[16] = {0};
	des0(true, ea->cw, commkey, tempcw);
	des0(true, ea->cw+8, commkey, tempcw+8);
	memcpy(ea->cw,tempcw,16);

	//回显已解密的CW
	if(tf_test) rdr_log(reader, "new_cw=%02X%02X%02X%02X%02X%02X%02X%02X %02X%02X%02X%02X%02X%02X%02X%02X",
		ea->cw[0], ea->cw[1], ea->cw[2], ea->cw[3], ea->cw[4], ea->cw[5], ea->cw[6], ea->cw[7],
		ea->cw[8], ea->cw[9], ea->cw[10], ea->cw[11], ea->cw[12], ea->cw[13], ea->cw[14], ea->cw[15]);

  }
  
  return OK;
}

static int32_t tongfang_get_emm_type(EMM_PACKET *ep, struct s_reader *UNUSED(reader))
{
  ep->type = UNKNOWN;
  return 1;
}

static int32_t tongfang_get_emm_filter(struct s_reader *rdr, struct s_csystem_emm_filter** emm_filters, unsigned int* filter_count)
{
  return OK;
}

static int32_t tongfang_do_emm(struct s_reader *reader, EMM_PACKET *ep)
{
/*   uchar emm_cmd[200];
  def_resp;
  int32_t write_len;

  if(SCT_LEN(ep->emm) < 8) { return ERROR; }

  write_len = ep->emm[15] + 5;
  memcpy(emm_cmd, ep->emm + 11, write_len);

  write_cmd(emm_cmd, emm_cmd + 5); */

  return OK;
}

static int32_t tongfang_card_info(struct s_reader * reader)
{
  static const uchar get_provider_cmd[] = {0x80,0x44,0x00,0x00,0x08};
  uchar get_sub_cmd[] = {0x80,0x48,0x00,0x00,0x04,0x01,0x00,0x00,0x13};
  def_resp;
  int32_t i;
  int32_t j;
  int32_t sub_count;
  uchar data[257];
  uchar sub_data[13];
  int32_t data_len = 0;
  uint16_t status = 0;
  
  //清理entitlement
  cs_clear_entitlement(reader);
  write_cmd(get_provider_cmd, NULL);
  if(tf_test) rdr_log(reader, "get_provider_cmd,rdata=%02X %02X",cta_res[cta_lr - 2],cta_res[cta_lr - 1]);  
  if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00)) return ERROR;

  for(i = 0; i < reader->nprov; i++)
  {

	rdr_log(reader, "provider:%02X%02X", cta_res[i * 2], cta_res[i * 2 + 1]);
	reader->prid[ i ][ 2 ] = cta_res[i * 2];
	reader->prid[ i ][ 3 ] = cta_res[i * 2 + 1];

  }
  
  for(i = 0; i < reader->nprov; i++)
  {

	//过滤0000和ffff
	if (reader->prid[ i ][ 2 ] == 0x00 && reader->prid[ i ][ 3 ] == 0x00) continue;
	if (reader->prid[ i ][ 2 ] == 0xff && reader->prid[ i ][ 3 ] == 0xff) continue;
	
	//填充get_sub_cmd
	memcpy(get_sub_cmd + 2, &reader->prid[ i ][ 2 ], 1);
	memcpy(get_sub_cmd + 3, &reader->prid[ i ][ 3 ], 1);

	//执行get_sub_cmd
	write_cmd(get_sub_cmd, get_sub_cmd + 5);
	if(tf_test) rdr_log(reader, "%02X%02X.get_sub_cmd,rdata=%02X %02X", reader->prid[ i ][ 2 ], reader->prid[ i ][ 3 ], cta_res[cta_lr - 2], cta_res[cta_lr - 1]);
	if((cta_res[cta_lr - 2] & 0xf0) != 0x60) continue;

	//获取定长数据
	data_len = tongfang_read_data(reader, cta_res[cta_lr - 1], data, &status);
	if(tf_test) rdr_log(reader, "%02X%02X.get_sub_cmd.tongfang_read_data,data_len=%02u,status=%04X", reader->prid[ i ][ 2 ], reader->prid[ i ][ 3 ], data_len, status);
	if((data_len < 0) || (status != 0x9000)) continue;

	//验证授权条数
	sub_count = data[2];
	if(tf_test) rdr_log(reader, "%02X%02X.get_sub_cmd,have %04d subscription", reader->prid[ i ][ 2 ], reader->prid[ i ][ 3 ], sub_count);
	if (((data_len -3) / 13) != sub_count) continue;

	for(j = 0; j < sub_count; j++)
	{
		//提取授权信息
		memcpy(sub_data, data + 13 * j + 3, 13);
		if(tf_test) rdr_log(reader, "%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X", sub_data[0], sub_data[1], sub_data[2], sub_data[3], sub_data[4], sub_data[5], sub_data[6], sub_data[7], sub_data[8], sub_data[9], sub_data[10], sub_data[1], sub_data[12]);

		//00 01.ff fe.00.11 87 65 7a.1d f7 01 7d
		//00 01 02 03 04 05 06 07 08 09 10 11 12 13
		
		//过滤非显示授权信息
		if(sub_data[01] == 0x00) continue;
		int sub_id = ((sub_data[2] << 8) | sub_data[3]) & 0xffff;
		int d_start = ((sub_data[5] << 8) | sub_data[6]) & 0xffff;
		int d_end = ((sub_data[9] << 8) | sub_data[10]) & 0xffff;
		if(tf_test) rdr_log(reader, "sub_id:%04X,d_start=%d to d_end=%d", sub_id, d_start, d_end);
		
		struct tm p_start;
		struct tm p_end;
		time_t t_start;
		time_t t_end;
		
		//生成ADD和LOG需要的时间信息(START&END)
		t_start = tongfang_cal_date(d_start);
		t_end = tongfang_cal_date(d_end);
		gmtime_r(&t_start,&p_start);
		gmtime_r(&t_end,&p_end);
		
		//信息回写&增加entitlement
		rdr_log(reader, "provider:%02X%02X, package:%04X, start:%04d-%02d-%02d, end:%04d-%02d-%02d", reader->prid[ i ][ 2 ], reader->prid[ i ][ 3 ], sub_id, p_start.tm_year + 1900, p_start.tm_mon + 1, p_start.tm_mday, p_end.tm_year + 1900, p_end.tm_mon + 1, p_end.tm_mday);
		cs_add_entitlement(reader, reader->caid, b2ll(4, reader->prid[i]), sub_id, 0, t_start, t_end, 1);

	}

  }
  
  return OK;

}

void reader_tongfang(struct s_cardsystem *ph)
{
	ph->do_emm=tongfang_do_emm;
	ph->do_ecm=tongfang_do_ecm;
	ph->card_info=tongfang_card_info;
	ph->card_init=tongfang_card_init;
	ph->get_emm_type=tongfang_get_emm_type;
	ph->get_emm_filter=tongfang_get_emm_filter;
	ph->caids[0]=0x4A02;
	ph->desc="tongfang";
}

////////////////////////////////////////////////////////////////////////////////////////////////////////
//!8字节DES运算
void des0(BOOL bEncrypt, BYTE* lpSrc, BYTE* lpKey, BYTE* lpResult)
{
  BYTE Src[ 64 ];
  BYTE Dest[ 64 ];
  BYTE KeyMain[ 64 ];
  int  i, j;
		
  for( i = 0; i < 8; i++ )
  {
    dtob( lpSrc[ i ], Src + i * 8 );
    dtob( lpKey[ i ], KeyMain + i * 8 );
  }

  des_algo( Src, Dest, KeyMain, bEncrypt );
  
  for( i = 0; i < 8; i++ )
  {
    lpResult[ i ] = 0;
    for( j = 0; j < 8; j++ ) 
      lpResult[ i ] |= ( 1 << ( 7 - j ) ) * Dest[ 8 * i + j ];
  }

}

//!8字节DES运算
void des0_ex(BOOL bEncrypt, BYTE* lpSrc, BYTE* KeyBlock, BYTE* lpResult)
{
	BYTE Src[ 64 ];
	BYTE Dest[ 64 ];
	//BYTE KeyMain[ 64 ];
	int  i, j;
	
	for( i = 0; i < 8; i++ )
	{
		dtob( lpSrc[ i ], Src + i * 8 );

	}
	
	des_algo_ex( Src, Dest, KeyBlock, bEncrypt );
	
	for( i = 0; i < 8; i++ )
	{
		lpResult[ i ] = 0;
		for( j = 0; j < 8; j++ ) 
			lpResult[ i ] |= ( 1 << ( 7 - j ) ) * Dest[ 8 * i + j ];
	}
}

//!字节到位的转换
void dtob(BYTE Data, BYTE* lpResult)
{
  int i;

  for( i = 0; i < 8; i++ )
  {
    lpResult[ i ] = 0;
    if( Data & 0x80 ) 
      lpResult[ i ] = 1;
    Data = Data << 1;
  }
}

//!DES计算
void des_algo(BYTE* lpSrc, BYTE* lpDest, BYTE* lpKey, BOOL bEncrypt)
{
  BYTE SubKey[ 48 ];
  BYTE Tmp[ 32 ];
  BYTE Buffer[ 48 ];
  BYTE Left[ 32 ];
  BYTE Right[ 32 ];
  int i;
  //int j;
  BYTE IP[] = {
    57, 49, 41, 33, 25, 17,  9,  1, 59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5, 63, 55, 47, 39, 31, 23, 15,  7,
    56, 48, 40, 32, 24, 16,  8,  0, 58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4, 62, 54, 46, 38, 30, 22, 14,  6,
    255
  };

  BYTE IP_1[] = {
    39,  7, 47, 15, 55, 23, 63, 31, 38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29, 36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27, 34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25, 32,  0, 40,  8, 48, 16, 56, 24,
    255
  };

  BYTE E[] = {
    31,  0,  1,  2,  3,  4,  3,  4,  5,  6,  7,  8,  7,  8,  9, 10,
    11, 12,	11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 20,
    21, 22, 23, 24,	23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31,  0,
    255
  };

  BYTE P[] = {
    15,  6, 19, 20, 28, 11, 27, 16,  0, 14, 22, 25,  4, 17, 30,  9,
    1,  7, 23, 13, 31, 26,  2,  8, 18, 12, 29,  5, 21, 10,  3, 24,
    255
  };

  Transfer( lpSrc, lpDest, IP );

  for( i = 0; i < 32; i++ ) 
  {
    Left[ i ] = lpDest[ i ];
    Right[ i ] = lpDest[ i + 32 ];
  }

  //! 主循环
  for( i = 0; i < 16; i++ )
  {			
    if( bEncrypt )
      KeyGenerate( lpKey, SubKey, i );
    else
      KeyGenerate( lpKey, SubKey, 15 - i );
    str_cpy( Right, Tmp, 32 );
    
    Transfer( Right, Buffer, E );
    str_xor( SubKey, Buffer, 48 );
    S_change( Buffer );
    Transfer( Buffer, Right, P );

    str_xor( Left, Right, 32 );
    str_cpy( Tmp, Left, 32 );
  }
       
  for( i = 0; i < 32; i++ ) 
  {
    lpSrc[ i ] = Right[ i ];
    lpSrc[ 32 + i ] = Left[ i ];
  }

  Transfer( lpSrc, lpDest, IP_1 );
}

//!DES计算
void des_algo_ex(BYTE* lpSrc, BYTE* lpDest, BYTE* KeyBlock, BOOL bEncrypt)
{
  BYTE SubKey[ 48 ];
  BYTE Tmp[ 32 ];
  BYTE Buffer[ 48 ];
  BYTE Left[ 32 ];
  BYTE Right[ 32 ];
  int i;
  //int j;
  BYTE IP[] = {
    57, 49, 41, 33, 25, 17,  9,  1, 59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5, 63, 55, 47, 39, 31, 23, 15,  7,
    56, 48, 40, 32, 24, 16,  8,  0, 58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4, 62, 54, 46, 38, 30, 22, 14,  6,
    255
  };

  BYTE IP_1[] = {
    39,  7, 47, 15, 55, 23, 63, 31, 38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29, 36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27, 34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25, 32,  0, 40,  8, 48, 16, 56, 24,
    255
  };

  BYTE E[] = {
    31,  0,  1,  2,  3,  4,  3,  4,  5,  6,  7,  8,  7,  8,  9, 10,
    11, 12,	11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 20,
    21, 22, 23, 24,	23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31,  0,
    255
  };

  BYTE P[] = {
    15,  6, 19, 20, 28, 11, 27, 16,  0, 14, 22, 25,  4, 17, 30,  9,
    1,  7, 23, 13, 31, 26,  2,  8, 18, 12, 29,  5, 21, 10,  3, 24,
    255
  };

  Transfer( lpSrc, lpDest, IP );

  for( i = 0; i < 32; i++ ) 
  {
    Left[ i ] = lpDest[ i ];
    Right[ i ] = lpDest[ i + 32 ];
  }

  //! 主循环
  for( i = 0; i < 16; i++ )
  {			
    if( bEncrypt )
      KeyGenerate_ex( KeyBlock, SubKey, i );
    else
      KeyGenerate_ex( KeyBlock, SubKey, 15 - i );

    str_cpy( Right, Tmp, 32 );

    Transfer( Right, Buffer, E );//lpSrc

    str_xor( SubKey, Buffer, 48 );//lpSrc

    S_change( Buffer );//lpSrc

    Transfer( Buffer, Right, P );//lpSrc
    
    str_xor( Left, Right, 32 );
    str_cpy( Tmp, Left, 32 );

  }
  
  for( i = 0; i < 32; i++ ) 
  {
    lpSrc[ i ] = Right[ i ];
    lpSrc[ 32 + i ] = Left[ i ];
  }

  Transfer( lpSrc, lpDest, IP_1 );
}

//!扩展置换
void Transfer(BYTE* lpSrc, BYTE* lpDest, BYTE* lpTable)
{
  int nTableLength, i;
		
  nTableLength = 0;
  while( lpTable[ nTableLength ] != 255 )	
    nTableLength++;
		
  for( i = 0; i < nTableLength; i++ ) 
  {
    lpDest[ i ] = lpSrc[ lpTable[ i ] ];
  }
}

//!叠代子密钥生成
void KeyGenerate(BYTE* lpKeyIn, BYTE* lpKeySub, int nCount)
{
  BYTE Buffer[ 56 ];
  BYTE C0[ 28 ];
  BYTE D0[ 28 ];
  int i;

  BYTE shift[] = {
    1,  2,  4,  6,  8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28
  };

  BYTE PC_1[] = {
	  56, 48, 40, 32, 24, 16,  8,  0, 57, 49, 41, 33, 25, 17,
		  9,  1, 58, 50, 42, 34, 26, 18, 10,  2, 59, 51, 43, 35,
		  62, 54, 46, 38, 30, 22, 14,  6, 61, 53, 45, 37, 29, 21,
		  13,  5, 60, 52, 44, 36, 28, 20, 12,  4, 27, 19, 11,  3,
		  255
  };

  BYTE PC_2[] = {
    13, 16, 10, 23,  0,  4,  2, 27, 14,  5, 20,  9, 22, 18, 11,  3,
    25, 7, 15, 6, 26, 19, 12,  1, 40, 51, 30, 36, 46, 54, 29, 39,
    50, 44,  32, 47,  43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31,
    255
  };

  Transfer( lpKeyIn, Buffer, PC_1 );

  for( i = 0; i < 28; i++ )
  {
    C0[ i ] = Buffer[ i ];
    D0[ i ] = Buffer[ i + 28 ];
  }

  for( i = 0; i < shift[ nCount ]; i++ )
  {
    Circle( C0, 28 );
    Circle( D0, 28 );
  }

  for ( i = 0; i < 28; i++ ) 
  {
    Buffer[ i ] = C0[ i ];
    Buffer[ i + 28 ] = D0[ i ];
  }

  Transfer( Buffer, lpKeySub, PC_2 );
}

//!叠代子密钥生成
void KeyGenerate_ex(BYTE* KeyBlock, BYTE* lpKeySub, int nCount)
{
	int i = 0;
    
	for (i=0; i<48; i++)
	{
		lpKeySub[i] = (KeyBlock[i*2+nCount/8]>>(nCount%8))&1;
	}
}

//!循环移位
void Circle(BYTE* lpBuf, int nLength)	// to complete left circel shift 1 bit per time
{
  BYTE tmp;
  int i;

  tmp = lpBuf[ 0 ];
  for( i = 0; i < nLength - 1; i++ )
    lpBuf[ i ] = lpBuf[ i + 1 ];
  lpBuf[ nLength - 1 ] = tmp;
}

//!S盒转换
void S_change(BYTE* lpBuf)
{
  BYTE Src[ 8 ][ 6 ];
  BYTE Dest[ 8 ][ 4 ];
  int	 i, j;
  int nAdr;

  BYTE S[ 8 ][ 64 ] = {
    {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
     0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
     4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
     15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
    },

    {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
     3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
     0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
     13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
    },

    {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
     13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
     13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
     1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
    },

    { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
     13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
     10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
     3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
    },

    { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
     14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
     4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
     11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
    },

    {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
     10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
     9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
     4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
    },

    { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
     13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
     1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
     6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
    },

    {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
     1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
     7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
     2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
    }
  };
		
  for( i = 0; i < 8; i++ ) 
    for( j = 0; j < 6; j++ ) 
      Src[ i ][ j ] = lpBuf[ i * 6 + j ];
  
  for( i = 0; i < 8; i++ ) 
  {
    j = Src[ i ][ 1 ] * 8 + Src[ i ][ 2 ] * 4 + Src[ i ][ 3 ] * 2 + Src[ i ][ 4 ];
    nAdr = ( Src[ i ][ 0 ] * 2 + Src[ i ][ 5 ] ) * 16 + j;
    j = S[ i ][ nAdr ];
    Dest[ i ][ 0 ] = j / 8;
    j %= 8;
    Dest[ i ][ 1 ] = j / 4;
    j %= 4;
    Dest[ i ][ 2 ] = j / 2;
    Dest[ i ][ 3 ] = j % 2;
  }

  for( i = 0; i < 8; i++ ) 
    for( j = 0; j < 4; j++ )
      lpBuf[ i * 4 + j ] = Dest[ i ][ j ];
}

//!字符串异或运算
void str_xor(BYTE* lpSrc, BYTE* lpDest, int nLen)
{
  int i;
  for( i = 0; i < nLen; i++ )
    lpDest[ i ] = ( lpSrc[ i ] + lpDest[ i ] ) % 2;
}

//!字符串拷贝
void str_cpy(BYTE* lpSrc, BYTE* lpDest, int nLen)
{
  int i;

  for( i = 0; i < nLen; i++ )
    lpDest[ i ] = lpSrc[ i ];
}
////////////////////////////////////////////////////////////////////////////////////////////////////////

#endif