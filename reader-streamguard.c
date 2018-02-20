#include "globals.h"
#ifdef READER_STREAMGURAD
#include "reader-common.h"

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

static int32_t streamguard_read_data(struct s_reader *reader, uchar size, uchar *cta_res, uint16_t *status)
{
  static uchar read_data_cmd[]={0x00,0xc0,0x00,0x00,0xff};
  uint16_t cta_lr;

  read_data_cmd[4] = size;
  write_cmd(read_data_cmd, NULL);

  *status = (cta_res[cta_lr - 2] << 8) | cta_res[cta_lr - 1];

  return(cta_lr - 2);
}

static int32_t streamguard_card_init(struct s_reader *reader, ATR* newatr)
{
  static const uchar begin_cmd1[] = {0x00,0xa4,0x04,0x00,0x02,0x3f,0x00};
  static const uchar begin_cmd2[] = {0x00,0xa4,0x04,0x00,0x02,0x4a,0x00};
  static const uchar get_serial_cmd[] = {0x00,0xb2,0x00,0x05,0x06,0x00,0x01,0xff,0x00,0x01,0xff};

  uchar data[257];
  int32_t data_len = 0;
  uint16_t status = 0;

  def_resp;
  get_atr;

  if ((atr_size != 4) || (atr[0] != 0x3b) || (atr[1] != 0x02)) return ERROR;

  reader->caid = 0x4AD2;
  reader->nprov = 1;
  memset(reader->prid, 0x00, sizeof(reader->prid));

  rdr_log(reader, "Streamguard card detected");

  write_cmd(begin_cmd1, begin_cmd1 + 5);
  if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00)) return ERROR;

  write_cmd(begin_cmd2, begin_cmd2 + 5);
  if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00)) return ERROR;

  write_cmd(get_serial_cmd, get_serial_cmd + 5);
  if((cta_res[cta_lr - 2] & 0xf0) != 0x60) return ERROR;

  data_len = streamguard_read_data(reader, cta_res[cta_lr - 1], data, &status);
  if(data_len < 0 || status != 0x9000) return ERROR;

  memset(reader->hexserial, 0, 8);
  memcpy(reader->hexserial + 2, data + 3, 4); // might be incorrect offset

  rdr_log(reader, "Type: Streamguard, Caid: %04X, Serial: %llu, Hex Serial: %02X%02X%02X%02X, Full Serial: %02X%02X%02X%02X%02X%02X%02X%02X",
            reader->caid, b2ll(6, reader->hexserial), reader->hexserial[2],
            reader->hexserial[3], reader->hexserial[4], reader->hexserial[5],
			data[7], data[8], data[9], data[10], data[11], data[12], data[13], data[14]);

  return OK;
}

static int32_t streamguard_do_ecm(struct s_reader *reader, const ECM_REQUEST *er, struct s_ecm_answer *ea)
{
  uchar ecm_cmd[200] = {0x80,0x32,0x00,0x00};
  uchar data[100];
  int32_t ecm_len;
  uchar* pbuf = data;
  int32_t i = 0;
  int32_t write_len = 0;
  def_resp;
  int32_t read_size = 0;
  int32_t data_len = 0;
  uint16_t status = 0;
  char *tmp;

  if((ecm_len = check_sct_len(er->ecm, 3)) < 0) return ERROR;

  if(cs_malloc(&tmp, ecm_len * 3 + 1)){
	rdr_debug_mask(reader, D_IFD, "ECM: %s", cs_hexdump(1, er->ecm, ecm_len, tmp, ecm_len * 3 + 1));
	free(tmp);
  }

  write_len = er->ecm[2] + 3;
  ecm_cmd[4] = write_len;
  memcpy(ecm_cmd + 5, er->ecm, write_len);

  /*
	for(i = 0; i < 200; i = i + 10){
		rdr_log(reader, "CMD[%02d]:%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X", i/10 + 1,
		ecm_cmd[i], ecm_cmd[i+1], ecm_cmd[i+2], ecm_cmd[i+3], ecm_cmd[i+4],
		ecm_cmd[i+5], ecm_cmd[i+6], ecm_cmd[i+7], ecm_cmd[i+8], ecm_cmd[i+9]);
	}
  */
  
  write_cmd(ecm_cmd, ecm_cmd + 5);

  if ((cta_lr - 2) >= 2)
  {
    read_size = cta_res[1];
  }
  else
  {
    if((cta_res[cta_lr - 2] & 0xf0) == 0x60)
    {
      read_size = cta_res[cta_lr - 1];
    }
    else
    {
      return ERROR;
    }
  }

  data_len = streamguard_read_data(reader, read_size, data, &status);

  if(data_len < 20) return ERROR;

  for(i = 0; i < (data_len - 1); i++)
  {
    if ((pbuf[0]==0x83)&&(pbuf[1]==0x16))
    {
      break;
    }
    pbuf++;
  }

  if (i >= data_len)
  {
    return ERROR;
  }
  
  if((er->ecm[0] & 0x01))
  {
    memcpy(ea->cw +  8, pbuf + 6, 4);
    memcpy(ea->cw + 12, pbuf + 6 + 4 + 1, 4);
    memcpy(ea->cw +  0, pbuf + 6 + 8 + 1, 4);
    memcpy(ea->cw +  4, pbuf + 6 + 8 + 4 + 1 + 1, 4);
  }
  else
  {
    memcpy(ea->cw +  0, pbuf + 6, 4);
    memcpy(ea->cw +  4, pbuf + 6 + 4 + 1, 4);
    memcpy(ea->cw +  8, pbuf + 6 + 8 + 1, 4);
    memcpy(ea->cw + 12, pbuf + 6 + 8 + 4 + 1 + 1, 4);
  }

  // All zeroes is no valid CW, can be a result of wrong boxid
  if(!cw_is_valid(ea->cw) || !cw_is_valid(ea->cw + 8)) return ERROR;
  
  return OK;
}

static int32_t streamguard_get_emm_type(EMM_PACKET *ep, struct s_reader *UNUSED(reader))
{
  ep->type = UNKNOWN;
  return 1;
}

static int32_t streamguard_do_emm(struct s_reader *reader, EMM_PACKET *ep)
{
/*   uchar emm_cmd[200] = {0x80,0x30,0x00,0x00};
  def_resp;
  int32_t write_len;

  if(ep->emm[2] < 5) return ERROR;

  write_len = ep->emm[2] + 3;
  emm_cmd[4] = write_len;
  memcpy(emm_cmd + 5, ep->emm, write_len);

  write_cmd(emm_cmd, emm_cmd + 5); */

  return OK;
}

static int32_t streamguard_card_info(struct s_reader * UNUSED(reader))
{
  return OK;
}

void reader_streamguard(struct s_cardsystem *ph) 
{
	ph->do_emm=streamguard_do_emm;
	ph->do_ecm=streamguard_do_ecm;
	ph->card_info=streamguard_card_info;
	ph->card_init=streamguard_card_init;
	ph->get_emm_type=streamguard_get_emm_type;
	ph->caids[0]=0x4AD2;
	ph->desc="Streamguard";
}

#endif