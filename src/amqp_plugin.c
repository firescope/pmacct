/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2017 by Paolo Lucente
*/

/*
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#define __AMQP_PLUGIN_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "plugin_common.h"
#include "amqp_common.h"
#include "plugin_cmn_json.h"
#include "plugin_cmn_avro.h"
#include "amqp_plugin.h"
#include "flow_url_common.h"
#include "flow_collapse.h"
#ifndef WITH_JANSSON
#error "--enable-rabbitmq requires --enable-jansson"
#endif

/* Functions */
void amqp_plugin(int pipe_fd, struct configuration *cfgptr, void *ptr) 
{
  struct pkt_data *data;
  struct ports_table pt;
  unsigned char *pipebuf;
  struct pollfd pfd;
  struct insert_data idata;
  time_t t, avro_schema_deadline = 0;
  int timeout, refresh_timeout, amqp_timeout = 0, avro_schema_timeout = 0;
  int ret, num, recv_budget, poll_bypass;
  struct ring *rg = &((struct channels_list_entry *)ptr)->rg;
  struct ch_status *status = ((struct channels_list_entry *)ptr)->status;
  struct plugins_list_entry *plugin_data = ((struct channels_list_entry *)ptr)->plugin;
  int datasize = ((struct channels_list_entry *)ptr)->datasize;
  u_int32_t bufsz = ((struct channels_list_entry *)ptr)->bufsize;
  pid_t core_pid = ((struct channels_list_entry *)ptr)->core_pid;
  struct networks_file_data nfd;

  unsigned char *rgptr;
  int pollagain = TRUE;
  u_int32_t seq = 1, rg_err_count = 0;

  struct extra_primitives extras;
  struct primitives_ptrs prim_ptrs;
  char *dataptr;

#ifdef WITH_AVRO
  char *avro_acct_schema_str;
#endif

#ifdef WITH_ZMQ
  struct p_zmq_host *zmq_host = &((struct channels_list_entry *)ptr)->zmq_host;
#else
  void *zmq_host = NULL;
#endif

  memcpy(&config, cfgptr, sizeof(struct configuration));
  memcpy(&extras, &((struct channels_list_entry *)ptr)->extras, sizeof(struct extra_primitives));
  recollect_pipe_memory(ptr);
  pm_setproctitle("%s [%s]", "RabbitMQ/AMQP Plugin", config.name);

  P_set_signals();
  P_init_default_values();
  P_config_checks();
  pipebuf = (unsigned char *) pm_malloc(config.buffer_size);
  memset(pipebuf, 0, config.buffer_size);

  timeout = config.sql_refresh_time*1000;

  if (!config.sql_user) config.sql_user = rabbitmq_user;
  if (!config.sql_passwd) config.sql_passwd = rabbitmq_pwd;
  if (!config.message_broker_output) config.message_broker_output = PRINT_OUTPUT_JSON;

  
  if (config.message_broker_output & PRINT_OUTPUT_JSON) {
    compose_json(config.what_to_count, config.what_to_count_2);
  }
  else if (config.message_broker_output & PRINT_OUTPUT_AVRO) {
#ifdef WITH_AVRO
    avro_acct_schema = build_avro_schema(config.what_to_count, config.what_to_count_2);
    avro_schema_add_writer_id(avro_acct_schema);

    if (config.avro_schema_output_file) write_avro_schema_to_file(config.avro_schema_output_file, avro_acct_schema);

    if (config.amqp_avro_schema_routing_key) {
      if (!config.amqp_avro_schema_refresh_time)
        config.amqp_avro_schema_refresh_time = DEFAULT_AVRO_SCHEMA_REFRESH_TIME;

      avro_schema_deadline = time(NULL);
      P_init_refresh_deadline(&avro_schema_deadline, config.amqp_avro_schema_refresh_time, 0, "m");
      avro_acct_schema_str = compose_avro_purge_schema(avro_acct_schema, config.name);
    }
    else {
      config.amqp_avro_schema_refresh_time = 0;
      avro_schema_deadline = 0;
      avro_schema_timeout = 0;
      avro_acct_schema_str = NULL;
    }
#endif
  }

  if ((config.sql_table && strchr(config.sql_table, '$')) && config.sql_multi_values) {
    Log(LOG_ERR, "ERROR ( %s/%s ): dynamic 'amqp_routing_key' is not compatible with 'amqp_multi_values'. Exiting.\n", config.name, config.type);
    exit_plugin(1);
  }

  if ((config.sql_table && strchr(config.sql_table, '$')) && config.amqp_routing_key_rr) {
    Log(LOG_ERR, "ERROR ( %s/%s ): dynamic 'amqp_routing_key' is not compatible with 'amqp_routing_key_rr'. Exiting.\n", config.name, config.type);
    exit_plugin(1);
  }

  /* setting function pointers */
  if (config.what_to_count & (COUNT_SUM_HOST|COUNT_SUM_NET))
    insert_func = P_sum_host_insert;
  else if (config.what_to_count & COUNT_SUM_PORT) insert_func = P_sum_port_insert;
  else if (config.what_to_count & COUNT_SUM_AS) insert_func = P_sum_as_insert;
#if defined (HAVE_L2)
  else if (config.what_to_count & COUNT_SUM_MAC) insert_func = P_sum_mac_insert;
#endif
  else insert_func = P_cache_insert;
  purge_func = amqp_cache_purge;

  memset(&nt, 0, sizeof(nt));
  memset(&nc, 0, sizeof(nc));
  memset(&pt, 0, sizeof(pt));

  load_networks(config.networks_file, &nt, &nc);
  set_net_funcs(&nt);

  if (config.ports_file) load_ports(config.ports_file, &pt);
  
  memset(&idata, 0, sizeof(idata));
  memset(&prim_ptrs, 0, sizeof(prim_ptrs));
  set_primptrs_funcs(&extras);

  if (config.pipe_zmq) P_zmq_pipe_init(zmq_host, &pipe_fd, &seq);
  else setnonblocking(pipe_fd);

  idata.now = time(NULL);

  /* print_refresh time init: deadline */
  refresh_deadline = idata.now; 
  P_init_refresh_deadline(&refresh_deadline, config.sql_refresh_time, config.sql_startup_delay, config.sql_history_roundoff);

  if (config.sql_history) {
    basetime_init = P_init_historical_acct;
    basetime_eval = P_eval_historical_acct;
    basetime_cmp = P_cmp_historical_acct;

    (*basetime_init)(idata.now);
  }

  /* setting number of entries in _protocols structure */
  while (_protocols[protocols_number].number != -1) protocols_number++;

  if (config.what_to_count & COUNT_CLASS) {
    /* set up shared memory for url's */
    init_url_entries();
  }

  /* plugin main loop */
  for(;;) {
    poll_again:
    status->wakeup = TRUE;
    poll_bypass = FALSE;

    calc_refresh_timeout(refresh_deadline, idata.now, &refresh_timeout);
    if (config.amqp_avro_schema_routing_key) calc_refresh_timeout(avro_schema_deadline, idata.now, &avro_schema_timeout);

    pfd.fd = pipe_fd;
    pfd.events = POLLIN;
    timeout = MIN(refresh_timeout, (avro_schema_timeout ? avro_schema_timeout : INT_MAX));
    ret = poll(&pfd, (pfd.fd == ERR ? 0 : 1), timeout);

    if (ret <= 0) {
      if (getppid() != core_pid) {
        Log(LOG_ERR, "ERROR ( %s/%s ): Core process *seems* gone. Exiting.\n", config.name, config.type);
        exit_plugin(1);
      }

      if (ret < 0) goto poll_again;
    }

    poll_ops:
    P_update_time_reference(&idata);

    if (idata.now > refresh_deadline) P_cache_handle_flush_event(&pt);

#ifdef WITH_AVRO
    if (idata.now > avro_schema_deadline) {
      amqp_avro_schema_purge(avro_acct_schema_str);
      avro_schema_deadline += config.amqp_avro_schema_refresh_time;
    }
#endif

    recv_budget = 0;
    if (poll_bypass) {
      poll_bypass = FALSE;
      goto read_data;
    }

    if (config.what_to_count & COUNT_CLASS) {
      init_url_reader();
      process_url();
    }

    switch (ret) {
    case 0: /* timeout */
      break;
    default: /* we received data */
      read_data:
      if (recv_budget == DEFAULT_PLUGIN_COMMON_RECV_BUDGET) {
	poll_bypass = TRUE;
	goto poll_ops;
      }

      if (config.pipe_homegrown) {
        if (!pollagain) {
          seq++;
          seq %= MAX_SEQNUM;
          if (seq == 0) rg_err_count = FALSE;
        }
        else {
          if ((ret = read(pipe_fd, &rgptr, sizeof(rgptr))) == 0) 
	    exit_plugin(1); /* we exit silently; something happened at the write end */
        }

        if ((rg->ptr + bufsz) > rg->end) rg->ptr = rg->base;

        if (((struct ch_buf_hdr *)rg->ptr)->seq != seq) {
          if (!pollagain) {
            pollagain = TRUE;
            goto poll_again;
          }
          else {
            rg_err_count++;
            if (config.debug || (rg_err_count > MAX_RG_COUNT_ERR)) {
              Log(LOG_WARNING, "WARN ( %s/%s ): Missing data detected (plugin_buffer_size=%llu plugin_pipe_size=%llu).\n",
			config.name, config.type, config.buffer_size, config.pipe_size);
              Log(LOG_WARNING, "WARN ( %s/%s ): Increase values or look for plugin_buffer_size, plugin_pipe_size in CONFIG-KEYS document.\n\n",
			config.name, config.type);
            }

	    rg->ptr = (rg->base + status->last_buf_off);
            seq = ((struct ch_buf_hdr *)rg->ptr)->seq;
          }
        }

        pollagain = FALSE;
        memcpy(pipebuf, rg->ptr, bufsz);
        rg->ptr += bufsz;
      }
#ifdef WITH_ZMQ
      else if (config.pipe_zmq) {
	ret = p_zmq_plugin_pipe_recv(zmq_host, pipebuf, config.buffer_size);
	if (ret > 0) {
	  if (seq && (((struct ch_buf_hdr *)pipebuf)->seq != ((seq + 1) % MAX_SEQNUM))) {
	    Log(LOG_WARNING, "WARN ( %s/%s ): Missing data detected. Sequence received=%u expected=%u\n",
		config.name, config.type, ((struct ch_buf_hdr *)pipebuf)->seq, ((seq + 1) % MAX_SEQNUM));
	  }

	  seq = ((struct ch_buf_hdr *)pipebuf)->seq;
	}
	else goto poll_again;
      }
#endif

      data = (struct pkt_data *) (pipebuf+sizeof(struct ch_buf_hdr));

      if (config.debug_internal_msg)
        Log(LOG_DEBUG, "DEBUG ( %s/%s ): buffer received cpid=%u len=%llu seq=%u num_entries=%u\n",
                config.name, config.type, core_pid, ((struct ch_buf_hdr *)pipebuf)->len,
                seq, ((struct ch_buf_hdr *)pipebuf)->num);

      if (!config.pipe_check_core_pid || ((struct ch_buf_hdr *)pipebuf)->core_pid == core_pid) {
      while (((struct ch_buf_hdr *)pipebuf)->num > 0) {
        for (num = 0; primptrs_funcs[num]; num++)
          (*primptrs_funcs[num])((u_char *)data, &extras, &prim_ptrs);

	for (num = 0; net_funcs[num]; num++)
	  (*net_funcs[num])(&nt, &nc, &data->primitives, prim_ptrs.pbgp, &nfd);

	if (config.ports_file) {
          if (!pt.table[data->primitives.src_port]) data->primitives.src_port = 0;
          if (!pt.table[data->primitives.dst_port]) data->primitives.dst_port = 0;
        }

        prim_ptrs.data = data;
        (*insert_func)(&prim_ptrs, &idata);

	((struct ch_buf_hdr *)pipebuf)->num--;
        if (((struct ch_buf_hdr *)pipebuf)->num) {
          dataptr = (unsigned char *) data;
          if (!prim_ptrs.vlen_next_off) dataptr += datasize;
          else dataptr += prim_ptrs.vlen_next_off;
          data = (struct pkt_data *) dataptr;
	}
      }
      }

      recv_budget++;
      goto read_data;
    }
  }
}

void init_amqp_host() {
  p_amqp_init_host(&amqpp_amqp_host);
  p_amqp_set_user(&amqpp_amqp_host, config.sql_user);
  p_amqp_set_passwd(&amqpp_amqp_host, config.sql_passwd);
  p_amqp_set_exchange(&amqpp_amqp_host, config.sql_db);
  p_amqp_set_routing_key(&amqpp_amqp_host, config.sql_table);
  p_amqp_set_exchange_type(&amqpp_amqp_host, config.amqp_exchange_type);
  p_amqp_set_host(&amqpp_amqp_host, config.sql_host);
  p_amqp_set_vhost(&amqpp_amqp_host, config.amqp_vhost);
  p_amqp_set_persistent_msg(&amqpp_amqp_host, config.amqp_persistent_msg);
  p_amqp_set_frame_max(&amqpp_amqp_host, config.amqp_frame_max);
  p_amqp_set_content_type_json(&amqpp_amqp_host);
  p_amqp_init_routing_key_rr(&amqpp_amqp_host);
  p_amqp_set_routing_key_rr(&amqpp_amqp_host, config.amqp_routing_key_rr);
}

void amqp_cache_purge(struct chained_cache *queue[], int index, int safe_action)
{
  struct pkt_primitives *data = NULL;
  struct pkt_bgp_primitives *pbgp = NULL;
  struct pkt_nat_primitives *pnat = NULL;
  struct pkt_mpls_primitives *pmpls = NULL;
  struct pkt_tunnel_primitives *ptun = NULL;
  char *pcust = NULL;
  struct pkt_vlen_hdr_primitives *pvlen = NULL;
  struct pkt_bgp_primitives empty_pbgp;
  struct pkt_nat_primitives empty_pnat;
  struct pkt_mpls_primitives empty_pmpls;
  struct pkt_tunnel_primitives empty_ptun;
  char *empty_pcust = NULL;
  char src_mac[18], dst_mac[18], src_host[INET6_ADDRSTRLEN], dst_host[INET6_ADDRSTRLEN], ip_address[INET6_ADDRSTRLEN];
  char rd_str[SRVBUFLEN], misc_str[SRVBUFLEN], dyn_amqp_routing_key[SRVBUFLEN], *orig_amqp_routing_key = NULL;
  char tmpbuf[SRVBUFLEN];
  int i, j, stop, batch_idx, is_routing_key_dyn = FALSE, qn = 0, ret, saved_index = index;
  int mv_num = 0, mv_num_save = 0;
  time_t start, duration;
  struct primitives_ptrs prim_ptrs;
  struct pkt_data dummy_data;
  pid_t writer_pid = getpid();

  char *json_buf = NULL;
  int json_buf_off = 0;

#ifdef WITH_AVRO
  avro_writer_t avro_writer;
  char *avro_buf = NULL;
  int avro_buffer_full = FALSE;
#endif

  /* setting some defaults */
  if (!config.sql_host) config.sql_host = default_amqp_host;
  if (!config.sql_db) config.sql_db = default_amqp_exchange;
  if (!config.amqp_exchange_type) config.amqp_exchange_type = default_amqp_exchange_type;
  if (!config.amqp_vhost) config.amqp_vhost = default_amqp_vhost;

  if (!config.sql_table) config.sql_table = default_amqp_routing_key;
  else {
    if (strchr(config.sql_table, '$')) {
      is_routing_key_dyn = TRUE;
      orig_amqp_routing_key = config.sql_table;
      config.sql_table = dyn_amqp_routing_key;
    }
  }
  if (config.amqp_routing_key_rr) {
    orig_amqp_routing_key = config.sql_table;
    config.sql_table = dyn_amqp_routing_key;
  }

  init_amqp_host();
  ret = p_amqp_connect_to_publish_ssl(&amqpp_amqp_host);
  if (ret) {
    init_amqp_host();
    ret = p_amqp_connect_to_publish(&amqpp_amqp_host);
    if (ret) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Can't connect to RabbitMQ server (%s) via SSL or standard socket. Exiting.\n", config.name, config.type, config.sql_host);
      return;
    }
    else { 
      Log(LOG_INFO, "INFO ( %s/%s ): Connected to RabbitMQ server(%s) via standard socket.\n", config.name, config.type, config.sql_host);
    }
  } else {
    Log(LOG_INFO, "INFO ( %s/%s ): Connected to RabbitMQ server(%s) via SSL socket.\n", config.name, config.type, config.sql_host);
  }

  for (j = 0, stop = 0; (!stop) && P_preprocess_funcs[j]; j++)
    stop = P_preprocess_funcs[j](queue, &index, j);

  Log(LOG_INFO, "INFO ( %s/%s ): *** Purging cache - START (PID: %u) ***\n", config.name, config.type, writer_pid);
  start = time(NULL);

  collapse_flows(queue, index);
  purge_flows();

  if (config.what_to_count & COUNT_CLASS) {
    url_entries_purge(config.what_to_count_2, pvlen);
  }

  p_amqp_close(&amqpp_amqp_host, FALSE);

  Log(LOG_INFO, "INFO ( %s/%s ): *** Purging cache - END (PID: %u, QN: %u/%u, ET: %u) ***\n",
		config.name, config.type, writer_pid, qn, saved_index, duration);

  if (config.sql_trigger_exec && !safe_action) P_trigger_exec(config.sql_trigger_exec); 

  if (empty_pcust) free(empty_pcust);

  if (json_buf) free(json_buf);

#ifdef WITH_AVRO
  if (avro_buf) free(avro_buf);
#endif
}

#ifdef WITH_AVRO
void amqp_avro_schema_purge(char *avro_schema_str)
{
  struct p_amqp_host amqp_avro_schema_host;
  int ret;

  if (!avro_schema_str || !config.amqp_avro_schema_routing_key) return;

  /* setting some defaults */
  if (!config.sql_host) config.sql_host = default_amqp_host;
  if (!config.sql_db) config.sql_db = default_amqp_exchange;
  if (!config.amqp_exchange_type) config.amqp_exchange_type = default_amqp_exchange_type;
  if (!config.amqp_vhost) config.amqp_vhost = default_amqp_vhost;

  p_amqp_init_host(&amqp_avro_schema_host);
  p_amqp_set_user(&amqp_avro_schema_host, config.sql_user);
  p_amqp_set_passwd(&amqp_avro_schema_host, config.sql_passwd);
  p_amqp_set_exchange(&amqp_avro_schema_host, config.sql_db);
  p_amqp_set_routing_key(&amqp_avro_schema_host, config.amqp_avro_schema_routing_key);
  p_amqp_set_exchange_type(&amqp_avro_schema_host, config.amqp_exchange_type);
  p_amqp_set_host(&amqp_avro_schema_host, config.sql_host);
  p_amqp_set_vhost(&amqp_avro_schema_host, config.amqp_vhost);
  p_amqp_set_persistent_msg(&amqp_avro_schema_host, config.amqp_persistent_msg);
  p_amqp_set_frame_max(&amqp_avro_schema_host, config.amqp_frame_max);
  p_amqp_set_content_type_json(&amqp_avro_schema_host);

  ret = p_amqp_connect_to_publish(&amqp_avro_schema_host);
  if (ret) return;

  ret = p_amqp_publish_string(&amqp_avro_schema_host, avro_schema_str);

  p_amqp_close(&amqp_avro_schema_host, FALSE);
}
#endif
