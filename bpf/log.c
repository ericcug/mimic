#include "main.h"

void log_any(enum log_level level, enum log_type type, union log_info* info) {
  if (unlikely(!info)) return;
  if (log_verbosity < level) return;
  struct rb_item* item = bpf_ringbuf_reserve(&mimic_rb, sizeof(*item), 0);
  if (unlikely(!item)) return;
  item->type = RB_ITEM_LOG_EVENT;
  item->log_event = (struct log_event){.level = level, .type = type};
  item->log_event.info = *info;
  bpf_ringbuf_submit(item, 0);
  return;
}

// Log general connection information
void log_conn(enum log_type type, struct conn_tuple* conn) {
  if (unlikely(!conn || !LOG_ALLOW_INFO)) return;
  log_any(LOG_INFO, type, &(union log_info){.conn = *conn});
}

// Log TCP packet trace
void log_tcp(bool recv, struct conn_tuple* conn, struct tcphdr* tcp, __u16 len) {
  if (likely(!conn || !LOG_ALLOW_TRACE)) return;
  union log_info info = {
    .conn = *conn,
    .len = len,
    .flags = ntohl(tcp_flag_word(tcp)) >> 16,
    .seq = htonl(tcp->seq),
    .ack_seq = htonl(tcp->ack_seq),
  };
  return log_any(LOG_TRACE, recv ? LOG_PKT_RECV_TCP : LOG_PKT_SEND_TCP, &info);
}

// Warn about connection destruction
void log_destroy(struct conn_tuple* conn, enum destroy_type type, __u32 cooldown) {
  if (unlikely(!conn || !LOG_ALLOW_WARN)) return;
  log_any(LOG_WARN, LOG_CONN_DESTROY,
          &(union log_info){.conn = *conn, .destroy_type = type, .cooldown = cooldown});
}