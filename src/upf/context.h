/*
 * Copyright (C) 2019-2023 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef UPF_CONTEXT_H
#define UPF_CONTEXT_H

#include "upf-config.h"

#if HAVE_NET_IF_H
#include <net/if.h>
#endif

#include "ogs-gtp.h"
#include "ogs-pfcp.h"
#include "ogs-app.h"

#include "ipfw/ogs-ipfw.h"

#include "timer.h"
#include "upf-sm.h"
#include "metrics.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int __upf_log_domain;

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __upf_log_domain

struct upf_route_trie_node;

typedef struct upf_context_s {
    ogs_hash_t *upf_n4_seid_hash;   /* hash table (UPF-N4-SEID) */
    ogs_hash_t *smf_n4_seid_hash;   /* hash table (SMF-N4-SEID) */
    ogs_hash_t *smf_n4_f_seid_hash; /* hash table (SMF-N4-F-SEID) */
    ogs_hash_t *ipv4_hash;  /* hash table (IPv4 Address) */
    ogs_hash_t *ipv6_hash;  /* hash table (IPv6 Address) */
    ogs_hash_t *eth_mac_hash;   /* hash table (UE MAC, Ethernet PDU) */

    /* IPv4 framed routes trie */
    struct upf_route_trie_node *ipv4_framed_routes;
    /* IPv6 framed routes trie */
    struct upf_route_trie_node *ipv6_framed_routes;

    ogs_list_t sess_list;
} upf_context_t;

/* trie mapping from IP framed routes to session. */
struct upf_route_trie_node {
    struct upf_route_trie_node *left;
    struct upf_route_trie_node *right;
    upf_sess_t *sess;
};

/* A device MAC address learned on an Ethernet PDU session.
 *
 * One session may serve several devices (5G-LAN: a LAN behind the UE),
 * so MACs are kept as a per-session list. The mac[] array is also the
 * key storage for upf_context_t.eth_mac_hash. */
#define UPF_MAX_NUM_OF_ETH_MAC 16

typedef struct upf_eth_mac_s {
    ogs_lnode_t     lnode;      /* member of upf_sess_t.eth_mac_list */
    uint8_t         mac[6];     /* key storage for eth_mac_hash */
    upf_sess_t      *sess;
} upf_eth_mac_t;

/* Accounting: */
typedef struct upf_sess_urr_acc_s {
    bool reporting_enabled;
    ogs_timer_t *t_validity_time; /* Quota Validity Time expiration handler */
    ogs_timer_t *t_time_quota; /* Time Quota expiration handler */
    ogs_timer_t *t_time_threshold; /* Time Threshold expiration handler */
    uint32_t time_start; /* When t_time_* started */
    ogs_pfcp_urr_ur_seqn_t report_seqn; /* Next seqn to use when reporting */
    uint64_t total_octets;
    uint64_t ul_octets;
    uint64_t dl_octets;
    uint64_t total_pkts;
    uint64_t ul_pkts;
    uint64_t dl_pkts;
    ogs_time_t time_of_first_packet;
    ogs_time_t time_of_last_packet;
    /* Snapshot of measurement when last report was sent: */
    struct {
        uint64_t total_octets;
        uint64_t ul_octets;
        uint64_t dl_octets;
        uint64_t total_pkts;
        uint64_t ul_pkts;
        uint64_t dl_pkts;
        ogs_time_t timestamp;
    } last_report;
} upf_sess_urr_acc_t;

#define UPF_SESS(pfcp_sess) ogs_container_of(pfcp_sess, upf_sess_t, pfcp)
typedef struct upf_sess_s {
    ogs_lnode_t     lnode;
    ogs_pool_id_t   id;
    ogs_pool_id_t   *upf_n4_seid_node;  /* A node of UPF-N4-SEID */

    ogs_pfcp_sess_t pfcp;

    uint64_t        upf_n4_seid;        /* UPF SEID is derived from NODE */
    struct {
        uint64_t    seid;
        ogs_ip_t    ip;
    } smf_n4_f_seid;                    /* SMF SEID is received from Peer */

    /* APN Configuration */
    ogs_pfcp_ue_ip_t *ipv4;
    ogs_pfcp_ue_ip_t *ipv6;

    /* Ethernet PDU session (5GS PDU session type 5):
     * no UE IP address; raw L2 bridging between GTP-U and a TAP device */
    bool            ethernet;
    ogs_pfcp_dev_t  *eth_dev;       /* TAP device used for bridging */
    ogs_list_t      eth_mac_list;   /* learned device MACs (upf_eth_mac_t) */

    ogs_ipsubnet_t   *ipv4_framed_routes;
    ogs_ipsubnet_t   *ipv6_framed_routes;

    char            *gx_sid;            /* Gx Session ID */
    ogs_pfcp_node_t *pfcp_node;

    /* Accounting: */
    upf_sess_urr_acc_t urr_acc[OGS_MAX_NUM_OF_URR]; /* FIXME: This probably needs to be mved to a hashtable or alike */
    char            *apn_dnn;            /* APN/DNN Item */
} upf_sess_t;

void upf_context_init(void);
void upf_context_final(void);
upf_context_t *upf_self(void);

int upf_context_parse_config(void);

upf_sess_t *upf_sess_add_by_message(ogs_pfcp_message_t *message);

upf_sess_t *upf_sess_add(ogs_pfcp_f_seid_t *f_seid);
int upf_sess_remove(upf_sess_t *sess);
void upf_sess_remove_all(void);
upf_sess_t *upf_sess_find_by_smf_n4_seid(uint64_t seid);
upf_sess_t *upf_sess_find_by_smf_n4_f_seid(ogs_pfcp_f_seid_t *f_seid);
upf_sess_t *upf_sess_find_by_upf_n4_seid(uint64_t seid);
upf_sess_t *upf_sess_find_by_ipv4(uint32_t addr);
upf_sess_t *upf_sess_find_by_ipv6(uint32_t *addr6);
upf_sess_t *upf_sess_find_by_eth_mac(const uint8_t *mac);
void upf_sess_eth_mac_learn(upf_sess_t *sess, const uint8_t *mac);
upf_sess_t *upf_sess_find_by_id(ogs_pool_id_t id);

uint8_t upf_sess_set_ue_ip(upf_sess_t *sess,
        uint8_t session_type, ogs_pfcp_pdr_t *pdr);
uint8_t upf_sess_set_ue_ipv4_framed_routes(upf_sess_t *sess,
        char *framed_routes[]);
uint8_t upf_sess_set_ue_ipv6_framed_routes(upf_sess_t *sess,
        char *framed_routes[]);

void upf_sess_urr_acc_add(upf_sess_t *sess, ogs_pfcp_urr_t *urr, size_t size, bool is_uplink);
void upf_sess_urr_acc_fill_usage_report(upf_sess_t *sess, const ogs_pfcp_urr_t *urr,
                                        ogs_pfcp_user_plane_report_t *report, unsigned int idx);
void upf_sess_urr_acc_snapshot(upf_sess_t *sess, ogs_pfcp_urr_t *urr);
void upf_sess_urr_acc_timers_setup(upf_sess_t *sess, ogs_pfcp_urr_t *urr);

#ifdef __cplusplus
}
#endif

#endif /* UPF_CONTEXT_H */
