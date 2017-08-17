

/**
 * Struct for ethernet Auto-discovery route
 */
typedef struct ethernet_ad_route {
  route_distinguisher rd;
  ethernet_segment_identifier eth_seg_iden;
  char ethernet_tag_id_hex[4];
  int mpls_label;
} ethernet_ad_route;

/**
 * Struct is used for evpn
 */
typedef struct evpn_tuple {
  uint8_t route_type;
  uint8_t length;
  struct route_specific {
    ethernet_ad_route eth_ad_route;
    mac_ip_advertisement_route mac_ip_adv_route;
    inclusive_multicast_ethernet_tag_route incl_multicast_eth_tag_route;
    ethernet_segment_route eth_segment_route;
  } route_type_specific;
} evpn_tuple;

/**
 * Node (local and remote) common fields
 */
typedef struct node_descriptor {
  uint16_t type;
  uint16_t len;
  uint32_t asn;             ///< BGP ASN
  uint32_t bgp_ls_id;       ///< BGP-LS Identifier
  uint8_t igp_router_id[8]; ///< IGP router ID
  uint8_t ospf_area_Id[4];  ///< OSPF area ID
  uint32_t
    bgp_router_id; ///< BGP router ID (draft-ietf-idr-bgpls-segment-routing-epe)
  uint8_t hash_bin[16]; ///< binary hash for node descriptor
} node_descriptor;

/**
 * Link Descriptor common fields
 */
typedef struct link_descriptor {
  uint16_t type;
  uint16_t len;
  uint32_t local_id;     ///< Link Local ID
  uint32_t remote_id;    ///< Link Remote ID
  uint8_t intf_addr[16]; ///< Interface binary address
  uint8_t nei_addr[16];  ///< Neighbor binary address
  uint32_t mt_id;        ///< Multi-Topology ID
  int is_ipv4;           ///< True if IPv4, false if IPv6
} link_descriptor;

/**
 * Prefix descriptor common fields
 */
typedef struct prefix_descriptor {
  uint16_t type;
  uint16_t len;
  char ospf_route_type[32]; ///< OSPF Route type in string form for DB enum
  uint32_t mt_id;           ///< Multi-Topology ID
  uint8_t prefix[16];       ///< Prefix binary address
  uint8_t prefix_bcast[16]; ///< Prefix broadcast/ending binary address
  uint8_t prefix_len;       ///< Length of prefix in bits
} prefix_descriptor;

typedef struct mp_reach_ls {
  uint16_t nlri_type;
  uint16_t nlri_len;
  uint8_t proto_id;
  uint64_t id;
  union nlri_ls {
    struct node_nlri {
      uint16_t type;
      uint16_t len;
      uint16_t count_local_nodes;
      node_descriptor *local_nodes;
    } node_nlri;

    struct link_nlri {
      uint16_t type;
      uint16_t len;
      uint16_t count_local_nodes;
      node_descriptor *local_nodes;
      uint16_t count_remote_nodes;
      node_descriptor *remote_nodes;
      uint16_t count_link_desc;
      link_descriptor *link_desc;
    } link_nlri;

    struct prefix_nlri_ipv4_ipv6 {
      uint16_t type;
      uint16_t len;
      uint16_t count_local_nodes;
      node_descriptor *local_nodes;
      uint16_t count_prefix_desc;
      prefix_descriptor *prefix_desc;
    } prefix_nlri_ipv4_ipv6;
  } nlri_ls;
} mp_reach_ls;

typedef struct link_peer_epe_node_sid {
  int L_flag;
  int V_flag;
  uint32_t sid_3;
  uint32_t sid_4;
  char ip_raw[16];
} link_peer_epe_node_sid;

typedef struct bgp_link_state_attrs {
  uint16_t type;
  uint16_t len;
  union node_attr {
    uint8_t node_flag_bits;
    uint8_t node_ipv4_router_id_local[4];
    uint8_t node_ipv6_router_id_local[16];
    uint8_t node_isis_area_id[8];
    uint8_t node_name[256];
    uint8_t mt_id[256];
  } node;
  union link_attr {
    uint8_t link_admin_group[4];
    uint32_t link_igp_metric;
    uint8_t link_ipv4_router_id_remote[4];
    uint8_t link_ipv6_router_id_remote[4];
    int32_t link_max_link_bw;
    int32_t link_max_resv_bw;
    char link_name[256];
    uint32_t link_te_def_metric;
    int32_t link_unresv_bw[8];
    link_peer_epe_node_sid link_peer_epe_sid;
  } link;
  union prefix_attr {
    uint32_t prefix_prefix_metric;
    uint32_t prefix_route_tag;
  } prefix;
} bgp_link_state_attrs;
