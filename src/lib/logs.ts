import { hex, parseCidr, intToIp } from './net';
import { isGcm, type Hash, type P1Enc, type P2Enc, type Site } from './types';

export type LogEvent =
  | 'start'
  | 'respond'
  | 'timeout'
  | 'unknown_peer'
  | 'version'
  | 'mode'
  | 'p1_reject'
  | 'p1_rejected'
  | 'nat'
  | 'psk_fail'
  | 'auth_rejected'
  | 'id_fail'
  | 'p1_up'
  | 'p2_reject'
  | 'p2_rejected'
  | 'ts_reject'
  | 'ts_rejected'
  | 'p2_up';

export const ERROR_EVENTS = new Set<LogEvent>([
  'timeout', 'unknown_peer', 'version', 'mode', 'p1_reject', 'p1_rejected', 'psk_fail',
  'auth_rejected', 'id_fail', 'p2_reject', 'p2_rejected', 'ts_reject', 'ts_rejected',
]);

export interface LogCtx {
  self: Site;
  other: Site;
  local: string; // own interface address
  remote: string; // peer address as this device sees it
  tn: string; // tunnel name
  T: string; // peer token
  v2: boolean; // exchange in use
  main: boolean;
  init: boolean; // this device is the initiator
  stage: 'sa' | 'auth';
  port: number;
  selL: string; // own selectors
  selR: string;
  pL: string; // selectors proposed by the peer (its local / its remote)
  pR: string;
  myId: string;
  idSeen: string; // identity the peer presented
  idWant: string; // identity this device expects
  seed: string;
}

/* ---------- algorithm naming shared by several platforms ---------- */

const ENC_IANA: Record<P1Enc | P2Enc, string> = {
  des: 'DES_CBC',
  '3des': '3DES_CBC',
  aes128: 'AES_CBC_128',
  aes192: 'AES_CBC_192',
  aes256: 'AES_CBC_256',
  aes128gcm: 'AES_GCM_16_128',
  aes192gcm: 'AES_GCM_16_192',
  aes256gcm: 'AES_GCM_16_256',
  chacha20poly1305: 'CHACHA20_POLY1305',
  camellia128: 'CAMELLIA_CBC_128',
  camellia192: 'CAMELLIA_CBC_192',
  camellia256: 'CAMELLIA_CBC_256',
  blowfish: 'BLOWFISH_CBC',
  null: 'NULL',
};
const INTEG_IANA: Record<Hash, string> = {
  md5: 'HMAC_MD5_96',
  sha1: 'HMAC_SHA1_96',
  sha256: 'HMAC_SHA2_256_128',
  sha384: 'HMAC_SHA2_384_192',
  sha512: 'HMAC_SHA2_512_256',
  aesxcbc: 'AES_XCBC_96',
};
const PRF_IANA: Record<Hash, string> = {
  md5: 'PRF_HMAC_MD5',
  sha1: 'PRF_HMAC_SHA1',
  sha256: 'PRF_HMAC_SHA2_256',
  sha384: 'PRF_HMAC_SHA2_384',
  sha512: 'PRF_HMAC_SHA2_512',
  aesxcbc: 'PRF_AES128_XCBC',
};
const DH_IANA: Record<number, string> = {
  1: 'MODP_768',
  2: 'MODP_1024',
  5: 'MODP_1536',
  14: 'MODP_2048',
  15: 'MODP_3072',
  16: 'MODP_4096',
  18: 'MODP_8192',
  19: 'ECP_256',
  20: 'ECP_384',
  21: 'ECP_521',
  24: 'MODP_2048_256',
  31: 'CURVE_25519',
};

export const ikeSuite = (s: Site) =>
  `${ENC_IANA[s.p1Enc]}/${INTEG_IANA[s.p1Hash]}/${PRF_IANA[s.p1Hash]}/${DH_IANA[s.dh]}`;

export const espSuite = (s: Site, withPfs: boolean) =>
  [ENC_IANA[s.p2Enc], isGcm(s.p2Enc) ? null : INTEG_IANA[s.p2Auth], withPfs && s.pfs ? DH_IANA[s.pfs] : null, 'NO_EXT_SEQ']
    .filter(Boolean)
    .join('/');

const nm = (c: string) => {
  const p = parseCidr(c);
  return p ? `${p.network}/${p.mask}` : c;
};
const range = (c: string) => {
  const p = parseCidr(c);
  return p ? `${p.network}-${intToIp(p.net + p.size - 1)}` : c;
};

/* ---------- Cisco IOS-XE ---------- */

function ios(e: LogEvent, c: LogCtx): string[] {
  const s = '(SESSION ID = 1,SA ID = 1)';
  const st = c.stage === 'sa' ? 'MM_NO_STATE' : 'MM_KEY_EXCH';
  const abort = (m: string) => `%IKEV2-3-NEG_ABORT: Negotiation aborted due to ERROR: ${m}`;
  const modeFail = `%CRYPTO-6-IKMP_MODE_FAILURE: Processing of ${c.main ? 'Main' : 'Aggressive'} mode failed with peer at ${c.remote}`;
  switch (e) {
    case 'start':
      return c.v2
        ? [`IKEv2:${s}:Generating IKE_SA_INIT message`, `IKEv2:${s}:Sending Packet [To ${c.remote}:500/From ${c.local}:500/VRF i0:f0]`]
        : [`ISAKMP: (0):beginning ${c.main ? 'Main' : 'Aggressive'} Mode exchange`, `ISAKMP-PAK: (0):sending packet to ${c.remote} my_port 500 peer_port 500 (I) ${c.main ? 'MM' : 'AG'}_NO_STATE`];
    case 'respond':
      return c.v2
        ? [`IKEv2:Received Packet [From ${c.remote}:500/To ${c.local}:500/VRF i0:f0] IKE_SA_INIT Exchange REQUEST`]
        : [`ISAKMP-PAK: (0):received packet from ${c.remote} dport 500 sport 500 Global (N) NEW SA`, `ISAKMP: (0):found peer pre-shared key matching ${c.remote}`];
    case 'timeout':
      return c.v2
        ? [`IKEv2:${s}:Retransmitting packet`, `IKEv2-ERROR:${s}:: Maximum number of retransmissions reached`, abort('Maximum number of retransmissions reached')]
        : [`ISAKMP: (0):retransmitting phase 1 ${st}...`, `ISAKMP-ERROR: (0):deleting SA reason "Death by retransmission P1" state (I) ${st} (peer ${c.remote})`];
    case 'unknown_peer':
      return c.v2
        ? [`IKEv2-ERROR:${s}:: Failed to locate an item in the database`, abort('Failed to locate an item in the database')]
        : [`ISAKMP-ERROR: (0):No pre-shared key with ${c.remote}!`, `ISAKMP-ERROR: (0):No Cert or pre-shared address key.`, modeFail];
    case 'version':
      return c.self.ikeVersion === 'ikev1'
        ? [`IKEv2-ERROR:Couldn't find matching SA: no IKEv2 policy/profile for ${c.remote}`, abort('Failed to find a matching policy')]
        : [`ISAKMP-ERROR: (0):no offers accepted!`, modeFail];
    case 'mode':
      return [`%CRYPTO-5-IKMP_AG_MODE_DISABLED: Unable to initiate or respond to Aggressive Mode while disabled`, modeFail];
    case 'p1_reject':
      return c.v2
        ? [`IKEv2-ERROR:${s}:Expected Policies:: Failed to find a matching policy`, abort('Failed to find a matching policy')]
        : [`ISAKMP: (0):atts are not acceptable. Next payload is 0`, `ISAKMP-ERROR: (0):no offers accepted!`, `ISAKMP-ERROR: (0):phase 1 SA policy not acceptable! (local ${c.local} remote ${c.remote})`, modeFail];
    case 'p1_rejected':
      return c.v2
        ? [`IKEv2-ERROR:${s}:: Received no proposal chosen notify`, abort('Received no proposal chosen notify')]
        : [`ISAKMP: (0):Notify has no hash. Rejected.`, `%CRYPTO-6-IKMP_MODE_FAILURE: Processing of Informational mode failed with peer at ${c.remote}`];
    case 'nat':
      return c.v2
        ? [`IKEv2:${s}:Checking NAT discovery`, `IKEv2:${s}:NAT detected float to init port 4500, resp port 4500`]
        : [`ISAKMP-INFO: (1001):NAT found, the node ${c.self.behindNat ? 'inside' : 'outside'} NAT`, `ISAKMP: (1001):Setting UDP ENC peer struct, floating to port 4500`];
    case 'psk_fail':
      return c.v2
        ? [`IKEv2-ERROR:${s}:: Failed to authenticate the IKE SA`, abort('Auth exchange failed')]
        : [`%CRYPTO-4-IKMP_BAD_MESSAGE: IKE message from ${c.remote} failed its sanity check or is malformed`, `ISAKMP-ERROR: (1001):reserved not zero on ID payload!`];
    case 'auth_rejected':
      return c.v2
        ? [`IKEv2-ERROR:${s}:: Auth exchange failed`, abort('Auth exchange failed')]
        : [`ISAKMP: (1001):retransmitting phase 1 MM_KEY_EXCH...`, `ISAKMP-ERROR: (1001):deleting SA reason "Death by retransmission P1" state (I) MM_KEY_EXCH (peer ${c.remote})`];
    case 'id_fail':
      return c.v2
        ? [`IKEv2:${s}:Searching policy based on peer's identity '${c.idSeen}' of type 'IPv4 address'`, `IKEv2-ERROR:${s}:: Failed to locate an item in the database`, abort('Failed to locate an item in the database')]
        : [`ISAKMP: (1001):processing ID payload. peer id ${c.idSeen}`, `ISAKMP-ERROR: (1001):peer identity does not match any keyring or profile entry`];
    case 'p1_up':
      return c.v2
        ? [`IKEv2:${s}:IKEV2 SA created; inserting SA into database. SA lifetime timer (${c.self.p1Life} sec) started`, `%IKEV2-5-SA_UP: SA UP`]
        : [`ISAKMP: (1001):SA authentication status: authenticated`, `ISAKMP: (1001):Old State = IKE_${c.init ? 'I_MM6' : 'R_MM5'}  New State = IKE_P1_COMPLETE`];
    case 'p2_reject':
      return c.v2
        ? [`IPSEC(ipsec_process_proposal): transform proposal not supported for identity`, `IKEv2-ERROR:${s}:: Received Policies: : Failed to find a matching policy`]
        : [`IPSEC(ipsec_process_proposal): transform proposal not supported for identity: {esp-…}`, `ISAKMP-ERROR: (1001):IPSec policy invalidated proposal with error 256`, `ISAKMP-ERROR: (1001):phase 2 SA policy not acceptable! (local ${c.local} remote ${c.remote})`];
    case 'p2_rejected':
      return c.v2
        ? [`IKEv2-ERROR:${s}:: Received no proposal chosen notify`, `IKEv2-ERROR:${s}:: Create child exchange failed`]
        : [`ISAKMP: (1001): processing NOTIFY PROPOSAL_NOT_CHOSEN protocol 3`, `ISAKMP: (1001):deleting node -1682318358 error TRUE reason "Delete Larval"`];
    case 'ts_reject':
      return c.v2
        ? [`IKEv2:${s}:There was no IPSEC policy found for received TS`, `IKEv2:${s}:Sending TS unacceptable notify`]
        : [`IPSEC(ipsec_process_proposal): proxy identities not supported`, `ISAKMP-ERROR: (1001):IPSec policy invalidated proposal with error 32`, `ISAKMP-ERROR: (1001):phase 2 SA policy not acceptable! (local ${c.local} remote ${c.remote})`];
    case 'ts_rejected':
      return c.v2
        ? [`IKEv2:${s}:Received Notify TS_UNACCEPTABLE`, `IKEv2-ERROR:${s}:: Create child exchange failed`]
        : [`ISAKMP: (1001): processing NOTIFY INVALID_ID_INFO protocol 1`, `ISAKMP: (1001):deleting node -1682318358 error TRUE reason "Delete Larval"`];
    case 'p2_up':
      return [
        `IPSEC(create_sa): sa created, (sa) sa_dest= ${c.local}, sa_proto= 50, sa_spi= 0x${hex(c.seed + c.self.key, 8).toUpperCase()}`,
        `%CRYPTO-5-SESSION_STATUS: Crypto tunnel is UP.  Peer ${c.remote}:${c.port}       Id: ${c.idSeen}`,
      ];
  }
}

/* ---------- Cisco ASA ---------- */

function asa(e: LogEvent, c: LogCtx): string[] {
  const ip = `IP = ${c.remote}`;
  const g = `Group = ${c.remote}, IP = ${c.remote}`;
  const v2p = `Local:${c.local}:${c.stage === 'sa' ? 500 : c.port} Remote:${c.remote}:${c.stage === 'sa' ? 500 : c.port}`;
  const abort = (m: string, user = c.remote) => `%ASA-4-750003: ${v2p} Username:${user} IKEv2 Negotiation aborted due to ERROR: ${m}`;
  const w = c.stage === 'sa' ? 'MM_WAIT_MSG2' : 'MM_WAIT_MSG6';
  const fsm = `%ASA-7-715065: ${ip}, IKE MM Initiator FSM error history (struct &0x00007f3c${hex(c.seed, 6)})  <state>, <event>:  MM_DONE, EV_ERROR-->${w}, EV_RETRY-->${w}, EV_TIMEOUT`;
  const qm = `%ASA-3-713902: ${g}, QM FSM error (P2 struct &0x00007f3c${hex(c.seed, 6)}, mess id 0x${hex(c.seed + 'm', 8)})!`;
  switch (e) {
    case 'start':
      return c.v2
        ? [`%ASA-5-750001: ${v2p} Username:Unknown IKEv2 Received request to establish an IPsec tunnel; local traffic selector = Address Range: ${range(c.selL)} Protocol: 0 Port Range: 0-65535; remote traffic selector = Address Range: ${range(c.selR)} Protocol: 0 Port Range: 0-65535`]
        : [`%ASA-5-713041: ${ip}, IKE Initiator: New Phase 1, Intf inside, IKE Peer ${c.remote}  local Proxy Address ${nm(c.selL).split('/')[0]}, remote Proxy Address ${nm(c.selR).split('/')[0]},  Crypto map (OUTSIDE_MAP)`];
    case 'respond':
      return c.v2
        ? [`%ASA-7-750002: ${v2p} Username:Unknown IKEv2 Received a IKE_INIT_SA request`]
        : [`%ASA-7-713236: ${ip}, IKE_DECODE RECEIVED Message (msgid=0) with payloads : HDR + SA (1) + VENDOR (13) + NONE (0)`, `%ASA-7-715047: ${ip}, processing SA payload`];
    case 'timeout':
      return c.v2
        ? [abort('Maximum number of retransmissions reached', 'Unknown')]
        : [fsm, `%ASA-3-713902: ${ip}, Removing peer from peer table failed, no match!`, `%ASA-4-713903: ${ip}, Error: Unable to remove PeerTblEntry`];
    case 'unknown_peer':
      return c.v2
        ? [abort('Failed to locate an item in the database', 'Unknown')]
        : [`%ASA-4-713903: ${ip}, Can't find a valid tunnel group, aborting...!`, `%ASA-3-713902: ${ip}, Removing peer from peer table failed, no match!`];
    case 'version':
      return c.self.ikeVersion === 'ikev1'
        ? [abort('Failed to find a matching policy', 'Unknown')]
        : [`%ASA-4-713903: ${ip}, IKEv1 is not enabled for this peer's crypto map entry, dropping`, `%ASA-3-713902: ${ip}, Removing peer from peer table failed, no match!`];
    case 'mode':
      return [`%ASA-4-713903: ${ip}, Received ${c.main ? 'Main' : 'Aggressive'} Mode request but the crypto map entry requires ${c.self.mode} mode`, `%ASA-3-713902: ${ip}, Removing peer from peer table failed, no match!`];
    case 'p1_reject':
      return c.v2
        ? [abort('Failed to find a matching policy', 'Unknown')]
        : [`%ASA-7-713906: ${ip}, All SA proposals found unacceptable`, `%ASA-3-713048: ${ip}, Error processing payload: Payload ID: 1`, `%ASA-7-715065: ${ip}, IKE MM Responder FSM error history (struct &0x00007f3c${hex(c.seed, 6)})  <state>, <event>:  MM_DONE, EV_ERROR-->MM_START, EV_RCV_MSG-->MM_START, EV_START_MM`];
    case 'p1_rejected':
      return c.v2
        ? [abort('Received no proposal chosen notify', 'Unknown')]
        : [`%ASA-5-713904: ${ip}, Received an un-encrypted NO_PROPOSAL_CHOSEN notify message, dropping`, `%ASA-4-713903: ${ip}, Information Exchange processing failed`];
    case 'nat':
      return [`%ASA-6-713172: ${g}, Automatic NAT Detection Status:     Remote end ${c.other.behindNat ? '  IS  ' : 'is NOT'} behind a NAT device     This   end ${c.self.behindNat ? '  IS  ' : 'is NOT'} behind a NAT device`];
    case 'psk_fail':
      return c.v2
        ? [abort('Failed to authenticate the IKE SA')]
        : [`%ASA-4-713903: ${g}, ERROR, had problems decrypting packet, probably due to mismatched pre-shared key.  Aborting`];
    case 'auth_rejected':
      return c.v2 ? [abort('Auth exchange failed')] : [fsm, `%ASA-3-713902: ${g}, Removing peer from peer table failed, no match!`];
    case 'id_fail':
      return c.v2
        ? [abort('Failed to locate an item in the database')]
        : [`%ASA-4-713903: ${g}, Peer identity ${c.idSeen} failed ID validation`];
    case 'p1_up':
      return c.v2
        ? [`%ASA-5-750006: ${v2p} Username:${c.remote} IKEv2 SA UP. Reason: New Connection Established`]
        : [`%ASA-6-113009: AAA retrieved default group policy (DfltGrpPolicy) for user = ${c.remote}`, `%ASA-5-713119: ${g}, PHASE 1 COMPLETED`];
    case 'p2_reject':
      return c.v2
        ? [abort('Failed to find a matching policy'), `%ASA-4-752012: IKEv2 was unsuccessful at setting up a tunnel.  Map Tag = OUTSIDE_MAP.  Map Sequence Number = 10.`]
        : [`%ASA-5-713904: ${g}, All IPSec SA proposals found unacceptable!`, qm, `%ASA-3-713902: ${g}, Removing peer from correlator table failed, no match!`];
    case 'p2_rejected':
      return c.v2
        ? [abort('Received no proposal chosen notify'), `%ASA-4-752012: IKEv2 was unsuccessful at setting up a tunnel.  Map Tag = OUTSIDE_MAP.  Map Sequence Number = 10.`]
        : [`%ASA-5-713068: ${g}, Received non-routine Notify message: No proposal chosen (14)`, qm];
    case 'ts_reject':
      return c.v2
        ? [`%ASA-4-751022: ${v2p} Username:${c.remote} IKEv2 Tunnel rejected: Crypto Map Policy not found for remote traffic selector ${range(c.pL).replace('-', '/')}/0/65535/0 local traffic selector ${range(c.pR).replace('-', '/')}/0/65535/0!`]
        : [`%ASA-3-713061: ${g}, Rejecting IPSec tunnel: no matching crypto map entry for remote proxy ${nm(c.pL)}/0/0 local proxy ${nm(c.pR)}/0/0 on interface outside`, qm];
    case 'ts_rejected':
      return c.v2
        ? [abort('Received TS unacceptable notify'), `%ASA-4-752012: IKEv2 was unsuccessful at setting up a tunnel.  Map Tag = OUTSIDE_MAP.  Map Sequence Number = 10.`]
        : [`%ASA-5-713068: ${g}, Received non-routine Notify message: Invalid ID info (18)`, qm];
    case 'p2_up':
      return c.v2
        ? [`%ASA-5-752016: IKEv2 was successful at setting up a tunnel.  Map Tag = OUTSIDE_MAP. Map Sequence Number = 10.`]
        : [`%ASA-5-713049: ${g}, Security negotiation complete for LAN-to-LAN Group (${c.remote})  ${c.init ? 'Initiator' : 'Responder'}, Inbound SPI = 0x${hex(c.seed + c.self.key, 8)}, Outbound SPI = 0x${hex(c.seed + c.other.key, 8)}`, `%ASA-5-713120: ${g}, PHASE 2 COMPLETED (msgid=${hex(c.seed + 'm', 8)})`];
  }
}

/* ---------- FortiGate ---------- */

function fortigate(e: LogEvent, c: LogCtx): string[] {
  const p = `ike 0:${c.tn}:1423:`;
  const q = `ike 0:${c.tn}:1423:${c.tn}-p2:4711:`;
  const ck = hex(c.seed + 'i', 16);
  const ck2 = hex(c.seed + 'r', 16);
  const prop = (pre: string, s: Site) => [
    `${pre}   type=${c.v2 ? 'ENCR' : 'OAKLEY_ENCRYPT_ALG'}, val=${ENC_IANA[s.p1Enc]}`,
    `${pre}   type=${c.v2 ? 'INTEGR' : 'OAKLEY_HASH_ALG'}, val=${c.v2 ? INTEG_IANA[s.p1Hash] : PRF_IANA[s.p1Hash].replace('PRF_HMAC_', '')}`,
    `${pre}   type=${c.v2 ? 'DH_GROUP' : 'OAKLEY_GROUP'}, val=${DH_IANA[s.dh].replace('_', '')}`,
  ];
  const timeout = [`${p} negotiation timeout, deleting`, `ike 0:${c.tn}: connection expiring due to phase1 down`, `ike 0:${c.tn}: deleting`];
  switch (e) {
    case 'start':
      return c.v2
        ? [`ike 0:${c.tn}: auto-negotiate connection`, `${p} sent IKE msg (SA_INIT): ${c.local}:500->${c.remote}:500, len=432, id=${ck}/0000000000000000`]
        : [`${p} initiator: ${c.main ? 'main' : 'aggressive'} mode is sending 1st message...`, `${p} sent IKE msg (${c.main ? 'ident_i1send' : 'agg_i1send'}): ${c.local}:500->${c.remote}:500, len=296, id=${ck}/0000000000000000`];
    case 'respond':
      return [
        `ike 0: comes ${c.remote}:500->${c.local}:500,ifindex=5....`,
        c.v2 ? `ike 0: IKEv2 exchange=SA_INIT id=${ck}/0000000000000000 len=432` : `ike 0: IKEv1 exchange=${c.main ? 'Identity Protection' : 'Aggressive'} id=${ck}/0000000000000000 len=296`,
        c.v2 ? `${p} responder received SA_INIT msg` : `${p} responder: ${c.main ? 'main' : 'aggressive'} mode get 1st message...`,
      ];
    case 'timeout':
      return timeout;
    case 'unknown_peer':
    case 'version':
      return [
        `ike 0: comes ${c.remote}:500->${c.local}:500,ifindex=5....`,
        `ike 0: IKEv${c.v2 ? 2 : 1} exchange=${c.v2 ? 'SA_INIT' : 'Identity Protection'} id=${ck}/0000000000000000 len=${c.v2 ? 432 : 296}`,
        `ike 0:${ck}/0000000000000000:1423: no matching gateway for new request`,
        `ike Negotiate ISAKMP SA Error: ike 0:${ck}/0000000000000000:1423: no SA proposal chosen`,
      ];
    case 'mode':
      return [`${p} responder: received ${c.main ? 'main' : 'aggressive'} mode request, gateway is set to ${c.self.mode} mode`, `${p} negotiation failure`, `ike Negotiate ISAKMP SA Error: ${p} no SA proposal chosen`];
    case 'p1_reject':
      return [`${p} incoming proposal:`, ...prop(p, c.other), `${p} my proposal, gw ${c.tn}:`, ...prop(p, c.self), `${p} negotiation failure`, `ike Negotiate ISAKMP SA Error: ${p} no SA proposal chosen`];
    case 'p1_rejected':
      return [`${p} received notify type NO_PROPOSAL_CHOSEN`, `${p} schedule delete of IKE SA ${ck}/0000000000000000`];
    case 'nat':
      return [`${p} NAT detected:${c.self.behindNat ? ' ME' : ''}${c.other.behindNat ? ' PEER' : ''}`, `${p} NAT-T float port 4500`];
    case 'psk_fail':
      return c.v2
        ? [`${p} auth verify done`, `${p} PSK auth failed: probable pre-shared key mismatch`]
        : [`${p} probable pre-shared secret mismatch`, `ike Negotiate ISAKMP SA Error: ${p} probable pre-shared secret mismatch`];
    case 'auth_rejected':
      return c.v2 ? [`${p} received notify type AUTHENTICATION_FAILED`, `${p} schedule delete of IKE SA ${ck}/${ck2}`] : timeout;
    case 'id_fail':
      return [`${p} peer identifier IPV4_ADDR ${c.idSeen}`, `${p} peer ID verification failed`];
    case 'p1_up':
      return [`${p} established IKE SA ${ck}/${ck2}`, `${p} ISAKMP SA lifetime=${c.self.p1Life}`];
    case 'p2_reject':
      return [`${q} incoming proposal: ESP:${espSuite(c.other, !c.v2)}`, `${q} my proposal: ESP:${espSuite(c.self, !c.v2)}`, `${q} negotiation failure`, `ike Negotiate IPsec SA Error: ${q} no SA proposal chosen`];
    case 'p2_rejected':
      return [c.v2 ? `${p} received notify type NO_PROPOSAL_CHOSEN` : `${p} notify msg received: NO-PROPOSAL-CHOSEN`, `ike 0:${c.tn}:${c.tn}-p2: IPsec SA connect failed`];
    case 'ts_reject':
      return [
        `ike 0:${c.tn}:1423::4711: peer proposal is: peer:0:${range(c.pL)}:0, me:0:${range(c.pR)}:0`,
        `ike 0:${c.tn}:1423::4711: no matching phase2 found`,
        c.v2 ? `ike 0:${c.tn}:1423::4711: traffic selectors unacceptable` : `${p} error processing quick-mode message from ${c.remote} as error`,
      ];
    case 'ts_rejected':
      return [c.v2 ? `${p} received notify type TS_UNACCEPTABLE` : `${p} notify msg received: INVALID-ID-INFORMATION`, `ike 0:${c.tn}:${c.tn}-p2: IPsec SA connect failed`];
    case 'p2_up':
      return [`${q} added IPsec SA: SPIs=${hex(c.seed + c.self.key, 8)}/${hex(c.seed + c.other.key, 8)}`, `${q} sending SNMP tunnel UP trap`];
  }
}

/* ---------- Palo Alto PAN-OS ---------- */

function panos(e: LogEvent, c: LogCtx): string[] {
  const role = c.init ? 'initiator' : 'responder';
  const ck = `${hex(c.seed + 'i', 16)}:${c.stage === 'sa' ? '0000000000000000' : hex(c.seed + 'r', 16)}`;
  const sa = `${c.local}[${c.stage === 'sa' ? 500 : c.port}]-${c.remote}[${c.stage === 'sa' ? 500 : c.port}]`;
  const mode = c.main ? 'main' : 'aggressive';
  const spis = `0x${hex(c.seed + c.self.key, 8).toUpperCase()}/0x${hex(c.seed + c.other.key, 8).toUpperCase()}`;
  const p1fail = (why: string) =>
    c.v2
      ? `IKEv2 IKE SA negotiation is failed as ${role}, non-rekey. Failed SA: ${sa} SPI:${ck}. Due to ${why}.`
      : `IKE phase-1 negotiation is failed as ${role}, ${mode} mode. Failed SA: ${sa} cookie:${ck}. Due to ${why}.`;
  const p2fail = (why: string) =>
    c.v2
      ? `IKEv2 child SA negotiation is failed as ${role}, non-rekey. Failed SA: ${sa} message id:0x00000001. Due to ${why}.`
      : `IKE phase-2 negotiation is failed as ${role}, quick mode. Failed SA: ${sa} message id:0x${hex(c.seed + 'm', 8).toUpperCase()}. Due to ${why}.`;
  switch (e) {
    case 'start':
    case 'respond':
      return c.v2
        ? [`IKEv2 IKE SA negotiation is started as ${role}, non-rekey. Initiated SA: ${sa} SPI:${ck}.`]
        : [`IKE phase-1 negotiation is started as ${role}, ${mode} mode. Initiated SA: ${sa} cookie:${ck}.`];
    case 'timeout':
      return [p1fail('timeout')];
    case 'unknown_peer':
      return [`IKE ${c.v2 ? 'IKEv2 SA_INIT' : 'phase-1'} negotiation is failed. Couldn't find configuration for IKE phase-1 request for peer IP ${c.remote}[500].`];
    case 'version':
      return [`Received IKEv${c.v2 ? 2 : 1} request from ${c.remote}[500], but IKE gateway GW-${c.T} is configured ${c.self.ikeVersion === 'ikev2' ? 'IKEv2' : 'IKEv1'} only mode. Ignoring.`];
    case 'mode':
      return [`IKE phase-1 negotiation is failed. Received ${mode} mode request, IKE gateway GW-${c.T} requires ${c.self.mode} mode.`];
    case 'p1_reject':
      return [`${c.v2 ? 'IKEv2 IKE SA' : 'IKE phase-1'} negotiation is failed. no suitable proposal found in peer's SA payload.`, `IKE protocol notification message sent: NO-PROPOSAL-CHOSEN (14).`];
    case 'p1_rejected':
      return [`IKE protocol notification message received: NO-PROPOSAL-CHOSEN (14).`, p1fail('negotiation failure')];
    case 'nat':
      return [`NAT-T: NAT detected (${[c.self.behindNat && 'local', c.other.behindNat && 'peer'].filter(Boolean).join(' and ')} behind NAT). Floating IKE to UDP 4500.`];
    case 'psk_fail':
      return c.v2 ? [p1fail('authentication failure'), `IKE protocol notification message sent: AUTHENTICATION_FAILED (24).`] : [`IKE phase-1 negotiation is failed likely due to pre-shared key mismatch.`];
    case 'auth_rejected':
      return c.v2 ? [`IKE protocol notification message received: AUTHENTICATION_FAILED (24).`, p1fail('authentication failure')] : [p1fail('timeout')];
    case 'id_fail':
      return [`${c.v2 ? 'IKEv2 IKE SA' : 'IKE phase-1'} negotiation is failed. Peer's ID payload ${c.idSeen} (type ipaddr) does not match a configured IKE gateway.`];
    case 'p1_up':
      return c.v2
        ? [`IKEv2 IKE SA negotiation is succeeded as ${role}, non-rekey. Established SA: ${sa} SPI:${ck} lifetime ${c.self.p1Life} Sec.`]
        : [`IKE phase-1 negotiation is succeeded as ${role}, ${mode} mode. Established SA: ${sa} cookie:${ck} lifetime ${c.self.p1Life} Sec.`];
    case 'p2_reject':
      return c.v2
        ? [`IKEv2 child SA negotiation is failed. no suitable proposal found in peer's SA payload.`, `IKE protocol notification message sent: NO-PROPOSAL-CHOSEN (14).`]
        : [`IKE phase-2 negotiation failed when processing SA payload. no suitable proposal found in peer's SA payload.`];
    case 'p2_rejected':
      return [`IKE protocol notification message received: NO-PROPOSAL-CHOSEN (14).`, p2fail('negotiation failure')];
    case 'ts_reject':
      return c.v2
        ? [`IKEv2 child SA negotiation failed when processing traffic selector. cannot find matching IPSec tunnel for received traffic selector.`]
        : [`IKE phase-2 negotiation failed when processing proxy ID. cannot find matching phase-2 tunnel for received proxy ID. received local id: ${c.pR} type IPv4_subnet protocol 0 port 0, received remote id: ${c.pL} type IPv4_subnet protocol 0 port 0.`];
    case 'ts_rejected':
      return c.v2
        ? [`IKE protocol notification message received: received notify type TS_UNACCEPTABLE`, p2fail('TS_UNACCEPTABLE')]
        : [`IKE protocol notification message received: INVALID-ID-INFORMATION (18).`, p2fail('negotiation failure')];
    case 'p2_up':
      return [
        c.v2
          ? `IKEv2 child SA negotiation is succeeded as ${role}, non-rekey. Established SA: ${sa} message id:0x00000001, SPI:${spis}.`
          : `IKE phase-2 negotiation is succeeded as ${role}, quick mode. Established SA: ${sa} message id:0x${hex(c.seed + 'm', 8).toUpperCase()}, SPI:${spis}.`,
        `IPSec key installed. Installed SA: ${sa} SPI:${spis} lifetime ${c.self.p2Life} Sec lifesize unlimited.`,
      ];
  }
}

/* ---------- Juniper SRX ---------- */

function srx(e: LogEvent, c: LogCtx): string[] {
  const role = c.init ? 'Initiator' : 'Responder';
  const tail = (known = true) =>
    `IKE Version: ${c.v2 ? 2 : 1}, VPN: ${known ? `VPN-${c.T}` : 'Not-Available'}, Gateway: ${known ? `GW-${c.T}` : 'Not-Available'}, Local: ${c.local}/${c.stage === 'sa' ? 500 : c.port}, Remote: ${c.remote}/${c.stage === 'sa' ? 500 : c.port}, Local IKE-ID: ${known && c.stage !== 'sa' ? c.myId : 'Not-Available'}, Remote IKE-ID: ${known && c.stage !== 'sa' ? c.idSeen : 'Not-Available'}, VR-ID: 0: Role: ${role}`;
  const ike = (m: string, known = true) => `kmd[1787]: IKE negotiation failed with error: ${m}. ${tail(known)}`;
  const ipsec = (m: string) => `kmd[1787]: IPSec negotiation failed with error: ${m}. ${tail()}`;
  const sa = (dir: string, spi: string) =>
    `kmd[1787]: KMD_PM_SA_ESTABLISHED: Local gateway: ${c.local}, Remote gateway: ${c.remote}, Local ID: ipv4_subnet(any:0,[0..7]=${c.selL}), Remote ID: ipv4_subnet(any:0,[0..7]=${c.selR}), Direction: ${dir}, SPI: 0x${spi}, AUX-SPI: 0, Mode: Tunnel, Type: dynamic`;
  switch (e) {
    case 'start':
      return [`kmd[1787]: IKE negotiation initiated: Gateway: GW-${c.T}, Local: ${c.local}/500, Remote: ${c.remote}/500, IKE Version: ${c.v2 ? 2 : 1}`];
    case 'respond':
      return [`kmd[1787]: IKE request received: Gateway: GW-${c.T}, Local: ${c.local}/500, Remote: ${c.remote}/500, IKE Version: ${c.v2 ? 2 : 1}`];
    case 'timeout':
      return [ike('Timed out')];
    case 'unknown_peer':
    case 'version':
    case 'mode':
      return [ike('IKE gateway configuration lookup failed during negotiation', false)];
    case 'p1_reject':
    case 'p1_rejected':
      return [ike('No proposal chosen')];
    case 'nat':
      return [`kmd[1787]: NAT-T: ${c.self.behindNat ? 'local' : 'remote'} end is behind a NAT device, switching to UDP 4500 for GW-${c.T}`];
    case 'psk_fail':
      return [ike(c.v2 ? 'Authentication failed' : 'Invalid syntax')];
    case 'auth_rejected':
      return [ike(c.v2 ? 'Authentication failed' : 'Timed out')];
    case 'id_fail':
      return [`kmd[1787]: Remote IKE-ID ${c.idSeen} does not match configured remote-identity ${c.idWant} for GW-${c.T}`, ike('Authentication failed')];
    case 'p1_up':
      return [`kmd[1787]: IKE negotiation successfully completed. ${tail()}`];
    case 'p2_reject':
    case 'p2_rejected':
      return [ipsec('No proposal chosen')];
    case 'ts_reject':
      return [
        `kmd[1787]: KMD_VPN_TS_MISMATCH: Traffic-selector mismatch, vpn name: VPN-${c.T}, Peer Proposed traffic-selector local-ip: ipv4(${range(c.pR)}), Peer Proposed traffic-selector remote-ip: ipv4(${range(c.pL)})`,
        ipsec(c.v2 ? 'TS unacceptable' : 'No proposal chosen'),
      ];
    case 'ts_rejected':
      return [ipsec(c.v2 ? 'TS unacceptable' : 'Invalid ID information')];
    case 'p2_up':
      return [sa('inbound', hex(c.seed + c.self.key, 8)), sa('outbound', hex(c.seed + c.other.key, 8))];
  }
}

/* ---------- MikroTik RouterOS ---------- */

function mikrotik(e: LogEvent, c: LogCtx): string[] {
  const ck = hex(c.seed + 'i', 16);
  const ck2 = hex(c.seed + 'r', 16);
  const pair = `${c.local}[500]<=>${c.remote}[500]`;
  const kill = `ipsec,info killing ike2 SA: ${c.tn} ${c.local}[${c.port}]-${c.remote}[${c.port}] spi:${ck}:${ck2}`;
  switch (e) {
    case 'start':
      return c.v2 ? [`ipsec ike2 starting for: ${c.remote}`, `ipsec adding payload: SA, KE, NONCE, NOTIFY(NAT_DETECTION)`] : [`ipsec,info initiate new phase 1 (${c.main ? 'Identity Protection' : 'Aggressive'}): ${pair}`];
    case 'respond':
      return c.v2 ? [`ipsec ike2 request, exchange: SA_INIT:0 ${c.remote}[500] ${ck}:0000000000000000`] : [`ipsec,info respond new phase 1 (${c.main ? 'Identity Protection' : 'Aggressive'}): ${pair}`];
    case 'timeout':
      return c.v2
        ? [`ipsec ike2 ${c.stage === 'sa' ? 'init' : 'auth'} retransmit`, `ipsec ike2 ${c.stage === 'sa' ? 'init' : 'auth'} retransmit`, `ipsec,error ike2 ${c.stage === 'sa' ? 'init' : 'auth'} timeout: ${c.remote}`, kill]
        : [`ipsec,error phase1 negotiation failed due to time up ${pair} ${ck}:${c.stage === 'sa' ? '0000000000000000' : ck2}`];
    case 'unknown_peer':
    case 'version':
    case 'mode':
      return c.v2 ? [`ipsec,error no IKEv2 peer config for ${c.remote}`] : [`ipsec,error couldn't find configuration.`, `ipsec,error ${c.remote} failed to pre-process ph1 packet (side: 1, status 1).`];
    case 'p1_reject':
      return c.v2
        ? [`ipsec processing payload: SA`, `ipsec,error no proposal chosen`, `ipsec reply notify: NO_PROPOSAL_CHOSEN`]
        : [`ipsec,error no suitable proposal found.`, `ipsec,error ${c.remote} failed to get valid proposal.`, `ipsec,error ${c.remote} failed to pre-process ph1 packet (side: 1, status 1).`, `ipsec,error ${c.remote} phase1 negotiation failed.`];
    case 'p1_rejected':
      return c.v2 ? [`ipsec,error got fatal error: NO_PROPOSAL_CHOSEN`, kill] : [`ipsec,error ${c.remote} fatal NO-PROPOSAL-CHOSEN notify messsage, phase1 should be deleted.`];
    case 'nat':
      return [`ipsec NAT detected:${c.self.behindNat ? ' ME' : ''}${c.other.behindNat ? ' PEER' : ''}`, `ipsec NAT-T: ports changed to: ${c.remote}[4500]<->${c.local}[4500]`];
    case 'psk_fail':
      return c.v2 ? [`ipsec processing payload: AUTH`, `ipsec,error PSK auth failed for ${c.remote}`, `ipsec reply notify: AUTHENTICATION_FAILED`] : [`ipsec,error ${c.remote} parsing packet failed, possible cause: wrong password`];
    case 'auth_rejected':
      return c.v2 ? [`ipsec,error got fatal error: AUTHENTICATION_FAILED`, kill] : [`ipsec,error phase1 negotiation failed due to time up ${pair} ${ck}:${ck2}`];
    case 'id_fail':
      return [`ipsec,error identity not found for peer: ADDR4: ${c.idSeen}`, ...(c.v2 ? [`ipsec reply notify: AUTHENTICATION_FAILED`] : [])];
    case 'p1_up':
      return c.v2
        ? [`ipsec,info new ike2 SA (${c.init ? 'I' : 'R'}): ${c.tn} ${c.local}[${c.port}]-${c.remote}[${c.port}] spi:${ck}:${ck2}`, `ipsec,info,account peer authorized: ${c.tn} ${c.local}[${c.port}]-${c.remote}[${c.port}] spi:${ck}:${ck2}`]
        : [`ipsec,info ISAKMP-SA established ${c.local}[${c.port}]-${c.remote}[${c.port}] spi:${ck}:${ck2}`];
    case 'p2_reject':
      return c.v2
        ? [`ipsec,error no matching proposal found for child SA`, `ipsec reply notify: NO_PROPOSAL_CHOSEN`]
        : [`ipsec,error no suitable proposal found.`, `ipsec,error ${c.remote} failed to get proposal for responder.`, `ipsec,error ${c.remote} failed to pre-process ph2 packet.`];
    case 'p2_rejected':
      return c.v2 ? [`ipsec,error got error: NO_PROPOSAL_CHOSEN`] : [`ipsec,error ${c.remote} fatal NO-PROPOSAL-CHOSEN notify messsage, phase1 should be deleted.`];
    case 'ts_reject':
      return c.v2 ? [`ipsec,error no policy found/generated`, `ipsec reply notify: TS_UNACCEPTABLE`] : [`ipsec,error failed to get sainfo.`, `ipsec,error ${c.remote} failed to get sainfo.`, `ipsec,error ${c.remote} failed to pre-process ph2 packet.`];
    case 'ts_rejected':
      return c.v2 ? [`ipsec,error got error: TS_UNACCEPTABLE`] : [`ipsec,error ${c.remote} fatal INVALID-ID-INFORMATION notify messsage, phase1 should be deleted.`];
    case 'p2_up':
      return [
        `ipsec,info IPsec-SA established: ESP/Tunnel ${c.remote}[${c.port}]->${c.local}[${c.port}] spi=0x${hex(c.seed + c.self.key, 8)}`,
        `ipsec,info IPsec-SA established: ESP/Tunnel ${c.local}[${c.port}]->${c.remote}[${c.port}] spi=0x${hex(c.seed + c.other.key, 8)}`,
      ];
  }
}

/* ---------- strongSwan ---------- */

function strongswan(e: LogEvent, c: LogCtx): string[] {
  const cn = c.tn.toLowerCase();
  const t = c.init ? '09' : '11';
  const mid = c.stage === 'sa' ? 0 : 1;
  const retrans = c.v2
    ? [1, 2, 3, 4, 5].map((n) => `${t}[IKE] retransmit ${n} of request with message ID ${mid}`)
    : [1, 2, 3, 4, 5].map((n) => `${t}[IKE] sending retransmit ${n} of request message ID 0, seq ${c.stage === 'sa' ? 1 : 3}`);
  const giveUp = [...retrans, `${t}[IKE] giving up after 5 retransmits`, `${t}[IKE] establishing IKE_SA failed, peer not responding`];
  switch (e) {
    case 'start':
      return c.v2
        ? [`${t}[IKE] initiating IKE_SA ${cn}[1] to ${c.remote}`, `${t}[ENC] generating IKE_SA_INIT request 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) N(FRAG_SUP) N(HASH_ALG) N(REDIR_SUP) ]`, `${t}[NET] sending packet: from ${c.local}[500] to ${c.remote}[500] (432 bytes)`]
        : [`${t}[IKE] initiating ${c.main ? 'Main' : 'Aggressive'} Mode IKE_SA ${cn}[1] to ${c.remote}`, `${t}[ENC] generating ${c.main ? 'ID_PROT' : 'AGGRESSIVE'} request 0 [ SA ${c.main ? '' : 'KE No ID '}V V V V V ]`, `${t}[NET] sending packet: from ${c.local}[500] to ${c.remote}[500] (296 bytes)`];
    case 'respond':
      return c.v2
        ? [`${t}[NET] received packet: from ${c.remote}[500] to ${c.local}[500] (432 bytes)`, `${t}[ENC] parsed IKE_SA_INIT request 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) ]`, `${t}[IKE] ${c.remote} is initiating an IKE_SA`]
        : [`${t}[NET] received packet: from ${c.remote}[500] to ${c.local}[500] (296 bytes)`, `${t}[ENC] parsed ${c.main ? 'ID_PROT' : 'AGGRESSIVE'} request 0 [ SA ${c.main ? '' : 'KE No ID '}V V V V ]`, `${t}[IKE] ${c.remote} is initiating a ${c.main ? 'Main' : 'Aggressive'} Mode IKE_SA`];
    case 'timeout':
      return giveUp;
    case 'unknown_peer':
    case 'version':
    case 'mode':
      return [`${t}[NET] received packet: from ${c.remote}[500] to ${c.local}[500] (${c.v2 ? 432 : 296} bytes)`, `${t}[IKE] no IKE config found for ${c.local}...${c.remote}, sending NO_PROPOSAL_CHOSEN`];
    case 'p1_reject':
      return [
        `${t}[CFG] received proposals: IKE:${ikeSuite(c.other)}`,
        `${t}[CFG] configured proposals: IKE:${ikeSuite(c.self)}`,
        c.v2 ? `${t}[IKE] received proposals unacceptable` : `${t}[IKE] no proposal found`,
        c.v2 ? `${t}[ENC] generating IKE_SA_INIT response 0 [ N(NO_PROP) ]` : `${t}[ENC] generating INFORMATIONAL_V1 request 2284731092 [ N(NO_PROP) ]`,
      ];
    case 'p1_rejected':
      return c.v2
        ? [`${t}[ENC] parsed IKE_SA_INIT response 0 [ N(NO_PROP) ]`, `${t}[IKE] received NO_PROPOSAL_CHOSEN notify error`]
        : [`${t}[ENC] parsed INFORMATIONAL_V1 request 2284731092 [ N(NO_PROP) ]`, `${t}[IKE] received NO_PROPOSAL_CHOSEN error notify`];
    case 'nat':
      return [c.self.behindNat ? `${t}[IKE] local host is behind NAT, sending keep alives` : '', c.other.behindNat ? `${t}[IKE] remote host is behind NAT` : ''].filter(Boolean);
    case 'psk_fail':
      if (c.v2) return [`${t}[IKE] tried 1 shared key for '${c.myId}' - '${c.idSeen}', but MAC mismatched`, `${t}[ENC] generating IKE_AUTH response 1 [ N(AUTH_FAILED) ]`];
      if (c.init) return [`${t}[IKE] calculated HASH does not match HASH payload`];
      return [`${t}[ENC] invalid ID_V1 payload length, decryption failed?`, `${t}[ENC] could not decrypt payloads`, `${t}[IKE] message parsing failed`, `${t}[IKE] ID_PROT request with message ID 0 processing failed`];
    case 'auth_rejected':
      return c.v2 ? [`${t}[ENC] parsed IKE_AUTH response 1 [ N(AUTH_FAILED) ]`, `${t}[IKE] received AUTHENTICATION_FAILED notify error`] : giveUp;
    case 'id_fail':
      return c.init
        ? [`${t}[CFG] constraint check failed: identity '${c.idWant}' required`, `${t}[CFG] selected peer config '${cn}' unacceptable: constraint checking failed`, `${t}[CFG] no alternative config found`]
        : [`${t}[CFG] looking for peer configs matching ${c.local}[%any]...${c.remote}[${c.idSeen}]`, `${t}[CFG] no matching peer config found`, ...(c.v2 ? [`${t}[ENC] generating IKE_AUTH response 1 [ N(AUTH_FAILED) ]`] : [])];
    case 'p1_up':
      return [`${t}[IKE] IKE_SA ${cn}[1] established between ${c.local}[${c.myId}]...${c.remote}[${c.idSeen}]`, `${t}[IKE] scheduling ${c.v2 ? 'rekeying' : 'reauthentication'} in ${Math.round(c.self.p1Life * 0.9)}s`];
    case 'p2_reject':
      return [
        `${t}[CFG] received proposals: ESP:${espSuite(c.other, !c.v2)}`,
        `${t}[CFG] configured proposals: ESP:${espSuite(c.self, !c.v2)}`,
        c.v2 ? `${t}[IKE] no acceptable proposal found` : `${t}[IKE] no matching proposal found, sending NO_PROPOSAL_CHOSEN`,
        ...(c.v2 ? [`${t}[IKE] failed to establish CHILD_SA, keeping IKE_SA`] : []),
      ];
    case 'p2_rejected':
      return c.v2
        ? [`${t}[IKE] received NO_PROPOSAL_CHOSEN notify, no CHILD_SA built`, `${t}[IKE] failed to establish CHILD_SA, keeping IKE_SA`]
        : [`${t}[IKE] received NO_PROPOSAL_CHOSEN error notify`];
    case 'ts_reject':
      return c.v2
        ? [`${t}[IKE] traffic selectors ${c.pR} === ${c.pL} unacceptable`, `${t}[IKE] failed to establish CHILD_SA, keeping IKE_SA`, `${t}[ENC] generating IKE_AUTH response 1 [ IDr AUTH N(TS_UNACCEPT) ]`]
        : [`${t}[IKE] no matching CHILD_SA config found for ${c.pR} === ${c.pL}`, `${t}[ENC] generating INFORMATIONAL_V1 request 3179842211 [ HASH N(INVAL_ID) ]`];
    case 'ts_rejected':
      return c.v2
        ? [`${t}[IKE] received TS_UNACCEPTABLE notify, no CHILD_SA built`, `${t}[IKE] failed to establish CHILD_SA, keeping IKE_SA`]
        : [`${t}[IKE] received INVALID_ID_INFORMATION error notify`];
    case 'p2_up':
      return [`${t}[IKE] CHILD_SA net-net{1} established with SPIs ${hex(c.seed + c.self.key, 8)}_i ${hex(c.seed + c.other.key, 8)}_o and TS ${c.selL} === ${c.selR}`];
  }
}

/* ---------- Microsoft Azure VPN Gateway ---------- */

function azure(e: LogEvent, c: LogCtx): string[] {
  const conn = `con-${c.tn.toLowerCase()}`;
  const lng = `lng-${c.tn.toLowerCase()}`;
  const ep = `local ${c.local}:${c.stage === 'sa' ? 500 : c.port} <-> remote ${c.remote}:${c.stage === 'sa' ? 500 : c.port}`;
  const ike = (m: string) => `IKEDiagnosticLog [${ep}] connection ${conn}: ${m}`;
  const tun = (m: string) => `TunnelDiagnosticLog [${ep}] connection ${conn}: ${m}`;
  const timeout = [
    ike(`no response from remote endpoint ${c.remote}; retransmitting IKE message`),
    ike(`connection ${conn} remains in Connecting state; peer ${c.remote} is not responding on UDP ${c.stage === 'sa' ? 500 : c.port}`),
  ];
  switch (e) {
    case 'start':
      return [ike(`initiating IKEv${c.v2 ? 2 : 1} ${c.v2 ? 'IKE_SA_INIT' : c.main ? 'main mode' : 'aggressive mode'} to ${c.remote}`), ike(`sending proposal IKE:${ikeSuite(c.self)}`)];
    case 'respond':
      return [ike(`received IKEv${c.v2 ? 2 : 1} request from ${c.remote}`), ike(`matched local network gateway ${lng} for remote endpoint ${c.remote}`)];
    case 'timeout':
      return timeout;
    case 'unknown_peer':
      return [ike(`received packet from ${c.remote}, but no local network gateway or connection matches this remote endpoint`), ike('dropping IKE request; check gatewayIpAddress on the local network gateway')];
    case 'version':
      return [ike(`received IKEv${c.v2 ? 2 : 1} request, but connection ${conn} is configured for IKEv${c.self.ikeVersion === 'ikev2' ? 2 : 1} only`), ike('ignoring request; align the connection protocol on both gateways')];
    case 'mode':
      return [ike(`received ${c.main ? 'main' : 'aggressive'} mode request; Azure VPN Gateway does not negotiate this exchange mode for connection ${conn}`), ike('negotiation failed before proposal selection')];
    case 'p1_reject':
      return [`IKEDiagnosticLog [${ep}] received IKE proposal: IKE:${ikeSuite(c.other)}`, `IKEDiagnosticLog [${ep}] configured IKE policy: IKE:${ikeSuite(c.self)}`, ike('no matching IKE proposal on the connection; sending NO_PROPOSAL_CHOSEN')];
    case 'p1_rejected':
      return [ike('received NO_PROPOSAL_CHOSEN from remote endpoint'), ike('IKE SA negotiation failed; compare the connection IPsec policy with the on-prem phase 1 proposal')];
    case 'nat':
      return [ike(`NAT detected (${[c.self.behindNat && 'local', c.other.behindNat && 'remote'].filter(Boolean).join(' and ')} behind NAT); using UDP 4500 NAT-T encapsulation`)];
    case 'psk_fail':
      return [ike('IKE authentication failed; shared key verification failed for the connection'), ike('sending AUTHENTICATION_FAILED notify')];
    case 'auth_rejected':
      return c.v2 ? [ike('received AUTHENTICATION_FAILED from remote endpoint'), ike('IKE SA deleted; authentication did not complete')] : timeout;
    case 'id_fail':
      return [ike(`remote IKE ID ${c.idSeen} does not match expected endpoint identity ${c.idWant} for ${lng}`), ike('authentication failed; Azure expects the peer identity to match the local network gateway endpoint')];
    case 'p1_up':
      return [ike(`IKE SA established with remote ${c.remote}; rekey lifetime ${c.self.p1Life}s`)];
    case 'p2_reject':
      return [`IKEDiagnosticLog [${ep}] received IPsec proposal: ESP:${espSuite(c.other, !c.v2)}`, `IKEDiagnosticLog [${ep}] configured IPsec policy: ESP:${espSuite(c.self, !c.v2)}`, ike('no matching IPsec proposal; sending NO_PROPOSAL_CHOSEN')];
    case 'p2_rejected':
      return [ike('received NO_PROPOSAL_CHOSEN for IPsec SA'), tun('IPsec SA not installed; IKE SA remains available for retry')];
    case 'ts_reject':
      return [ike(`proposed traffic selectors local ${c.pR} remote ${c.pL} are not covered by VNet/local-network-gateway prefixes`), ike('traffic selector unacceptable; enable policy-based traffic selectors or align the prefixes')];
    case 'ts_rejected':
      return [ike('received TS_UNACCEPTABLE from remote endpoint'), tun('IPsec SA not installed for the requested prefixes')];
    case 'p2_up':
      return [tun(`IPsec SA installed; SPIs in 0x${hex(c.seed + c.self.key, 8)} out 0x${hex(c.seed + c.other.key, 8)}`), tun(`connection ${conn} state Connected for traffic selectors ${c.selL} <-> ${c.selR}`)];
  }
}

export function vendorLog(e: LogEvent, c: LogCtx): string[] {
  switch (c.self.vendor) {
    case 'cisco-ios': return ios(e, c);
    case 'cisco-asa': return asa(e, c);
    case 'fortigate': return fortigate(e, c);
    case 'paloalto': return panos(e, c);
    case 'juniper-srx': return srx(e, c);
    case 'mikrotik': return mikrotik(e, c);
    case 'strongswan': return strongswan(e, c);
    case 'azure': return azure(e, c);
  }
}
