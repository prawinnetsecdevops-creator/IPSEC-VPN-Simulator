import { isGcm, type Hash, type P1Enc, type P2Enc } from '../types';
import { FAULT, type Gen } from './common';

const AZ_IKE_ENC: Record<P1Enc, string> = {
  aes256gcm: 'GCMAES256',
  aes128gcm: 'GCMAES128',
  aes256: 'AES256',
  aes192: 'AES192',
  aes128: 'AES128',
  '3des': 'DES3',
  des: 'DES',
  chacha20poly1305: 'AES256',
  camellia256: 'AES256',
  camellia192: 'AES192',
  camellia128: 'AES128',
  blowfish: 'AES128',
};

const AZ_ESP_ENC: Record<P2Enc, string> = {
  aes256gcm: 'GCMAES256',
  aes192gcm: 'GCMAES192',
  aes128gcm: 'GCMAES128',
  aes256: 'AES256',
  aes192: 'AES192',
  aes128: 'AES128',
  '3des': 'DES3',
  des: 'DES',
  null: 'None',
  chacha20poly1305: 'AES256',
  camellia256: 'AES256',
  camellia192: 'AES192',
  camellia128: 'AES128',
  blowfish: 'AES128',
};

const AZ_IKE_INT: Record<Hash, string> = {
  sha384: 'SHA384',
  sha256: 'SHA256',
  sha1: 'SHA1',
  md5: 'MD5',
  sha512: 'SHA384',
  aesxcbc: 'SHA256',
};

const AZ_ESP_INT: Record<Hash, string> = {
  sha256: 'SHA256',
  sha1: 'SHA1',
  md5: 'MD5',
  sha384: 'SHA256',
  sha512: 'SHA256',
  aesxcbc: 'SHA256',
};

function azDh(group: number, pfs: boolean): string {
  if (group === 0) return 'None';
  if (group === 1) return pfs ? 'PFS1' : 'DHGroup1';
  if (group === 2) return pfs ? 'PFS2' : 'DHGroup2';
  if (group === 14) return pfs ? 'PFS14' : 'DHGroup14';
  if (group === 19) return 'ECP256';
  if (group === 20) return 'ECP384';
  if (group === 24) return pfs ? 'PFS24' : 'DHGroup24';
  return `<unsupported:DH group ${group}>`;
}

export function azureConfig(g: Gen): string {
  const { s } = g;
  const L: string[] = [
    `# ${g.title}`,
    '# Microsoft Azure VPN Gateway — Azure CLI script (Bash). Review resource names before running.',
    '# Prerequisite: an Azure Virtual Network Gateway already exists in a GatewaySubnet,',
    '# with a public IP. The Azure VNet prefix is the local network; the Local Network',
    '# Gateway below represents the on-prem peer and its prefixes.',
    '',
    'RESOURCE_GROUP="rg-network"',
    'LOCATION="eastus"',
    'VNET_GATEWAY="vgw-prod"                 # existing Azure VPN gateway',
    `AZURE_GATEWAY_PUBLIC_IP="${s.wanIp || '<azure-gateway-public-ip>'}"`,
    `LOCAL_GATEWAY="lng-${g.tn.toLowerCase()}"             # on-prem device as Azure sees it`,
    `CONNECTION="con-${g.tn.toLowerCase()}"`,
    `ONPREM_GATEWAY_IP="${g.peer}"`,
    `AZURE_VNET_PREFIX="${g.lan.cidr}"`,
    `ONPREM_PREFIX="${g.rlan.cidr}"`,
    '',
  ];

  if (s.behindNat)
    L.push(`# ${FAULT} Azure VPN Gateway is a public managed endpoint; do not model it behind NAT. Use AZURE_GATEWAY_PUBLIC_IP on the peer.`);
  if (g.localId)
    L.push(`# NOTE: Azure presents the gateway public IP as its IKE identity; custom local ID "${g.localId}" is not a managed-gateway setting.`);
  if (g.remoteId)
    L.push(`# NOTE: Azure expects the on-prem IKE identity to match the Local Network Gateway endpoint (${g.peer}); "${g.remoteId}" must be matched on the on-prem device.`);
  if (!g.v2)
    L.push('# NOTE: modern Azure route-based VpnGw deployments should prefer IKEv2; IKEv1 support is limited to legacy/policy-based deployments and specific SKUs.');
  if (!g.v2 && s.mode === 'aggressive')
    L.push('# UNSUPPORTED: Azure VPN Gateway does not expose IKEv1 aggressive mode; use IKEv2 or IKEv1 main mode where supported.');
  if (!s.natT)
    L.push('# NOTE: NAT-T cannot be switched off as a connection setting in this script; Azure negotiates NAT-T for IKEv2 when the on-prem peer is behind NAT.');

  L.push(
    '# 1) Local Network Gateway = on-prem public endpoint + on-prem prefixes',
    'az network local-gateway create \\',
    '  --resource-group "$RESOURCE_GROUP" \\',
    '  --name "$LOCAL_GATEWAY" \\',
    '  --location "$LOCATION" \\',
    '  --gateway-ip-address "$ONPREM_GATEWAY_IP" \\',
    '  --local-address-prefixes "$ONPREM_PREFIX"',
    '',
    '# 2) Site-to-site connection from the Azure VPN gateway to the on-prem device',
    'az network vpn-connection create \\',
    '  --resource-group "$RESOURCE_GROUP" \\',
    '  --name "$CONNECTION" \\',
    '  --location "$LOCATION" \\',
    '  --vnet-gateway1 "$VNET_GATEWAY" \\',
    '  --local-gateway2 "$LOCAL_GATEWAY" \\',
    '  --connection-type IPsec \\',
    `  --connection-protocol ${g.v2 ? 'IKEv2' : 'IKEv1'} \\`,
    `  --shared-key "${s.psk}" \\`,
    '  --enable-bgp false \\',
    `  --use-policy-based-traffic-selectors ${g.policy || g.specific ? 'true' : 'false'}`,
    '',
  );

  const espInt = isGcm(s.p2Enc) ? AZ_ESP_ENC[s.p2Enc] : AZ_ESP_INT[s.p2Auth];
  const unsupported: string[] = [];
  if ([5, 15, 16, 21].includes(s.dh)) unsupported.push(`DH group ${s.dh} is not in the Azure custom IKE policy list; use DHGroup14, ECP256 or ECP384.`);
  if (s.pfs && [5, 15, 16, 21].includes(s.pfs)) unsupported.push(`PFS group ${s.pfs} is not in the Azure custom IPsec policy list; use PFS14, ECP256 or ECP384.`);
  if (!isGcm(s.p2Enc) && ['sha384', 'sha512'].includes(s.p2Auth)) unsupported.push(`${s.p2Auth.toUpperCase()} is not offered for Azure IPsec integrity here; use SHA256 or AES-GCM.`);
  for (const u of unsupported) L.push(`# UNSUPPORTED: ${u}`);

  L.push(
    '# 3) Custom IKE/IPsec policy on the connection (route-based gateway; not Basic SKU)',
    'az network vpn-connection ipsec-policy add \\',
    '  --connection-name "$CONNECTION" \\',
    '  --resource-group "$RESOURCE_GROUP" \\',
    `  --ike-encryption ${AZ_IKE_ENC[s.p1Enc]} \\`,
    `  --ike-integrity ${AZ_IKE_INT[s.p1Hash]} \\`,
    `  --dh-group ${azDh(s.dh, false)} \\`,
    `  --ipsec-encryption ${AZ_ESP_ENC[s.p2Enc]} \\`,
    `  --ipsec-integrity ${espInt} \\`,
    `  --pfs-group ${azDh(s.pfs, true)} \\`,
    `  --sa-lifetime ${s.p2Life} \\`,
    '  --sa-data-size 102400000',
    '',
    `# Phase 1 lifetime in the simulator is ${s.p1Life}s; Azure gateway IKE lifetime is platform-managed unless your SKU/API exposes it.`,
    `# DPD in the simulator is ${s.dpd ? 'enabled' : 'disabled'}; keep DPD behaviour aligned on the on-prem device.`,
    '',
  );

  if (s.route) {
    L.push(
      '# 4) Routing: workload subnets must send on-prem prefixes to the virtual network gateway',
      '# Repeat for each workload route table that needs the tunnel:',
      'az network route-table route create \\',
      '  --resource-group "$RESOURCE_GROUP" \\',
      '  --route-table-name "<workload-route-table>" \\',
      `  --name "to-${g.t}" \\`,
      '  --address-prefix "$ONPREM_PREFIX" \\',
      '  --next-hop-type VirtualNetworkGateway',
    );
  } else {
    L.push(`# ${FAULT} no route sends ${g.rlan.cidr} to VirtualNetworkGateway; Azure workloads will follow their default route`);
  }

  L.push('');
  if (s.fwPolicy) {
    L.push(
      '# 5) Workload NSGs must allow the VPN prefixes (GatewaySubnet itself should not be treated like a workload subnet)',
      'az network nsg rule create --resource-group "$RESOURCE_GROUP" --nsg-name "<workload-nsg>" --name Allow-OnPrem-To-Azure --priority 200 --direction Inbound --access Allow --protocol "*" --source-address-prefixes "$ONPREM_PREFIX" --destination-address-prefixes "$AZURE_VNET_PREFIX" --source-port-ranges "*" --destination-port-ranges "*"',
      'az network nsg rule create --resource-group "$RESOURCE_GROUP" --nsg-name "<workload-nsg>" --name Allow-Azure-To-OnPrem --priority 210 --direction Outbound --access Allow --protocol "*" --source-address-prefixes "$AZURE_VNET_PREFIX" --destination-address-prefixes "$ONPREM_PREFIX" --source-port-ranges "*" --destination-port-ranges "*"',
    );
  } else {
    L.push(`# ${FAULT} no NSG/Azure Firewall allowance for ${g.rlan.cidr} <-> ${g.lan.cidr}; decrypted traffic can be dropped at workload subnets`);
  }

  if (s.natExempt) L.push('# NAT: keep VPN traffic out of Azure Firewall/NAT Gateway SNAT so the original VNet and on-prem prefixes are preserved.');
  else L.push(`# ${FAULT} VPN traffic is being SNATed before the gateway; Azure Firewall/NAT rules must not translate ${g.lan.cidr} -> ${g.rlan.cidr}`);

  L.push(
    '',
    '# Verify',
    'az network vpn-connection show --name "$CONNECTION" --resource-group "$RESOURCE_GROUP" --output json',
    '# Azure Portal / Log Analytics: Virtual network gateway -> Connections, Diagnostic settings -> IKEDiagnosticLog and TunnelDiagnosticLog',
  );

  return L.join('\n');
}
