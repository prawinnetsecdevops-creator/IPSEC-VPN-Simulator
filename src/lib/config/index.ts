import type { Site } from '../types';
import { asaConfig, iosConfig } from './cisco';
import { mkGen } from './common';
import { fortigateConfig, panosConfig, srxConfig } from './firewalls';
import { mikrotikConfig, strongswanConfig } from './open';
import { azureConfig } from './azure';

/** CLI configuration for `s`, reflecting exactly what is set on that site (faults included). */
export function generateConfig(s: Site, o: Site): string {
  const g = mkGen(s, o);
  switch (s.vendor) {
    case 'cisco-ios': return iosConfig(g);
    case 'cisco-asa': return asaConfig(g);
    case 'fortigate': return fortigateConfig(g);
    case 'paloalto': return panosConfig(g);
    case 'juniper-srx': return srxConfig(g);
    case 'mikrotik': return mikrotikConfig(g);
    case 'strongswan': return strongswanConfig(g);
    case 'azure': return azureConfig(g);
  }
}
