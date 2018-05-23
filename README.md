# Contract Parser

`contract_parser` correlates zoning-rules, filters, statistics, EPG names, and 
produces NXOS/IOS-like ACL results.  This simplifies verification and 
troubleshooting ACI policy. This script can safely be executed directly on 
ACI leaf or APIC. When executed on the APIC, it will collect concrete objects
across all leafs which can take a few minutes for large policy deployments.

In addition to contract information, `contract_parser` will print service 
graph information which is especially useful for verifying complex forwarding
scenarios such as redirects with PBR.

> Note, starting in ACI 3.2 `contract_parser` is bundled within image and 
available on the leaf.  Simply type 'contract_parser.py' from ibash.

There are several filtering and print options to display just the information
you are interested in.  Use the --help for full details.  Common filtering 
options include VRF (name or VNID), EPG (name or VNID), and contract.

## Policy Example on Leaf

```
fab3-leaf103# python ./bootflash/contract_parser.py --vrf ag:v1
Key:
[prio:RuleId] [vrf:{str}] action protocol src-epg [src-l4] dst-epg [dst-l4] [flags][contract:{str}] [hit=count]

[9:4165] [vrf:ag:v1] permit any tn-ag/ap-app/epg-e2(16390) tn-ag/ap-app/epg-e1(32773) [contract:uni/tn-ag/brc-c1] [hit=0]
[9:4166] [vrf:ag:v1] permit any tn-ag/ap-app/epg-e1(32773) tn-ag/ap-app/epg-e2(16390) [contract:uni/tn-ag/brc-c1] [hit=5,+5]
[16:4113] [vrf:ag:v1] permit any epg:any tn-ag/bd-l2-only(32771) [contract:implicit] [hit=0]
[16:4125] [vrf:ag:v1] permit any epg:any tn-ag/bd-bd2(49154) [contract:implicit] [hit=0]
[16:4115] [vrf:ag:v1] permit arp epg:any epg:any [contract:implicit] [hit=0]
[21:4114] [vrf:ag:v1] deny,log any epg:any epg:any [contract:implicit] [hit=2095]
[22:4116] [vrf:ag:v1] deny,log any epg:any pfx-0.0.0.0/0(15) [contract:implicit] [hit=0]
```


## Service Graph Example on APIC

```
apic1# ./contract_parser.py
<snip>

# Service Graph Information

[Graph:uni/tn-dualip/AbsGraph-G1]
  contract: uni/tn-dualip/brc-webCtrct
  node: Node2
    funcType:GoTo, routingMode:Redirect, isCopy:no, lDev:ADCCluster1
    Device: swtb25-infra (state: disconnected)
      int:provider (state:down) encap:vlan-2010 bd:uni/tn-dualip/BD-BD2 path:topology/pod-1/paths-106/pathep-[eth1/24]
      ext:consumer (state:down) encap:vlan-2011 bd:uni/tn-dualip/BD-BD5 path:topology/pod-1/paths-106/pathep-[eth1/24]
    Device: ESX (state: disconnected)
      ext:consumer (state:down) encap:vlan-2011 bd:uni/tn-dualip/BD-BD5 path:topology/pod-1/paths-106/pathep-[eth1/23]
      int:provider (state:down) encap:vlan-2010 bd:uni/tn-dualip/BD-BD2 path:topology/pod-1/paths-106/pathep-[eth1/23]
    Device: swtb32-leaf1 (state: disconnected)
      ext:consumer (state:down) encap:vlan-2011 bd:uni/tn-dualip/BD-BD5 path:topology/pod-1/protpaths-106-107/pathep-[vpc1]
      int:provider (state:down) encap:vlan-2010 bd:uni/tn-dualip/BD-BD2 path:topology/pod-1/protpaths-106-107/pathep-[vpc1]
    Device: swtb30-infra (state: disconnected)
      ext:consumer (state:down) encap:vlan-2011 bd:uni/tn-dualip/BD-BD5 path:topology/pod-1/paths-110/pathep-[eth1/3]
      int:provider (state:down) encap:vlan-2010 bd:uni/tn-dualip/BD-BD2 path:topology/pod-1/paths-110/pathep-[eth1/3]

[Graph:uni/tn-l2pbr_shared_service_epg_to_l3out/AbsGraph-WebGraph]
  contract: uni/tn-l2pbr_shared_service_epg_to_l3out/brc-webCtrct
  node: N1
    funcType:GoThrough, routingMode:Redirect, isCopy:no, lDev:N1
    Device: ASA1 (state: disconnected)
      Gig0/1:internal (state:down) encap:vlan-1280 bd:uni/tn-l2pbr_shared_service_epg_to_l3out/BD-N1IntBD path:topology/pod-2/paths-122/pathep-[eth1/43]
      Gig0/0:external (state:down) encap:vlan-1270 bd:uni/tn-l2pbr_shared_service_epg_to_l3out/BD-N1ExtBD path:topology/pod-2/paths-121/pathep-[eth1/43]

```

## Offline Example

`contract_parser` supports collection and analysis of data offline. Use the 
--offlineHelp option to print the list of commands to collect and follow the 
directions.  For example:

```

agossett$ python contract_parser.py --offlineHelp

  Offline mode expects a .tgz file.  For example:
  ./contract_parser.py --offline ./offline_data.tgz

  When executing in offline mode, ensure that all required data is present in
  input tar file. For best results, collect information for all tables using
  the filenames used below.
  Once all commands have completed, the final tar file can be found at:
  /tmp/offline_data.tgz

  bash -c '

  icurl http://127.0.0.1:7777/api/class/vzToEPg.json > /tmp/off_vzToEPg.json 2> /dev/null
  icurl http://127.0.0.1:7777/api/class/fvEpP.json > /tmp/off_fvEpP.json 2> /dev/null
  icurl http://127.0.0.1:7777/api/class/fvAREpP.json > /tmp/off_fvAREpP.json 2> /dev/null
  <snip>

  # compress and combine files
  rm /tmp/offline_data.tgz
  tar -zcvf /tmp/offline_data.tgz /tmp/off_*
  rm /tmp/off_*
  '

agossett$ python contract_parser.py --offline ./offline_data.tgz

```


