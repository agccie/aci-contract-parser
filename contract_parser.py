#!/usr/bin/python

import logging, re, json, time, sys, os, subprocess
import math

# ----------------------------------------------------------------------------
# Static Globals/Defaults
# ----------------------------------------------------------------------------

CACHE_DIR           = "/tmp/"
EXEC_ONLINE         = 0
EXEC_OFFLINE        = 1
EXEC_MODE           = EXEC_ONLINE
SHOW_CONTRACT       = True
SHOW_GRAPH          = True
UNIQUE_PCTAG_MAX    = 0x4000
UNIQUE_PCTAG_MIN    = 16
STATIC_UNIQUE       = {
    13: "ext-shrsvc",
    14: "int-shrsvc",
    15: "pfx-0.0.0.0/0"
}

# list of epg classes for name resolution
EPG_CLASSES         = ["vzToEPg", "fvEpP", "fvAREpP", "fvABD", "fvACtx", 
                        "fvInBEpP", "fvOoBEpP"] 
VRF_CLASSES         = ["l3Ctx"]
ACTRL_CLASSES       = [
    # actlr classes for software rule/entries/stats
    "actrlRule", "actrlEntry", "actrlRuleHit5min",
    # pbr classes
    "svcredirDest", "svcredirRsDestAtt", "svcredirDestGrp", 
    "actrlRsToRedirDestGrp",
    # copy service classes
    "svccopyDest", "svccopyDestGrp", "svccopyRsCopyDestAtt",
    "actrlRsToCopyDestGrp",
]
CONTRACT_CLASSES    = [
    "actrlRsToEpgConn", "vzTrCreatedBy", "vzRuleOwner","vzObservableRuleOwner"
]
GRAPH_CLASSES = ["vnsNodeInst", "vnsRsNodeInstToLDevCtx", "vnsLDevCtx",
    "vnsLIfCtx", "vnsRsLIfCtxToBD", "vnsRsLIfCtxToLIf",
    "vnsRsLDevCtxToLDev", "vnsLDevVip",
    "vnsCDev", "vnsCIf", "vnsRsCIfPathAtt", "vnsLIf", "vnsRsCIfAtt", 
    "vnsRsCIfAttN",
]

# fixed regex for extracting node-id
node_regex = re.compile("^topology/pod-[0-9]+/node-(?P<node>[0-9]+)/")

def td(start, end, milli=True):
    """ timestamp delta  string"""
    if milli: return "{0:.3f} msecs".format((end-start)*1000)
    else: return "{0:.3f} secs".format((end-start))

# ----------------------------------------------------------------------------
# Common Functions
# ----------------------------------------------------------------------------

def pretty_print(js):
    """ try to convert json to pretty-print format """
    try:
        return json.dumps(js, indent=4, separators=(",", ":"), sort_keys=True)
    except Exception as e:
        return "%s" % js

def str_to_protocol(prot):
    """ map common protocol strings to int value """
    # if int was original string, return int value
    try: return int(prot)
    except Exception as e: pass
    p = {
        "icmp": 1,
        "igmp": 2,
        "tcp": 6,
        "udp": 17,
        "gre": 47,
        "ah": 51,
        "icmp6": 58, "icmpv6": 58,
        "eigrp": 88,
        "ospf": 89, "ospfigp": 89,
        "pim": 103
    }
    return p.get(prot.lower(), 0)

def protocol_to_str(prot):
    """ map supported protocol int to string value """
    try: prot = int(prot)
    except Exception as e: return prot
    p = {
        1: "icmp",
        2: "igmp",
        6: "tcp",
        8: "egp",
        9: "igp",
        17: "udp",
        58: "icmpv6",
        88: "eigrp",
        89: "ospfigp",
        103: "pim",
        115: "l2tp",
    }
    return p.get(prot, prot)

def port_to_str(port):
    """ map supported int L4ports to string value """
    try: port = int(port)
    except Exception as e: return port
    p = {
        20: "ftpData",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        443: "https",
        554: "rtsp",
    }
    return p.get(port, port)

def str_to_port(port):
    """ map support str l4ports to int value """
    p = {
        "ftpData": 20,
        "smtp": 25,
        "dns": 53,
        "http": 80,
        "pop3": 110,
        "https": 443,
        "rtsp": 554,
    }
    return p.get(port, port)

def icmp_opcode_to_str(opcode):
    """ map icmpv4 opcode to string """
    if opcode == 0: return "echo-reply"
    elif opcode == 3: return "dst-unreach"
    elif opcode == 4: return "src-quench"
    elif opcode == 8: return "echo-request"
    elif opcode == 11: return "time-exceeded"
    else: return "opcode-%s" % opcode

def icmp6_opcode_to_str(opcode):
    """ map icmpv6 opcode to string """
    if opcode == 1: return "dst-unreach"
    elif opcode == 2: return "pkt-too-big"
    elif opcode == 3: return "time-exceeded"
    elif opcode == 128: return "echo-request"
    elif opcode == 129: return "echo-reply"
    elif opcode == 133: return "router-solicit"
    elif opcode == 134: return "router-advert"
    elif opcode == 135: return "nbr-solicit"
    elif opcode == 136: return "nbr-advert"
    elif opcode == 137: return "redirect"
    else: return "opcode-%s" % opcode

def tcpflags_to_str(tcpflags, mask):
    """ return tcpflags string """
    f = ""
    tcpflags = tcpflags & ((~mask) & 0xff)
    if (tcpflags & 1)>0: f+= " fin"
    if (tcpflags & 2)>0: f+= " syn"
    if (tcpflags & 4)>0: f+= " rst"
    if (tcpflags & 8)>0: f+= " psh"
    if (tcpflags & 16)>0: f+= " ack"
    if (tcpflags & 32)>0: f+= " urg"
    if len(f)>0: return "(%s)" % f.strip()
    return ""

def offline_extract(tgz, **kwargs):
    """ 
    extract files in tar bundle to tmp directory.  Only files matching
    provided offline_keys dict (which is also used as key in returned dict)
    """
    offline_files = {}
    offline_dir = kwargs.get("offline_dir", "/tmp/")
    offline_keys = kwargs.get("offline_keys", {})
    import tarfile
    # force odir to real directory (incase 'file' is provided as offline_dir)
    odir = os.path.dirname(offline_dir)
    try:
        t = tarfile.open(tgz, "r:gz")
        for m in t.getmembers():
            # check for files matching offline_keys
            for tn in offline_keys:
                if "%s." % tn in m.name:
                    offline_files[tn] = "%s/%s" % (odir, m.name)
                    t.extract(m, path=odir)
                    logging.debug("extracting %s/%s" % (odir, m.name))
                    break

    except Exception as e:
        logging.error("Failed to extract content from offline tar file")
        import traceback
        traceback.print_exc()
        sys.exit()
    
    return offline_files

def online_get_cli(cmd):
    """ execute an online command and return result (None on error) """
    clist = time.time()
    try:
        logging.debug("executing command \"%s\"" % cmd)
        # check_output in 2.7 only, apic may be on 2.6
        if hasattr(subprocess, "check_output"):
            # execute command
            data = subprocess.check_output(cmd, shell=True)
        else:
            # apic may not support check_output, use communicate
            cmd = re.sub("2> /dev/null", "", cmd)
            p = subprocess.Popen(cmd.split(" "), stdout=subprocess.PIPE)
            data, err = p.communicate()
        logging.debug("cli collect time: %s" % td(clist, time.time()))
        return data

    except Exception as e:
        logging.error("error executing command (%s): %s" % (cmd,e))
        return None

def get_class_data(classname, fname=None, **kwargs):
    """ perform icurl or read fname to get class data, return json """
  
    # options for filter and page size
    flt = kwargs.get("flt", "")
    page_size = kwargs.get("page_size", 75000)
    page = kwargs.get("page", 0)
    if len(flt)>0: flt="&%s" % flt
    if "order-by" not in flt: flt="&order-by=%s.dn%s" % (classname, flt)
    
    if fname is not None:
        try:
            logging.debug("reading file %s" % fname)
            with open(fname, "r") as f:
                jst = time.time()
                j = json.loads(f.read())
                logging.debug("json load time: %s" % td(jst, time.time()))
                return j 
        except Exception as e:
            logging.error("unabled to read %s: %s" % (c,e))
            return {}
        except ValueError as e:
            logging.warning("failed to decode json for class %s"%classname) 
            return {} 
        except TypeError as e:
            logging.warning("failed to decode json for class %s"%classname) 
            return {}
    else:
        # walk through pages until return count is less than page_size 
        results = []
        while 1:
            cmd = "icurl -s 'http://127.0.0.1:7777/api/class/"
            cmd+= "%s.json?page-size=%s&page=%s%s'" % (classname,
                    page_size, page, flt)
            cmd+= " 2> /dev/null"
            icurlst = time.time()
            data = online_get_cli(cmd)
            logging.debug("icurl time: %s" % td(icurlst, time.time()))

            # failed to get data
            if data is None: 
                logging.warning("failed to get data for class: %s" % classname)
                return {}

            # parse json data
            try:
                jst = time.time()
                js = json.loads(data)
                logging.debug("json load time: %s" % td(jst, time.time()))
                if "imdata" not in js or "totalCount" not in js:
                    logging.error("invalid icurl result: %s" % js)
                    return {}
                results+=js["imdata"]
                logging.debug("results count: %s/%s" % (
                    len(results),js["totalCount"]))
                if len(js["imdata"])<page_size or \
                    len(results)>=int(js["totalCount"]):
                    logging.debug("all pages received")
                    r = {
                        "imdata": results,
                        "totalCount": len(results)
                    }
                    return r
                page+= 1
 
            except ValueError as e:
                logging.warning("failed to decode json for class %s"%classname)
                return {} 
            except TypeError as e:
                logging.warning("failed to decode json for class %s"%classname)
                return {}
 
    # some unknown error, return empty result
    logging.warning("unexpecedt error occurred when getting class %s"%classname)
    return {}

def get_epg_info(**kwargs):
    """ 
    icurl for epg info/read epg file and return dictionary of epgs
    epgs[vnid][pcTag] = epg_name
    """
    exec_mode = kwargs.get("exec_mode", EXEC_ONLINE)
    offline_files = kwargs.get("offline_files", {})
    epgs = {}
    # concrete classes to collect info from:
    for c in EPG_CLASSES:
        j = {}
        if exec_mode == EXEC_OFFLINE:
            if c in offline_files:
                j = get_class_data(c, offline_files[c])
        else:
            j = get_class_data(c)
            
        pst = time.time()
        _n = "\w\d_\-\."
        # tn is always present (required)
        rx = "uni/tn-(?P<tn>[%s]+)" % _n
        # subset of following are present (order dependent)
        rx+= "(/ctx-(?P<vrf>[%s]+))?" % _n
        rx+= "(/BD-(?P<bd>[%s]+))?" % _n
        rx+= "(/out-(?P<l3out>[%s]+))?" % _n
        rx+= "(/l2out-(?P<l2out>[%s]+))?" % _n
        rx+= "(/mgmtp-(?P<mgmtp>[%s]+))?" % _n
        rx+= "(/extmgmt-(?P<extmgmt>[%s]+))?" % _n
        rx+= "(/instp-(?P<instp>[%s]+))?" % _n
        rx+= "(/instP-(?P<instP>[%s]+))?" % _n
        rx+= "(/oob-(?P<oob>[%s]+))?" % _n
        rx+= "(/inb-(?P<inb>[%s]+))?" % _n
        rx+= "(/ap-(?P<ap>[%s]+))?" % _n
        rx+= "(/epg-(?P<epg>[%s]+))?" % _n
        rx+= "(.+?/G-(?P<G>.+?)-N-.+?-C-(?P<C>[%s]+))?" % _n
        rkeys = ["vrf", "bd", "l3out", "l2out", "mgmtp", "extmgmt",
                "instp", "instP", "oob", "inb", "ap", "epg", "G", "C"]
                
        if "imdata" in j:
            for d in j["imdata"]:
                if type(d) is dict and "attributes" in d.values()[0]:
                    attr = d.values()[0]["attributes"]
                    if "epgDn" in attr and len(attr["epgDn"])>0: _dn = "epgDn"
                    else: _dn = "dn"
                    scope = 0
                    if _dn in attr and "pcTag" in attr and \
                        ("scope" in attr or "scopeId" in attr):
                        try:
                            pcTag = int(attr["pcTag"])
                            if "scope" in attr: scope = int(attr["scope"])
                            elif "scopeId" in attr: scope = int(attr["scopeId"])
                            r1 = re.search(rx, attr[_dn])
                            if r1 is not None:
                                n = "tn-%s" % r1.group("tn")
                                for k in rkeys:
                                    if r1.group("%s"%k) is not None:
                                        n+= "/%s-%s"% (k,r1.group("%s"%k))
                                if scope not in epgs: epgs[scope] = {}
                                # don't overwrite previous entries
                                # (will be found multiple times...)
                                if pcTag not in epgs[scope]:
                                    epgs[scope][pcTag] = n

                        except Exception as e: 
                            #skip pcTag/scope that aren't integers ('any')
                            err = "skipping pcTag: [dn,pcTag,"
                            err+= "scope]=[%s,%s,%s]" % (attr[_dn], 
                                attr["pcTag"], scope)
                            logging.debug(err)

                    # for vzToEPg - add vrf epg tag (may not be local to leaf)
                    if "ctxDefDn" in attr and "ctxPcTag" in attr and \
                        "ctxSeg" in attr and attr["ctxPcTag"]!="any":
                        try:
                            scope = int(attr["ctxSeg"])
                            pcTag = int(attr["ctxPcTag"])
                            r1 = re.search(rx, attr["ctxDefDn"])
                            if r1 is not None:
                                n = "tn-%s" % r1.group("tn")
                                for k in rkeys:
                                    if r1.group("%s"%k) is not None:
                                        n+= "/%s-%s"% (k,r1.group("%s"%k))
                                if scope not in epgs: epgs[scope] = {}
                                epgs[scope][pcTag] = n
                        except Exception as e:
                            #skip pcTag/scope that aren't integers ('any')
                            err = "skipping pcTag: [dn,pcTag,"
                            err+= "scope]=[%s,%s,%s]" % (attr["ctxDefDn"], 
                                attr["ctxPcTag"], attr["ctxSeg"])
                            logging.debug(err)

        logging.debug("json parse time: %s" % td(pst, time.time()))

    # return results
    return epgs

def get_vrf_info(**kwargs):
    """ 
    icurl for vrf info/read vrf file and return dictionary of vrfs.  Each 
    entry has 3 different indexes.  Example:
    vrfs["name::<name>"] = 
    vrfs["vnid::<vnid>"] = {
        "name": "<name>",
        "vnid": <vnid>,
        "pcTag": <pcTag>
    }
    """
    exec_mode = kwargs.get("exec_mode", EXEC_ONLINE)
    offline_files = kwargs.get("offline_files", {})
    vrfs = {}
    
    # concrete classes to collect info from:
    for c in VRF_CLASSES:
        j = {}
        if exec_mode == EXEC_OFFLINE:
            if c in offline_files:
                j = get_class_data(c, offline_files[c])
        else:
            j = get_class_data(c)
        pst = 0
        if "imdata" in j:
            for d in j["imdata"]:
                if type(d) is dict and "attributes" in d.values()[0]:
                    attr = d.values()[0]["attributes"]
                    # expect name, pcTag, scope(==vnid), and 
                    # resourceId(==hwscope) or (?possibly secLbl)
                    # secLbl (==hwscope)
                    v={"name": None,"vnid": None,"scope": None,"pcTag":None}
                    if "name" in attr: v["name"] = attr["name"]
                    else: 
                        logging.debug("skipping l3Ctx %s (no name)"%attr)
                        continue
                    if "pcTag" in attr: 
                        if attr["pcTag"] == "any": v["pcTag"] = 0
                        else: v["pcTag"] = int(attr["pcTag"])
                    else:
                        logging.debug("skipping l3Ctx %s (no pcTag)"%attr)
                        continue
                    if "scope" in attr: v["vnid"] = int(attr["scope"])
                    else:
                        logging.debug("skipping l3Ctx %s (no scope)"%attr)
                        continue
                    
                    # add triple-indexed entry to dict
                    vrfs["name::%s"%v["name"]] = v
                    vrfs["vnid::%s"%v["vnid"]] = v
            pst = time.time()
        logging.debug("json parse time: %s" % td(pst, time.time()))
    
    # return results
    return vrfs

def get_bd_info(**kwargs):
    """ 
    build mapping for bd name/vnid. Return double-mapped dict
    bds["name::<name>"] = 
    bds["vnid::<vnid>"] = {
        "name": "<name>",
        "vnid": <vnid>,
        "vrf": <vrf-vnid>,
        "pcTag": <pcTag>
    }
    """
    exec_mode = kwargs.get("exec_mode", EXEC_ONLINE)
    offline_files = kwargs.get("offline_files", {})
    bds = {}
    
    # concrete classes to collect info from:
    for c in ["fvABD"]:
        j = {}
        if exec_mode == EXEC_OFFLINE:
            if c in offline_files:
                j = get_class_data(c, offline_files[c])
        else:
            j = get_class_data(c)
        pst = 0
        if "imdata" in j:
            for d in j["imdata"]:
                if type(d) is dict and "attributes" in d.values()[0]:
                    attr = d.values()[0]["attributes"]
                    # set 'name' to dn
                    v={"name": None,"vnid": None,"pcTag":None}
                    if "bdDn" in attr: v["name"] = attr["bdDn"]
                    elif "dn" in attr: v["name"] = attr["dn"]
                    else: 
                        logging.debug("skipping fvABD %s (no name)"%attr)
                        continue
                    if "pcTag" in attr: 
                        if attr["pcTag"] == "any": v["pcTag"] = 0
                        else: v["pcTag"] = int(attr["pcTag"])
                    else:
                        logging.debug("skipping fvABD %s (no pcTag)"%attr)
                        continue
                    if "scope" in attr: v["vrf"] = int(attr["scope"])
                    else:
                        logging.debug("skipping fvABD %s (no scope)"%attr)
                        continue
                    if "seg" in attr: 
                        v["vnid"] = int(attr["seg"])
                    else:
                        logging.debug("skip fvABD %s (no seg)"%attr)
                        continue
                    
                    # add triple-indexed entry to dict
                    bds["name::%s"%v["name"]] = v
                    bds["vnid::%s"%v["vnid"]] = v
            pst = time.time()
        logging.debug("json parse time: %s" % td(pst, time.time()))
    
    # return results
    return bds


def get_contract_info(**kwargs):
    """ 
    read actrlRsToEpgConn and vzRuleOwner to build mapping of rule to contract.
    return dict indexed by actrlRule: {
        "rule": "contract"
    }
    """
    exec_mode = kwargs.get("exec_mode", EXEC_ONLINE)
    offline_files = kwargs.get("offline_files", {})
    contracts = {}
    
    # handle rstoEpgCon
    reg1 = "(?P<r>^.+?)/rstoEpgConn-\[cdef-.*?"
    reg1+= "\[(?P<v>uni/tn-[^/]+/(oob)?brc-[^\]]+)\]"
    reg1 = re.compile(reg1)
    # handle vzRuleOwner for implicit rules
    reg2 = "(?P<r>^.+?)/own-\[.+?"
    reg2+="(\[tdef-.*?\[(?P<v>uni/tn-[^/]+/taboo-[^\]]+)\]/rstabooRFltAtt.+?)?"
    reg2+="-tag"
    reg2 = re.compile(reg2)
    # handle taboo owners
    reg3 = "(?P<r>^.+?)/trCreatedBy-\[tdef-.*?"
    reg3+= "\[(?P<v>uni/tn-[^/]+/taboo-[^\]]+)\]/rstabooRFltAtt"
    reg3 = re.compile(reg3)
    # handle vzObservableRuleOwner
    reg4 = "(?P<r>^.+?)/oown-\[cdef-.*?"
    reg4+= "\[(?P<v>uni/tn-[^/]+/(oob)?brc-[^\]]+)\]"
    reg4 = re.compile(reg4)

    search = {
        "actrlRsToEpgConn": {"reg": reg1,},
        "vzRuleOwner": {"reg": reg2, "default": "implicit"},
        "vzTrCreatedBy": {"reg": reg3 },
        "vzObservableRuleOwner": {"reg": reg4},
    }
    
    # concrete classes to collect info from:
    for c in CONTRACT_CLASSES:
        j = {}
        if exec_mode == EXEC_OFFLINE:
            if c in offline_files: j = get_class_data(c, offline_files[c])
        else: j = get_class_data(c)
        if "imdata" in j:
            for d in j["imdata"]:
                if type(d) is dict and "attributes" in d.values()[0]:
                    classname = d.keys()[0]
                    attr = d.values()[0]["attributes"]
                    if "dn" in attr and classname in search:
                        # statically defined 'search' per classname with 'r'
                        # named group for the rule that it matches and either
                        # 'default' defined in the dict or 'v' group in regex
                        # for the value to apply
                        s = search[classname]
                        r1 = s["reg"].search(attr["dn"])
                        if r1 is not None:
                            # ok to have duplicates, just continue
                            if r1.group("r") in contracts: continue
                            if r1.group("v") is not None:
                                contracts[r1.group("r")] = r1.group("v")
                            elif "default" in s:
                                contracts[r1.group("r")] = s["default"]
                        else:
                            logging.warn("failed to match against %s %s" % (
                                classname, attr["dn"]))
    return contracts

# ----------------------------------------------------------------------------
# actrl Object
# ----------------------------------------------------------------------------

class ActrlNode(object):
    def __init__(self, node):
        self.node = node
        # indexed by self.rules[prio][vnid] = [list of rules]
        self.rules = {}
        # indexed by filter name (contains list of filters for multiple ent)
        self.filters = {}
        # indexed by rule dn
        self.stats = {}
        # actrl_redirs pointer to svcredirDestGrp indexed by rule dn
        self.redirs = {}
        # actrl_copy pointer to svccopyDestGrp indexed by rule dn
        self.copys = {}

class Actrl(object):

    # actrl:RulePrio for sorting rules
    # this is version of code dependent, for now setting to most recent version
    # dme/model/specific/mo/switch/feature/actrl/types.xml
    RULEPRIO = {
        "class-eq-filter": 1,
        "class-eq-deny": 2,
        "class-eq-allow": 3,
        "prov-nonshared-to-cons": 4,
        "black_list": 5,
        "fabric_infra": 6,
        "fully_qual": 7,
        "system_incomplete": 8,
        "src_dst_any": 9,
        "shsrc_any_filt_perm": 10,
        "shsrc_any_any_perm": 11,
        "shsrc_any_any_deny": 12,
        "src_any_filter": 13,
        "any_dest_filter": 14,
        "src_any_any": 15,
        "any_dest_any": 16,
        "any_any_filter": 16,
        "grp_src_any_any_deny": 18,
        "grp_any_dest_any_deny": 19,
        "grp_any_any_any_permit": 20,
        "any_any_any": 21,
        "any_vrf_any_deny": 22,
        "default_action": 23,
        "default": 0            # actual constant DEFAULT but use .lower()
    }

    def __init__(self, args):

        # check cache settings - note that state is never saved to cache but
        # for offline mode, cache directory is used during file extraction.
        # if not supplied, use defaults in offline_extract function
        self.cache_file = args.cache
        if len(self.cache_file)==0 or self.cache_file=="0":
            self.cache_file = None

        # check exec_mode from arguments
        offline_keys =  ACTRL_CLASSES + VRF_CLASSES + EPG_CLASSES + \
                        CONTRACT_CLASSES + GRAPH_CLASSES
        self.exec_mode = EXEC_ONLINE
        self.offline_files = {}
        self.bds = {}
        self.vrfs = {}
        self.epgs = {}
        self.unique_epgs = {}
        self.contracts = {}
        self.graphs = {}

        if args.offline: 
            self.exec_mode = EXEC_OFFLINE
            self.offline_files = offline_extract(args.offline,
                offline_dir = self.cache_file,  # file is ok-func works it out
                offline_keys = offline_keys
            )

        # if name resolution is enabled...
        if not args.noNames:
            # grab vrf info, two-way indexed by name::%s, vnid::%s
            self.vrfs = get_vrf_info(
                exec_mode=self.exec_mode,
                offline_files=self.offline_files
            )
            # grab bd info, two-way indexed by name::%s, vnid::%s
            self.bds = get_bd_info(
                exec_mode=self.exec_mode,
                offline_files=self.offline_files
            )
            # grab epg names, epgs[scope][pcTag] = name
            self.epgs = get_epg_info(
                exec_mode=self.exec_mode,
                offline_files=self.offline_files
            )
            # build list of shared service 'unique' epgs
            for vnid in self.epgs:
                for pcTag in self.epgs[vnid]:
                    if pcTag >= UNIQUE_PCTAG_MIN and pcTag <= UNIQUE_PCTAG_MAX:
                        self.unique_epgs[pcTag] = self.epgs[vnid][pcTag]
            # add static uniques as well
            for pcTag in STATIC_UNIQUE:
                self.unique_epgs[pcTag] = STATIC_UNIQUE[pcTag]

        # build actrlRule to contract info if enabled
        if SHOW_CONTRACT:
            self.contracts = get_contract_info(
                exec_mode=self.exec_mode,
                offline_files=self.offline_files
            )

        # rules/filters/stats/redirs are all objects with a node 
        self.nodes = {}
        self.filter_nodes = args.nodes

        # build rules, filters, stats, and redirects
        self.get_rules()
        self.get_filters()
        self.get_stats()
        self.get_redirs()
        self.get_copys()

        # build graph info if enabled
        if SHOW_GRAPH: self.get_graphs()

    def get_node(self, n):
        """ get/create an ActrlNode from self.nodes 
            return None if node is not allowed by filter
        """
        if n not in self.nodes:
            # check if this node is filtered
            if len(self.filter_nodes)==0 or n in self.filter_nodes:
                self.nodes[n] = ActrlNode(n)
                logging.debug("new node %s added" % n)
            else: return None
        return self.nodes[n]

    def get_rules(self):
        """ get/build concrete rules """
        classname = "actrlRule"
        j = {}
        if self.exec_mode == EXEC_OFFLINE:
            if classname in self.offline_files:
                j = get_class_data(classname, self.offline_files[classname])
        else:
            j = get_class_data(classname)
        if "imdata" in j:
            logging.debug("%s count: %s" % (classname, len(j["imdata"])))
            for d in j["imdata"]:
                if type(d) is dict and "attributes" in d.values()[0]:
                    attr = d.values()[0]["attributes"]
                    rule = {
                        "dn": None, "id": None,
                        "fltId": None, "action": None, 
                        "direction": None, "operSt": None,
                        "dPcTag": None, "sPcTag": None, "scopeId": None,
                        "type": None, "prio": None,
                        "markDscp": None, "qosGrp": None,
                    } 
                    skip_rule = False
                    for key in rule:
                        if key not in attr:
                            logging.warn("skipping rule, %s missing: %s" % (
                                attr, key))
                            skip_rule = True
                            break
                        rule[key] = attr[key]
                    if skip_rule: continue
    
                    # if contract mapping is enabled, try to add contract 
                    # attribute to rule
                    if SHOW_CONTRACT: 
                        rule["contract"] = self.contracts.get(rule["dn"],None)
                    else:
                        rule["contract"] = None

                    # determine node-id - not present if executed on leaf
                    r1 = node_regex.search(attr["dn"])
                    if r1 is not None: node = self.get_node(r1.group("node")) 
                    else: node = self.get_node("0")
                    if node is None: continue
                    
                    # index rules by int priority value
                    prio = Actrl.RULEPRIO.get(rule["prio"], 0)
                    if prio not in node.rules: node.rules[prio] = {}
                    if rule["scopeId"] not in node.rules[prio]:
                        node.rules[prio][rule["scopeId"]] = []
                    # add rule to self.rules
                    node.rules[prio][rule["scopeId"]].append(rule)

    def get_filters(self):
        """ get/build concrete filters """
        classname = "actrlEntry"
        j = {}
        if self.exec_mode == EXEC_OFFLINE:
            if classname in self.offline_files:
                j = get_class_data(classname, self.offline_files[classname])
        else:
            j = get_class_data(classname)
        if "imdata" in j:
            logging.debug("%s count: %s" % (classname, len(j["imdata"])))
            for d in j["imdata"]:
                if type(d) is dict and "attributes" in d.values()[0]:
                    attr = d.values()[0]["attributes"]
                    flt = {
                        "dn": None, "name": None,
                        "applyToFrag": None, "arpOpc": None,
                        "dFromPort": None, "dToPort": None,
                        "etherT": None, "icmpv4T": None, "icmpv6T": None,
                        "prot": None, "sFromPort": None,
                        "sToPort": None, "stateful": None, "tcpRules": None,
                        "matchDscp": "unspecified",
                    }
                    # optional keys (code dependent)
                    opt_keys = ["matchDscp"]
                    skip_flt = False
                    for key in flt:
                        if key in attr:
                            flt[key] = attr[key]
                        elif key in opt_keys: pass
                        else:
                            logging.debug("skipping flt, %s missing: %s" % (
                                attr, key))
                            skip_flt = True
                            break
                    if skip_flt: continue

                    # determine node-id - not present if executed on leaf
                    r1 = node_regex.search(attr["dn"])
                    if r1 is not None: node = self.get_node(r1.group("node")) 
                    else: node = self.get_node("0")
                    if node is None: continue

                    fkey = flt["name"]
                    r1 = re.search("^(?P<flt>[0-9]+)_(?P<ent>[0-9]+)$",
                        flt["name"])
                    if r1 is not None: fkey = "%s"%r1.group("flt")
                    if fkey not in node.filters: node.filters[fkey] = []
                    # format ports to integers
                    flt["sFromPort"] = str_to_port(flt["sFromPort"])
                    flt["sToPort"] = str_to_port(flt["sToPort"])
                    flt["dFromPort"] = str_to_port(flt["dFromPort"])
                    flt["dToPort"] = str_to_port(flt["dToPort"])
                    node.filters[fkey].append(flt)
                    # 'default' filter is same as 'any' filter, add second key
                    if fkey == "any":
                        if "default" not in node.filters: 
                            node.filters["default"] = []
                        node.filters["default"].append(flt)

    def get_stats(self):
        """ get/build concrete stats """

        classname = "actrlRuleHit5min"
        j = {}
        if self.exec_mode == EXEC_OFFLINE:
            if classname in self.offline_files:
                j = get_class_data(classname, self.offline_files[classname])
        else:
            j = get_class_data(classname)

        if "imdata" in j:
            logging.debug("%s count: %s" % (classname, len(j["imdata"])))
            for d in j["imdata"]:
                if type(d) is dict and "attributes" in d.values()[0]:
                    attr = d.values()[0]["attributes"]
                    if "dn" not in attr:
                        logging.debug("skipping stat, dn missing: %s"%attr)
                        continue
                    stat = {
                        "dn": None,
                        "ingrPktsCum": None, "egrPktsCum": None,
                        "ingrPktsLast": None, "egrPktsLast": None,
                        # SB counters do not have direction
                        "pktsCum": None, "pktsLast": None
                    }
                    match_count = 0
                    for key in stat:
                        if key in attr:
                            match_count+= 1
                            stat[key] = attr[key]
                        else:
                            stat[key] = "0"
                    if match_count==0:
                        logging.debug("skipping stat, %s missing attributes"%(
                            attr))
                        continue

                    # determine node-id - not present if executed on leaf
                    r1 = node_regex.search(attr["dn"])
                    if r1 is not None: node = self.get_node(r1.group("node")) 
                    else: node = self.get_node("0")
                    if node is None: continue

                    # fixup dn by removing "/CDactrlRuleHit5min" - fixed len
                    dn = attr["dn"][0:len(attr["dn"])-19]
                    node.stats[dn] = stat

    def generic_parse(self, obj, index_key, required_keys, relax=False):
        """ generic verification/parsing of object ensuring all required keys
            are present
            obj = dictionary to parse 
                must contain 'imdata' and "attributes" for each object
            required_keys = list of required keys in object to extract
            index_key = unique index for object in return dictionary
            relax = if true set missing 'required_keys' to empty value, if false
                    skip the entire object
        """
        if index_key not in required_keys: required_keys.append(index_key)
        final_ret = {}
        if "imdata" in obj:
            for d in obj["imdata"]:
                if type(d) is not dict or "attributes" not in d.values()[0]:
                    logging.debug("skipping invalid object: %s" % d)
                    continue
                d = d.values()[0]["attributes"]
                ret = {}
                valid=True
                for key in required_keys:
                    if key not in d: 
                        logging.debug("object missing key %s: %s"%(key,d))
                        if relax: d[key] = ""
                        else:
                            valid=False
                            break
                    ret[key] = d[key]
                if not valid: continue
                final_ret[ret[index_key]] = ret
        return final_ret 

    def get_redirs(self):
        """ get/build concrete redirect info """

        # get redirect groups first
        j1 = j2 = j3 = j4 = {}
        classname1 = "svcredirDest"
        classname2 = "svcredirRsDestAtt"
        classname3 = "svcredirDestGrp"
        classname4 = "actrlRsToRedirDestGrp"
        if self.exec_mode == EXEC_OFFLINE:
            if classname1 in self.offline_files:
                j1 = get_class_data(classname1, self.offline_files[classname1])
            if classname2 in self.offline_files:
                j2 = get_class_data(classname2, self.offline_files[classname2])
            if classname3 in self.offline_files:
                j3 = get_class_data(classname3, self.offline_files[classname3])
            if classname4 in self.offline_files:
                j4 = get_class_data(classname4, self.offline_files[classname4])
        else:
            j1 = get_class_data(classname1)
            # if no data was found in svcredirDest, then stop
            if len(j1) == 0:
                logger.debug("no %s found, skipping get_redirs" % classname1)
                return
            j2 = get_class_data(classname2)
            j3 = get_class_data(classname3)
            j4 = get_class_data(classname4)

        # build dict of destinations indexed by dn
        dest = self.generic_parse(j1, "dn", ["dn","ip","vMac","vrf",
                    "vrfEncap", "bdVnid", "operSt", "operStQual"])
        # try to remap bdVnid to bd name
        for dn in dest:
            d = dest[dn]
            d["bd"] = d["bdVnid"]
            r1 = re.search("vxlan-(?P<vnid>[0-9]+)", d["bdVnid"])
            if r1 is not None:
                key = "vnid::%s" % r1.group("vnid")
                if key in self.bds: d["bd"] = self.bds[key]["name"]

        # build dict of destAtt indexed by dn
        destAtt = self.generic_parse(j2, "dn", ["dn", "tDn"])
        # re-index destgrps based on group number with pointer to actual dest
        # grps[node-id][group-id] -> list(dest objects)
        grps = {}
        for dn in destAtt:
            # determine node-id - not present if executed on leaf
            node_id = "0"
            r0 = node_regex.search(dn)
            if r0 is not None: node_id = r0.group("node")
            if node_id not in grps: grps[node_id] = {}

            r1 = re.search("destgrp-(?P<id>[0-9]+)", dn)
            if r1 is None: 
                logging.debug("invalid dn for svcredirRsDestAtt: %s" % dn)
                continue
            gid = r1.group("id")
            if gid not in grps[node_id]: grps[node_id][gid] = []
            if destAtt[dn]["tDn"] in dest:
                grps[node_id][gid].append(dest[destAtt[dn]["tDn"]])

        # build dict of redirs indexed by dn
        redir_grps = self.generic_parse(j3, "dn", ["dn","operSt","operStQual",
            "id","ctrl"])
        # for each redir, check if group is in grps to have list of redirDest
        for dn in redir_grps:
            # determine node-id - not present if executed on leaf
            node_id = "0"
            r0 = node_regex.search(dn)
            if r0 is not None: node_id = r0.group("node")
            if node_id not in grps: grps[node_id] = {}

            redir_grps[dn]["dests"] = []
            r1 = re.search("destgrp-(?P<id>[0-9]+)", dn)
            if r1 is None: 
                logging.debug("invalid dn for svcredirDestGrp: %s" % dn)
                continue
            if r1.group("id") in grps[node_id]:
                redir_grps[dn]["dests"] = grps[node_id][r1.group("id")]

        # build dict of actrlRsToRedirDestGrp indexed by dn
        tmp_actrl = self.generic_parse(j4, "dn", ["dn", "tDn"])
        for dn in tmp_actrl:
            # fixup dn to drop rstoRedirDestGrp so it points to actrl
            d = "/".join(dn.split("/")[0:-1])
            # tDn should point to known destGroup
            if tmp_actrl[dn]["tDn"] not in redir_grps:
                logging.debug("%s not found in svcredirDestGrp" % (
                    tmp_actrl[dn]["tDn"]))
                continue

            # determine node-id - not present if executed on leaf
            r1 = node_regex.search(dn)
            if r1 is not None: node = self.get_node(r1.group("node")) 
            else: node = self.get_node("0")
            if node is None: continue
            node.redirs[d] = redir_grps[tmp_actrl[dn]["tDn"]]

    def get_copys(self):
        """ get/build concrete copy service info """

        # get redirect groups first
        j1 = j2 = j3 = j4 = {}
        classname1 = "svccopyDest"
        classname2 = "svccopyRsCopyDestAtt"
        classname3 = "svccopyDestGrp"
        classname4 = "actrlRsToCopyDestGrp"
        if self.exec_mode == EXEC_OFFLINE:
            if classname1 in self.offline_files:
                j1 = get_class_data(classname1, self.offline_files[classname1])
            if classname2 in self.offline_files:
                j2 = get_class_data(classname2, self.offline_files[classname2])
            if classname3 in self.offline_files:
                j3 = get_class_data(classname3, self.offline_files[classname3])
            if classname4 in self.offline_files:
                j4 = get_class_data(classname4, self.offline_files[classname4])
        else:
            j1 = get_class_data(classname1)
            # if no data was found in svccopyDest, then stop
            if len(j1) == 0: 
                logger.debug("no %s found, skipping get_copys" % classname1)
                return
            j2 = get_class_data(classname2)
            j3 = get_class_data(classname3)
            j4 = get_class_data(classname4)

        # build dict of destinations indexed by dn
        dest = self.generic_parse(j1, "dn", ["dn","id","tepIp", "bdVnid", 
            "operSt", "operStQual"])

        # build dict of destAtt indexed by dn
        destAtt = self.generic_parse(j2, "dn", ["dn", "tDn"])
        # re-index destgrps based on group number with pointer to actual dest
        # grps[node-id][group-id] -> list(dest objects)
        grps = {}
        for dn in destAtt:
            # determine node-id - not present if executed on leaf
            node_id = "0"
            r0 = node_regex.search(dn)
            if r0 is not None: node_id = r0.group("node")
            if node_id not in grps: grps[node_id] = {}

            r1 = re.search("destgrp-(?P<id>[0-9]+)", dn)
            if r1 is None: 
                logging.debug("invalid dn for svccopyRsDestAtt: %s" % dn)
                continue
            gid = r1.group("id")
            if gid not in grps[node_id]: grps[node_id][gid] = []
            if destAtt[dn]["tDn"] in dest:
                grps[node_id][gid].append(dest[destAtt[dn]["tDn"]])

        # build dict of copys indexed by dn
        copy_grps = self.generic_parse(j3, "dn", ["dn","id","operSt",
            "operStQual"])
        # for each copy, check if group is in grps to have list of copyDest
        for dn in copy_grps:
            # determine node-id - not present if executed on leaf
            node_id = "0"
            r0 = node_regex.search(dn)
            if r0 is not None: node_id = r0.group("node")
            if node_id not in grps: grps[node_id] = {}

            copy_grps[dn]["dests"] = []
            r1 = re.search("destgrp-(?P<id>[0-9]+)", dn)
            if r1 is None: 
                logging.debug("invalid dn for svccopyDestGrp: %s" % dn)
                continue
            if r1.group("id") in grps[node_id]:
                copy_grps[dn]["dests"] = grps[node_id][r1.group("id")]

        # build dict of actrlRsToCopyDestGrp indexed by dn
        tmp_actrl = self.generic_parse(j4, "dn", ["dn", "tDn"])
        for dn in tmp_actrl:
            # fixup dn to drop rstoCopyDestGrp so it points to actrl
            d = "/".join(dn.split("/")[0:-1])
            # tDn should point to known destGroup
            if tmp_actrl[dn]["tDn"] not in copy_grps:
                logging.debug("%s not found in svccopyDestGrp" % (
                    tmp_actrl[dn]["tDn"]))
                continue

            # determine node-id - not present if executed on leaf
            r1 = node_regex.search(dn)
            if r1 is not None: node = self.get_node(r1.group("node")) 
            else: node = self.get_node("0")
            if node is None: continue
            node.copys[d] = copy_grps[tmp_actrl[dn]["tDn"]]

    def get_graphs(self):
        """ get/build deployed graph instances on a per vnsNodeInst basis

        Managed Objects
            vnsNodeInst (dn, funcType, isCopy, routingMode, ctxName, name, 
                         extract contract and graph from dn)
                child:
                vnsRsNodeInstToLDevCtx (tCl	vnsLDevCtx)
            vnsLDevCtx (dn)
                child:
                vnsLIfCtx (dn, connNameOrLbl)
                    child:
                    vnsRsLIfCtxToBD (dn, tDn)
                    vnsRsLIfCtxToLIf (tCl vnsLIf)
                vnsRsLDevCtxToLDev (tCl vnsLDevVip)


            vnsLDevVip (dn, name, isCopy, funcType)
                child:
                vnsCDev (dn, name, state, vmOp)
                    child:
                    vnsCIf (dn, name, operSt, configSt, configIssues)
                        child:
                        vnsRsCIfPathAtt (tDn - tCl fabricPathEp)
                vnsLIf (dn, encap, name)
                    child:
                    vnsRsCIfAttN + vnsRsCIfAtt (tCl vnsCIf)

        Internal data structure to maintain:

            inode: {    # vnsNodeInst
                "dn", "funcType", "isCopy", "routingMode", "ctxName", "name",
                "contract"      # extracted from dn
                "graph"         # extracted from dn
                "ldev"          # ptr from ldevctx["ldev"] using:
                                #   vnsRsNodeInstToLDevCtx to map ldevctx
            }

            ldevctx: {  # vnsLDevCtx
                "dn", "ctrctNameOrLbl", "nodeNameOrLbl", "graphNameOrLbl",
                "ldev":{}       # ptr to ldev from vnsRsLDevCtxToLDev
            }

            ldev: {             # vnsLDevVip
                "dn", "name", "funcType", "isCopy"
                "cdev": {
                    "<dn>": {
                        "dn", "name", "state", "vmOp",
                        "cif": {
                            "dn", "name", "configIssues", "configSt", "operSt",
                            "path",                 # vnsRsCIfPathAtt
                            "lif": {                # from vnsLIf/vnsRsCIfAtt
                                "dn", "encap", "name",
                                "lifctx": {}        # ptr to lifctx object
                            },
                        },
                    },
                },
            }

        self.graphs = {
            "<graph-name>": {
                "<contract-name>": {
                    "<vnsNodeInst.dn>": {}              # ptr to inode
                }
            }
        }
        
        """
        data = {}
        for c in GRAPH_CLASSES: 
            if self.exec_mode == EXEC_OFFLINE:
                if c in self.offline_files:
                    data[c] = get_class_data(c, self.offline_files[c])
            else:
                data[c] = get_class_data(c)

        # ldev objects
        ldev = self.generic_parse(data.get("vnsLDevVip",{}),"dn",
            ["dn","name","funcType","isCopy"], relax=True)
        lif = self.generic_parse(data.get("vnsLIf",{}), "dn",
            ["dn", "name", "encap"], relax = True)
        cdev = self.generic_parse(data.get("vnsCDev",{}), "dn",
            ["dn", "name", "state", "vmOp"], relax=True)
        cif = self.generic_parse(data.get("vnsCIf",{}), "dn", 
            ["dn", "name", "operSt", "configIssues", "configSt"], relax=True)
        cif_att = self.generic_parse(data.get("vnsRsCIfAtt",{}), "dn", 
            ["dn","tCl","tDn"])
        cif_att2 = self.generic_parse(data.get("vnsRsCIfAttN",{}), "dn", 
            ["dn","tCl","tDn"])
        # merge data from vnsRsCIfAtt and vnsRsCIfAttN
        for k in cif_att2:
            if k not in cif_att: cif_att[k] = cif_att2[k]
        rs_cif_to_pathatt = self.generic_parse(data.get("vnsRsCIfPathAtt",{}),
            "dn", ["dn", "tCl", "tDn"])

        # ldevctx objects
        ldevctx = self.generic_parse(data.get("vnsLDevCtx",{}), "dn", 
            ["dn", "ctrctNameOrLbl", "graphNameOrLbl", "nodeNameOrLbl"],
            relax=True)
        lifctx = self.generic_parse(data.get("vnsLIfCtx",{}), "dn",
            ["dn", "connNameOrLbl", "permitLog"], relax=True)
        rs_lifctx_to_bd = self.generic_parse(
            data.get("vnsRsLIfCtxToBD", {}), "dn", ["dn","tCl", "tDn"])
        rs_lifctx_to_lif = self.generic_parse(
            data.get("vnsRsLIfCtxToLIf", {}), "dn", ["dn", "tCl", "tDn"])
        rs_ldevctx_to_ldev = self.generic_parse(
            data.get("vnsRsLDevCtxToLDev",{}), "dn", ["dn", "tCl", "tDn"])

        # node instance objects
        inode = self.generic_parse(data.get("vnsNodeInst",{}),"dn",
            ["dn", "funcType", "isCopy", "routingMode", "ctxName", "name"],
            relax=True)
        rs_inode_to_ldevctx = self.generic_parse(
            data.get("vnsRsNodeInstToLDevCtx",{}), "dn", ["dn","tCl","tDn"])

        # map ldevctx to ldev
        for dn in ldevctx: ldevctx[dn]["ldev"] = {}
        for dn in rs_ldevctx_to_ldev:
            rs = rs_ldevctx_to_ldev[dn]
            if rs["tDn"] not in ldev:
                logger.debug("rsLDevCtxToLDev(%s) vnsLDev tDn(%s) not found"%(
                    rs["dn"], rs["tDn"]))
                continue
            pdn = re.sub("/rsLDevCtxToLDev$", "", rs["dn"])
            if pdn not in ldevctx:
                logger.debug("rsLDevCtxToLDev(%s) parent(%s) not found"%(
                    rs["dn"], pdn))
            else:
                ldevctx[pdn]["ldev"] = ldev[rs["tDn"]]

        # add bd to each lifctx from rs_lifctx_to_bd
        for dn in lifctx: lifctx[dn]["bd"] = ""
        for dn in rs_lifctx_to_bd:
            rs = rs_lifctx_to_bd[dn]
            pdn = re.sub("/rsLIfCtxToBD$", "", rs["dn"])
            if pdn not in lifctx:
                logger.debug("vnsRsLIfCtxToBD(%s) parent(%s) not found"%(
                    rs["dn"], pdn))
            else:
                lifctx[pdn]["bd"] = rs["tDn"]

        # add lifctx to each lif from rs_lifctx_to_lif
        for dn in lif: lif[dn]["lifctx"] = {}
        for dn in rs_lifctx_to_lif:
            rs = rs_lifctx_to_lif[dn]
            if rs["tDn"] not in lif:
                logger.debug("vnsRsLIfCtxToLIf(%s) vnsLIf tDn(%s) not found"%(
                    rs["dn"], rs["tDn"]))
                continue
            pdn = re.sub("/rsLIfCtxToLIf$", "", rs["dn"])
            if pdn not in lifctx:
                logger.debug("vnsRsLIfCtxToLIf(%s) parent(%s) not found"%(
                    rs["dn"], pdn))
            else:
                lif[rs["tDn"]]["lifctx"] = lifctx[pdn]
        
        # add require attributes to ldev
        for dn in ldev: ldev[dn]["cdev"] = {}

        # add cdev to ldev, add required attributes
        for dn in cdev:
            l = cdev[dn]
            l["cif"] = {}
            pdn = re.sub("/cDev-%s$" % re.escape(l["name"]), "", l["dn"])
            if pdn in ldev: ldev[pdn]["cdev"][l["dn"]] = l
            else:
                logger.debug("vnsCDev(%s) parent(%s) not found"%(l["dn"],pdn))
    
        # add cif to each cdev
        for dn in cif:
            l = cif[dn]
            l["lif"] = {}
            l["path"] = ""
            pdn = re.sub("/cIf-\[%s\]$" % re.escape(l["name"]), "", l["dn"])
            if pdn in cdev: cdev[pdn]["cif"][l["dn"]] = l
            else:
                logger.debug("vnsCIf(%s) parent(%s) not found"%(l["dn"],pdn))

        # add pathatt to each cif
        for dn in rs_cif_to_pathatt:
            rs = rs_cif_to_pathatt[dn]
            pdn = re.sub("/rsCIfPathAtt$", "", rs["dn"])
            if pdn not in cif:
                logger.debug("vnsRsCIfPathAtt(%s) parent(%s) not found"%(
                    rs["dn"], pdn))
            else:
                cif[pdn]["path"] = rs["tDn"]

        # use cif_att to add lif info to each cif - theoretically multiple
        # lif could have relationship to cif based on format of dn but for now
        # lets assume that can't happen...
        for dn in cif_att:
            attach = cif_att[dn]
            if attach["tDn"] not in cif:
                logger.debug("unable to map vnsRsCIfAtt to vnsCIf: %s"%attach)
                continue
            pdn = re.sub("/rscIfAttN?-\[%s\]$"%re.escape(attach["tDn"]), "", \
                            attach["dn"])
            if pdn not in lif: 
                logger.debug("vnsRsCIfAtt(%s) parent(%s) not found"%(
                    attach["dn"], pdn))
            else:
                cif[attach["tDn"]]["lif"] = lif[pdn]

        # build inode (vnsNodeInst) and then map to ldev
        # extract graph/contract from dn and add required attributes
        reg = "uni/tn-[^/]+/GraphInst_C-\[(?P<contract>[^]]+)\]"
        reg+= "-G-\[(?P<graph>[^]]+)\]"
        for dn in inode:
            n = inode[dn]
            n["ldev"] = {}
            r1 = re.search(reg, n["dn"])
            if r1 is not None:
                n["graph"] = r1.group("graph")
                n["contract"] = r1.group("contract")
            else:
                # ok to continue even with unknown graph/contract names
                logger.debug("failed to parse dn from vnsNodeInst(%s)"%n["dn"])
                n["graph"] = "?"
                n["contract"] = "?"

        # map ldev to inode object
        for dn in rs_inode_to_ldevctx:
            rs = rs_inode_to_ldevctx[dn]
            if rs["tDn"] not in ldevctx:
                logger.debug("vnsRsNodeInstToLDevCtx(%s) tDn(%s) missing"%(
                    rs["dn"], rs["tDn"]))
                continue
            pdn = re.sub("/rsNodeInstToLDevCtx$", "", rs["dn"])
            if pdn not in inode:
                logger.debug("rsNodeInstToLDev(%s) parent(%s) not found"%(
                    rs["dn"], pdn))
            else:
                inode[pdn]["ldev"] = ldevctx[rs["tDn"]]["ldev"]

        # create final graph info
        for dn in inode:
            l = inode[dn]
            if l["graph"] not in self.graphs: self.graphs[l["graph"]] = {}
            if l["contract"] not in self.graphs[l["graph"]]:
                self.graphs[l["graph"]][l["contract"]] = {}
            self.graphs[l["graph"]][l["contract"]][l["dn"]] = l

# ----------------------------------------------------------------------------
# actrlFilter Object
# ----------------------------------------------------------------------------
class ActrlFilter(object):
    
    def __init__(self, args, actrl):
        self.actrl = actrl
        self.results = {}  # results[node][prio][vnid]=[list of rules]
        self.flt_cache = {} # caceh result of parsed filters
        # filters
        self.filtered_results = 0   # number of entries after filters   
        self.exact_match = (not args.checkMask) # 'lazy' filter
        self.epgs = []
        self.depgs = []
        self.sepgs = []
        self.protocols = []
        self.ports = []
        self.sports = []
        self.dports = []
        self.contracts = []

        # filter inital results based on vnid/vrf-name
        if args.vrf:
            # args is either an integer for vnid or name in format <tenant:vrf>
            # could theoretically be overlay-1 but at this time no support
            # for filtering on overlay-1.  If provided value is an int then 
            # assuming vnid
            filter_vrfs = []
            for v in args.vrf:
                try:
                    vnid = int(v)
                    filter_vrfs.append(vnid)
                    continue
                except ValueError as e: pass
                if "name::%s" % v in actrl.vrfs:
                    filter_vrfs.append(actrl.vrfs["name::%s"%v]["vnid"])
                else:
                    logging.error("vrfs \"%s\" not found" % v)
            
            # only add matching vrfs to initial results
            for node_id in actrl.nodes:
                self.results[node_id] = {}
                node = actrl.nodes[node_id]
                for prio in node.rules:
                    for vnid in node.rules[prio]:
                        for v in filter_vrfs:
                            if int(vnid) == v: 
                                if prio not in self.results[node_id]: 
                                    self.results[node_id][prio] = {}
                                self.results[node_id][prio][vnid] = \
                                    node.rules[prio][vnid]

        # no vrf filter - set initial results to match rule list
        else: 
            for node_id in actrl.nodes:
                node = actrl.nodes[node_id]
                self.results[node_id] = node.rules 
 
        # based on arguments, build filter list
        filters = []        
        if args.epg:
            filters.append(self.filter_epg)
            self.epgs = self.get_pcTags(args.epg)
        if args.sepg:
            filters.append(self.filter_sepg)
            self.sepgs = self.get_pcTags(args.sepg)
        if args.depg:
            filters.append(self.filter_depg)
            self.depgs = self.get_pcTags(args.depg)
        if args.nonzero: filters.append(self.filter_nonzero)
        if args.incr: filters.append(self.filter_increment)
        if args.prot:
            filters.append(self.filter_protocol)
            # convert each protocol 'int' value to string
            for p in args.prot:
                self.protocols.append(protocol_to_str(p))
        if args.port:
            filters.append(self.filter_port)
            # convert each port 'int' value to string
            for p in args.port:
                self.ports.append(str_to_port(p))
        if args.sport:
            filters.append(self.filter_sport)
            # convert each port 'int' value to string
            for p in args.sport:
                self.sports.append(str_to_port(p))
        if args.dport:
            filters.append(self.filter_dport)
            # convert each port 'int' value to string
            for p in args.dport:
                self.dports.append(str_to_port(p))
        if args.contract:
            filters.append(self.filter_contract)
            self.contracts = args.contract

        # loop through pipeline results and apply filters (if any)
        for node_id in self.results:
            for prio in self.results[node_id]:
                for vnid in self.results[node_id][prio]:
                    for r in self.results[node_id][prio][vnid]:
                        ignore = False
                        if node_id not in self.actrl.nodes: 
                            logging.warn("node %s not found in actrl"%node_id)
                            continue
                        node = self.actrl.nodes[node_id]
                        # get filter associated to rule and add ptr to rule
                        if r["fltId"] in node.filters:
                            r["_filter"] = node.filters[r["fltId"]]

                        # check rule against all filters
                        for f in filters:
                            if not f(r, node=node):
                                ignore = True
                                break
                        # set ignore flag for rule
                        r["_ignore"] = ignore
                        if not ignore: 
                            self.filtered_results+=1
        logging.debug("Filtered result count: %s" % self.filtered_results)

    def get_epg_name(self, vnid, pcTag):
        """ return string for epg name based on vnid+ pcTag """
        # try to convert vnid/pcTag from unicode to int ('any' exception)
        try:
            vnid = int(vnid)
            pcTag = int(pcTag)
        except: pass
        if vnid in self.actrl.epgs:
            if pcTag in self.actrl.epgs[vnid]:
                return "%s(%s)" % (self.actrl.epgs[vnid][pcTag],pcTag)
        # check if pcTag is in unique list
        if pcTag in self.actrl.unique_epgs:
            return "%s(%s)" % (self.actrl.unique_epgs[pcTag], pcTag)
        return "epg:%s" % pcTag

    def get_pcTags(self, epgs):
        """
        receive list of epgs in integer or DN format and return list of 
        corresponding {"vnid":<int>,"pcTag":<int>} values.  If integer
        is provided, then 'vnid' is None.
        shared services pcTags can be in multiple vrfs, so vnid set to 0
        for any shared services values
        """
        # build index of dn -> scope/vnid mapping
        tmp = {}
        for vnid in self.actrl.epgs:
            for pcTag in self.actrl.epgs[vnid]:
                tmp[self.actrl.epgs[vnid][pcTag]] = (vnid, pcTag)
        ret = []
        for e in epgs:
            # valid epg DN always includes tenant so starts with tn-...
            if "tn-" in e:
                if e in tmp: 
                    vnid = tmp[e][0]
                    pcTag = tmp[e][1]
                    if pcTag>=UNIQUE_PCTAG_MIN and pcTag<=UNIQUE_PCTAG_MAX:
                        vnid = None # force scope to None for shared epgs
                    ret.append({"vnid":vnid, "pcTag":pcTag})
            # check if epg is integer value
            else:
                try:
                    pcTag = int(e)
                    ret.append({"vnid":None, "pcTag": pcTag})
                except Exception as e: pass
        return ret

    def filter_check_match(self, v1, v2, v3=None):
        """ 
        check value v1 against v2 and return true if match. If v3 is provided
        then assume v2-v3 is range to check against.
        """
        # try to convert all values to integers 
        try:
            v1 = int(v1)
            v2 = int(v2)
            if v3 is not None: v3 = int(v3)
        except Exception as e: pass
        if self.exact_match:
            # range not applicable for exact_match
            if v1 == v2: return True
            else: return False
        if v2 == "unspecified" or \
            ((type(v2) is str or type(v2) is unicode) and len(v2) ==0) \
            or v2 == "any":
            # v2 is unspecified, empty string, or 'any'
            return True
        elif v1 == "unspecified" or \
            ((type(v1) is str or type(v1) is unicode) and len(v1) ==0) \
            or v1 == "any":
            # v1 is unspecified, empty string, or 'any'
            return True
        else:
            # check for exact match on single value or within range 
            if v3 is not None:
                if v1>=v2 and v1<=v3: return True
                return False
            elif v1 == v2: return True
        return False

    def filter_nonzero(self, rule, node=None):
        """ filter non-zero rule, return false if stat not found """
        # stat indexed by rule  dn
        if node is None: return False
        if rule["dn"] in node.stats:
            stat = node.stats[rule["dn"]]
            try: 
                if int(stat["ingrPktsCum"])>0: return True
            except Exception as e: pass
            try:
                if int(stat["egrPktsCum"])>0: return True
            except Exception as e: pass
            try:
                if int(stat["pktsCum"])>0: return True
            except Exception as e: pass
        return False
    
    def filter_increment(self, rule, node=None):
        """ filter increment rule, return false if stat not found """
        # stat indexed by rule  dn
        if node is None: return False
        if rule["dn"] in node.stats:
            stat = node.stats[rule["dn"]]
            try: 
                if int(stat["ingrPktsLast"])>0: return True
            except Exception as e: pass
            try:
                if int(stat["egrPktsLast"])>0: return True
            except Exception as e: pass
            try:
                if int(stat["pktsLast"])>0: return True
            except Exception as e: pass
        return False

    def filter_epg(self, rule, node=None):
        """ filter epg by calling filter_sepg and filter_depg """
        if self.filter_sepg(rule, self.epgs) or \
            self.filter_depg(rule, self.epgs):
            return True
        return False

    def filter_sepg(self, rule, override_values=None, node=None):
        """ filter source epg """
        if override_values is None: override_values = self.sepgs
        pcTag = rule["sPcTag"]
        vnid = rule["scopeId"]
        for v in override_values:
            if self.filter_check_match(pcTag, v["pcTag"]):
                # check vrf if not None (not shared service)
                if v["vnid"] is None or \
                    self.filter_check_match(vnid, v["vnid"]):
                    return True
        return False

    def filter_depg(self, rule, override_values=None, node=None):
        """ filter dest epg """
        if override_values is None: override_values = self.depgs
        pcTag = rule["dPcTag"]
        vnid = rule["scopeId"]
        for v in override_values:
            if self.filter_check_match(pcTag, v["pcTag"]):
                # check vrf if not None (not shared service)
                if v["vnid"] is None or \
                    self.filter_check_match(vnid, v["vnid"]):
                    return True
        return False
 
    def filter_protocol(self, rule, node=None):
        """ 
        filter protocol
        this is based on rule so return True if any filter matches.
        return False if filter not found
        """
        if "_filter" not in rule: return False
        for f in rule["_filter"]:
            prot = f["prot"]
            for p in self.protocols:
                if self.filter_check_match(prot, p): return True
        return False

    def filter_port(self, rule, node=None):
        """ filter port by calling filter_sport and filter_dport """
        if self.filter_sport(rule, self.ports) or \
            self.filter_dport(rule, self.ports):
            return True
        return False

    def filter_sport(self, rule, override_values=None, node=None):
        """ filter source port """
        if override_values is None: override_values = self.sports
        if "_filter" not in rule: return False
        for f in rule["_filter"]:
            fromPort = f["sFromPort"]
            toPort = f["sToPort"]
            for v in override_values:
                if self.filter_check_match(v, fromPort, toPort): return True
        return False

    def filter_dport(self, rule, override_values=None, node=None):
        """ filter destination port """
        if override_values is None: override_values = self.dports
        if "_filter" not in rule: return False
        for f in rule["_filter"]:
            fromPort = f["dFromPort"]
            toPort = f["dToPort"]
            for v in override_values:
                if self.filter_check_match(v, fromPort, toPort): return True
        return False

    def filter_contract(self, rule, node=None):
        """ filter contract
        return true only if contract for rule matches filter contracts
        """
        return (rule["contract"] is not None and \
                rule["contract"] in self.contracts)

    def print_fmt(self):
        """ print format string, different when running on leaf vs. apic """

        # if only node_id in self.actrl.nodes is '0' then running on the leaf
        on_leaf = len(self.actrl.nodes)==1 and "0" in self.actrl.nodes

        # format
        # [id:prio] [vrf:<vrf>] (dis) action 
        #    flt:prot sepg flt:sport depg flt:dport [hit=0][contract=str]
        # (cont) flt:prot ...
        #    (dis) destgrp-x vrf:x ip:x mac: 
        if on_leaf:
            fmt = "Key:\n[prio:RuleId] [vrf:{str}] action protocol "
            fmt+= "src-epg [src-l4] dst-epg [dst-l4] [flags]"
            if SHOW_CONTRACT: fmt+= "[contract:{str}] "
            fmt+= "[hit=count]\n"
            print fmt
        else:
            fmt = "Key:\n[node:nodeId] [prio:RuleId] [vrf:{str}] action "
            fmt+= "protocol "
            fmt+= "src-epg [src-l4] dst-epg [dst-l4] [flags] "
            if SHOW_CONTRACT: fmt+= "[contract:{str}] "
            fmt+= "[hit=count]\n"
            print fmt

    def print_results(self, node_id):
        """ print filtered results """
       
        # format
        # [id:prio] [vrf:<vrf>] (dis) action 
        #        flt:prot sepg flt:sport depg flt:dport [contract:{str}] [hit=0]
        # (cont) flt:prot ...
        #        (dis) destgrp-x vrf:x ip:x mac: 
        if node_id == "0": node_hdr = ""
        else: node_hdr = "[node:%s] " % node_id

        if node_id not in self.results: 
            logging.warn("node %s not found in filtered results"%node_id)
            return
        node = self.actrl.nodes[node_id]
        for prio in sorted(self.results[node_id].keys()):
            for vnid in self.results[node_id][prio]:
                # map vnid to vrf
                if "vnid::%s" % vnid in self.actrl.vrfs:
                    vrf = "%s" % self.actrl.vrfs["vnid::%s"%vnid]["name"]
                else: vrf = "%s" % vnid
                for r in self.results[node_id][prio][vnid]:
                    if "_ignore" in r and r["_ignore"]: continue
                    sepg = self.get_epg_name(vnid, r["sPcTag"])
                    depg = self.get_epg_name(vnid, r["dPcTag"])
                    hdr = ["%s[%s:%s] [vrf:%s] " % (node_hdr,prio,r["id"],vrf)]
                    if r["operSt"]!="enabled": hdr.append("(%s) "% r["operSt"])
                    hdr.append("%s" % r["action"])
                    # check qos flags for markDscp and qosGrp
                    if r["qosGrp"] != "unspecified":
                        hdr.append(",set:%s" % r["qosGrp"])
                    if r["markDscp"] != "unspecified":
                        hdr.append(",markDscp:%s" % r["markDscp"])
                    hdr = "".join(hdr)

                    # initial stats (set to ? if not found)
                    hits = "[hit=?]"
                    if r["dn"] in node.stats:
                        stat = node.stats[r["dn"]]
                        # ingress/egress for NS/Donner.  No direction for tahoe
                        if "pktsCum" in stat and stat["pktsCum"]>0:
                            last = int(stat["pktsLast"])
                            if last>0:
                                hits = "[hit=%s,+%s]" % (stat["pktsCum"], last)
                            else: 
                                hits = "[hit=%s]" % stat["pktsCum"]
                        else:
                            igr_hits = stat["ingrPktsCum"]
                            egr_hits = stat["egrPktsCum"]
                            igr_last = int(stat["ingrPktsLast"])
                            egr_last = int(stat["egrPktsLast"])
                            if igr_last>0: igr_hits="%s,+%s"%(igr_hits,igr_last)
                            if egr_last>0: egr_hits="%s,+%s"%(egr_hits,egr_last)
                            hits = "[ing:hit=%s][egr:hit=%s]" % (igr_hits,
                                egr_hits)

                    # contract information (set to ? if not found)
                    if SHOW_CONTRACT:
                        if r["dn"] in self.actrl.contracts: 
                            contract = "[contract:%s]" % (
                                            self.actrl.contracts[r["dn"]])
                        else:
                            contract="[contract:?]"
                    else: contract =""

                    # padding for multiple lines
                    hpad = '{0:>{num}}'.format(" ",num=len(hdr))

                    # get entry for all filters
                    if "_filter" not in r: 
                        ff = self.format_filter(None, sepg, depg)
                        print hdr, ff, contract, hits
                    else: 
                        fcount = 0
                        for f in r["_filter"]:
                            ff = self.format_filter(f, sepg, depg)
                            if fcount==0:
                                print hdr, ff, contract, hits
                            else:
                                print hpad, ff
                            fcount+=1

                    # get redir details (1 or more dests)
                    if "redir" in r["action"] and r["dn"] in node.redirs:
                        redir = node.redirs[r["dn"]]
                        disabled = "operSt" not in redir or \
                                    redir["operSt"]=="disabled"
                        reason = redir["operStQual"]
                        grp = redir["id"]
                        for d in redir["dests"]:
                            f = "destgrp-%s " % grp 
                            if d["operSt"] == "disabled":
                                f+= "(disabled %s) " % d["operStQual"]
                            elif disabled:
                                f+= "(disabled %s) " % reason
                            f+= "vrf:%s ip:%s mac:%s bd:%s" % (
                                d["vrf"], d["ip"], d["vMac"], d["bd"]
                            )
                            print hpad, f

                    # get redir details (1 or more dests)
                    if "copy" in r["action"] and r["dn"] in node.copys:
                        cp = node.copys[r["dn"]]
                        disabled = "operSt" not in cp or \
                                    cp["operSt"]=="disabled"
                        reason = cp["operStQual"]
                        grp = cp["id"]
                        for d in cp["dests"]:
                            f = "destgrp-%s " % grp 
                            if d["operSt"] == "disabled":
                                f+= "(disabled %s) " % d["operStQual"]
                            elif disabled:
                                f+= "(disabled %s) " % reason
                            f+= "bd:%s tep:%s" % (d["bdVnid"], d["tepIp"])
                            print hpad, f

    def format_filter(self, flt, sepg, depg):
        """ format filter object, return defaults if flt is None """
        if flt is None:
            return "? %s %s" % (sepg, depg)
        fstr = []
        # check etherT 
        if flt["etherT"] == "unspecified":
            fstr.append("any %s %s" % (sepg, depg))
        elif flt["etherT"] in ["ip", "ipv4", "ipv6"]:
            fstr.append("%s " % flt["etherT"])
            # match dscp flag
            if flt["matchDscp"] != "unspecified":
                fstr.append("(matchDscp:%s) " % flt["matchDscp"])
            if flt["prot"] == "unspecified": 
                fstr.append("%s %s" % (sepg, depg))
            elif flt["prot"] == "tcp" or flt["prot"] == "udp":
                # if tcp or udp, check l4 port numbers
                # prot src-epg
                fstr.append("%s %s " % (flt["prot"], sepg))
                if flt["sFromPort"] != "unspecified" and \
                    flt["sToPort"] != "unspecified":
                    # src port(s)
                    if flt["sFromPort"] == flt["sToPort"]:
                        fstr.append("eq %s " % flt["sFromPort"])
                    else:
                        fstr.append("range %s-%s " % (flt["sFromPort"],
                            flt["sToPort"]))
                # dst-epg
                fstr.append("%s " % depg)
                if flt["dFromPort"] != "unspecified" and \
                    flt["dToPort"] != "unspecified":
                    # dst port(s)
                    if flt["dFromPort"] == flt["dToPort"]:
                        fstr.append("eq %s " % flt["dFromPort"])
                    else:
                        fstr.append("range %s-%s " % (flt["dFromPort"],
                            flt["dToPort"]))
                # add tcp flags
                if flt["prot"] == "tcp":
                    if flt["tcpRules"] != "unspecified" and \
                        len(flt["tcpRules"])>0:
                        fstr.append("(%s) " % flt["tcpRules"])
                    if flt["stateful"] == "yes": fstr.append("stateful ")
                
            elif flt["prot"] == "icmp":
                # check icmp fields
                fstr.append("%s " % flt["prot"])
                if flt["icmpv4T"] != "unspecified": 
                    fstr.append("%s " %flt["icmpv4T"])
                fstr.append("%s %s" % (sepg, depg))
            elif flt["prot"] == "icmpv6":
                # check icmp fields
                fstr.append("%s " % flt["prot"])
                if flt["icmpv6T"] != "unspecified": 
                    fstr.append("%s " %flt["icmpv6T"])
                fstr.append("%s %s" % (sepg, depg))
            else:
                fstr.append("%s " % flt["prot"])
                fstr.append("%s %s " % (sepg, depg))
    
            # apply frag at end (only applicable to ip)
            if flt["applyToFrag"] == "yes":
                fstr.append("frag ")
 
        # special check for arp (arpOpc)
        elif flt["etherT"] == "arp":
            fstr.append("%s" % flt["etherT"])
            if flt["arpOpc"]!="unspecified":fstr.append("-%s" % flt["arpOpc"])
            fstr.append(" %s %s" % (sepg, depg))

        # non-arp and non-ip filter
        else:
            fstr.append("%s %s %s" % (flt["etherT"], sepg, depg))
       
        return "".join(fstr)

    def print_graph(self):
        """ print actrl.graphs if enabled (future filtering) """
        if not SHOW_GRAPH: return
        if len(self.actrl.graphs)==0: return

        # format
        # Graph <graph-name>:
        #   contract: <contract-name>
        #   Node: <node-name>
        #       funcType:<>, routingMode:<>, isCopy:<>, lDev:<>
        #       Device: ldev.name (state: cdev.state)
        #           lif.name:cif.name (state: cif.operSt) encap:lif.encap \
        #           bd: lifctx.bd path:cif.path
        print "\n"
        print "# Service Graph Information"
        for g in self.actrl.graphs:
            print "\n[Graph:%s]" % g
            for c in self.actrl.graphs[g]:
                print "  contract: %s" % c
                for dn in self.actrl.graphs[g][c]:
                    inode = self.actrl.graphs[g][c][dn]
                    print "  node: %s" % inode["name"]
                    print "    %s" % ", ".join([
                        "funcType:%s" % inode["funcType"],
                        "routingMode:%s" % inode["routingMode"],
                        "isCopy:%s" % inode["isCopy"],
                        "lDev:%s" % inode["ldev"].get("name","?"),
                    ])
                    if "cdev" not in inode["ldev"]: continue
                    for cdev_dn in inode["ldev"]["cdev"]:
                        cdev = inode["ldev"]["cdev"][cdev_dn]
                        print "    %s" % " ".join([
                            "Device: %s" % cdev.get("name", "?"),
                            "(state: %s)" % cdev.get("state", "?"),
                        ])  
                        if "cif" not in cdev or len(cdev["cif"])==0: continue
                        for cif_dn in cdev["cif"]:
                            cif = cdev["cif"][cif_dn]
                            lif = cif.get("lif", {})
                            lifctx = lif.get("lifctx", {})
                            cif_name = cif.get("name", "?")
                            cif_state = cif.get("operSt", "?")
                            cif_path = cif.get("path", "?")
                            lif_name = lif.get("name", "?")
                            lif_encap = lif.get("encap", "?")
                            lifctx_bd = lifctx.get("bd", "?")
                            name = cif_name
                            if cif_name != lif_name: 
                                name = "%s:%s" % (cif_name, lif_name)
                            print "      %s" % " ".join([
                                name,
                                "(state:%s)" % cif_state,
                                "encap:%s" % lif_encap,
                                "bd:%s" % lifctx_bd,
                                "path:%s" % cif_path
                            ])
                            
# ----------------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------------
if __name__ == "__main__":

    import argparse

    desc = """
  This script checks zoning rules, filters, and statistics and correlates with 
  EPG names. The results are printed in NXOS/IOS-like ACL syntax.
    """

    offlineHelp="""
    Use this option when executing the script on offline data. 
    If not set, this script assumes it is executing on a live 
    apic/leaf and will query tables directly.
    """
    cacheHelp="""
    When executing in offline mode, the cache directory is the location where
    compressed files are extracted. The default is '%s'.
    """ % CACHE_DIR 
    filterNodeHelp="""
    display entries specific to one or more leaf nodes
    """
    filterProtoHelp="""
    display entries with specific protocol. Following strings are supported: 
    (icmp, igmp, tcp, egp, igp, udp, icmpv6, eigrp, ospf, pim, l2tp)
    """
    filterCheckMaskHelp = """
    By default, filtering uses a 'lazy' match which will match attributes with
    exact value provided, ignoring corresponding mask. To match values that 
    fall within a range based on the TCAM mask value, then use --checkMask
    option.
    """
    filterOptionDesc="""
    Multiple values for the same option can be listed and will be 'OR' together
    (ex. --sclass 5 10, which displays source class values of 5 or 10). 
    Combining multiple logical options will be 'AND' together.
    """
    filterOptionEpg="""
    The integer pcTag or DN name can be provided. Note the dn is a partial dn in
    the form tn-<tenant>/ap-<applicationProfile>/epg-<epg>
    """
    filterOptionVrf="""
    The integer vnid of the vrf can be provided or the vrf name in the form
    <tenant>:<vrf>
    """
    filterContractHelp="""
    display only rules that match a specific contract. The name of the
    contract is in the form uni/tn-<tenant>/brc-<contract>
    """
    graphHelp = """
    do not display graph information. Note, graph information is only captured
    when the script is executed on the APIC
    """

    parser = argparse.ArgumentParser(description=desc,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        )
    parser.add_argument("--offline", action="store", dest="offline",
        help=offlineHelp)
    parser.add_argument("--offlineHelp", action="store_true", dest="ohelp",
        help="print further offline help instructions")
    parser.add_argument("--noNames", action="store_true", dest="noNames",
        help="do not resolve tenant nor EPG names")
    parser.add_argument("--noContract", action="store_true", dest="noContract",
        help="do not resolve actrlRule contract names")
    parser.add_argument("--noGraph", action="store_true", dest="noGraph",
        help=graphHelp)
    parser.add_argument("--cache", action="store", dest="cache",
        help=cacheHelp, default=CACHE_DIR)
    parser.add_argument("--debug", action="store", help="debug level",
        dest="debug", default="INFO", choices=["debug", "info", "warning",
        "error", "critical"])

    fgroup = parser.add_argument_group("Filter options", 
        description=filterOptionDesc)
    fgroup.add_argument("--nz","--nonzero", action="store_true", dest="nonzero",
        help="display only entries with non-zero hits")
    fgroup.add_argument("--incremented", action="store_true", dest="incr",
        help="display only entries that have incremented since last checked")
    fgroup.add_argument("--node", action="store", dest="nodes", 
        help=filterNodeHelp, nargs="+", default=[])
    fgroup.add_argument("--contract", action="store", dest="contract",
        help=filterContractHelp, nargs="+", default=[])
    fgroup.add_argument("--vrf", action="store", dest="vrf", 
        help="display entries for a specific vrf. %s" % filterOptionVrf,
        nargs="+")
    fgroup.add_argument("--epg", action="store", dest="epg",
        help="display entires for specific EPG. %s" % filterOptionEpg,
        nargs="+")
    fgroup.add_argument("--sepg", action="store", dest="sepg",
        help="display entires for specific EPG. %s" %filterOptionEpg,
        nargs="+")
    fgroup.add_argument("--depg", action="store", dest="depg",
        help="display entires for specific EPG. %s" % filterOptionEpg,
        nargs="+")
    fgroup.add_argument("--protocol", action="store", dest="prot",
        help=filterProtoHelp,
        nargs="+")
    fgroup.add_argument("--port", action="store", dest="port", type=int,
        help="display entries with specific src or dst L4 port",
        nargs="+")
    fgroup.add_argument("--sport", action="store", dest="sport", type=int,
        help="display entries with specific src L4 port",
        nargs="+")
    fgroup.add_argument("--dport", action="store", dest="dport", type=int,
        help="display entries with specific dst L4 port",
        nargs="+")
    fgroup.add_argument("--checkMask", action="store_true", dest="checkMask",
        help=filterCheckMaskHelp)

    # parse arguments
    args = parser.parse_args()

    # configure logging for debuging
    logger = logging.getLogger("")
    logger.setLevel(logging.WARNING)
    logger_handler = logging.StreamHandler(sys.stdout)

    # set debug level
    args.debug = args.debug.upper()
    if args.debug == "DEBUG"        : logger.setLevel(logging.DEBUG)
    elif args.debug == "INFO"       : logger.setLevel(logging.INFO)
    elif args.debug == "WARNING"    : logger.setLevel(logging.WARNING)
    elif args.debug == "ERROR"      : logger.setLevel(logging.ERROR)
    elif args.debug == "CRITICAL"   : logger.setLevel(logging.CRITICAL)

    # set different logging outputs based on debug level
    if args.debug == "DEBUG":
        fmt ="%(asctime)s.%(msecs).03d %(levelname)-8s %(filename)"
        fmt+="16s:(%(lineno)d): %(message)s"
        logger_handler.setFormatter(logging.Formatter(
            fmt=fmt,
            datefmt="%Z %Y-%m-%d %H:%M:%S")
        )
        logger.addHandler(logger_handler)
    else:
        fmt = "%(levelname)-8s %(message)s"
        logger_handler.setFormatter(logging.Formatter(fmt=fmt))
        logger.addHandler(logger_handler)


    #offline-help
    if args.ohelp:
        # use remap only for offline help (automatically applied for online)
        icurl_cli = "\n"
        for c in EPG_CLASSES + VRF_CLASSES + ACTRL_CLASSES + CONTRACT_CLASSES \
            + GRAPH_CLASSES:
            icurl_cli+= "  icurl http://127.0.0.1:7777/api/class/%s.json"%c
            icurl_cli+= " > /tmp/off_%s.json 2> /dev/null\n" % c

        offlineOptionDesc="""
  Offline mode expects a .tgz file.  For example:
  %s --offline ./offline_data.tgz

  When executing in offline mode, ensure that all required data is present in
  input tar file. For best results, collect information for all tables using
  the filenames used below.  
  Once all commands have completed, the final tar file can be found at:
  /tmp/offline_data.tgz

  bash -c '
  %s
  # compress and combine files
  rm /tmp/offline_data.tgz
  tar -zcvf /tmp/offline_data.tgz /tmp/off_*
  rm /tmp/off_*
  '""" % (__file__, icurl_cli)
        print offlineOptionDesc
        sys.exit()
       
    # if not args.offline, then test connectivity to apic
    if not args.offline:
        uni = get_class_data("polUni")
        if uni is None or len(uni)==0:
            msg = "\nError: Trying to execute on an unsupported device. "
            msg+= "This script is intended to run on the apic, leaf, or on"
            msg+= " offline data.  Use -h for help.\n"
            sys.exit(msg)
   
    # set build/show contract 
    if args.noContract: SHOW_CONTRACT = False
    if args.noGraph: SHOW_GRAPH = False
        
    total_time_start = time.time()
    # filter nodes is only filtering performed by Actrl 
    # (to return smaller data sets...)
    actrl = Actrl(args)         
    actrlFilter = ActrlFilter(args, actrl)
    actrlFilter.print_fmt()
    for node_id in sorted(actrlFilter.results.keys()):
        actrlFilter.print_results(node_id)
    actrlFilter.print_graph()
    logging.debug("total time: %s" % td(total_time_start, time.time()))
