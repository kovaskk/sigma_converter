#!//usr/bin/python3
import argparse
import collections
import os
import configparser
import bs4, re
import json
import base64
from xml.etree.ElementTree import Element, SubElement, Comment, tostring
import yaml
from ruamel.yaml import YAML

debug = False

class Var:
    __slots__ = ("name", "neg")
    def __init__(self, name, neg=False):
        self.name = name
        self.neg = neg
    def __repr__(self): return f"{'not ' if self.neg else ''}{self.name}"

class Node: pass
class NVar(Node):
    __slots__=("name",)
    def __init__(self, name): self.name=name
class NNot(Node):
    __slots__=("x",)
    def __init__(self, x): self.x=x
class NAnd(Node):
    __slots__=("l","r")
    def __init__(self, l, r): self.l, self.r = l, r
class NOr(Node):
    __slots__=("l","r")
    def __init__(self, l, r): self.l, self.r = l, r

class Notify(object):
    def __init__(self):
        pass

    def info(self, message):
        print("[#] %s" % message)

    def error(self, message):
        print("[!] %s" % message)
        
    def debug(self, message):
        if debug:
            print("[*] %s" % repr(message)[1:-1])


class BuildRules(object):
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config.read(r'./config.ini')
        self.rules_link = self.config.get('sigma', 'rules_link')
        self.low = self.config.get('levels', 'low')
        self.medium = self.config.get('levels', 'medium')
        self.high = self.config.get('levels', 'high')
        self.critical = self.config.get('levels', 'critical')
        self.no_full_log = self.config.get('options', 'no_full_log')
        self.sigma_guid_email = eval(self.config.get('options', 'sigma_guid_email'), {}, {})
        self.alert_by_email = self.config.get('options', 'alert_by_email')
        self.email_levels = self.config.get('options', 'email_levels')
        self.rule_id_start = int(self.config.get('options', 'rule_id_start'))
        self.rule_id = self.rule_id_start
        self.out_file = self.config.get('sigma', 'out_file')
        self.track_rule_ids_file = self.config.get('options','rule_id_file')  # file that stores Sigma GUID to Wazuh rule ID mappings
        self.track_rule_ids = self.load_wazuh_to_sigma_id_mappings()  # in memory Dict of self.track_rule_ids_file contents
        self.used_wazuh_ids = self.get_used_wazuh_rule_ids()  # used Wazuh rule IDs used in previous runs
        self.used_wazuh_ids_this_run = []  # new Wazuh rule IDs consummed this run
        self.root = self.create_root()
        self.rule_count = 0
        # monkey patching prettify
        # reference: https://stackoverflow.com/questions/15509397/custom-indent-width-for-beautifulsoup-prettify
        orig_prettify = bs4.BeautifulSoup.prettify
        r = re.compile(r'^(\s*)', re.MULTILINE)

        def prettify(self, encoding=None, formatter="minimal", indent_width=4):
            Notify.debug(self, "Function: {}".format(self.prettify.__name__))
            return r.sub(r'\1' * indent_width, orig_prettify(self, encoding, formatter))

        bs4.BeautifulSoup.prettify = prettify

    def load_wazuh_to_sigma_id_mappings(self):
        """
            Need to track Wazuh rule ID between runs so that any rules dependent
            on these auto generated rules will not be broken by subsequent runs.
        """
        Notify.debug(self, "Function: {}".format(self.load_wazuh_to_sigma_id_mappings.__name__))
        try:
            with open(self.track_rule_ids_file, 'r') as ids:
                return json.load(ids)
        except:
            Notify.error(self, "ERROR loading rule id tracking file: %s" % self.track_rule_ids_file)
            return {}

    def get_used_wazuh_rule_ids(self):
        Notify.debug(self, "Function: {}".format(self.get_used_wazuh_rule_ids.__name__))
        # ids = [str(self.rule_id_start)] # never use the first number
        ids = []
        for k, v in self.track_rule_ids.items():
            for i in v:
                if i not in ids:
                    ids.append(i)
        return ids

    def create_root(self):
        Notify.debug(self, "Function: {}".format(self.create_root.__name__))
        root = Element('group')
        root.set('name', 'sigma,')
        self.add_header_comment(root)
        return root

    def add_header_comment(self, root):
        comment = Comment("""
Author: Brian Kellogg
Sigma: https://github.com/SigmaHQ/sigma
Wazuh: https://wazuh.com
All Sigma rules licensed under DRL: https://github.com/SigmaHQ/sigma/blob/master/LICENSE.Detection.Rules.md
""")
        root.append(comment)

    def update_rule_id_mappings(self, sigma_guid, wid):
        Notify.debug(self, "Function: {}".format(self.update_rule_id_mappings.__name__))
        if sigma_guid in self.track_rule_ids:
            if wid not in self.track_rule_ids[sigma_guid]:
                self.track_rule_ids[sigma_guid].append(wid)
        else:
            self.track_rule_ids[sigma_guid] = [wid]

    def find_unused_rule_id(self, sigma_guid):
        """
            Lets make sure we use a Wazuh rule ID not already assigned to a Sigma GUID
        """
        Notify.debug(self, "Function: {}".format(self.find_unused_rule_id.__name__))
        while True:
            self.rule_id += 1
            wid = str(self.rule_id)
            if wid not in self.used_wazuh_ids:
                if wid not in self.used_wazuh_ids_this_run:
                    self.update_rule_id_mappings(sigma_guid, wid)
                    return wid

    def find_wazuh_id(self, sigma_guid):
        """
            Has this Sigma rule already been converted and assigned a Wazuh rule ID?
            If so, we need to keep it the same.
        """
        Notify.debug(self, "Function: {}".format(self.find_wazuh_id.__name__))
        if sigma_guid in self.track_rule_ids:
            for wid in self.track_rule_ids[sigma_guid]:
                if wid not in self.used_wazuh_ids_this_run:
                    return wid
        wid = self.find_unused_rule_id(sigma_guid)
        return wid

    def init_rule(self, level, sigma_guid):
        Notify.debug(self, "Function: {}".format(self.init_rule.__name__))
        rule = SubElement(self.root, 'rule')
        wid = self.find_wazuh_id(sigma_guid)
        self.used_wazuh_ids_this_run.append(wid)
        rule.set('id', wid)
        rule.set('level', self.get_level(level))
        self.rule_count += 1
        return rule

    def convert_field_name(self, product, field):
        Notify.debug(self, "Function: {}".format(self.convert_field_name.__name__))
        if product in self.config.sections():
            if field in self.config[product]:
                return self.config[product][field]
        return "full_log"  # target full log if we cannot find the field

    def if_ends_in_space(self, value, is_b64):
        """
            spaces at end of logic are being chopped, therefore hacking this fix
        """
        Notify.debug(self, "Function: {}".format(self.if_ends_in_space.__name__))
        if value.startswith('(?i)'):  # if value start with this, it is a Sigma regex, remove it as it will be added again
            value = value[4:]
        if value.endswith(' '):
            value = '(?:' + value + ')'
        if is_b64:
            return value
        return '(?i)' + value

    def handle_full_log_field(self, value):
        """
            We do not want to honor Sigma startswith and endswith logic if we use the full_log field
        """
        Notify.debug(self, "Function: {}".format(self.handle_full_log_field.__name__))
        if value.startswith('^'):
            value = value[1:]
        if value.endswith('$') and not value[-2:] == r'\$':
            value = value[:-1]
        return value

    def add_logic(self, rule, product, field, negate, value, is_b64):
        Notify.debug(self, "Function: {}".format(self.add_logic.__name__))
        logic = SubElement(rule, 'field')
        name = self.convert_field_name(product, field)
        logic.set('name', name)
        logic.set('negate', negate)
        logic.set('type', 'pcre2')
        value = str(value).replace(r'\?', r'.').replace(r'\\', r'\\+') # This does replace escaped '*'s, FIX UP NEEDED
        value = re.sub(r'(?:\\\\\+){2,}', r'\\\\+', value) # cleanup multiple '\\+' back to back
        if name == 'full_log':
            logic.text = self.if_ends_in_space(self.handle_full_log_field(value), is_b64).replace(r'\*', r'.+') # assumption is all '*' are wildcards
        else:
            logic.text = self.if_ends_in_space(value, is_b64).replace(r'\*', r'.+') # assumption is all '*' are wildcards

    def get_level(self, level):
        Notify.debug(self, "Function: {}".format(self.get_level.__name__))
        if level == "critical":
            return self.critical
        if level == "high":
            return self.high
        if level == "medium":
            return self.medium
        return self.low

    def add_options(self, rule, level, sigma_guid):
        Notify.debug(self, "Function: {}".format(self.add_options.__name__))
        if self.no_full_log == 'yes':
            options = SubElement(rule, 'options')
            options.text = "no_full_log"
        if self.alert_by_email == 'yes' and (level in self.email_levels):
            options = SubElement(rule, 'options')
            options.text = "alert_by_email"
            return
        if sigma_guid in self.sigma_guid_email:
            if_sid = SubElement(rule, 'options')
            if_sid.text = "alert_by_email"

    def add_mitre(self, rule, tags):
        Notify.debug(self, "Function: {}".format(self.add_mitre.__name__))
        mitre = SubElement(rule, 'mitre')
        for t in tags:
            mitre_id = SubElement(mitre, 'id')
            mitre_id.text = t

    def add_sigma_author(self, rule, sigma_rule_auther):
        Notify.debug(self, "Function: {}".format(self.add_sigma_author.__name__))
        comment = Comment('Sigma Rule Author: ' + sigma_rule_auther)
        rule.append(comment)

    def add_sigma_link_info(self, rule, sigma_rule_link):
        Notify.debug(self, "Function: {}".format(self.add_sigma_link_info.__name__))
        link = SubElement(rule, 'info')
        link.set('type', 'link')
        link.text = (self.rules_link + sigma_rule_link)

    def add_rule_comment(self, rule, misc):
        Notify.debug(self, "Function: {}".format(self.add_rule_comment.__name__))
        comment = Comment(misc.replace('--', ' - '))  # '--' not allowed in XML comment
        rule.append(comment)

    def add_sigma_rule_references(self, rule, reference):
        Notify.debug(self, "Function: {}".format(self.add_sigma_rule_references.__name__))
        refs = 'References: \n'
        for r in reference:
            refs += '\t' + r + '\n'
        comment = Comment(refs[:-1])
        rule.append(comment)

    def add_description(self, rule, title):
        Notify.debug(self, "Function: {}".format(self.add_description.__name__))
        description = SubElement(rule, 'description')
        description.text = title

    def add_sources(self, rule, sources):
        Notify.debug(self, "Function: {}".format(self.add_sources.__name__))
        log_sources = ""
        for key, value in sources.items():
            if value and not key == 'definition':
                log_sources += value + ","
        groups = SubElement(rule, 'group')
        groups.text = log_sources

    def add_if_group_guid(self, rule, sigma_guid):
        Notify.debug(self, "Function: {}".format(self.add_if_group_guid.__name__))
        if sigma_guid in self.config['if_group_guid']:
            if_sid = SubElement(rule, 'if_group')
            if_sid.text = self.config['if_group_guid'][sigma_guid]
            return True
        return False

    def add_if_sid_guid(self, rule, sigma_guid):
        Notify.debug(self, "Function: {}".format(self.add_if_group.__name__))
        if sigma_guid in self.config['if_sid_guid']:
            if_sid = SubElement(rule, 'if_sid')
            if_sid.text = self.config['if_sid_guid'][sigma_guid]
            return True
        return False

    def add_if_group(self, rule, log_source):
        Notify.debug(self, "Function: {}".format(self.add_if_group.__name__))
        target = ""
        if ('service' in log_source) and (log_source['service'] in self.config['if_group']):
            target = log_source['service']
        elif ('product' in log_source) and (log_source['product'] in self.config['if_group']):
            target = log_source['product']
        if target:
            if_group = SubElement(rule, 'if_group')
            if_group.text = self.config['if_group'][target]
            return True
        return False
        
    def add_if_sid(self, rule, log_source):
        Notify.debug(self, "Function: {}".format(self.add_if_sid.__name__))
        target = ""
        if ('service' in log_source) and (log_source['service'] in self.config['if_sid']):
            target = log_source['service']
        elif log_source['product'] in self.config['if_sid']:
            target = log_source['product']
        if target:
            if_sid = SubElement(rule, 'if_sid')
            if_sid.text = self.config['if_sid'][target]

    def create_rule(self, sigma_rule, sigma_rule_link, sigma_guid):
        Notify.debug(self, "Function: {}".format(self.create_rule.__name__))
        level = sigma_rule['level']
        rule = self.init_rule(level, sigma_guid)
        if 'tags' in sigma_rule:
            self.add_mitre(rule, sigma_rule['tags'])
        self.add_description(rule, sigma_rule['title'])
        self.add_options(rule, level, sigma_rule['id'])
        self.add_sources(rule, sigma_rule['logsource'])
        if_group_guid = self.add_if_group_guid(rule, sigma_guid)
        if not if_group_guid:
            if_sid_guid = self.add_if_sid_guid(rule, sigma_guid)
            if not if_sid_guid and 'product' in sigma_rule['logsource']:
                if_group = self.add_if_group(rule, sigma_rule['logsource'])
                if not if_group:
                    self.add_if_sid(rule, sigma_rule['logsource'])
        return rule

    def write_wazah_id_to_sigman_id(self):
        Notify.debug(self, "Function: {}".format(self.write_wazah_id_to_sigman_id.__name__))
        with open(self.track_rule_ids_file, 'w') as ids:
            ids.write(json.dumps(self.track_rule_ids))
                

    def write_rules_file(self):
        Notify.debug(self, "Function: {}".format(self.write_rules_file.__name__))
        xml = bs4.BeautifulSoup(tostring(self.root), 'xml').prettify()

        # collapse some tags to single lines
        xml = re.sub(r'<id>\n\s+', r'<id>', xml)
        xml = re.sub(r'\s+</id>', r'</id>', xml)

        xml = re.sub(r'<if_sid>\n\s+', r'<if_sid>', xml)
        xml = re.sub(r'\s+</if_sid>', r'</if_sid>', xml)

        xml = re.sub(r'<if_group>\n\s+', r'<if_group>', xml)
        xml = re.sub(r'\s+</if_group>', r'</if_group>', xml)

        xml = re.sub(r'<field(.+)>\n\s+', r'<field\1>', xml)
        xml = re.sub(r'\s+</field>', r'</field>', xml)

        xml = re.sub(r'<description>\n\s+', r'<description>', xml)
        xml = re.sub(r'\s+</description>', r'</description>', xml)

        xml = re.sub(r'<options>\n\s+', r'<options>', xml)
        xml = re.sub(r'\s+</options>', r'</options>', xml)

        xml = re.sub(r'<group>\n\s+', r'<group>', xml)
        xml = re.sub(r'\s+</group>', r'</group>', xml)

        xml = re.sub(r'<info(.+)>\n\s+', r'<info\1>', xml)
        xml = re.sub(r'\s+</info>', r'</info>', xml)

        xml = re.sub(r'</rule></group>', r'</rule>\n</group>', xml)
        xml = xml.replace('<?xml version="1.0" encoding="utf-8"?>\n', '')

        with open(self.out_file, "w", encoding="utf-8") as file:
            file.write(xml)

        self.write_wazah_id_to_sigman_id()


class ParseSigmaRules(object):
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config.read(r'./config.ini')
        self.sigma_rules_dir = self.config.get('sigma', 'directory')
        self.sigma_rules = self.get_sigma_rules()
        self.error_count = 0
        self.converted_total = 0

    def get_sigma_rules(self):
        Notify.debug(self, "Function: {}".format(self.get_sigma_rules.__name__))
        fname = []
        exclude = set(['deprecated'])
        for root, dirs, f_names in os.walk(self.sigma_rules_dir):
            dirs[:] = [d for d in dirs if d not in exclude]
            for f in f_names:
                fname.append(os.path.join(root, f))
        return fname

    def load_sigma_rule(self, rule_file):
        Notify.debug(self, "Function: {}".format(self.load_sigma_rule.__name__))
        try:
            yaml = YAML(typ='safe')
            with open(rule_file) as file:
                sigma_raw_rule = file.read()
            sigma_rule = yaml.load(sigma_raw_rule)
            return sigma_rule
        except:
            self.error_count += 1
            return ""

    def fixup_condition(self, condition):
        """
            Replace spaces with _ when the words constitute a logic operation.
            Allows for easier tokenization.
        """
        Notify.debug(self, "Function: {}".format(self.fixup_condition.__name__))
        if isinstance(condition, list):
            return [tok.replace('1 of them', '1_of')
                        .replace('all of them', 'all_of')
                        .replace('1 of', '1_of')
                        .replace('all of', 'all_of') \
                        .replace('(', ' ( ') \
                        .replace(')', ' ) ')
                    for tok in condition]
        return condition.replace('1 of them', '1_of') \
            .replace('all of them', 'all_of') \
            .replace('1 of', '1_of') \
            .replace('all of', 'all_of') \
            .replace('(', ' ( ') \
            .replace(')', ' ) ')

    def remove_wazuh_rule(self, rules, rule, sid):
        Notify.debug(self, "Function: {}".format(self.remove_wazuh_rule.__name__))
        wid = rule.get('id')
        if wid == str(rules.rule_id - 1):
            rules.rule_id -= 1
        if wid in rules.track_rule_ids[sid]:
            rules.track_rule_ids[sid].remove(wid)
        if wid in rules.used_wazuh_ids_this_run:
            rules.used_wazuh_ids_this_run.remove(wid)
        rules.rule_count -= 1  # decrement count of rules created
        rules.root.remove(rule)  # destroy the extra rule that is created

    def fixup_logic(self, logic, is_regex):
        Notify.debug(self, "Function: {}".format(self.fixup_logic.__name__))
        logic = str(logic)
        # if len(logic) > 2:  # when converting to Wazuh pcre2 expressions, we don't need start and end wildcards
        #     if logic[0] == '*': logic = logic[1:]
        #     if logic[-1] == '*': logic = logic[:-1]
        if is_regex:
            return logic
        else:
            return re.escape(logic)

    def handle_b64offsets_list(self, value):
        Notify.debug(self, "Function: {}".format(self.handle_b64offsets_list.__name__))
        offset1 = ('|'.join([str(base64.b64encode(i.encode('utf-8')), 'utf-8') for i in value])).replace('=', '')
        offset2 = ('|'.join([str(base64.b64encode((' ' + i).encode('utf-8')), 'utf-8') for i in value])).replace('=','')[2:]
        offset3 = ('|'.join([str(base64.b64encode(('  ' + i).encode('utf-8')), 'utf-8') for i in value])).replace('=','')[3:]
        return offset1 + "|" + offset2 + "|" + offset3

    def handle_b64offsets(self, value):
        Notify.debug(self, "Function: {}".format(self.handle_b64offsets.__name__))
        offset1 = (str(base64.b64encode(value.encode('utf-8')), 'utf-8')).replace('=', '')
        offset2 = (str(base64.b64encode((' ' + value).encode('utf-8')), 'utf-8')).replace('=', '')[2:]
        offset3 = (str(base64.b64encode(('  ' + value).encode('utf-8')), 'utf-8')).replace('=', '')[3:]
        return offset1 + "|" + offset2 + "|" + offset3

    def handle_keywords(self, rules, rule, sigma_rule, sigma_rule_link, product, logic, negate, is_b64):
        Notify.debug(self, "Function: {}".format(self.handle_keywords.__name__))
        rules.add_logic(rule, product, "full_log", negate, logic, is_b64)

    def handle_dict(self, d, rules, rule, product, sigma_rule, sigma_rule_link, negate):
        Notify.debug(self, "Function: {}".format(self.handle_dict.__name__))
        for k, v in d.items():
            field, logic, is_b64 = self.convert_transforms(k, v, negate)
            self.is_dict_list_or_not(logic, rules, rule, sigma_rule, sigma_rule_link, product, field, negate, is_b64)
        return rules.create_rule(sigma_rule, sigma_rule_link, sigma_rule['id'])

    def is_dict_list_or_not(self, logic, rules, rule, sigma_rule, sigma_rule_link, product, field, negate, is_b64):
        Notify.debug(self, "Function: {}".format(self.is_dict_list_or_not.__name__))
        if isinstance(logic, list):
            for l in logic:
                rules.add_logic(rule, product, field, negate, l, is_b64)
            return
        rules.add_logic(rule, product, field, negate, logic, is_b64)

    def list_add_unique(self, record, values, key):
        Notify.debug(self, "Function: {}".format(self.list_add_unique.__name__))
        for d in values:
            for k, v in d.items():
                if k == key:
                    v = [v]
                    if isinstance(record[key], list):
                        for i in record[key]:
                            if i not in v:
                                v.append(i)
                    if record[key] not in v:
                        v.append(record[key])
                    return values
        values.append(record)
        return values

    def handle_detection_nested_lists(self, values, record, key, value):
        """
            We can run into lists at various depths in Sigma deteciton logic.
        """
        Notify.debug(self, "Function: {}".format(self.handle_detection_nested_lists.__name__))
        values = []
        if not key.endswith('|all'):
            if isinstance(record[key], list):
                values = self.list_add_unique(record, values, key)
            else:
                if isinstance(value, list):
                    values = self.list_add_unique(record, values, key)
                else:
                    values = self.list_add_unique(record, values, key)
        else:
            values.append(record)
        Notify.debug(self, "Detection values: {}".format(values))
        return values

    def get_detection(self, detection, token):
        """
            Break apart detection logic into dictionaries for use in creating the Wazuh logic.
            e.g. {"fieldname|<startswith|endswith|etc.>": ["something to look for", "another thing to look for"]}
        """
        Notify.debug(self, "Function: {}".format(self.get_detection.__name__))
        record = {}
        values = []
        Notify.debug(self, "Detection: {}".format(detection))
        if isinstance(detection, list):
            for d in detection:
                if isinstance(d, dict):
                    for k, v in d.items():
                        values.extend(self.handle_detection_nested_lists(values, d, k, v))
                else:
                    record[token] = detection
                    values.append(record)
                    break
            return values
        for k, v in detection.items():
            record[k] = v
            Notify.debug(self, "Detection Record: {}".format(record))
        values.append(record)
        Notify.debug(self, "Discovered Detections: {}".format(values))
        return values

    def get_product(self, sigma_rule):
        Notify.debug(self, "Function: {}".format(self.get_product.__name__))
        if 'logsource' in sigma_rule and 'product' in sigma_rule['logsource']:
            return sigma_rule['logsource']['product'].lower()
        return ""

    def handle_list(self, value, is_b64, b64_offset, is_regex, exact_match):
        Notify.debug(self, "Function: {}".format(self.handle_list.__name__))
        if isinstance(value, list):
            if is_b64:
                if b64_offset:
                    return self.handle_b64offsets_list(value)
                return ('|'.join([str(base64.b64encode(i.encode('utf-8')), 'utf-8') for i in value])).replace('=', '')
            if exact_match:
                return '^' + ('$|^'.join([self.fixup_logic(i, is_regex) for i in value])) + '$'
            else:
                return ('|'.join([self.fixup_logic(i, is_regex) for i in value]))
        if is_b64:
            if b64_offset:
                return self.handle_b64offsets(value)
            return str(base64.b64encode(value.encode('utf-8')), 'utf-8').replace('=', '')
        if exact_match:
            return self.fixup_logic('^' + re.escape(str(value)) + '$', True)
        else:
            return self.fixup_logic(value, is_regex)

    def handle_or_to_and(self, value, negate, contains_all, start, end, is_regex, exact_match):
        Notify.debug(self, "Function: {}".format(self.handle_or_to_and.__name__))
        """
            We have to split up contains_all and any negated fields into individual field statements in Wazuh rules
        """
        if (negate == "yes" or contains_all) and isinstance(value, list):
            result = []
            for v in value:
                v = self.fixup_logic(v, is_regex)
                result.append(start + v + end)
            return result
        else:
            return self.handle_list(value, False, False, is_regex, exact_match)
        
    def handle_windash(self, value):
        if isinstance(value, list):
            temp = []
            for v in value:
                temp.append(v.replace('-', '[/-]'))
            value = temp
        else:
            value = value.replace('-', '[/-]')
        return value

    def convert_transforms(self, key, value, negate, rules, product):
        """
            This needs to be refactored to better handle expanding Sigma rule modifiers
            See: https://sigmahq.io/docs/basics/modifiers.html
        """
        Notify.debug(self, "Function: {}".format(self.convert_transforms.__name__))
        if '|' in key:
            field, transform = key.split('|', 1)
            if transform.lower() == 'contains':
                return field, self.handle_or_to_and(value, negate, False, '', '', False, False), False
            if transform.lower() in ['contains|all', 'all']:
                return field, self.handle_or_to_and(value, negate, True, '', '', False, False), False
            
            if transform.lower() in ['contains|windash', 'windash']:
                value = self.handle_windash(value)
                return field, self.handle_or_to_and(value, negate, False, '', '', True, False), False
            if transform.lower() in ['contains|windash|all', 'contains|all|windash', 'windash|all']:
                value = self.handle_windash(value)
                return field, self.handle_or_to_and(value, negate, True, '', '', True, False), False

            if transform.lower() == 'startswith':
                return field, self.handle_or_to_and(value, negate, False, '^(?:', ')', False, False), False
            if transform.lower() == 'endswith':
                return field, self.handle_or_to_and(value, negate, False, '(?:', ')$', False, False), False
            if transform.lower() == "re":
                return field, self.handle_or_to_and(value, negate, False, '', '', True, False), False
            if transform.lower() == "base64offset|contains":
                return field, self.handle_or_to_and(value, negate, False, '', '', False, False), True
            if transform.lower() == "base64|contains":
                return field, self.handle_or_to_and(value, negate, False, '', '', False, False), True
            # if transform.lower() == "cidr":
            #     return field, self.handle_or_to_and(value, negate, False, '', '', False, True), False
        else:
            field = key            
        field_name = rules.convert_field_name(product, field)
        if field_name == 'full_log':
            return key, self.handle_or_to_and(value, negate, False, '', '', False, False), False
        else:
            return key, self.handle_or_to_and(value, negate, False, '', '', False, True), False
    
    def is_list_of_dicts(self, data):
        Notify.debug(self, "Function: {}".format(self.is_list_of_dicts.__name__))
        if isinstance(data, list):
            for i in data:
                if isinstance(i, dict):
                    return True
        return False

    def handle_fields(self, rules, rule, token, negate, sigma_rule,
                      sigma_rule_link, detections, product):
        Notify.debug(self, "Function: {}".format(self.handle_fields.__name__))
        detection = self.get_detection(detections, token)
        Notify.debug(self, "Detections: {}".format(detections))
        Notify.debug(self, "Detection: {}".format(detection))
        for d in detection:
            Notify.debug(self, "Detection: {}".format(d))
            for k, v in d.items():
                field, logic, is_b64 = self.convert_transforms(k, v, negate, rules, product)
                Notify.debug(self, "Logic: {}".format(logic))
                # if not self.is_list_of_dicts(k):
                #     self.handle_keywords(rules, rule, sigma_rule, sigma_rule_link, product, logic, negate, is_b64)
                #     continue
                self.is_dict_list_or_not(logic, rules, rule, sigma_rule, sigma_rule_link, product, field, negate, is_b64)

    def handle_logic_paths(self, rules, sigma_rule, sigma_rule_link, logic_paths):
        Notify.debug(self, "Function: {}".format(self.handle_logic_paths.__name__))
        product = self.get_product(sigma_rule)
        logic_paths = list(filter(None, logic_paths))
        for path in logic_paths:
            negate = "no"
            rule = rules.create_rule(sigma_rule, sigma_rule_link, sigma_rule['id'])
            Notify.debug(self, "Logic Path: {}".format(path))
            path = list(filter(None, path))
            for p in path:
                if isinstance(p, collections.abc.Sequence) and not isinstance(p, str): # kludge to fix token that is an array
                    p = p[0]
                Notify.debug(self, "Token - {} : {}".format(type(p), p))
                Notify.debug(self, "Detection Type: {}".format(type(sigma_rule['detection'])))
                if p == "not":
                    negate = "yes"
                    continue
                self.handle_fields(rules, rule, p, negate,
                                    sigma_rule, sigma_rule_link,
                                    sigma_rule['detection'][p],
                                    product)
                negate = "no"

    def handle_all_of(self, detections, token):
        Notify.debug(self, "Function: {}".format(self.handle_all_of.__name__))
        path = []
        Notify.debug(self, "All of token: {}".format(token))
        if token.endswith('*'):
            for d in detections:
                if d.startswith(token.replace('*', '')):
                    path.extend([d])
        else:
            path.extend([token])
        Notify.debug(self, "All of: {}".format(path))
        return path

    def handle_one_of(self, detections, token, path, negate):
        Notify.debug(self, "Function: {}".format(self.handle_one_of.__name__))
        paths = []
        path_start = path.copy()
        for d in detections:
            if d.startswith(token.replace('*', '')):
                if negate:
                    path_start.extend(["not"])
                path_start.extend([d])
                Notify.debug(self, "One of path: {}".format(path_start))
                if not negate:
                    paths.append(path_start)
                    path_start = path.copy()
                Notify.debug(self, "One of paths: {}".format(paths))
        if negate:
            paths.extend([path_start])
        Notify.debug(self, "One of results: {}".format(paths))
        return paths

    def propagate_nots(self, tokens):
        Notify.debug(self, "Function: {}".format(self.propagate_nots.__name__))
        Notify.debug(self, "Tokens: {}".format(tokens))
        new_tokens = []
        not_found = False
        paren_found_after_not = False
        level = 0
        for t in tokens:
            if not_found and paren_found_after_not and (t not in ['or', 'and', '(', ')']):
                new_tokens.append('not')
            elif t == 'not':
                not_found = True
            elif t == '(' and not_found:
                level += 1
                if level == 1:
                    new_tokens.pop()
                paren_found_after_not = True
            elif t == ')':
                if level > 0:
                    level -= 1
                elif level == 0:
                    not_found = False
                    paren_found_after_not = False
            new_tokens.append(t)
        Notify.debug(self, "New Tokens: {}".format(new_tokens))
        return new_tokens
    
    def reorder_tokens(self, tokens):
        Notify.debug(self, "Function: {}".format(self.reorder_tokens.__name__))
        Notify.debug(self, "Tokens: {}".format(tokens))
        new_tokens = []
        for t in reversed(tokens):
            if t == 'not':
                if len(new_tokens) > 1 and new_tokens[-2] in ['1_of', 'all_of']:
                    new_tokens.insert(-2, t)
                else:
                    new_tokens.insert(-1, t)
            elif t == '1_of':
                new_tokens.insert(-1, t)
            elif t == 'all_of':
                new_tokens.insert(-1, t)
            elif t == '(':
                new_tokens.append(')')
            elif t == ')':
                new_tokens.append('(')
            else:
                new_tokens.append(t)
        Notify.debug(self, "Tokens: {}".format(new_tokens))
        return new_tokens
    
    def reorder_one_ofs(self, tokens):
        Notify.debug(self, "Function: {}".format(self.reorder_one_ofs.__name__))
        tokens_length = len(tokens)
        if tokens_length <= 2:
            return tokens
        if (not tokens[0] == '1_of' and not tokens[1] == '1_of' and 'and' in tokens and tokens_length < 6):
            return tokens
        tokens = self.reorder_tokens(tokens)
        return tokens
    
    def compare_lists(self, list1, list2):
        Notify.debug(self, "Function: {}".format(self.compare_lists.__name__))
        for num2 in list2:
            # If the number is less than any number in the first list, return True
            if any(num1 > num2 for num1 in list1):
                return True
        return False
    
    def reorder_or_and(self, tokens):
        Notify.debug(self, "Function: {}".format(self.reorder_or_and.__name__))
        ors = []
        ands = []
        left_parens = []
        right_parens = []
        for (i, t) in enumerate(tokens):
            if t == 'or':
                ors.append(i)
            elif t == 'and':
                ands.append(i)
            elif t == '(':
                left_parens.append(i)
            elif t == ')':
                right_parens.append(i)
        if self.compare_lists(ors, ands):
            self.reorder_tokens(tokens)

    def _is_op(self, t):
        return t in ("and", "or", "not", "(", ")")

    def _collect_matches(self, detections: dict, prefix: str):
        key = prefix.replace('*', '')
        # исключаем служебный ключ 'condition'
        return sorted([k for k in detections.keys() if k != 'condition' and k.startswith(key)])

    def _expand_macros(self, tokens, detections: dict):
        """ 1_of X* -> (X1 or X2 ...);  all_of X* -> (X1 and X2 ...) """
        out = []
        i = 0
        n = len(tokens)
        while i < n:
            t = tokens[i]
            tl = t.lower()
            if tl in ("1_of", "all_of"):
                if i + 1 >= n:
                    out.append(t);
                    i += 1;
                    continue
                mask = tokens[i + 1]
                matches = self._collect_matches(detections, mask)
                # если совпадений нет — оставим как есть (не должно, но безопасно)
                if not matches:
                    out.extend([t, mask]);
                    i += 2;
                    continue
                out.append("(")
                glue = "or" if tl == "1_of" else "and"
                for j, m in enumerate(matches):
                    out.append(m)
                    if j + 1 < len(matches): out.append(glue)
                out.append(")")
                i += 2
                continue
            out.append(t)
            i += 1
        return out

    def _to_ast(self, tokens):
        """Шунтирующий двор: not > and > or; not — унарный."""
        prec = {"or": 1, "and": 2, "not": 3}
        right_assoc = {"not"}

        def apply(op, stack):
            if op == "not":
                a = stack.pop();
                stack.append(NNot(a))
            else:
                b = stack.pop();
                a = stack.pop()
                stack.append(NAnd(a, b) if op == "and" else NOr(a, b))

        out, ops = [], []
        i = 0
        while i < len(tokens):
            t = tokens[i]
            tl = t.lower()
            if t == "(":
                ops.append(t)
            elif t == ")":
                while ops and ops[-1] != "(":
                    apply(ops.pop(), out)
                if ops and ops[-1] == "(": ops.pop()
            elif tl in prec:
                while ops and ops[-1] in prec and (
                        prec[ops[-1]] > prec[tl] or (prec[ops[-1]] == prec[tl] and tl not in right_assoc)
                ):
                    apply(ops.pop(), out)
                ops.append(tl)
            else:
                out.append(NVar(t))
            i += 1
        while ops:
            apply(ops.pop(), out)
        return out[0] if out else None

    def _nnf(self, node):
        """Протолкнуть not внутрь (ННФ)."""
        if node is None: return None
        if isinstance(node, NVar): return node
        if isinstance(node, NNot):
            x = node.x
            if isinstance(x, NVar): return NNot(x)
            if isinstance(x, NNot): return self._nnf(x.x)
            if isinstance(x, NAnd): return self._nnf(NOr(NNot(x.l), NNot(x.r)))
            if isinstance(x, NOr):  return self._nnf(NAnd(NNot(x.l), NNot(x.r)))
        if isinstance(node, NAnd): return NAnd(self._nnf(node.l), self._nnf(node.r))
        if isinstance(node, NOr):  return NOr(self._nnf(node.l), self._nnf(node.r))
        return node

    def _dnf(self, node):
        """
        Возвращает список конъюнкций; каждая конъюнкция — список Var(name,neg).
        """

        def litsets(n):
            if isinstance(n, NVar): return [[Var(n.name, False)]]
            if isinstance(n, NNot) and isinstance(n.x, NVar): return [[Var(n.x.name, True)]]
            if isinstance(n, NOr):
                return litsets(n.l) + litsets(n.r)
            if isinstance(n, NAnd):
                L, R = litsets(n.l), litsets(n.r)
                out = []
                for a in L:
                    for b in R:
                        out.append(a + b)
                return out
            # на этом этапе ННФ должна оставлять только Var / Not(Var) / And / Or
            return [[]]

        return litsets(node)

    def _tokens_to_ast_dnf_paths(self, tokens, detections):
        """
        1) разворачиваем макросы 2) строим AST 3) NNF 4) DNF
        5) DNF -> logic_paths формата, понятного handle_logic_paths
        """
        # распространить not на скобки перед разворачиванием макросов
        tokens = self.propagate_nots(tokens)  # уже есть в коде
        tokens = self._expand_macros(tokens, detections)  # 1_of/all_of -> or/and
        ast = self._to_ast(tokens)
        ast_nnf = self._nnf(ast)
        conjs = self._dnf(ast_nnf)
        logic_paths = []
        for conj in conjs:
            path = []
            for lit in conj:
                if lit.neg: path.append("not")
                path.append(lit.name)
            logic_paths.append(path)
        return logic_paths

    def build_logic_paths(self, rules, tokens, sigma_rule, sigma_rule_link):
        Notify.debug(self, "Function: {}".format(self.build_logic_paths.__name__))
        Notify.debug(self, "*" * 80)
        Notify.debug(self, "Rule ID: " + sigma_rule['id'])
        Notify.debug(self, "Rule Link: " + sigma_rule_link)
        Notify.debug(self, "Tokens (raw): {}".format(tokens))

        tokens = list(filter(None, tokens))
        tokens = [t.strip() for t in tokens if t.strip()]

        # если встречается 1_of/all_of — используем новый путь на базе ДНФ
        if any(t.lower() in ("1_of", "all_of") for t in tokens):
            logic_paths = self._tokens_to_ast_dnf_paths(tokens, sigma_rule['detection'])
            Notify.debug(self, "Logic Paths (DNF): {}".format(logic_paths))
            return self.handle_logic_paths(rules, sigma_rule, sigma_rule_link, logic_paths)

        # fallback: старый путь без макросов
        tokens = self.propagate_nots(self.reorder_one_ofs(tokens))
        logic_paths = []
        path = []
        negate = False
        level = 0
        is_or = False
        is_and = False
        all_of = False
        one_of = False
        ignore = False

        for t in tokens:
            if t.lower() == 'not':
                negate = True;
                continue
            if t == '(':
                level += 1;
                continue
            if t == ')':
                level -= 1;
                continue
            if t.lower() == 'or':
                is_or = True;
                continue
            if t.lower() == 'and':
                is_or = False;
                is_and = True;
                continue
            if all_of:
                path.extend(self.handle_all_of(sigma_rule['detection'], t))
                ignore = True;
                all_of = False;
                continue
            if one_of:
                paths = self.handle_one_of(sigma_rule['detection'], t, path, negate)
                ignore = True;
                logic_paths.extend(paths);
                continue
            if is_or and not negate:
                logic_paths.append(path)
                if level == 0 or not is_and:
                    path = []
                elif (len(path) > 1) and (path[-1] != 'not'):
                    path = path[:-1]
            if t.lower() == '1_of':
                one_of = True;
                continue
            if negate:
                if path and path[-1] != 'not':
                    path.append('not')
                elif not path:
                    path.append('not')
            if t.lower() == 'all_of':
                all_of = True;
                continue
            path.append(t)
            negate = False
            ignore = False
        if path and not ignore:
            logic_paths.append(path)

        Notify.debug(self, "Logic Paths (legacy): {}".format(logic_paths))
        self.handle_logic_paths(rules, sigma_rule, sigma_rule_link, logic_paths)


class TrackSkips(object):
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config.read(r'./config.ini', encoding="utf8")
        self.wazuh_rules_file = self.config.get('sigma', 'out_file')
        self.process_experimental_rules = self.config.get('sigma', 'process_experimental')
        self.sigma_skip_ids = eval(self.config.get('sigma', 'skip_sigma_guids'), {}, {})
        self.sigma_convert_all = self.config.get('sigma', 'convert_all')
        self.sigma_only_products = eval(self.config.get('sigma', 'convert_only_products'), {}, {})
        self.sigma_only_categories = eval(self.config.get('sigma', 'convert_only_categories'), {}, {})
        self.sigma_only_services = eval(self.config.get('sigma', 'convert_only_services'), {}, {})
        self.sigma_skip_products = eval(self.config.get('sigma', 'skip_products'), {}, {})
        self.sigma_skip_categories = eval(self.config.get('sigma', 'skip_categories'), {}, {})
        self.sigma_skip_services = eval(self.config.get('sigma', 'skip_services'), {}, {})
        self.near_skips = 0
        self.cidr = 0
        self.paren_skips = 0
        self.timeframe_skips = 0
        self.one_of_and_skips = 0
        self.experimental_skips = 0
        self.hard_skipped = 0
        self.rules_skipped = 0

    def rule_not_loaded(self, rule, sigma_rule):
        Notify.debug(self, "Function: {}".format(self.rule_not_loaded.__name__))
        if not sigma_rule:
            self.rules_skipped += 1
            Notify.error(self, "ERROR loading Sigma rule: " + rule)
            return True
        return False

    def skip_experimental_rules(self, sigma_rule):
        Notify.debug(self, "Function: {}".format(self.skip_experimental_rules.__name__))
        if self.process_experimental_rules == "no":
            if 'status' in sigma_rule:
                if sigma_rule['status'] == "experimental":
                    self.rules_skipped += 1
                    self.experimental_skips += 1
                    return True
        return False

    def inc_skip_counters(self):
        Notify.debug(self, "Function: {}".format(self.inc_skip_counters.__name__))
        self.rules_skipped += 1
        self.hard_skipped += 1

    def skip_rule(self, sigma_rule):
        Notify.debug(self, "Function: {}".format(self.skip_rule.__name__))
        skip = False
        if sigma_rule["id"] in self.sigma_skip_ids:  # skip specific Sigma rule GUIDs
            skip = True
        if 'category' in sigma_rule['logsource']:
            if sigma_rule['logsource']['category'].lower() in self.sigma_skip_categories:
                skip = True
        if 'service' in sigma_rule['logsource']:
            if sigma_rule['logsource']['service'].lower() in self.sigma_skip_services:
                skip = True
        if 'product' in sigma_rule['logsource']:
            if sigma_rule['logsource']['product'].lower() in self.sigma_skip_products:
                skip = True
        if skip:
            self.inc_skip_counters()
            return True

        if self.sigma_convert_all.lower() == 'yes':  # convert all rules except explicit GUID skips
            return False

        skip = True
        if 'category' in sigma_rule['logsource']:
            if sigma_rule['logsource']['category'].lower() in self.sigma_only_categories:
                skip = False
        if 'service' in sigma_rule['logsource']:
            if sigma_rule['logsource']['service'].lower() in self.sigma_only_services:
                skip = False
        if 'product' in sigma_rule['logsource']:
            if sigma_rule['logsource']['product'].lower() in self.sigma_only_products:
                skip = False
        if skip:
            self.inc_skip_counters()
        return skip

    def skip_logic(self, condition, detection):
        Notify.debug(self, "Function: {}".format(self.skip_logic.__name__))
        skip = False
        logic = []
        message = "SKIPPED Sigma rule:"
        if '|' in condition:
            skip = True
            self.near_skips += 1
            logic.append('Near')
        # if (condition.count('(') > 1 and ' or ' in condition) or (
        #         not ') or (' in condition and condition.count('(') == 2):
        #     skip = True
        #     self.paren_skips += 1
        #     logic.append('Paren')
        detection_string = yaml.dump(detection) # need to search it as string
        if 'timeframe' in detection_string:
            skip = True
            self.timeframe_skips += 1
            logic.append('Timeframe')
        if '|cidr:' in detection_string:
            skip = True
            self.cidr += 1
            logic.append('Cidr')
        one_of_count = condition.lower().split().count('1_of') # filter out rules with multiple 1_of's
        if (one_of_count > 1 and 'and' in condition) or ("not 1_of" in condition):
            skip = True
            self.one_of_and_skips += 1
            logic.append('more than 1_of with and')
        return skip, "{} {}".format(message, logic)

    def check_for_skip(self, rule, sigma_rule, detection, condition):
        """
            All logic conditions are not parsed yet.
            This procedure will skip Sigma rules we are not ready to parse.
        """
        Notify.debug(self, "Function: {}".format(self.check_for_skip.__name__))
        if self.skip_experimental_rules(sigma_rule):
            Notify.info(self, "SKIPPED Sigma rule: " + rule)
            return True
        if self.skip_rule(sigma_rule):
            Notify.info(self, "HARD SKIPPED Sigma rule: " + rule)
            return True

        skip, message = self.skip_logic(condition, detection)
        if skip:
            self.rules_skipped += 1
            Notify.info(self, message + ": " + rule)

        return skip
    
    def find_unique_ids(self):
        unique_ids = set()  # To store unique IDs

        with open(self.wazuh_rules_file, 'r', encoding="utf8") as file:
            content = file.read()

            # Search for all occurrences of text between <!--ID: and -->
            import re
            pattern = r'<!--ID: (.*?)-->'
            matches = re.findall(pattern, content)

            # Add unique IDs to the set
            for match in matches:
                unique_ids.add(match.strip())  # Remove leading/trailing spaces

        # Return the total count of unique IDs
        return len(unique_ids)

    def report_stats(self, error_count, wazuh_rules_count, sigma_rules_count):
        Notify.debug(self, "Function: {}".format(self.report_stats.__name__))
        sigma_rules_converted = self.find_unique_ids()
        sigma_rules_converted_percent = round(((sigma_rules_converted / sigma_rules_count) * 100), 2)
        print("\n\n" + "*" * 75)
        print(" Number of Sigma Experimental rules skipped: %s" % self.experimental_skips)
        print("    Number of Sigma TIMEFRAME rules skipped: %s" % self.timeframe_skips)
        print("Number of Sigma 1 OF with AND rules skipped: %s" % self.one_of_and_skips)
        print("        Number of Sigma PAREN rules skipped: %s" % self.paren_skips)
        print("         Number of Sigma CIDR rules skipped: %s" % self.cidr)
        print("         Number of Sigma NEAR rules skipped: %s" % self.near_skips)
        print("       Number of Sigma CONFIG rules skipped: %s" % self.hard_skipped)
        print("        Number of Sigma ERROR rules skipped: %s" % error_count)
        print("-" * 55)
        print("                  Total Sigma rules skipped: %s" % self.rules_skipped)
        print("                Total Sigma rules converted: %s" % sigma_rules_converted)
        print("-" * 55)
        print("                  Total Wazuh rules created: %s" % wazuh_rules_count)
        print("-" * 55)
        print("                          Total Sigma rules: %s" % sigma_rules_count)
        print("                    Sigma rules converted %%: %s" % sigma_rules_converted_percent)
        print("*" * 75 + "\n\n")

def arguments() -> argparse.ArgumentParser:
    global debug
    parser = argparse.ArgumentParser(
        usage="%(prog)s [OPTION]",
        description="Convert Sigma rules into Wazuh rules."
    )
    parser.add_argument(
        "-v", "--version", action="version",
        version = f"{parser.prog} version 1.0.0"
    )
    parser.add_argument('--debug', "-d", action="store_true",
                        help="increase output verbosity")
    args = parser.parse_args()
    if args.debug:
        debug = args.debug

def main():
    arguments()
    notify = Notify()
    notify.debug("Function: {}".format(main.__name__))
    convert = ParseSigmaRules()
    wazuh_rules = BuildRules()
    stats = TrackSkips()
    sigma_rule_ids = set()

    for rule in convert.sigma_rules:
        sigma_rule = convert.load_sigma_rule(rule)
        if 'id' in sigma_rule:
            sigma_rule_ids.add(sigma_rule['id'])
        if stats.rule_not_loaded(rule, sigma_rule):
            continue

        try:
            conditions = convert.fixup_condition(sigma_rule['detection']['condition'])
            #notify.debug(conditions)
        except:
            #notify.debug(conditions)
            continue

        skip_rule = stats.check_for_skip(rule, sigma_rule, sigma_rule['detection'], conditions)
        if skip_rule:
            continue
        #notify.debug(rule)

        # build the URL to the sigma rule, handle relative paths
        partial_url_path = rule.replace('/sigma/rules', '').replace('../', '/').replace('./', '/').replace('\\','/').replace('..', '')

        if isinstance(conditions, list):
            for condition in conditions:  # create new rule for each condition, needs work
                tokens = condition.strip().split(' ')
                convert.build_logic_paths(wazuh_rules, tokens, sigma_rule, partial_url_path)
            continue
        tokens = conditions.strip().split(' ')
        convert.build_logic_paths(wazuh_rules, tokens, sigma_rule, partial_url_path)

    # write out all Wazuh rules created
    wazuh_rules.write_rules_file()
    stats.report_stats(convert.error_count, wazuh_rules.rule_count, len(sigma_rule_ids))


if __name__ == "__main__":
    main()
