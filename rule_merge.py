import requests
import yaml
import os
import re
import ipaddress
import sys
from collections import OrderedDict
from urllib.parse import urlparse
import concurrent.futures
import time

def get_script_dir():
    return os.path.dirname(os.path.realpath(__file__))

def download_rules(url, max_retries=3, timeout=30):
    """Download URL with simple retry/backoff to handle transient network errors."""
    for attempt in range(1, max_retries + 1):
        try:
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
            # reading text may raise on incomplete reads; if so, try again
            content = response.text
            return content
        except Exception as e:
            # print a concise retry message to stderr
            if attempt < max_retries:
                print(f"下载时出错 (尝试 {attempt}/{max_retries}): {e}，正在重试...", file=sys.stderr)
                time.sleep(1 * attempt)
                continue
            else:
                print(f"下载时出错: {e}", file=sys.stderr)
                return None

def download_all_rules(rule_sets_config):
    all_rules = {}
    # stats per rule type for download summary
    download_stats = {k: {'total_sources': len(v), 'success': 0, 'failed': 0} for k, v in rule_sets_config.items()}

    # temp store results keyed by (output_name, index) so we can preserve source order
    temp_results = {k: {} for k in rule_sets_config.keys()}

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_meta = {}
        for output_name, urls in rule_sets_config.items():
            for idx, (url, comment) in enumerate(urls):
                future = executor.submit(download_rules, url)
                future_to_meta[future] = (output_name, idx, url, comment)
            # If already in clash/acl style like DOMAIN,DOMAIN-SUFFIX,DOMAIN-KEYWORD -> try to convert
        for future in concurrent.futures.as_completed(future_to_meta):
            output_name, idx, url, comment = future_to_meta[future]
            try:
                content = future.result()
                if content:
                    try:
                        file_format = get_file_format(url)
                    except Exception as e:
                        # record as failed with error
                        temp_results[output_name][idx] = {'success': False, 'error': str(e), 'comment': comment, 'url': url}
                        download_stats.setdefault(output_name, {'total_sources': 0, 'success': 0, 'failed': 0})
                        download_stats[output_name]['failed'] += 1
                        continue

                    temp_results[output_name][idx] = {'success': True, 'content': content, 'file_format': file_format, 'comment': comment, 'url': url}
                    download_stats.setdefault(output_name, {'total_sources': 0, 'success': 0, 'failed': 0})
                    download_stats[output_name]['success'] += 1
                else:
                    temp_results[output_name][idx] = {'success': False, 'error': '下载返回空内容', 'comment': comment, 'url': url}
                    download_stats.setdefault(output_name, {'total_sources': 0, 'success': 0, 'failed': 0})
                    download_stats[output_name]['failed'] += 1
            except Exception as exc:
                temp_results[output_name][idx] = {'success': False, 'error': str(exc), 'comment': comment, 'url': url}
                download_stats.setdefault(output_name, {'total_sources': 0, 'success': 0, 'failed': 0})
                download_stats[output_name]['failed'] += 1

    # Print structured download results per rule type in original config order
    print("\n下载结果（按规则类型与源的配置顺序）:")
    for output_name, urls in rule_sets_config.items():
        print(f"{output_name}:")
        for idx, (url, comment) in enumerate(urls):
            res = temp_results.get(output_name, {}).get(idx)
            if not res:
                print(f"  [下载] {comment} - 失败 (未知错误)")
            elif res.get('success'):
                print(f"  [下载] {comment} - 成功")
            else:
                err = res.get('error')
                print(f"  [下载] {comment} - 失败: {err}")

    # print a concise download summary per rule type
    print("\n按规则类型的下载汇总:")
    for rtype, stats in download_stats.items():
        total = stats.get('total_sources', 0)
        succ = stats.get('success', 0)
        fail = stats.get('failed', 0)
        print(f"  {rtype}: 来源数={total}, 成功={succ}, 失败={fail}")

    # separator for readability
    print('\n' + '-' * 60 + '\n')

    # build final all_rules preserving original source order, only include successful downloads
    for output_name, urls in rule_sets_config.items():
        ordered_list = []
        for idx, (url, comment) in enumerate(urls):
            res = temp_results.get(output_name, {}).get(idx)
            if res and res.get('success'):
                ordered_list.append((res['content'], res['file_format'], res['comment'], res['url']))
        if ordered_list:
            all_rules[output_name] = ordered_list

    return all_rules

def parse_rules(content, file_format):
    if content is None:
        return []
    try:
        if file_format == 'txt':
            lines = content.splitlines()
            return [line.strip() for line in lines if line.strip() and not line.strip().lower() == 'payload:']
        elif file_format in ['list']:
            return [line.strip() for line in content.splitlines() if line.strip() and not line.startswith('#')]
        elif file_format == 'yaml':
            # attempt to parse YAML content; support common layouts
            try:
                parsed = yaml.safe_load(content)
                items = []
                # If YAML is a dict try common keys first
                if isinstance(parsed, dict):
                    for key in ('payload', 'rules', 'data'):
                        if key in parsed and isinstance(parsed[key], list):
                            for it in parsed[key]:
                                txt = convert_yaml_item_to_txt(it)
                                if txt:
                                    items.append(txt)
                            if items:
                                return items
                    # otherwise flatten any list values found in the dict
                    for v in parsed.values():
                        if isinstance(v, list):
                            for it in v:
                                txt = convert_yaml_item_to_txt(it)
                                if txt:
                                    items.append(txt)
                    if items:
                        return items
                # If YAML is a list, convert each element
                if isinstance(parsed, list):
                    for it in parsed:
                        txt = convert_yaml_item_to_txt(it)
                        if txt:
                            items.append(txt)
                    if items:
                        return items
            except Exception:
                # fallback to line-based parsing
                lines = content.splitlines()
                return [line.strip() for line in lines if line.strip()]
        else:
            raise ValueError(f"Unsupported file format: {file_format}")
    except Exception as e:
        print(f"解析规则时出错: {e}", file=sys.stderr)
        return []

def convert_list_to_txt(rule):
    r = rule.strip()
    if not r:
        return None
    # handle common explicit prefixes
    if r.startswith('DOMAIN,'):
        return f"- '{r.split(',',1)[1].strip()}'"
    elif r.startswith('DOMAIN-SUFFIX,'):
        return f"- '+.{r.split(',',1)[1].strip()}'"
    elif r.startswith('DOMAIN-KEYWORD,'):
        # take the keyword part
        return f"- '{r.split(',',1)[1].strip()}'"
    else:
        # fallback: try to extract domain-like part after first comma, otherwise take whole line
        parts = r.split(',')
        domain_part = parts[1].strip() if len(parts) > 1 else parts[0].strip()
        if domain_part:
            return f"- '{domain_part}'"
    return None

def convert_yaml_item_to_txt(item):
    """Convert a YAML-parsed item into the same txt-list form we use for .list items.

    Returns strings like "- 'example.com'" or "- '+.example.com'" or None when nothing useful.
    """
    if item is None:
        return None
    # dict/list handling: try to extract a meaningful string value
    if isinstance(item, dict):
        # try common keys that may contain domain-like values
        for key in ('value', 'domain', 'host', 'rule', 'payload', 'name', 'pattern'):
            if key in item and isinstance(item[key], str) and item[key].strip():
                return convert_yaml_item_to_txt(item[key].strip())
        # fallback: try any string value in the dict
        for v in item.values():
            if isinstance(v, str) and v.strip():
                return convert_yaml_item_to_txt(v.strip())
        return None
    if isinstance(item, (list, tuple)):
        for v in item:
            res = convert_yaml_item_to_txt(v)
            if res:
                return res
        return None

    # string handling
    s = str(item).strip()
    if not s:
        return None

    # If the YAML item already contains an ACL/Clash style rule, convert DOMAIN-* / DOMAIN-KEYWORD to txt form.
    # Keep IP-CIDR/IP-ASN as-is so they can be written to merged conf later.
    up = s.upper()
    if up.startswith(('DOMAIN,', 'DOMAIN-SUFFIX,', 'DOMAIN-KEYWORD,')):
        c = convert_list_to_txt(s)
        if c:
            return c
        # fallback: if conversion failed, continue to other heuristics
    if up.startswith(('IP-CIDR,', 'IP-ASN,')):
        return s

    # if looks like comma-separated rule (DOMAIN, ...), reuse convert_list_to_txt
    if ',' in s:
        c = convert_list_to_txt(s)
        if c:
            return c

    # wildcard or prefix forms
    if s.startswith('+.'):
        return f"- '+.{s[2:]}'"
    if s.startswith('*.'):
        return f"- '+.{s[2:]}'"
    if s.startswith('.'):
        return f"- '+.{s[1:]}'"

    # try to parse as URL to extract hostname
    try:
        parsed = urlparse(s)
        if parsed.hostname:
            return f"- '{parsed.hostname}'"
    except Exception:
        pass

    # fallback: split by non-alphanumeric/dot chars and take last token
    parts = re.split(r'[^0-9a-zA-Z\.\-]+', s)
    for p in reversed(parts):
        if p:
            return f"- '{p}'"
    return None

def convert_txt_to_conf(rule):
    if rule.startswith("- '+."):
        domain = rule[5:-1] if rule.endswith("'") else rule[5:]
        return f"DOMAIN-SUFFIX,{domain},PROXY"
    elif rule.startswith("- '"):
        domain = rule[3:-1] if rule.endswith("'") else rule[3:]
        return f"DOMAIN,{domain},PROXY"
    elif rule.startswith("DOMAIN-SUFFIX,") or rule.startswith("DOMAIN,") or rule.startswith("DOMAIN-KEYWORD,"):
        parts = rule.split(',')
        if len(parts) == 2:
            return f"{rule},PROXY"
        elif len(parts) == 3 and parts[2] != "PROXY":
            return f"{parts[0]},{parts[1]},PROXY"
    return rule

def normalize_rule(rule):
    """Normalize a rule to a canonical representation used for deduplication.

    The normalized form is a lowercase, comma-separated string without quotes
    and without action (we focus on domain and kind). Examples:
      - "DOMAIN,example.com,PROXY" -> "domain,example.com"
      - "DOMAIN-SUFFIX,example.com,PROXY" -> "domain-suffix,example.com"
      - "- '+.example.com'" -> "domain-suffix,example.com"
      - "- 'example.com'" -> "domain,example.com"
      - plain "example.com" -> "domain-suffix,example.com"

    This function is conservative and aims to make semantically-equal rules
    produce identical normalized strings.
    """
    if not rule:
        return ''
    r = rule.strip()
    # remove leading list markers
    if r.startswith("- "):
        r = r[2:].strip()
    # remove surrounding quotes
    if r.startswith("'") and r.endswith("'"):
        r = r[1:-1]
    if r.startswith('"') and r.endswith('"'):
        r = r[1:-1]

    # handle DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD formats
    parts = [p.strip() for p in r.split(',')]
    if parts and parts[0].upper().startswith('DOMAIN'):
        kind = parts[0].lower()
        if len(parts) >= 2:
            value = parts[1].lower()
            # normalize leading +.
            if value.startswith('+.'):
                value = value[2:]
            return f"{kind},{value}"

    # handle patterns like "+.example.com" or ".example.com"
    if r.startswith('+.'):
        return f"domain-suffix,{r[2:].lower()}"
    if r.startswith('.'):
        return f"domain-suffix,{r[1:].lower()}"

    # if looks like a domain with wildcard prefix
    if r.startswith('*.'):
        return f"domain-suffix,{r[2:].lower()}"

    # if it's a bare domain or contains only domain-like chars
    cleaned = r.lower()
    # if it looks like an IP or CIDR, accept as-is (use ipaddress)
    try:
        ipaddress.ip_network(cleaned, strict=False)
        return f"ip,{cleaned}"
    except Exception:
        pass

    # require at least one dot for domain forms; otherwise treat as invalid
    if '.' not in cleaned:
        return ''

    # finally treat as domain-suffix by default
    return f"domain-suffix,{cleaned}"

def get_file_format(url):
    path = urlparse(url).path
    extension = os.path.splitext(path)[1].lower()
    if extension in ['.txt', '.list', '.yaml', '.yml']:
        if extension == '.txt':
            return 'txt'
        elif extension == '.list':
            return 'list'
        else:
            return 'yaml'
    else:
        raise ValueError(f"Unsupported file format: {extension}")

def read_custom_rules(file_name):
    file_path = os.path.join(get_script_dir(), file_name)
    if not os.path.exists(file_path):
        print(f"未找到自定义规则文件 {file_path}.")
        return {'direct': [], 'proxy': [], 'ai': []}
    
    custom_rules = {'direct': [], 'proxy': [], 'ai': []}
    current_category = None
    
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line.startswith('#'):
                if 'direct' in line.lower():
                    current_category = 'direct'
                elif 'proxy' in line.lower():
                    current_category = 'proxy'
                elif 'ai' in line.lower():
                    current_category = 'ai'
            elif line and current_category:
                custom_rules[current_category].append(line)
    
    return custom_rules

def save_rules_txt(rules, output_file):
    file_path = os.path.join(get_script_dir(), output_file)
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("payload:\n")
            for rule in rules:
                f.write(f"  {rule}\n")
        # 仅显示已生成文件路径，不显示条数以减少冗余输出
        print(f"已生成 {file_path}")
        # separator for readability
        print('\n' + '-' * 60 + '\n')
    except IOError as e:
        print(f"写入 {file_path} 时出错: {e}", file=sys.stderr)

def process_rules(rule_sets, custom_rules, rule_type=None, verbose=True):
    """
    Process downloaded rule sets into txt format list for a given rule_type.
    If rule_type is provided, include it in log outputs and print a per-type summary.
    """
    # show custom rules count and internal duplicates (if any) so user can see how many were pre-added
    # We'll produce an order-preserving unique list based on normalized keys.
    result_rules = []  # final ordered payload rules (original representations)
    # normalized set for dedupe checks (custom is baseline)
    existing_norm = set()
    if custom_rules:
        for cr in custom_rules:
            n = normalize_rule(cr)
            # only include valid domain/ip forms into the baseline
            if n:
                existing_norm.add(n)
                # include custom rule in payload only if it's a domain/domain-suffix (not domain-keyword or ip/asn)
                if not n.startswith('domain-keyword') and not n.startswith('ip,'):
                    # avoid duplicates among custom rules themselves
                    if n not in existing_norm:
                        result_rules.append(cr)
                    else:
                        # if already present (very rare since we just added), skip
                        pass
    try:
        custom_count_raw = len(custom_rules) if custom_rules else 0
        custom_count_unique = len(set(custom_rules)) if custom_rules else 0
    except Exception:
        custom_count_raw = 0
        custom_count_unique = 0
    custom_duplicates = max(0, custom_count_raw - custom_count_unique)
    if custom_count_raw and verbose:
        if rule_type:
            if custom_duplicates > 0:
                print(f"已为 {rule_type} 添加 {custom_count_unique} 条自定义规则（去重{custom_duplicates}条），来源: custom_rule (原始: {custom_count_raw})")
            else:
                print(f"已为 {rule_type} 添加 {custom_count_unique} 条自定义规则，来源: custom_rule (原始: {custom_count_raw})")
        else:
            if custom_duplicates > 0:
                print(f"已添加 {custom_count_unique} 条自定义规则（去重{custom_duplicates}条），来源: custom_rule (原始: {custom_count_raw})")
            else:
                print(f"已添加 {custom_count_unique} 条自定义规则，来源: custom_rule (原始: {custom_count_raw})")
    total_added = 0
    # total_raw_download: include custom rules raw count and sum of original counts from each source
    total_raw_download = custom_count_raw
    # total_processed_download: number of items actually participating in dedupe (custom unique + processed items from sources)
    total_processed_download = len(existing_norm)

    for content, file_format, comment, url in rule_sets:
        rules = parse_rules(content, file_format)
        original_count = len(rules)
        total_raw_download += original_count
        if file_format == 'list':
            processed_rules = [convert_list_to_txt(rule) for rule in rules if convert_list_to_txt(rule)]
        else:
            processed_rules = rules

        # For payload outputs we do NOT include IP-CIDR/IP-ASN entries; keep those only for conf output.
        ignored_ip_count = 0
        ignored_keyword_count = 0
        invalid_count = 0

        # track per-source counts
        unique_new = 0
        duplicates = 0

        for pr in processed_rules:
            if not pr:
                continue
            up = pr.upper()
            # ignore IP entries completely for payload
            if up.startswith('IP-CIDR') or up.startswith('IP-ASN'):
                ignored_ip_count += 1
                continue

            # convert and normalize
            nr = normalize_rule(pr)
            if not nr:
                invalid_count += 1
                continue

            # exclude DOMAIN-KEYWORD from payload (keep in conf only)
            if nr.startswith('domain-keyword'):
                ignored_keyword_count += 1
                continue

            # if not seen before, include in ordered result and mark as seen
            if nr not in existing_norm:
                result_rules.append(pr)
                existing_norm.add(nr)
                unique_new += 1
            else:
                duplicates += 1

        # keep total_added as the total number of processed items (去重前总数) for summary
        total_added += len(processed_rules)

        if verbose:
            notes = []
            if ignored_ip_count:
                notes.append(f"忽略 IP/CIDR/ASN {ignored_ip_count} 条")
            if ignored_keyword_count:
                notes.append(f"忽略 DOMAIN-KEYWORD {ignored_keyword_count} 条")
            if invalid_count:
                notes.append(f"忽略 无效条目 {invalid_count} 条")
            note_str = f"，{'，'.join(notes)}" if notes else ""
            if rule_type:
                if duplicates > 0:
                    print(f"已为 {rule_type} 添加 {unique_new} 条规则（去重{duplicates}条）{note_str}，来源：{comment} (原始: {original_count})")
                else:
                    print(f"已为 {rule_type} 添加 {unique_new} 条规则{note_str}，来源：{comment} (原始: {original_count})")
            else:
                if duplicates > 0:
                    print(f"已添加 {unique_new} 条规则（去重{duplicates}条）{note_str}，来源：{comment} (原始: {original_count})")
                else:
                    print(f"已添加 {unique_new} 条规则{note_str}，来源：{comment} (原始: {original_count})")

    # final unique count is based on normalized baseline
    unique_count = len(existing_norm)
    return result_rules

def process_rules_for_conf(rule_sets, custom_rules, rule_type=None, verbose=True):
    """
    Process downloaded rule sets into clash conf format for a given rule_type.
    If rule_type is provided, include it in log outputs and print a per-type summary.
    """
    all_processed_rules = []
    # compute custom rules raw/unique counts and duplicates
    try:
        custom_count_raw = len(custom_rules) if custom_rules else 0
        custom_count_unique = len(set(custom_rules)) if custom_rules else 0
    except Exception:
        custom_count_raw = 0
        custom_count_unique = 0
    # For conf processing we must convert custom rules into conf format for accurate dedupe
    converted_custom = []
    if custom_rules:
        for r in custom_rules:
            try:
                converted = convert_txt_to_conf(r) if not (r.startswith('DOMAIN-') or r.startswith('DOMAIN,')) else r
            except Exception:
                converted = r
            if converted:
                converted_custom.append(converted)
    converted_custom_unique = set(converted_custom)
    custom_converted_unique_count = len(converted_custom_unique)
    custom_duplicates = max(0, custom_count_raw - len(converted_custom_unique))
    if custom_count_raw and verbose and rule_type:
        if custom_duplicates > 0:
            print(f"已为 {rule_type} 添加 {custom_converted_unique_count} 条自定义规则（去重{custom_duplicates}条），来源: custom_rule (原始: {custom_count_raw})")
        else:
            print(f"已为 {rule_type} 添加 {custom_converted_unique_count} 条自定义规则，来源: custom_rule (原始: {custom_count_raw})")
    total_added = 0
    # total_raw_download: include custom rules raw count and sum of original counts from each source
    total_raw_download = custom_count_raw
    # total_processed_download: include converted unique custom rules as initial processed set
    # normalized baseline for conf processing
    existing_norm = set()
    if converted_custom:
        for cr in converted_custom:
            nr = normalize_rule(cr)
            if nr:
                existing_norm.add(nr)
    total_processed_download = len(existing_norm)
    # 不记录 per-source debug 明细（按用户要求仅保留每个来源的已添加/去重行）
    for content, file_format, comment, url in rule_sets:
        rules = parse_rules(content, file_format)
        original_count = len(rules)
        total_raw_download += original_count
        if file_format == 'list':
            processed_rules = [rule for rule in rules if rule.startswith(('DOMAIN,', 'DOMAIN-SUFFIX,', 'DOMAIN-KEYWORD,'))]
        else:  # 'txt' format
            processed_rules = [convert_txt_to_conf(rule) for rule in rules]
        n_processed = len(processed_rules)
        # use normalization for dedupe checks
        unique_new = 0
        duplicates = 0
        norms = []
        for r in processed_rules:
            nr = normalize_rule(r)
            norms.append(nr)
            if nr and nr not in existing_norm:
                unique_new += 1
            else:
                duplicates += 1
        all_processed_rules.extend(processed_rules)
        for nr in norms:
            if nr:
                existing_norm.add(nr)
        added = unique_new
            # 保留每个来源的已添加/去重输出，但不记录 per-source debug 明细以避免重复汇总
        # keep total_added as the total number of processed items (去重前总数) for summary
        total_added += n_processed
        if verbose:
            if rule_type:
                if duplicates > 0:
                    print(f"已为 {rule_type} 添加 {added} 条规则（去重{duplicates}条），来源：{comment} (原始: {original_count})")
                else:
                    print(f"已为 {rule_type} 添加 {added} 条规则，来源：{comment} (原始: {original_count})")
            else:
                if duplicates > 0:
                    print(f"已添加 {added} 条规则（去重{duplicates}条），来源：{comment} (原始: {original_count})")
                else:
                    print(f"已添加 {added} 条规则，来源：{comment} (原始: {original_count})")

    # include converted custom rules in final set
    all_processed_rules.extend(converted_custom)
    # unique normalized count
    unique = sorted(set(all_processed_rules))
    # total_dedup is based on processed (normalized) items
    total_dedup = total_processed_download - len(existing_norm)
    # 不再打印按来源累计去重一致性警告或每类型汇总（按用户要求）仅返回唯一规则集合
    return unique

def format_rule(rule):
    if rule.startswith("- '+.") or rule.startswith("- '"):
        return convert_txt_to_conf(rule)
    # preserve IP and ASN entries
    if rule.upper().startswith(('IP-CIDR,', 'IP-ASN,')):
        return rule
    elif not (rule.startswith("DOMAIN-SUFFIX,") or rule.startswith("DOMAIN,") or rule.startswith("DOMAIN-KEYWORD,")):
        return f"DOMAIN-SUFFIX,{rule},PROXY"
    else:
        parts = rule.split(',')
        if len(parts) == 2:
            return f"{rule},PROXY"
        elif len(parts) == 3 and parts[2] != "PROXY":
            return f"{parts[0]},{parts[1]},PROXY"
    return rule

def generate_merged_rules_conf(all_downloaded_rules, custom_rules):
    # do not print per-source or per-type summaries here to avoid duplicate logs
    proxy_rules = process_rules_for_conf(all_downloaded_rules.get("Proxy", []), custom_rules.get('proxy', []), rule_type='Proxy', verbose=False)
    ai_rules = process_rules_for_conf(all_downloaded_rules.get("Ai", []), custom_rules.get('ai', []), rule_type='Ai', verbose=False)
    
    merged_conf_rules = sorted(set(proxy_rules + ai_rules))
    
    merged_conf_file = os.path.join(get_script_dir(), "merged_rules.conf")
    try:
        with open(merged_conf_file, 'w', encoding='utf-8') as f:
            for rule in merged_conf_rules:
                formatted_rule = format_rule(rule)
                f.write(f"{formatted_rule}\n")
        print(f"已生成 {merged_conf_file}，包含 {len(merged_conf_rules)} 条唯一规则")
        # separator for readability
        print('\n' + '-' * 60 + '\n')
    except IOError as e:
        print(f"写入 {merged_conf_file} 时出错: {e}", file=sys.stderr)

def main():
    rule_sets_config = {
        "Proxy": [
            ("https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt", "Loyalsoldier Proxy"),
        ],
        "Ai": [
            ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/Ruleset/AI.list", "ACL4SSR AI"), 
            ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Copilot/Copilot.list", "blackmatrix7 Copilot"),
            ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/OpenAI/OpenAI.list", "blackmatrix7 OpenAI"),    
            ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Gemini/Gemini.yaml", "blackmatrix7 Gemini"),    
            ("https://raw.githubusercontent.com/szkane/ClashRuleSet/main/Clash/Ruleset/CiciAi.list", "szkane CiciAi"),   
        ],
        "Direct": [
            ("https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt", "Loyalsoldier Direct"),
            ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Download/Download.list", "blackmatrix7 Download"),
            ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/ChinaMax/ChinaMax.list", "blackmatrix7 ChinaMax"),
            ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Direct/Direct.list", "blackmatrix7 Direct"),
            ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaDomain.list", "ACL4SSR ChinaDomain"),
            ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaCompanyIp.list", "ACL4SSR ChinaCompanyIp"),
            ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/LocalAreaNetwork.list", "ACL4SSR LocalAreaNetwork"),
        ],
        "Reject": [
            ("https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt", "Loyalsoldier reject"),
        ],
    }

    custom_rules = read_custom_rules('custom_rule.txt')

    print("正在下载所有规则...")
    all_downloaded_rules = download_all_rules(rule_sets_config)

    # Generate merged_rules.conf
    generate_merged_rules_conf(all_downloaded_rules, custom_rules)

    # Process rules for txt files (if still needed)
    for output_name in ["Proxy", "Ai", "Direct", "Reject"]:
        rules = process_rules(all_downloaded_rules.get(output_name, []), custom_rules.get(output_name.lower(), []), rule_type=output_name)
        save_rules_txt(rules, f"{output_name}.txt")

if __name__ == "__main__":
    main()

