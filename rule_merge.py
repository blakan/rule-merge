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
    """下载URL，使用简单重试/退避处理瞬时网络错误。"""
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
    # 按规则类型统计下载汇总
    download_stats = {k: {'total_sources': len(v), 'success': 0, 'failed': 0} for k, v in rule_sets_config.items()}

    # 临时存储结果，按(output_name, index)键，以便保留源顺序
    temp_results = {k: {} for k in rule_sets_config.keys()}

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_meta = {}
        for output_name, urls in rule_sets_config.items():
            for idx, (url, comment) in enumerate(urls):
                future = executor.submit(download_rules, url)
                future_to_meta[future] = (output_name, idx, url, comment)
            # 如果已经是clash/acl风格如DOMAIN,DOMAIN-SUFFIX,DOMAIN-KEYWORD -> 尝试转换
        for future in concurrent.futures.as_completed(future_to_meta):
            output_name, idx, url, comment = future_to_meta[future]
            try:
                content = future.result()
                if content:
                    try:
                        file_format = get_file_format(url)
                    except Exception as e:
                        # 记录为失败并附带错误
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

    # 按规则类型和源配置顺序打印结构化下载结果
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

    # 打印按规则类型的简洁下载汇总
    print("\n按规则类型的下载汇总:")
    for rtype, stats in download_stats.items():
        total = stats.get('total_sources', 0)
        succ = stats.get('success', 0)
        fail = stats.get('failed', 0)
        print(f"  {rtype}: 来源数={total}, 成功={succ}, 失败={fail}")

    # 可读性分隔符
    print('\n' + '-' * 60 + '\n')

    # 构建最终all_rules，保留原始源顺序，仅包含成功下载
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
            # 尝试解析YAML内容；支持常见布局
            try:
                parsed = yaml.safe_load(content)
                items = []
                # 如果YAML是dict，先尝试常见键
                if isinstance(parsed, dict):
                    for key in ('payload', 'rules', 'data'):
                        if key in parsed and isinstance(parsed[key], list):
                            for it in parsed[key]:
                                txt = convert_yaml_item_to_txt(it)
                                if txt:
                                    items.append(txt)
                            if items:
                                return items
                    # 否则展平dict中找到的任何list值
                    for v in parsed.values():
                        if isinstance(v, list):
                            for it in v:
                                txt = convert_yaml_item_to_txt(it)
                                if txt:
                                    items.append(txt)
                    if items:
                        return items
                # 如果YAML是list，转换每个元素
                if isinstance(parsed, list):
                    for it in parsed:
                        txt = convert_yaml_item_to_txt(it)
                        if txt:
                            items.append(txt)
                    if items:
                        return items
            except Exception:
                # 回退到基于行的解析
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
    """将YAML解析的项目转换为我们用于.list项目的相同txt-list形式。

    返回如"- 'example.com'"或"- '+.example.com'"或None的字符串，当没有有用内容时。
    """
    if item is None:
        return None
    # dict/list处理：尝试提取有意义的字符串值
    if isinstance(item, dict):
        # 尝试可能包含类似域名的常见键
        for key in ('value', 'domain', 'host', 'rule', 'payload', 'name', 'pattern'):
            if key in item and isinstance(item[key], str) and item[key].strip():
                return convert_yaml_item_to_txt(item[key].strip())
        # 回退：尝试dict中的任何字符串值
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

    # 字符串处理
    s = str(item).strip()
    if not s:
        return None

    # 如果YAML项目已经包含ACL/Clash风格规则，将DOMAIN-* / DOMAIN-KEYWORD转换为txt形式。
    # 保持IP-CIDR/IP-ASN不变，以便稍后写入合并的conf。
    up = s.upper()
    if up.startswith(('DOMAIN,', 'DOMAIN-SUFFIX,', 'DOMAIN-KEYWORD,')):
        c = convert_list_to_txt(s)
        if c:
            return c
        # 回退：如果转换失败，继续其他启发式
    if up.startswith(('IP-CIDR,', 'IP-ASN,')):
        return s

    # 如果看起来像逗号分隔的规则(DOMAIN, ...), 重用convert_list_to_txt
    if ',' in s:
        c = convert_list_to_txt(s)
        if c:
            return c

    # 通配符或前缀形式
    if s.startswith('+.'):
        return f"- '+.{s[2:]}'"
    if s.startswith('*.'):
        return f"- '+.{s[2:]}'"
    if s.startswith('.'):
        return f"- '+.{s[1:]}'"

    # 尝试解析为URL以提取主机名
    try:
        parsed = urlparse(s)
        if parsed.hostname:
            return f"- '{parsed.hostname}'"
    except Exception:
        pass

    # 回退：按非字母数字/点字符分割，取最后一个标记
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
    """将规则标准化为用于去重的规范表示。

    标准化形式是小写的逗号分隔字符串，没有引号
    也没有动作（我们关注域名和种类）。示例：
      - "DOMAIN,example.com,PROXY" -> "domain,example.com"
      - "DOMAIN-SUFFIX,example.com,PROXY" -> "domain-suffix,example.com"
      - "- '+.example.com'" -> "domain-suffix,example.com"
      - "- 'example.com'" -> "domain,example.com"
      - plain "example.com" -> "domain-suffix,example.com"

    此函数保守，旨在使语义相等的规则
    产生相同的标准化字符串。
    """
    if not rule:
        return ''
    r = rule.strip()
    # 移除前导列表标记
    if r.startswith("- "):
        r = r[2:].strip()
    # 移除周围引号
    if r.startswith("'") and r.endswith("'"):
        r = r[1:-1]
    if r.startswith('"') and r.endswith('"'):
        r = r[1:-1]

    # 处理DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD格式
    parts = [p.strip() for p in r.split(',')]
    if parts and parts[0].upper().startswith('DOMAIN'):
        kind = parts[0].lower()
        if len(parts) >= 2:
            value = parts[1].lower()
            # 标准化前导+.
            if value.startswith('+.'):
                value = value[2:]
            return f"{kind},{value}"

    # 处理如"+.example.com"或".example.com"的模式
    if r.startswith('+.'):
        return f"domain-suffix,{r[2:].lower()}"
    if r.startswith('.'):
        return f"domain-suffix,{r[1:].lower()}"

    # 如果看起来像带通配符前缀的域名
    if r.startswith('*.'):
        return f"domain-suffix,{r[2:].lower()}"

    # 如果是裸域名或仅包含类似域名的字符
    cleaned = r.lower()
    # 如果看起来像IP或CIDR，按原样接受（使用ipaddress）
    try:
        ipaddress.ip_network(cleaned, strict=False)
        return f"ip,{cleaned}"
    except Exception:
        pass

    # 对于域名形式要求至少一个点；否则视为无效
    if '.' not in cleaned:
        return ''

    # 最后默认视为domain-suffix
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
    处理下载的规则集为给定rule_type的txt格式列表。
    支持自定义规则的覆盖：如果规则在自定义的其他类型中，则跳过它。
    """
    # 构建全局自定义规则的规范化映射（所有类型）
    custom_all_norms = {}  # normalized_rule -> category
    for cat in ['direct', 'proxy', 'ai', 'reject']:
        for rule in custom_rules.get(cat, []):
            n = normalize_rule(rule)
            if n:
                custom_all_norms[n] = cat
    
    # 当前类型在自定义中的规范化集合
    current_type_norms = set()
    for rule in custom_rules.get(rule_type.lower() if rule_type else '', []):
        n = normalize_rule(rule)
        if n:
            current_type_norms.add(n)
    
    # 用于去重检查的标准化集
    existing_norm = set()
    result_rules = []  # final ordered payload rules (original representations)
    total_added = 0
    # total_raw_download: 每个源的原始数量总和
    total_raw_download = 0
    # total_processed_download: 实际参与去重的项目数量
    total_processed_download = 0

    for content, file_format, comment, url in rule_sets:
        rules = parse_rules(content, file_format)
        original_count = len(rules)
        total_raw_download += original_count
        if file_format == 'list':
            processed_rules = [convert_list_to_txt(rule) for rule in rules if convert_list_to_txt(rule)]
        else:
            processed_rules = rules

        # 对于payload输出，我们不包括IP-CIDR/IP-ASN条目；仅在conf输出中保留那些。
        ignored_ip_count = 0
        ignored_keyword_count = 0
        invalid_count = 0

        # 跟踪每源数量
        unique_new = 0
        duplicates = 0

        for pr in processed_rules:
            if not pr:
                continue
            up = pr.upper()
            # 忽略IP条目
            if up.startswith('IP-CIDR') or up.startswith('IP-ASN'):
                ignored_ip_count += 1
                continue

            # 转换并标准化
            nr = normalize_rule(pr)
            if not nr:
                invalid_count += 1
                continue

            # 排除DOMAIN-KEYWORD（仅在conf中保留）
            if nr.startswith('domain-keyword'):
                ignored_keyword_count += 1
                continue

            # 如果规则在自定义的其他类型中，则跳过（自定义规则优先，按其分类）
            if nr in custom_all_norms and custom_all_norms[nr] != rule_type.lower():
                continue

            # 如果之前未见过，包含在有序结果中并标记为已见
            if nr not in existing_norm:
                result_rules.append(pr)
                existing_norm.add(nr)
                unique_new += 1
            else:
                duplicates += 1

        # 将total_added保留为处理项的总数量（去重前总数）用于汇总
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

    # 最终唯一数量基于标准化基准
    unique_count = len(existing_norm)
    return result_rules

def process_rules_for_conf(rule_sets, custom_rules, rule_type=None, verbose=True):
    """
    处理下载的规则集为给定rule_type的clash conf格式。
    支持自定义规则的覆盖：如果规则在自定义的其他类型中，则跳过它。
    """
    # 构建全局自定义规则的规范化映射（所有类型）
    custom_all_norms = {}  # normalized_rule -> category
    for cat in ['direct', 'proxy', 'ai', 'reject']:
        for rule in custom_rules.get(cat, []):
            n = normalize_rule(rule)
            if n:
                custom_all_norms[n] = cat
    
    # 当前类型在自定义中的规范化集合
    current_type_norms = set()
    for rule in custom_rules.get(rule_type.lower() if rule_type else '', []):
        n = normalize_rule(rule)
        if n:
            current_type_norms.add(n)
    
    all_processed_rules = []
    # total_raw_download: 每个源的原始数量总和
    total_raw_download = 0
    total_added = 0
    # 用于conf处理的标准化基准
    existing_norm = set()
    total_processed_download = 0
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
        # 使用标准化进行去重检查
        unique_new = 0
        duplicates = 0
        norms = []
        for r in processed_rules:
            nr = normalize_rule(r)
            norms.append(nr)
            # 如果规则在自定义的其他类型中，则跳过（自定义规则优先，按其分类）
            if nr and nr in custom_all_norms and custom_all_norms[nr] != rule_type.lower():
                continue
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
        # 将total_added保留为处理项的总数量（去重前总数）用于汇总
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

    # 唯一标准化数量
    unique = sorted(set(all_processed_rules))
    # 仅返回唯一规则集合
    return unique

def format_rule(rule):
    if rule.startswith("- '+.") or rule.startswith("- '"):
        return convert_txt_to_conf(rule)
    # 保留IP和ASN条目
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
    # 这里不打印每源或每类型汇总以避免重复日志
    proxy_rules = process_rules_for_conf(all_downloaded_rules.get("Proxy", []), custom_rules, rule_type='Proxy', verbose=False)
    ai_rules = process_rules_for_conf(all_downloaded_rules.get("Ai", []), custom_rules, rule_type='Ai', verbose=False)
    
    merged_conf_rules = sorted(set(proxy_rules + ai_rules))
    
    merged_conf_file = os.path.join(get_script_dir(), "merged_rules.conf")
    try:
        with open(merged_conf_file, 'w', encoding='utf-8') as f:
            for rule in merged_conf_rules:
                formatted_rule = format_rule(rule)
                f.write(f"{formatted_rule}\n")
        print(f"已生成 {merged_conf_file}，包含 {len(merged_conf_rules)} 条唯一规则")
        # 可读性分隔符
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
             ("https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/openai.yaml", "MetaCubeX openai"), 
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

    # 只处理 Proxy 规则
    print("\n处理 Proxy 规则...")
    print('-' * 60)
    
    # 处理下载的 proxy 规则，传入完整的custom_rules用于跨类型检查
    proxy_rules = process_rules(all_downloaded_rules.get("Proxy", []), custom_rules, rule_type="Proxy", verbose=True)
    
    # 获取自定义 proxy 规则
    custom_proxy_rules = custom_rules.get('proxy', [])
    
    # 合并：自定义规则在前，下载规则在后（自定义优先）
    final_proxy_rules = custom_proxy_rules + proxy_rules
    
    # 去重最终规则（自定义优先）
    normalized_final = {}
    for rule in final_proxy_rules:
        norm = normalize_rule(rule)
        if norm not in normalized_final:
            normalized_final[norm] = rule
    final_proxy_rules = list(normalized_final.values())
    
    # 保存到文件
    save_rules_txt(final_proxy_rules, "Proxy.txt")

    # 生成 merged_rules.conf
    generate_merged_rules_conf(all_downloaded_rules, custom_rules)

    # 处理并保存其他类型规则文件
    for output_name in ["Ai", "Direct", "Reject"]:
        rules = process_rules(all_downloaded_rules.get(output_name, []), custom_rules, rule_type=output_name)
        save_rules_txt(rules, f"{output_name}.txt")

if __name__ == "__main__":
    main()

