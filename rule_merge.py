import requests
import yaml
import os
import sys
from collections import OrderedDict
from urllib.parse import urlparse
import concurrent.futures

def download_rules(url):
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        content = response.text
        return content
    except requests.RequestException as e:
        print(f"Error downloading {url}: {e}", file=sys.stderr)
        return None

def download_all_rules(rule_sets_config):
    all_rules = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(download_rules, url): (output_name, url, comment) 
                         for output_name, urls in rule_sets_config.items() 
                         for url, comment in urls}
        for future in concurrent.futures.as_completed(future_to_url):
            output_name, url, comment = future_to_url[future]
            try:
                content = future.result()
                if content:
                    file_format = get_file_format(url)
                    all_rules.setdefault(output_name, []).append((content, file_format, comment))
                else:
                    print(f"Failed to download rules from {comment} ({url})")
            except Exception as exc:
                print(f"{comment} ({url}) generated an exception: {exc}", file=sys.stderr)
    return all_rules

def process_rule(rule):
    # 移除注释和空白
    rule = rule.split('#')[0].strip()
    
    # 如果规则为空，返回None
    if not rule or rule.lower() == 'payload:':
        return None
    
    # 移除引号和多余的加号、减号、点号和空格
    rule = rule.strip("'-+ .")
    
    # 检查是否包含HTML标签或属性，如果有则跳过
    if '<' in rule or '>' in rule or 'class=' in rule or 'data-' in rule:
        return None
    
    # 确保规则有正确的前缀
    prefixes = ['DOMAIN,', 'DOMAIN-SUFFIX,', 'DOMAIN-KEYWORD,', 'DOMAIN-REGEX,', 'IP-CIDR,', 'IP-CIDR6,', 'IP-ASN,', 'PROCESS-NAME,', 'USER-AGENT,']
    if not any(rule.startswith(prefix) for prefix in prefixes):
        rule = 'DOMAIN-SUFFIX,' + rule
    
    return rule

def parse_rules(content, file_format):
    if content is None:
        return {'payload': []}
    try:
        if file_format == 'yml':
            return yaml.safe_load(content)
        elif file_format in ['txt', 'list']:
            rules = {'payload': []}
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    rules['payload'].append(line)
            return rules
        else:
            raise ValueError(f"Unsupported file format: {file_format}")
    except Exception as e:
        print(f"Error parsing rules: {e}", file=sys.stderr)
        return {'payload': []}

def sort_rules(rules):
    return sorted(rules, key=lambda x: (x.split(',')[0], x))

def merge_rules(rule_sets):
    merged = []
    for rule_set in rule_sets:
        for rule in rule_set.get('payload', []):
            processed_rule = process_rule(rule)
            if processed_rule:
                merged.append(processed_rule)
    
    sorted_merged = sort_rules(set(merged))
    
    print(f"Merged rules count: {len(sorted_merged)}")
    print(f"Sample of merged rules: {sorted_merged[:5]}")  # 打印一些合并后的规则样本
    return {'payload': sorted_merged}

def save_rules_txt(rules, output_file):
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for rule in rules:
                f.write(f"{rule}\n")
        print(f"Generated {output_file} with {len(rules)} rules")
    except IOError as e:
        print(f"Error writing to {output_file}: {e}", file=sys.stderr)

def merge_rules_with_priority(custom_rules, third_party_rules):
    merged = []
    
    # 添加自定义规则
    for rule in custom_rules:
        processed_rule = process_rule(rule)
        if processed_rule:
            merged.append(processed_rule)
    
    # 统计自定义规则数量
    custom_rules_count = len(merged)
    
    # 添加第三方规则（如果不在自定义规则中）
    for rule in third_party_rules:
        processed_rule = process_rule(rule)
        if processed_rule and processed_rule not in merged:
            merged.append(processed_rule)

    sorted_merged = sort_rules(merged)
    
    return {'payload': sorted_merged, 'custom_count': custom_rules_count}

def save_merged_rules_conf(all_downloaded_rules, output_file, custom_proxy_domains, custom_direct_domains):
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for output_name, rule_sets in all_downloaded_rules.items():
                all_processed_rules = []
                for content, file_format, comment in rule_sets:
                    rules = parse_rules(content, file_format)
                    processed_rules = [rule for rule in (process_rule(r) for r in rules['payload']) if rule]
                    all_processed_rules.extend(processed_rules)
                
                merged_rules = {'payload': sort_rules(set(all_processed_rules))}

                # 处理自定义规则
                if output_name == "Proxy":
                    merged_rules = merge_rules_with_priority(custom_proxy_domains, merged_rules['payload'])
                elif output_name == "Direct":
                    merged_rules = merge_rules_with_priority(custom_direct_domains, merged_rules['payload'])
                
                for rule in merged_rules.get('payload', []):
                    f.write(f"{rule}\n")
                
                print(f"Added {len(merged_rules['payload'])} rules for {output_name}")
        print(f"Generated {output_file}")
    except IOError as e:
        print(f"Error writing to {output_file}: {e}", file=sys.stderr)

def get_file_format(content_or_url):
    if content_or_url.startswith(('http://', 'https://')):
        # 这是一个 URL
        path = urlparse(content_or_url).path
        extension = os.path.splitext(path)[1].lower()
    else:
        # 这是内容字符串，尝试通过内容判断格式
        if content_or_url.strip().startswith(('DOMAIN', 'IP-CIDR', 'USER-AGENT')):
            return 'txt'
        elif content_or_url.strip().startswith(('payload:', '---')):
            return 'yml'
        else:
            # 默认为 txt 格式
            return 'txt'
    
    if extension in ['.yml', '.yaml']:
        return 'yml'
    elif extension in ['.txt', '.list']:
        return 'txt'
    else:
        raise ValueError(f"Unsupported file format: {extension}")

def read_custom_domains(file_path):
    if not os.path.exists(file_path):
        print(f"Info: Custom domain file {file_path} does not exist. Skipping.")
        return []
    
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except IOError:
        print(f"Warning: Could not read {file_path}. Skipping custom domains.")
        return []

def merge_proxy_and_ai_rules(all_downloaded_rules, output_file):
    try:
        merged_rules = []
        
        # 合并 Proxy 和 Ai 规则
        for output_name in ['Proxy', 'Ai']:
            if output_name in all_downloaded_rules:
                for content, _, _ in all_downloaded_rules[output_name]:
                    rules = parse_rules(content, get_file_format(content))
                    processed_rules = [rule for rule in (process_rule(r) for r in rules['payload']) if rule]
                    merged_rules.extend(processed_rules)
        
        # 排序并去重
        sorted_merged = sort_rules(set(merged_rules))
        
        # 写入文件
        with open(output_file, 'w', encoding='utf-8') as f:
            for rule in sorted_merged:
                f.write(f"{rule}\n")
        
        print(f"Generated {output_file} with {len(sorted_merged)} rules")
        print(f"Sample of merged rules: {sorted_merged[:5]}")
    except IOError as e:
        print(f"Error writing to {output_file}: {e}", file=sys.stderr)

def main():
    rule_sets_config = {
         "Proxy": [
        ("https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt", "Loyalsoldier Proxy"),
        ],
        "Ai": [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Copilot/Copilot.list", "blackmatrix7 Copilot"),
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/OpenAI/OpenAI.list", "blackmatrix7 OpenAI"),    
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

    # 读取自定义域名
    custom_proxy_domains = read_custom_domains('custom_proxy.txt')
    custom_direct_domains = read_custom_domains('custom_direct.txt')

    # 并发下载所有规则
    print("Downloading all rules...")
    all_downloaded_rules = download_all_rules(rule_sets_config)
    print("All rules downloaded successfully.")

    # 处理规则并整合自定义域名
    for output_name, rule_sets in all_downloaded_rules.items():
        print(f"\nProcessing {output_name} rules:")
        all_processed_rules = []
        for content, file_format, comment in rule_sets:
            rules = parse_rules(content, file_format)
            processed_rules = [rule for rule in (process_rule(r) for r in rules['payload']) if rule]
            all_processed_rules.extend(processed_rules)
            print(f"Added {len(processed_rules)} rules from {comment}")
            print(f"Sample of processed rules from {comment}: {processed_rules[:5]}")

        if not all_processed_rules:
            print(f"No valid rules found for {output_name}. Skipping.")
            continue

        # 合并自定义规则
        if output_name == "Proxy":
            merged_rules = merge_rules_with_priority(custom_proxy_domains, all_processed_rules)
        elif output_name == "Direct":
            merged_rules = merge_rules_with_priority(custom_direct_domains, all_processed_rules)
        else:
            merged_rules = {'payload': sort_rules(set(all_processed_rules)), 'custom_count': 0}

        # 打印自定义规则数量和总规则数量
        print(f"Custom rules count: {merged_rules['custom_count']}")
        print(f"Total merged rules count: {len(merged_rules['payload'])}")

        # 保存文件
        txt_output_file = f"{output_name}.txt"
        save_rules_txt(merged_rules['payload'], txt_output_file)

        print(f"Sample of final merged rules: {merged_rules['payload'][:5]}")

    # 生成合并的 merged_rules.conf 文件
    print("\nProcessing Merged_rules.conf:")
    merged_conf_file = "merged_rules.conf"
    merge_proxy_and_ai_rules(all_downloaded_rules, merged_conf_file)

if __name__ == "__main__":
    main()
