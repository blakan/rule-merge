import requests
import yaml
import os
import sys
from collections import OrderedDict
from urllib.parse import urlparse

def download_rules(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        content = response.text
        print(f"Successfully downloaded rules from {url}")
        print(f"Content sample: {content[:100]}...")  # 打印内容样本
        return content
    except requests.RequestException as e:
        print(f"Error downloading {url}: {e}", file=sys.stderr)
        return None

def process_rule(rule):
    # 移除注释
    rule = rule.split('#')[0].strip()
    
    # 如果规则为空，返回None
    if not rule:
        return None
    
    # 检查是否包含HTML标签或属性，如果有则跳过
    if '<' in rule or '>' in rule or 'class=' in rule or 'data-' in rule:
        return None
    
    # 如果规则以引号开始和结束，移除引号
    if (rule.startswith("'") and rule.endswith("'")) or (rule.startswith('"') and rule.endswith('"')):
        rule = rule[1:-1]
    
    # 如果规则已经以 '- ' 开头，直接返回
    if rule.startswith('- '):
        return rule
    
    # 否则，在规则前添加 '- '
    return f"- {rule}"

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
    
def merge_rules(rule_sets):
    merged = set()
    for rule_set in rule_sets:
        for rule in rule_set.get('payload', []):
            processed_rule = process_rule(rule)
            if processed_rule:
                merged.add(processed_rule)
    
    print(f"Merged rules count: {len(merged)}")
    print(f"Sample of merged rules: {list(merged)[:5]}")  # 打印一些合并后的规则样本
    return {'payload': sorted(merged)}

def save_rules_txt(rules, output_file):
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("payload:\n")
            for rule in rules.get('payload', []):
                f.write(f"{rule}\n")
        print(f"Generated {output_file} with {len(rules.get('payload', []))} rules")
    except IOError as e:
        print(f"Error writing to {output_file}: {e}", file=sys.stderr)

def merge_rules_with_priority(custom_rules, third_party_rules):
    merged = set()
    
    # 添加自定义规则
    for rule in custom_rules:
        processed_rule = process_rule(rule)
        if processed_rule:
            merged.add(processed_rule)
    
    # 添加第三方规则（如果不在自定义规则中）
    for rule in third_party_rules:
        processed_rule = process_rule(rule)
        if processed_rule and processed_rule not in merged:
            merged.add(processed_rule)

    print(f"Merged rules with priority count: {len(merged)}")
    print(f"Sample of merged rules with priority: {list(merged)[:5]}")  # 打印一些合并后的规则样本
    return {'payload': sorted(merged)}

def save_merged_rules_conf(rule_sets_config, output_file, custom_proxy_domains, custom_direct_domains):
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for output_name, rule_urls in rule_sets_config.items():
                rule_sets = []
                for url in rule_urls:
                    content = download_rules(url)
                    file_format = get_file_format(url)
                    rules = parse_rules(content, file_format)
                    rule_sets.append(rules)
                
                merged_rules = merge_rules(rule_sets)

                # 处理自定义规则
                if output_name == "Proxy":
                    merged_rules = merge_rules_with_priority(custom_proxy_domains, merged_rules['payload'])
                elif output_name == "Direct":
                    merged_rules = merge_rules_with_priority(custom_direct_domains, merged_rules['payload'])
                
                for rule in merged_rules.get('payload', []):
                    f.write(f"{rule[2:]}\n")  # 移除开头的 '- '
        print(f"Generated {output_file}")
    except IOError as e:
        print(f"Error writing to {output_file}: {e}", file=sys.stderr)

def get_file_format(url):
    path = urlparse(url).path
    extension = os.path.splitext(path)[1].lower()
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

def main():
    rule_sets_config = {
        "Proxy": [
            "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt",
        ],
        "Direct": [
            "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt",
            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Download/Download.list",
            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/ChinaMax/ChinaMax.list",
            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Direct/Direct.list",            
            "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaDomain.list",
            "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaCompanyIp.list",
        #    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaIp.list",
            "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/LocalAreaNetwork.list",
        ],
        "Reject": [
            "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt",
        ],
        "Ai": [
            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Copilot/Copilot.list",
            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/OpenAI/OpenAI.list",    
        ],
    }

    # 读取自定义域名
    custom_proxy_domains = read_custom_domains('custom_proxy.txt')
    custom_direct_domains = read_custom_domains('custom_direct.txt')

    # 处理规则并整合自定义域名
    for output_name, rule_urls in rule_sets_config.items():
        print(f"\nProcessing {output_name} rules:")
        rule_sets = []
    for url in rule_urls:
        content = download_rules(url)
        if content:
            file_format = get_file_format(url)
            rules = parse_rules(content, file_format)
            rule_sets.append(rules)
            print(f"  Added {len(rules['payload'])} rules from {url}")
    
    if not rule_sets:
        print(f"No valid rules found for {output_name}. Skipping.")
        return

    merged_rules = merge_rules(rule_sets)
    print(f"Merged rules count before priority: {len(merged_rules['payload'])}")

    # 使用新的合并函数，确保自定义规则优先
    if output_name == "Proxy":
        merged_rules = merge_rules_with_priority(custom_proxy_domains, merged_rules['payload'])
    elif output_name == "Direct":
        merged_rules = merge_rules_with_priority(custom_direct_domains, merged_rules['payload'])

    print(f"Final merged rules count: {len(merged_rules['payload'])}")

    # 保存文件
    txt_output_file = f"{output_name}.txt"
    save_rules_txt(merged_rules, txt_output_file)

    # 生成合并的 .conf 文件
    merged_conf_file = "merged_rules.conf"
    save_merged_rules_conf(rule_sets_config, merged_conf_file, custom_proxy_domains, custom_direct_domains)


if __name__ == "__main__":
    main()
