import requests
import yaml
import os
from collections import OrderedDict
from urllib.parse import urlparse

def download_rules(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Error downloading {url}: {e}", file=sys.stderr)
        return None

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
    merged = {'payload': set()}
    for rule_set in rule_sets:
        merged['payload'].update(rule_set.get('payload', []))
    
    merged['payload'] = sorted(merged['payload'])
    return merged

def process_rule(rule):
    if not isinstance(rule, str):
        return '', ''

    original_rule = rule.strip()
    
    # 检查是否为特定类型的规则
    if original_rule.startswith(('DOMAIN-KEYWORD,', 'DOMAIN-SUFFIX,', 'DOMAIN,')):
        rule_type, domain = original_rule.split(',', 1)
        return rule_type.lower().split('-')[-1], domain.strip()
    
    # 初始化规则类型为 suffix（默认使用 DOMAIN-SUFFIX）
    rule_type = 'suffix'
    
    # 循环处理前缀，直到没有变化为止
    while True:
        new_rule = rule.lstrip('+-. ')
        new_rule = new_rule.strip("'\"")
        
        # 如果规则没有变化，跳出循环
        if new_rule == rule:
            break
        
        rule = new_rule
    
    # 移除可能的注释（以 # 开始）
    rule = rule.split('#')[0].strip()
    
    # 如果规则为空，返回空值
    if not rule:
        return '', ''
    
    return rule_type, rule

def merge_rules_with_priority(custom_rules, third_party_rules):
    merged = {'payload': []}
    custom_set = set(custom_rules)
    
    for rule in custom_rules:
        merged['payload'].append(rule)
    
    for rule in third_party_rules:
        rule_type, processed_rule = process_rule(rule)
        if processed_rule not in custom_set:
            merged['payload'].append(rule)

    return merged
        
def save_rules_txt(rules, output_file):
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("payload:\n")
            for rule in rules.get('payload', []):
                rule_type, processed_rule = process_rule(rule)
                if processed_rule:
                    if rule_type == 'keyword':
                        f.write(f"  - DOMAIN-KEYWORD,{processed_rule}\n")
                    elif rule_type == 'suffix':
                        f.write(f"  - DOMAIN-SUFFIX,{processed_rule}\n")
                    else:
                        f.write(f"  - '{processed_rule}'\n")
        print(f"Generated {output_file}")
    except IOError as e:
        print(f"Error writing to {output_file}: {e}", file=sys.stderr)

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
                    rule_type, processed_rule = process_rule(rule)
                    if processed_rule:
                        if output_name == "Ai":
                            conf_type = "PROXY"
                        else:
                            conf_type = output_name.upper()
                        
                        if rule_type == 'keyword':
                            f.write(f"DOMAIN-KEYWORD,{processed_rule},{conf_type}\n")
                        elif rule_type == 'domain':
                            f.write(f"DOMAIN,{processed_rule},{conf_type}\n")
                        else:
                            # 默认使用 DOMAIN-SUFFIX
                            f.write(f"DOMAIN-SUFFIX,{processed_rule},{conf_type}\n")
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
            "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaIp.list",
            "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/LocalAreaNetwork.list",
            "https://raw.githubusercontent.com/Aethersailor/Custom_OpenClash_Rules/main/Rule/Custom_Direct.list",
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
        rule_sets = []
        for url in rule_urls:
            content = download_rules(url)
            if content:
                file_format = get_file_format(url)
                rules = parse_rules(content, file_format)
                rule_sets.append(rules)
        
        if not rule_sets:
            print(f"No valid rules found for {output_name}. Skipping.")
            continue

        merged_rules = merge_rules(rule_sets)

        # 使用新的合并函数，确保自定义规则优先
        if output_name == "Proxy":
            merged_rules = merge_rules_with_priority(custom_proxy_domains, merged_rules['payload'])
        elif output_name == "Direct":
            merged_rules = merge_rules_with_priority(custom_direct_domains, merged_rules['payload'])


        # 保存文件
        txt_output_file = f"{output_name}.txt"
        save_rules_txt({'payload': merged_rules['payload']}, txt_output_file)

    # 生成合并的 .conf 文件
    merged_conf_file = "merged_rules.conf"
    save_merged_rules_conf(rule_sets_config, merged_conf_file, custom_proxy_domains, custom_direct_domains)


if __name__ == "__main__":
    main()
