import requests
import yaml
import os
from collections import OrderedDict
from urllib.parse import urlparse

def download_rules(url):
    response = requests.get(url)
    response.raise_for_status()
    return response.text

def parse_rules(content, file_format):
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

def merge_rules(rule_sets):
    merged = {'payload': set()}
    for rule_set in rule_sets:
        merged['payload'].update(rule_set.get('payload', []))
    
    merged['payload'] = sorted(merged['payload'])
    return merged

def save_rules_txt(rules, output_file):
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("payload:\n")
        for rule in rules.get('payload', []):
            if ',' in rule:
                parts = rule.split(',')
                if len(parts) >= 2:
                    domain = parts[1]
                else:
                    domain = rule
            else:
                domain = rule
            
            if domain.startswith('+.'):
                domain = domain[2:]  # 去掉前缀的 '+.'
            
            f.write(f"  - '{domain}'\n")

def save_merged_rules_conf(rule_sets_config, output_file):
    with open(output_file, 'w', encoding='utf-8') as f:
        for output_name, rule_urls in rule_sets_config.items():
            rule_sets = []
            for url in rule_urls:
                try:
                    content = download_rules(url)
                    file_format = get_file_format(url)
                    rules = parse_rules(content, file_format)
                    rule_sets.append(rules)
                except Exception as e:
                    print(f"Error processing {url}: {str(e)}")
                    continue
            
            if not rule_sets:
                print(f"No valid rules found for {output_name}. Skipping.")
                continue

            merged_rules = merge_rules(rule_sets)
            
            for rule in merged_rules.get('payload', []):
                if ',' in rule:
                    parts = rule.split(',')
                    if len(parts) >= 2:
                        domain = parts[1]
                    else:
                        domain = rule
                else:
                    domain = rule
                
                if domain.startswith('+.'):
                    domain = domain[2:]  # 去掉前缀的 '+.'
                
                # 判断是否为AI链接，如果是则类型为PROXY
                if 'ai_link' in domain:
                    rule_type = 'PROXY'
                else:
                    rule_type = output_name.upper()  # 默认类型为配置名称的大写形式
                
                f.write(f"DOMAIN-SUFFIX,{domain},{rule_type}\n")

def get_file_format(url):
    path = urlparse(url).path
    extension = os.path.splitext(path)[1].lower()
    if extension in ['.yml', '.yaml']:
        return 'yml'
    elif extension in ['.txt', '.list']:
        return 'txt'
    else:
        raise ValueError(f"Unsupported file format: {extension}")

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

    # 生成合并的 .conf 文件
    merged_conf_file = "merged_rules.conf"
    save_merged_rules_conf(rule_sets_config, merged_conf_file)
    print(f"Generated {merged_conf_file}")

    # 生成单独的 .txt 文件
    for output_name, rule_urls in rule_sets_config.items():
        rule_sets = []
        for url in rule_urls:
            try:
                content = download_rules(url)
                file_format = get_file_format(url)
                rules = parse_rules(content, file_format)
                rule_sets.append(rules)
            except Exception as e:
                print(f"Error processing {url}: {str(e)}")
                continue
        
        if not rule_sets:
            print(f"No valid rules found for {output_name}. Skipping.")
            continue

        merged_rules = merge_rules(rule_sets)
        
        # 保存文件
        txt_output_file = f"{output_name}.txt"
        save_rules_txt(merged_rules, txt_output_file)
        print(f"Generated {txt_output_file}")

if __name__ == "__main__":
    main()
