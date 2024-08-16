import requests
import yaml
import os
import sys
from collections import OrderedDict
from urllib.parse import urlparse
import concurrent.futures

def get_script_dir():
    return os.path.dirname(os.path.realpath(__file__))

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

def parse_rules(content, file_format):
    if content is None:
        return []
    try:
        if file_format == 'txt':
            lines = content.splitlines()
            return [line.strip() for line in lines if line.strip() and not line.strip().lower() == 'payload:']
        elif file_format in ['list']:
            return [line.strip() for line in content.splitlines() if line.strip() and not line.startswith('#')]
        else:
            raise ValueError(f"Unsupported file format: {file_format}")
    except Exception as e:
        print(f"Error parsing rules: {e}", file=sys.stderr)
        return []

def convert_list_to_txt(rule):
    if rule.startswith('DOMAIN,'):
        return f"- '{rule.split(',')[1]}'"
    elif rule.startswith('DOMAIN-SUFFIX,'):
        return f"- '+.{rule.split(',')[1]}'"
    return None

def convert_txt_to_conf(rule):
    if rule.startswith("- '+."):
        domain = rule[5:-1] if rule.endswith("'") else rule[5:]
        return f"DOMAIN-SUFFIX,{domain},PROXY"
    elif rule.startswith("DOMAIN-SUFFIX,") or rule.startswith("DOMAIN,") or rule.startswith("DOMAIN-KEYWORD,"):
        return f"{rule},PROXY"
    return rule

def get_file_format(url):
    path = urlparse(url).path
    extension = os.path.splitext(path)[1].lower()
    if extension in ['.txt', '.list']:
        return 'txt' if extension == '.txt' else 'list'
    else:
        raise ValueError(f"Unsupported file format: {extension}")

def read_custom_rules(file_name):
    file_path = os.path.join(get_script_dir(), file_name)
    if not os.path.exists(file_path):
        print(f"Custom rule file {file_path} not found.")
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

def merge_rules_with_priority(custom_rules, third_party_rules):
    all_rules = custom_rules + third_party_rules
    sorted_rules = sorted(set(all_rules))
    return sorted_rules

def save_rules_txt(rules, output_file):
    file_path = os.path.join(get_script_dir(), output_file)
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("payload:\n")
            for rule in rules:
                f.write(f"  {rule}\n")
        print(f"Generated {file_path} with {len(rules)} rules")
    except IOError as e:
        print(f"Error writing to {file_path}: {e}", file=sys.stderr)

def merge_proxy_and_ai_rules(proxy_rules, ai_rules, custom_proxy_rules):
    all_rules = custom_proxy_rules + proxy_rules + ai_rules
    sorted_unique_rules = sorted(set(all_rules))
    return [rule if rule.endswith(',PROXY') else f"{rule},PROXY" for rule in sorted_unique_rules]

def remove_duplicate_rules(proxy_rules, ai_rules):
    return [rule for rule in proxy_rules if rule not in ai_rules]

def process_rules(rule_sets, custom_rules):
    all_processed_rules = custom_rules.copy()  # 保持自定义规则的原有格式
    for content, file_format, comment in rule_sets:
        rules = parse_rules(content, file_format)
        if file_format == 'list':
            processed_rules = [convert_list_to_txt(rule) for rule in rules if convert_list_to_txt(rule)]
        else:
            processed_rules = rules
        all_processed_rules.extend(processed_rules)
        print(f"Added {len(processed_rules)} rules from {comment}")

    all_processed_rules = sorted(set(all_processed_rules))
    return all_processed_rules

def generate_merged_rules_conf(proxy_rules, ai_rules, custom_rules):
    merged_conf_rules = merge_proxy_and_ai_rules(proxy_rules, ai_rules, custom_rules.get('proxy', []) + custom_rules.get('ai', []))
    merged_conf_rules = sorted(set(merged_conf_rules))
    
    merged_conf_file = os.path.join(get_script_dir(), "merged_rules.conf")
    try:
        with open(merged_conf_file, 'w', encoding='utf-8') as f:
            for rule in custom_rules.get('proxy', []) + custom_rules.get('ai', []):
                f.write(f"{convert_txt_to_conf(rule)}\n")
            for rule in merged_conf_rules:
                if rule not in custom_rules.get('proxy', []) and rule not in custom_rules.get('ai', []):
                    f.write(f"{rule}\n")
        print(f"Generated {merged_conf_file} with {len(merged_conf_rules)} rules")
    except IOError as e:
        print(f"Error writing to {merged_conf_file}: {e}", file=sys.stderr)

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

    custom_rules = read_custom_rules('custom_rule.txt')

    print("Downloading all rules...")
    all_downloaded_rules = download_all_rules(rule_sets_config)
    print("All rules downloaded successfully.")

    # 首先处理 AI 规则
    ai_rules = process_rules(all_downloaded_rules.get("Ai", []), custom_rules.get('ai', []))
    save_rules_txt(ai_rules, "Ai.txt")

    # 然后处理 Proxy 规则，并去除与 AI 重复的规则
    proxy_rules = process_rules(all_downloaded_rules.get("Proxy", []), custom_rules.get('proxy', []))
    proxy_rules = remove_duplicate_rules(proxy_rules, ai_rules)
    save_rules_txt(proxy_rules, "Proxy.txt")

    # 处理其他规则集
    for output_name in ["Direct", "Reject"]:
        rules = process_rules(all_downloaded_rules.get(output_name, []), custom_rules.get(output_name.lower(), []))
        save_rules_txt(rules, f"{output_name}.txt")

    # 生成 merged_rules.conf
    generate_merged_rules_conf(proxy_rules, ai_rules, custom_rules)

if __name__ == "__main__":
    main()
