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
    if rule.startswith("- '"):
        domain = rule[3:-1]
        return f"DOMAIN,{domain},PROXY"
    elif rule.startswith("- '+."):
        domain = rule[5:-1]
        return f"DOMAIN-SUFFIX,{domain},PROXY"
    return rule

def get_file_format(url):
    path = urlparse(url).path
    extension = os.path.splitext(path)[1].lower()
    if extension in ['.txt', '.list']:
        return 'txt' if extension == '.txt' else 'list'
    else:
        raise ValueError(f"Unsupported file format: {extension}")

def read_custom_rules(file_path):
    if not os.path.exists(file_path):
        print(f"Custom rule file {file_path} not found.")
        return []
    with open(file_path, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

def merge_rules_with_priority(custom_rules, third_party_rules):
    all_rules = custom_rules + third_party_rules
    sorted_rules = sorted(set(all_rules))  # 先去重，再排序
    return sorted_rules

def save_rules_txt(rules, output_file):
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("payload:\n")
            for rule in rules:
                f.write(f"  {rule}\n")  # 添加两个空格
        print(f"Generated {output_file} with {len(rules)} rules")
    except IOError as e:
        print(f"Error writing to {output_file}: {e}", file=sys.stderr)

def merge_proxy_and_ai_rules(proxy_rules, ai_rules, custom_proxy_rules):
    all_rules = custom_proxy_rules + proxy_rules + ai_rules
    sorted_unique_rules = sorted(set(all_rules))  # 先去重，再排序
    return [rule if rule.endswith(',PROXY') else f"{rule},PROXY" for rule in sorted_unique_rules]

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

    custom_proxy_rules = read_custom_rules('custom_proxy.txt')
    custom_direct_rules = read_custom_rules('custom_direct.txt')

    print("Downloading all rules...")
    all_downloaded_rules = download_all_rules(rule_sets_config)
    print("All rules downloaded successfully.")

    for output_name, rule_sets in all_downloaded_rules.items():
        print(f"\nProcessing {output_name} rules:")
        all_processed_rules = []
        for content, file_format, comment in rule_sets:
            rules = parse_rules(content, file_format)
            if file_format == 'list':
                processed_rules = [convert_list_to_txt(rule) for rule in rules if convert_list_to_txt(rule)]
            else:
                processed_rules = rules
            all_processed_rules.extend(processed_rules)
            print(f"Added {len(processed_rules)} rules from {comment}")

        all_processed_rules = sorted(set(all_processed_rules))  # 先去重，再排序

        if not all_processed_rules:
            print(f"No valid rules found for {output_name}. Skipping.")
            continue

        if output_name == "Proxy":
            merged_rules = merge_rules_with_priority(custom_proxy_rules, all_processed_rules)
        elif output_name == "Direct":
            merged_rules = merge_rules_with_priority(custom_direct_rules, all_processed_rules)
        else:
            merged_rules = all_processed_rules

        print(f"Total merged rules count: {len(merged_rules)}")

        txt_output_file = f"{output_name}.txt"
        save_rules_txt(merged_rules, txt_output_file)

    # Generate merged_rules.conf
    print("\nProcessing Merged_rules.conf:")
    proxy_rules = all_downloaded_rules.get("Proxy", [])
    ai_rules = all_downloaded_rules.get("Ai", [])
    
    all_proxy_rules = []
    all_ai_rules = []
    
    for content, file_format, _ in proxy_rules:
        rules = parse_rules(content, file_format)
        all_proxy_rules.extend(rules if file_format == 'list' else [convert_txt_to_conf(rule) for rule in rules])
    
    for content, file_format, _ in ai_rules:
        rules = parse_rules(content, file_format)
        all_ai_rules.extend(rules if file_format == 'list' else [convert_txt_to_conf(rule) for rule in rules])

    merged_conf_rules = merge_proxy_and_ai_rules(all_proxy_rules, all_ai_rules, custom_proxy_rules)
    merged_conf_rules = sorted(set(merged_conf_rules))  # 先去重，再排序
    
    merged_conf_file = "merged_rules.conf"
    try:
        with open(merged_conf_file, 'w', encoding='utf-8') as f:
            for rule in merged_conf_rules:
                f.write(f"{rule}\n")
        print(f"Generated {merged_conf_file} with {len(merged_conf_rules)} rules")
    except IOError as e:
        print(f"Error writing to {merged_conf_file}: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
    
