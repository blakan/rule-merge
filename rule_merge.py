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
        print(f"Successfully downloaded rules from {url}")
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
                    all_rules.setdefault(output_name, []).append((content, file_format, comment, url))
                    print(f"Successfully downloaded and processed rules from {comment} ({url})")
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

def process_rules(rule_sets, custom_rules):
    all_processed_rules = custom_rules.copy()
    for content, file_format, comment, url in rule_sets:
        rules = parse_rules(content, file_format)
        original_count = len(rules)
        if file_format == 'list':
            processed_rules = [convert_list_to_txt(rule) for rule in rules if convert_list_to_txt(rule)]
        else:
            processed_rules = rules
        all_processed_rules.extend(processed_rules)
        print(f"Added {len(processed_rules)} rules from {comment} (Original: {original_count})")

    all_processed_rules = sorted(set(all_processed_rules))
    return all_processed_rules

def process_rules_for_conf(rule_sets, custom_rules):
    all_processed_rules = []
    for content, file_format, comment, url in rule_sets:
        rules = parse_rules(content, file_format)
        original_count = len(rules)
        if file_format == 'list':
            processed_rules = [rule for rule in rules if rule.startswith(('DOMAIN,', 'DOMAIN-SUFFIX,', 'DOMAIN-KEYWORD,'))]
        else:  # 'txt' format
            processed_rules = [convert_txt_to_conf(rule) for rule in rules]
        all_processed_rules.extend(processed_rules)
        print(f"Added {len(processed_rules)} rules from {comment} (Original: {original_count})")
    
    all_processed_rules.extend(custom_rules)
    return sorted(set(all_processed_rules))

def format_rule(rule):
    if rule.startswith("- '+.") or rule.startswith("- '"):
        return convert_txt_to_conf(rule)
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
    proxy_rules = process_rules_for_conf(all_downloaded_rules.get("Proxy", []), custom_rules.get('proxy', []))
    ai_rules = process_rules_for_conf(all_downloaded_rules.get("Ai", []), custom_rules.get('ai', []))
    
    merged_conf_rules = sorted(set(proxy_rules + ai_rules))
    
    merged_conf_file = os.path.join(get_script_dir(), "merged_rules.conf")
    try:
        with open(merged_conf_file, 'w', encoding='utf-8') as f:
            for rule in merged_conf_rules:
                formatted_rule = format_rule(rule)
                f.write(f"{formatted_rule}\n")
        print(f"Generated {merged_conf_file} with {len(merged_conf_rules)} unique rules")
    except IOError as e:
        print(f"Error writing to {merged_conf_file}: {e}", file=sys.stderr)

def main():
    rule_sets_config = {
        "Proxy": [
            ("https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt", "Loyalsoldier Proxy"),
        ],
        "Ai": [
            ("https://github.com/ACL4SSR/ACL4SSR/blob/master/Clash/Ruleset/AI.list", "ACL4SSR AI"), 
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

    print("Downloading all rules...")
    all_downloaded_rules = download_all_rules(rule_sets_config)
    print("All rules downloaded successfully.")

    # Generate merged_rules.conf
    generate_merged_rules_conf(all_downloaded_rules, custom_rules)

    # Process rules for txt files (if still needed)
    for output_name in ["Proxy", "Ai", "Direct", "Reject"]:
        rules = process_rules(all_downloaded_rules.get(output_name, []), custom_rules.get(output_name.lower(), []))
        save_rules_txt(rules, f"{output_name}.txt")

if __name__ == "__main__":
    main()

