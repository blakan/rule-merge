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

def save_rules_txt(rules, output_file):
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("payload:\n")
            for rule in rules.get('payload', []):
                domain = process_domain(rule)
                if domain:
                    f.write(f"  - '{domain}'\n")
        print(f"Generated {output_file}")
    except IOError as e:
        print(f"Error writing to {output_file}: {e}", file=sys.stderr)

def save_merged_rules_conf(rule_sets_config, output_file):
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
                
                for rule in merged_rules.get('payload', []):
                    domain = process_domain(rule)
                    if domain:
                        rule_type = 'PROXY' if 'ai_link' in domain.lower() else output_name.upper()
                        f.write(f"DOMAIN-SUFFIX,{domain},{rule_type}\n")
        print(f"Generated {output_file}")
    except IOError as e:
        print(f"Error writing to {output_file}: {e}", file=sys.stderr)
        
def process_domain(rule):
    if not isinstance(rule, str):
        return ''

    # 移除所有引号和首尾空白字符
    domain = rule.strip()
    
    # 移除开头的破折号和空格
    domain = domain.lstrip('- ')

    # 移除开头和结尾的引号
    domain = domain.strip("'\"")
    
    # 循环处理，直到没有变化为止
    while True:
        new_domain = domain
        # 移除开头的 '+.', '-', '+', '.' 等字符
        new_domain = new_domain.lstrip('+.-')
        # 移除结尾的 ',' 等字符
        new_domain = new_domain.rstrip(',')
        # 再次去除首尾空白和引号
        new_domain = new_domain.strip().strip("'\"")
        
        # 如果处理后的域名没有变化，说明已经清理完毕
        if new_domain == domain:
            break
        domain = new_domain

    return domain

# 测试函数
def test_process_domain():
    test_cases = [
        "  - '+.test.org,  ",
        "'+.cnyes.com",
        "'-+.example.com'",
        "'+.-+.complex-example.net,'",
        "3dns-1.adobe.com",
        "'normal.domain.com'",
    ]
    
    for case in test_cases:
        result = process_domain(case)
        print(f"Original: {case}")
        print(f"Processed: {result}")
        print()

# 运行测试
test_process_domain()

def get_file_format(url):
    path = urlparse(url).path
    extension = os.path.splitext(path)[1].lower()
    if extension in ['.yml', '.yaml']:
        return 'yml'
    elif extension in ['.txt', '.list']:
        return 'txt'
    else:
        raise ValueError(f"Unsupported file format: {extension}")

def ensure_files_exist(file_names):
    for file_name in file_names:
        if not os.path.exists(file_name):
            open(file_name, 'a').close()
            print(f"Created empty file: {file_name}")

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

    # 确保所有文件存在
    ensure_files_exist(['Proxy.txt', 'Direct.txt', 'Reject.txt', 'Ai.txt', 'merged_rules.conf'])

    # 生成合并的 .conf 文件
    save_merged_rules_conf(rule_sets_config, "merged_rules.conf")

    # 生成单独的 .txt 文件
    for output_name, rule_urls in rule_sets_config.items():
        rule_sets = []
        for url in rule_urls:
            content = download_rules(url)
            file_format = get_file_format(url)
            rules = parse_rules(content, file_format)
            rule_sets.append(rules)
        
        merged_rules = merge_rules(rule_sets)
        save_rules_txt(merged_rules, f"{output_name}.txt")

if __name__ == "__main__":
    main()
