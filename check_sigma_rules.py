#!/usr/bin/env python3
import requests
import json
import sys

# Configuration
API_URL = "http://localhost:8000/api/rules"

def get_rules():
    """Get all rules from the API."""
    try:
        response = requests.get(API_URL)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Failed to get rules: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Error getting rules: {str(e)}")
        return None

def print_rules_summary(rules_data):
    """Print a summary of the rules."""
    if not rules_data or 'rules' not in rules_data:
        print("No rules data available")
        return
    
    rules = rules_data['rules']
    total = rules_data.get('total', len(rules))
    
    print(f"\n=== Sigma Rules Summary ===")
    print(f"Total rules: {total}")
    
    # Count enabled/disabled rules
    enabled_count = sum(1 for rule in rules if rule.get('enabled', False))
    print(f"Enabled rules: {enabled_count}")
    print(f"Disabled rules: {total - enabled_count}")
    
    # Count by severity
    severity_counts = {}
    for rule in rules:
        severity = rule.get('severity', 'unknown')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    print("\nRules by severity:")
    for severity, count in severity_counts.items():
        print(f"  {severity}: {count}")
    
    # Count by category
    category_counts = {}
    for rule in rules:
        category = rule.get('category', 'uncategorized')
        if not category:
            category = 'uncategorized'
        category_counts[category] = category_counts.get(category, 0) + 1
    
    print("\nRules by category:")
    for category, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {category}: {count}")

def print_rules_table(rules_data, show_all=False, filter_enabled=None, filter_category=None, filter_severity=None):
    """Print a table of rules."""
    if not rules_data or 'rules' not in rules_data:
        print("No rules data available")
        return
    
    rules = rules_data['rules']
    
    # Apply filters
    filtered_rules = rules
    
    if filter_enabled is not None:
        filtered_rules = [r for r in filtered_rules if r.get('enabled', False) == filter_enabled]
    
    if filter_category:
        filtered_rules = [r for r in filtered_rules if r.get('category', '').lower() == filter_category.lower()]
    
    if filter_severity:
        filtered_rules = [r for r in filtered_rules if r.get('severity', '').lower() == filter_severity.lower()]
    
    # Limit to 20 rules unless show_all is True
    if not show_all and len(filtered_rules) > 20:
        print(f"\nShowing 20 of {len(filtered_rules)} rules. Use --all to show all rules.")
        filtered_rules = filtered_rules[:20]
    
    # Print table header
    print("\n{:<20} {:<40} {:<10} {:<15} {:<10}".format("ID", "Title", "Severity", "Category", "Enabled"))
    print("-" * 100)
    
    # Print table rows
    for rule in filtered_rules:
        rule_id = rule.get('id', 'N/A')
        if len(rule_id) > 20:
            rule_id = rule_id[:17] + "..."
        
        title = rule.get('title', 'N/A')
        if len(title) > 40:
            title = title[:37] + "..."
        
        severity = rule.get('severity', 'N/A')
        category = rule.get('category', 'N/A')
        enabled = 'Yes' if rule.get('enabled', False) else 'No'
        
        print("{:<20} {:<40} {:<10} {:<15} {:<10}".format(
            rule_id, title, severity, category, enabled
        ))
    
    print(f"\nTotal: {len(filtered_rules)} rules")

def main():
    """Main function."""
    # Parse command line arguments
    show_all = '--all' in sys.argv
    filter_enabled = None
    if '--enabled' in sys.argv:
        filter_enabled = True
    elif '--disabled' in sys.argv:
        filter_enabled = False
    
    filter_category = None
    filter_severity = None
    
    for arg in sys.argv:
        if arg.startswith('--category='):
            filter_category = arg.split('=')[1]
        elif arg.startswith('--severity='):
            filter_severity = arg.split('=')[1]
    
    # Get rules
    rules_data = get_rules()
    if not rules_data:
        return
    
    # Print summary
    print_rules_summary(rules_data)
    
    # Print table
    print_rules_table(rules_data, show_all, filter_enabled, filter_category, filter_severity)
    
    print("\nUsage:")
    print("  --all: Show all rules (default: show only 20)")
    print("  --enabled: Show only enabled rules")
    print("  --disabled: Show only disabled rules")
    print("  --category=<category>: Filter by category")
    print("  --severity=<severity>: Filter by severity")

if __name__ == "__main__":
    main()