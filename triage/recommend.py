def recommend_response(alert):
    rule_id = str(alert.get("rule", {}).get("id"))

    if rule_id == "5712":  # SSH brute force
        print("- Check /var/log/auth.log for additional failed attempts")
        print("- Block the source IP using UFW or iptables")
        print("- Consider enabling fail2ban")
        print("- Investigate if any login was eventually successful")
    else:
        print("- Review alert context manually")
        print("- Investigate logs and process activity")
        print("- Escalate if unusual behavior is confirmed")
