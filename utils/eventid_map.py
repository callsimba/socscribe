def get_event_description(event_id):
    mapping = {
        "1": "Process Creation",
        "3": "Network Connection",
        "10": "Process Access",
        "11": "File Created",
        "13": "Registry Key Activity",
        "21": "Driver Loaded",
        "22": "Image Loaded",
        "23": "File Deleted",
        "25": "Process Tampering",
    }
    return mapping.get(str(event_id), "Unknown or Custom Event")
