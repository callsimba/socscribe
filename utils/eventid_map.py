def get_event_description(event_id):
    mapping = {
    "1": "Process Creation",
    "2": "File Creation Time Changed",
    "3": "Network Connection",
    "4": "Sysmon Service State Changed",
    "5": "Process Terminated",
    "6": "Driver Loaded",
    "7": "Image Loaded",
    "8": "CreateRemoteThread",
    "9": "RawAccessRead",
    "10": "Process Access",
    "11": "File Created",
    "12": "Registry Object Added or Deleted",
    "13": "Registry Key/Value Set",
    "14": "Registry Value Renamed",
    "15": "File CreateStreamHash",
    "16": "Sysmon Configuration Changed",
    "17": "Pipe Created",
    "18": "Pipe Connected",
    "19": "WMI Event Filter Activity",
    "20": "WMI Event Consumer Activity",
    "21": "WMI Event Consumer To Filter",
    "22": "DNS Query",
    "23": "File Deleted",
    "24": "Clipboard Event",
    "25": "Process Tampering",
    "26": "File Block Executable",
    "27": "File Block Shredding",
    "28": "Image Load via Section Mapping",
    "255": "Sysmon Error Event"
}

    return mapping.get(str(event_id), "Unknown or Custom Event")
