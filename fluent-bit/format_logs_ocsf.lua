function reformat_ocsf(tag, timestamp, record)
    -- Create OCSF-compliant record
    local ocsf_record = {}
    
    -- Core OCSF fields
    ocsf_record["time"] = os.date("!%Y-%m-%dT%H:%M:%SZ", timestamp)
    
    -- Map syslog facility to OCSF category and activity
    local facility_map = {
        ["kern"] = {
            category_uid = 2,
            category_name = "System",
            activity_id = 2001,
            activity_name = "System Activity"
        },
        ["user"] = {
            category_uid = 3,
            category_name = "Identity & Access Management",
            activity_id = 3001,
            activity_name = "User Activity"
        },
        ["auth"] = {
            category_uid = 3,
            category_name = "Identity & Access Management",
            activity_id = 3002,
            activity_name = "Authentication"
        },
        ["daemon"] = {
            category_uid = 2,
            category_name = "System",
            activity_id = 2002,
            activity_name = "Service Activity"
        },
        ["syslog"] = {
            category_uid = 2,
            category_name = "System",
            activity_id = 2003,
            activity_name = "Logging"
        }
    }
    
    -- Default classification if facility not recognized
    local facility = record["facility"] or "syslog"
    local classification = facility_map[facility] or {
        category_uid = 9,
        category_name = "Other",
        activity_id = 9001,
        activity_name = "Other Activity"
    }
    
    -- Apply classification
    ocsf_record["category_uid"] = classification.category_uid
    ocsf_record["category_name"] = classification.category_name
    ocsf_record["activity_id"] = classification.activity_id
    ocsf_record["activity_name"] = classification.activity_name
    
    -- Set class (typically based on event source)
    ocsf_record["class_uid"] = 1000  -- Log class
    ocsf_record["class_name"] = "Log"
    
    -- Map severity
    local severity_map = {
        [0] = {"Emergency", 100},
        [1] = {"Alert", 90},
        [2] = {"Critical", 80},
        [3] = {"Error", 70},
        [4] = {"Warning", 60},
        [5] = {"Notice", 50},
        [6] = {"Informational", 40},
        [7] = {"Debug", 30}
    }
    
    local priority = tonumber(record["priority"]) or 6
    local severity_info = severity_map[priority] or severity_map[6]
    
    ocsf_record["severity"] = severity_info[1]
    ocsf_record["severity_id"] = severity_info[2]
    
    -- Set status (default to Success)
    ocsf_record["status"] = "Success"
    ocsf_record["status_id"] = 1
    
    -- Extract message
    if record["message"] then
        ocsf_record["message"] = record["message"]
    else
        if record["hostname"] and record["ident"] then
            ocsf_record["message"] = string.format("Message from %s [%s]", record["hostname"], record["ident"])
        else
            ocsf_record["message"] = "Syslog message"
        end
    end
    
    -- Extract observables
    -- Source endpoint
    if record["hostname"] then
        ocsf_record["src_endpoint"] = {
            hostname = record["hostname"],
            ip = record["ip"] or "",
            port = record["port"] or ""
        }
    end
    
    -- Device information
    ocsf_record["device"] = {
        product = {
            name = "SIEMBox",
            vendor_name = "SIEMBox"
        }
    }
    
    -- Store original event
    ocsf_record["raw_event"] = record
    
    return 1, timestamp, ocsf_record
end

return reformat_ocsf