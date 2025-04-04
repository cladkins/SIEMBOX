function reformat_ocsf(tag, timestamp, record)
    -- Create OCSF-compliant record
    local ocsf_record = {}
    
    -- Core OCSF fields
    ocsf_record["time"] = os.date("!%Y-%m-%dT%H:%M:%SZ", timestamp)
    
    -- Determine OCSF class, category, and activity based on record content
    -- This mapping aligns with pySigma-pipeline-ocsf expectations
    local ocsf_mapping = determine_ocsf_mapping(record)
    
    -- Apply OCSF classification
    ocsf_record["class_uid"] = ocsf_mapping.class_uid
    ocsf_record["class_name"] = ocsf_mapping.class_name
    ocsf_record["category_uid"] = ocsf_mapping.category_uid
    ocsf_record["category_name"] = ocsf_mapping.category_name
    ocsf_record["activity_id"] = ocsf_mapping.activity_id
    ocsf_record["activity_name"] = ocsf_mapping.activity_name
    
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
    
    -- Add metadata that helps with pySigma OCSF pipeline matching
    ocsf_record["metadata"] = {
        version = "1.0.0",
        product = {
            name = "SIEMBox",
            vendor_name = "SIEMBox",
            feature = {
                name = "OCSF Log Processing"
            }
        }
    }
    
    -- Store original event
    ocsf_record["raw_event"] = record
    
    return 1, timestamp, ocsf_record
end

-- Function to determine OCSF mapping based on record content
function determine_ocsf_mapping(record)
    -- Default mapping
    local default_mapping = {
        class_uid = 1000,
        class_name = "Log",
        category_uid = 9,
        category_name = "Other",
        activity_id = 9001,
        activity_name = "Other Activity"
    }
    
    -- Extract facility and other indicators
    local facility = record["facility"] or ""
    local program = record["ident"] or record["program"] or ""
    local message = record["message"] or ""
    
    -- Process-related events
    if string.find(message, "process") or string.find(message, "exec") or string.find(program, "proc") then
        return {
            class_uid = 2000,
            class_name = "Process Activity",
            category_uid = 2,
            category_name = "System",
            activity_id = 2001,
            activity_name = "Process Creation"
        }
    end
    
    -- File-related events
    if string.find(message, "file") or string.find(message, "open") or string.find(message, "read") or string.find(message, "write") then
        return {
            class_uid = 3000,
            class_name = "File Activity",
            category_uid = 2,
            category_name = "System",
            activity_id = 3001,
            activity_name = "File Access"
        }
    end
    
    -- Network-related events
    if string.find(message, "connect") or string.find(message, "network") or string.find(message, "socket") then
        return {
            class_uid = 4000,
            class_name = "Network Activity",
            category_uid = 4,
            category_name = "Network",
            activity_id = 4001,
            activity_name = "Network Connection"
        }
    end
    
    -- Authentication events
    if facility == "auth" or string.find(message, "login") or string.find(message, "auth") or string.find(program, "sshd") then
        return {
            class_uid = 5000,
            class_name = "Authentication",
            category_uid = 3,
            category_name = "Identity & Access Management",
            activity_id = 5001,
            activity_name = "User Authentication"
        }
    end
    
    -- Map syslog facility to OCSF category and activity
    local facility_map = {
        ["kern"] = {
            class_uid = 2000,
            class_name = "System Activity",
            category_uid = 2,
            category_name = "System",
            activity_id = 2001,
            activity_name = "Kernel Activity"
        },
        ["user"] = {
            class_uid = 5000,
            class_name = "User Activity",
            category_uid = 3,
            category_name = "Identity & Access Management",
            activity_id = 5001,
            activity_name = "User Activity"
        },
        ["daemon"] = {
            class_uid = 2000,
            class_name = "Service Activity",
            category_uid = 2,
            category_name = "System",
            activity_id = 2002,
            activity_name = "Service Activity"
        },
        ["syslog"] = {
            class_uid = 1000,
            class_name = "Log",
            category_uid = 2,
            category_name = "System",
            activity_id = 1001,
            activity_name = "Logging"
        }
    }
    
    -- Return mapping based on facility if available
    return facility_map[facility] or default_mapping
end

return reformat_ocsf