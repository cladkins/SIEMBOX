function reformat(tag, timestamp, record)
    -- Print the record for debugging
    print("Input record: " .. require("cjson").encode(record))
    
    -- Create a new record that matches the API's expected structure
    local new_record = {}
    
    -- Set the source field (required by the API)
    new_record["source"] = "syslog"
    
    -- Set the message field (required by the API)
    if record["message"] then
        new_record["message"] = record["message"]
    else
        -- If no message field, use the whole record as the message
        new_record["message"] = require("cjson").encode(record)
    end
    
    -- Set the level field (default to "INFO" if not present)
    new_record["level"] = "INFO"
    
    -- Create a metadata object with all the original fields
    local log_metadata = {}
    for k, v in pairs(record) do
        log_metadata[k] = v
    end
    
    -- Add the metadata to the new record
    new_record["log_metadata"] = log_metadata
    
    -- Print the new record for debugging
    print("Output record: " .. require("cjson").encode(new_record))
    
    -- Return the new record
    return 1, timestamp, new_record
end

return reformat