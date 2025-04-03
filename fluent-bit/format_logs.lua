function reformat(tag, timestamp, record)
    -- Create a new record that matches the API's expected structure
    local new_record = {}
    
    -- Set the source field (required by the API)
    new_record["source"] = record["hostname"] or "syslog"
    
    -- Set the message field (required by the API)
    new_record["message"] = record["message"] or ""
    
    -- Set the level field (default to "INFO" if not present)
    new_record["level"] = record["level"] or "INFO"
    
    -- Create a metadata object with all the original fields
    local metadata = {}
    for k, v in pairs(record) do
        if k ~= "message" then
            metadata[k] = v
        end
    end
    
    -- Add the metadata to the new record
    new_record["log_metadata"] = metadata
    
    -- Return the new record
    return 1, timestamp, new_record
end

return reformat