function reformat(tag, timestamp, record)
    -- Create a new record that exactly matches the API's expected structure
    local new_record = {}
    
    -- Set the source field (required by the API)
    new_record["source"] = "syslog"
    
    -- Set the message field (required by the API)
    if record["message"] then
        new_record["message"] = record["message"]
    else
        -- If no message field, create one from available data
        if record["hostname"] and record["ident"] then
            new_record["message"] = string.format("Message from %s [%s]", record["hostname"], record["ident"])
        else
            new_record["message"] = "Syslog message"
        end
    end
    
    -- Set the level field (default to "INFO" if not present)
    new_record["level"] = "INFO"
    
    -- Create a metadata object with all the original fields
    local log_metadata = {}
    for k, v in pairs(record) do
        -- Only add non-nil values to avoid serialization issues
        if v ~= nil then
            log_metadata[k] = v
        end
    end
    
    -- Add the metadata to the new record
    new_record["log_metadata"] = log_metadata
    
    -- Return the new record
    return 1, timestamp, new_record
end

return reformat