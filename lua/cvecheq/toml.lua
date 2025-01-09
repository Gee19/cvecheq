local toml = {}

function toml.parse(data)
	local result = {}
	local current_section = nil

	for line in data:gmatch("[^\r\n]+") do
		line = line:match("^%s*(.-)%s*$") -- Trim whitespace
		if line:match("^#") or line == "" then
			-- Ignore comments and blank lines
		elseif line:match("^%[.+%]$") then
			-- Handle sections
			current_section = line:match("^%[([^%]]+)%]$")
			result[current_section] = {}
		elseif line:match("^.+%s=%s.+$") then
			-- Handle key-value pairs
			local key, value = line:match("^([^=]+)%s=%s(.+)$")
			key = key:match("^%s*(.-)%s*$") -- Trim key
			value = value:match("^%s*(.-)%s*$") -- Trim value

			-- Remove quotes around string values
			if value:match('^".*"$') or value:match("^'.*'$") then
				value = value:sub(2, -2)
			end

			-- Add the key-value pair to the current section
			if current_section then
				result[current_section][key] = value
			else
				result[key] = value
			end
		end
	end

	return result
end

return toml
