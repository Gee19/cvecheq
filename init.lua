local M = {}

local api = vim.api
local plenary_http = require("plenary.job")
local toml = require("toml") -- TOML parser library
local json = vim.json        -- Lua JSON module for encoding/decoding
local uv = vim.loop          -- Access LuaJIT's libuv bindings

-- Cache file path
local cache_file = vim.fn.stdpath("cache") .. "/cve_checker_cache.json"

-- Load cached results from file
local function load_cache()
	local fd = uv.fs_open(cache_file, "r", 438)
	if not fd then return {} end

	local stat = uv.fs_fstat(fd)
	local data = uv.fs_read(fd, stat.size, 0)
	uv.fs_close(fd)

	if data then
		return json.decode(data)
	end
	return {}
end

-- Save cached results to file
local function save_cache(cache)
	local fd = uv.fs_open(cache_file, "w", 438)
	if fd then
		uv.fs_write(fd, json.encode(cache), 0)
		uv.fs_close(fd)
	end
end

-- Fetch CVEs, PyPI URL, and GitHub link for a given dependency
local function fetch_cves(dependency, cache)
	if cache[dependency] then
		print(string.format("Using cached results for %s", dependency))
		return cache[dependency]
	end

	-- Fetch PyPI package details
	local pypi_url = "https://pypi.org/pypi/" .. dependency .. "/json"
	local pypi_result = plenary_http:new({
		command = "curl",
		args = { "-s", pypi_url },
	}):sync()

	if not pypi_result or not pypi_result[1] then
		print(string.format("Failed to fetch PyPI data for %s", dependency))
		return {}
	end

	local pypi_data = vim.json.decode(pypi_result[1])
	local homepage = pypi_data.info.home_page or ""
	local source_repo = pypi_data.info.project_urls and pypi_data.info.project_urls.Source or ""

	-- Fetch GHSA
	local cve_api_url = source_repo .. "security"
	local cve_result = plenary_http:new({
		command = "curl",
		args = { "-s", cve_api_url },
	}):sync()

	local cves = {}
	-- if cve_result and cve_result[1] then
	-- 	cves = vim.json.decode(cve_result[1])
	-- end

	-- Cache the results
	cache[dependency] = {
		pypi_url = "https://pypi.org/project/" .. dependency,
		github_url = source_repo,
		homepage = homepage,
		cves = cves,
	}

	return cache[dependency]
end

-- Process dependencies in pyproject.toml
local function process_pyproject()
	local filepath = vim.fn.expand("%:p")
	local file_content = vim.fn.readfile(filepath)
	local parsed_toml = toml.parse(table.concat(file_content, "\n"))

	local dependencies = parsed_toml.tool and parsed_toml.tool.poetry.dependencies
	if not dependencies then
		api.nvim_err_writeln("No dependencies found in pyproject.toml")
		return
	end

	-- Load cache
	local cache = load_cache()

	for dep, _ in pairs(dependencies) do
		-- Rate limiting: Add a small delay between requests
		vim.defer_fn(function()
			local data = fetch_cves(dep, cache)
			print(string.format("Dependency: %s", dep))
			print(string.format("- PyPI URL: %s", data.pypi_url))
			if data.github_url ~= "" then
				print(string.format("- GitHub URL: %s", data.github_url))
			elseif data.homepage ~= "" then
				print(string.format("- Homepage: %s", data.homepage))
			end

			if #data.cves > 0 then
				for _, cve in ipairs(data.cves) do
					print(string.format("- CVE: %s | Fix Version: %s", cve.id, cve.fix_version))
				end
			else
				print("- No CVEs found")
			end

			-- Save cache after processing each dependency
			save_cache(cache)
		end, 500) -- 500 ms delay between requests
	end
end

-- Autocommand to trigger the plugin on opening pyproject.toml
function M.setup()
	api.nvim_create_autocmd("BufReadPost", {
		pattern = "pyproject.toml",
		callback = process_pyproject,
	})
end

return M
