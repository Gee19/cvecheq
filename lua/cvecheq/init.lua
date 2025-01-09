local M = {}

local api = vim.api
local plenary_http = require("plenary.job")
local toml = require("cvecheq.toml") -- TOML parser library
local json = vim.json                -- Lua JSON module for encoding/decoding
local uv = vim.loop                  -- Access LuaJIT's libuv bindings

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

-- Display CVE info as virtual text
local function display_virtual_text(bufnr, line, cves)
	if #cves > 0 then
		local virtual_text = {}
		for _, cve in ipairs(cves) do
			table.insert(virtual_text, string.format("CVE: %s (Fix: %s)", cve.id, cve.fix_version))
		end

		api.nvim_buf_set_extmark(bufnr, api.nvim_create_namespace("cve_checker"), line, 0, {
			virt_text = { { table.concat(virtual_text, " | "), "WarningMsg" } },
			virt_text_pos = "eol",
		})
	end
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
	local bufnr = api.nvim_get_current_buf()

	-- Iterate over dependencies
	local line = 0
	for dep, _ in pairs(dependencies) do
		vim.defer_fn(function()
			local data = fetch_cves(dep, cache)

			-- Print basic info to the command line
			print(string.format("Dependency: %s", dep))
			if #data.cves > 0 then
				for _, cve in ipairs(data.cves) do
					print(string.format("- CVE: %s | Fix Version: %s", cve.id, cve.fix_version))
				end
			else
				print("- No CVEs found")
			end

			-- Display CVEs as virtual text
			display_virtual_text(bufnr, line, data.cves)

			-- Save cache after processing each dependency
			save_cache(cache)
		end, 500) -- 500 ms delay between requests

		line = line + 1
	end
end

-- Command to run the plugin
function M.run()
	local filepath = vim.fn.expand("%:p")
	if not filepath:match("pyproject%.toml$") then
		vim.api.nvim_err_writeln("CveChecker only works with pyproject.toml files!")
		return
	end

	local file = io.open(filepath, "r")
	if not file then
		vim.api.nvim_err_writeln("Unable to open pyproject.toml file!")
		return
	end

	local data = file:read("*a")
	file:close()

	-- Parse TOML data
	local parsed = toml.parse(data)

	-- Check for dependencies
	local dependencies = parsed["tool.poetry.dependencies"]
	if not dependencies or vim.tbl_isempty(dependencies) then
		vim.api.nvim_err_writeln("No dependencies found in pyproject.toml")
		return
	end

	print("Dependencies found:")
	for dep, version in pairs(dependencies) do
		print(dep .. " : " .. version)
	end
end

-- Autocommand to trigger the plugin on opening pyproject.toml
function M.setup()
	api.nvim_create_user_command("CveCheckerRun", M.run, {})
	vim.api.nvim_create_autocmd("BufReadPost", {
		pattern = "pyproject.toml",
		callback = function()
			require("cvecheq").run()
		end,
	})
end

return M
