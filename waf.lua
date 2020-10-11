-- 判断和处理主模块

-----------------------------------------------------------------------
-- des：黑白名单
-----------------------------------------------------------------------
if blockip() then
	ngx.exit(444)
end

if whiteip() then
	ngx.ctx.whiteip=true
	return
end

-----------------------------------------------------------------------
-- des：sid处理和计数
-----------------------------------------------------------------------
local wsid = ngx.var.cookie_wsid
local ip = ngx.var.binary_remote_addr
local dict_deny = ngx.shared.dict_deny
local namespace = ngx.var.namespace or ''
-- 先处理无wsid时的deny
if wsid == nil and dict_deny:get(ip..'\x40') == '\x03' then
	ngx.exit(444)
end

local count_a = 0	-- 2XX计数
local count_b = 0	-- 非2XX计数
local now = ngx.localtime():sub(-5, -4)
local credible = 10	-- 默认wsid可信等级为10

local dict_sid = ngx.shared.dict_sid
local dict_ip = ngx.shared.dict_ip
local dict_sys = ngx.shared.dict_sys

-- 针对ip层面，整个ip信誉太低，会提高wsid可信阀值  3倍的Deny2值
local counti_a = get_last_num(dict_ip, ip..'\x01', now, namespace)
local counti_b = get_last_num(dict_ip, ip..'\x02', now, namespace)
if counti_a + counti_b >= Deny2*3 or counti_b >= 30*3 then
	credible = 50
end
ngx.ctx.credible=credible	--传递给log阶段

local ok, key = check_sid(wsid)
if ok ~= true then
	count_a = get_last_num(dict_sid, ip..'\x01', now, namespace)
	count_b = get_last_num(dict_sid, ip..'\x02', now, namespace)
	key = ip
	local time, sid = get_sid()
	-- ngx.header['Set-Cookie'] = 'wsid='.. time .. '|' .. sid ..'; path=/; Expires=' .. ngx.cookie_time(ngx.time() + 60 * 60 * 24 * 7) .. ';  Domain='.. domain() ..'; HttpOnly'
else
	count_a = get_last_num(dict_sid, key..'\x01', now, namespace)
	count_b = get_last_num(dict_sid, key..'\x02', now, namespace)
	if count_a <= credible then
		count_a = get_last_num(dict_sid, ip..'\x01', now, namespace)
		count_b = get_last_num(dict_sid, ip..'\x02', now, namespace)
		key = ip
	end
end


-----------------------------------------------------------------------
-- des：阀值判断
-----------------------------------------------------------------------

if dict_deny:get(key..'\x40') == '\x03' then
	ngx.exit(444)
end

local count_n = count_a + count_b

-- 该局部阶段自定义的阀值
local Deny1 = ngx.var.Deny1 or Deny1
local Deny2 = ngx.var.Deny2 or Deny2
local Deny3 = ngx.var.Deny3 or Deny3

-- wsid - cookie
if count_n >= Deny3 or count_b >= 60 then
	denyType3(dict_deny, key)
elseif count_n >= Deny2 or count_b >= 30 then
	denyType2(dict_deny, key, count_n - Deny2)
elseif count_n >= Deny1 or count_b >= 15 then
	denyType1()
end

-----------------------------------------------------------------------
-- des：cpu负载流程
-----------------------------------------------------------------------

local load_avg = dict_sys:get('cpu1')
if load_avg ~=nil then
	if load_avg >= 0.9  then
		local a = count_n / get_last_num(dict_sys, 'count', now)
		if a >= 0.3 then
			denyType3(dict_deny, key)
		elseif a >= 0.1 then
			denyType2(dict_deny, key, 0)
		elseif a >= 0.05 then
			denyType1()
		end
	elseif load_avg >= 0.8 then
		local a = count_n / get_last_num(dict_sys, 'count', now)
		if a >= 0.35 then
			denyType3(dict_deny, key)
		elseif a >= 0.15 then
			denyType2(dict_deny, key, 0)
		elseif a >= 0.05 then
			denyType1()
		end
	end
end



-----------------------------------------------------------------------
-- des：安全检查
-----------------------------------------------------------------------
if ngx.var.disbale_sec ~= 0 then
	local sec, tag = sec_check()
	if sec then
		local html = [[
			<title>异常……</title>
			<center><h1>服务器检测到了异常，]]..tag..[[</h1></center>
			<hr>
			<center>403</center>
		]]
		ngx.header.content_type = 'text/html'
		ngx.status = 403
		ngx.say(html)
		ngx.exit(403)
	end
end
