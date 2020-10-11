
local dict_sid = ngx.shared.dict_sid
local dict_ip = ngx.shared.dict_ip

--local value = limit:incr('xxx', 1, 0, 60*60)
local ip = ngx.var.binary_remote_addr

local now = tonumber(ngx.localtime():sub(-5, -4))

if whiteip() then
	ngx.say("whiteip")
	ngx.exit(200)
end

--ngx.header.content_type = 'text/html'
local namespace = ngx.var.namespace or ''

local count_a = 0	-- 2XX计数
local count_b = 0	-- 非2XX计数
local wsid = ngx.var.cookie_wsid
local ok, key = check_sid(wsid)
if ok ~= true then
	count_a = get_last_num(dict_sid, ip..'\x01', now, namespace)
	count_b = get_last_num(dict_sid, ip..'\x02', now, namespace)
	key = ip
else
	count_a = get_last_num(dict_sid, key..'\x01', now, namespace)
	count_b = get_last_num(dict_sid, key..'\x02', now, namespace)
	if count_a + count_b <= ngx.ctx.credible then
		count_a = get_last_num(dict_sid, ip..'\x01', now, namespace)
		count_b = get_last_num(dict_sid, ip..'\x02', now, namespace)
		key = ip
	end
end

ngx.header.content_type = 'text/html'

local times = ngx.var.arg_c
local dict_context = ngx.var.arg_dict
if dict_context ~= nil then
	local arg = dict_sid:get_keys()
	for k,v in pairs(arg) do
		ngx.say("[GET ] key:", k, " v:", v)
	end
end
if ngx.var.http_Referer == nil and times~=nil then
	
	for i = 1, tonumber(times)-1  do
		ngx.say([[
		<script  src="]].. i ..[[.js" async ></script >
	]])
	end
end


local count_n = count_a + count_b

-- 该局部阶段自定义的阀值
local Deny1 = ngx.var.Deny1 or Deny1
local Deny2 = ngx.var.Deny2 or Deny2
local Deny3 = ngx.var.Deny3 or Deny3

-- wsid - cookie
if count_n >= Deny3 or count_b >= 60 then
	ngx.say("触发Deny3<br>")
elseif count_n >= Deny2 or count_b >= 30 then
	ngx.say("触发Deny2<br>")
elseif count_n >= Deny1 or count_b >= 15 then
	ngx.say("触发Deny1<br>")
end

-- for i = 1, 100000 do
-- 	local c
-- 	--c = string.find("asdasd","s")
-- 	c = ngx.re.find("asdasd","s","isjo")
-- 	--string.find("asdasd","s",1,true)
-- end

--denyType2(dict_deny, sid_g)



ngx.say("当前时间周期:",now)
ngx.say("<br>sid下的正常请求数:", get_last_num(dict_sid, key..'\x01', now))
ngx.say("<br>sid下的异常请求数:", get_last_num(dict_sid, key..'\x02', now))
ngx.say("<br>整个ip下的正常请求数:", get_last_num(dict_ip, ip..'\x01', now))
ngx.say("<br>整个ip下的异常请求数:", get_last_num(dict_ip, ip..'\x02', now))
ngx.say("<br>当前有效的请求总数:", count_a + count_b)
ngx.say("<br>当前CPU负载:",ngx.shared.dict_sys:get('cpu1'))

-- ngx.say(whiteip())

-- ngx.ctx.foo=11233