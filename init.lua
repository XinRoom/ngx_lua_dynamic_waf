require 'config'

function getClientIp()
    local IP  = ngx.var.remote_addr
    return IP or "unknown"
end
-- function write(logfile,msg)
--     local fd = io.open(logfile,"ab")
--     if fd == nil then return end
--     fd:write(msg)
--     fd:flush()
--     fd:close()
-- end
-- function log(method,url,data,ruletag)
--     if attacklog then
--         local realIp = getClientIp()
--         local ua = ngx.var.http_user_agent
--         local servername=ngx.var.server_name
--         local time=ngx.localtime()
--         if ua  then
--             line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\"  \""..ua.."\" \""..ruletag.."\"\n"
--         else
--             line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\" - \""..ruletag.."\"\n"
--         end
--         local filename = logdir..'/'..servername.."_"..ngx.today().."_sec.log"
--         write(filename,line)
--     end
-- end

function whiteip()
    if next(ipWhitelist) ~= nil then
        for _,ip in ipairs(ipWhitelist) do
            if getClientIp()==ip then
                return true
            end
        end
    end
    return false
end

function blockip()
     if next(ipBlocklist) ~= nil then
         for _,ip in ipairs(ipBlocklist) do
             if getClientIp()==ip then
                 ngx.exit(403)
                 return true
             end
         end
     end
     return false
end



-----------------------------------------------------------------------
-- des：生成sid
-- arg： att-扩展
-----------------------------------------------------------------------
function get_sid (att)
    if att == nil then
        att = ''
    end
    --local host = ngx.var.host
    local time = ngx.now()
    -- 引入随机数
    time = tostring(time)..math.random(0,99)
    local sid = ngx.encode_base64(ngx.md5_bin(auth_pir..time..att)):sub(1, 16)
    return time, sid
    -- '; path=/; Expires=' .. ngx.cookie_time(ngx.time() + 60 * 60 * 24 * 7) * 7) ... '; Domain=.a.xinroom.cn; Secure; HttpOnly'
end


-----------------------------------------------------------------------
-- des：检查合法性sid
-- arg：wsid-带时间的sid, expire-过期时间, att-扩展, comp-时间反向
-----------------------------------------------------------------------
function check_sid (wsid, expire, att, comp)
    -- local host = ngx.var.host
    if expire == nil then
        expire = 3600 * 24 * 7
    end
    if att == nil then
        att = ''
    end
    if wsid ~= nil and wsid ~= '' then
        local from, to, err = ngx.re.find(wsid, [[\|]], "jo")
        if from and from > 1 and from == to then
            local time = tonumber(string.sub(wsid, 0, from-3))  --有2位是随机数
            local tmp = false
            if comp == nil then
                tmp = (time + expire) > ngx.now()
            else
                tmp = (time + expire) <= ngx.now()
            end
            if time ~= nil and tmp then
                local mac = string.sub(wsid, from+1)
                -- 引入两位随机数
                if ngx.encode_base64(ngx.md5_bin(auth_pir..string.sub(wsid, 0, from-1)..att)):sub(1, 16) == mac then
                    return true, ngx.decode_base64(mac)
                end
            end
        end
    end
    return false
end

-----------------------------------------------------------------------
-- des：字符串分割
-- arg：_str-要被分割的字符串 ,seperator-分割字符
-----------------------------------------------------------------------
function explode ( _str, seperator)
    local pos, arr = 0, {}
    for st, sp in function() return string.find( _str, seperator, pos, true ) end do
        table.insert(arr, string.sub(_str, pos, st-1 ))
        pos = sp + 1
    end
    table.insert(arr, string.sub( _str, pos))
    return arr
end


-----------------------------------------------------------------------
-- des：获得近一分钟统计数据
-- arg：
-----------------------------------------------------------------------
function get_last_num ( _dict, key1, key2, namespace)
    -- key2 = tonumber(key2)
    local key3 = key2-1
    namespace = namespace or ''
    if key2 == 0 then key3 = 59 end   -- 00min的上一秒为59min
    local last_value = _dict:get(key1..namespace..key3)
    if last_value == nil then
        last_value = _dict:get(key1..namespace..'\x03') or 0
    end
    local val = _dict:get(key1..namespace..key2) or 0
    local ttl = _dict:ttl(key1..namespace..key2) or 0
    local ave = 0
    if ttl > 60*4 then
        ave = math.ceil(last_value / 60 * (ttl - 60*4) )
    else
        val = last_value
    end
    return val + ave
end

-----------------------------------------------------------------------
-- des：获得一级域名
-- arg：
-----------------------------------------------------------------------
function domain ()
    local host = ngx.var.host
    local pos, arr = 0, {}
    for st, sp in function() return string.find( host, '.', pos, true ) end do
        table.insert(arr, sp)
        pos = sp + 1
    end
    if #arr >= 2 and tonumber(host:sub(arr[(#arr)]+1)) == nil then
        return host:sub(arr[(#arr)-1])
    end
    return '.'..host
end

-----------------------------------------------------------------------
-- des：更新键值统计数据，增量加一
-- arg：_dict-要更新的dict, key1-主键值 , key2-统计键值, inc增量, namespace命令空间
-----------------------------------------------------------------------
function incr_dict ( _dict, key1, key2, inc, namespace)
    -- key2 = tonumber(key2)
    local incr = inc or 1
    namespace = namespace or ''
    _dict:incr(key1..namespace..key2, incr, 0, 60*5)
    local key3 = key2-1
    if key2 == 0 then key3 = 59 end
    local last_value = _dict:get(key1..namespace..key3)
    if last_value == nil then
        return
    else
        _dict:set(key1..namespace..'\x03', last_value, 60*10)
        _dict:delete(key1..namespace..key3)
    end
end



-----------------------------------------------------------------------
----------------------------- deny module -----------------------------
-----------------------------------------------------------------------

-----------------------------------------------------------------------
-- des：deny type-1 随机延迟0~2秒响应
-- arg：
-----------------------------------------------------------------------
function denyType1()
    ngx.sleep(math.random() / 2)
end

-----------------------------------------------------------------------
-- des：deny type-2 禁止5s 且必须在第4 或者 6s时重刷新
-- arg：
-----------------------------------------------------------------------
function denyType2(dict, key, ex)
    -- 验证通过判断
    local wsid_2 = ngx.var.cookie_wsid_2
    -- 有效期为5s后到1天内
    if wsid_2 and check_sid(wsid_2, 5, key, true) and check_sid(wsid_2, 60*60*24, key) then
        if ex > Deny2_ex then
            denyType1()
        end
        return
    end

    -- 1s内只响应一次
    -- \x21  denytype=2, subtype=1 -> 正进行deny中 
    if dict:get(key..'\x21') ~= nil then
        ngx.exit(444)
    end
    dict:set(key..'\x21', 1, 1)

    -- auth_str
    local time, auth_str = get_sid(key)

    local html = [=[
        <title>请稍后……</title>
        <center><h1>服务器检测到了异常，5秒后会自动刷新，请稍后！</h1></center>
        <hr>
        <center>579</center>
        <script type="text/javascript">
        //<![CDATA[
        (function(){
        setTimeout(function(){
            var Days = 1;
            var exp = new Date();
            exp.setTime(exp.getTime() + Days*24*60*60*1000);
            document.cookie = "wsid_2="+]=]..jsfuck(time..'|'..auth_str)..'+";expires=" + exp.toGMTString() + "; Path=/; Domain='.. domain() ..[=[";
            setTimeout(function(){location.reload()},100);
        },5200);
        })();
        //]]>
        </script>
    ]=]
    ngx.header.content_type = 'text/html'
    ngx.status = 579
    ngx.say(html)
    ngx.exit(579)
end


-----------------------------------------------------------------------
-- des：deny type-3 禁止5min
-- arg：
-----------------------------------------------------------------------
function denyType3(dict, key)
    dict:set(key..'\x40', '\x03', 60*5)
    ngx.exit(444)
end


-- jsfuck used
local USE_CHAR_CODE = "USE_CHAR_CODE"
MAPPING = {}
MAPPING['a'] =   '(false+"")[1]'
MAPPING['b'] =   '([]["entries"]()+"")[2]'
MAPPING['c'] =   '([]["fill"]+"")[3]'
MAPPING['d'] =   '(undefined+"")[2]'
MAPPING['e'] =   '(false+"")[4]'
MAPPING['f'] =   '(false+"")[0]'
MAPPING['g'] =   '(false+[0]+String)[20]'
MAPPING['h'] =   '(+(101))["to"+String["name"]](21)[1]'
MAPPING['i'] =   '([false]+undefined)[10]'
MAPPING['j'] =   '([]["entries"]()+"")[3]'
MAPPING['k'] =   '(+(20))["to"+String["name"]](21)'
MAPPING['l'] =   '(false+"")[2]'
MAPPING['m'] =   '(Number+"")[11]'
MAPPING['n'] =   '(undefined+"")[1]'
MAPPING['o'] =   '(true+[]["fill"])[10]'
MAPPING['p'] =   '(+(211))["to"+String["name"]](31)[1]'
MAPPING['q'] =   '(+(212))["to"+String["name"]](31)[1]'
MAPPING['r'] =   '(true+"")[1]'
MAPPING['s'] =   '(false+"")[3]'
MAPPING['t'] =   '(true+"")[0]'
MAPPING['u'] =   '(undefined+"")[0]'
MAPPING['v'] =   '(+(31))["to"+String["name"]](32)'
MAPPING['w'] =   '(+(32))["to"+String["name"]](33)'
MAPPING['x'] =   '(+(101))["to"+String["name"]](34)[1]'
MAPPING['y'] =   '(NaN+[Infinity])[10]'
MAPPING['z'] =   '(+(35))["to"+String["name"]](36)'

MAPPING['A'] =   '(+[]+Array)[10]'
MAPPING['B'] =   '(+[]+Boolean)[10]'
MAPPING['C'] =   'Function("return escape")()(("")["italics"]())[2]'
MAPPING['D'] =   'Function("return escape")()([]["fill"])["slice"]("-1")'
MAPPING['E'] =   '(RegExp+"")[12]'
MAPPING['F'] =   '(+[]+Function)[10]'
MAPPING['G'] =   '(true+Function("return Date")()())[29]'
MAPPING['H'] =   USE_CHAR_CODE
MAPPING['I'] =   '(Infinity+"")[0]'
MAPPING['J'] =   USE_CHAR_CODE
MAPPING['K'] =   USE_CHAR_CODE
MAPPING['L'] =   USE_CHAR_CODE
MAPPING['M'] =   '(true+Function("return Date")()())[30]'
MAPPING['N'] =   '(NaN+"")[0]'
MAPPING['O'] =   '(NaN+Function("return{}")())[11]'
MAPPING['P'] =   USE_CHAR_CODE
MAPPING['Q'] =   USE_CHAR_CODE
MAPPING['R'] =   '(+[]+RegExp)[10]'
MAPPING['S'] =   '(+[]+String)[10]'
MAPPING['T'] =   '(NaN+Function("return Date")()())[30]'
MAPPING['U'] =   '(NaN+Function("return{}")()["to"+String["name"]]["call"]())[11]'
MAPPING['V'] =   USE_CHAR_CODE
MAPPING['W'] =   USE_CHAR_CODE
MAPPING['X'] =   USE_CHAR_CODE
MAPPING['Y'] =   USE_CHAR_CODE
MAPPING['Z'] =   USE_CHAR_CODE

MAPPING[' '] =   '(NaN+[]["fill"])[11]'
MAPPING['!'] =   USE_CHAR_CODE
MAPPING['"'] =   '("")["fontcolor"]()[12]'
MAPPING['#'] =   USE_CHAR_CODE
MAPPING['$'] =   USE_CHAR_CODE
MAPPING['%'] =   'Function("return escape")()([]["fill"])[21]'
MAPPING['&'] =   '("")["link"](0+")[10]'
MAPPING['\''] =  USE_CHAR_CODE
MAPPING['('] =   '(undefined+[]["fill"])[22]'
MAPPING[')'] =   '([0]+false+[]["fill"])[20]'
MAPPING['*'] =   USE_CHAR_CODE
MAPPING['+'] =   '(+(+!+[]+(!+[]+[])[!+[]+!+[]+!+[]]+[+!+[]]+[+[]]+[+[]])+[])[2]'
MAPPING[','] =   '([]["slice"]["call"](false+"")+"")[1]'
MAPPING['-'] =   '(+(.+[0000000001])+"")[2]'
MAPPING['.'] =   '(+(+!+[]+[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+[!+[]+!+[]]+[+[]])+[])[+!+[]]'
MAPPING['/'] =   '(false+[0])["italics"]()[10]'
MAPPING['='] =   '(RegExp()+"")[3]'
MAPPING[';'] =   '("")["link"](")[14]'
MAPPING['<'] =   '("")["italics"]()[0]'
MAPPING['='] =   '("")["fontcolor"]()[11]'
MAPPING['>'] =   '("")["italics"]()[2]'
MAPPING['?'] =   '(RegExp()+"")[2]'
MAPPING['@'] =   USE_CHAR_CODE
MAPPING['['] =   '([]["entries"]()+"")[0]'
MAPPING['\\'] =  USE_CHAR_CODE
MAPPING[']'] =   '([]["entries"]()+"")[22]'
MAPPING['^'] =   USE_CHAR_CODE
MAPPING['_'] =   USE_CHAR_CODE
MAPPING['`'] =   USE_CHAR_CODE
MAPPING['{'] =   '(true+[]["fill"])[20]'
MAPPING['|'] =   USE_CHAR_CODE
MAPPING['}'] =   '([]["fill"]+"")["slice"]("-1")'
MAPPING['~'] =   USE_CHAR_CODE

-- number init
local output;
for number = 0 ,9 do
    output = "+[]";

    if number > 0 then output = "+!" .. output end
    for i = 1 , number-1 do output = "+!+[]" .. output end
    if number > 1 then output = output:sub(2) end

    MAPPING[tostring(number)] = "[" .. output .. "]";
end


function jsfuck(c)
    c = tostring(c)
    if c == '' or c == nil then return '' end
    local out = ''

    for i = 1, string.len(c) do
        --ngx.say(c:sub(i,i))
        local t = c:sub(i,i)
        if MAPPING[t] == "USE_CHAR_CODE" or MAPPING[t] == nil then
            --ngx.say(11)
            local rep =  "([]+[])[" .. jsfuck("constructor") .. "]" ..
              "[" .. jsfuck("fromCharCode") .. "]"  ..
              "(" .. jsfuck(string.byte(t)) .. ")"
            MAPPING[t] = rep
            out = out..'+'..rep
        else
            out = out..'+'..MAPPING[t]
        end
    end

    return out:sub(2)
end




-----------------------------------------------------------------------
-- des：基本安全过滤
-----------------------------------------------------------------------



function sec_check()
	-- args
	local args = ngx.var.args
    local uri = ngx.var.uri
    -- local ua = ngx.var.http_user_agent
	if args == nil then args = '' end

	-- post_data
	if ngx.var.http_Content_Type == "application/x-www-form-urlencoded" then
		ngx.req.read_body()
		local post_args, err = ngx.req.get_post_args()
		if err == "truncated" then
			return true, "post error"
		end

		if not post_args then
			return false
		end
		for _, val in pairs(post_args) do
			if type(val) == "table" then
				args = args..table.concat(val, ", ")
			else
				args = args..val
			end
		end
	end


	if args == nil then return false end
	args = string.lower(ngx.unescape_uri(args))

	-- sql
	-- 命令语句
	local tab_sql1 = {
		"and",
		"or",
		"exec",
		"insert",
		"select",
		"union",
		"update",
		"count",
		"group by",
		"updatexml",
		"extractvalue",
		"sleep"
	}
	-- 分隔标识符
	local tab_sql2 = {
		"\'",
		"\"",
		"/*",
		"*\\",
		"`",
		"-",
		"*",
		"(",
		")"
	}
	for _,rule1 in ipairs(tab_sql1) do
		local sta, en = string.find(args,string.lower(rule1),1,true)
        if en ~= nil then  --,"isjo"
			for _,rule2 in ipairs(tab_sql2) do
				if string.find(args,string.lower(rule2),en,true) ~= nil then
					return true, "sql", rule2
				end
			end
		end
	end

	-- XSS
	local tab_xss1 = {
		"<script",
		"<body",
		"<img",
		"<link",
		"<div",
		"<style",
		"<iframe",
		"<video",
		"<audio",
		"<input"
	}
	local tab_xss2 = {
		">",
		"javascript:",
		"</",
		"url(",
		" src=",
		" onload=",
		" onerror=",
		"/onload=",
		"/onerror=",
		" onmouseover=",
		" onblur=",
	}
	for _,rule1 in ipairs(tab_xss1) do
		local sta, en = string.find(args,string.lower(rule1),1,true)
        if en ~= nil then  --,"isjo"
			for _,rule2 in ipairs(tab_xss2) do
				if string.find(args,string.lower(rule2),en,true) ~= nil then
					-- log('GET',ngx.var.request_uri,"-",rule)
					-- say_html()
					-- ngx.say(args)
					return true, "xss", rule2
				end
			end
		end
	end

	-- 敏感目录/文件
	local tab_mg1 = {
		"etc/",
		"../",
		"."
	}
	local tab_mg2 = {
		"../",
		"passwd",
		"www",
		".swp",
		".svn",
		".htaccess",
		".bash_history",
		".bak",
		".sql",
		".old"
	}
	local uri2 = uri..args
	for _,rule1 in ipairs(tab_mg1) do
		local sta, en = string.find(uri2,string.lower(rule1),1,true)
        if en ~= nil then  --,"isjo"
			for _,rule2 in ipairs(tab_mg2) do
				if string.find(uri2,string.lower(rule2),sta,true) ~= nil then
					-- log('GET',ngx.var.request_uri,"-",rule)
					-- say_html()
					-- ngx.say(args)
					return true, "mgml", rule2
				end
			end
		end
    end

	return false
end