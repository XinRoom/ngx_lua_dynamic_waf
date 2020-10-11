-- 日志阶段状态码收集模块

---------------------------------------------------------
-- shared init
-- lua_shared_dict dict_sid 20m;
-- lua_shared_dict dict_ip 15m;
-- lua_shared_dict dict_ips 10m;
---------------------------------------------------------
-- key: m_key+time_min+

-- 1min 内统计: 2XX | >=4XX | agv_rep_time
-- 每条数据默认59分钟后失效

-- 白名单ip不记录
if ngx.ctx.whiteip == true then
	return
end

local dict_sid = ngx.shared.dict_sid
local dict_ip = ngx.shared.dict_ip
local dict_sys = ngx.shared.dict_sys

-- 统计响应处理时间
-- local resp_time = ngx.now() - ngx.req.start_time()
local now = tonumber(ngx.localtime():sub(-5, -4))  --os.date('%M')
local ip = ngx.var.binary_remote_addr
local credible = ngx.ctx.credible or 10
--svrname_key = ngx.var.host

local wsid = ngx.var.cookie_wsid
local namespace = ngx.var.namespace or ''
-----------------------------------------------------------------------
-- des：dict_sid update
-- arg：key2-标记
-----------------------------------------------------------------------
local update_sid = function(key1, key2, inc, namespace)
    if key1 ~= nil then
        local ok, sid= check_sid(key1)
        if ok then
            incr_dict(dict_sid, sid..key2, now, inc, namespace)

            if get_last_num(dict_sid, sid..'\x01', now, namespace) <= credible then
                incr_dict(dict_sid, ip..key2, now, inc, namespace)
            end
        else
            incr_dict(dict_sid, ip..key2, now, inc, namespace)
        end
    end
end


-- 统计>=4xx的状态码
local status = tonumber(ngx.var.status)
if status ~= 579 and status ~= 444 then
    local key2 = '\x02'   --标记:4XX,5XX
    local inc = 1       --默认增量为1
    if status < 400 then
        key2 = '\x01'   --标记:1XX,2XX,3XX
    end

    -- 403 最为异常
    if status == 403 or status == 500 then
        inc = 5
    end

    -- 客户端在未接收数据的情况下就主动关闭了连接
    if ngx.var.bytes_sent == 0 then
        key2 = '\x02'
        inc = 10
        -- ngx.log(ngx.WARN, ngx.var.remote_addr.."-bytes_sent 0")
    end

    -- wsid - cookie
    if wsid ~= nil then
        update_sid(wsid, key2, inc, namespace)
    else
        -- sid => ip
        incr_dict(dict_sid, ip..key2, now, inc, namespace)
    end

    -- 统计ip的状态
    incr_dict(dict_ip, ip..key2, now, inc, namespace)
    incr_dict(dict_sys, 'count', now)
end



-- dney done log
-- local denytype = ngx.ctx.denytype
-- if denytype ~= nil then
--     if denytype == '\x10' then
--         local limit = ngx.shared.limit
--         limit:set('lt', ngx.ctx.foo, 10)
--     elseif denytype == '\x20' then
--         local limit = ngx.shared.limit
--         limit:set('lt', ngx.ctx.foo, 10)
--     else
--         local limit = ngx.shared.limit
--         limit:set('lt', ngx.ctx.foo, 10)
--     end
-- end



