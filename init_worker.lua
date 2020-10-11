-- 统计cpu平均负载的线程

-- 获取cpu核心数
local cpu_core = 0
local fp = io.open("/proc/cpuinfo")
local data = fp:read("*all")
fp:close()
local iterator, _ = ngx.re.gmatch(data, "processor","jio")
while true do
    local m, _ = iterator()
    if not m then
        break
    end
    cpu_core = cpu_core + 1
end

local dict_sys = ngx.shared.dict_sys

-- 获得cpu平均负载
local function count_cpu_usage()
    -- 每分钟释放一次过期的内存
    if ngx.time() % 60 == 0 then
        ngx.shared.dict_sid:flush_expired()
        ngx.shared.dict_ip:flush_expired()
        ngx.shared.dict_deny:flush_expired()
        ngx.shared.dict_sys:flush_expired()
    end
    local fp = io.open("/proc/loadavg","r")
    local data = fp:read("*all")
    fp:close()
    local m, _ = ngx.re.match(data, "(.*?) (.*?) (.*?) ", "jio")
    if m then
        dict_sys:set('cpu1',tonumber(m[1])/cpu_core)
        dict_sys:set('cpu2',tonumber(m[2])/cpu_core)
    end
end


-- 定时任务
local function count_cpu_usage_timed_job()
    -- 定义间隔执行时间
    local delay = 1
    local count
    local log = ngx.log
    count = function(premature)
        if not premature then
            local ok, err = pcall(count_cpu_usage, premature)
            if not ok then
                log(ngx.ERR, "count cpu usage error:",err)
            end
            local ok, _ = ngx.timer.at(delay, count)
            if not ok then
                log(ngx.ERR, "timer error:",err)
                return
            end
        end
    end
    local ok, err = ngx.timer.at(delay, count)
    if not ok then
        log(ngx.ERR, "timer error:",err)
        return
    end
end


-- 防止多个worker同时进行
if ngx.worker.id() == 0 then
    count_cpu_usage_timed_job()
end
