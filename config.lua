-- 定义和处理配置模块

auth_pir = '*5rwewr****'
ipBlocklist={
    "1.0.0.1"
}
ipWhitelist={
    "127.0.0.1"
}


-- Blocklist_UA={
-- }

Deny1=100    -- 触发type1防护的1s内请求数
Deny2=300    -- 触发type2防护的1s内请求数
Deny2_ex = 100  -- 在type2的基础上，1s内超过Deny2+Deny2_ex会触发Deny1类型延迟
Deny3=500    -- 触发type3防护的1s内请求数
