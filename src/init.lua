-- ipTIME Monitor Edge Driver v1.0
-- LAN 방식 | 표준 Capability 사용 (커스텀 Capability 불필요)
--
-- Capability 매핑:
--   temperatureMeasurement.temperature  → 다운로드 속도 (MB/s)
--   relativeHumidityMeasurement.humidity → 업로드 속도 (MB/s)
--   tvChannel.tvChannel.name            → 연결된 기기 수 (예: "12 대")
--   refresh                             → 수동 갱신

local capabilities = require "st.capabilities"
local cap_model   = capabilities["insidehonest32774.iptimeModel"]
local cap_conn    = capabilities["insidehonest32774.internetConnection"]
local cap_ext_ip  = capabilities["insidehonest32774.externalIpAddress"]
local cap_dl      = capabilities["insidehonest32774.downloadTraffic"]
local cap_ul      = capabilities["insidehonest32774.uploadTraffic"]
local cap_devices = capabilities["insidehonest32774.connectedDevices"]
local cap_login   = capabilities["insidehonest32774.loginStatus"]
local Driver       = require "st.driver"
local socket       = require "cosock.socket"
local log          = require "log"
local json         = require "st.json"
local http         = require "cosock.socket.http"
http.TIMEOUT       = 5 -- Prevent socket hang on Hub
local ltn12        = require "ltn12"

local function emit_login_status(device, status)
  device:emit_event(cap_login.status({ value = status }, { state_change = true }))
end

------------------------------------------------------------
-- 모듈 변수
------------------------------------------------------------
local initialized = false

------------------------------------------------------------
-- 상수
------------------------------------------------------------
local DEFAULT_HOST     = "192.168.0.1"
local DEFAULT_INTERVAL = 60
local SESSION_TTL      = 540

local UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " ..
           "AppleWebKit/537.36 (KHTML, like Gecko) " ..
           "Chrome/114.0.0.0 Safari/537.36"

------------------------------------------------------------
-- preferences 헬퍼
------------------------------------------------------------
local function pref(device, key, default)
  local v = device.preferences and device.preferences[key]
  if v == nil or v == "" then return default end
  return v
end

------------------------------------------------------------
-- ipTIME 로그인 → efm_session_id 반환
------------------------------------------------------------
local function do_login(device)
  local host = pref(device, "routerIp", DEFAULT_HOST)
  local user = pref(device, "adminUser", "admin")
  local pass = pref(device, "adminPass", "admin")

  log.info(string.format("[iptime] 로그인 시도: http://%s/cgi/service.cgi", host))

  local payload = {
    method = "session/login",
    params = {
      id = user,
      pw = pass
    }
  }
  local body = json.encode(payload)
  local resp = {}

  local _, status, headers = http.request({
    url    = "http://" .. host .. "/cgi/service.cgi",
    method = "POST",
    headers = {
      ["Host"]           = host,
      ["Content-Type"]   = "application/json; charset=utf-8",
      ["Content-Length"] = tostring(#body),
      ["Connection"]     = "close",
      ["User-Agent"]     = UA,
      ["Referer"]        = "http://" .. host .. "/ui/login",
      ["Origin"]         = "http://" .. host,
    },
    source = ltn12.source.string(body),
    sink   = ltn12.sink.table(resp),
  })

  if not status then
    log.error("[iptime] 로그인 연결 실패")
    emit_login_status(device, "Connection Error (IP unreachable)")
    device:set_field("login_status_text", "Connection Error (IP unreachable)")
    return nil
  end

  local raw_resp = table.concat(resp)
  raw_resp = raw_resp:gsub("[\x80-\xff]", "?")
  log.debug("[iptime] 로그인 응답 바디: " .. raw_resp)

  local set_cookie = (headers and (headers["set-cookie"] or headers["Set-Cookie"])) or ""
  local session_id = set_cookie:match("efm_session_id=([^;]+)")

  if session_id then
    log.info("[iptime] 로그인 성공 → session=" .. session_id)
    device:set_field("session_id",   session_id, { persist = false })
    device:set_field("session_time", os.time(),  { persist = false })
    emit_login_status(device, "Connected (Auto Login)")
    device:set_field("login_status_text", "Connected (Auto Login)")
    return session_id
  else
    log.warn("[iptime] 쿠키 없음 (status=" .. tostring(status) .. ")")
    emit_login_status(device, "Login Failed (ID/PW or Captcha)")
    device:set_field("login_status_text", "Login Failed (ID/PW or Captcha)")
    return nil
  end
end

------------------------------------------------------------
-- 유효 세션 반환 (만료 시 자동 재로그인)
------------------------------------------------------------
local function get_session(device)
  local sid   = device:get_field("session_id")
  local stime = device:get_field("session_time") or 0
  if sid and (os.time() - stime) < SESSION_TTL then
    return sid
  end

  log.info("[iptime] 세션 만료 → 재로그인")
  return do_login(device)
end

------------------------------------------------------------
-- service.cgi POST 요청
------------------------------------------------------------
local function api_call(device, method)
  local host    = pref(device, "routerIp", DEFAULT_HOST)
  local session = get_session(device)
  if not session then
    log.error("[iptime] 세션 없음: " .. method)
    return nil, "No Session"
  end

  local body = '{"method":"' .. method .. '"}'
  local resp = {}

  local _, status = http.request({
    url    = "http://" .. host .. "/cgi/service.cgi",
    method = "POST",
    headers = {
      ["Host"]           = host,
      ["Content-Type"]   = "application/json; charset=utf-8",
      ["Content-Length"] = tostring(#body),
      ["Accept"]         = "*/*",
      ["Cache-Control"]  = "no-store",
      ["Connection"]     = "close",
      ["Origin"]         = "http://" .. host,
      ["Referer"]        = "http://" .. host .. "/ui/sysinfo",
      ["User-Agent"]     = UA,
      ["Cookie"]         = "efm_session_id=" .. session,
    },
    source = ltn12.source.string(body),
    sink   = ltn12.sink.table(resp),
  })

  if status ~= 200 then
    log.warn("[iptime] API 오류 method=" .. method .. " status=" .. tostring(status))
    if status == 302 or status == 401 or status == 403 then
      device:set_field("session_id", nil)
      device:set_field("login_status_text", "Session Expired")
    end
    return nil, tostring(status or "HTTP Err")
  end

  local raw = table.concat(resp)
  raw = raw:gsub("[\x80-\xff]", "?") -- Sanitize EUC-KR bytes to prevent JSON parse errors
  log.debug(string.format("[iptime] API 응답 method=%s raw=%s", method, raw))
  local ok, decoded = pcall(json.decode, raw)
  if not ok then
    log.error("[iptime] JSON 파싱 실패: " .. tostring(decoded))
    return nil, "JSON Parse Error"
  end

  if decoded and decoded.error then
    local err_msg = decoded.error.message or "API Error"
    log.warn(string.format("[iptime] API 에러 응답: %s (code=%s)", err_msg, tostring(decoded.error.code)))
    if decoded.error.code == -31998 or err_msg == "Unauthenticated" then
      device:set_field("session_id", nil)
      device:set_field("login_status_text", "Session Expired")
    end
    return nil, err_msg
  end

  return decoded and decoded.result, "OK"
end

------------------------------------------------------------
-- 실시간 속도 계산 (누적 바이트 차이 → MB/s)
-- 바이트 차이 / 경과 시간(초) = Byte/s → ÷1,000,000 = MB/s
------------------------------------------------------------
local function calc_speed(device, new_rx, new_tx)
  local prev_rx   = device:get_field("prev_rx")   or new_rx
  local prev_tx   = device:get_field("prev_tx")   or new_tx
  local prev_time = device:get_field("prev_time") or os.time()

  local elapsed = os.time() - prev_time
  if elapsed <= 0 then elapsed = DEFAULT_INTERVAL end

  local rx_bps = (new_rx - prev_rx) / elapsed   -- Byte/s
  local tx_bps = (new_tx - prev_tx) / elapsed   -- Byte/s

  if rx_bps < 0 then rx_bps = 0 end
  if tx_bps < 0 then tx_bps = 0 end

  -- MB/s 로 변환, 소수점 2자리 반올림
  local rx_mbs = math.floor(rx_bps / 10000) / 100   -- MB/s
  local tx_mbs = math.floor(tx_bps / 10000) / 100   -- MB/s

  device:set_field("prev_rx",   new_rx,    { persist = false })
  device:set_field("prev_tx",   new_tx,    { persist = false })
  device:set_field("prev_time", os.time(), { persist = false })

  return rx_mbs, tx_mbs
end

------------------------------------------------------------
-- SmartThings 상태 업데이트
--
-- 표준 Capability 활용:
--   temperatureMeasurement   → 다운로드 속도 (단위: "°C" 자리에 MB/s 표시)
--   relativeHumidityMeasurement → 업로드 속도 (단위: "%" 자리에 MB/s)
--   tvChannel                → 연결된 기기 수 문자열
------------------------------------------------------------
local function update_states(device, rx_mbs, tx_mbs, dev_count, conn_status, ext_ip)
  local model = pref(device, "routerModel", "ipTIME")
  conn_status = conn_status or "Unknown"
  ext_ip      = ext_ip or "0.0.0.0"

  log.info(string.format("[%s] ↓%.2f MB/s  ↑%.2f MB/s  기기:%d대  연결:%s  IP:%s",
    model, rx_mbs, tx_mbs, dev_count, conn_status, ext_ip))

  -- 공유기 모델명
  device:emit_event(
    cap_model.model({
      value = model
    }, { state_change = true })
  )

  -- 인터넷 연결 상태
  device:emit_event(
    cap_conn.connection({
      value = conn_status
    }, { state_change = true })
  )

  -- 외부 IP 주소
  device:emit_event(
    cap_ext_ip.ip({
      value = ext_ip
    }, { state_change = true })
  )

  -- 다운로드 속도
  device:emit_event(
    cap_dl.downloadSpeed({
      value = rx_mbs,
      unit  = "MB/s"
    }, { state_change = true })
  )

  -- 업로드 속도
  device:emit_event(
    cap_ul.uploadSpeed({
      value = tx_mbs,
      unit  = "MB/s"
    }, { state_change = true })
  )

  -- 연결된 기기 수 (English formatting)
  local devices_value = string.format("%d Devices Connected", dev_count)
  if dev_count == 1 then
    devices_value = "1 Device Connected"
  end
  device:emit_event(
    cap_devices.devices({
      value = devices_value
    }, { state_change = true })
  )
end

------------------------------------------------------------
-- 폴링 함수 (타이머 콜백용)
------------------------------------------------------------
local function poll_handler(driver, device)
  log.debug(string.format("[iptime] 폴링 실행 (IP=%s, ID=%s)",
    pref(device, "routerIp", DEFAULT_HOST),
    pref(device, "adminUser", "admin")
  ))

  local login_status = device:get_field("login_status_text") or "Connected"

  -- WAN 트래픽 통계 조회
  local stat, stat_err = api_call(device, "port/stat/get")
  local rx_mbs, tx_mbs = 0, 0
  if stat then
    for _, port in ipairs(stat) do
      if port.type == "wan" and tonumber(port.port) == 1 then
        local new_rx = tonumber(port.rx and port.rx.byte) or 0
        local new_tx = tonumber(port.tx and port.tx.byte) or 0
        rx_mbs, tx_mbs = calc_speed(device, new_rx, new_tx)
        break
      end
    end
  end

  -- 연결 기기 수 조회 (network/interface/lan/stations)
  local stations, conn_err = api_call(device, "network/interface/lan/stations")
  local dev_count = 0
  if stations then
    dev_count = #stations
  end

  -- WAN 인터넷 상태 및 외부 IP 조회
  local wan_info, wan_err = api_call(device, "network/interface/wan1/info")
  local conn_status = "Disconnected"
  local ext_ip      = "0.0.0.0"
  if wan_info then
    local p_stat = wan_info.protocol_status
    local stat   = wan_info.status
    if p_stat == "ok" or stat == "up" then
      conn_status = "Connected"
    else
      conn_status = p_stat or stat or "Disconnected"
    end
    ext_ip = wan_info.ip or "0.0.0.0"
  end

  -- Update diagnostic status
  local diag = string.format("%s | Stat: %s | Conn: %s | WAN: %s",
    login_status,
    stat_err or "FAIL",
    conn_err or "FAIL",
    wan_err or "FAIL"
  )
  emit_login_status(device, diag)

  update_states(device, rx_mbs, tx_mbs, dev_count, conn_status, ext_ip)
end

------------------------------------------------------------
-- Command Handlers
------------------------------------------------------------
local function handle_refresh(driver, device, command)
  log.info("[iptime] 수동 갱신 요청")
  poll_handler(driver, device)
end

------------------------------------------------------------
-- Lifecycle Handlers
------------------------------------------------------------
local function device_init(driver, device)
  log.debug(device.id .. ": " .. device.device_network_id .. " > INITIALIZING")

  -- 초기 로그인
  do_login(device)

  -- 초기 상태 즉시 표시 (0으로 초기화)
  update_states(device, 0, 0, 0, "Unknown", "0.0.0.0")

  -- 주기적 폴링 타이머 설정
  local interval = tonumber(pref(device, "pollInterval", DEFAULT_INTERVAL)) or DEFAULT_INTERVAL
  local poll_timer = driver:call_on_schedule(
    interval,
    function()
      poll_handler(driver, device)
    end
  )
  device:set_field("poll_timer", poll_timer)

  -- 즉시 데이터 조회 실행
  poll_handler(driver, device)

  initialized = true
end

local function device_added(driver, device)
  log.info(device.id .. ": " .. device.device_network_id .. " > ADDED")
end

local function device_removed(driver, device)
  log.warn(device.id .. ": " .. device.device_network_id .. " > REMOVED")

  if device:get_field("poll_timer") then
    driver:cancel_timer(device:get_field("poll_timer"))
  end

  local device_list = driver:get_devices()
  if #device_list == 0 then
    initialized = false
  end
end

local function handler_infochanged(driver, device, event, args)
  log.debug("[iptime] Info changed handler invoked")

  local changed = false

  if args.old_st_store.preferences then
    if args.old_st_store.preferences.routerIp ~= device.preferences.routerIp then
      log.info("[iptime] 공유기 IP 변경")
      device:set_field("session_id", nil)
      do_login(device)
      changed = true
    elseif args.old_st_store.preferences.adminUser ~= device.preferences.adminUser or
           args.old_st_store.preferences.adminPass ~= device.preferences.adminPass then
      log.info("[iptime] 관리자 정보 변경")
      device:set_field("session_id", nil)
      do_login(device)
      changed = true
    end



    if args.old_st_store.preferences.routerModel ~= device.preferences.routerModel then
      local new_model = pref(device, "routerModel", "ipTIME")
      log.info("[iptime] 공유기 모델명 변경 -> " .. new_model)
      device:try_update_metadata({ label = "ipTIME " .. new_model })
      changed = true
    end

    if args.old_st_store.preferences.pollInterval ~= device.preferences.pollInterval then
      local new_interval = tonumber(pref(device, "pollInterval", DEFAULT_INTERVAL)) or DEFAULT_INTERVAL
      log.info("[iptime] 폴링 간격 변경 -> " .. new_interval .. "초")
      local old_timer = device:get_field("poll_timer")
      if old_timer then
        driver:cancel_timer(old_timer)
      end
      local poll_timer = driver:call_on_schedule(
        new_interval,
        function()
          poll_handler(driver, device)
        end
      )
      device:set_field("poll_timer", poll_timer)
      changed = true
    end
  end

  if changed then
    log.info("[iptime] 설정 변경 감지 -> 즉시 폴링 실행")
    poll_handler(driver, device)
  end
end

------------------------------------------------------------
-- Discovery Handler (LAN 방식)
------------------------------------------------------------
local function discovery_handler(driver, _, should_continue)
  log.info("[iptime] discovery_handler 실행 - LAN 기기 생성")

  if not initialized then
    log.info("[iptime] ipTIME Monitor 기기 생성 중")

    local create_device_msg = {
      type                  = "LAN",
      device_network_id     = "iptime_monitor_singleton",
      label                 = "ipTIME Monitor",
      profile               = "iptime-router",
      manufacturer          = "Custom",
      model                 = "ipTIME-Monitor",
      vendor_provided_label = "ipTIME Monitor",
    }

    local ok, err = pcall(function()
      assert(driver:try_create_device(create_device_msg), "기기 생성 실패")
    end)

    if ok then
      log.info("[iptime] 기기 생성 완료")
    else
      log.error("[iptime] 기기 생성 중 오류: " .. tostring(err))
    end
  else
    log.info("[iptime] 기기가 이미 생성되어 있음")
  end
end

------------------------------------------------------------
-- Driver 등록
------------------------------------------------------------
thisDriver = Driver("iptime-monitor-v11", {
  discovery = discovery_handler,
  lifecycle_handlers = {
    init        = device_init,
    added       = device_added,
    removed     = device_removed,
    infoChanged = handler_infochanged,
  },
  capability_handlers = {
    [capabilities.refresh.ID] = {
      [capabilities.refresh.commands.refresh.NAME] = handle_refresh,
    },
  }
})

log.info("[iptime] ipTIME Monitor Driver v1.0 Starting")

thisDriver:run()
